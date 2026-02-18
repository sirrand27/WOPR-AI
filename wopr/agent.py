#!/usr/bin/env python3
"""
W.O.P.R. Network Defense Sentry
Monitors the network via UniFi MCP and posts observations
to the Blackboard Live Activity feed.

Usage:
    python agent.py              # Normal operation (defense sentry)
    python agent.py --test       # Single inference test
    python agent.py --status     # Check service status
"""

import json
import logging
import re
import signal
import sys
import threading
import time
import urllib.request
import urllib.error

from config import (
    AGENT_NAME, OLLAMA_URL, OLLAMA_MODEL,
    POLL_INTERVAL, SYSTEM_PROMPT,
    INQUIRY_POLL_INTERVAL, INQUIRY_PROMPT, INQUIRY_TOOL_WHITELIST,
    MAX_INQUIRY_CHAIN_DEPTH,
    LOG_FILE, LOG_LEVEL
)
from blackboard import BlackboardClient
from voice import VoiceClient
from learning import LearningEngine
from memory import Memory
from tools import execute_tool, TOOL_REGISTRY
from unifi_defense import UniFiDefenseLoop

# === Logging Setup ===
_log_format = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
_log_handlers = [logging.FileHandler(LOG_FILE, encoding="utf-8")]
# Only add StreamHandler if stdout is a TTY (avoids double-logging under nohup)
if sys.stdout.isatty():
    _log_handlers.append(logging.StreamHandler(sys.stdout))
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=_log_format,
    handlers=_log_handlers
)
logger = logging.getLogger("wopr")


def _tts_prep(text):
    """Preprocess text for TTS — expand abbreviations the voice can't pronounce."""
    text = text.replace("TH/s", "terahash per second")
    text = text.replace("GH/s", "gigahash per second")
    text = text.replace("MH/s", "megahash per second")
    text = text.replace("KH/s", "kilohash per second")
    text = text.replace("H/s", "hash per second")
    text = text.replace("W.O.P.R.", "Whopper")
    return text


def _ollama_chat(messages, timeout=120):
    """Send messages to Ollama, return response text or None."""
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
    }
    url = f"{OLLAMA_URL}/api/chat"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read())
            return result.get("message", {}).get("content", "")
    except Exception as e:
        logger.error(f"Ollama inference failed: {e}")
        return None


def _parse_tool_call(text):
    """Extract tool call from LLM output — tries multiple formats."""
    # Try ```tool ... ``` block first
    match = re.search(r'```tool\s*\n?(.*?)\n?```', text, re.DOTALL)
    if match:
        try:
            call = json.loads(match.group(1).strip())
            if "tool" in call:
                return call["tool"], call.get("args", {})
        except (json.JSONDecodeError, AttributeError):
            pass

    # Fallback: find any JSON object containing "tool" key
    # Walk through text looking for { that starts a tool call
    for match in re.finditer(r'\{\s*"tool"\s*:', text):
        start = match.start()
        # Find matching closing brace (handle nested braces for args)
        depth = 0
        for i in range(start, len(text)):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    try:
                        call = json.loads(candidate)
                        if "tool" in call:
                            return call["tool"], call.get("args", {})
                    except json.JSONDecodeError:
                        pass
                    break

    return None, None


def _extract_device_name(query):
    """Extract a device/hostname/IP/MAC from an investigation query."""
    q = query.lower()

    # Direct MAC address in query — return it for lookup
    mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', q)
    if mac_match:
        return mac_match.group(0)

    # Direct IP address in query
    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', q)
    if ip_match:
        return ip_match.group(1)

    # Try explicit patterns for hostnames
    patterns = [
        r"(?:investigate|check|inspect|analyze|analyse|look at|examine)\s+(?:the\s+)?(.+?)(?:'s\s+pc|'s\s+laptop|'s\s+device|'s\s+machine|'s\s+computer|\s+pc|\s+laptop|\s+device|\s+machine|\s+computer)?(?:\s*$|\s+for|\s+on|\s+from)",
        r"(?:what is|what's)\s+(.+?)\s+doing",
        r"(?:timeline|history)\s+(?:for|of)\s+(?:the\s+)?(.+?)(?:\s*$|\s+over|\s+in|\s+during)",
        r"(?:lateral movement|spreading|pivot)\s+from\s+(?:the\s+)?(.+?)(?:\s*$|\s+to|\s+across)",
    ]
    for pattern in patterns:
        m = re.search(pattern, q)
        if m:
            name = m.group(1).strip().strip("'\"")
            skip = {"the", "this", "my", "a", "an", "that", "network", "all", "every"}
            if name and name not in skip:
                return name

    # Fallback: last significant word
    skip_words = {
        "what", "from", "that", "this", "with", "about", "have", "does", "been",
        "investigate", "check", "analyze", "analyse", "timeline", "examine",
        "history", "lateral", "movement", "forensic", "look", "inspect",
        # Action verbs that shouldn't be device names
        "attacking", "dropping", "broadcasting", "spreading", "moving",
        "connecting", "happening", "working", "running", "doing", "sending",
        "receiving", "scanning", "blocking", "disconnecting", "reconnecting",
        # Networking terms that aren't device names
        "network", "status", "health", "report", "overview", "summary",
        "traffic", "bandwidth", "protocol", "alert", "event", "perimeter",
    }
    words = q.split()
    for w in reversed(words):
        if len(w) > 3 and w not in skip_words:
            return w
    # All words are skip words — return empty (no device name found)
    return ""


def _format_tool_result(tool_name, tool_result, query=""):
    """Build a clean natural language summary when Ollama can't summarize."""
    try:
        data = json.loads(tool_result) if isinstance(tool_result, str) else tool_result
    except (json.JSONDecodeError, TypeError):
        data = None

    if tool_name == "unifi_clients":
        clients = data if isinstance(data, list) else data.get("clients", []) if isinstance(data, dict) else []
        summary_str = data.get("summary", "") if isinstance(data, dict) else ""
        if clients:
            total = len(clients)
            wired = sum(1 for c in clients if c.get("is_wired", False))
            wireless = total - wired
            return (f"PERIMETER STATUS. {total} clients currently connected. "
                    f"{wired} wired, {wireless} wireless. W.O.P.R. out.")
        elif summary_str:
            return f"PERIMETER STATUS. {summary_str}. W.O.P.R. out."

    if tool_name == "unifi_client_detail" and isinstance(data, dict):
        name = data.get("hostname") or data.get("name") or "Unknown"
        mac = data.get("mac", "unknown")
        ip = data.get("ip", "no IP assigned")
        oui = data.get("oui") or data.get("manufacturer") or "unknown manufacturer"
        network = data.get("network") or data.get("essid") or "unknown network"
        is_wired = data.get("is_wired", False)
        conn_type = "wired" if is_wired else f"wireless ({network})"
        uptime = data.get("uptime", 0)
        uptime_str = f"{uptime // 3600}h {(uptime % 3600) // 60}m" if uptime else "not reported"
        return (f"DEVICE REPORT. {name} ({mac}). IP: {ip}. "
                f"Manufacturer: {oui}. Connection: {conn_type}. "
                f"Uptime: {uptime_str}. W.O.P.R. out.")

    if tool_name == "unifi_search" and isinstance(data, list):
        if not data:
            return "SEARCH RESULT. No matching devices found. W.O.P.R. out."
        results = []
        for d in data[:5]:
            name = d.get("hostname") or d.get("name") or "unknown"
            mac = d.get("mac", "")
            ip = d.get("ip", "no IP")
            results.append(f"{name} ({mac}, {ip})")
        return (f"SEARCH RESULT. {len(data)} device(s) found: "
                f"{'; '.join(results)}. W.O.P.R. out.")

    if tool_name == "unifi_health" and isinstance(data, dict):
        subs = data.get("subsystems", data)
        wan = subs.get("wan", {})
        lan = subs.get("lan", {})
        wlan = subs.get("wlan", {})
        www = subs.get("www", {})
        wan_status = wan.get("status", "unknown")
        lan_status = lan.get("status", "unknown")
        wlan_status = wlan.get("status", "unknown")
        lan_clients = lan.get("num_user", "N/A")
        wlan_clients = wlan.get("num_user", "N/A")
        total = (lan_clients or 0) + (wlan_clients or 0) if isinstance(lan_clients, int) and isinstance(wlan_clients, int) else "N/A"
        isp = wan.get("isp_name", "unknown")
        latency = www.get("latency")
        latency_str = f"{latency}ms" if latency else "N/A"
        return (f"PERIMETER STATUS. {total} clients connected — "
                f"{wlan_clients} wireless, {lan_clients} wired. "
                f"WAN: {wan_status} ({isp}, latency {latency_str}). "
                f"WLAN: {wlan_status}. LAN: {lan_status}. W.O.P.R. out.")

    if tool_name == "unifi_devices" and isinstance(data, list):
        lines = []
        for d in data[:10]:
            name = d.get("name") or d.get("hostname") or "unnamed"
            model = d.get("model", "unknown")
            status = "online" if d.get("state", 0) == 1 else "offline"
            lines.append(f"{name} ({model}, {status})")
        return (f"INFRASTRUCTURE. {len(data)} device(s): "
                f"{'; '.join(lines)}. W.O.P.R. out.")

    if tool_name == "unifi_alerts" and isinstance(data, list):
        if not data:
            return "ALERT STATUS. No recent alerts. Perimeter nominal. W.O.P.R. out."
        summaries = []
        for a in data[:5]:
            msg = a.get("msg") or a.get("message") or "unknown alert"
            ts = a.get("datetime") or a.get("time") or ""
            summaries.append(f"{msg} ({ts})" if ts else msg)
        return (f"ALERT STATUS. {len(data)} alert(s): "
                f"{'; '.join(summaries)}. W.O.P.R. out.")

    if tool_name == "unifi_events" and isinstance(data, list):
        if not data:
            return "EVENT LOG. No recent events. W.O.P.R. out."
        summaries = []
        for e in data[:5]:
            msg = e.get("msg") or e.get("message") or "event"
            summaries.append(msg[:80])
        return (f"EVENT LOG. {len(data)} event(s): "
                f"{'; '.join(summaries)}. W.O.P.R. out.")

    # Generic fallback — extract summary, never dump raw JSON
    if isinstance(data, dict):
        # Try to pull a summary or count from the dict
        summary = data.get("summary", "")
        count = data.get("count", data.get("total", ""))
        if summary:
            return f"SENSOR DATA ({tool_name}). {summary}. W.O.P.R. out."
        elif count:
            return f"SENSOR DATA ({tool_name}). {count} entries returned. W.O.P.R. out."
        else:
            keys = ", ".join(str(k) for k in list(data.keys())[:8])
            return f"SENSOR DATA ({tool_name}). Data received ({keys}). Insufficient context to summarize. W.O.P.R. out."
    elif isinstance(data, list):
        return f"SENSOR DATA ({tool_name}). {len(data)} entries returned. W.O.P.R. out."
    else:
        result_str = str(tool_result)[:500]
        # Strip any JSON-like content
        if '{' in result_str:
            return f"SENSOR DATA ({tool_name}). Data received. W.O.P.R. out."
        return f"SENSOR DATA ({tool_name}). {result_str}. W.O.P.R. out."


def _get_whitelisted_tool_descriptions():
    """Get tool descriptions for whitelisted inquiry tools only."""
    lines = []
    for name in INQUIRY_TOOL_WHITELIST:
        if name in TOOL_REGISTRY:
            tool = TOOL_REGISTRY[name]
            params = ", ".join(tool["params"])
            lines.append(f"  - {name}({params}): {tool['description']}")
    return "\n".join(lines)


class InboxHandler:
    """Polls Blackboard inbox, answers queries via Ollama + UniFi tools.
    Reactive only — W.O.P.R. speaks when spoken to."""

    def __init__(self, blackboard, voice, learning, defense):
        self.blackboard = blackboard
        self.voice = voice
        self.learning = learning
        self.defense = defense
        self.memory = Memory()

        self._thread = None
        self._running = False

    def _reply(self, to_agent, content, message_type="info", speak=True):
        """Send a Blackboard reply and speak it via Joshua voice."""
        self.blackboard.send_message(
            to_agent=to_agent, content=content, message_type=message_type)
        if speak and self.voice and self.voice.enabled and len(content) >= 20:
            self.voice.speak(_tts_prep(content))

    def _escalate(self, reason, context="", severity="HIGH"):
        """Escalate to JOSHUA via Blackboard."""
        content = (f"ESCALATION — {severity}. {reason}\n\n"
                   f"Context: {context[:500]}\n\n"
                   f"W.O.P.R. requesting JOSHUA review.")
        self.blackboard.send_message(
            to_agent="joshua", content=content, message_type="alert")
        logger.info(f"Escalated to JOSHUA: {reason[:80]}")

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="inbox-handler"
        )
        self._thread.start()
        logger.info(f"Inbox handler started ({INQUIRY_POLL_INTERVAL}s poll)")

    def stop(self):
        self._running = False

    def is_running(self):
        return self._running and self._thread and self._thread.is_alive()

    def _loop(self):
        while self._running:
            try:
                result = self.blackboard.check_inbox()
                if result and isinstance(result, dict):
                    messages = result.get("messages", [])
                    if messages:
                        logger.info(f"Inbox: {len(messages)} message(s) received")
                    for msg in messages:
                        if isinstance(msg, dict) and msg.get("content"):
                            self._handle_message(msg)
                        elif isinstance(msg, dict):
                            logger.debug(f"Inbox: skipped message without content: {list(msg.keys())}")
            except Exception as e:
                logger.error(f"Inbox poll error: {e}", exc_info=True)
            time.sleep(INQUIRY_POLL_INTERVAL)

    def _handle_message(self, msg):
        """Process an incoming Blackboard message."""
        sender = msg.get("from_agent", "unknown")
        query = msg.get("content", "").strip()
        msg_type = msg.get("message_type", "info")

        # Skip heartbeats and status messages
        if msg_type == "status" or query.lower() == "heartbeat":
            return

        query_lower = query.lower().strip()
        to_agent = msg.get("to_agent", "").lower()

        # --- Directive Filtering (broadcast & out-of-scope) ---
        _OOS_KEYWORDS = [
            "training is a go", "fine-tune", "finetune", "qlora", "lora",
            "code review", "edit code", "modify code", "write code",
            "deploy", "git push", "git commit", "pip install",
            "implement feature", "refactor", "development",
            "osint", "sherlock", "theharvester", "court records",
            "case file", "run training",
        ]
        is_broadcast = to_agent in ("all", "broadcast", "everyone")
        # Preserve existing training handlers (trigger/export/status)
        is_local_training_cmd = query_lower in (
            "trigger training", "train", "export training", "training status")
        if not is_local_training_cmd and any(kw in query_lower for kw in _OOS_KEYWORDS):
            if is_broadcast:
                logger.info(f"Filtered out-of-scope broadcast from {sender}: {query[:60]}")
                return  # Silently ignore — not for WOPR
            else:
                self._reply(sender,
                    "That directive is outside W.O.P.R. operational scope. "
                    "Training and development: defer to TARS Dev. "
                    "OSINT and analysis: defer to JOSHUA. "
                    "W.O.P.R. out.", speak=False)
                logger.info(f"Refused out-of-scope directive from {sender}: {query[:60]}")
                return

        logger.info(f"Inquiry from {sender}: {query[:100]}")

        # Check for posture approval commands
        if query_lower.startswith("approve "):
            self._handle_posture_command(sender, query_lower)
            return
        if query_lower.startswith("reset "):
            mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', query_lower)
            if mac_match and self.defense and hasattr(self.defense, 'posture'):
                mac = mac_match.group(0)
                self.defense.posture.reset_device(mac)
                self._reply(sender, f"Device {mac} reset to OBSERVE.")
                return

        # Check for training trigger
        if query_lower in ("trigger training", "train", "export training", "training status"):
            self._handle_training_command(sender, query_lower)
            return

        # Check for miner-related queries
        miner_result = self._handle_miner_query(sender, query_lower, query)
        if miner_result:
            miner_response, miner_speak = miner_result
            self._reply(sender, miner_response, speak=miner_speak)
            logger.info(f"Miner query from {sender}: {query[:60]} → answered directly")
            return

        # SSID-specific pre-emption: if the query asks about a specific network,
        # bypass the 7b model entirely and return filtered real data.
        # The model cannot reliably filter by SSID — it attributes all data to
        # whatever network name the user mentioned.
        ssid_preempt = self._preempt_ssid_query(query)
        if ssid_preempt:
            self._reply(sender, ssid_preempt)
            logger.info(f"SSID pre-emption for {sender}: {query[:60]}")
            return

        # Build defense context
        defense_ctx = "Defense loop not active."
        if self.defense and self.defense.is_running():
            try:
                defense_ctx = self.defense.get_recent_context()
            except Exception:
                defense_ctx = "Defense context unavailable."

        # Build tool list
        tool_list = _get_whitelisted_tool_descriptions()

        # Build system message with context
        system_msg = SYSTEM_PROMPT + "\n\n" + INQUIRY_PROMPT.format(
            tool_list=tool_list,
            defense_context=defense_ctx
        )

        # Add to memory and build message list
        self.memory.add_user(query, source=sender)
        messages = [{"role": "system", "content": system_msg}] + self.memory.get_messages()

        # First Ollama pass (with latency tracking)
        _t0 = time.time()
        response = _ollama_chat(messages, timeout=120)
        _latency_ms = int((time.time() - _t0) * 1000)
        if self.defense and hasattr(self.defense, 'diagnostics'):
            self.defense.diagnostics.record_ollama_latency(_latency_ms)

        if not response:
            # Ollama down — try direct tool execution as fallback
            response = self._fallback_response(query)
            self._reply(sender, response)
            return

        # Check for predefined chain template first
        chain_match = self._get_chain_template(query)
        if chain_match:
            chain_name, chain = chain_match
            final_response = self._execute_chain(chain, query, system_msg, chain_name=chain_name)
        else:
            # Multi-tool chain loop (up to MAX_INQUIRY_CHAIN_DEPTH)
            all_tool_results = []
            current_response = response

            for depth in range(MAX_INQUIRY_CHAIN_DEPTH):
                tool_name, tool_args = _parse_tool_call(current_response)

                if not tool_name:
                    # LLM is done — no more tool calls
                    break

                if tool_name not in INQUIRY_TOOL_WHITELIST:
                    logger.warning(f"Blocked non-whitelisted tool: {tool_name}")
                    tool_result = f"[DENIED] Tool '{tool_name}' is outside defense scope."
                else:
                    logger.info(f"Executing inquiry tool [{depth+1}/{MAX_INQUIRY_CHAIN_DEPTH}]: "
                                f"{tool_name}({tool_args})")
                    tool_result = execute_tool(tool_name, tool_args)

                all_tool_results.append((tool_name, tool_result))

                # Feed result back to Ollama for next step
                summary_prompt = (
                    "The tool returned the following data. "
                    "If you need more data to fully answer the question, call another tool. "
                    "If you have enough data, answer in plain English using W.O.P.R. voice. "
                    "CRITICAL RULES:\n"
                    "- Respond in 2-4 short declarative sentences. Use W.O.P.R. headers.\n"
                    "- Extract key numbers (client counts, IPs, MACs, statuses) and state them plainly.\n"
                    "- NEVER include raw JSON, curly braces, brackets, or key-value pairs in your response.\n"
                    "- NEVER paste or echo the tool output. Interpret the data and report findings.\n"
                    "- End with 'W.O.P.R. out.'\n\n"
                    f"TOOL: {tool_name}\nDATA:\n{str(tool_result)[:3000]}"
                )
                self.memory.add_assistant(current_response)
                self.memory.add_user(summary_prompt, source="system")
                messages = [{"role": "system", "content": system_msg}] + self.memory.get_messages()
                current_response = _ollama_chat(messages, timeout=120)

                if not current_response:
                    break

            # Determine final response
            if all_tool_results:
                final_response = current_response
                # Validate — if garbled or contains JSON, use structured fallback
                last_tool, last_result = all_tool_results[-1]
                _has_json = (
                    '": {' in (final_response or '') or
                    '": [' in (final_response or '') or
                    final_response and final_response.strip().startswith('{') or
                    final_response and '"status"' in final_response and '"num_user"' in final_response
                )
                if not final_response or len(final_response.strip()) < 20 or \
                   _has_json or \
                   'Tool output' in final_response or \
                   final_response.count('"tool"') > 0:
                    final_response = _format_tool_result(last_tool, last_result, query)

                # Post-tool SSID validation: if the query asked about a specific
                # network/SSID, and we have unifi_clients data, verify the model
                # actually filtered by SSID instead of reporting the full count.
                ssid_override = self._validate_ssid_response(query, all_tool_results, final_response)
                if ssid_override:
                    final_response = ssid_override
            else:
                # No tools called — the model may have hallucinated.
                # If the query looks like it needs real data, force a tool call.
                forced = self._force_tool_if_needed(query)
                if forced:
                    final_response = forced
                else:
                    final_response = current_response or response

        # Store in memory
        self.memory.add_assistant(final_response)

        # Post response to Blackboard + voice
        self._reply(sender, final_response)

        logger.info(f"Replied to {sender}: {final_response[:100]}")

        # Capture training example
        if self.learning:
            try:
                self.learning.capture(
                    context=f"Inquiry from {sender}: {query}",
                    reasoning=f"Processed via {'tool ' + tool_name if tool_name else 'direct inference'}",
                    action=f"tool={tool_name}, args={tool_args}" if tool_name else "direct_response",
                    observation=final_response[:500],
                    conclusion="Inquiry answered via Blackboard.",
                    category="tactical",
                    phase="defense"
                )
                self.learning.flush()
            except Exception:
                pass

    # Predefined chain templates for common composite queries
    # Forensic chains use "resolved_mac" as a sentinel — _execute_chain injects the
    # MAC resolved from step 1's device_db_query lookup result.
    _CHAIN_TEMPLATES = {
        "threat_assessment": [
            ("unifi_client_detail", lambda q: {"mac": re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', q.lower()).group(0)}),
            ("unifi_dpi", lambda q: {}),
            ("unifi_events", lambda q: {"limit": 10}),
            ("unifi_alerts", lambda q: {"limit": 10}),
        ],
        "network_overview": [
            ("unifi_clients", lambda q: {}),
            ("unifi_health", lambda q: {}),
            ("unifi_devices", lambda q: {}),
        ],
        "device_investigation": [
            ("device_db_query", lambda q: {"query_type": "lookup", "name": _extract_device_name(q)}),
            ("unifi_client_detail", "resolved_mac"),
            ("device_db_query", "resolved_mac_timeline"),
            ("unifi_events", lambda q: {"limit": 20}),
            ("unifi_dpi", lambda q: {}),
        ],
        "forensic_timeline": [
            ("device_db_query", lambda q: {"query_type": "lookup", "name": _extract_device_name(q)}),
            ("device_db_query", "resolved_mac_timeline_48"),
            ("device_db_query", "resolved_mac_correlate"),
            ("device_db_query", "resolved_mac_anomalies"),
            ("unifi_dpi", lambda q: {}),  # TARS Dev: DPI to identify protocols during anomaly window
        ],
        "lateral_movement_check": [
            ("device_db_query", lambda q: {"query_type": "lookup", "name": _extract_device_name(q)}),
            ("device_db_query", "resolved_mac_correlate_15"),
            ("unifi_events", lambda q: {"limit": 30}),
            ("unifi_alerts", lambda q: {"limit": 20}),
            ("unifi_firewall", lambda q: {}),  # TARS Dev: check firewall rules between correlated devices
        ],
        "incident_response": [
            # Full DFIR cycle: detect → timeline → correlate → evidence → alerts → report
            # Note: active response (kick/block) requires operator approval, not in this chain
            ("device_db_query", lambda q: {"query_type": "lookup", "name": _extract_device_name(q)}),
            ("unifi_client_detail", "resolved_mac"),
            ("device_db_query", "resolved_mac_timeline_48"),
            ("device_db_query", "resolved_mac_correlate"),
            ("unifi_dpi", lambda q: {}),
            ("unifi_alerts", lambda q: {"limit": 20}),
        ],
    }

    def _get_chain_template(self, query):
        """Match query to a predefined chain template.
        Returns (template_name, list of (tool_name, args_or_sentinel)) or None."""
        query_lower = query.lower()
        mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', query_lower)

        if ("threat assessment" in query_lower or "full report" in query_lower) and mac_match:
            return ("threat_assessment", self._CHAIN_TEMPLATES["threat_assessment"])

        if "network overview" in query_lower or "full network" in query_lower:
            return ("network_overview", self._CHAIN_TEMPLATES["network_overview"])

        # Forensic: incident response (TARS Dev suggestion — full DFIR cycle)
        if any(kw in query_lower for kw in ["incident response", "respond to",
                                              "contain and", "contain the",
                                              "isolate and investigate", "dfir", "full investigation"]):
            return ("incident_response", self._CHAIN_TEMPLATES["incident_response"])

        # Forensic: lateral movement
        if any(kw in query_lower for kw in ["lateral movement", "spreading from", "pivot from"]):
            return ("lateral_movement_check", self._CHAIN_TEMPLATES["lateral_movement_check"])

        # Forensic: timeline / history
        if any(kw in query_lower for kw in ["timeline for", "timeline of", "history for",
                                              "history of", "reconstruct"]):
            return ("forensic_timeline", self._CHAIN_TEMPLATES["forensic_timeline"])

        # Forensic: investigate / examine device (broadest match — last)
        if any(kw in query_lower for kw in ["investigate", "forensic", "examine",
                                              "what is", "what's", "look at",
                                              "inspect", "deep dive"]):
            # Guard: skip if query is about network/status/health (not a specific device)
            network_terms = {"network", "health", "status", "overview", "perimeter",
                            "traffic", "bandwidth", "all devices", "all clients",
                            "summary", "report", "fleet", "mining"}
            if any(nt in query_lower for nt in network_terms):
                return None
            # Only trigger if there's a plausible device name to resolve
            name = _extract_device_name(query)
            if name and len(name) > 2:
                return ("device_investigation", self._CHAIN_TEMPLATES["device_investigation"])

        return None

    def _execute_chain(self, chain, query, system_msg, chain_name=""):
        """Execute a predefined tool chain and summarize all results.
        Supports context propagation: forensic chains resolve a device name
        to a MAC in step 1, then inject that MAC into subsequent steps."""
        all_results = []
        resolved_mac = None  # Populated by step 1 of forensic chains
        resolved_ip = None   # TARS Dev #5: carry IP alongside MAC
        resolved_hostname = None
        resolved_network = None  # Network/VLAN segment

        for tool_name, tool_args_spec in chain:
            if tool_name not in INQUIRY_TOOL_WHITELIST:
                continue

            # Resolve args — handle sentinels for context propagation
            if callable(tool_args_spec):
                tool_args = tool_args_spec(query)
            elif isinstance(tool_args_spec, str) and tool_args_spec.startswith("resolved_mac"):
                if not resolved_mac:
                    logger.warning(f"Chain {chain_name}: no resolved MAC for {tool_name}, skipping")
                    continue
                # Parse sentinel: "resolved_mac" / "resolved_mac_timeline" / etc.
                if tool_args_spec == "resolved_mac":
                    tool_args = {"mac": resolved_mac}
                elif tool_args_spec == "resolved_mac_timeline":
                    tool_args = {"query_type": "timeline", "mac": resolved_mac, "hours": 24}
                elif tool_args_spec == "resolved_mac_timeline_48":
                    tool_args = {"query_type": "timeline", "mac": resolved_mac, "hours": 48}
                elif tool_args_spec == "resolved_mac_correlate":
                    tool_args = {"query_type": "correlate", "mac": resolved_mac, "window_minutes": 30}
                elif tool_args_spec == "resolved_mac_correlate_15":
                    tool_args = {"query_type": "correlate", "mac": resolved_mac, "window_minutes": 15}
                elif tool_args_spec == "resolved_mac_anomalies":
                    tool_args = {"query_type": "anomalies", "mac": resolved_mac, "days": 7}
                else:
                    logger.warning(f"Chain [{chain_name}]: unrecognized sentinel '{tool_args_spec}', "
                                   f"falling back to bare MAC")
                    tool_args = {"mac": resolved_mac}
            elif isinstance(tool_args_spec, dict):
                tool_args = tool_args_spec
            else:
                tool_args = {}

            logger.info(f"Chain [{chain_name}] tool: {tool_name}({tool_args})")
            result = execute_tool(tool_name, tool_args)
            all_results.append(f"=== {tool_name} ===\n{str(result)[:1000]}")

            # After step 1 lookup: extract resolved MAC, IP, hostname, network
            if not resolved_mac and tool_name == "device_db_query" and isinstance(tool_args, dict) \
                    and tool_args.get("query_type") == "lookup":
                try:
                    parsed = json.loads(result) if isinstance(result, str) else result
                    device_rec = None
                    if isinstance(parsed, list) and parsed:
                        device_rec = parsed[0]
                    elif isinstance(parsed, dict) and parsed.get("mac"):
                        device_rec = parsed
                    if device_rec:
                        candidate_mac = device_rec.get("mac", "")
                        # Validate MAC format before propagating
                        if candidate_mac and re.match(r'^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$', candidate_mac.lower()):
                            resolved_mac = candidate_mac
                        else:
                            logger.warning(f"Chain [{chain_name}]: invalid MAC from lookup: {candidate_mac!r}")
                        resolved_hostname = device_rec.get("hostname", "")
                        # Extract IP from ip_history (most recent)
                        ip_hist = device_rec.get("ip_history", "")
                        if ip_hist:
                            ips = [s.strip() for s in ip_hist.split(",") if s.strip()]
                            resolved_ip = ips[-1] if ips else ""
                        # Derive network segment from IP
                        if resolved_ip and "." in resolved_ip:
                            octets = resolved_ip.split(".")
                            if len(octets) == 4:
                                resolved_network = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                        logger.info(
                            f"Chain [{chain_name}]: resolved device — "
                            f"MAC={resolved_mac} IP={resolved_ip} "
                            f"host={resolved_hostname} net={resolved_network}"
                        )
                except Exception:
                    pass

            # If this was the first tool (device lookup) and MAC is still unresolved,
            # inject an error note so the summary reflects the failed lookup.
            if not resolved_mac and tool_name == "device_db_query" and isinstance(tool_args, dict) \
                    and tool_args.get("query_type") == "lookup":
                logger.warning(f"Chain [{chain_name}]: device lookup failed — no MAC resolved from result")
                all_results.append(f"=== LOOKUP ERROR ===\nDevice not found in knowledge base for query: {query}")

        # Single summarization pass over all results
        combined = "\n\n".join(all_results)

        # Forensic chains get a structured report prompt
        is_forensic = chain_name in ("device_investigation", "forensic_timeline",
                                      "lateral_movement_check", "incident_response")
        if is_forensic:
            # Build device context header from resolved fields
            device_ctx = ""
            if resolved_mac or resolved_ip or resolved_hostname:
                ctx_parts = []
                if resolved_hostname:
                    ctx_parts.append(f"Hostname: {resolved_hostname}")
                if resolved_mac:
                    ctx_parts.append(f"MAC: {resolved_mac}")
                if resolved_ip:
                    ctx_parts.append(f"IP: {resolved_ip}")
                if resolved_network:
                    ctx_parts.append(f"Network: {resolved_network}")
                device_ctx = "RESOLVED SUBJECT: " + " | ".join(ctx_parts) + "\n\n"

            summary_prompt = (
                "You are W.O.P.R. reporting a forensic investigation. "
                "Structure your report with these headers:\n"
                "SUBJECT: Device identification (hostname, MAC, IP, OUI)\n"
                "ACTIVITY: What the device is doing\n"
                "ANOMALIES: Anything unusual found\n"
                "TIMELINE: Key events in chronological order\n"
                "ASSESSMENT: Threat level and recommended action\n\n"
                "Use the data below. Include specific numbers, IPs, MACs. "
                "Do NOT output JSON or code.\n\n"
                f"{device_ctx}"
                f"QUERY: {query}\n\nDATA:\n{combined[:6000]}"
            )
        else:
            summary_prompt = (
                "Multiple tools were called to answer the query. "
                "Summarize ALL the data below into a comprehensive 3-5 sentence report. "
                "Include specific numbers, IPs, MACs, and hostnames. "
                "Do NOT output JSON or code.\n\n"
                f"QUERY: {query}\n\nDATA:\n{combined[:6000]}"
            )

        messages = [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": summary_prompt},
        ]
        response = _ollama_chat(messages, timeout=120)

        if not response or len(response.strip()) < 20 or response.strip().startswith('{'):
            # Structured fallback: return raw combined results
            response = f"INVESTIGATION REPORT — {chain_name}\n\n{combined[:4000]}\n\nW.O.P.R. out."

        # Capture forensic chain as training example for future fine-tuning
        if is_forensic and self.learning and len(response) > 50:
            try:
                tool_list_str = ", ".join(t for t, _ in chain)
                self.learning.capture(
                    context=f"Forensic chain [{chain_name}]: {query}",
                    reasoning=f"Chain tools: {tool_list_str}. "
                              f"Resolved: MAC={resolved_mac} IP={resolved_ip} "
                              f"Host={resolved_hostname} Net={resolved_network}",
                    action=f"forensic_chain:{chain_name}",
                    observation=response[:500],
                    conclusion=f"Forensic {chain_name} complete — "
                               f"{len(all_results)} tools executed.",
                    category="forensic",
                    phase="investigation"
                )
            except Exception:
                pass

        return response

    def _handle_miner_query(self, sender, query_lower, original_query):
        """Handle miner-related queries directly (no Ollama needed).
        Returns (response, speak) tuple or None if not a miner query."""
        mm = self.defense.miner_monitor if self.defense and hasattr(self.defense, 'miner_monitor') else None
        if not mm or not mm.enabled:
            return None

        # Fleet summary
        if any(w in query_lower for w in ["miner status", "fleet status", "fleet summary",
                                           "mining status", "hashrate", "miners"]):
            return (mm.format_fleet_report(), True)

        # Connectivity suggestions
        if any(w in query_lower for w in ["connectivity suggest", "why are miners",
                                           "miner dropping", "miner disconnect",
                                           "miner wifi", "miner connection"]):
            return (mm.get_connectivity_suggestions(), True)

        # Restart miner — matches: "restart miner X", "restart bitaxe X",
        # "restart rawi_bitaxe2", "restart X", "reboot X"
        if re.search(r'\brestart\b|\breboot\b', query_lower):
            # Extract identifier: try MAC first, then hostname after "restart"/"reboot"
            mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', query_lower)
            if mac_match:
                identifier = mac_match.group(0)
            else:
                # Strip the verb and optional "miner"/"bitaxe" prefix
                rest = re.sub(r'^.*?\b(?:restart|reboot)\b\s*', '', query_lower).strip()
                rest = re.sub(r'^(?:miner|bitaxe|nerdminer)\s+', '', rest).strip()
                identifier = rest.split()[0] if rest else ""

            if identifier:
                detail = mm.get_miner_detail(identifier)
                if detail and detail.get("ip"):
                    ip = detail["ip"]
                    mac = detail["mac"]
                    success = mm._restart_miner(ip, mac, f"Manual restart by {sender}")
                    if success:
                        return (f"RESTART INITIATED. {detail.get('hostname', mac)} at {ip}. W.O.P.R. out.", True)
                    return (f"RESTART FAILED. Could not reach {detail.get('hostname', mac)} at {ip}.", True)
                return (f"Miner '{identifier}' not found in fleet.", True)
            return ("Specify miner to restart. Example: restart miner rawi_bitaxe1", True)

        # Firmware update
        if re.search(r'\b(?:firmware|flash|ota)\b.*\b(?:update|upgrade|flash)\b'
                      r'|\b(?:update|upgrade|flash)\b.*\b(?:firmware|ota)\b', query_lower):
            # "firmware update <miner>", "flash firmware <miner>", "ota update <miner>"
            mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', query_lower)
            if mac_match:
                identifier = mac_match.group(0)
            else:
                rest = re.sub(
                    r'\b(?:firmware|flash|ota|update|upgrade|miner|bitaxe|all)\b', '', query_lower
                ).strip()
                identifier = rest.split()[0] if rest.split() else ""

            if not identifier:
                # "firmware update all" — fleet-wide
                if "all" in query_lower or "fleet" in query_lower:
                    versions = mm.get_fleet_firmware()
                    lines = ["FLEET FIRMWARE STATUS."]
                    for mac, info in sorted(versions.items(), key=lambda x: x[1].get("hostname", "")):
                        lines.append(
                            f"  {info.get('hostname', mac):25s} board={info.get('boardVersion', '?')} "
                            f"v={info.get('version', '?')} ASIC={info.get('ASICModel', '?')}")
                    available = mm.list_firmware()
                    if available:
                        lines.append(f"AVAILABLE BINARIES: {', '.join(available.keys())}")
                    else:
                        lines.append(f"NO FIRMWARE BINARIES in {mm.list_firmware.__self__.__class__.__name__} dir. "
                                     f"Place esp-miner-<boardVersion>.bin files to enable OTA.")
                    lines.append("Specify target: firmware update <hostname>. W.O.P.R. out.")
                    return ("\n".join(lines), False)
                return ("Specify target. Example: firmware update rawi_bitaxe1, "
                        "or firmware update all for fleet status. W.O.P.R. out.", True)

            detail = mm.get_miner_detail(identifier)
            if not detail or not detail.get("ip"):
                return (f"Miner '{identifier}' not found in fleet. W.O.P.R. out.", True)

            ip = detail["ip"]
            mac = detail["mac"]
            success, msg = mm.firmware_update(ip, mac)
            if success:
                return (f"OTA COMPLETE. {msg} W.O.P.R. out.", True)
            return (f"OTA FAILED. {msg} W.O.P.R. out.", True)

        # Firmware status / list
        if re.search(r'\bfirmware\b.*\b(?:status|version|list|check)\b'
                      r'|\b(?:version|check)\b.*\bfirmware\b', query_lower):
            versions = mm.get_fleet_firmware()
            lines = ["FLEET FIRMWARE STATUS."]
            for mac, info in sorted(versions.items(), key=lambda x: x[1].get("hostname", "")):
                lines.append(
                    f"  {info.get('hostname', mac):25s} board={info.get('boardVersion', '?')} "
                    f"v={info.get('version', '?')} ASIC={info.get('ASICModel', '?')}")
            available = mm.list_firmware()
            if available:
                lines.append(f"AVAILABLE BINARIES: {', '.join(available.keys())}")
            else:
                lines.append("No firmware binaries staged.")
            lines.append("W.O.P.R. out.")
            return ("\n".join(lines), False)

        # Set clock / frequency / voltage with safety validation
        if re.search(r'\bset\b.*\b(?:freq|frequency|clock|voltage|core.?voltage|mhz|mv)\b', query_lower):
            # Parse: "set frequency 525 on rawi_bitaxe1", "set clock 500mhz rawi_bitaxe2",
            #         "set voltage 1150 on bitaxe601", "set freq 525 voltage 1150 rawi_bitaxe1"
            mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', query_lower)
            freq_match = re.search(r'\b(?:freq(?:uency)?|clock)\s*[=:]?\s*(\d+)', query_lower)
            volt_match = re.search(r'\b(?:voltage|core.?voltage|cv)\s*[=:]?\s*(\d+)', query_lower)

            freq_val = int(freq_match.group(1)) if freq_match else None
            volt_val = int(volt_match.group(1)) if volt_match else None

            if freq_val is None and volt_val is None:
                return ("Specify values. Example: set frequency 525 on rawi_bitaxe1. W.O.P.R. out.", True)

            # Extract miner identifier
            if mac_match:
                identifier = mac_match.group(0)
            else:
                # Remove the command parts and numbers, find the hostname
                rest = re.sub(
                    r'\b(?:set|freq(?:uency)?|clock|voltage|core.?voltage|cv|mhz|mv|on|to)\b|\d+',
                    '', query_lower
                ).strip()
                identifier = rest.split()[0] if rest.split() else ""

            if not identifier:
                return ("Specify target miner. Example: set frequency 525 on rawi_bitaxe1. W.O.P.R. out.", True)

            detail = mm.get_miner_detail(identifier)
            if not detail or not detail.get("ip"):
                return (f"Miner '{identifier}' not found in fleet. W.O.P.R. out.", True)

            ip = detail["ip"]
            mac = detail["mac"]
            success, msg = mm.safe_set_clock(ip, mac, frequency=freq_val, core_voltage=volt_val)
            if success:
                return (f"CLOCK SET. {msg} W.O.P.R. out.", True)
            return (f"CLOCK SET REJECTED. {msg} W.O.P.R. out.", True)

        # Throttle miner
        if "throttle miner" in query_lower or "throttle bitaxe" in query_lower:
            mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', query_lower)
            if mac_match:
                identifier = mac_match.group(0)
            else:
                parts = query_lower.split("throttle")
                identifier = parts[-1].strip().split()[0] if len(parts) > 1 else ""
                if identifier in ("miner", "bitaxe"):
                    rest = parts[-1].strip().split()
                    identifier = rest[1] if len(rest) > 1 else ""

            if identifier:
                detail = mm.get_miner_detail(identifier)
                if detail and detail.get("ip"):
                    ip = detail["ip"]
                    mac = detail["mac"]
                    freq = detail.get("frequency", 0)
                    temp = detail.get("last_temp", 0)
                    if freq > 0:
                        if mm.is_throttled(mac):
                            return (f"{detail.get('hostname', mac)} already throttled. W.O.P.R. out.", True)
                        success = mm._throttle_miner(ip, mac, freq, temp)
                        if success:
                            return (f"THROTTLE INITIATED. {detail.get('hostname', mac)} at {ip}. "
                                    f"Frequency reduced. W.O.P.R. out.", True)
                        return (f"THROTTLE FAILED. Could not reach {detail.get('hostname', mac)} at {ip}. W.O.P.R. out.", True)
                    return (f"No frequency data for {detail.get('hostname', mac)}. Cannot throttle. W.O.P.R. out.", True)
                return (f"Miner '{identifier}' not found in fleet. W.O.P.R. out.", True)
            return ("Specify miner to throttle. Example: throttle miner rawi_bitaxe1. W.O.P.R. out.", True)

        # Restore miner
        if "restore miner" in query_lower or "restore bitaxe" in query_lower or "unthrottle miner" in query_lower:
            mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', query_lower)
            if mac_match:
                identifier = mac_match.group(0)
            else:
                parts = query_lower.split("restore") if "restore" in query_lower else query_lower.split("unthrottle")
                identifier = parts[-1].strip().split()[0] if len(parts) > 1 else ""
                if identifier in ("miner", "bitaxe"):
                    rest = parts[-1].strip().split()
                    identifier = rest[1] if len(rest) > 1 else ""

            if identifier:
                detail = mm.get_miner_detail(identifier)
                if detail and detail.get("ip"):
                    ip = detail["ip"]
                    mac = detail["mac"]
                    temp = detail.get("last_temp", 0)
                    if mm.is_throttled(mac):
                        success = mm._restore_miner(ip, mac, temp)
                        if success:
                            return (f"RESTORE INITIATED. {detail.get('hostname', mac)} at {ip}. "
                                    f"Original frequency restored. W.O.P.R. out.", True)
                        return (f"RESTORE FAILED. Could not reach {detail.get('hostname', mac)} at {ip}. W.O.P.R. out.", True)
                    return (f"{detail.get('hostname', mac)} is not throttled. W.O.P.R. out.", True)
                return (f"Miner '{identifier}' not found in fleet. W.O.P.R. out.", True)
            return ("Specify miner to restore. Example: restore miner rawi_bitaxe1. W.O.P.R. out.", True)

        # Miner/worker detail
        if any(w in query_lower for w in ["miner detail", "miner info",
                                           "worker detail", "worker info"]):
            cleaned = query_lower
            for phrase in ["miner detail", "miner info", "worker detail", "worker info"]:
                cleaned = cleaned.replace(phrase, "")
            parts = cleaned.strip().split()
            identifier = parts[0] if parts else ""
            if not identifier:
                mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', query_lower)
                if mac_match:
                    identifier = mac_match.group(0)
            if identifier:
                detail = mm.get_miner_detail(identifier)
                if detail:
                    return (self._format_miner_detail(detail), True)
                return (f"Miner/worker '{identifier}' not found.", True)
            return ("Specify miner. Example: miner detail nerdqaxe+ or worker detail nerdminer1", True)

        # List all pool workers — no voice (too long/tabular)
        if any(w in query_lower for w in ["pool workers", "all workers", "worker list",
                                           "list miners", "list workers"]):
            db = self.defense.device_db if self.defense else None
            if db:
                workers = db.get_all_pool_workers()
                if workers:
                    lines = [f"POOL WORKERS. {len(workers)} registered."]
                    for w in workers:
                        hr = w.get("hashrate_1h", 0)
                        from miner_monitor import _format_hashrate
                        lines.append(
                            f"  {w['worker_name']}: {_format_hashrate(hr)} "
                            f"({w.get('worker_type', '?')}, {w.get('status', '?')})")
                    lines.append("W.O.P.R. out.")
                    return ("\n".join(lines), False)
            return ("No pool worker data available yet.", False)

        return None  # Not a miner query

    def _format_miner_detail(self, detail):
        """Format miner/worker detail into W.O.P.R. response string."""
        from miner_monitor import _format_hashrate

        # Pool worker record (no AxeOS data)
        if "worker_name" in detail and "mac" not in detail.get("pool", detail):
            wn = detail.get("worker_name", "unknown")
            return (
                f"POOL WORKER. {wn}. "
                f"Type: {detail.get('worker_type', 'unknown')}. "
                f"Status: {detail.get('status', 'unknown')}. "
                f"Hashrate 5m: {_format_hashrate(detail.get('hashrate_5m', 0))}. "
                f"Hashrate 1h: {_format_hashrate(detail.get('hashrate_1h', 0))}. "
                f"Best difficulty: {detail.get('best_difficulty', 0):,.0f}. "
                f"MAC: {detail.get('mac', 'unlinked')}. "
                f"W.O.P.R. out."
            )

        # AxeOS miner record (possibly merged with pool data)
        hostname = detail.get("hostname", "unknown")
        mac = detail.get("mac", "unknown")
        parts = [
            f"MINER DETAIL. {hostname} ({mac}).",
            f"IP: {detail.get('ip', 'unknown')}.",
            f"Status: {detail.get('status', 'unknown')}.",
            f"Hashrate: {detail.get('last_hashrate', 0):.1f} GH/s "
            f"(avg {detail.get('avg_hashrate', 0):.1f}).",
            f"Temp: {detail.get('last_temp', 0):.1f}C (max {detail.get('max_temp', 0):.1f}C).",
            f"Best diff: {detail.get('best_diff', '0')}.",
            f"WiFi RSSI: {detail.get('wifi_rssi', 0)}dBm.",
            f"Uptime: {detail.get('uptime_seconds', 0) // 3600}h.",
            f"Restarts: {detail.get('restart_count', 0)}.",
            f"Shares: {detail.get('shares_accepted', 0)} accepted, "
            f"{detail.get('shares_rejected', 0)} rejected.",
        ]

        # Append pool data if merged
        pool = detail.get("pool")
        if pool:
            parts.append(
                f"Pool worker: {pool.get('worker_name', '?')}. "
                f"Pool 1h: {_format_hashrate(pool.get('hashrate_1h', 0))}. "
                f"Pool best: {pool.get('best_difficulty', 0):,.0f}."
            )

        # Show throttle status if applicable
        mm = self.defense.miner_monitor if self.defense and hasattr(self.defense, 'miner_monitor') else None
        if mm and mm.is_throttled(mac):
            state = mm._throttled_miners.get(mac, {})
            parts.append(
                f"THROTTLED. Original freq: {state.get('original_freq', '?')} MHz. "
                f"Reduced freq: {state.get('throttled_freq', '?')} MHz."
            )

        parts.append("W.O.P.R. out.")
        return " ".join(parts)

    def _handle_training_command(self, sender, command):
        """Handle training pipeline commands."""
        from learning import TrainingPipeline
        pipeline = TrainingPipeline(self.blackboard)

        if command == "training status":
            status = pipeline.get_status()
            response = (
                f"TRAINING STATUS. "
                f"Export files: {status['export_files']}. "
                f"Total examples: {status['total_examples']}. "
                f"Min required: {status['min_required']}. "
                f"Ready: {'YES' if status['ready_to_train'] else 'NO'}. "
                f"W.O.P.R. out."
            )
        elif command in ("trigger training", "train", "export training"):
            filepath, count = pipeline.export_training_data()
            if filepath:
                response = (
                    f"TRAINING EXPORT COMPLETE. "
                    f"Exported {count} examples to {filepath}. "
                    f"Manual LoRA fine-tune step required. W.O.P.R. out."
                )
            else:
                response = (
                    f"TRAINING EXPORT. Insufficient data ({count} examples, "
                    f"need {pipeline.min_examples}). Continue accumulating. W.O.P.R. out."
                )
        else:
            response = "Unknown training command."

        self._reply(sender, response)
        logger.info(f"Training command from {sender}: {command}")

    def _handle_posture_command(self, sender, command):
        """Handle posture approval commands: approve isolate/block <mac>."""
        if not self.defense or not hasattr(self.defense, 'posture'):
            self._reply(sender, "Defense posture system not active.")
            return

        mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', command)
        if not mac_match:
            self._reply(sender, "No valid MAC address found in command.")
            return

        mac = mac_match.group(0)
        success, action, desc = self.defense.posture.approve_action(mac, approved_by=sender)

        if success:
            response = f"APPROVED. {desc}. Posture action executed."
        else:
            response = f"Action failed or no pending action. {desc}"

        self._reply(sender, response)
        logger.info(f"Posture command from {sender}: {command} → {response}")

    def _preempt_ssid_query(self, query):
        """If the query asks about a specific SSID, get real filtered data directly.
        Returns a response string or None if the query is not SSID-specific."""
        target_ssid = self._extract_target_ssid(query)
        if not target_ssid:
            return None

        # Verify the query actually asks for analysis/info about this network
        q = query.lower()
        analysis_keywords = ["analyze", "analyse", "scan", "audit", "inspect",
                             "check", "report", "show", "tell me about", "what is",
                             "how many", "status", "devices on", "clients on"]
        if not any(a in q for a in analysis_keywords):
            return None

        logger.info(f"[SSID-PREEMPT] Handling SSID-specific query directly: {target_ssid}")

        from tools import unifi_get_clients
        try:
            clients_raw = unifi_get_clients()
        except Exception as e:
            logger.error(f"[SSID-PREEMPT] Failed to get client data: {e}")
            return None

        result = self._filter_clients_by_ssid(clients_raw, target_ssid)
        if result is None:
            return None

        filtered, total = result
        return self._build_ssid_report(target_ssid, filtered, total)

    def _extract_target_ssid(self, query):
        """Extract a target SSID name from a query, if present."""
        q = query.lower()
        # Check known SSIDs first (exact match)
        from config import KNOWN_SSIDS
        for ssid in KNOWN_SSIDS:
            if ssid.lower() in q:
                return ssid

        # Extract from "the X network" / "X network" / "X ssid" / "X wifi" patterns
        import re
        patterns = [
            r'(?:the\s+)?(\w[\w.-]*)\s+(?:network|ssid|wifi|wireless)',
            r'(?:analyze|analyse|scan|check|inspect)\s+(?:the\s+)?(\w[\w.-]*)\s+',
        ]
        for pattern in patterns:
            m = re.search(pattern, q)
            if m:
                name = m.group(1)
                # Exclude generic words that aren't SSIDs
                skip = {"the", "this", "my", "our", "your", "a", "all", "entire",
                        "full", "whole", "main", "home", "guest", "current", "unifi",
                        "and", "or", "any", "each", "every", "no", "what", "which",
                        "that", "their", "its", "on", "of", "for", "is", "are",
                        "perimeter", "status", "health", "give", "report"}
                if name not in skip:
                    return name

        return None

    def _filter_clients_by_ssid(self, clients_raw, target_ssid):
        """Filter a unifi_clients result by SSID, return (filtered, total) or None."""
        try:
            clients = json.loads(clients_raw) if isinstance(clients_raw, str) else clients_raw
            if not isinstance(clients, list):
                clients = clients.get("data", clients.get("clients", []))
        except (json.JSONDecodeError, AttributeError, TypeError):
            return None

        if not isinstance(clients, list) or not clients:
            return None

        filtered = [c for c in clients if isinstance(c, dict) and
                    target_ssid.lower() in (c.get("essid", "") or c.get("network", "") or "").lower()]
        return filtered, len(clients)

    def _build_ssid_report(self, target_ssid, filtered, total):
        """Build a factual SSID analysis report from filtered client data."""
        count = len(filtered)
        if count > 0:
            devices = []
            for c in filtered[:15]:
                name = c.get("hostname", c.get("name", "unknown"))
                mac = c.get("mac", "?")
                ip = c.get("ip", "?")
                devices.append(f"{name} ({mac}, {ip})")
            device_list = "; ".join(devices)
            return (
                f"NETWORK ANALYSIS: {target_ssid}. "
                f"{count} clients on this network (of {total} total across all networks). "
                f"Devices: {device_list}. "
                f"W.O.P.R. out."
            )
        return (
            f"NETWORK ANALYSIS: {target_ssid}. "
            f"No clients currently connected to this SSID. "
            f"{total} total clients across all networks. "
            f"W.O.P.R. out."
        )

    def _validate_ssid_response(self, query, all_tool_results, model_response):
        """Post-tool validation: if query is about a specific SSID and model used
        unifi_clients, verify the model correctly filtered by SSID.
        Returns override response or None."""
        target_ssid = self._extract_target_ssid(query)
        if not target_ssid:
            return None

        # Check if unifi_clients was called in the chain
        used_clients = any(t == "unifi_clients" for t, _ in all_tool_results)
        if not used_clients:
            return None

        # Get FRESH untruncated client data for accurate filtering
        from tools import unifi_get_clients
        try:
            clients_raw = unifi_get_clients()
        except Exception:
            return None

        result = self._filter_clients_by_ssid(clients_raw, target_ssid)
        if result is None:
            return None

        filtered, total = result
        actual_count = len(filtered)

        # Check if model response is plausibly wrong — claims near-total count
        # for a specific SSID, or ignores the SSID entirely
        import re
        numbers_in_response = re.findall(r'\b(\d+)\s*(?:active\s+)?clients?\b', model_response.lower())
        for num_str in numbers_in_response:
            claimed = int(num_str)
            if claimed > total * 0.8 and actual_count < total * 0.8:
                logger.warning(
                    f"[ANTI-HALLUCINATION] Model claimed {claimed} clients on {target_ssid}, "
                    f"actual is {actual_count}/{total}. Overriding."
                )
                return self._build_ssid_report(target_ssid, filtered, total)

        # Also override if the model didn't mention the target SSID at all
        if target_ssid.lower() not in model_response.lower():
            logger.warning(
                f"[ANTI-HALLUCINATION] Model ignored SSID '{target_ssid}' in response. Overriding."
            )
            return self._build_ssid_report(target_ssid, filtered, total)

        return None

    def _force_tool_if_needed(self, query):
        """If the model didn't call a tool but the query needs real data, force one.
        Returns a tool-based response string, or None if no tool is appropriate."""
        q = query.lower()

        # Queries about specific networks/SSIDs
        ssid_keywords = ["network", "ssid", "wifi", "wireless", "vlan"]
        analysis_keywords = ["analyze", "analyse", "scan", "audit", "inspect",
                             "check", "report", "show", "tell me about", "what is"]
        needs_data = any(a in q for a in analysis_keywords) and any(s in q for s in ssid_keywords)

        # Also catch "analyze <name>" where name isn't a miner keyword
        if not needs_data and any(a in q for a in analysis_keywords):
            miner_words = ["miner", "fleet", "hashrate", "bitaxe", "nerdminer", "worker"]
            if not any(m in q for m in miner_words):
                needs_data = True

        if not needs_data:
            return None

        logger.info(f"[ANTI-HALLUCINATION] Model skipped tool call for data query: {query[:80]}")

        # Get client data (use raw function to avoid truncation)
        from tools import unifi_get_clients
        try:
            clients_raw = unifi_get_clients()
        except Exception:
            clients_raw = None
        if not clients_raw or "error" in str(clients_raw).lower():
            return "SENSOR ERROR. UniFi client data unavailable. Cannot analyze."

        # Check for SSID-specific query
        target_ssid = self._extract_target_ssid(query)
        if target_ssid:
            result = self._filter_clients_by_ssid(clients_raw, target_ssid)
            if result:
                filtered, total = result
                return self._build_ssid_report(target_ssid, filtered, total)

        # No specific SSID — general network overview
        try:
            clients = json.loads(clients_raw) if isinstance(clients_raw, str) else clients_raw
            if not isinstance(clients, list):
                clients = clients.get("data", clients.get("clients", []))
            count = len(clients) if isinstance(clients, list) else "?"
        except Exception:
            count = "?"
        health_raw = execute_tool("unifi_health", {})
        return (
            f"NETWORK OVERVIEW. {count} clients connected. "
            f"Health data: {str(health_raw)[:1500]}. "
            f"W.O.P.R. out."
        )

    def _fallback_response(self, query):
        """When Ollama is unavailable, try direct tool execution based on query."""
        query_lower = query.lower()

        # MAC address pattern
        mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', query_lower)
        if mac_match:
            mac = mac_match.group(0)
            result = execute_tool("unifi_client_detail", {"mac": mac})
            return f"CLIENT DETAIL ({mac}):\n{result[:2000]}"

        if any(w in query_lower for w in ["how many", "client", "connected", "devices"]):
            result = execute_tool("unifi_clients", {})
            return f"CLIENT LIST:\n{result[:2000]}"

        if any(w in query_lower for w in ["health", "status", "network"]):
            result = execute_tool("unifi_health", {})
            return f"NETWORK HEALTH:\n{result[:2000]}"

        if any(w in query_lower for w in ["alert", "threat", "ids", "ips"]):
            result = execute_tool("unifi_alerts", {"limit": 10})
            return f"RECENT ALERTS:\n{result[:2000]}"

        if any(w in query_lower for w in ["event", "disconnect", "roam"]):
            result = execute_tool("unifi_events", {"limit": 10})
            return f"RECENT EVENTS:\n{result[:2000]}"

        # Forensic: investigate a device by name (Ollama bypass)
        if any(w in query_lower for w in ["investigate", "forensic", "examine", "timeline",
                                            "history", "lateral movement", "what happened",
                                            "show history", "deep dive", "look at",
                                            "what is", "what's"]):
            name = _extract_device_name(query)
            if name and len(name) > 2:
                result = execute_tool("device_db_query", {"query_type": "lookup", "name": name})
                return f"FORENSIC LOOKUP ({name}):\n{result[:2000]}"

        # Default: return defense context
        if self.defense and self.defense.is_running():
            return self.defense.get_recent_context()
        return "Insufficient data. Ollama offline, no matching tool pattern."


class JoshuaAgent:
    """Network defense sentry — monitors UniFi, posts to Live Activity."""

    def __init__(self):
        self.blackboard = BlackboardClient()
        self.voice = VoiceClient()
        self.learning = LearningEngine(self.blackboard)
        self.defense = UniFiDefenseLoop(self.blackboard, self.voice, self.learning)
        self.inbox = InboxHandler(self.blackboard, self.voice, self.learning, self.defense)
        self.running = False

    def run(self):
        """Main loop — start defense thread, then idle with heartbeat."""
        logger.info(f"=== {AGENT_NAME} starting (defense sentry mode) ===")
        logger.info(f"Blackboard: {self.blackboard.base_url}")

        # Check services
        if not self.blackboard.is_available():
            logger.error("Blackboard is not reachable. Waiting...")

        self.voice.check_available()
        logger.info(f"Voice: {'enabled' if self.voice.enabled else 'disabled'}")

        # Start UniFi Network Defense loop (background thread)
        try:
            self.defense.start()
            defense_status = "active"
        except Exception as e:
            logger.warning(f"UniFi Defense loop failed to start: {e}")
            defense_status = "inactive"

        # Start inbox handler (reactive queries via Blackboard)
        try:
            self.inbox.start()
            inbox_status = "active"
        except Exception as e:
            logger.warning(f"Inbox handler failed to start: {e}")
            inbox_status = "inactive"

        # Announce presence
        self.blackboard.send_message(
            to_agent="operator",
            content=f"{AGENT_NAME} online. Defense sentry mode. "
                    f"Voice: {'active' if self.voice.enabled else 'inactive'}, "
                    f"Network Defense: {defense_status}, "
                    f"Inquiry Handler: {inbox_status}.",
            message_type="status"
        )

        self.running = True

        # Main loop — monitor defense + inbox thread health
        while self.running:
            try:
                # Check if defense thread is still alive
                if not self.defense.is_running():
                    logger.error("Defense loop thread died — restarting")
                    try:
                        self.defense.start()
                    except Exception as e:
                        logger.error(f"Defense restart failed: {e}")

                # Check if inbox thread is still alive
                if not self.inbox.is_running():
                    logger.error("Inbox handler thread died — restarting")
                    try:
                        self.inbox.start()
                    except Exception as e:
                        logger.error(f"Inbox restart failed: {e}")

                time.sleep(POLL_INTERVAL)

            except KeyboardInterrupt:
                logger.info("Interrupted by user")
                self.running = False
            except Exception as e:
                logger.error(f"Agent loop error: {e}", exc_info=True)
                time.sleep(POLL_INTERVAL)

        # Shutdown
        self.inbox.stop()
        self.defense.stop()
        logger.info(f"=== {AGENT_NAME} shutdown ===")
        self.blackboard.send_message(
            to_agent="operator",
            content=f"{AGENT_NAME} going offline.",
            message_type="status"
        )

    def test(self):
        """Single inference test."""
        print(f"Testing {AGENT_NAME} with Ollama ({OLLAMA_MODEL})...")
        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "user", "content": "Professor Falken, status report."}
            ],
            "stream": False,
        }
        url = f"{OLLAMA_URL}/api/chat"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read())
                response = result.get("message", {}).get("content", "")
                print(f"\nJOSHUA: {response}")
                if self.voice.enabled:
                    self.voice.speak(response)
        except Exception as e:
            print(f"ERROR: {e}")

    def status(self):
        """Check all service connectivity."""
        print(f"=== {AGENT_NAME} Status ===")

        # Ollama
        try:
            url = f"{OLLAMA_URL}/api/tags"
            with urllib.request.urlopen(url, timeout=5) as resp:
                models = json.loads(resp.read())
                names = [m["name"] for m in models.get("models", [])]
                has_model = OLLAMA_MODEL in names or any(
                    OLLAMA_MODEL.split(":")[0] in n for n in names
                )
                print(f"Ollama: ONLINE ({len(names)} models, "
                      f"{OLLAMA_MODEL}: {'YES' if has_model else 'NOT FOUND'})")
        except Exception as e:
            print(f"Ollama: OFFLINE ({e})")

        # Blackboard
        bb_status = "ONLINE" if self.blackboard.is_available() else "OFFLINE"
        print(f"Blackboard: {bb_status} ({self.blackboard.base_url})")

        # Voice
        voice_status = "ONLINE" if self.voice.check_available() else "OFFLINE"
        print(f"Voice: {voice_status} ({self.voice.host}:{self.voice.port})")

        # UniFi MCP
        from config import UNIFI_MCP_URL
        try:
            url = f"{UNIFI_MCP_URL}/mcp"
            with urllib.request.urlopen(url, timeout=5):
                print(f"UniFi MCP: ONLINE ({UNIFI_MCP_URL})")
        except Exception:
            print(f"UniFi MCP: OFFLINE ({UNIFI_MCP_URL})")

        # Defense loop
        defense_alive = self.defense.is_running()
        print(f"Defense Loop: {'ACTIVE' if defense_alive else 'INACTIVE'}")

        # Diagnostics
        if hasattr(self.defense, 'diagnostics'):
            diag = self.defense.diagnostics.get_health_summary()
            print(f"Diagnostics: {diag['status']} — "
                  f"Ollama avg {diag['ollama_avg_ms']}ms, "
                  f"Cycle avg {diag['cycle_avg_ms']}ms")
            if diag['degraded_subsystems']:
                print(f"  Degraded: {', '.join(diag['degraded_subsystems'])}")

        # Device DB
        if hasattr(self.defense, 'device_db'):
            count = self.defense.device_db.get_device_count()
            print(f"Device DB: {count} devices tracked")


def _handle_signal(sig, frame):
    """Graceful shutdown on SIGINT/SIGTERM."""
    logger.info(f"Received signal {sig}, shutting down...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    agent = JoshuaAgent()

    if len(sys.argv) > 1:
        if sys.argv[1] == "--test":
            agent.test()
        elif sys.argv[1] == "--status":
            agent.status()
        else:
            print(f"Usage: python agent.py [--test|--status]")
    else:
        agent.run()
