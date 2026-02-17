"""
Local Joshua AI Agent — UniFi Network Defense Module
AI-augmented IDS layer using UniFi MCP on port 9600.

Polls UniFi MCP every 30s, maintains behavioral baselines,
classifies threats, auto-responds to CRITICAL, and reports
all detections to Blackboard + voice alerts.
"""

import json
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta

from config import UNIFI_MCP_URL, AGENT_NAME, MINER_TEMP_CRITICAL, ANOMALY_SUPPRESSION_WINDOW

logger = logging.getLogger(__name__)

# Threat severity thresholds
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Polling interval (seconds)
DEFENSE_POLL_INTERVAL = 30


class DiagnosticsMonitor:
    """Tracks subsystem health — Ollama latency, MCP failures, cycle times."""

    def __init__(self, blackboard=None):
        self.blackboard = blackboard
        self.ollama_latency_ms = deque(maxlen=50)
        self.poll_cycle_times_ms = deque(maxlen=50)
        self.tool_execution_errors = deque(maxlen=20)
        self._mcp_counters = defaultdict(lambda: {"success": 0, "fail": 0})
        self._degraded = set()
        self._last_hourly_report = datetime.now(timezone.utc)

    def record_ollama_latency(self, ms):
        """Record Ollama inference time in ms."""
        self.ollama_latency_ms.append(ms)
        if ms > 30000:
            self._mark_degraded("ollama", f"Latency {ms}ms exceeds 30s threshold")
        elif "ollama" in self._degraded and ms < 15000:
            self._degraded.discard("ollama")

    def record_mcp_result(self, service, success, error=None):
        """Record MCP call success/failure."""
        key = "success" if success else "fail"
        self._mcp_counters[service][key] += 1
        if not success:
            recent_fails = self._mcp_counters[service]["fail"]
            recent_ok = self._mcp_counters[service]["success"]
            total = recent_fails + recent_ok
            if total >= 5 and recent_fails / total > 0.5:
                self._mark_degraded(service, f"Failure rate {recent_fails}/{total}")
        elif service in self._degraded:
            # Recovering — clear after 3 consecutive successes
            if self._mcp_counters[service]["success"] >= 3:
                self._degraded.discard(service)

    def record_poll_cycle(self, duration_ms):
        """Record poll cycle duration."""
        self.poll_cycle_times_ms.append(duration_ms)

    def record_tool_error(self, tool, error):
        """Record a tool execution error."""
        self.tool_execution_errors.append({
            "tool": tool,
            "error": str(error)[:200],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def _mark_degraded(self, subsystem, reason):
        """Mark a subsystem as degraded and optionally report."""
        if subsystem not in self._degraded:
            self._degraded.add(subsystem)
            logger.warning(f"[DIAG] DEGRADED: {subsystem} — {reason}")
            if self.blackboard:
                try:
                    self.blackboard.post_finding(
                        title=f"Subsystem Degraded: {subsystem}",
                        severity="MEDIUM",
                        description=f"W.O.P.R. diagnostics: {subsystem} is degraded. {reason}",
                    )
                except Exception:
                    pass

    def get_health_summary(self):
        """Return current health status dict."""
        ollama_avg = (sum(self.ollama_latency_ms) / len(self.ollama_latency_ms)
                      if self.ollama_latency_ms else 0)
        cycle_avg = (sum(self.poll_cycle_times_ms) / len(self.poll_cycle_times_ms)
                     if self.poll_cycle_times_ms else 0)
        return {
            "degraded_subsystems": list(self._degraded),
            "ollama_avg_ms": round(ollama_avg),
            "ollama_samples": len(self.ollama_latency_ms),
            "cycle_avg_ms": round(cycle_avg),
            "cycle_samples": len(self.poll_cycle_times_ms),
            "mcp_counters": dict(self._mcp_counters),
            "recent_tool_errors": len(self.tool_execution_errors),
            "status": "DEGRADED" if self._degraded else "NOMINAL",
        }

    def periodic_check(self):
        """Called each poll cycle — posts hourly summary to Blackboard."""
        now = datetime.now(timezone.utc)
        if (now - self._last_hourly_report) >= timedelta(hours=1):
            self._last_hourly_report = now
            summary = self.get_health_summary()
            logger.info(f"[DIAG] Hourly: {summary['status']}, "
                        f"Ollama avg {summary['ollama_avg_ms']}ms, "
                        f"Cycle avg {summary['cycle_avg_ms']}ms, "
                        f"Errors: {summary['recent_tool_errors']}")
            # Diagnostics go to log only, not Live Activity (reduces clutter)
            # Only post to Live Activity if something is degraded
            if self.blackboard and summary.get('degraded_subsystems'):
                try:
                    self.blackboard.post_activity(
                        f"[DIAG] DEGRADED: {summary['degraded_subsystems']} — "
                        f"Ollama {summary['ollama_avg_ms']}ms avg, "
                        f"Cycle {summary['cycle_avg_ms']}ms avg",
                        entry_type="WARN"
                    )
                except Exception:
                    pass


class UniFiMCPClient:
    """HTTP client for UniFi MCP on localhost:9600 (streamable-http transport)."""

    def __init__(self, base_url=None):
        import urllib.request
        import urllib.error
        self.base_url = (base_url or UNIFI_MCP_URL).rstrip("/")
        self._urllib = urllib.request
        self._urllib_error = urllib.error
        self._session_id = None
        self._request_id = 0

    def _next_id(self):
        self._request_id += 1
        return self._request_id

    def _ensure_session(self):
        """Initialize MCP session if not yet established."""
        if self._session_id:
            return True
        url = f"{self.base_url}/mcp"
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "joshua_defense", "version": "1.0"}
            }
        }
        body = json.dumps(payload).encode()
        req = self._urllib.Request(
            url, data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"
            }
        )
        try:
            with self._urllib.urlopen(req, timeout=10) as resp:
                session_id = resp.headers.get("mcp-session-id")
                if session_id:
                    self._session_id = session_id
                    logger.info(f"UniFi MCP session established: {session_id[:12]}...")
                    return True
                logger.error("UniFi MCP initialize returned no session ID")
                return False
        except Exception as e:
            logger.error(f"UniFi MCP session init failed: {e}")
            return False

    def _call_tool(self, tool_name, arguments=None, timeout=15):
        """Call an MCP tool on the UniFi MCP server."""
        if not self._ensure_session():
            return None

        url = f"{self.base_url}/mcp"
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments or {}
            }
        }
        body = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        req = self._urllib.Request(url, data=body, method="POST", headers=headers)
        try:
            with self._urllib.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                # Parse SSE response
                for line in raw.split("\n"):
                    if line.startswith("data:"):
                        data = json.loads(line[5:].strip())
                        if "result" in data:
                            content = data["result"].get("content", [])
                            for c in content:
                                text = c.get("text", "")
                                try:
                                    return json.loads(text)
                                except (json.JSONDecodeError, ValueError):
                                    return {"text": text}
                        if "error" in data:
                            logger.error(f"UniFi MCP error: {data['error']}")
                            return None
                return None
        except Exception as e:
            # Session may have expired — reset and retry once
            if self._session_id and "400" in str(e):
                self._session_id = None
                return self._call_tool(tool_name, arguments, timeout)
            logger.error(f"UniFi MCP call failed: {tool_name} — {e}")
            return None

    # === Monitoring Tools (poll every 30s) ===

    def get_threat_summary(self):
        return self._call_tool("get_threat_summary")

    def get_alerts(self, limit=50):
        return self._call_tool("get_alerts", {"limit": limit})

    def get_events(self, limit=50):
        return self._call_tool("get_events", {"limit": limit})

    def get_syslog_events(self, limit=50):
        return self._call_tool("get_syslog_events", {"limit": limit})

    # === Investigation Tools (on-demand) ===

    def get_clients(self):
        return self._call_tool("get_clients", timeout=30)

    def get_client_detail(self, mac):
        return self._call_tool("get_client_detail", {"mac": mac})

    def search_clients(self, query):
        return self._call_tool("search_clients", {"query": query})

    def get_dpi_stats(self):
        return self._call_tool("get_dpi_stats", timeout=30)

    def get_devices(self):
        return self._call_tool("get_devices")

    def get_network_health(self):
        return self._call_tool("get_network_health")

    def get_firewall_rules(self):
        return self._call_tool("get_firewall_rules")

    # === Response Actions ===

    def block_client(self, mac, reason=""):
        return self._call_tool("block_client", {"mac": mac, "reason": reason})

    def unblock_client(self, mac):
        return self._call_tool("unblock_client", {"mac": mac})

    def kick_client(self, mac):
        return self._call_tool("kick_client", {"mac": mac})


class BehavioralBaseline:
    """Tracks normal network behavior and detects deviations."""

    def __init__(self, device_db=None):
        self.known_clients = {}       # mac -> {hostname, oui, first_seen, networks, ...}
        self.known_ouis = set()       # set of seen OUI prefixes
        self.client_count_history = []  # list of (timestamp, count)
        self.baseline_ready = False
        self._learning_cycles = 0
        self._min_learning_cycles = 10  # ~5 minutes of data before flagging
        self.db = device_db
        self._prev_macs = set()       # MACs seen in previous poll (for connect/disconnect)

        # Attempt instant baseline recovery from persistent DB
        if self.db:
            try:
                clients, ouis, count = self.db.load_baseline_state()
                if count >= 10:
                    self.known_clients = clients
                    self.known_ouis = ouis
                    self.baseline_ready = True
                    self._learning_cycles = self._min_learning_cycles
                    self._prev_macs = set(clients.keys())
                    logger.info(f"Baseline recovered from DB: {count} devices, "
                                f"{len(ouis)} OUIs — baseline READY immediately")
                elif count > 0:
                    self.known_clients = clients
                    self.known_ouis = ouis
                    self._prev_macs = set(clients.keys())
                    logger.info(f"Partial baseline from DB: {count} devices (need 10+ for ready)")
            except Exception as e:
                logger.warning(f"Baseline DB recovery failed: {e}")

    def update_client_list(self, clients):
        """Update baseline with current client list. Returns list of anomalies."""
        anomalies = []
        if not clients:
            return anomalies

        current_macs = set()
        now = datetime.now(timezone.utc).isoformat()

        for client in clients:
            mac = client.get("mac", "").lower()
            if not mac:
                continue

            current_macs.add(mac)
            hostname = client.get("hostname", client.get("name", "unknown"))
            oui = mac[:8]  # First 3 octets
            network = client.get("network", client.get("essid", "unknown"))

            if mac not in self.known_clients:
                # New device detected
                self.known_clients[mac] = {
                    "hostname": hostname,
                    "oui": oui,
                    "first_seen": now,
                    "networks": {network},
                    "connection_count": 1,
                }

                if self.baseline_ready:
                    anomaly = {
                        "type": "new_device",
                        "mac": mac,
                        "hostname": hostname,
                        "oui": oui,
                        "network": network,
                    }
                    # Unknown OUI is more suspicious
                    if oui not in self.known_ouis:
                        anomaly["unknown_oui"] = True
                    anomalies.append(anomaly)
            else:
                # Known device — check for network changes
                known = self.known_clients[mac]
                known["connection_count"] = known.get("connection_count", 0) + 1

                if network and network not in known.get("networks", set()):
                    known.setdefault("networks", set()).add(network)
                    if self.baseline_ready:
                        anomalies.append({
                            "type": "network_change",
                            "mac": mac,
                            "hostname": known["hostname"],
                            "old_networks": list(known["networks"] - {network}),
                            "new_network": network,
                        })

            self.known_ouis.add(oui)

        # Track client count over time
        self.client_count_history.append((now, len(current_macs)))
        if len(self.client_count_history) > 1000:
            self.client_count_history = self.client_count_history[-500:]

        # Check for population spikes
        if self.baseline_ready and len(self.client_count_history) > 5:
            avg_count = sum(c for _, c in self.client_count_history[-20:]) / min(20, len(self.client_count_history))
            current_count = len(current_macs)
            if current_count > avg_count * 1.5 and current_count - avg_count > 3:
                anomalies.append({
                    "type": "population_spike",
                    "current_count": current_count,
                    "average_count": round(avg_count, 1),
                })

        # Track connect/disconnect transitions for connection_log
        if self.db:
            new_macs = current_macs - self._prev_macs
            gone_macs = self._prev_macs - current_macs
            for mac in new_macs:
                client_info = self.known_clients.get(mac, {})
                network = ""
                ip = ""
                # Find this client's info from the current poll
                for c in clients:
                    if c.get("mac", "").lower() == mac:
                        network = c.get("network", c.get("essid", ""))
                        ip = c.get("ip", "")
                        break
                event = "reconnect" if mac in self.known_clients and self.known_clients[mac].get("connection_count", 0) > 1 else "connect"
                try:
                    self.db.log_connection(mac, event, network, ip)
                except Exception:
                    pass
            for mac in gone_macs:
                try:
                    self.db.log_connection(mac, "disconnect")
                except Exception:
                    pass
            self._prev_macs = current_macs.copy()

        # Persist all current clients to DB
        if self.db:
            for client in clients:
                mac = client.get("mac", "").lower()
                if not mac:
                    continue
                try:
                    self.db.upsert_device(
                        mac=mac,
                        hostname=client.get("hostname", client.get("name", "unknown")),
                        oui=mac[:8],
                        network=client.get("network", client.get("essid", "")),
                        ip=client.get("ip", ""),
                        tx_bytes=client.get("tx_bytes", 0),
                        rx_bytes=client.get("rx_bytes", 0),
                    )
                except Exception:
                    pass

        # Advance learning
        self._learning_cycles += 1
        if self._learning_cycles >= self._min_learning_cycles and not self.baseline_ready:
            self.baseline_ready = True
            logger.info(f"Behavioral baseline established: {len(self.known_clients)} clients, "
                        f"{len(self.known_ouis)} OUIs tracked")

        return anomalies

    def get_summary(self):
        """Get baseline summary."""
        return {
            "total_known_clients": len(self.known_clients),
            "known_ouis": len(self.known_ouis),
            "baseline_ready": self.baseline_ready,
            "learning_cycles": self._learning_cycles,
        }


class ThreatClassifier:
    """Classifies detected anomalies and determines response."""

    # Anomaly type -> base severity
    SEVERITY_MAP = {
        "new_device": SEVERITY_MEDIUM,
        "network_change": SEVERITY_LOW,
        "population_spike": SEVERITY_HIGH,
        "auth_failure_spike": SEVERITY_HIGH,
        "rogue_ap": SEVERITY_CRITICAL,
        "unusual_dpi": SEVERITY_MEDIUM,
        "ips_alert": SEVERITY_HIGH,
        "threat_detected": SEVERITY_HIGH,
        # Enhancement 2: new detector types
        "bandwidth_spike": SEVERITY_MEDIUM,
        "unusual_time": SEVERITY_LOW,
        "rapid_reconnect": SEVERITY_HIGH,
        "dpi_deviation": SEVERITY_MEDIUM,
        "ids_correlated": SEVERITY_HIGH,
        "rf_anomaly": SEVERITY_MEDIUM,
    }

    @classmethod
    def classify(cls, anomaly):
        """Classify an anomaly and return (severity, description, auto_respond)."""
        anomaly_type = anomaly.get("type", "unknown")
        base_severity = cls.SEVERITY_MAP.get(anomaly_type, SEVERITY_INFO)

        # Escalate new device with unknown OUI to HIGH
        if anomaly_type == "new_device" and anomaly.get("unknown_oui"):
            base_severity = SEVERITY_HIGH

        # Build description
        description = cls._describe(anomaly)

        # Auto-respond only on CRITICAL
        auto_respond = base_severity == SEVERITY_CRITICAL

        return base_severity, description, auto_respond

    @classmethod
    def _describe(cls, anomaly):
        """Generate human-readable description of anomaly."""
        atype = anomaly.get("type", "unknown")

        if atype == "new_device":
            oui_note = " (UNKNOWN MANUFACTURER)" if anomaly.get("unknown_oui") else ""
            return (f"New device joined network: {anomaly.get('hostname', 'unknown')} "
                    f"({anomaly.get('mac', '??:??:??')}) on {anomaly.get('network', 'unknown')}"
                    f"{oui_note}")

        elif atype == "network_change":
            return (f"Device {anomaly.get('hostname', 'unknown')} ({anomaly.get('mac', '')}) "
                    f"moved to network {anomaly.get('new_network', '?')}")

        elif atype == "population_spike":
            return (f"Client population spike: {anomaly.get('current_count', 0)} "
                    f"(average: {anomaly.get('average_count', 0)})")

        elif atype == "auth_failure_spike":
            return f"Authentication failure spike detected: {anomaly.get('count', 0)} failures"

        elif atype == "rogue_ap":
            return f"Rogue access point detected: {anomaly.get('ssid', 'unknown')} ({anomaly.get('bssid', '')})"

        elif atype == "bandwidth_spike":
            return (f"Bandwidth anomaly: {anomaly.get('hostname', 'unknown')} ({anomaly.get('mac', '')}) "
                    f"— {anomaly.get('ratio', '?')}x above baseline")

        elif atype == "unusual_time":
            return (f"Unusual connection time: {anomaly.get('hostname', 'unknown')} ({anomaly.get('mac', '')}) "
                    f"at hour {anomaly.get('hour', '?')}")

        elif atype == "rapid_reconnect":
            return (f"Rapid reconnection detected: {anomaly.get('hostname', 'unknown')} ({anomaly.get('mac', '')}) "
                    f"— {anomaly.get('count', '?')} reconnects in {anomaly.get('window', 10)} min "
                    f"(possible deauth attack)")

        elif atype == "dpi_deviation":
            return (f"DPI profile deviation: {anomaly.get('hostname', 'unknown')} ({anomaly.get('mac', '')}) "
                    f"— {anomaly.get('category', '?')} at {anomaly.get('ratio', '?')}x baseline")

        elif atype == "ids_correlated":
            return (f"IDS alert correlated to known device: {anomaly.get('hostname', 'unknown')} "
                    f"({anomaly.get('mac', '')}) — {anomaly.get('alert_count', 1)} alert(s)")

        elif atype == "rf_anomaly":
            return (f"RF anomaly on {anomaly.get('frequency', '?')} MHz: "
                    f"{anomaly.get('signal_count', '?')} signals in burst")

        return f"Anomaly detected: {json.dumps(anomaly)}"


# Response posture levels (escalation order)
POSTURE_OBSERVE = "OBSERVE"
POSTURE_ALERT = "ALERT"
POSTURE_ISOLATE = "ISOLATE"
POSTURE_BLOCK = "BLOCK"

_POSTURE_ORDER = [POSTURE_OBSERVE, POSTURE_ALERT, POSTURE_ISOLATE, POSTURE_BLOCK]
_POSTURE_TIMERS = {
    POSTURE_OBSERVE: 300,   # 5 min before auto-escalate
    POSTURE_ALERT: 600,     # 10 min
    POSTURE_ISOLATE: 1800,  # 30 min
}


class ResponsePosture:
    """Graduated response: OBSERVE → ALERT → ISOLATE → BLOCK.
    Replaces binary CRITICAL→auto-block with tiered escalation."""

    def __init__(self, unifi_client, blackboard, voice, device_db=None):
        self.unifi = unifi_client
        self.blackboard = blackboard
        self.voice = voice
        self.device_db = device_db
        # Per-device posture tracking: mac → {level, detections, first_detected, last_escalation}
        self._device_posture = {}
        self._pending_actions = {}  # mac → {action, reason} — awaiting operator approval

    def evaluate(self, mac, severity, anomaly):
        """Evaluate an anomaly and return the action to execute.
        Returns: (action, description) where action is one of:
        'log', 'alert', 'kick', 'block', 'pending_isolate', 'pending_block'
        """
        from config import ROGUE_AP_AUTO_BLOCK
        anomaly_type = anomaly.get("type", "unknown")
        now = time.time()

        # Get or create posture entry
        if mac not in self._device_posture:
            self._device_posture[mac] = {
                "level": POSTURE_OBSERVE,
                "detections": 0,
                "first_detected": now,
                "last_escalation": now,
            }

        posture = self._device_posture[mac]
        posture["detections"] += 1
        current_level = posture["level"]

        # Rogue AP bypasses approval — auto-escalate to BLOCK
        if anomaly_type == "rogue_ap" and ROGUE_AP_AUTO_BLOCK:
            posture["level"] = POSTURE_BLOCK
            self._execute_block(mac, f"Rogue AP auto-block: {anomaly_type}")
            return "block", f"Auto-blocked rogue AP {mac}"

        # Determine target level based on severity + detection count
        target = self._calc_target_level(severity, posture["detections"])

        # Only escalate (never de-escalate automatically)
        current_idx = _POSTURE_ORDER.index(current_level)
        target_idx = _POSTURE_ORDER.index(target)

        if target_idx <= current_idx:
            # No escalation needed — log at current level
            return self._action_for_level(current_level, mac, anomaly_type)

        # Escalate
        posture["level"] = target
        posture["last_escalation"] = now
        logger.warning(f"[POSTURE] {mac}: {current_level} → {target} "
                       f"(detections={posture['detections']}, severity={severity})")

        # Log to device DB
        if self.device_db:
            self.device_db.log_response_action(
                mac, f"escalate:{target}", anomaly_type, target)

        return self._action_for_level(target, mac, anomaly_type)

    def _calc_target_level(self, severity, detections):
        """Determine target posture based on severity and detection count."""
        if severity == SEVERITY_CRITICAL:
            if detections >= 2:
                return POSTURE_BLOCK
            return POSTURE_ISOLATE
        if severity == SEVERITY_HIGH:
            if detections >= 3:
                return POSTURE_ISOLATE
            if detections >= 1:
                return POSTURE_ALERT
            return POSTURE_OBSERVE
        if severity == SEVERITY_MEDIUM:
            if detections >= 3:
                return POSTURE_ALERT
            return POSTURE_OBSERVE
        return POSTURE_OBSERVE

    def _action_for_level(self, level, mac, anomaly_type):
        """Return (action_name, description) for a posture level."""
        if level == POSTURE_OBSERVE:
            return "log", f"Observing {mac}"
        elif level == POSTURE_ALERT:
            return "alert", f"ALERT on {mac} — {anomaly_type}"
        elif level == POSTURE_ISOLATE:
            self._pending_actions[mac] = {"action": "kick", "reason": anomaly_type}
            return "pending_isolate", f"Requesting approval to isolate {mac}"
        elif level == POSTURE_BLOCK:
            self._pending_actions[mac] = {"action": "block", "reason": anomaly_type}
            return "pending_block", f"Requesting approval to block {mac}"
        return "log", f"Unknown posture for {mac}"

    def _execute_block(self, mac, reason):
        """Execute a block action immediately (rogue AP bypass)."""
        try:
            self.unifi.block_client(mac, reason=reason)
            logger.warning(f"[POSTURE] BLOCK executed: {mac} — {reason}")
            if self.device_db:
                self.device_db.log_response_action(mac, "block", reason, POSTURE_BLOCK)
                self.device_db.set_trust_level(mac, "blocked", reason=reason, actor="wopr_auto")
        except Exception as e:
            logger.error(f"[POSTURE] Block failed for {mac}: {e}")

    def approve_action(self, mac, approved_by="operator"):
        """Operator approves a pending isolate/block action.
        Returns (success, action_taken, description)."""
        if mac not in self._pending_actions:
            return False, None, f"No pending action for {mac}"

        pending = self._pending_actions.pop(mac)
        action = pending["action"]
        reason = pending["reason"]

        try:
            if action == "kick":
                self.unifi.kick_client(mac)
                logger.warning(f"[POSTURE] ISOLATE approved by {approved_by}: {mac}")
                if self.device_db:
                    self.device_db.log_response_action(
                        mac, "isolate", reason, POSTURE_ISOLATE, approved_by)
                return True, "isolate", f"Isolated (kicked) {mac}"

            elif action == "block":
                self.unifi.block_client(mac, reason=f"Approved by {approved_by}: {reason}")
                logger.warning(f"[POSTURE] BLOCK approved by {approved_by}: {mac}")
                if self.device_db:
                    self.device_db.log_response_action(
                        mac, "block", reason, POSTURE_BLOCK, approved_by)
                    self.device_db.set_trust_level(mac, "blocked", reason=reason, actor=approved_by)
                return True, "block", f"Blocked {mac}"

        except Exception as e:
            logger.error(f"[POSTURE] Approved action failed for {mac}: {e}")
            return False, action, f"Action failed: {e}"

        return False, None, "Unknown action type"

    def reset_device(self, mac):
        """De-escalate a device back to OBSERVE."""
        if mac in self._device_posture:
            old = self._device_posture[mac]["level"]
            self._device_posture[mac] = {
                "level": POSTURE_OBSERVE,
                "detections": 0,
                "first_detected": time.time(),
                "last_escalation": time.time(),
            }
            self._pending_actions.pop(mac, None)
            logger.info(f"[POSTURE] Reset {mac}: {old} → OBSERVE")
            if self.device_db:
                self.device_db.log_response_action(mac, "reset", f"from {old}", POSTURE_OBSERVE)
            return True
        return False

    def check_escalation_timers(self):
        """Auto-escalate devices whose timers have expired without resolution."""
        now = time.time()
        for mac, posture in list(self._device_posture.items()):
            level = posture["level"]
            if level == POSTURE_BLOCK:
                continue  # Already at max
            timer = _POSTURE_TIMERS.get(level, 0)
            if timer and (now - posture["last_escalation"]) > timer:
                # Auto-escalate one level
                idx = _POSTURE_ORDER.index(level)
                if idx < len(_POSTURE_ORDER) - 1:
                    new_level = _POSTURE_ORDER[idx + 1]
                    posture["level"] = new_level
                    posture["last_escalation"] = now
                    logger.warning(f"[POSTURE] Timer escalation: {mac} {level} → {new_level}")
                    if self.device_db:
                        self.device_db.log_response_action(
                            mac, f"timer_escalate:{new_level}", "timeout", new_level)

    def get_posture_summary(self):
        """Return current posture state for all tracked devices."""
        return {
            mac: {
                "level": p["level"],
                "detections": p["detections"],
                "pending": mac in self._pending_actions,
            }
            for mac, p in self._device_posture.items()
        }


class FlipperMonitor:
    """Flipper Zero RF monitoring — WiFi AP scan + Sub-GHz anomaly detection."""

    def __init__(self, blackboard, voice):
        from config import (FLIPPER_MCP_URL, FLIPPER_WIFI_SCAN_INTERVAL,
                           FLIPPER_SUBGHZ_SCAN_INTERVAL)
        self.blackboard = blackboard
        self.voice = voice
        self._flipper_url = FLIPPER_MCP_URL
        self._wifi_interval = FLIPPER_WIFI_SCAN_INTERVAL
        self._subghz_interval = FLIPPER_SUBGHZ_SCAN_INTERVAL
        self._last_wifi_scan = 0
        self._last_subghz_scan = 0
        self._known_aps = {}  # BSSID → {ssid, first_seen, count}
        self._available = None  # None = unchecked

    def _check_available(self):
        """Probe Flipper MCP health."""
        from tools import execute_tool
        try:
            result = execute_tool("flipper_status", {})
            self._available = result is not None and "error" not in str(result).lower()
        except Exception:
            self._available = False
        return self._available

    def poll(self, poll_count, managed_aps):
        """Run periodic scans. Returns list of anomalies."""
        import time as _time
        now = _time.time()
        anomalies = []

        # Check availability periodically
        if self._available is None or poll_count % 100 == 0:
            if not self._check_available():
                return []

        if not self._available:
            return []

        # WiFi AP scan
        if (now - self._last_wifi_scan) >= self._wifi_interval:
            self._last_wifi_scan = now
            anomalies.extend(self._wifi_scan(managed_aps))

        # Sub-GHz scan
        if (now - self._last_subghz_scan) >= self._subghz_interval:
            self._last_subghz_scan = now
            anomalies.extend(self._subghz_scan())

        return anomalies

    def _wifi_scan(self, managed_aps):
        """Scan for WiFi APs and cross-reference against managed infrastructure."""
        from tools import execute_tool
        from config import KNOWN_SSIDS
        anomalies = []

        try:
            result = execute_tool("flipper_wifi_scan", {})
            if not result or isinstance(result, str) and "error" in result.lower():
                return []

            aps = result if isinstance(result, list) else []
            if isinstance(result, dict):
                aps = result.get("networks", result.get("aps", []))

            for ap in aps:
                if not isinstance(ap, dict):
                    continue
                bssid = ap.get("bssid", ap.get("mac", "")).lower()
                ssid = ap.get("ssid", ap.get("name", ""))

                if not bssid:
                    continue

                # Track AP
                if bssid not in self._known_aps:
                    self._known_aps[bssid] = {
                        "ssid": ssid, "first_seen": time.time(), "count": 1}
                else:
                    self._known_aps[bssid]["count"] += 1

                # Check for rogue: SSID matches known but BSSID is unmanaged
                if ssid in KNOWN_SSIDS and bssid not in managed_aps:
                    anomalies.append({
                        "type": "rogue_ap",
                        "bssid": bssid,
                        "ssid": ssid,
                        "source": "flipper_rf",
                        "rssi": ap.get("rssi", 0),
                    })

        except Exception as e:
            logger.debug(f"Flipper WiFi scan failed: {e}")

        return anomalies

    def _subghz_scan(self):
        """Listen on Sub-GHz frequencies for anomalous signal bursts."""
        from tools import execute_tool
        anomalies = []

        for freq in ["433920000", "315000000"]:  # 433.92 MHz, 315 MHz
            try:
                result = execute_tool("flipper_subghz_receive", {
                    "frequency": freq, "duration": 5
                })
                if not result:
                    continue

                signals = []
                if isinstance(result, list):
                    signals = result
                elif isinstance(result, dict):
                    signals = result.get("signals", result.get("captures", []))

                if len(signals) > 10:
                    anomalies.append({
                        "type": "rf_anomaly",
                        "frequency": int(freq) / 1000000,
                        "signal_count": len(signals),
                        "source": "flipper_subghz",
                    })

            except Exception as e:
                logger.debug(f"Flipper Sub-GHz scan on {freq} failed: {e}")

        return anomalies


class AutoReporter:
    """Generates hourly SITREPs and daily digests, posted to Blackboard."""

    def __init__(self, blackboard, device_db, baseline, miner_monitor=None):
        from config import HOURLY_REPORT_ENABLED, DAILY_REPORT_ENABLED, HOURLY_REPORT_INTERVAL
        self.blackboard = blackboard
        self.device_db = device_db
        self.baseline = baseline
        self.miner_monitor = miner_monitor
        self._hourly_enabled = HOURLY_REPORT_ENABLED
        self._daily_enabled = DAILY_REPORT_ENABLED
        self._interval = HOURLY_REPORT_INTERVAL
        self._last_hourly = datetime.now(timezone.utc)
        self._last_daily = datetime.now(timezone.utc)

    def check_and_report(self):
        """Called each poll cycle — generate reports when due."""
        now = datetime.now(timezone.utc)

        # Hourly SITREP
        if self._hourly_enabled and (now - self._last_hourly).total_seconds() >= self._interval:
            self._last_hourly = now
            self._generate_hourly()

        # Daily digest (check every hour, fire once per 24h)
        if self._daily_enabled and (now - self._last_daily).total_seconds() >= 86400:
            self._last_daily = now
            self._generate_daily()

    def _generate_hourly(self):
        """Hourly SITREP: client count, new devices, anomalies, fleet hashrate."""
        summary = self.baseline.get_summary()
        delta = self.device_db.get_hourly_delta(hours=1) if self.device_db else {}

        new_conns = len(delta.get("new_connections", []))
        disconns = len(delta.get("disconnections", []))

        report = (
            f"HOURLY SITREP. "
            f"Clients: {summary['total_known_clients']}. "
            f"OUIs: {summary['known_ouis']}. "
            f"Baseline: {'READY' if summary['baseline_ready'] else 'LEARNING'}. "
            f"New connections (1h): {new_conns}. "
            f"Disconnections (1h): {disconns}."
        )

        # Add fleet hashrate if miner monitor is active
        if self.miner_monitor and self.miner_monitor.enabled:
            fleet = self.miner_monitor.get_fleet_summary()
            report += (
                f" Mining fleet: {fleet['online']}/{fleet['total']} online, "
                f"{fleet['total_hashrate']:.1f} GH/s."
            )

        logger.info(f"[REPORT] {report}")
        try:
            self.blackboard.send_message(
                to_agent="operator",
                content=report,
                message_type="status"
            )
        except Exception as e:
            logger.error(f"Hourly report post failed: {e}")

    def _generate_daily(self):
        """Daily digest: comprehensive summary posted as finding."""
        if not self.device_db:
            return

        digest = self.device_db.get_daily_digest()
        trust = digest.get("trust_breakdown", {})

        report = (
            f"DAILY DIGEST. "
            f"Total devices tracked: {digest['total_tracked']}. "
            f"Active in 24h: {digest['active_24h']}. "
            f"Trust levels — "
            f"Trusted: {trust.get('trusted', 0)}, "
            f"Known: {trust.get('known', 0)}, "
            f"Unknown: {trust.get('unknown', 0)}, "
            f"Suspicious: {trust.get('suspicious', 0)}, "
            f"Blocked: {trust.get('blocked', 0)}. "
            f"Total alerts: {digest['total_alerts']}."
        )

        if self.miner_monitor and self.miner_monitor.enabled:
            fleet = self.miner_monitor.get_fleet_summary()
            report += (
                f" Mining fleet: {fleet['total']} miners, "
                f"{fleet['online']} online, "
                f"{fleet['total_hashrate']:.1f} GH/s total, "
                f"best difficulty {fleet['best_diff']}, "
                f"{fleet.get('total_restarts', 0)} restarts today."
            )

        logger.info(f"[REPORT] {report}")
        try:
            self.blackboard.post_finding(
                title="W.O.P.R. Daily Digest",
                severity="INFO",
                description=report,
            )
        except Exception as e:
            logger.error(f"Daily report post failed: {e}")


class UniFiDefenseLoop:
    """Main defense loop — polls UniFi MCP, detects threats, responds."""

    def __init__(self, blackboard, voice, learning=None):
        from device_db import DeviceKnowledgeBase
        self.unifi = UniFiMCPClient()
        self.blackboard = blackboard
        self.voice = voice
        self.learning = learning
        self.device_db = DeviceKnowledgeBase()
        self.baseline = BehavioralBaseline(device_db=self.device_db)
        self.classifier = ThreatClassifier()
        self.diagnostics = DiagnosticsMonitor(blackboard)
        self.posture = ResponsePosture(self.unifi, blackboard, voice, self.device_db)
        # Miner fleet monitor
        self.miner_monitor = None
        try:
            from miner_monitor import MinerMonitor
            from config import MINER_MONITORING_ENABLED
            if MINER_MONITORING_ENABLED:
                self.miner_monitor = MinerMonitor(self.device_db, blackboard, voice)
        except Exception as e:
            logger.warning(f"MinerMonitor init failed: {e}")
        # Automated reporting
        self.reporter = AutoReporter(blackboard, self.device_db, self.baseline, self.miner_monitor)
        # Flipper Zero RF monitor
        self.flipper_monitor = None
        try:
            from config import FLIPPER_MONITORING_ENABLED
            if FLIPPER_MONITORING_ENABLED:
                self.flipper_monitor = FlipperMonitor(blackboard, voice)
        except Exception as e:
            logger.debug(f"FlipperMonitor not enabled: {e}")
        self._thread = None
        self._running = False
        self._poll_count = 0
        self._recent_anomalies = deque(maxlen=10)
        # Anomaly suppression — {(mac, anomaly_type): {last_ts, count, last_severity}}
        self._anomaly_suppression = {}
        # Detection depth state
        self._managed_infrastructure = set()  # Managed AP MACs
        self._processed_alert_ids = set()     # Already-processed IDS alert IDs
        self._last_clients = []               # Cache last client list for detectors

    def start(self):
        """Start the defense loop in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="unifi-defense")
        self._thread.start()
        logger.info("UniFi Network Defense loop started (30s interval)")

    def stop(self):
        """Stop the defense loop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("UniFi Network Defense loop stopped")

    def _loop(self):
        """Main polling loop."""
        try:
            self.voice.speak("WOPR defense grid online. Monitoring network perimeter.")
        except Exception as e:
            logger.warning(f"Voice announcement failed: {e}")

        logger.info("Defense loop entering main cycle")

        while self._running:
            try:
                self._poll_cycle()
                self._poll_count += 1

                # Log every cycle for the first 3, then every 10th
                if self._poll_count <= 3 or self._poll_count % 10 == 0:
                    summary = self.baseline.get_summary()
                    logger.info(
                        f"Defense cycle #{self._poll_count}: "
                        f"{summary['total_known_clients']} clients, "
                        f"{summary['known_ouis']} OUIs, "
                        f"baseline={'READY' if summary['baseline_ready'] else 'LEARNING'}"
                    )
            except Exception as e:
                logger.error(f"Defense loop error: {e}", exc_info=True)

            time.sleep(DEFENSE_POLL_INTERVAL)

        logger.info("Defense loop exited main cycle")

    def _post_activity(self, activity, entry_type="CMD"):
        """Post to Blackboard activity log for Live Activity display."""
        try:
            from zoneinfo import ZoneInfo
            cst_stamp = datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S CST")
            self.blackboard.post_activity(f"[{cst_stamp}] {activity}", entry_type=entry_type)
        except Exception:
            pass  # Never let activity logging break the defense loop

    def _poll_cycle(self):
        """Single polling cycle."""
        _cycle_start = time.time()

        # 1. Get threat summary
        threat_summary = self.unifi.get_threat_summary()
        if threat_summary and not threat_summary.get("error"):
            self._process_threat_summary(threat_summary)
            self.diagnostics.record_mcp_result("unifi", True)
        elif threat_summary is None:
            self.diagnostics.record_mcp_result("unifi", False, "threat_summary returned None")

        # 2. Get current client list and update baseline
        clients_result = self.unifi.get_clients()
        if clients_result and not clients_result.get("error"):
            # UniFi MCP returns {"summary": ..., "clients": [...]}
            if isinstance(clients_result, list):
                clients = clients_result
            elif isinstance(clients_result, dict):
                clients = (clients_result.get("clients")
                           or clients_result.get("result")
                           or [])
            else:
                clients = []
            client_count = len(clients) if isinstance(clients, list) else 0
            self._last_clients = clients if isinstance(clients, list) else []
            anomalies = self.baseline.update_client_list(clients)
            for anomaly in anomalies:
                self._handle_anomaly(anomaly)

            # 2a. Bandwidth anomaly detection (every poll)
            if self.baseline.baseline_ready:
                self._detect_bandwidth_anomalies(clients)

            # 2b. Temporal pattern analysis (every poll)
            if self.baseline.baseline_ready:
                self._detect_temporal_anomalies(clients)

            # 2d. Connection frequency tracking (every poll — uses DB)
            if self.device_db:
                self._detect_rapid_reconnects()

            # Update miner IP mapping from client data
            if self.miner_monitor:
                self.miner_monitor.update_ip_map(clients)

        # 2c. Rogue AP detection (every 10th cycle = ~5 min)
        if self._poll_count % 10 == 0:
            self._detect_rogue_aps()

        # 3. Check alerts + IDS correlation (every 5th cycle = ~2.5 min)
        if self._poll_count % 5 == 0:
            alerts = self.unifi.get_alerts(limit=10)
            if alerts and not alerts.get("error"):
                self._process_alerts(alerts)

        # 2e. DPI profiling (every 20th cycle = ~10 min)
        if self._poll_count % 20 == 0 and self._poll_count > 0 and self.device_db:
            self._detect_dpi_deviations()

        # Mining fleet poll (every 2nd cycle = ~60s)
        if self.miner_monitor and self._poll_count % 2 == 0 and self._poll_count > 0:
            try:
                miner_anomalies = self.miner_monitor.poll_all()
                for anomaly in miner_anomalies:
                    # Miner anomalies are informational — don't feed into threat posture
                    atype = anomaly.get("type", "unknown")
                    mac = anomaly.get("mac", "")
                    hostname = anomaly.get("hostname", "unknown")
                    if atype == "miner_overheat":
                        self.voice.speak(
                            f"Mining alert. {hostname} overheating at {anomaly.get('temp', 0)} degrees.")
                        self.blackboard.post_finding(
                            title=f"Miner Overheat: {hostname}",
                            severity="HIGH",
                            description=f"{hostname} ({mac}) at {anomaly.get('temp')}C "
                                        f"(critical: {MINER_TEMP_CRITICAL}C). "
                                        f"Action: {anomaly.get('action', 'unknown')}",
                            host=mac,
                        )
                    elif atype == "miner_throttle":
                        self._post_activity(
                            f"[MINER] THROTTLE: {hostname} ({mac}) at "
                            f"{anomaly.get('temp', 0)}C — clock reduced",
                            entry_type="WARN")
                    elif atype == "miner_offline":
                        self._post_activity(
                            f"[MINER] OFFLINE: {hostname} ({mac})", entry_type="WARN")
                    elif atype == "miner_hashrate_drop":
                        self._post_activity(
                            f"[MINER] Hashrate drop: {hostname} at "
                            f"{anomaly.get('current', 0):.1f} GH/s "
                            f"(avg {anomaly.get('average', 0):.1f})", entry_type="WARN")
                    elif atype == "miner_stale_shares":
                        rssi = anomaly.get("wifi_rssi", 0)
                        rssi_note = f" (WiFi RSSI: {rssi} dBm)" if rssi else ""
                        self._post_activity(
                            f"[MINER] High reject rate: {hostname} at "
                            f"{anomaly.get('reject_pct', 0)}% stale shares"
                            f"{rssi_note}", entry_type="WARN")

                # Public Pool API poll (self-throttled to every PUBLIC_POOL_POLL_INTERVAL)
                pool_anomalies = self.miner_monitor.poll_public_pool()
                for anomaly in pool_anomalies:
                    atype = anomaly.get("type", "")
                    if atype == "pool_worker_offline":
                        worker = anomaly.get("worker", "unknown")
                        wtype = anomaly.get("worker_type", "unknown")
                        self._post_activity(
                            f"[POOL] Worker OFFLINE: {worker} ({wtype})", entry_type="WARN")

            except Exception as e:
                logger.error(f"Miner poll error: {e}")
                self.diagnostics.record_tool_error("miner_monitor", e)

        # 4. Defense cycle status — log only, not posted to Live Activity (reduces clutter)
        if self._poll_count % 10 == 0 and self._poll_count > 0:
            summary = self.baseline.get_summary()
            logger.info(f"[DEFENSE] Cycle #{self._poll_count}: "
                        f"{summary['total_known_clients']} clients tracked, "
                        f"{summary['known_ouis']} OUIs, "
                        f"baseline={'READY' if summary['baseline_ready'] else 'LEARNING'}")

        # 5. Post baseline established event (once)
        if self._poll_count == self.baseline._min_learning_cycles and self.baseline.baseline_ready:
            self._post_activity(
                f"Behavioral baseline established: {self.baseline.get_summary()['total_known_clients']} clients cataloged"
            )

        # 6. Check posture escalation timers
        self.posture.check_escalation_timers()

        # 7. Automated reporting
        self.reporter.check_and_report()

        # 8. Flipper Zero RF scans (if enabled)
        if self.flipper_monitor:
            anomalies = self.flipper_monitor.poll(self._poll_count, self._managed_infrastructure)
            for anomaly in anomalies:
                self._handle_anomaly(anomaly)

        # 9. Record cycle timing + run diagnostics check
        _cycle_ms = int((time.time() - _cycle_start) * 1000)
        self.diagnostics.record_poll_cycle(_cycle_ms)
        self.diagnostics.periodic_check()

    def _process_threat_summary(self, summary):
        """Process threat summary from UniFi MCP."""
        # Extract threat indicators
        threats = summary if isinstance(summary, list) else summary.get("result", [])
        if isinstance(threats, dict):
            threats = [threats]

        for threat in threats:
            if not isinstance(threat, dict):
                continue
            # Check for active IPS threats, anomaly scores, etc.
            threat_score = threat.get("threat_score", threat.get("score", 0))
            if threat_score and int(threat_score) > 0:
                self._handle_anomaly({
                    "type": "threat_detected",
                    "details": threat,
                    "score": threat_score,
                })

    def _process_alerts(self, alerts_result):
        """Process recent UniFi alerts with IDS/IPS correlation (2f)."""
        alerts = alerts_result if isinstance(alerts_result, list) else alerts_result.get("result", [])
        if isinstance(alerts, dict):
            alerts = [alerts]

        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            # Only process unhandled alerts
            if alert.get("handled") or alert.get("archived"):
                continue

            # Dedup by alert ID
            alert_id = alert.get("_id", alert.get("id", ""))
            if alert_id and alert_id in self._processed_alert_ids:
                continue
            if alert_id:
                self._processed_alert_ids.add(alert_id)
                # Keep set bounded
                if len(self._processed_alert_ids) > 500:
                    self._processed_alert_ids = set(list(self._processed_alert_ids)[-250:])

            alert_type = alert.get("key", alert.get("type", "unknown"))
            if "auth" in alert_type.lower() and "fail" in alert_type.lower():
                self._handle_anomaly({
                    "type": "auth_failure_spike",
                    "count": alert.get("count", 1),
                    "details": alert,
                })

            # 2f: IDS/IPS alert correlation — cross-reference with device DB
            if self.device_db:
                src_ip = alert.get("src_ip", alert.get("srcipAddress", {}).get("text", ""))
                dst_ip = alert.get("dst_ip", alert.get("dstipAddress", {}).get("text", ""))
                # Try to find the device by IP in known clients
                for check_ip in [src_ip, dst_ip]:
                    if not check_ip:
                        continue
                    for mac, info in self.baseline.known_clients.items():
                        # Check cached client data for IP match
                        for c in self._last_clients:
                            if isinstance(c, dict) and c.get("ip") == check_ip:
                                matched_mac = c.get("mac", "").lower()
                                if matched_mac:
                                    self.device_db.increment_alert_count(matched_mac)
                                    dev = self.device_db.get_device(matched_mac)
                                    alert_count = dev.get("alert_count", 1) if dev else 1
                                    sev_type = "ids_correlated"
                                    self._handle_anomaly({
                                        "type": sev_type,
                                        "mac": matched_mac,
                                        "hostname": info.get("hostname", "unknown"),
                                        "alert_type": alert_type,
                                        "alert_count": alert_count,
                                        "ip": check_ip,
                                    })
                                break
                        else:
                            continue
                        break

    def get_recent_context(self):
        """Return recent defense state for inquiry prompts."""
        summary = self.baseline.get_summary()
        baseline_str = (
            f"Baseline: {'READY' if summary['baseline_ready'] else 'LEARNING'}, "
            f"{summary['total_known_clients']} clients tracked, "
            f"{summary['known_ouis']} OUI prefixes, "
            f"{summary['learning_cycles']} cycles completed."
        )
        # Add diagnostics status
        diag = self.diagnostics.get_health_summary()
        diag_str = f"System: {diag['status']}"
        if diag['degraded_subsystems']:
            diag_str += f" (degraded: {', '.join(diag['degraded_subsystems'])})"

        # Add device DB stats
        db_str = ""
        if self.device_db:
            db_count = self.device_db.get_device_count()
            db_str = f"\nPersistent DB: {db_count} devices tracked."

        if self._recent_anomalies:
            anomaly_lines = "\n".join(f"  - {a}" for a in self._recent_anomalies)
            return (f"{baseline_str}\n{diag_str}{db_str}\n"
                    f"Recent anomalies ({len(self._recent_anomalies)}):\n{anomaly_lines}")
        return f"{baseline_str}\n{diag_str}{db_str}\nNo recent anomalies."

    def _is_suppressed(self, mac, anomaly_type, severity):
        """Check if anomaly should be suppressed (dedup within window).
        Returns (suppressed: bool, count: int) — count of suppressed occurrences."""
        key = (mac or "global", anomaly_type)
        now = time.time()
        entry = self._anomaly_suppression.get(key)

        if not entry:
            # First occurrence — not suppressed
            self._anomaly_suppression[key] = {
                "last_ts": now, "count": 1, "last_severity": severity
            }
            return False, 0

        elapsed = now - entry["last_ts"]
        severity_order = {SEVERITY_INFO: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2,
                          SEVERITY_HIGH: 3, SEVERITY_CRITICAL: 4}
        escalated = severity_order.get(severity, 0) > severity_order.get(entry["last_severity"], 0)

        if elapsed < ANOMALY_SUPPRESSION_WINDOW and not escalated:
            # Within suppression window and severity didn't escalate — suppress
            entry["count"] += 1
            return True, entry["count"]

        # Window expired or severity escalated — allow through
        suppressed_count = entry["count"] - 1  # how many were suppressed since last post
        self._anomaly_suppression[key] = {
            "last_ts": now, "count": 1, "last_severity": severity
        }
        return False, max(suppressed_count, 0)

    def _handle_anomaly(self, anomaly):
        """Classify anomaly, evaluate posture, take action, report.
        Includes deduplication — suppresses repeated (mac, type) within 15m window."""
        severity, description, _auto_respond = self.classifier.classify(anomaly)
        mac = anomaly.get("mac", "")
        anomaly_type = anomaly.get("type", "unknown")

        # Record for inquiry context (always, even if suppressed)
        self._recent_anomalies.append(f"[{severity}] {description}")

        # Check suppression — skip Blackboard/voice/activity if within window
        suppressed, suppressed_count = self._is_suppressed(mac, anomaly_type, severity)
        if suppressed:
            logger.debug(f"[SUPPRESSED x{suppressed_count}] [{severity}] {description}")
            # Still evaluate posture (escalation timers need continuous input)
            if mac:
                self.posture.evaluate(mac, severity, anomaly)
                if self.device_db and severity in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM):
                    self.device_db.increment_alert_count(mac)
            return

        # If prior occurrences were suppressed, annotate the description
        if suppressed_count > 0:
            description = f"{description} (repeated {suppressed_count + 1}x in {ANOMALY_SUPPRESSION_WINDOW // 60}m)"

        logger.warning(f"[{severity}] {description}")

        # Post to Live Activity window
        if severity in (SEVERITY_CRITICAL, SEVERITY_HIGH):
            self._post_activity(f"[{severity}] {description}", entry_type="CRITICAL")
        else:
            self._post_activity(f"[{severity}] {description}")

        # Evaluate through graduated response posture
        if mac:
            action, posture_desc = self.posture.evaluate(mac, severity, anomaly)

            if action == "block":
                description = f"[AUTO-BLOCKED] {description}"
            elif action == "pending_isolate":
                description = f"[PENDING ISOLATE] {description}"
                # Notify operator
                self.blackboard.send_message(
                    to_agent="operator",
                    content=f"APPROVAL REQUIRED: Isolate {mac}? Reply 'approve isolate {mac}'. Reason: {description}",
                    message_type="alert"
                )
            elif action == "pending_block":
                description = f"[PENDING BLOCK] {description}"
                self.blackboard.send_message(
                    to_agent="operator",
                    content=f"APPROVAL REQUIRED: Block {mac}? Reply 'approve block {mac}'. Reason: {description}",
                    message_type="alert"
                )

            # Track alert count in device DB
            if self.device_db and severity in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM):
                self.device_db.increment_alert_count(mac)

        # CRITICAL/HIGH: voice alert
        if severity in (SEVERITY_CRITICAL, SEVERITY_HIGH):
            voice_msg = f"ALERT. {description}"
            self.voice.speak(voice_msg)

        # All severities: post to Blackboard
        self.blackboard.post_finding(
            title=f"Network Defense: {anomaly_type}",
            severity=severity,
            description=description,
            host=mac,
            evidence=json.dumps(anomaly, default=str),
        )

        # Capture training example for tactical category
        if self.learning and severity in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM):
            self.learning.capture_tool_interaction(
                tool_name="unifi_defense",
                tool_args={"poll_cycle": self._poll_count},
                tool_output=description,
                user_query=f"Network defense monitoring cycle {self._poll_count}",
                agent_analysis=f"[{severity}] {description}",
            )

    # ── Detection Sub-Detectors (Enhancement 2) ────────────────

    def _detect_bandwidth_anomalies(self, clients):
        """2a: Flag clients with tx/rx > 5x rolling average AND > 50MB delta."""
        if not self.device_db:
            return
        for client in clients:
            mac = client.get("mac", "").lower()
            if not mac:
                continue
            tx = client.get("tx_bytes", 0)
            rx = client.get("rx_bytes", 0)
            if tx == 0 and rx == 0:
                continue
            device = self.device_db.get_device(mac)
            if not device:
                continue
            avg_tx = device.get("avg_tx_bytes", 0)
            avg_rx = device.get("avg_rx_bytes", 0)
            # Check for spike: current > 5x average AND absolute delta > 50MB
            threshold_bytes = 50 * 1024 * 1024  # 50MB
            if avg_tx > 0 and tx > avg_tx * 5 and (tx - avg_tx) > threshold_bytes:
                self._handle_anomaly({
                    "type": "bandwidth_spike",
                    "mac": mac,
                    "hostname": client.get("hostname", "unknown"),
                    "direction": "TX",
                    "current": tx,
                    "average": avg_tx,
                    "ratio": round(tx / avg_tx, 1),
                })
            if avg_rx > 0 and rx > avg_rx * 5 and (rx - avg_rx) > threshold_bytes:
                self._handle_anomaly({
                    "type": "bandwidth_spike",
                    "mac": mac,
                    "hostname": client.get("hostname", "unknown"),
                    "direction": "RX",
                    "current": rx,
                    "average": avg_rx,
                    "ratio": round(rx / avg_rx, 1),
                })

    def _detect_temporal_anomalies(self, clients):
        """2b: Flag devices connecting at unusual hours (needs 72h+ history)."""
        if not self.device_db:
            return
        current_hour = datetime.now(timezone.utc).hour
        for client in clients:
            mac = client.get("mac", "").lower()
            if not mac:
                continue
            # Update typical hours in DB
            self.device_db.update_typical_hours(mac, current_hour)
            # Check if unusual
            if self.device_db.is_unusual_hour(mac, current_hour):
                oui = mac[:8]
                anomaly = {
                    "type": "unusual_time",
                    "mac": mac,
                    "hostname": client.get("hostname", "unknown"),
                    "hour": current_hour,
                }
                # Escalate if unknown OUI
                if oui not in self.baseline.known_ouis:
                    anomaly["unknown_oui"] = True
                self._handle_anomaly(anomaly)

    def _detect_rogue_aps(self):
        """2c: Cross-reference client AP MACs against managed infrastructure."""
        from config import KNOWN_SSIDS
        # Refresh managed AP list every 10th cycle
        devices = self.unifi.get_devices()
        if devices:
            device_list = devices if isinstance(devices, list) else devices.get("result", [])
            if isinstance(device_list, list):
                for dev in device_list:
                    if isinstance(dev, dict):
                        dev_mac = dev.get("mac", "").lower()
                        if dev_mac:
                            self._managed_infrastructure.add(dev_mac)
                logger.debug(f"Managed infrastructure: {len(self._managed_infrastructure)} devices")

        if not self._managed_infrastructure:
            return

        # Check clients for unmanaged AP MACs
        for client in self._last_clients:
            if not isinstance(client, dict):
                continue
            ap_mac = client.get("ap_mac", "").lower()
            ssid = client.get("essid", client.get("network", ""))

            if ap_mac and ap_mac not in self._managed_infrastructure:
                # Client connected to unmanaged AP
                self._handle_anomaly({
                    "type": "rogue_ap",
                    "mac": client.get("mac", "").lower(),
                    "hostname": client.get("hostname", "unknown"),
                    "bssid": ap_mac,
                    "ssid": ssid,
                })
            elif ssid and ssid not in KNOWN_SSIDS and ssid != "unknown":
                # Unknown SSID (could be rogue)
                logger.debug(f"Unknown SSID detected: {ssid} for {client.get('mac', '')}")

    def _detect_rapid_reconnects(self):
        """2d: Flag devices with >5 reconnects in 10 minutes (deauth signature)."""
        # Check recently connected MACs from baseline transitions
        for mac in list(self.baseline._prev_macs)[:50]:  # Limit to avoid DB thrashing
            count = self.device_db.get_reconnect_count(mac, window_minutes=10)
            if count > 5:
                hostname = self.baseline.known_clients.get(mac, {}).get("hostname", "unknown")
                self._handle_anomaly({
                    "type": "rapid_reconnect",
                    "mac": mac,
                    "hostname": hostname,
                    "count": count,
                    "window": 10,
                })

    def _detect_dpi_deviations(self):
        """2e: Check per-device DPI for significant deviations from baseline."""
        dpi_result = self.unifi.get_dpi_stats()
        if not dpi_result:
            return

        # DPI results can be a list or dict
        dpi_data = dpi_result if isinstance(dpi_result, list) else dpi_result.get("result", [])
        if isinstance(dpi_data, dict):
            dpi_data = [dpi_data]

        for entry in dpi_data:
            if not isinstance(entry, dict):
                continue
            mac = entry.get("mac", "").lower()
            if not mac:
                continue
            # Build DPI category dict from entry
            categories = {}
            for cat_entry in entry.get("by_cat", entry.get("categories", [])):
                if isinstance(cat_entry, dict):
                    cat_name = cat_entry.get("cat", cat_entry.get("name", "unknown"))
                    cat_bytes = cat_entry.get("tx_bytes", 0) + cat_entry.get("rx_bytes", 0)
                    categories[str(cat_name)] = cat_bytes

            if not categories:
                continue

            # Update baseline and check for deviations
            self.device_db.update_dpi_baseline(mac, categories)
            deviations = self.device_db.get_dpi_deviation(mac, categories)
            for dev in deviations:
                hostname = self.baseline.known_clients.get(mac, {}).get("hostname", "unknown")
                self._handle_anomaly({
                    "type": "dpi_deviation",
                    "mac": mac,
                    "hostname": hostname,
                    "category": dev["category"],
                    "current": dev["current"],
                    "baseline": dev["baseline"],
                    "ratio": dev["ratio"],
                })

    def is_running(self):
        """Check if the defense loop is active."""
        return self._running and self._thread and self._thread.is_alive()
