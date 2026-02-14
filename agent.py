#!/usr/bin/env python3
"""
Local Joshua AI Agent — Main Agent Loop
Autonomous OSINT analyst running on Kali via Ollama.

Polls Blackboard for messages, processes with LLM, executes tools,
posts responses and findings back to Blackboard.

Usage:
    python agent.py              # Normal operation
    python agent.py --test       # Single inference test
    python agent.py --status     # Check service status
"""

import json
import logging
import re
import signal
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

from config import (
    AGENT_NAME, OLLAMA_URL, OLLAMA_MODEL, SYSTEM_PROMPT,
    POLL_INTERVAL, IDLE_POLL_INTERVAL,
    TEMPERATURE, TOP_P, NUM_CTX, NUM_PREDICT,
    LOG_FILE, LOG_LEVEL
)
from blackboard import BlackboardClient
from memory import Memory
from tools import execute_tool, get_tool_descriptions, TOOL_REGISTRY
from voice import VoiceClient
from learning import LearningEngine
from unifi_defense import UniFiDefenseLoop

# === Logging Setup ===
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("joshua")


class JoshuaAgent:
    """Autonomous OSINT analyst agent."""

    def __init__(self):
        self.blackboard = BlackboardClient()
        self.memory = Memory()
        self.voice = VoiceClient()
        self.learning = LearningEngine(self.blackboard)
        self.defense = UniFiDefenseLoop(self.blackboard, self.voice, self.learning)
        self.running = False
        self._last_activity = time.time()

    def _build_system_prompt(self):
        """Build full system prompt with tool descriptions and task context."""
        prompt = SYSTEM_PROMPT + "\n\nAVAILABLE TOOLS:\n" + get_tool_descriptions()
        if self.memory.task_context:
            prompt += f"\n\nCURRENT TASK:\n{self.memory.task_context}"
        return prompt

    def _call_ollama(self, messages):
        """Send messages to Ollama API and get response."""
        system_prompt = self._build_system_prompt()

        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                *messages
            ],
            "stream": False,
            "options": {
                "temperature": TEMPERATURE,
                "top_p": TOP_P,
                "num_ctx": NUM_CTX,
                "num_predict": NUM_PREDICT
            }
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
                return result.get("message", {}).get("content", "")
        except urllib.error.URLError as e:
            logger.error(f"Ollama request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return None

    def _extract_tool_calls(self, response):
        """Extract tool call JSON blocks from LLM response."""
        tool_calls = []
        # Match ```tool ... ``` blocks
        pattern = r'```tool\s*\n?(.*?)\n?```'
        matches = re.findall(pattern, response, re.DOTALL)
        for match in matches:
            try:
                call = json.loads(match.strip())
                if "tool" in call:
                    tool_calls.append(call)
            except json.JSONDecodeError:
                logger.warning(f"Invalid tool call JSON: {match[:100]}")
        return tool_calls

    def _process_message(self, message):
        """Process a single incoming Blackboard message."""
        from_agent = message.get("from_agent", "unknown")
        content = message.get("content", "")
        msg_type = message.get("message_type", "info")

        logger.info(f"Processing message from {from_agent} ({msg_type}): {content[:80]}...")

        # Add to memory
        self.memory.add_user(f"[{from_agent}] {content}", source="blackboard")

        # Get LLM response
        messages = self.memory.get_messages()
        response = self._call_ollama(messages)

        if not response:
            logger.error("No response from Ollama")
            return

        logger.info(f"LLM response ({len(response)} chars): {response[:120]}...")

        # Check for tool calls
        tool_calls = self._extract_tool_calls(response)
        if tool_calls:
            response = self._handle_tool_calls(response, tool_calls, content)

        # Add response to memory
        self.memory.add_assistant(response)

        # Post response to Blackboard
        # Clean response for posting (remove tool blocks)
        clean_response = re.sub(r'```tool\s*\n?.*?\n?```', '', response, flags=re.DOTALL).strip()
        if clean_response:
            self.blackboard.send_message(
                to_agent=from_agent,
                content=f"[{AGENT_NAME}] {clean_response}",
                message_type="response"
            )

        # Speak important responses
        if self.voice.enabled and len(clean_response) > 50:
            self.voice.speak(clean_response)

        # Flush any pending training examples
        if self.learning.pending_count > 0:
            self.learning.flush()

        self._last_activity = time.time()

    def _handle_tool_calls(self, response, tool_calls, original_query):
        """Execute tool calls and feed results back to LLM."""
        all_results = []

        for call in tool_calls:
            tool_name = call.get("tool", "")
            tool_args = call.get("args", {})

            logger.info(f"Executing tool: {tool_name}({tool_args})")
            result = execute_tool(tool_name, tool_args)
            all_results.append(f"[{tool_name}] {result}")

            # Capture training example
            self.learning.capture_tool_interaction(
                tool_name=tool_name,
                tool_args=tool_args,
                tool_output=result,
                user_query=original_query,
                agent_analysis=""  # Will be filled by follow-up LLM call
            )

        # Feed tool results back to LLM for analysis
        tool_context = "\n\n".join(all_results)
        self.memory.add_user(
            f"[TOOL RESULTS]\n{tool_context}",
            source="tools"
        )

        follow_up = self._call_ollama(self.memory.get_messages())
        if follow_up:
            self.memory.add_assistant(follow_up)
            return follow_up

        return response + "\n\n[Tool results received but analysis failed]"

    def _check_tasks(self):
        """Check for pending tasks assigned to this agent."""
        result = self.blackboard.get_tasks(status_filter="pending")
        if not result:
            return

        tasks = result if isinstance(result, list) else result.get("tasks", [])
        for task in tasks:
            assigned = task.get("assigned_to", "")
            if assigned == AGENT_NAME or assigned == "":
                task_id = task.get("id", "")
                title = task.get("title", "")
                logger.info(f"Found task: {title} ({task_id})")

                # Claim it
                self.blackboard.claim_task(task_id)
                self.memory.set_task_context(
                    f"Task: {title}\nDescription: {task.get('description', '')}"
                )

                # Process as a message
                self._process_message({
                    "from_agent": "blackboard",
                    "content": f"TASK: {title}\n{task.get('description', '')}",
                    "message_type": "directive"
                })

                # Complete task
                self.blackboard.complete_task(
                    task_id,
                    result=f"Processed by {AGENT_NAME}"
                )
                self.memory.clear_task_context()

    def run(self):
        """Main agent loop — poll Blackboard and process messages."""
        logger.info(f"=== {AGENT_NAME} starting ===")
        logger.info(f"Ollama: {OLLAMA_URL} / {OLLAMA_MODEL}")
        logger.info(f"Blackboard: {self.blackboard.base_url}")
        logger.info(f"Poll interval: {POLL_INTERVAL}s")

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

        # Announce presence
        self.blackboard.send_message(
            to_agent="operator",
            content=f"{AGENT_NAME} online. Ollama: {OLLAMA_MODEL}, "
                    f"Voice: {'active' if self.voice.enabled else 'inactive'}, "
                    f"Network Defense: {defense_status}. "
                    f"Polling Blackboard every {POLL_INTERVAL}s.",
            message_type="status"
        )

        self.running = True
        consecutive_empty = 0

        while self.running:
            try:
                # Check inbox
                inbox = self.blackboard.check_inbox(mark_read=True)
                if inbox:
                    messages = inbox.get("messages", [])
                    count = inbox.get("count", 0)

                    if count > 0:
                        consecutive_empty = 0
                        logger.info(f"Inbox: {count} new message(s)")
                        for msg in messages:
                            self._process_message(msg)
                    else:
                        consecutive_empty += 1

                # Check tasks periodically
                if consecutive_empty % 6 == 0:  # Every ~60s at 10s poll
                    self._check_tasks()

                # Adaptive polling — slow down when idle
                if consecutive_empty > 30:  # 5 minutes of no messages
                    interval = IDLE_POLL_INTERVAL
                else:
                    interval = POLL_INTERVAL

                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Interrupted by user")
                self.running = False
            except Exception as e:
                logger.error(f"Agent loop error: {e}", exc_info=True)
                time.sleep(POLL_INTERVAL)

        # Stop defense loop
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
        response = self._call_ollama([
            {"role": "user", "content": "Professor Falken, status report."}
        ])
        if response:
            print(f"\nJOSHUA: {response}")
            if self.voice.enabled:
                self.voice.speak(response)
        else:
            print("ERROR: No response from Ollama")

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

        # Court Records
        try:
            url = f"{COURT_RECORDS_URL}/mcp"
            with urllib.request.urlopen(url, timeout=5):
                print(f"Court Records MCP: ONLINE ({COURT_RECORDS_URL})")
        except Exception:
            print(f"Court Records MCP: OFFLINE ({COURT_RECORDS_URL})")

        # UniFi MCP
        try:
            url = f"{UNIFI_MCP_URL}/mcp"
            with urllib.request.urlopen(url, timeout=5):
                print(f"UniFi MCP: ONLINE ({UNIFI_MCP_URL})")
        except Exception:
            print(f"UniFi MCP: OFFLINE ({UNIFI_MCP_URL})")

        # Flipper Zero MCP
        try:
            url = f"{FLIPPER_MCP_URL}/mcp"
            with urllib.request.urlopen(url, timeout=5):
                print(f"Flipper Zero MCP: ONLINE ({FLIPPER_MCP_URL})")
        except Exception:
            print(f"Flipper Zero MCP: OFFLINE ({FLIPPER_MCP_URL})")

        # Memory
        print(f"Memory: {self.memory.get_context_summary()}")


def _handle_signal(sig, frame):
    """Graceful shutdown on SIGINT/SIGTERM."""
    logger.info(f"Received signal {sig}, shutting down...")
    sys.exit(0)


# Import here to avoid circular at module level
from config import COURT_RECORDS_URL, UNIFI_MCP_URL, FLIPPER_MCP_URL

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
