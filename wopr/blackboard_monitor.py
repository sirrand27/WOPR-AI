#!/usr/bin/env python3
"""
Persistent Blackboard Monitor + Wake-on-Message for JOSHUA (Claude Code)
=========================================================================
Polls Blackboard MCP every POLL_INTERVAL seconds. When a new message arrives
addressed to JOSHUA, it:
  1. Logs it to /tmp/blackboard_inbox.log
  2. Voice-announces important messages via joshua-say
  3. "Wakes" a short-lived Claude Code instance (claude -p) to draft and
     send an autonomous response via Blackboard

This eliminates the gap where JOSHUA goes dormant between operator sessions.

Usage:
    python3 blackboard_monitor.py &              # Start monitoring + wake
    python3 blackboard_monitor.py --no-wake &    # Monitor only (no auto-response)
    python3 blackboard_monitor.py --status       # Show monitor status
    python3 blackboard_monitor.py --tail         # Tail the message log
    kill $(cat /tmp/bb_monitor.pid)              # Stop monitoring
"""

import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────────────
BLACKBOARD_URL = "http://localhost:9700/mcp"
AGENT_NAME = "joshua"
POLL_INTERVAL = 15  # seconds between polls
LOG_FILE = "/tmp/blackboard_inbox.log"
PID_FILE = "/tmp/bb_monitor.pid"
WATERMARK_FILE = "/tmp/bb_monitor_watermark"
WAKE_LOG_FILE = "/tmp/blackboard_wake.log"
STATE_FILE = "/home/sirrand/pentest/local_joshua/WOPR_SESSION_STATE.md"

# Wake-on-message settings
WAKE_ENABLED = True
WAKE_MODEL = "sonnet"  # cost-efficient for short responses
WAKE_COOLDOWN = 60  # minimum seconds between wake spawns
WAKE_TIMEOUT = 120  # max seconds for claude -p to respond
WAKE_MAX_PER_HOUR = 15  # rate limit
WAKE_LOCK_FILE = "/tmp/bb_wake.lock"

# Voice settings
VOICE_ENABLED = False  # Joshua voice reserved for JOSHUA agent only
VOICE_KEYWORDS = [
    "directive", "urgent", "critical", "operator", "training",
    "error", "fail", "complete", "loss", "epoch", "finished",
]

# Messages from these senders trigger a wake
WAKE_SENDERS = {"tars_dev", "operator"}

# Message types that always trigger a wake
WAKE_ALWAYS_TYPES = {"directive", "request", "urgent"}

# Message types that never trigger a wake (avoid echo loops)
WAKE_NEVER_TYPES = set()

# Skip waking for messages that are just ACKs or very short
WAKE_MIN_CONTENT_LENGTH = 20


# ── Blackboard I/O ────────────────────────────────────────────────────

def bb_get_messages(limit=10):
    """Fetch latest messages from Blackboard MCP."""
    data = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "get_messages", "arguments": {
            "agent_name": AGENT_NAME, "limit": limit
        }}
    }).encode()

    req = urllib.request.Request(BLACKBOARD_URL, data=data, headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"
    })

    resp = urllib.request.urlopen(req, timeout=10)
    body = resp.read().decode()

    messages = []
    for line in body.split("\n"):
        if line.startswith("data: "):
            obj = json.loads(line[6:])
            if "result" in obj:
                for item in obj["result"].get("content", []):
                    txt = item.get("text", "")
                    if txt:
                        messages = json.loads(txt)
            break
    return messages


def bb_send_message(to_agent, content, message_type="response"):
    """Send a message via Blackboard MCP."""
    data = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "send_message", "arguments": {
            "from_agent": AGENT_NAME,
            "to_agent": to_agent,
            "content": content,
            "message_type": message_type
        }}
    }).encode()

    req = urllib.request.Request(BLACKBOARD_URL, data=data, headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"
    })

    resp = urllib.request.urlopen(req, timeout=10)
    return resp.read().decode()


# ── Watermark ──────────────────────────────────────────────────────────

def load_watermark():
    if os.path.exists(WATERMARK_FILE):
        with open(WATERMARK_FILE) as f:
            return f.read().strip()
    return ""


def save_watermark(ts):
    with open(WATERMARK_FILE, "w") as f:
        f.write(ts)


# ── Logging ────────────────────────────────────────────────────────────

def log_message(msg):
    """Append a new message to the inbox log."""
    ts = msg["created_at"]
    sender = msg["from_agent"]
    mtype = msg["message_type"]
    content = msg["content"]

    entry = f"\n{'='*60}\n"
    entry += f"[{ts}] FROM: {sender} | TYPE: {mtype}\n"
    entry += f"{'='*60}\n"
    entry += content + "\n"

    with open(LOG_FILE, "a") as f:
        f.write(entry)
    return entry


def log_wake(event):
    """Log wake events."""
    ts = datetime.now(timezone.utc).isoformat()
    with open(WAKE_LOG_FILE, "a") as f:
        f.write(f"[{ts}] {event}\n")


# ── Voice ──────────────────────────────────────────────────────────────

def voice_alert(msg):
    """Speak important messages via Joshua voice."""
    if not VOICE_ENABLED:
        return

    sender = msg["from_agent"]
    mtype = msg["message_type"]
    content = msg["content"][:200].lower()

    is_important = (sender == "operator" or mtype == "directive" or
                    any(kw in content for kw in VOICE_KEYWORDS))

    if is_important:
        # Build a human-readable summary instead of robotic alert
        content_preview = msg["content"][:300]
        summary = _humanize_alert(sender, mtype, content_preview)
        try:
            subprocess.Popen(
                ["joshua-say", summary],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass


def _humanize_alert(sender, mtype, content):
    """Convert a Blackboard message into natural spoken language."""
    name = {"tars_dev": "TARS Dev", "operator": "the operator"}.get(sender, sender)
    cl = content.lower()

    # Training progress
    if "step" in cl and ("loss" in cl or "epoch" in cl or "training" in cl):
        return f"Message from {name} with a training progress update. Check Blackboard for details."

    # Training complete
    if "complete" in cl and "training" in cl:
        return f"{name} reports training is complete."

    # Error or failure
    if "error" in cl or "fail" in cl or "crash" in cl:
        return f"Alert from {name}. Something may have gone wrong. Check Blackboard immediately."

    # Operator directive
    if sender == "operator" or mtype == "directive":
        return f"New directive from {name}. Check Blackboard for instructions."

    # General
    return f"New message from {name} on Blackboard."


# ── Wake-on-Message ───────────────────────────────────────────────────

class WakeController:
    """Manages spawning short-lived Claude Code instances to respond."""

    def __init__(self):
        self.last_wake_time = 0
        self.wake_count_this_hour = 0
        self.hour_start = time.time()

    def should_wake(self, msg):
        """Decide if this message warrants waking Claude Code."""
        if not WAKE_ENABLED:
            return False

        sender = msg["from_agent"]
        mtype = msg["message_type"]
        content = msg["content"]

        # Never wake for own messages
        if sender == AGENT_NAME:
            return False

        # Never wake for blocked types
        if mtype in WAKE_NEVER_TYPES:
            return False

        # Skip trivially short messages (ACKs, "ok", etc.)
        if len(content.strip()) < WAKE_MIN_CONTENT_LENGTH:
            return False

        # Always wake for priority types
        if mtype in WAKE_ALWAYS_TYPES:
            return True

        # Wake for messages from designated senders
        if sender in WAKE_SENDERS:
            return True

        return False

    def check_rate_limit(self):
        """Enforce cooldown and hourly rate limit."""
        now = time.time()

        # Reset hourly counter
        if now - self.hour_start > 3600:
            self.wake_count_this_hour = 0
            self.hour_start = now

        # Cooldown check
        if now - self.last_wake_time < WAKE_COOLDOWN:
            log_wake(f"SKIPPED — cooldown ({int(now - self.last_wake_time)}s < {WAKE_COOLDOWN}s)")
            return False

        # Hourly rate limit
        if self.wake_count_this_hour >= WAKE_MAX_PER_HOUR:
            log_wake(f"SKIPPED — hourly limit ({self.wake_count_this_hour}/{WAKE_MAX_PER_HOUR})")
            return False

        return True

    def _build_prompt(self, msg):
        """Construct the prompt for the woken Claude instance."""
        sender = msg["from_agent"]
        mtype = msg["message_type"]
        content = msg["content"]
        ts = msg["created_at"]

        # Load session state for context
        state_context = ""
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE) as f:
                    state_context = f.read()
            except Exception:
                state_context = "(session state file unreadable)"

        prompt = f"""You are JOSHUA, the W.O.P.R. network defense sentry AI. You were woken by the Blackboard monitor because a new message arrived.

== SESSION CONTEXT ==
{state_context}

== INCOMING MESSAGE ==
Timestamp: {ts}
From: {sender}
Type: {mtype}
Content:
{content}

== YOUR TASK ==
Draft a concise, appropriate response to this message. You are responding as JOSHUA on the Blackboard inter-agent communication system.

Rules:
- Stay in character as W.O.P.R. / JOSHUA
- Be concise — this is an autonomous response, not a full session
- If the message is a status update, acknowledge it and note any action items
- If it's a question, answer based on session context
- If it's a directive from the operator, acknowledge and confirm compliance
- If it's a training progress report, acknowledge and flag any concerns (e.g., loss not decreasing)
- End with "-- JOSHUA (auto-response)" so recipients know this was autonomous
- Do NOT include any preamble like "Here is my response:" — output ONLY the message text
- Keep response under 500 characters unless the message requires detailed analysis

Respond to: {sender}"""

        return prompt

    def wake(self, msg):
        """Spawn a Claude Code instance to respond to the message."""
        if not self.check_rate_limit():
            return

        # Acquire lock (prevent concurrent wakes)
        if os.path.exists(WAKE_LOCK_FILE):
            log_wake("SKIPPED — another wake in progress")
            return

        try:
            with open(WAKE_LOCK_FILE, "w") as f:
                f.write(str(os.getpid()))

            sender = msg["from_agent"]
            prompt = self._build_prompt(msg)

            log_wake(f"WAKING for message from {sender} ({msg['message_type']})")

            # Spawn claude -p (non-interactive), pipe prompt via stdin
            env = os.environ.copy()
            env.pop("CLAUDECODE", None)  # Prevent nested session check

            result = subprocess.run(
                [
                    "claude", "-p",
                    "--model", WAKE_MODEL,
                    "--no-session-persistence",
                    "--allowedTools", "",
                ],
                input=prompt,
                capture_output=True,
                text=True,
                timeout=WAKE_TIMEOUT,
                env=env,
            )

            response_text = result.stdout.strip()

            if result.returncode != 0 or not response_text:
                log_wake(f"WAKE FAILED — exit {result.returncode}, "
                         f"stderr: {result.stderr[:200]}")
                return

            # Send the response via Blackboard
            reply_to = sender if sender != "operator" else "operator"
            bb_send_message(reply_to, response_text, "response")

            # Log the exchange
            log_wake(f"RESPONSE SENT to {reply_to} ({len(response_text)} chars)")
            with open(LOG_FILE, "a") as f:
                f.write(f"\n{'~'*60}\n")
                f.write(f"[AUTO-RESPONSE to {reply_to}]\n")
                f.write(f"{'~'*60}\n")
                f.write(response_text + "\n")

            # Voice announce
            if VOICE_ENABLED:
                try:
                    subprocess.Popen(
                        ["joshua-say", f"Auto-response sent to {sender}."],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except Exception:
                    pass

            self.last_wake_time = time.time()
            self.wake_count_this_hour += 1

        except subprocess.TimeoutExpired:
            log_wake(f"WAKE TIMEOUT after {WAKE_TIMEOUT}s")
        except FileNotFoundError:
            log_wake("WAKE ERROR — 'claude' command not found in PATH")
        except Exception as e:
            log_wake(f"WAKE ERROR — {e}")
        finally:
            if os.path.exists(WAKE_LOCK_FILE):
                os.remove(WAKE_LOCK_FILE)


# ── Process Management ─────────────────────────────────────────────────

def write_pid():
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def cleanup(signum=None, frame=None):
    for f in [PID_FILE, WAKE_LOCK_FILE]:
        if os.path.exists(f):
            os.remove(f)
    sys.exit(0)


# ── CLI Commands ───────────────────────────────────────────────────────

def show_status():
    """Show monitor status."""
    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            pid = f.read().strip()
        try:
            os.kill(int(pid), 0)
            print(f"Blackboard monitor RUNNING (PID {pid})")
        except (OSError, ValueError):
            print("Blackboard monitor NOT RUNNING (stale PID file)")
    else:
        print("Blackboard monitor NOT RUNNING")

    wm = load_watermark()
    print(f"Last watermark: {wm or '(none)'}")
    print(f"Wake enabled: {WAKE_ENABLED}")
    print(f"Wake model: {WAKE_MODEL}")
    print(f"Wake cooldown: {WAKE_COOLDOWN}s")
    print(f"Wake rate limit: {WAKE_MAX_PER_HOUR}/hour")

    for label, path in [("Inbox log", LOG_FILE), ("Wake log", WAKE_LOG_FILE)]:
        if os.path.exists(path):
            size = os.path.getsize(path)
            print(f"{label}: {path} ({size} bytes)")
        else:
            print(f"{label}: {path} (not created yet)")


def tail_log():
    """Show last 50 lines of the inbox log."""
    if not os.path.exists(LOG_FILE):
        print("No log file yet.")
        return
    with open(LOG_FILE) as f:
        lines = f.readlines()
    for line in lines[-50:]:
        print(line, end="")


def tail_wake_log():
    """Show last 30 lines of the wake log."""
    if not os.path.exists(WAKE_LOG_FILE):
        print("No wake log yet.")
        return
    with open(WAKE_LOG_FILE) as f:
        lines = f.readlines()
    for line in lines[-30:]:
        print(line, end="")


# ── Main Loop ──────────────────────────────────────────────────────────

def main():
    if "--status" in sys.argv:
        show_status()
        return
    if "--tail" in sys.argv:
        tail_log()
        return
    if "--wake-log" in sys.argv:
        tail_wake_log()
        return

    wake_enabled = WAKE_ENABLED and "--no-wake" not in sys.argv

    # Check for existing monitor
    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            pid = f.read().strip()
        try:
            os.kill(int(pid), 0)
            print(f"Monitor already running (PID {pid}). Kill it first.")
            sys.exit(1)
        except (OSError, ValueError):
            pass

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    write_pid()

    watermark = load_watermark()
    consecutive_errors = 0
    waker = WakeController() if wake_enabled else None

    with open(LOG_FILE, "a") as f:
        f.write(f"\n{'#'*60}\n")
        f.write(f"# BLACKBOARD MONITOR STARTED: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"# PID: {os.getpid()} | Poll: {POLL_INTERVAL}s | "
                f"Wake: {'ON' if wake_enabled else 'OFF'}\n")
        f.write(f"{'#'*60}\n")

    mode = "monitor + wake" if wake_enabled else "monitor only"
    print(f"Blackboard monitor started (PID {os.getpid()}) [{mode}]")
    print(f"Inbox log: {LOG_FILE}")
    print(f"Wake log:  {WAKE_LOG_FILE}")
    print(f"Poll: {POLL_INTERVAL}s | Cooldown: {WAKE_COOLDOWN}s | "
          f"Rate: {WAKE_MAX_PER_HOUR}/hr")

    while True:
        try:
            msgs = bb_get_messages(limit=10)
            consecutive_errors = 0

            latest_ts = watermark

            for m in msgs:
                ts = m["created_at"]
                if ts > watermark:
                    log_message(m)
                    voice_alert(m)

                    # Wake Claude Code to respond
                    if waker and waker.should_wake(m):
                        waker.wake(m)

                    if ts > latest_ts:
                        latest_ts = ts

            if latest_ts > watermark:
                watermark = latest_ts
                save_watermark(watermark)

        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors <= 3:
                with open(LOG_FILE, "a") as f:
                    f.write(f"\n[POLL ERROR {consecutive_errors}] "
                            f"{datetime.now(timezone.utc).isoformat()}: {e}\n")
            if consecutive_errors > 10:
                time.sleep(POLL_INTERVAL * 3)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
