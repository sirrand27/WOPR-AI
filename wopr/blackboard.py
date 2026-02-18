"""
Local Joshua AI Agent — Blackboard MCP Client
JSON-RPC client for Blackboard MCP server on port 9700.
Uses SSE (Server-Sent Events) transport per MCP protocol.
"""

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone

from config import BLACKBOARD_URL, AGENT_NAME

logger = logging.getLogger(__name__)

_request_id = 0


def _next_id():
    global _request_id
    _request_id += 1
    return _request_id


class BlackboardClient:
    """MCP JSON-RPC client for Blackboard server."""

    def __init__(self, base_url=None):
        self.base_url = (base_url or BLACKBOARD_URL).rstrip("/")
        self._last_check = None

    def _mcp_call(self, tool_name, arguments, timeout=15):
        """Call a Blackboard MCP tool via JSON-RPC over SSE."""
        url = f"{self.base_url}/mcp"
        payload = {
            "jsonrpc": "2.0",
            "id": _next_id(),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }

        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                # Parse SSE response — find data: lines
                for line in raw.split("\n"):
                    if line.startswith("data:"):
                        data = json.loads(line[5:].strip())
                        if "result" in data:
                            content = data["result"].get("content", [])
                            for c in content:
                                text = c.get("text", "")
                                try:
                                    return json.loads(text)
                                except json.JSONDecodeError:
                                    return {"text": text}
                        if "error" in data:
                            logger.error(f"MCP error: {data['error']}")
                            return None
                return None
        except urllib.error.URLError as e:
            logger.error(f"Blackboard MCP call failed: {tool_name} — {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Blackboard returned invalid JSON: {tool_name} — {e}")
            return None

    def check_inbox(self, mark_read=True):
        """Check for new messages addressed to this agent."""
        result = self._mcp_call("check_inbox", {
            "agent_name": AGENT_NAME
        })
        if result:
            self._last_check = datetime.now(timezone.utc).isoformat()
        return result

    def send_message(self, to_agent, content, message_type="info"):
        """Send a message to another agent or operator."""
        return self._mcp_call("send_message", {
            "from_agent": AGENT_NAME,
            "to_agent": to_agent,
            "content": content,
            "message_type": message_type
        })

    def get_tasks(self, status_filter=None):
        """Get tasks, optionally filtered by status."""
        args = {}
        if status_filter:
            args["status"] = status_filter
        return self._mcp_call("get_tasks", args)

    def claim_task(self, task_id):
        """Claim a pending task."""
        return self._mcp_call("claim_task", {
            "task_id": task_id,
            "agent_name": AGENT_NAME
        })

    def complete_task(self, task_id, result, artifacts=None):
        """Mark a task as complete."""
        args = {
            "task_id": task_id,
            "result": result
        }
        if artifacts:
            args["artifacts"] = artifacts
        return self._mcp_call("complete_task", args)

    def update_task(self, task_id, status, result=None):
        """Update task status."""
        return self._mcp_call("update_task", {
            "task_id": task_id,
            "status": status,
            "result": result or ""
        })

    def post_finding(self, title, severity, description="", host="",
                     port=0, evidence="", remediation="", cvss=0.0):
        """Post a security finding."""
        return self._mcp_call("post_finding", {
            "title": title,
            "severity": severity,
            "description": description,
            "host": host,
            "port": port,
            "evidence": evidence,
            "remediation": remediation,
            "cvss": cvss
        })

    def submit_training_example(self, category, phase, context, reasoning,
                                 action, observation="", conclusion="",
                                 tools_used=None, hosts_involved=None,
                                 severity_relevant="INFO"):
        """Submit a training example to the Blackboard."""
        return self._mcp_call("submit_training_example", {
            "agent": AGENT_NAME,
            "category": category,
            "phase": phase,
            "context": context,
            "reasoning": reasoning,
            "action": action,
            "observation": observation,
            "conclusion": conclusion,
            "tools_used": tools_used or [],
            "hosts_involved": hosts_involved or [],
            "severity_relevant": severity_relevant
        })

    def post_activity(self, activity, entry_type="CMD"):
        """Post to the activity log."""
        return self._mcp_call("post_activity", {
            "agent_name": AGENT_NAME,
            "content": activity,
            "entry_type": entry_type
        })

    def update_defense_status(self, status_dict):
        """Post structured defense status to Blackboard for Mission Control dashboard."""
        return self._mcp_call("update_defense_status", {
            "agent_name": AGENT_NAME,
            "status_json": json.dumps(status_dict, default=str)
        })

    def get_status(self):
        """Get mission status."""
        return self._mcp_call("get_status", {})

    def is_available(self):
        """Check if Blackboard is reachable."""
        try:
            result = self._mcp_call("get_status", {})
            return result is not None
        except Exception:
            return False
