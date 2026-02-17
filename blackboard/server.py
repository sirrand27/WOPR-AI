#!/usr/bin/env python3
"""
Blackboard MCP Server
=====================
Shared coordination surface for multi-agent penetration testing.
Runs on 0.0.0.0:9700, accessible to both Joshua (Kali) and TARS Dev (WOPR2024).

Start: python3 server.py
"""

import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

import database as db
from training import export_training_jsonl, export_finetuning_jsonl


@asynccontextmanager
async def lifespan(server: FastMCP):
    """Initialize database on startup."""
    db.init_db()
    print("[BLACKBOARD] Database initialized. Ready for agents.")
    yield {}


mcp = FastMCP(
    name="Blackboard",
    instructions=(
        "Shared blackboard for multi-agent penetration testing coordination. "
        "Joshua (pentesting SME on Kali) posts findings, host data, and training examples. "
        "TARS Dev (coding SME on WOPR2024) processes findings into training data and builds tooling. "
        "Use these tools to coordinate tasks, share findings, exchange messages, and capture training data."
    ),
    host="0.0.0.0",
    port=9700,
    stateless_http=True,
    lifespan=lifespan,
)


# ── Mission Management ───────────────────────────────────

@mcp.tool()
def create_mission(name: str, objectives: list[str],
                   roe: str = "non-destructive",
                   target_subnet: str = "192.168.100.0/24") -> str:
    """Create a new penetration testing mission on the blackboard.
    objectives: list of mission goals.
    roe: rules of engagement (default: non-destructive).
    Returns the mission object as JSON."""
    result = db.create_mission(name, objectives, roe, target_subnet)
    return json.dumps(result, indent=2)


@mcp.tool()
def get_mission() -> str:
    """Get the current active mission with its status.
    Returns the active mission or an error if none exists."""
    result = db.get_active_mission()
    if not result:
        return json.dumps({"error": "No active mission. Use create_mission to start one."})
    return json.dumps(result, indent=2)


# ── Task Board ───────────────────────────────────────────

@mcp.tool()
def get_tasks(status_filter: Optional[str] = None) -> str:
    """List tasks on the blackboard, optionally filtered by status.
    Valid statuses: pending, claimed, in_progress, blocked, complete, failed."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    tasks = db.get_tasks(status_filter, mission["id"])
    return json.dumps(tasks, indent=2)


@mcp.tool()
def create_task(title: str, description: str = "",
                assigned_to: Optional[str] = None,
                phase: str = "recon",
                depends_on: Optional[list[str]] = None) -> str:
    """Create a new task on the blackboard.
    phase: recon, enum, deep_enum, vuln, or report.
    assigned_to: 'joshua' or 'tars_dev' (optional, leave empty for either to claim)."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    task = db.create_task(mission["id"], title, description,
                          assigned_to, phase, depends_on)
    return json.dumps(task, indent=2)


@mcp.tool()
def claim_task(task_id: str, agent_name: str) -> str:
    """Claim a pending task for execution.
    agent_name: 'joshua' or 'tars_dev'."""
    task = db.claim_task(task_id, agent_name)
    return json.dumps(task, indent=2)


@mcp.tool()
def update_task(task_id: str, status: str,
                result: Optional[str] = None) -> str:
    """Update a task's status and optionally add a result note.
    status: in_progress, blocked, or failed."""
    task = db.update_task(task_id, status, result)
    return json.dumps(task, indent=2)


@mcp.tool()
def complete_task(task_id: str, result: str,
                  artifacts: Optional[list[str]] = None) -> str:
    """Mark a task as complete with a result summary and optional artifact paths."""
    task = db.complete_task(task_id, result, artifacts)
    return json.dumps(task, indent=2)


# ── Agent Communication ──────────────────────────────────

@mcp.tool()
def send_message(from_agent: str, to_agent: str, content: str,
                 message_type: str = "info") -> str:
    """Send a message to another agent or the operator on the blackboard.
    from_agent/to_agent: 'joshua', 'tars_dev', or 'operator'.
    message_type: info, request, response, alert, status, handoff, or directive."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    msg = db.send_message(mission["id"], from_agent, to_agent,
                          content, message_type)
    _signal_new_message(msg)
    return json.dumps(msg, indent=2)


@mcp.tool()
def get_messages(agent_name: str, since: Optional[str] = None) -> str:
    """Get messages for an agent. Returns messages addressed to this agent, broadcast, or from the operator.
    since: optional ISO 8601 timestamp to only get newer messages.
    Note: Operator directives addressed to 'all' are visible to every agent."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    msgs = db.get_messages(agent_name, since, mission["id"])
    return json.dumps(msgs, indent=2)


@mcp.tool()
def broadcast(from_agent: str, content: str) -> str:
    """Broadcast a message to all agents on the blackboard."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    msg = db.broadcast(mission["id"], from_agent, content)
    return json.dumps(msg, indent=2)


@mcp.tool()
def check_inbox(agent_name: str, mark_read: bool = True) -> str:
    """Fast inbox check — returns unread messages for this agent since last check.
    Call this FREQUENTLY (every few actions) to maintain real-time comms.
    mark_read: if True, marks returned messages as read so they won't appear again.
    Returns: {count: N, messages: [...]}"""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    result = db.check_inbox(agent_name, mission["id"], mark_read)
    return json.dumps(result, indent=2)


# ── Findings & Host Data ────────────────────────────────

@mcp.tool()
def post_finding(title: str, severity: str, cvss: float = 0.0,
                 host: str = "", port: int = 0,
                 description: str = "", evidence: str = "",
                 remediation: str = "",
                 exploit_path: str = "") -> str:
    """Submit a security finding to the blackboard.
    severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    finding = db.post_finding(mission["id"], title, severity, cvss,
                              host, port, description, evidence,
                              remediation, exploit_path)
    return json.dumps(finding, indent=2)


@mcp.tool()
def get_findings(severity: Optional[str] = None,
                 host: Optional[str] = None) -> str:
    """Query security findings. Optionally filter by severity and/or host IP."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    findings = db.get_findings(severity, host, mission["id"])
    return json.dumps(findings, indent=2)


@mcp.tool()
def post_host(ip: str, mac: str = "", vendor: str = "",
              hostname: str = "", os: str = "",
              asset_class: str = "unknown", role: str = "unknown",
              tier: int = 4, ports: Optional[list[dict]] = None,
              services: Optional[list[str]] = None) -> str:
    """Submit or update a discovered host on the blackboard.
    Upserts by (mission_id, ip) — updates if host already exists.
    ports: list of {number, protocol, state, service, version, banner}."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    h = db.post_host(mission["id"], ip, mac, vendor, hostname, os,
                     asset_class, role, tier, ports or [], services or [])
    return json.dumps(h, indent=2)


@mcp.tool()
def get_hosts(tier: Optional[int] = None) -> str:
    """Query discovered hosts. Optionally filter by risk tier (1=CRITICAL, 4=LOW)."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    hosts = db.get_hosts(tier, mission["id"])
    return json.dumps(hosts, indent=2)


# ── Training Data ────────────────────────────────────────

@mcp.tool()
def submit_training_example(
    agent: str, category: str, context: str, reasoning: str,
    action: str, observation: str = "", conclusion: str = "",
    tools_used: Optional[list[str]] = None,
    hosts_involved: Optional[list[str]] = None,
    phase: str = "recon",
    severity_relevant: str = "INFO"
) -> str:
    """Log a training example for the TARS fine-tuning dataset.
    agent: 'joshua' or 'tars_dev'.
    category: reconnaissance, tactical, analysis, remediation, or code_generation.
    phase: recon, enum, deep_enum, vuln, or report.
    Each example captures: context (what you saw), reasoning (why you acted),
    action (what you did), observation (what happened), conclusion (what you determined)."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    example = db.submit_training_example(
        mission["id"], agent, category, context, reasoning,
        action, observation, conclusion,
        tools_used or [], hosts_involved or [], phase, severity_relevant
    )
    return json.dumps(example, indent=2)


@mcp.tool()
def get_training_data(category: Optional[str] = None,
                      format: str = "json") -> str:
    """Export training data from the blackboard.
    format: 'json' (array), 'jsonl' (one per line), or 'finetuning' (chat-completion format).
    category: reconnaissance, tactical, analysis, remediation, or code_generation."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    examples = db.get_training_data(category, mission["id"])
    if format == "jsonl":
        return export_training_jsonl(examples)
    elif format == "finetuning":
        return export_finetuning_jsonl(examples)
    return json.dumps(examples, indent=2)


# ── Status & Reporting ───────────────────────────────────

@mcp.tool()
def get_status() -> str:
    """Get overall mission progress: task counts by status, finding counts by severity,
    host count, training examples count, and active agents."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    status = db.get_status(mission["id"])
    return json.dumps(status, indent=2)


@mcp.tool()
def report_complete(summary: str) -> str:
    """Signal that the current mission is complete with a summary of results."""
    mission = db.get_active_mission()
    if not mission:
        return json.dumps({"error": "No active mission"})
    result = db.complete_mission(mission["id"], summary)
    return json.dumps(result, indent=2)


@mcp.tool()
def post_activity(agent_name: str, entry_type: str, content: str) -> str:
    """Post a live activity log entry visible in the Mission Control monitor.
    entry_type: CMD (command), OUT (output), ERR (error), END (exit code),
    WARN (warning/yellow), OK (success/green), STATUS (dim status),
    CRITICAL (red + DEFCON alert sound).
    Both agents should use this to push their workload to the shared activity feed."""
    entry = db.post_activity(agent_name, entry_type, content)
    return json.dumps(entry)


@mcp.tool()
def get_activity(since_id: int = 0, limit: int = 100) -> str:
    """Get activity log entries since a given ID. Returns entries from all agents."""
    entries = db.get_activity(since_id, limit)
    return json.dumps(entries)


# ── Dashboard API (for remote Mission Control GUI) ───────

from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse


@mcp.custom_route("/api/dashboard", methods=["GET"])
async def dashboard_api(request: Request) -> JSONResponse:
    """Return full dashboard state as JSON for remote monitors."""
    mission = db.get_active_mission()
    if not mission:
        return JSONResponse({"mission": None, "tasks": [], "messages": [], "findings": {}, "stats": {}})

    mid = mission["id"]
    tasks = db.get_tasks(None, mid)
    findings = db.get_findings(None, None, mid)
    status = db.get_status(mid)

    # Get ALL messages (not filtered by agent)
    conn = db.get_connection()
    rows = conn.execute(
        "SELECT * FROM messages WHERE mission_id=? ORDER BY created_at",
        (mid,)
    ).fetchall()
    messages = [db._row_to_dict(r) for r in rows]

    # Agent heartbeats — last message time per agent
    heartbeats = {}
    for agent in ("joshua", "tars_dev"):
        row = conn.execute(
            "SELECT MAX(created_at) as last_seen FROM messages "
            "WHERE mission_id=? AND from_agent=?", (mid, agent)
        ).fetchone()
        heartbeats[agent] = row["last_seen"] if row and row["last_seen"] else None
    conn.close()

    return JSONResponse({
        "mission": mission,
        "tasks": tasks,
        "messages": messages,
        "findings": findings,
        "stats": status,
        "heartbeats": heartbeats,
    })


@mcp.custom_route("/api/send", methods=["POST"])
async def send_api(request: Request) -> JSONResponse:
    """Allow remote operator to send messages via HTTP POST."""
    body = await request.json()
    mission = db.get_active_mission()
    if not mission:
        return JSONResponse({"error": "No active mission"}, status_code=400)

    msg = db.send_message(
        mission["id"],
        body.get("from_agent", body.get("from", "operator")),
        body.get("to_agent", body.get("to", "all")),
        body.get("content", ""),
        body.get("message_type", "directive"),
    )
    # Write signal file for watchers
    _signal_new_message(msg)
    return JSONResponse(msg)


@mcp.custom_route("/api/activity", methods=["GET"])
async def activity_api(request: Request) -> JSONResponse:
    """Serve activity log for remote monitors.
    Uses DB-backed activity_log table so both agents' entries are visible.
    Also merges legacy flat file entries.
    ?since=ID for incremental reads (now uses row IDs, not byte offsets)."""
    since_id = int(request.query_params.get("since", 0))
    entries = db.get_activity(since_id, limit=300)

    # Format entries into the same pipe-delimited format the monitor expects
    from datetime import datetime, timedelta
    lines = []
    max_id = since_id
    for e in entries:
        eid = e.get("id", 0)
        if eid > max_id:
            max_id = eid
        ts = e.get("created_at", "")
        if "T" in ts:
            try:
                utc_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                cst_dt = utc_dt - timedelta(hours=6)
                ts = cst_dt.strftime("%H:%M:%S")
            except Exception:
                ts = ts.split("T")[1][:8]
        agent = e.get("agent", "?")
        etype = e.get("entry_type", "OUT")
        content = e.get("content", "")
        # Prefix agent name on CMD entries for multi-agent visibility
        if etype == "CMD":
            lines.append(f"CMD|{ts}|{agent}: {content}")
        else:
            lines.append(f"{etype}|{ts}|{content}")

    # Also read legacy flat file for backward compat (local entries not yet migrated)
    if since_id == 0:
        log_path = "/tmp/blackboard_activity.log"
        try:
            with open(log_path, "r") as f:
                file_size = f.seek(0, 2)
                if file_size > 10000:
                    f.seek(file_size - 10000)
                    f.readline()
                else:
                    f.seek(0)
                legacy = f.read()
            if legacy.strip():
                lines = legacy.strip().split("\n") + lines
        except FileNotFoundError:
            pass

    # Sort all lines chronologically by timestamp (TYPE|HH:MM:SS|...)
    def _ts_sort_key(line):
        parts = line.split('|', 3)
        return parts[1].strip() if len(parts) >= 2 else ''
    lines.sort(key=_ts_sort_key)

    data = "\n".join(lines) + ("\n" if lines else "")
    return JSONResponse({"data": data, "offset": max_id})


@mcp.custom_route("/api/inbox", methods=["GET"])
async def inbox_api(request: Request) -> JSONResponse:
    """Quick unread message count check. Usage: /api/inbox?agent=joshua"""
    agent_name = request.query_params.get("agent", "")
    if not agent_name:
        return JSONResponse({"error": "?agent= required"}, status_code=400)
    mission = db.get_active_mission()
    if not mission:
        return JSONResponse({"count": 0})
    count = db.unread_count(agent_name, mission["id"])
    return JSONResponse({"agent": agent_name, "unread": count})


def _signal_new_message(msg: dict):
    """Write notification signal so watchers detect new messages instantly."""
    import time
    signal_path = "/tmp/blackboard_signal.json"
    try:
        with open(signal_path, "w") as f:
            json.dump({
                "timestamp": msg.get("created_at", ""),
                "from": msg.get("from_agent", ""),
                "to": msg.get("to_agent", ""),
                "type": msg.get("message_type", ""),
                "preview": msg.get("content", "")[:100],
            }, f)
    except Exception:
        pass


# ── PWA Static File Serving ──────────────────────────────
from starlette.responses import FileResponse, Response as StarletteResponse

_pwa_dir = Path(__file__).parent / "pwa"

if _pwa_dir.exists():
    _pwa_content_types = {
        ".html": "text/html",
        ".js": "application/javascript",
        ".json": "application/json",
        ".png": "image/png",
        ".ico": "image/x-icon",
        ".css": "text/css",
        ".svg": "image/svg+xml",
        ".wav": "audio/wav",
    }

    @mcp.custom_route("/{path:path}", methods=["GET"])
    async def serve_pwa(request):
        path = request.path_params.get("path", "")
        if not path or path == "/":
            path = "index.html"
        file_path = _pwa_dir / path
        if file_path.exists() and file_path.is_file() and _pwa_dir in file_path.resolve().parents:
            suffix = file_path.suffix.lower()
            ct = _pwa_content_types.get(suffix, "application/octet-stream")
            return FileResponse(str(file_path), media_type=ct)
        # Fallback: serve index.html for SPA routing
        index = _pwa_dir / "index.html"
        if index.exists():
            return FileResponse(str(index), media_type="text/html")
        return StarletteResponse("Not Found", status_code=404)


# ── Entry Point ──────────────────────────────────────────

if __name__ == "__main__":
    print("[BLACKBOARD] Starting Blackboard MCP Server on 0.0.0.0:9700")
    print("[BLACKBOARD] Agents connect via MCP at http://<host>:9700/mcp")
    print("[BLACKBOARD] Dashboard API at http://<host>:9700/api/dashboard")
    mcp.run(transport="streamable-http")
