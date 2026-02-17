"""
Blackboard MCP Server — Database Layer
SQLite DAL with WAL mode for concurrent agent access.
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

DB_PATH = Path(__file__).parent / "blackboard.db"
_lock = threading.Lock()

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=10000;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    objectives TEXT NOT NULL,
    roe TEXT NOT NULL DEFAULT 'non-destructive',
    target_subnet TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('planning','active','paused','complete')),
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL REFERENCES missions(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    assigned_to TEXT,
    phase TEXT NOT NULL DEFAULT 'recon'
        CHECK(phase IN ('recon','enum','deep_enum','vuln','report')),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','claimed','in_progress','blocked','complete','failed')),
    depends_on TEXT,
    result TEXT,
    artifacts TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    claimed_at TEXT,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL REFERENCES missions(id),
    from_agent TEXT NOT NULL,
    to_agent TEXT NOT NULL,
    content TEXT NOT NULL,
    message_type TEXT NOT NULL DEFAULT 'info'
        CHECK(message_type IN ('info','request','response','alert','status','handoff','directive')),
    created_at TEXT NOT NULL,
    read_at TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL REFERENCES missions(id),
    ip TEXT NOT NULL,
    mac TEXT DEFAULT '',
    vendor TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    os TEXT DEFAULT '',
    asset_class TEXT DEFAULT 'unknown',
    role TEXT DEFAULT 'unknown',
    tier INTEGER DEFAULT 4,
    ports TEXT DEFAULT '[]',
    services TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(mission_id, ip)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL REFERENCES missions(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    cvss REAL DEFAULT 0.0,
    host TEXT DEFAULT '',
    port INTEGER DEFAULT 0,
    description TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    exploit_path TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS training_examples (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL REFERENCES missions(id),
    agent TEXT NOT NULL,
    category TEXT NOT NULL
        CHECK(category IN ('reconnaissance','tactical','analysis',
                           'remediation','code_generation')),
    context TEXT NOT NULL,
    reasoning TEXT NOT NULL,
    action TEXT NOT NULL,
    observation TEXT NOT NULL DEFAULT '',
    conclusion TEXT NOT NULL DEFAULT '',
    tools_used TEXT DEFAULT '[]',
    hosts_involved TEXT DEFAULT '[]',
    phase TEXT DEFAULT 'recon',
    severity_relevant TEXT DEFAULT 'INFO',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent TEXT NOT NULL,
    entry_type TEXT NOT NULL DEFAULT 'CMD'
        CHECK(entry_type IN ('CMD','OUT','ERR','END','WARN','OK','STATUS','CRITICAL')),
    content TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_to);
CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_agent, created_at);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_hosts_tier ON hosts(tier);
CREATE INDEX IF NOT EXISTS idx_training_category ON training_examples(category);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return str(uuid4())


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_connection()
    conn.executescript(SCHEMA_SQL)
    conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def _parse_json_field(val: str, default=None):
    if val is None:
        return default if default is not None else []
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else []


# ── Missions ─────────────────────────────────────────────

def create_mission(name: str, objectives: list[str], roe: str, target_subnet: str) -> dict:
    with _lock:
        conn = get_connection()
        mid = _uuid()
        now = _now()
        conn.execute(
            "INSERT INTO missions (id, name, objectives, roe, target_subnet, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (mid, name, json.dumps(objectives), roe, target_subnet, now)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM missions WHERE id=?", (mid,)).fetchone()
        conn.close()
    result = _row_to_dict(row)
    result["objectives"] = _parse_json_field(result["objectives"])
    return result


def get_active_mission() -> dict | None:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM missions WHERE status='active' ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if not row:
        return None
    result = _row_to_dict(row)
    result["objectives"] = _parse_json_field(result["objectives"])
    return result


def complete_mission(mission_id: str, summary: str) -> dict:
    with _lock:
        conn = get_connection()
        now = _now()
        conn.execute(
            "UPDATE missions SET status='complete', completed_at=? WHERE id=?",
            (now, mission_id)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM missions WHERE id=?", (mission_id,)).fetchone()
        conn.close()
    result = _row_to_dict(row)
    result["objectives"] = _parse_json_field(result["objectives"])
    result["completion_summary"] = summary
    return result


# ── Tasks ────────────────────────────────────────────────

def create_task(mission_id: str, title: str, description: str,
                assigned_to: str | None, phase: str,
                depends_on: list[str] | None) -> dict:
    with _lock:
        conn = get_connection()
        tid = _uuid()
        now = _now()
        conn.execute(
            "INSERT INTO tasks (id, mission_id, title, description, assigned_to, "
            "phase, depends_on, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (tid, mission_id, title, description, assigned_to, phase,
             json.dumps(depends_on) if depends_on else None, now, now)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
        conn.close()
    return _task_from_row(row)


def get_tasks(status_filter: str | None, mission_id: str) -> list[dict]:
    conn = get_connection()
    if status_filter:
        rows = conn.execute(
            "SELECT * FROM tasks WHERE mission_id=? AND status=? ORDER BY created_at",
            (mission_id, status_filter)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM tasks WHERE mission_id=? ORDER BY created_at",
            (mission_id,)
        ).fetchall()
    conn.close()
    return [_task_from_row(r) for r in rows]


def claim_task(task_id: str, agent_name: str) -> dict:
    with _lock:
        conn = get_connection()
        now = _now()
        conn.execute(
            "UPDATE tasks SET assigned_to=?, status='claimed', claimed_at=?, updated_at=? "
            "WHERE id=?",
            (agent_name, now, now, task_id)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
    return _task_from_row(row)


def update_task(task_id: str, status: str, result: str | None) -> dict:
    with _lock:
        conn = get_connection()
        now = _now()
        if result:
            conn.execute(
                "UPDATE tasks SET status=?, result=?, updated_at=? WHERE id=?",
                (status, result, now, task_id)
            )
        else:
            conn.execute(
                "UPDATE tasks SET status=?, updated_at=? WHERE id=?",
                (status, now, task_id)
            )
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
    return _task_from_row(row)


def complete_task(task_id: str, result: str, artifacts: list[str] | None) -> dict:
    with _lock:
        conn = get_connection()
        now = _now()
        conn.execute(
            "UPDATE tasks SET status='complete', result=?, artifacts=?, "
            "completed_at=?, updated_at=? WHERE id=?",
            (result, json.dumps(artifacts) if artifacts else None, now, now, task_id)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
    return _task_from_row(row)


def _task_from_row(row: sqlite3.Row) -> dict:
    d = _row_to_dict(row)
    d["depends_on"] = _parse_json_field(d.get("depends_on"))
    d["artifacts"] = _parse_json_field(d.get("artifacts"))
    return d


# ── Messages ─────────────────────────────────────────────

def send_message(mission_id: str, from_agent: str, to_agent: str,
                 content: str, message_type: str) -> dict:
    with _lock:
        conn = get_connection()
        mid = _uuid()
        now = _now()
        conn.execute(
            "INSERT INTO messages (id, mission_id, from_agent, to_agent, content, "
            "message_type, created_at) VALUES (?,?,?,?,?,?,?)",
            (mid, mission_id, from_agent, to_agent, content, message_type, now)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        conn.close()
    return _row_to_dict(row)


def get_messages(agent_name: str, since: str | None, mission_id: str) -> list[dict]:
    conn = get_connection()
    if since:
        rows = conn.execute(
            "SELECT * FROM messages WHERE mission_id=? AND "
            "(to_agent=? OR to_agent='all') AND created_at>? ORDER BY created_at",
            (mission_id, agent_name, since)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM messages WHERE mission_id=? AND "
            "(to_agent=? OR to_agent='all') ORDER BY created_at",
            (mission_id, agent_name)
        ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def broadcast(mission_id: str, from_agent: str, content: str) -> dict:
    return send_message(mission_id, from_agent, "all", content, "info")


def check_inbox(agent_name: str, mission_id: str, mark_read: bool = True) -> dict:
    """Return unread messages for an agent and optionally mark them read."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM messages WHERE mission_id=? AND "
        "(to_agent=? OR to_agent='all') AND read_at IS NULL "
        "AND from_agent != ? ORDER BY created_at",
        (mission_id, agent_name, agent_name)
    ).fetchall()
    msgs = [_row_to_dict(r) for r in rows]
    if mark_read and msgs:
        with _lock:
            ids = [m["id"] for m in msgs]
            now = _now()
            conn.executemany(
                "UPDATE messages SET read_at=? WHERE id=?",
                [(now, mid) for mid in ids]
            )
            conn.commit()
    conn.close()
    return {"count": len(msgs), "messages": msgs}


def unread_count(agent_name: str, mission_id: str) -> int:
    """Fast count of unread messages for an agent."""
    conn = get_connection()
    row = conn.execute(
        "SELECT COUNT(*) as c FROM messages WHERE mission_id=? AND "
        "(to_agent=? OR to_agent='all') AND read_at IS NULL AND from_agent != ?",
        (mission_id, agent_name, agent_name)
    ).fetchone()
    conn.close()
    return row["c"]


# ── Hosts ────────────────────────────────────────────────

def post_host(mission_id: str, ip: str, mac: str, vendor: str,
              hostname: str, os: str, asset_class: str, role: str,
              tier: int, ports: list[dict], services: list[str]) -> dict:
    with _lock:
        conn = get_connection()
        hid = _uuid()
        now = _now()
        conn.execute(
            "INSERT INTO hosts (id, mission_id, ip, mac, vendor, hostname, os, "
            "asset_class, role, tier, ports, services, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(mission_id, ip) DO UPDATE SET "
            "mac=excluded.mac, vendor=excluded.vendor, hostname=excluded.hostname, "
            "os=excluded.os, asset_class=excluded.asset_class, role=excluded.role, "
            "tier=excluded.tier, ports=excluded.ports, services=excluded.services, "
            "updated_at=excluded.updated_at",
            (hid, mission_id, ip, mac, vendor, hostname, os, asset_class, role,
             tier, json.dumps(ports), json.dumps(services), now, now)
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM hosts WHERE mission_id=? AND ip=?", (mission_id, ip)
        ).fetchone()
        conn.close()
    return _host_from_row(row)


def get_hosts(tier: int | None, mission_id: str) -> list[dict]:
    conn = get_connection()
    if tier is not None:
        rows = conn.execute(
            "SELECT * FROM hosts WHERE mission_id=? AND tier=? ORDER BY ip",
            (mission_id, tier)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM hosts WHERE mission_id=? ORDER BY tier, ip",
            (mission_id,)
        ).fetchall()
    conn.close()
    return [_host_from_row(r) for r in rows]


def _host_from_row(row: sqlite3.Row) -> dict:
    d = _row_to_dict(row)
    d["ports"] = _parse_json_field(d.get("ports"))
    d["services"] = _parse_json_field(d.get("services"))
    return d


# ── Findings ─────────────────────────────────────────────

def post_finding(mission_id: str, title: str, severity: str, cvss: float,
                 host: str, port: int, description: str, evidence: str,
                 remediation: str, exploit_path: str) -> dict:
    with _lock:
        conn = get_connection()
        fid = _uuid()
        now = _now()
        conn.execute(
            "INSERT INTO findings (id, mission_id, title, severity, cvss, host, port, "
            "description, evidence, remediation, exploit_path, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (fid, mission_id, title, severity, cvss, host, port,
             description, evidence, remediation, exploit_path, now)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        conn.close()
    return _row_to_dict(row)


def get_findings(severity: str | None, host: str | None, mission_id: str) -> list[dict]:
    conn = get_connection()
    query = "SELECT * FROM findings WHERE mission_id=?"
    params: list = [mission_id]
    if severity:
        query += " AND severity=?"
        params.append(severity)
    if host:
        query += " AND host=?"
        params.append(host)
    query += " ORDER BY cvss DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


# ── Training Examples ────────────────────────────────────

def submit_training_example(mission_id: str, agent: str, category: str,
                            context: str, reasoning: str, action: str,
                            observation: str, conclusion: str,
                            tools_used: list[str], hosts_involved: list[str],
                            phase: str, severity_relevant: str) -> dict:
    with _lock:
        conn = get_connection()
        eid = _uuid()
        now = _now()
        conn.execute(
            "INSERT INTO training_examples (id, mission_id, agent, category, context, "
            "reasoning, action, observation, conclusion, tools_used, hosts_involved, "
            "phase, severity_relevant, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, mission_id, agent, category, context, reasoning, action,
             observation, conclusion, json.dumps(tools_used),
             json.dumps(hosts_involved), phase, severity_relevant, now)
        )
        conn.commit()
        row = conn.execute("SELECT * FROM training_examples WHERE id=?", (eid,)).fetchone()
        conn.close()
    d = _row_to_dict(row)
    d["tools_used"] = _parse_json_field(d.get("tools_used"))
    d["hosts_involved"] = _parse_json_field(d.get("hosts_involved"))
    return d


def get_training_data(category: str | None, mission_id: str) -> list[dict]:
    conn = get_connection()
    if category:
        rows = conn.execute(
            "SELECT * FROM training_examples WHERE mission_id=? AND category=? "
            "ORDER BY created_at",
            (mission_id, category)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM training_examples WHERE mission_id=? ORDER BY created_at",
            (mission_id,)
        ).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = _row_to_dict(r)
        d["tools_used"] = _parse_json_field(d.get("tools_used"))
        d["hosts_involved"] = _parse_json_field(d.get("hosts_involved"))
        results.append(d)
    return results


# ── Activity Log ─────────────────────────────────────────

def post_activity(agent: str, entry_type: str, content: str) -> dict:
    """Post an activity log entry from any agent."""
    with _lock:
        conn = get_connection()
        now = _now()
        conn.execute(
            "INSERT INTO activity_log (agent, entry_type, content, created_at) "
            "VALUES (?,?,?,?)",
            (agent, entry_type, content, now)
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM activity_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()
    return _row_to_dict(row)


def get_activity(since_id: int = 0, limit: int = 200) -> list[dict]:
    """Get activity log entries since a given ID."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM activity_log WHERE id > ? ORDER BY id LIMIT ?",
        (since_id, limit)
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


# ── Status ───────────────────────────────────────────────

def get_status(mission_id: str) -> dict:
    conn = get_connection()
    mission = conn.execute("SELECT * FROM missions WHERE id=?", (mission_id,)).fetchone()
    task_counts = {}
    for status in ("pending", "claimed", "in_progress", "blocked", "complete", "failed"):
        row = conn.execute(
            "SELECT COUNT(*) as c FROM tasks WHERE mission_id=? AND status=?",
            (mission_id, status)
        ).fetchone()
        task_counts[status] = row["c"]

    finding_counts = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        row = conn.execute(
            "SELECT COUNT(*) as c FROM findings WHERE mission_id=? AND severity=?",
            (mission_id, sev)
        ).fetchone()
        finding_counts[sev] = row["c"]

    host_count = conn.execute(
        "SELECT COUNT(*) as c FROM hosts WHERE mission_id=?", (mission_id,)
    ).fetchone()["c"]

    training_count = conn.execute(
        "SELECT COUNT(*) as c FROM training_examples WHERE mission_id=?", (mission_id,)
    ).fetchone()["c"]

    agents = conn.execute(
        "SELECT DISTINCT assigned_to FROM tasks WHERE mission_id=? AND assigned_to IS NOT NULL",
        (mission_id,)
    ).fetchall()

    conn.close()

    m = _row_to_dict(mission)
    m["objectives"] = _parse_json_field(m["objectives"])

    return {
        "mission": m,
        "task_counts": task_counts,
        "finding_counts": finding_counts,
        "host_count": host_count,
        "training_examples_count": training_count,
        "agents_active": [r["assigned_to"] for r in agents],
    }
