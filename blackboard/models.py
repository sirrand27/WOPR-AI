"""
Blackboard MCP Server — Data Models
Pydantic v2 models for all blackboard data structures.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel


# ── Enums ────────────────────────────────────────────────

class MissionStatus(str, Enum):
    planning = "planning"
    active = "active"
    paused = "paused"
    complete = "complete"


class TaskStatus(str, Enum):
    pending = "pending"
    claimed = "claimed"
    in_progress = "in_progress"
    blocked = "blocked"
    complete = "complete"
    failed = "failed"


class Phase(str, Enum):
    recon = "recon"
    enum = "enum"
    deep_enum = "deep_enum"
    vuln = "vuln"
    report = "report"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class MessageType(str, Enum):
    info = "info"
    request = "request"
    response = "response"
    alert = "alert"
    status = "status"
    handoff = "handoff"


class TrainingCategory(str, Enum):
    reconnaissance = "reconnaissance"
    tactical = "tactical"
    analysis = "analysis"
    remediation = "remediation"
    code_generation = "code_generation"


# ── Shared Sub-models ────────────────────────────────────

class PortModel(BaseModel):
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""
