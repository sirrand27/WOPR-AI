"""Pydantic models for UniFi MCP server."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel


class ThreatLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(str, Enum):
    BLOCK = "block"
    UNBLOCK = "unblock"
    ALERT = "alert"
    QUARANTINE = "quarantine"


class Client(BaseModel):
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    oui: Optional[str] = None  # manufacturer
    network: Optional[str] = None
    signal: Optional[int] = None
    rssi: Optional[int] = None
    channel: Optional[int] = None
    radio: Optional[str] = None  # 2.4GHz / 5GHz / 6GHz
    essid: Optional[str] = None
    ap_name: Optional[str] = None
    uptime: Optional[int] = None  # seconds
    tx_bytes: Optional[int] = None
    rx_bytes: Optional[int] = None
    tx_rate: Optional[int] = None  # kbps
    rx_rate: Optional[int] = None  # kbps
    is_wired: bool = False
    is_guest: bool = False
    blocked: bool = False
    first_seen: Optional[int] = None  # epoch
    last_seen: Optional[int] = None  # epoch
    raw: Optional[dict] = None


class Alert(BaseModel):
    id: Optional[str] = None
    timestamp: Optional[int] = None
    category: Optional[str] = None
    signature: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None  # blocked / detected
    severity: Optional[str] = None
    raw: Optional[dict] = None


class Event(BaseModel):
    id: Optional[str] = None
    timestamp: Optional[int] = None
    event_type: Optional[str] = None
    message: Optional[str] = None
    client_mac: Optional[str] = None
    hostname: Optional[str] = None
    ssid: Optional[str] = None
    ap_name: Optional[str] = None
    raw: Optional[dict] = None


class Device(BaseModel):
    mac: str
    name: Optional[str] = None
    model: Optional[str] = None
    type: Optional[str] = None  # uap, usw, ugw
    ip: Optional[str] = None
    firmware: Optional[str] = None
    uptime: Optional[int] = None
    status: Optional[str] = None  # connected, disconnected
    clients: Optional[int] = None
    raw: Optional[dict] = None


class DpiApp(BaseModel):
    app: Optional[str] = None
    category: Optional[str] = None
    tx_bytes: int = 0
    rx_bytes: int = 0
    client_mac: Optional[str] = None
