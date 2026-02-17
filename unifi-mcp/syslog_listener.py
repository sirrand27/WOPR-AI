"""Syslog listener for UDM Pro event ingestion.

Receives syslog messages from UDM Pro over UDP 514 (or configurable port).
Parses events and stores them in a ring buffer for Joshua to query.
Fires callbacks for high-priority events (IDS alerts, auth failures).
"""

import logging
import os
import re
import socket
import threading
import time
from collections import deque
from typing import Callable, Optional

log = logging.getLogger("unifi_mcp.syslog")

SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "5514"))  # non-root port
BUFFER_SIZE = int(os.environ.get("SYSLOG_BUFFER", "2000"))

# Syslog severity levels
SEVERITY = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

# Patterns for high-priority events
IDS_PATTERN = re.compile(r"IDS|IPS|threat|intrusion|attack|exploit", re.I)
AUTH_PATTERN = re.compile(r"auth.*fail|login.*fail|invalid.*password|unauthorized", re.I)
CLIENT_PATTERN = re.compile(r"(assoc|disassoc|connect|disconnect|roam)", re.I)
DHCP_PATTERN = re.compile(r"DHCP(ACK|DISCOVER|REQUEST|OFFER)", re.I)


class SyslogEvent:
    __slots__ = ("timestamp", "severity", "facility", "source", "message", "raw")

    def __init__(self, timestamp: float, severity: int, facility: int,
                 source: str, message: str, raw: str):
        self.timestamp = timestamp
        self.severity = severity
        self.facility = facility
        self.source = source
        self.message = message
        self.raw = raw

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "severity": SEVERITY.get(self.severity, "unknown"),
            "severity_num": self.severity,
            "source": self.source,
            "message": self.message,
            "is_ids": bool(IDS_PATTERN.search(self.message)),
            "is_auth_failure": bool(AUTH_PATTERN.search(self.message)),
            "is_client_event": bool(CLIENT_PATTERN.search(self.message)),
        }


class SyslogListener:
    """UDP syslog receiver with ring buffer and event callbacks."""

    def __init__(self, port: int = SYSLOG_PORT, buffer_size: int = BUFFER_SIZE):
        self._port = port
        self._buffer: deque[SyslogEvent] = deque(maxlen=buffer_size)
        self._callbacks: list[Callable[[SyslogEvent], None]] = []
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self._stats = {
            "messages_received": 0,
            "ids_alerts": 0,
            "auth_failures": 0,
            "client_events": 0,
            "errors": 0,
        }

    def add_callback(self, callback: Callable[[SyslogEvent], None]):
        """Register a callback for incoming syslog events."""
        self._callbacks.append(callback)

    def start(self) -> bool:
        """Start listening for syslog messages."""
        if self._running:
            return True

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self._port))
            self._sock.settimeout(1.0)
            self._running = True
            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
            log.info("Syslog listener started on UDP port %d", self._port)
            return True
        except Exception as e:
            log.error("Failed to start syslog listener: %s", e)
            return False

    def stop(self):
        """Stop the listener."""
        self._running = False
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=3)
        log.info("Syslog listener stopped")

    def _listen_loop(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
                message = data.decode("utf-8", errors="replace")
                event = self._parse(message, addr[0])
                if event:
                    with self._lock:
                        self._buffer.append(event)
                        self._stats["messages_received"] += 1
                        if IDS_PATTERN.search(event.message):
                            self._stats["ids_alerts"] += 1
                        if AUTH_PATTERN.search(event.message):
                            self._stats["auth_failures"] += 1
                        if CLIENT_PATTERN.search(event.message):
                            self._stats["client_events"] += 1

                    for cb in self._callbacks:
                        try:
                            cb(event)
                        except Exception as e:
                            log.warning("Callback error: %s", e)

            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    self._stats["errors"] += 1
                break
            except Exception as e:
                self._stats["errors"] += 1
                log.warning("Syslog receive error: %s", e)

    def _parse(self, raw: str, source: str) -> Optional[SyslogEvent]:
        """Parse RFC 3164 / RFC 5424 syslog message."""
        severity = 6  # default: info
        facility = 1  # default: user

        # Extract PRI field: <PRI>
        m = re.match(r"<(\d+)>(.*)", raw)
        if m:
            pri = int(m.group(1))
            facility = pri >> 3
            severity = pri & 0x07
            raw_msg = m.group(2).strip()
        else:
            raw_msg = raw.strip()

        return SyslogEvent(
            timestamp=time.time(),
            severity=severity,
            facility=facility,
            source=source,
            message=raw_msg,
            raw=raw,
        )

    def get_recent(self, count: int = 50, severity_max: int = 7,
                   filter_type: str = None) -> list[dict]:
        """Get recent syslog events from the ring buffer."""
        with self._lock:
            events = list(self._buffer)

        # Filter
        filtered = []
        for e in reversed(events):  # newest first
            if e.severity > severity_max:
                continue
            if filter_type == "ids" and not IDS_PATTERN.search(e.message):
                continue
            if filter_type == "auth" and not AUTH_PATTERN.search(e.message):
                continue
            if filter_type == "client" and not CLIENT_PATTERN.search(e.message):
                continue
            filtered.append(e.to_dict())
            if len(filtered) >= count:
                break

        return filtered

    def get_stats(self) -> dict:
        with self._lock:
            stats = dict(self._stats)
            stats["buffer_size"] = len(self._buffer)
            stats["buffer_capacity"] = self._buffer.maxlen
            stats["port"] = self._port
            stats["running"] = self._running
        return stats


class NetConsoleListener:
    """UDP NetConsole receiver for UniFi device kernel/debug output.

    Separate from syslog — captures low-level device diagnostics.
    """

    NETCONSOLE_PORT = int(os.environ.get("NETCONSOLE_PORT", "5515"))

    def __init__(self, port: int = 0, buffer_size: int = BUFFER_SIZE):
        self._port = port or self.NETCONSOLE_PORT
        self._buffer: deque[dict] = deque(maxlen=buffer_size)
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self._stats = {"messages_received": 0, "errors": 0}

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self._port))
            self._sock.settimeout(1.0)
            self._running = True
            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
            log.info("NetConsole listener started on UDP port %d", self._port)
            return True
        except Exception as e:
            log.error("Failed to start NetConsole listener: %s", e)
            return False

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=3)

    def _listen_loop(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
                message = data.decode("utf-8", errors="replace").strip()
                if message:
                    entry = {
                        "timestamp": time.time(),
                        "source": addr[0],
                        "message": message,
                    }
                    with self._lock:
                        self._buffer.append(entry)
                        self._stats["messages_received"] += 1
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    self._stats["errors"] += 1
                break
            except Exception:
                self._stats["errors"] += 1

    def get_recent(self, count: int = 50) -> list[dict]:
        with self._lock:
            events = list(self._buffer)
        return list(reversed(events))[:count]

    def get_stats(self) -> dict:
        with self._lock:
            stats = dict(self._stats)
            stats["buffer_size"] = len(self._buffer)
            stats["port"] = self._port
            stats["running"] = self._running
        return stats


# Singletons
_listener: Optional[SyslogListener] = None
_netconsole: Optional[NetConsoleListener] = None


def get_syslog_listener() -> SyslogListener:
    global _listener
    if _listener is None:
        _listener = SyslogListener()
    return _listener


def get_netconsole_listener() -> NetConsoleListener:
    global _netconsole
    if _netconsole is None:
        _netconsole = NetConsoleListener()
    return _netconsole
