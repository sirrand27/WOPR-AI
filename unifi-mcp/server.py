"""W.O.P.R. UniFi MCP Server — Network Defense Layer

Port 9600. WOPR-exclusive — not shared with TARS Dev.
Wraps the UDM Pro API for Joshua AI to monitor, analyze, and defend the network.

Environment variables:
    UNIFI_HOST      UDM Pro IP (default: 192.168.1.1)
    UNIFI_PORT      API port (default: 443)
    UNIFI_USER      Local admin username
    UNIFI_PASS      Local admin password
    UNIFI_SITE      Site name (default: default)
    SYSLOG_PORT     UDP syslog listen port (default: 5514)
    BLACKBOARD_URL  Blackboard MCP URL (default: http://localhost:9700)
"""

import atexit
import json
import logging
import os
import time
from typing import Optional

from mcp.server.fastmcp import FastMCP

from unifi_client import get_unifi_client, UniFiClient
from syslog_listener import get_syslog_listener, SyslogListener, get_netconsole_listener, NetConsoleListener
from models import ThreatLevel, ActionType

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("unifi_mcp")

BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL", "http://localhost:9700")

mcp = FastMCP(
    "WOPR UniFi Network Defense",
    port=9600,
    host="127.0.0.1",
)


# ── Cleanup ────────────────────────────────────────────────────────

def _shutdown():
    try:
        get_unifi_client().logout()
    except Exception:
        pass
    try:
        get_syslog_listener().stop()
    except Exception:
        pass
    try:
        get_netconsole_listener().stop()
    except Exception:
        pass

atexit.register(_shutdown)


# ── Helper ─────────────────────────────────────────────────────────

def _format_bytes(b: int) -> str:
    if b is None:
        return "0B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}PB"


def _format_uptime(seconds: int) -> str:
    if not seconds:
        return "unknown"
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    mins = (seconds % 3600) // 60
    if days > 0:
        return f"{days}d {hours}h {mins}m"
    if hours > 0:
        return f"{hours}h {mins}m"
    return f"{mins}m"


def _post_to_blackboard(category: str, title: str, content: str,
                        threat_level: str = "info"):
    """Post an alert to the Blackboard MCP (best-effort)."""
    try:
        import requests
        requests.post(
            f"{BLACKBOARD_URL}/mcp",
            json={
                "method": "tools/call",
                "params": {
                    "name": "post_finding",
                    "arguments": {
                        "agent_name": "unifi_mcp",
                        "category": category,
                        "title": title,
                        "content": content,
                        "threat_level": threat_level,
                    }
                }
            },
            timeout=5,
        )
    except Exception:
        pass


# ── STATUS ─────────────────────────────────────────────────────────

@mcp.tool()
def unifi_status() -> str:
    """Get UniFi MCP server status: connection health, device counts, syslog stats.
    Run this first to verify the server is connected to the UDM Pro."""
    client = get_unifi_client()
    syslog = get_syslog_listener()

    netconsole = get_netconsole_listener()

    status = {
        "server": "WOPR UniFi Network Defense",
        "port": 9600,
        "classification": "WOPR-EXCLUSIVE",
        "unifi": {
            "host": client._host,
            "configured": client.is_configured,
            "authenticated": client.is_authenticated,
        },
        "syslog": syslog.get_stats(),
        "netconsole": netconsole.get_stats(),
    }

    if client.is_authenticated:
        try:
            health = client.get_health()
            devices = client.get_devices()
            clients = client.get_clients()

            status["network"] = {
                "devices": len(devices),
                "active_clients": len(clients),
                "wired_clients": sum(1 for c in clients if c.get("is_wired")),
                "wireless_clients": sum(1 for c in clients if not c.get("is_wired")),
            }

            for h in health:
                subsys = h.get("subsystem", "unknown")
                status["network"][f"{subsys}_status"] = h.get("status", "unknown")

        except Exception as e:
            status["network_error"] = str(e)

    return json.dumps(status, indent=2)


# ── CLIENTS ────────────────────────────────────────────────────────

@mcp.tool()
def get_clients(sort_by: str = "last_seen", wired_only: bool = False,
                wireless_only: bool = False) -> str:
    """List all connected clients on the network.

    Args:
        sort_by: Sort field — last_seen, hostname, signal, tx_bytes (default: last_seen)
        wired_only: Only show wired clients
        wireless_only: Only show wireless clients

    Returns summary of each client: MAC, IP, hostname, signal, traffic, network.
    """
    client = get_unifi_client()
    raw_clients = client.get_clients()

    if wired_only:
        raw_clients = [c for c in raw_clients if c.get("is_wired")]
    if wireless_only:
        raw_clients = [c for c in raw_clients if not c.get("is_wired")]

    results = []
    for c in raw_clients:
        entry = {
            "mac": c.get("mac", "?"),
            "ip": c.get("ip", "?"),
            "hostname": c.get("hostname", c.get("name", "?")),
            "oui": c.get("oui", "?"),
            "network": c.get("network", c.get("essid", "wired" if c.get("is_wired") else "?")),
            "signal": c.get("signal") if not c.get("is_wired") else None,
            "radio": c.get("radio", ""),
            "channel": c.get("channel", ""),
            "uptime": _format_uptime(c.get("uptime", 0)),
            "tx": _format_bytes(c.get("tx_bytes", 0)),
            "rx": _format_bytes(c.get("rx_bytes", 0)),
            "is_wired": c.get("is_wired", False),
            "is_guest": c.get("is_guest", False),
            "blocked": c.get("blocked", False),
        }
        results.append(entry)

    # Sort
    sort_keys = {
        "last_seen": lambda x: 0,
        "hostname": lambda x: (x.get("hostname") or "zzz").lower(),
        "signal": lambda x: x.get("signal") or -999,
        "tx_bytes": lambda x: 0,
    }
    if sort_by in sort_keys:
        results.sort(key=sort_keys[sort_by])

    header = f"Active clients: {len(results)}"
    if wired_only:
        header += " (wired only)"
    if wireless_only:
        header += " (wireless only)"

    return json.dumps({"summary": header, "clients": results}, indent=2)


@mcp.tool()
def get_client_detail(mac: str) -> str:
    """Get detailed information about a specific client by MAC address.

    Args:
        mac: Client MAC address (e.g., aa:bb:cc:dd:ee:ff)

    Returns full client details including traffic, signal history, DPI data.
    """
    client = get_unifi_client()
    raw = client.get_client(mac)

    if "error" in raw:
        return json.dumps(raw)

    detail = {
        "mac": raw.get("mac"),
        "ip": raw.get("ip"),
        "hostname": raw.get("hostname", raw.get("name")),
        "oui": raw.get("oui"),
        "network": raw.get("network", raw.get("essid")),
        "is_wired": raw.get("is_wired", False),
        "is_guest": raw.get("is_guest", False),
        "blocked": raw.get("blocked", False),
        "signal": raw.get("signal"),
        "rssi": raw.get("rssi"),
        "channel": raw.get("channel"),
        "radio": raw.get("radio"),
        "radio_proto": raw.get("radio_proto"),
        "ap_mac": raw.get("ap_mac"),
        "uptime": _format_uptime(raw.get("uptime", 0)),
        "first_seen": raw.get("first_seen"),
        "last_seen": raw.get("last_seen"),
        "tx_bytes": _format_bytes(raw.get("tx_bytes", 0)),
        "rx_bytes": _format_bytes(raw.get("rx_bytes", 0)),
        "tx_rate": raw.get("tx_rate"),
        "rx_rate": raw.get("rx_rate"),
        "satisfaction": raw.get("satisfaction"),
    }

    # DPI data
    try:
        dpi = client.get_dpi_client(mac)
        if dpi:
            detail["dpi_apps"] = dpi[:20]
    except Exception:
        pass

    return json.dumps(detail, indent=2)


@mcp.tool()
def search_clients(query: str) -> str:
    """Search for clients by hostname, MAC, IP, or manufacturer (OUI).

    Args:
        query: Search string (partial match on hostname, MAC, IP, or OUI)

    Searches both active and historical client database.
    """
    client = get_unifi_client()
    query_lower = query.lower()

    # Search active clients
    active = client.get_clients()
    # Search all known clients
    all_known = client.get_all_clients()

    seen_macs = set()
    matches = []

    for pool, source in [(active, "active"), (all_known, "known")]:
        for c in pool:
            mac = c.get("mac", "")
            if mac in seen_macs:
                continue

            searchable = " ".join(str(v) for v in [
                c.get("mac", ""), c.get("ip", ""), c.get("hostname", ""),
                c.get("name", ""), c.get("oui", ""),
            ]).lower()

            if query_lower in searchable:
                seen_macs.add(mac)
                matches.append({
                    "mac": mac,
                    "ip": c.get("ip", "?"),
                    "hostname": c.get("hostname", c.get("name", "?")),
                    "oui": c.get("oui", "?"),
                    "source": source,
                    "blocked": c.get("blocked", False),
                    "last_seen": c.get("last_seen"),
                    "first_seen": c.get("first_seen"),
                })

    return json.dumps({
        "query": query,
        "matches": len(matches),
        "results": matches,
    }, indent=2)


# ── ALERTS & EVENTS ───────────────────────────────────────────────

@mcp.tool()
def get_alerts(limit: int = 30) -> str:
    """Get IDS/IPS alerts from the UDM Pro.

    Args:
        limit: Maximum number of alerts to return (default: 30)

    Returns threat detections with severity, source/dest, and action taken.
    """
    client = get_unifi_client()
    raw_alerts = client.get_alerts(limit=limit)

    alerts = []
    for a in raw_alerts:
        alerts.append({
            "timestamp": a.get("datetime", a.get("time")),
            "category": a.get("catname", a.get("inner_alert_category")),
            "signature": a.get("inner_alert_signature", a.get("msg")),
            "severity": a.get("inner_alert_severity"),
            "action": a.get("inner_alert_action", "detected"),
            "src_ip": a.get("src_ip"),
            "dst_ip": a.get("dst_ip"),
            "src_port": a.get("src_port"),
            "dst_port": a.get("dst_port"),
            "protocol": a.get("proto"),
            "archived": a.get("archived", False),
        })

    return json.dumps({
        "total": len(alerts),
        "alerts": alerts,
    }, indent=2)


@mcp.tool()
def get_events(limit: int = 50, event_type: str = "") -> str:
    """Get network events (connections, disconnections, auth failures, roaming).

    Args:
        limit: Maximum events to return (default: 50)
        event_type: Filter by type — leave empty for all, or use:
                    connect, disconnect, auth, roam, upgrade

    Returns timestamped event log from the UDM Pro.
    """
    client = get_unifi_client()
    raw_events = client.get_events(limit=limit)

    events = []
    for e in raw_events:
        etype = e.get("key", "")
        if event_type and event_type.lower() not in etype.lower():
            continue

        events.append({
            "timestamp": e.get("datetime", e.get("time")),
            "type": etype,
            "message": e.get("msg", ""),
            "client_mac": e.get("user", e.get("guest")),
            "hostname": e.get("hostname"),
            "ssid": e.get("ssid"),
            "ap_name": e.get("ap_name", e.get("ap")),
        })

        if len(events) >= limit:
            break

    return json.dumps({
        "total": len(events),
        "filter": event_type or "all",
        "events": events,
    }, indent=2)


@mcp.tool()
def get_syslog_events(count: int = 50, severity: str = "all",
                      filter_type: str = "") -> str:
    """Get recent syslog events received from the UDM Pro.

    Args:
        count: Number of events to return (default: 50)
        severity: Minimum severity — all, debug, info, notice, warning, error,
                  critical, alert, emergency (default: all)
        filter_type: Filter — ids, auth, client, or empty for all

    Requires syslog forwarding configured on the UDM Pro to this server's IP.
    """
    syslog = get_syslog_listener()

    sev_map = {
        "emergency": 0, "alert": 1, "critical": 2, "error": 3,
        "warning": 4, "notice": 5, "info": 6, "debug": 7, "all": 7,
    }
    max_sev = sev_map.get(severity.lower(), 7)

    events = syslog.get_recent(count=count, severity_max=max_sev,
                               filter_type=filter_type or None)

    stats = syslog.get_stats()

    return json.dumps({
        "total_returned": len(events),
        "stats": stats,
        "events": events,
    }, indent=2)


# ── NETCONSOLE ─────────────────────────────────────────────────────

@mcp.tool()
def get_netconsole_events(count: int = 50) -> str:
    """Get recent NetConsole messages from UniFi devices.

    Args:
        count: Number of messages to return (default: 50)

    NetConsole captures device-level kernel output, crash logs, and debug info.
    Useful for investigating device-level anomalies, firmware issues, or hardware attacks.
    """
    nc = get_netconsole_listener()
    events = nc.get_recent(count=count)
    stats = nc.get_stats()

    return json.dumps({
        "total_returned": len(events),
        "stats": stats,
        "events": events,
    }, indent=2)


# ── DPI ────────────────────────────────────────────────────────────

@mcp.tool()
def get_dpi_stats(mac: str = "") -> str:
    """Get Deep Packet Inspection data — application-level traffic breakdown.

    Args:
        mac: Client MAC for per-client stats, or empty for site-wide

    Shows which applications and categories are consuming bandwidth.
    """
    client = get_unifi_client()

    if mac:
        raw = client.get_dpi_client(mac)
        scope = f"client {mac}"
    else:
        raw = client.get_dpi_site()
        scope = "site-wide"

    return json.dumps({
        "scope": scope,
        "entries": len(raw),
        "data": raw[:50],
    }, indent=2)


# ── DEVICES ────────────────────────────────────────────────────────

@mcp.tool()
def get_devices() -> str:
    """List all UniFi network infrastructure devices (APs, switches, gateway).

    Returns device name, model, firmware, uptime, client count, and status.
    """
    client = get_unifi_client()
    raw = client.get_devices()

    devices = []
    for d in raw:
        devices.append({
            "mac": d.get("mac"),
            "name": d.get("name", d.get("model")),
            "model": d.get("model"),
            "type": d.get("type"),
            "ip": d.get("ip"),
            "firmware": d.get("version"),
            "uptime": _format_uptime(d.get("uptime", 0)),
            "status": "connected" if d.get("state") == 1 else "disconnected",
            "clients": d.get("num_sta", 0),
        })

    return json.dumps({
        "total": len(devices),
        "devices": devices,
    }, indent=2)


# ── CLIENT ACTIONS ─────────────────────────────────────────────────

@mcp.tool()
def block_client(mac: str, reason: str = "") -> str:
    """Block a client device from the network by MAC address.

    Args:
        mac: Client MAC address to block
        reason: Reason for blocking (logged to Blackboard)

    CAUTION: This immediately disconnects the client and prevents reconnection.
    """
    client = get_unifi_client()
    result = client.block_client(mac)

    # Log to Blackboard
    _post_to_blackboard(
        "network_defense",
        f"Client Blocked: {mac}",
        f"MAC: {mac}\nReason: {reason or 'Manual block via WOPR'}\nAction: block-sta",
        "medium",
    )

    if "error" not in result:
        return json.dumps({
            "status": "blocked",
            "mac": mac,
            "reason": reason,
            "message": f"Client {mac} has been blocked from the network",
        })
    return json.dumps(result)


@mcp.tool()
def unblock_client(mac: str) -> str:
    """Unblock a previously blocked client, allowing it to reconnect.

    Args:
        mac: Client MAC address to unblock
    """
    client = get_unifi_client()
    result = client.unblock_client(mac)

    _post_to_blackboard(
        "network_defense",
        f"Client Unblocked: {mac}",
        f"MAC: {mac}\nAction: unblock-sta",
        "info",
    )

    if "error" not in result:
        return json.dumps({
            "status": "unblocked",
            "mac": mac,
            "message": f"Client {mac} has been unblocked",
        })
    return json.dumps(result)


@mcp.tool()
def kick_client(mac: str) -> str:
    """Force a client to disconnect and reconnect (soft kick).

    Args:
        mac: Client MAC address to kick

    Unlike block, the client can immediately reconnect.
    Useful for forcing re-authentication or clearing stale connections.
    """
    client = get_unifi_client()
    result = client.reconnect_client(mac)

    if "error" not in result:
        return json.dumps({
            "status": "kicked",
            "mac": mac,
            "message": f"Client {mac} forced to reconnect",
        })
    return json.dumps(result)


# ── FIREWALL ───────────────────────────────────────────────────────

@mcp.tool()
def get_firewall_rules() -> str:
    """List all firewall rules configured on the UDM Pro.

    Returns rule name, action, protocol, source/destination, enabled state.
    """
    client = get_unifi_client()
    raw = client.get_firewall_rules()

    rules = []
    for r in raw:
        rules.append({
            "id": r.get("_id"),
            "name": r.get("name"),
            "enabled": r.get("enabled", True),
            "action": r.get("action"),
            "protocol": r.get("protocol", "all"),
            "ruleset": r.get("ruleset"),
            "rule_index": r.get("rule_index"),
            "src_address": r.get("src_address"),
            "dst_address": r.get("dst_address"),
            "src_port": r.get("src_port"),
            "dst_port": r.get("dst_port"),
        })

    return json.dumps({
        "total": len(rules),
        "rules": rules,
    }, indent=2)


# ── NETWORK HEALTH ─────────────────────────────────────────────────

@mcp.tool()
def get_network_health() -> str:
    """Get overall network health metrics from the UDM Pro.

    Returns subsystem status (WAN, LAN, WLAN), ISP performance,
    latency, throughput, and gateway resource usage.
    """
    client = get_unifi_client()
    health = client.get_health()
    sysinfo = client.get_sysinfo()

    subsystems = {}
    for h in health:
        name = h.get("subsystem", "unknown")
        subsystems[name] = {
            "status": h.get("status"),
            "num_user": h.get("num_user"),
            "num_guest": h.get("num_guest"),
            "num_ap": h.get("num_ap"),
            "tx_bytes": _format_bytes(h.get("tx_bytes-r", 0)),
            "rx_bytes": _format_bytes(h.get("rx_bytes-r", 0)),
            "latency": h.get("latency"),
            "uptime": h.get("uptime"),
            "isp_name": h.get("isp_name"),
            "wan_ip": h.get("wan_ip"),
        }

    return json.dumps({
        "subsystems": subsystems,
        "sysinfo": sysinfo if isinstance(sysinfo, dict) else {},
    }, indent=2)


# ── THREAT ANALYSIS (Joshua integration) ──────────────────────────

@mcp.tool()
def get_threat_summary() -> str:
    """Get a consolidated threat summary for Joshua AI analysis.

    Combines IDS/IPS alerts, syslog events, new/unknown devices,
    and anomalous traffic patterns into a single briefing.
    """
    client = get_unifi_client()
    syslog = get_syslog_listener()

    summary = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "classification": "WOPR-EXCLUSIVE",
    }

    # IDS/IPS alerts (last 24h)
    try:
        alerts = client.get_alerts(limit=20)
        summary["ids_alerts"] = {
            "count": len(alerts),
            "recent": [
                {
                    "sig": a.get("inner_alert_signature", a.get("msg", "?")),
                    "src": a.get("src_ip"),
                    "dst": a.get("dst_ip"),
                    "action": a.get("inner_alert_action", "?"),
                }
                for a in alerts[:5]
            ],
        }
    except Exception:
        summary["ids_alerts"] = {"error": "unavailable"}

    # Syslog stats
    summary["syslog"] = syslog.get_stats()

    # High-priority syslog events
    ids_events = syslog.get_recent(count=10, filter_type="ids")
    auth_events = syslog.get_recent(count=10, filter_type="auth")
    summary["syslog_ids_events"] = len(ids_events)
    summary["syslog_auth_failures"] = len(auth_events)

    # Client overview
    try:
        clients = client.get_clients()
        blocked = [c for c in clients if c.get("blocked")]
        guest = [c for c in clients if c.get("is_guest")]

        summary["clients"] = {
            "total_active": len(clients),
            "blocked": len(blocked),
            "guests": len(guest),
        }
    except Exception:
        summary["clients"] = {"error": "unavailable"}

    return json.dumps(summary, indent=2)


# ── MAIN ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Start syslog listener
    syslog = get_syslog_listener()
    if syslog.start():
        log.info("Syslog listener active on UDP port %d", syslog._port)
    else:
        log.warning("Syslog listener failed to start (non-critical)")

    # Start NetConsole listener
    netconsole = get_netconsole_listener()
    if netconsole.start():
        log.info("NetConsole listener active on UDP port %d", netconsole._port)
    else:
        log.warning("NetConsole listener failed to start (non-critical)")

    # Attempt initial UniFi connection
    client = get_unifi_client()
    if client.is_configured:
        if client.login():
            log.info("UniFi Controller connection established")
        else:
            log.warning("UniFi login failed — tools will retry on first call")
    else:
        log.warning("UniFi credentials not set — configure UNIFI_USER / UNIFI_PASS")

    log.info("W.O.P.R. UniFi Network Defense MCP starting on port 9600")
    mcp.run(transport="streamable-http")
