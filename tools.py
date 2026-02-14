"""
Local Joshua AI Agent — Tool Wrappers
Subprocess wrappers for OSINT tools and HTTP clients for MCP services.
"""

import json
import logging
import subprocess
import urllib.request
import urllib.error

from config import COURT_RECORDS_URL, UNIFI_MCP_URL, FLIPPER_MCP_URL

logger = logging.getLogger(__name__)

# Tool timeout in seconds
TOOL_TIMEOUT = 120


def _run_cmd(cmd, timeout=TOOL_TIMEOUT):
    """Run a shell command and return stdout/stderr."""
    logger.info(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout.strip()
        if result.returncode != 0 and result.stderr:
            output += f"\n[STDERR] {result.stderr.strip()}"
        return output if output else "[No output]"
    except subprocess.TimeoutExpired:
        return f"[ERROR] Command timed out after {timeout}s"
    except FileNotFoundError:
        return f"[ERROR] Tool not found: {cmd[0]}"
    except Exception as e:
        return f"[ERROR] {e}"


def _http_request(url, method="GET", data=None, timeout=30):
    """Make an HTTP request and return JSON response."""
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(
        url, data=body, method=method,
        headers={"Content-Type": "application/json"} if body else {}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


# === OSINT Tool Wrappers ===

def sherlock(username, timeout=90):
    """Run Sherlock username enumeration."""
    return _run_cmd(
        ["sherlock", username, "--print-found", "--timeout", "15"],
        timeout=timeout
    )


def theharvester(domain, source="all", limit=200):
    """Run theHarvester for domain/email OSINT."""
    return _run_cmd(
        ["theHarvester", "-d", domain, "-b", source, "-l", str(limit)],
        timeout=TOOL_TIMEOUT
    )


def whatweb(target):
    """Run WhatWeb for web technology fingerprinting."""
    return _run_cmd(
        ["whatweb", "--color=never", target],
        timeout=60
    )


def fierce(domain):
    """Run fierce for DNS enumeration."""
    return _run_cmd(
        ["fierce", "--domain", domain],
        timeout=90
    )


def dnsrecon(domain, record_type="std"):
    """Run dnsrecon for DNS reconnaissance."""
    return _run_cmd(
        ["dnsrecon", "-d", domain, "-t", record_type],
        timeout=90
    )


def photon(url, depth=2):
    """Run Photon for web crawling and data extraction."""
    return _run_cmd(
        ["photon", "-u", url, "-l", str(depth), "--stdout"],
        timeout=TOOL_TIMEOUT
    )


def h8mail(target):
    """Run h8mail for breach/credential OSINT."""
    return _run_cmd(
        ["h8mail", "-t", target, "--loose"],
        timeout=90
    )


# === MCP Service Wrappers ===

def court_records_search(first_name, last_name, state=""):
    """Search court records via Court Records MCP on :9800."""
    url = f"{COURT_RECORDS_URL}/mcp"
    data = {
        "method": "tools/call",
        "params": {
            "name": "get_criminal_history",
            "arguments": {
                "first_name": first_name,
                "last_name": last_name,
            }
        }
    }
    if state:
        data["params"]["arguments"]["state"] = state
    result = _http_request(url, method="POST", data=data, timeout=60)
    if "error" in result:
        return f"[ERROR] Court Records MCP: {result['error']}"
    return json.dumps(result, indent=2)


def court_records_case(case_number, court=""):
    """Search by case number via Court Records MCP."""
    url = f"{COURT_RECORDS_URL}/mcp"
    data = {
        "method": "tools/call",
        "params": {
            "name": "search_case_number",
            "arguments": {"case_number": case_number}
        }
    }
    if court:
        data["params"]["arguments"]["court"] = court
    result = _http_request(url, method="POST", data=data, timeout=60)
    if "error" in result:
        return f"[ERROR] Court Records MCP: {result['error']}"
    return json.dumps(result, indent=2)


# === UniFi MCP Wrappers ===

def _mcp_call(base_url, tool_name, arguments=None, timeout=15):
    """Generic MCP tool call via HTTP POST."""
    url = f"{base_url}/mcp"
    data = {
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments or {}
        }
    }
    result = _http_request(url, method="POST", data=data, timeout=timeout)
    if "error" in result:
        return f"[ERROR] MCP {tool_name}: {result['error']}"
    return json.dumps(result, indent=2)


def unifi_get_clients():
    """Get all connected clients from UniFi."""
    return _mcp_call(UNIFI_MCP_URL, "get_clients", timeout=30)


def unifi_get_client_detail(mac):
    """Get detailed info for a specific client."""
    return _mcp_call(UNIFI_MCP_URL, "get_client_detail", {"mac": mac})


def unifi_search_clients(query):
    """Search clients by name/MAC/IP."""
    return _mcp_call(UNIFI_MCP_URL, "search_clients", {"query": query})


def unifi_get_devices():
    """Get all UniFi network devices."""
    return _mcp_call(UNIFI_MCP_URL, "get_devices")


def unifi_get_network_health():
    """Get network health status."""
    return _mcp_call(UNIFI_MCP_URL, "get_network_health")


def unifi_get_firewall_rules():
    """Get firewall rules."""
    return _mcp_call(UNIFI_MCP_URL, "get_firewall_rules")


def unifi_get_dpi_stats():
    """Get DPI (Deep Packet Inspection) statistics."""
    return _mcp_call(UNIFI_MCP_URL, "get_dpi_stats", timeout=30)


def unifi_get_alerts(limit=50):
    """Get recent alerts."""
    return _mcp_call(UNIFI_MCP_URL, "get_alerts", {"limit": limit})


def unifi_get_events(limit=50):
    """Get recent events."""
    return _mcp_call(UNIFI_MCP_URL, "get_events", {"limit": limit})


def unifi_block_client(mac, reason=""):
    """Block a client by MAC address."""
    return _mcp_call(UNIFI_MCP_URL, "block_client", {"mac": mac, "reason": reason})


def unifi_unblock_client(mac):
    """Unblock a client by MAC address."""
    return _mcp_call(UNIFI_MCP_URL, "unblock_client", {"mac": mac})


def unifi_kick_client(mac):
    """Kick (disconnect) a client by MAC address."""
    return _mcp_call(UNIFI_MCP_URL, "kick_client", {"mac": mac})


# === Flipper Zero MCP Wrappers ===

def flipper_call(tool_name, arguments=None):
    """Call a Flipper Zero MCP tool."""
    return _mcp_call(FLIPPER_MCP_URL, tool_name, arguments, timeout=30)


# === Tool Registry ===

TOOL_REGISTRY = {
    "sherlock": {
        "fn": lambda args: sherlock(args.get("username", "")),
        "description": "Username enumeration across social platforms",
        "params": ["username"]
    },
    "theharvester": {
        "fn": lambda args: theharvester(
            args.get("domain", ""),
            args.get("source", "all"),
            args.get("limit", 200)
        ),
        "description": "Domain and email OSINT",
        "params": ["domain", "source?", "limit?"]
    },
    "whatweb": {
        "fn": lambda args: whatweb(args.get("target", args.get("url", ""))),
        "description": "Web technology fingerprinting",
        "params": ["target"]
    },
    "fierce": {
        "fn": lambda args: fierce(args.get("domain", "")),
        "description": "DNS enumeration and zone transfer attempts",
        "params": ["domain"]
    },
    "dnsrecon": {
        "fn": lambda args: dnsrecon(
            args.get("domain", ""),
            args.get("type", "std")
        ),
        "description": "DNS reconnaissance",
        "params": ["domain", "type?"]
    },
    "photon": {
        "fn": lambda args: photon(
            args.get("url", ""),
            args.get("depth", 2)
        ),
        "description": "Web crawling and data extraction",
        "params": ["url", "depth?"]
    },
    "h8mail": {
        "fn": lambda args: h8mail(args.get("target", args.get("email", ""))),
        "description": "Breach and credential OSINT",
        "params": ["target"]
    },
    "court_records": {
        "fn": lambda args: court_records_search(
            args.get("first_name", ""),
            args.get("last_name", ""),
            args.get("state", "")
        ),
        "description": "Criminal history search via Court Records MCP",
        "params": ["first_name", "last_name", "state?"]
    },
    "court_case": {
        "fn": lambda args: court_records_case(
            args.get("case_number", ""),
            args.get("court", "")
        ),
        "description": "Case number lookup via Court Records MCP",
        "params": ["case_number", "court?"]
    },
    # UniFi Network Defense tools
    "unifi_clients": {
        "fn": lambda args: unifi_get_clients(),
        "description": "List all connected UniFi network clients",
        "params": []
    },
    "unifi_client_detail": {
        "fn": lambda args: unifi_get_client_detail(args.get("mac", "")),
        "description": "Get detailed info for a UniFi client by MAC",
        "params": ["mac"]
    },
    "unifi_search": {
        "fn": lambda args: unifi_search_clients(args.get("query", "")),
        "description": "Search UniFi clients by name/MAC/IP",
        "params": ["query"]
    },
    "unifi_devices": {
        "fn": lambda args: unifi_get_devices(),
        "description": "List all UniFi network devices (APs, switches, gateways)",
        "params": []
    },
    "unifi_health": {
        "fn": lambda args: unifi_get_network_health(),
        "description": "Get UniFi network health status",
        "params": []
    },
    "unifi_firewall": {
        "fn": lambda args: unifi_get_firewall_rules(),
        "description": "Get UniFi firewall rules",
        "params": []
    },
    "unifi_dpi": {
        "fn": lambda args: unifi_get_dpi_stats(),
        "description": "Get Deep Packet Inspection statistics",
        "params": []
    },
    "unifi_alerts": {
        "fn": lambda args: unifi_get_alerts(args.get("limit", 50)),
        "description": "Get recent UniFi alerts",
        "params": ["limit?"]
    },
    "unifi_events": {
        "fn": lambda args: unifi_get_events(args.get("limit", 50)),
        "description": "Get recent UniFi events",
        "params": ["limit?"]
    },
    "unifi_block": {
        "fn": lambda args: unifi_block_client(args.get("mac", ""), args.get("reason", "")),
        "description": "Block a client on UniFi network by MAC",
        "params": ["mac", "reason?"]
    },
    "unifi_unblock": {
        "fn": lambda args: unifi_unblock_client(args.get("mac", "")),
        "description": "Unblock a client on UniFi network by MAC",
        "params": ["mac"]
    },
    "unifi_kick": {
        "fn": lambda args: unifi_kick_client(args.get("mac", "")),
        "description": "Kick (disconnect) a client from UniFi network",
        "params": ["mac"]
    },
    # Flipper Zero tools
    "flipper": {
        "fn": lambda args: flipper_call(args.get("tool", ""), args.get("arguments", {})),
        "description": "Call any Flipper Zero MCP tool (SubGHz, NFC, RFID, IR, GPIO, BadUSB, WiFi)",
        "params": ["tool", "arguments?"]
    },
}


def execute_tool(tool_name, args):
    """Execute a tool by name with given arguments."""
    if tool_name not in TOOL_REGISTRY:
        return f"[ERROR] Unknown tool: {tool_name}. Available: {', '.join(TOOL_REGISTRY.keys())}"

    tool = TOOL_REGISTRY[tool_name]
    logger.info(f"Executing tool: {tool_name} with args: {args}")

    try:
        result = tool["fn"](args)
        # Truncate very long outputs
        if len(result) > 8000:
            result = result[:8000] + f"\n\n[TRUNCATED — {len(result)} chars total]"
        return result
    except Exception as e:
        logger.error(f"Tool execution failed: {tool_name} — {e}")
        return f"[ERROR] Tool '{tool_name}' failed: {e}"


def get_tool_descriptions():
    """Get formatted tool descriptions for system prompt injection."""
    lines = []
    for name, tool in TOOL_REGISTRY.items():
        params = ", ".join(tool["params"])
        lines.append(f"  - {name}({params}): {tool['description']}")
    return "\n".join(lines)
