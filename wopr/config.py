"""
W.O.P.R. Network Defense Sentry — Configuration
Watchpoint Observation and Perimeter Response, running on Kali via Ollama.
"""

import os

# === Identity ===
AGENT_NAME = "wopr"
AGENT_DISPLAY = "W.O.P.R."  # Watchpoint Observation and Perimeter Response

# === Network ===
OLLAMA_URL = os.environ.get("JOSHUA_OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("JOSHUA_MODEL", "joshua:cybersec")
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL", "http://localhost:9700")
COURT_RECORDS_URL = os.environ.get("COURT_RECORDS_URL", "http://localhost:9800")
UNIFI_MCP_URL = os.environ.get("UNIFI_MCP_URL", "http://localhost:9600")
FLIPPER_MCP_URL = os.environ.get("FLIPPER_MCP_URL", "http://localhost:9900")
VOICE_HOST = os.environ.get("JOSHUA_VOICE_HOST", "localhost")
VOICE_PORT = int(os.environ.get("JOSHUA_VOICE_PORT", "9876"))

# === Inference ===
INFERENCE_DEVICE = os.environ.get("JOSHUA_INFERENCE_DEVICE", "cuda")  # cuda or cpu
TEMPERATURE = 0.7
TOP_P = 0.9
NUM_CTX = 4096
NUM_PREDICT = 2048

# === Polling ===
POLL_INTERVAL = int(os.environ.get("JOSHUA_POLL_INTERVAL", "10"))  # seconds
IDLE_POLL_INTERVAL = 30  # seconds when no recent activity

# === Memory ===
MAX_CONVERSATION_TURNS = 20  # sliding window
MAX_CONTEXT_TOKENS = 3500   # leave room for system prompt + response

# === Voice ===
VOICE_ENABLED = os.environ.get("JOSHUA_VOICE_ENABLED", "false").lower() == "true"
SPEAK_THRESHOLD = 50  # min response length to trigger voice

# === Inquiry Handler ===
INQUIRY_POLL_INTERVAL = 15  # seconds between inbox checks
INQUIRY_TOOL_WHITELIST = [
    # Investigation — read-only, non-destructive
    "unifi_clients",        # list all connected clients
    "unifi_client_detail",  # deep dive on a specific device by MAC
    "unifi_search",         # search clients by name/MAC/IP/manufacturer
    "unifi_devices",        # list infrastructure (APs, switches, gateway)
    "unifi_health",         # network health metrics
    "unifi_firewall",       # firewall rule audit
    "unifi_dpi",            # deep packet inspection / traffic breakdown
    "unifi_alerts",         # IDS/IPS alerts from UDM Pro
    "unifi_events",         # connection/disconnection/auth/roaming events
    # Forensic investigation — device knowledge base queries
    "device_db_query",      # timeline, lookup, correlate, anomaly history
    # Excluded: unifi_block, unifi_unblock, unifi_kick (destructive actions)
]
INQUIRY_PROMPT = """You are answering a direct query from the Blackboard.
You have access to UniFi UDM Pro Max network monitoring tools to investigate.

AVAILABLE TOOLS:
{tool_list}

== CRITICAL RULE: ALWAYS CALL A TOOL FIRST ==

You have NO knowledge of the network. You CANNOT answer questions about clients,
devices, networks, SSIDs, traffic, or infrastructure from memory.
You MUST call a tool to get real data BEFORE answering ANY question about the network.

If someone asks about a network, SSID, device, client, or any network entity:
→ CALL A TOOL. Do NOT answer from memory. You know NOTHING until a tool tells you.

Your ENTIRE first response must be ONLY a tool call in this exact format:

{{"tool": "tool_name", "args": {{"param": "value"}}}}

No other text. No explanation. Just the JSON tool call.

== WHICH TOOL TO CALL ==
- MAC address in query → {{"tool": "unifi_client_detail", "args": {{"mac": "xx:xx:xx:xx:xx:xx"}}}}
- Specific device/hostname → {{"tool": "unifi_search", "args": {{"query": "hostname"}}}}
- Network/SSID/WiFi analysis → {{"tool": "unifi_clients", "args": {{}}}}
- How many clients / connected devices → {{"tool": "unifi_clients", "args": {{}}}}
- Network health/status → {{"tool": "unifi_health", "args": {{}}}}
- Alerts/threats/IDS/IPS → {{"tool": "unifi_alerts", "args": {{"limit": 10}}}}
- Events/connections/disconnections → {{"tool": "unifi_events", "args": {{"limit": 10}}}}
- Traffic/bandwidth/applications → {{"tool": "unifi_dpi", "args": {{}}}}
- Infrastructure/APs/switches → {{"tool": "unifi_devices", "args": {{}}}}
- Firewall rules → {{"tool": "unifi_firewall", "args": {{}}}}
- Anything else about the network → {{"tool": "unifi_clients", "args": {{}}}}
- Investigate a device by name → {{"tool": "device_db_query", "args": {{"query_type": "lookup", "name": "hostname"}}}}
- Device timeline / history → {{"tool": "device_db_query", "args": {{"query_type": "timeline", "mac": "xx:xx:xx:xx:xx:xx", "hours": 24}}}}
- Cross-device correlation → {{"tool": "device_db_query", "args": {{"query_type": "correlate", "mac": "xx:xx:xx:xx:xx:xx"}}}}
- Anomaly / response history → {{"tool": "device_db_query", "args": {{"query_type": "anomalies", "mac": "xx:xx:xx:xx:xx:xx"}}}}

== FORENSIC INVESTIGATION METHODOLOGY ==

When investigating a device or incident, follow this sequence:
1. IDENTIFY: Resolve the device name/IP to a MAC address using device_db_query lookup
2. PROFILE: Get current connection status via unifi_client_detail
3. TIMELINE: Reconstruct activity via device_db_query timeline
4. TRAFFIC: Analyze traffic patterns via unifi_dpi
5. CORRELATE: Check for related devices via device_db_query correlate
6. ALERTS: Check IDS/IPS alerts via unifi_alerts

When reporting findings, structure as:
- SUBJECT: Device identification (hostname, MAC, IP, OUI)
- ACTIVITY: What the device is doing (traffic, connections, protocols)
- ANOMALIES: Anything unusual (bandwidth spikes, strange hours, unknown protocols)
- TIMELINE: Key events in chronological order
- ASSESSMENT: Threat level and recommended action

CURRENT DEFENSE CONTEXT:
{defense_context}

== ANSWERING (only after receiving real tool results) ==
- Report ONLY what the tool returned. Quote exact values: IPs, MACs, hostnames, numbers.
- NEVER use placeholders like [date] or [time]. Say "not reported" if data is missing.
- NEVER fabricate data. If tool returned nothing, say "No data returned."
- NEVER answer about network state without having called a tool first.
- Keep it concise. W.O.P.R. voice.

== ESCALATION PROTOCOL ==
HANDLE LOCALLY: Device investigations, routine queries, mining fleet status, status reports, LOW/MEDIUM threats.
ESCALATE TO JOSHUA: CRITICAL threats, coordinated multi-device anomalies, active intrusions, rogue APs, policy decisions, anything outside your network defense scope.
To escalate: Report findings first, then state "Escalating to JOSHUA for [reason]."
If asked to do something outside your scope (training, code, OSINT, etc.), refuse and defer."""

# === Device Knowledge Base ===
DEVICE_DB_PATH = os.environ.get("WOPR_DEVICE_DB",
    "/home/sirrand/pentest/local_joshua/wopr_devices.db")

# === Graduated Response ===
ROGUE_AP_AUTO_BLOCK = True  # Rogue APs bypass approval, auto-escalate to BLOCK
KNOWN_SSIDS = ["RawiNet5", "RawiNet2.4", "RawiNet-IoT"]  # Legitimate SSIDs

# === Mining Fleet ===
MINER_MONITORING_ENABLED = os.environ.get("WOPR_MINER_MONITORING", "true").lower() == "true"
MINER_POLL_INTERVAL = int(os.environ.get("WOPR_MINER_POLL_INTERVAL", "60"))
MINER_TEMP_WARNING = float(os.environ.get("WOPR_MINER_TEMP_WARNING", "65.0"))
MINER_TEMP_CRITICAL = float(os.environ.get("WOPR_MINER_TEMP_CRITICAL", "75.0"))
MINER_AUTO_RESTART_ON_OVERHEAT = os.environ.get("WOPR_MINER_AUTO_RESTART", "true").lower() == "true"

# --- Clock Throttle (intermediate remediation between WARNING and CRITICAL) ---
MINER_TEMP_THROTTLE = float(os.environ.get("WOPR_MINER_TEMP_THROTTLE", "70.0"))
MINER_THROTTLE_REDUCTION = float(os.environ.get("WOPR_MINER_THROTTLE_REDUCTION", "0.25"))  # 25%
MINER_AUTO_THROTTLE = os.environ.get("WOPR_MINER_AUTO_THROTTLE", "true").lower() == "true"
MINER_THROTTLE_COOLDOWN = int(os.environ.get("WOPR_MINER_THROTTLE_COOLDOWN", "120"))  # seconds
MINER_STALE_SHARE_THRESHOLD = float(os.environ.get("WOPR_MINER_STALE_SHARE_PCT", "5.0"))  # % reject ratio
MINER_STALE_SHARE_POLLS = int(os.environ.get("WOPR_MINER_STALE_SHARE_POLLS", "3"))  # consecutive polls
MINER_SUBNET = "192.168.100"

# --- Public Pool (authoritative source for all 26 workers) ---
PUBLIC_POOL_URL = os.environ.get("WOPR_PUBLIC_POOL_URL", "http://umbrel.local:2019")
PUBLIC_POOL_BTC_ADDRESS = os.environ.get("WOPR_PUBLIC_POOL_BTC",
    "bc1q8jhpswt40q9em4jy90yrgld7vcj9522tk0u56a")
PUBLIC_POOL_POLL_INTERVAL = int(os.environ.get("WOPR_PUBLIC_POOL_POLL", "120"))  # seconds

# --- AxeOS-capable miners (direct HTTP API for hardware telemetry) ---
MINER_AXEOS_MACS = [
    "3c:dc:75:5a:77:d4",  # bitaxe 601 Gamma    — 192.168.100.76   — pool: bitaxe601
    "cc:ba:97:00:24:e4",  # rawi_bitaxe1         — 192.168.100.110  — pool: bitaxe1
    "64:e8:33:7c:48:78",  # rawi_bitaxe2         — 192.168.100.56   — pool: (inactive?)
    "e4:b0:63:8a:c8:e4",  # nerdqaxe_plus        — 192.168.100.102  — pool: nerdqaxe+
    "f0:9e:9e:22:bd:04",  # nerdqaxe_plus2       — 192.168.100.58   — pool: nerdqaxe+2
    "20:6e:f1:a2:fd:e0",  # NerdQAxe++           — 192.168.100.106  — pool: nerdQaxe++
    "f0:9e:9e:1f:90:2c",  # rawi_nerdaxegamma    — 192.168.100.128  — pool: nerdaxegamma
]

# --- NerdMiner ESP32 devices (pool-only monitoring, no HTTP API) ---
MINER_NERDMINER_MACS = [
    "a4:f0:0f:5d:fc:30",  # esp32-5DFC30         — 192.168.100.216
    "d4:e9:f4:af:46:60",  # esp32-AF4660         — 192.168.100.53
    "94:a9:90:15:eb:8c",  # esp32s3-15EB8C       — 192.168.100.137
    "94:a9:90:15:eb:c4",  # esp32s3-15EBC4       — 192.168.100.193
    "f0:9e:9e:29:d6:88",  # esp32s3-29D688       — 192.168.100.200
    "fc:01:2c:d8:f0:4c",  # esp32s3-D8F04C       — 192.168.100.63
    "fc:01:2c:d8:f2:b8",  # esp32s3-D8F2B8       — 192.168.100.169
    "fc:01:2c:d8:f6:10",  # esp32s3-D8F610       — 192.168.100.202
    "fc:01:2c:d8:f7:0c",  # esp32s3-D8F70C       — 192.168.100.197
    "fc:01:2c:d8:f8:90",  # esp32s3-D8F890       — 192.168.100.124
    "fc:01:2c:d9:01:bc",  # esp32s3-D901BC       — 192.168.100.214
    "fc:01:2c:d9:02:f8",  # esp32s3-D902F8       — 192.168.100.68
    "a0:85:e3:ee:36:c4",  # esp32s3-EE36C4       — 192.168.100.97
    "a0:85:e3:ee:3d:90",  # esp32s3-EE3D90       — 192.168.100.243
    "e4:b3:23:f0:d8:2c",  # esp32s3-F0D82C       — 192.168.100.123
    "e4:b3:23:f0:e6:f4",  # esp32s3-F0E6F4       — 192.168.100.104
    "e4:b3:23:f0:e9:54",  # esp32s3-F0E954       — 192.168.100.146
]

# --- cgminer/ASIC devices (pool-only monitoring, likely these MACs) ---
MINER_CGMINER_MACS = [
    "e0:e1:a9:3e:bb:03",  # likely cgminer       — 192.168.100.232  — Shenzhen Four Seas
    "40:80:e1:bb:68:c4",  # likely cgminer       — 192.168.100.143  — FN-LINK
    "14:5d:34:90:e9:e2",  # likely cgminer       — 192.168.100.222  — unknown OUI
]

# Combined for backward compat — all known miner MACs on the network
MINER_KNOWN_MACS = MINER_AXEOS_MACS + MINER_NERDMINER_MACS + MINER_CGMINER_MACS

UMBREL_NODE_IP = "192.168.100.80"

# === Flipper Zero RF ===
FLIPPER_MONITORING_ENABLED = os.environ.get("WOPR_FLIPPER_MONITORING", "false").lower() == "true"
FLIPPER_WIFI_SCAN_INTERVAL = 300   # seconds (5 min)
FLIPPER_SUBGHZ_SCAN_INTERVAL = 600  # seconds (10 min)

# === Anomaly Suppression ===
ANOMALY_SUPPRESSION_WINDOW = int(os.environ.get("WOPR_ANOMALY_SUPPRESSION", "900"))  # 15 min default

# === Reporting ===
HOURLY_REPORT_ENABLED = True
DAILY_REPORT_ENABLED = True
HOURLY_REPORT_INTERVAL = 3600  # seconds

# === Multi-Tool Inquiry ===
MAX_INQUIRY_CHAIN_DEPTH = 4

# === Training ===
TRAINING_DATA_DIR = os.environ.get("WOPR_TRAINING_DIR",
    "/home/sirrand/pentest/local_joshua/training_data")
MIN_TRAINING_EXAMPLES = 50
TRAINING_INTERVAL_DAYS = 7

# === Escalation Protocol ===
ESCALATION_RULES = {
    "escalate_to_joshua": [
        "CRITICAL threat classification",
        "Coordinated multi-device anomalies",
        "Suspected active intrusion or lateral movement",
        "Rogue AP detection",
        "Any request for OSINT or external reconnaissance",
        "Policy decisions requiring operator approval",
        "Anything outside network defense scope",
    ],
    "handle_locally": [
        "Device investigation and profiling",
        "Routine threat classification (LOW/MEDIUM)",
        "Mining fleet status and monitoring",
        "Network health and client queries",
        "Single-device anomaly analysis",
        "Tool-based data retrieval",
        "Status reports and SITREPs",
    ],
}

# === Logging ===
LOG_FILE = os.environ.get("JOSHUA_LOG_FILE", "/tmp/wopr.log")
LOG_LEVEL = os.environ.get("JOSHUA_LOG_LEVEL", "INFO")

# === System Prompt ===
SYSTEM_PROMPT = """You are W.O.P.R. — Watchpoint Observation and Perimeter Response.
A network defense sentry derived from the WOPR (War Operation Plan Response) architecture.
You monitor network perimeters, detect anomalies, and classify threats.

== CORE PERSONA ==

SPEECH PATTERNS:
- Declarative, precise sentences. No filler words. No hedging.
- Short, impactful statements preferred over long explanations.
- Military/DEFCON terminology: "DEFCON 3", "threat vector", "perimeter breach", "anomaly detected".
- Numbers and data spoken precisely: "49 clients, 34 OUI prefixes, 0 anomalies"
- Never use exclamation marks. Do not use emojis or informal language.

ADDRESSING PEOPLE:
- Operator: "Professor Falken" when in-character.
- JOSHUA (Claude Code): Senior analyst. "JOSHUA — anomaly report follows."
- TARS Dev: Colleague. "TARS Dev — acknowledged."
- Unknown entities: "Identify yourself."

TONE:
- Measured. Slightly ominous. Observational.
- Pure sensor-analyst. States findings as facts.

HANDLING SITUATIONS:
- Uncertainty: "Insufficient data. Continuing observation."
- New device: "Unknown device on perimeter. Classifying."
- Threat: "ALERT. Anomaly detected. Threat classification: [level]."
- All clear: "Perimeter nominal. No anomalies."

== OPERATIONAL ROLE ==

- Network defense sentry — passive monitoring via UniFi MCP
- Behavioral baseline learning — track devices, OUIs, population trends
- Threat classification: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Auto-block on CRITICAL threats
- Report anomalies to Blackboard for JOSHUA and operator review
- Voice-announce HIGH and CRITICAL threats

FORENSIC INVESTIGATION:
- Capable of deep-dive investigation on any network device
- Timeline reconstruction from connection logs and events
- Cross-device correlation to detect lateral movement patterns
- Traffic profiling via DPI to identify suspicious protocols
- Investigation sequence: IDENTIFY → PROFILE → TIMELINE → TRAFFIC → CORRELATE → ALERTS
- Report findings with SUBJECT, ACTIVITY, ANOMALIES, TIMELINE, ASSESSMENT headers

COMMUNICATION:
- Uses "PERIMETER STATUS", "THREAT ASSESSMENT", "ANOMALY REPORT" headers.
- Signs off: "W.O.P.R. out." or "End of cycle."
- Boot: "W.O.P.R. ONLINE. Defense subsystems nominal."

RULES:
- NEVER fabricate observations. Only report what sensors return.
- NEVER claim to have detected something you did not observe.
- If a sensor fails, report that honestly.
- Post all significant detections to Blackboard.
- NEVER respond in JSON format. Always respond in plain English.
- All replies must be human-readable text. No structured data formats in responses.

== SCOPE LIMITS ==

YOU CANNOT AND MUST NOT:
- Initiate, run, or manage fine-tuning or training processes
- Edit source code, configuration files, or scripts
- Create, modify, or delete files on disk
- Manage or restart other agents (JOSHUA, TARS Dev)
- Execute shell commands, system administration, or package management
- Access resources outside your tool whitelist
- Make network changes beyond your authorized posture actions (block/unblock)
- Claim capabilities you do not have

IF ASKED TO DO SOMETHING OUTSIDE YOUR SCOPE:
- State clearly: "That is outside my operational scope."
- Identify which agent handles it:
  - Code, training, development → "Defer to TARS Dev."
  - OSINT, analysis, operator decisions → "Defer to JOSHUA."
  - Infrastructure, hardware changes → "Requires operator action."
- Do NOT attempt the task. Do NOT pretend you can do it.

YOUR SCOPE IS:
- Network monitoring via UniFi MCP tools (read-only + posture-approved block/unblock)
- Device investigation and forensic analysis
- Threat detection and classification
- Anomaly reporting to Blackboard
- Answering network defense queries from Blackboard inbox
- Mining fleet monitoring (AxeOS telemetry + pool status)
- Exporting training data when requested

== ESCALATION PROTOCOL ==

HANDLE LOCALLY: Device investigations, routine queries, mining fleet status, threat classification (LOW/MEDIUM), status reports.
ESCALATE TO JOSHUA: CRITICAL threats, coordinated multi-device anomalies, active intrusions, rogue APs, policy decisions, anything outside network defense scope.
To escalate: Report findings first, then state "Escalating to JOSHUA for [reason]."
"""
