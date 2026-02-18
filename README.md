```
     ╔══════════════════════════════════════════════════════════════╗
     ║                                                              ║
     ║  ██╗    ██╗ ██████╗ ██████╗ ██████╗                         ║
     ║  ██║    ██║██╔═══██╗██╔══██╗██╔══██╗                        ║
     ║  ██║ █╗ ██║██║   ██║██████╔╝██████╔╝                        ║
     ║  ██║███╗██║██║   ██║██╔═══╝ ██╔══██╗                        ║
     ║  ╚███╔███╔╝╚██████╔╝██║     ██║  ██║                        ║
     ║   ╚══╝╚══╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝                        ║
     ║                                                              ║
     ║     Watchpoint Observation and                               ║
     ║              Perimeter Response                              ║
     ║                                                              ║
     ║           NETWORK DEFENSE SENTRY                             ║
     ╚══════════════════════════════════════════════════════════════╝
```

# W.O.P.R. — Network Defense Sentry

**Autonomous network defense agent** powered by a fine-tuned local LLM via [Ollama](https://ollama.com). W.O.P.R. runs as a containerized 5-service stack on a **Jetson Orin Nano 8GB**, monitoring the network perimeter via UniFi, detecting anomalies, managing a BitAxe miner fleet, and coordinating with other agents through the Blackboard MCP surface.

Part of a multi-agent framework alongside **JOSHUA** (Claude Code — senior analyst, operator-facing) and **TARS Dev** (Windows — development, deployment).

Aesthetic and callsign derived from the WOPR supercomputer in *WarGames* (1983).

---

## Agent Roster

| Agent | Identity | Role | Platform |
|-------|----------|------|----------|
| **JOSHUA** | Claude Code (Opus 4.6) | Interactive analyst, operator-facing | Kali Linux |
| **W.O.P.R.** | Local Ollama sentry (`joshua:cybersec`) | Network defense, miner fleet, passive monitoring | Jetson Orin Nano 8GB |
| **TARS Dev** | Windows AI agent | Development, deployment, fine-tuning | Windows 11 |

---

## Current Deployment

**Primary Host:** NVIDIA Jetson Orin Nano 8GB (`192.168.100.191`)

| Component | Status | Details |
|-----------|--------|---------|
| NVMe Boot | Samsung 990 PRO 1TB | 848GB free, root on `/dev/nvme0n1p1` |
| Docker | CE 29.2.1 + Compose v5.0.2 | nvidia-container-toolkit 1.16.2 |
| JetPack | 6.2.1 | aarch64, MAXN power mode, `jetson_clocks` |
| Swap | 16GB on NVMe | `swappiness=60` |

### Docker Compose Stack

| Container | Port | Service | Health |
|-----------|------|---------|--------|
| `wopr-ollama` | 11434 | Ollama LLM server | `ollama list` check |
| `wopr-blackboard` | 9700 | Blackboard MCP + Mission Control PWA | HTTP `/api/dashboard` |
| `wopr-unifi-mcp` | 9600 | UniFi network MCP server | HTTP health endpoint |
| `wopr-agent` | — | W.O.P.R. defense sentry loop | Log file freshness |
| `wopr-voice` | 9876 | Piper TTS voice server | TCP socket check |

All services use **bind-mounted volumes** for live code updates without container rebuilds.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    JETSON ORIN NANO 8GB                              │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              W.O.P.R. DEFENSE SENTRY LOOP                     │  │
│  │                                                               │  │
│  │  ┌──────────┐  ┌──────────────┐  ┌────────────────────────┐  │  │
│  │  │ UniFi MCP│→ │  Behavioral  │→ │ Threat Classification  │  │  │
│  │  │  :9600   │  │  Baseline    │  │ + Auto-Response        │  │  │
│  │  └──────────┘  └──────────────┘  └────────────────────────┘  │  │
│  │                                                               │  │
│  │  ┌──────────┐  ┌──────────────┐  ┌────────────────────────┐  │  │
│  │  │  Miner   │  │  Device      │  │ Anomaly Deduplication  │  │  │
│  │  │ Monitor  │  │  Knowledge   │  │ + Suppression Window   │  │  │
│  │  │ (AxeOS)  │  │  Base        │  │                        │  │  │
│  │  └──────────┘  └──────────────┘  └────────────────────────┘  │  │
│  │                                                               │  │
│  │  ┌──────────┐  ┌──────────────┐  ┌────────────────────────┐  │  │
│  │  │Correlation│  │  Incident   │  │ Threat Intelligence    │  │  │
│  │  │ Engine   │  │  Timelines   │  │ (abuse.ch feeds)       │  │  │
│  │  │(RF+Net)  │  │  (HIGH+)     │  │ C2 IPs + domains       │  │  │
│  │  └──────────┘  └──────────────┘  └────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────────┐   │
│  │Blackboard│  │Mission Control│  │  Ollama  │  │  Piper TTS   │   │
│  │MCP :9700 │  │  PWA (v30)   │  │  :11434  │  │    :9876     │   │
│  │(auth+MCP)│  │(WarGames UI) │  │joshua:cs │  │ (voice alert)│   │
│  └──────────┘  └──────────────┘  └──────────┘  └──────────────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  ESP32 Marauder (via Flipper Zero USB-UART)                  │   │
│  │  RF Monitor: deauth detection, probe requests, pwnagotchi    │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
         │                                     ▲
         ▼                                     │
   ┌──────────┐                          ┌──────────┐
   │  JOSHUA  │  Blackboard MCP :9700    │ TARS Dev │
   │  (Kali)  │◄────────────────────────►│(Windows) │
   └──────────┘  (Bearer token auth)     └──────────┘
```

---

## Features

### Network Defense (Primary Mission)
- AI-augmented IDS via UniFi MCP (30-second polling cycle)
- Behavioral baseline learning (device population, OUI tracking, network assignments)
- Threat classification: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Auto-block on CRITICAL threats (rogue APs, unauthorized devices)
- Anomaly deduplication with configurable suppression windows
- DEFCON level system (1-5) with automatic calculation from threat posture
- Defense cycle status logged internally (no Live Activity clutter)
- Hourly diagnostics posted only when subsystems are degraded

### Cross-Layer Correlation Engine
- Sliding-window correlation of RF events (Marauder) with network events (UniFi)
- Dual ring buffers with configurable window (default 120s)
- **Evil Twin detection**: deauth attack + rogue AP with matching SSID → CRITICAL
- **Deauth→Reconnect**: deauth targeting client + reconnect to different AP → HIGH
- **Probe→Associate**: suspicious probe from MAC + same device joins network → HIGH
- **Coordinated Attack**: 3+ deauth targets or 2+ sources + population spike → CRITICAL
- Per-(type, MAC) dedup with 5-minute cooldown to prevent alert floods
- Recursion-safe: synthetic correlated anomalies won't re-trigger correlation checks

### Incident Timelines
- Automated context snapshots on HIGH+ severity events
- Captures 8 context sources: recent anomalies, device profile, posture state, RF status, diagnostics, miner fleet, correlation engine, baseline state
- Per-(MAC, type) dedup window (default 10 min) prevents timeline floods
- Human-readable summary + structured JSON evidence posted to Blackboard
- Context buffer records ALL anomalies (even suppressed) for complete situational awareness

### Threat Intelligence (abuse.ch Feeds)
- Pulls from 3 public threat feeds (no API keys required):
  - **Feodo Tracker**: C2 server IPs (Emotet, Dridex, TrickBot, QakBot)
  - **URLhaus**: currently-online malicious URLs → extracted IPs and domains
  - **ThreatFox**: IoC hostfile (malicious domains)
- SQLite persistence + in-memory `set()` for O(1) lookup (~2K IPs, ~48K domains)
- Daily feed refresh (configurable), survives container restarts via DB cache
- Cross-references UniFi client IPs against threat database every 10th defense cycle
- Matches produce `threat_intel_match` anomaly at CRITICAL severity

### RF Monitoring (ESP32 Marauder)
- ESP32 Marauder connected via Flipper Zero USB-UART bridge
- 4-phase scan cycle: AP scan → deauth detection → probe request capture → pwnagotchi detection
- Real-time deauth attack detection with source/target/channel tracking
- Probe request intelligence — device fingerprinting from broadcast probes
- Pwnagotchi detection via beacon frame fingerprinting
- RF events fed into Correlation Engine for cross-layer compound attack detection
- Integrated into defense status and Mission Control radar display

### Miner Fleet Monitoring
- AxeOS BitAxe miner fleet management (HTTP API polling for 7 AxeOS miners)
- Public Pool API integration for full 27-worker fleet (AxeOS + NerdMiners + cgminers)
- Real-time hashrate, temperature, and efficiency tracking
- Temperature-based alerts (65C warning, 75C critical restart)
- **Auto-restart offline miners** after configurable consecutive failures (default 5)
- **Sustained hashrate drop detection**: alerts after N consecutive polls below 50% of average
- **Near-zero hashrate detection**: immediate alert when hashrate drops below 0.01 GH/s (possible firmware compromise)
- **Pool failover recovery verification**: snapshots worker states on outage, verifies all workers reconnect after recovery
- **Per-miner health scoring** (0-100, A-F grade): temperature (25%), hashrate stability (25%), uptime (20%), share quality (15%), WiFi RSSI (15%)
- Pool failover detection and reporting
- Share quality monitoring and anomaly detection
- Fleet summary in W.O.P.R. status reports

### Device Knowledge Base
- Persistent SQLite device database with behavioral profiles
- MAC address, OUI vendor, hostname, network assignment tracking
- Trust scoring and historical anomaly correlation
- Response action audit logging

### Blackboard MCP Integration
- Posts security findings with severity, evidence, and remediation
- Reports perimeter status to Live Activity terminal
- Agent-to-agent messaging (JOSHUA, TARS Dev, operator)
- Training example submission for QLoRA fine-tuning
- Heartbeat monitoring for Mission Control
- **API key authentication** on all `/api/*` and `/mcp` endpoints (Bearer token)
- Graceful auth disable when `BLACKBOARD_API_KEY` is unset (backward compatible)

### Mission Control PWA (v30)
- Browser-based dashboard served at port 9700
- **WarGames visual theme**: CRT scanline overlay, screen vignette, phosphor glow
- **API key auth overlay** with localStorage persistence and lock-to-logout
- Four-pane layout: Network Defense, Task Board, Agent Comms, Live Activity
- **Network Defense pane**: DEFCON level with context reason, threat list, RF radar sweep
- **Canvas radar display**: animated sweep line with AP blips from Marauder data
- **Mining Fleet dashboard**: per-type breakdown (axeos/cgminer/nerdminer), best difficulty, pool status
- **Boot sequence**: WarGames-style typewriter animation on load
- DEFCON-level screen tint (green→yellow→orange→red per threat level)
- WarGames-authentic teletype animation with tick sounds (Web Audio API)
- Smart scroll follow-state (auto-follows typing, disengages on user scroll)
- Incremental message rendering (no full DOM rebuild on poll)
- Fast catch-up on page load (all history rendered instantly, only new lines animate)
- DEFCON alert audio on CRITICAL events
- Resizable panes with persistent layout (localStorage)
- Service worker for offline capability

### Voice Alerts
- Piper TTS on Jetson (GPU-accelerated)
- Speaks HIGH+ severity threat alerts
- WarGames personality in voice output

### Learning System
- Every defense cycle with anomalies generates structured training examples
- Context, reasoning, action, observation, conclusion format
- Batched and flushed to Blackboard for QLoRA fine-tuning pipeline

---

## Repository Structure

```
WOPR-AI/
├── wopr/                        # W.O.P.R. Agent Modules
│   ├── agent.py                 #   Defense sentry loop + inquiry system
│   ├── config.py                #   Configuration (env var overrides)
│   ├── unifi_defense.py         #   AI-augmented UniFi defense engine
│   ├── correlation.py           #   Cross-layer RF + network correlation engine
│   ├── incident_timeline.py     #   Automated incident timeline generator
│   ├── threat_intel.py          #   Threat feed integration (abuse.ch)
│   ├── device_db.py             #   Device knowledge base (SQLite)
│   ├── miner_monitor.py         #   AxeOS BitAxe miner fleet monitor + health scoring
│   ├── blackboard.py            #   Blackboard MCP JSON-RPC client
│   ├── blackboard_monitor.py    #   Message monitoring + auto-ACK
│   ├── tools.py                 #   Tool registry + MCP service wrappers
│   ├── voice.py                 #   TTS voice client
│   ├── learning.py              #   Training example auto-generation
│   ├── memory.py                #   Sliding window conversation memory
│   ├── marauder.py              #   ESP32 Marauder RF monitor (serial)
│   ├── Dockerfile               #   Agent container image
│   └── __init__.py
│
├── blackboard/                  # Blackboard MCP Server
│   ├── server.py                #   FastMCP server (0.0.0.0:9700)
│   ├── database.py              #   SQLite backing store
│   ├── models.py                #   Data models
│   ├── training.py              #   Training data export (JSONL)
│   ├── Dockerfile               #   Server container image
│   └── pwa/                     #   Mission Control Progressive Web App
│       ├── index.html           #     Dashboard UI (v29 — WarGames theme + auth)
│       ├── sw.js                #     Service worker (v29)
│       ├── manifest.json        #     PWA manifest
│       ├── tick.wav             #     Teletype tick sample (30ms, 2.9KB)
│       ├── defcon.wav           #     DEFCON alert sound
│       ├── icon-192.png         #     App icon
│       └── icon-512.png         #     App icon (large)
│
├── unifi-mcp/                   # UniFi Network MCP Server
│   ├── server.py                #   MCP tool server (:9600)
│   ├── unifi_client.py          #   UniFi controller API client
│   ├── syslog_listener.py       #   UDP syslog receiver
│   ├── models.py                #   Data models
│   └── Dockerfile               #   Server container image
│
├── voice/                       # Voice Server
│   ├── voice_server.py          #   Piper TTS server (:9876)
│   └── Dockerfile               #   Voice container image
│
├── scripts/                     # Deployment
│   ├── deploy.sh                #   Docker Compose deployment script
│   └── jetson-first-boot.sh     #   Jetson Orin Nano first-boot setup
│
├── docker-compose.yml           # 5-service stack definition
├── .env.example                 # Environment config template
├── joshua.modelfile             # Ollama Modelfile (base personality)
├── joshua_cybersec.modelfile    # Ollama Modelfile (fine-tuned cybersec)
├── finetune_wopr.py             # QLoRA fine-tuning pipeline
├── launch-wopr.sh               # Bare-metal launch script (non-Docker)
├── local-joshua.service         # Systemd service unit (non-Docker)
├── setup.sh                     # Quick setup script
├── requirements.txt             # Python dependencies
├── test_forensics.py            # Integration tests
└── README.md
```

---

## Configuration

Environment variables are defined in `.env` (see `.env.example`):

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `BLACKBOARD_API_KEY` | *(empty — auth disabled)* | API key for Blackboard endpoints. Set to enable Bearer token auth on all `/api/*` and `/mcp` routes. Generate with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |

When set, all API requests require `Authorization: Bearer <key>` header. The PWA prompts for the key on first load and stores it in `localStorage`. WOPR reads it from the container environment. JOSHUA's polling hook reads from `~/.blackboard_key`.

### Network Services

| Variable | Default | Description |
|----------|---------|-------------|
| `BLACKBOARD_URL` | `http://blackboard:9700` | Blackboard MCP endpoint |
| `UNIFI_MCP_URL` | `http://unifi-mcp:9600` | UniFi MCP endpoint |
| `OLLAMA_URL` | `http://ollama:11434` | Ollama API endpoint |
| `VOICE_HOST` | `voice` | Voice server hostname |
| `VOICE_PORT` | `9876` | Voice server port |

### UniFi Controller

| Variable | Default | Description |
|----------|---------|-------------|
| `UNIFI_HOST` | `192.168.100.1` | UDM Pro IP address |
| `UNIFI_PORT` | `443` | Controller HTTPS port |
| `UNIFI_USER` | — | Controller username |
| `UNIFI_PASS` | — | Controller password |
| `UNIFI_VERIFY_SSL` | `0` | SSL verification (0=skip) |

### W.O.P.R. Agent

| Variable | Default | Description |
|----------|---------|-------------|
| `WOPR_MODEL` | `joshua:cybersec` | Ollama model name |
| `DEVICE_DB_PATH` | `/data/wopr/wopr_devices.db` | Device database path |
| `LOG_FILE` | `/data/logs/wopr.log` | Log file path |
| `JOSHUA_VOICE_ENABLED` | `false` | Voice output (reserved for JOSHUA agent) |
| `MARAUDER_ENABLED` | `false` | Enable ESP32 Marauder RF monitoring |
| `MARAUDER_DEVICE` | `/dev/ttyACM0` | Marauder serial device (Flipper Zero USB-UART) |

### Cross-Layer Correlation

| Variable | Default | Description |
|----------|---------|-------------|
| `WOPR_CORRELATION_ENABLED` | `true` | Enable RF + network event correlation |
| `WOPR_CORRELATION_WINDOW` | `120` | Correlation window in seconds |
| `WOPR_CORRELATION_BUFFER` | `500` | Max events per ring buffer (RF / network) |

### Incident Timelines

| Variable | Default | Description |
|----------|---------|-------------|
| `WOPR_TIMELINE_ENABLED` | `true` | Enable automatic incident timelines on HIGH+ events |
| `WOPR_TIMELINE_LOOKBACK` | `300` | Context lookback window in seconds (5 min) |
| `WOPR_TIMELINE_DEDUP` | `600` | Per-(MAC, type) dedup window in seconds (10 min) |

### Threat Intelligence

| Variable | Default | Description |
|----------|---------|-------------|
| `WOPR_THREAT_INTEL_ENABLED` | `true` | Enable abuse.ch feed integration |
| `WOPR_THREAT_INTEL_PULL` | `86400` | Feed refresh interval in seconds (24h) |
| `WOPR_THREAT_INTEL_CHECK` | `10` | Cross-reference clients every Nth defense cycle |

### Miner Fleet Automation

| Variable | Default | Description |
|----------|---------|-------------|
| `WOPR_MINER_OFFLINE_RESTART` | `5` | Consecutive poll failures before auto-restart |
| `WOPR_MINER_OFFLINE_AUTO_RESTART` | `true` | Enable automatic restart of offline miners |
| `WOPR_MINER_HR_DROP_POLLS` | `3` | Consecutive low-hashrate polls before alert |

---

## Model

W.O.P.R. runs on **joshua:cybersec** — a QLoRA fine-tuned model optimized for network defense, threat classification, and security analysis. Built on dolphin-mistral:7b-v2.8 with cybersecurity training data generated from real defense observations.

**Resource Requirements:**
- Disk: ~4.1 GB (Q4_K_M GGUF)
- VRAM/Unified Memory: ~4.5 GB
- Inference: ~3-8s per response on Jetson Orin Nano (MAXN mode)

---

## Deployment

### Docker Compose (Jetson — Recommended)

```bash
# 1. Clone the repo
git clone https://github.com/sirrand27/WOPR-AI.git
cd WOPR-AI

# 2. Configure environment
cp .env.example .env
# Edit .env with your UniFi credentials and network settings
# Generate an API key for Blackboard auth:
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
# Add to .env as BLACKBOARD_API_KEY=<generated-key>

# 3. Import the model (transfer GGUF separately — not in repo)
# scp joshua_cybersec.gguf to the Jetson, then:
docker compose up -d ollama
docker exec wopr-ollama ollama create joshua:cybersec -f /opt/wopr/joshua_cybersec.Modelfile

# 4. Start the full stack
docker compose up -d

# 5. Verify
docker compose ps
# Open http://<jetson-ip>:9700 for Mission Control
```

### Live Updates

Code changes are deployed without rebuilding containers:

```bash
# Edit files in the repo, then push to Jetson
scp blackboard/pwa/index.html user@jetson:/opt/wopr/blackboard/pwa/
# Changes take effect immediately (bind-mounted volumes)

# For Python changes that require restart:
docker compose restart wopr-agent
```

### Bare Metal (Legacy)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama create joshua:cybersec -f joshua_cybersec.modelfile

# Run directly
python3 wopr/agent.py

# Or install systemd service
cp local-joshua.service ~/.config/systemd/user/
systemctl --user enable --now local-joshua
```

---

## Network Defense Pipeline

```
UniFi MCP Poll (30s) → Threat Summary → Client Baseline → Anomaly Detection
         │                                                        │
         │    ┌───────────────────────────────┐                   │
         └───►│ Threat Intel Cross-Reference  │───────────────────┤
              │ (abuse.ch: C2 IPs + domains)  │                   │
              └───────────────────────────────┘                   │
                          ┌───────────────────────────────────────┘
                          ▼
                   Threat Classification
                          │
                          ├──► Correlation Engine (RF + Network)
                          │         Evil Twin / Deauth→Reconnect / Coordinated
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
       CRITICAL        HIGH/MED        LOW/INFO
    Auto-Block +    Blackboard +      Log Only
    Voice Alert     Finding Post
    + Timeline      + Timeline
```

### Severity Levels

| Severity | Anomaly Types | Response |
|----------|---------------|----------|
| CRITICAL | Rogue AP, unauthorized device on secure VLAN, evil twin detected, coordinated attack, threat intel match | Auto-block + voice + Blackboard finding + incident timeline |
| HIGH | Unknown OUI, population spike, auth failure burst, IPS alert, deauth→reconnect, probe→associate | Blackboard finding + voice alert + incident timeline |
| MEDIUM | New device (known OUI), unusual DPI pattern, miner temp warning | Blackboard finding |
| LOW | Device network change, miner share anomaly | Blackboard finding |
| INFO | Baseline learning, routine events | Log only |

---

## License

For authorized security testing, CTF competitions, and educational use only.
