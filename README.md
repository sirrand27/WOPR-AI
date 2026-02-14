```
     ╔══════════════════════════════════════════════════════════════╗
     ║                                                              ║
     ║       ██╗ ██████╗ ███████╗██╗  ██╗██╗   ██╗ █████╗          ║
     ║       ██║██╔═══██╗██╔════╝██║  ██║██║   ██║██╔══██╗         ║
     ║       ██║██║   ██║███████╗███████║██║   ██║███████║         ║
     ║  ██   ██║██║   ██║╚════██║██╔══██║██║   ██║██╔══██║         ║
     ║  ╚█████╔╝╚██████╔╝███████║██║  ██║╚██████╔╝██║  ██║         ║
     ║   ╚════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝         ║
     ║                                                              ║
     ║     Joint Operational Strategic Heuristic for                ║
     ║              Unified Analysis                                ║
     ║                                                              ║
     ║           W.O.P.R. // LOCAL AI AGENT                        ║
     ╚══════════════════════════════════════════════════════════════╝
```

# Joshua AI

**Autonomous OSINT analyst and network defense agent** powered by a local LLM via [Ollama](https://ollama.com). Joshua operates as a fully self-contained AI agent on Kali Linux — no cloud AI services required. It polls a shared Blackboard MCP coordination server for tasks and messages, executes OSINT tools, monitors network perimeter via UniFi, and learns from every interaction.

Personality and callsign derived from the WOPR supercomputer in *WarGames* (1983).

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     JOSHUA AGENT LOOP                          │
│                                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Memory   │  │  Ollama  │  │  Tools   │  │   Learning   │  │
│  │ (sliding  │→ │ LLM API  │→ │ (25 OSINT│→ │  (training   │  │
│  │  window)  │  │ :11434   │  │  + MCP)  │  │   examples)  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘  │
│        ↑                                          │            │
│        │           ┌──────────────┐               │            │
│        └───────────│  Blackboard  │←──────────────┘            │
│                    │  MCP :9700   │                             │
│                    └──────┬───────┘                             │
│                           │                                    │
│  ┌────────────────────────┼────────────────────────────────┐  │
│  │            UniFi Network Defense Loop                    │  │
│  │  ┌──────────┐  ┌──────────────┐  ┌──────────────────┐  │  │
│  │  │ UniFi MCP│→ │  Behavioral  │→ │ Threat Classifier│  │  │
│  │  │  :9600   │  │  Baseline    │  │  + Auto-Response  │  │  │
│  │  └──────────┘  └──────────────┘  └──────────────────┘  │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────────┐    │
│  │  Voice   │  │ Court Records│  │  Flipper Zero MCP    │    │
│  │ F5-TTS   │  │  MCP :9800   │  │       :9900          │    │
│  │  :9876   │  └──────────────┘  └──────────────────────┘    │
│  └──────────┘                                                  │
└────────────────────────────────────────────────────────────────┘
```

## Features

**AI Agent Core**
- Autonomous poll-think-act-respond loop via Blackboard MCP
- Local LLM inference via Ollama (dolphin-mistral:7b-v2.8, uncensored)
- Sliding window conversation memory with token-aware context management
- Tool calling via JSON code blocks extracted from LLM output
- Adaptive polling — slows down during idle periods

**OSINT Tool Suite (25 tools)**
- **sherlock** — username enumeration across social platforms
- **theHarvester** — domain, subdomain, and email discovery
- **whatweb** — web technology fingerprinting
- **fierce** — DNS enumeration and zone transfer detection
- **dnsrecon** — DNS reconnaissance
- **photon** — web crawling and data extraction
- **h8mail** — breach and credential OSINT
- **Court Records MCP** — criminal history, case lookup, offender search
- **UniFi MCP** — 13 network management tools (clients, devices, firewall, DPI, block/kick)
- **Flipper Zero MCP** — RF, NFC, Sub-GHz, BadUSB, WiFi (via ESP32 Marauder)

**Network Defense**
- AI-augmented IDS via UniFi MCP (30-second polling)
- Behavioral baseline learning (new devices, OUI tracking, population monitoring)
- Threat classification: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Auto-block on CRITICAL threats (rogue APs, etc.)
- Voice alerts on HIGH+ severity events

**Collaborative Learning**
- Auto-generates training examples from every tool interaction
- Structured format: context → reasoning → action → observation → conclusion
- Submits to Blackboard for aggregation and future fine-tuning (QLoRA)

**Voice Integration**
- Speaks responses and alerts via F5-TTS Joshua voice clone (TCP :9876)
- WOPR/WarGames personality in all voice output
- Configurable threshold — only speaks responses over 50 characters

---

## Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.10+ | Agent runtime (stdlib only — no pip dependencies) |
| [Ollama](https://ollama.com) | 0.16+ | Local LLM inference server |
| Kali Linux | 2024.4+ | OSINT tools pre-installed |
| NVIDIA GPU | CUDA 12.x | GPU inference (optional — CPU fallback supported) |

**MCP Services (optional, enhances capabilities):**

| Service | Port | Purpose |
|---------|------|---------|
| Blackboard MCP | 9700 | Multi-agent coordination and task management |
| Court Records MCP | 9800 | Automated court/offender database searches |
| UniFi MCP | 9600 | UniFi network monitoring and defense |
| Flipper Zero MCP | 9900 | Hardware hacking tool integration |
| Joshua Voice Server | 9876 | F5-TTS voice synthesis (Joshua voice clone) |

**OSINT Tools (install via apt):**
```bash
sudo apt install sherlock theharvester whatweb fierce dnsrecon photon h8mail
```

---

## Installation

### Quick Setup

```bash
# 1. Clone the repo
git clone <repo-url>
cd Joshua-AI

# 2. Install Ollama (if not already installed)
curl -fsSL https://ollama.com/install.sh | sh

# 3. Pull the base model and create Joshua personality
ollama pull dolphin-mistral:7b-v2.8
ollama create joshua -f joshua.modelfile

# 4. Run the automated setup
bash setup.sh
```

### Manual Setup

```bash
# Create Python venv
python3 -m venv venv

# Create the Ollama model
ollama create joshua -f joshua.modelfile

# Install systemd service
mkdir -p ~/.config/systemd/user/
cp local-joshua.service ~/.config/systemd/user/
systemctl --user daemon-reload

# Test
python3 agent.py --status
python3 agent.py --test
```

---

## Usage

### CLI Modes

```bash
# Normal operation — polls Blackboard, processes messages, executes tools
python3 agent.py

# Single inference test — sends one prompt to Ollama and prints response
python3 agent.py --test

# Status check — tests connectivity to all services
python3 agent.py --status
```

### Systemd Service

```bash
# Enable and start
systemctl --user enable local-joshua
systemctl --user start local-joshua

# View logs
journalctl --user -u local-joshua -f

# Restart
systemctl --user restart local-joshua
```

### Status Check Output

```
=== local_joshua Status ===
Ollama: ONLINE (3 models, joshua:latest: YES)
Blackboard: ONLINE (http://localhost:9700)
Voice: ONLINE (localhost:9876)
Court Records MCP: OFFLINE (http://localhost:9800)
UniFi MCP: ONLINE (http://localhost:9600)
Flipper Zero MCP: OFFLINE (http://localhost:9900)
Memory: 0 turns (0 user, 0 assistant)
```

---

## Configuration

All configuration is in `config.py` and can be overridden via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `JOSHUA_OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `JOSHUA_MODEL` | `joshua:latest` | Ollama model name |
| `BLACKBOARD_URL` | `http://localhost:9700` | Blackboard MCP endpoint |
| `COURT_RECORDS_URL` | `http://localhost:9800` | Court Records MCP endpoint |
| `UNIFI_MCP_URL` | `http://localhost:9600` | UniFi MCP endpoint |
| `FLIPPER_MCP_URL` | `http://localhost:9900` | Flipper Zero MCP endpoint |
| `JOSHUA_VOICE_HOST` | `localhost` | Voice server host |
| `JOSHUA_VOICE_PORT` | `9876` | Voice server port |
| `JOSHUA_VOICE_ENABLED` | `true` | Enable/disable voice output |
| `JOSHUA_INFERENCE_DEVICE` | `cuda` | `cuda` or `cpu` |
| `JOSHUA_POLL_INTERVAL` | `10` | Blackboard poll interval (seconds) |
| `JOSHUA_LOG_FILE` | `/tmp/local_joshua.log` | Log file path |
| `JOSHUA_LOG_LEVEL` | `INFO` | Log level |

### LLM Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Temperature | 0.7 | Balanced creativity/precision |
| Top-P | 0.9 | Nucleus sampling |
| Context Window | 4096 tokens | Model limit |
| Max Predict | 2048 tokens | Response length cap |
| Conversation Memory | 20 turns | Sliding window |

---

## Tool Calling

Joshua uses a structured JSON format for tool invocation. The LLM outputs tool calls as fenced code blocks that the agent loop parses and executes:

````
```tool
{"tool": "sherlock", "args": {"username": "johndoe"}}
```
````

### Tool Registry

| Tool | Parameters | Description |
|------|-----------|-------------|
| `sherlock` | `username` | Username enumeration across social platforms |
| `theharvester` | `domain`, `source?`, `limit?` | Domain and email OSINT |
| `whatweb` | `target` | Web technology fingerprinting |
| `fierce` | `domain` | DNS enumeration and zone transfer attempts |
| `dnsrecon` | `domain`, `type?` | DNS reconnaissance |
| `photon` | `url`, `depth?` | Web crawling and data extraction |
| `h8mail` | `target` | Breach and credential OSINT |
| `court_records` | `first_name`, `last_name`, `state?` | Criminal history search |
| `court_case` | `case_number`, `court?` | Case number lookup |
| `unifi_clients` | — | List connected network clients |
| `unifi_client_detail` | `mac` | Client details by MAC |
| `unifi_search` | `query` | Search clients by name/MAC/IP |
| `unifi_devices` | — | List network infrastructure |
| `unifi_health` | — | Network health status |
| `unifi_firewall` | — | Firewall rules |
| `unifi_dpi` | — | Deep Packet Inspection stats |
| `unifi_alerts` | `limit?` | Recent alerts |
| `unifi_events` | `limit?` | Recent events |
| `unifi_block` | `mac`, `reason?` | Block client by MAC |
| `unifi_unblock` | `mac` | Unblock client |
| `unifi_kick` | `mac` | Disconnect client |
| `flipper` | `tool`, `arguments?` | Any Flipper Zero MCP tool |

---

## Network Defense Module

The `UniFiDefenseLoop` runs as a background thread, polling UniFi MCP every 30 seconds:

### Detection Pipeline

1. **Threat Summary** — pulls IPS/IDS threat data from UniFi
2. **Client Baseline** — tracks all connected devices, learns normal population
3. **Anomaly Detection** — flags new devices, unknown OUIs, network changes, population spikes
4. **Threat Classification** — assigns severity based on anomaly type and context
5. **Auto-Response** — CRITICAL threats trigger automatic client blocking
6. **Reporting** — all detections posted to Blackboard as findings + voice alerts on HIGH+

### Severity Levels

| Severity | Anomaly Types | Response |
|----------|---------------|----------|
| CRITICAL | Rogue AP detected | Auto-block + voice + Blackboard |
| HIGH | Unknown OUI device, population spike, auth failure spike, IPS alert | Voice alert + Blackboard |
| MEDIUM | New device (known OUI), unusual DPI | Blackboard finding |
| LOW | Device network change | Blackboard finding |
| INFO | Baseline learning, routine events | Log only |

### Baseline Learning

The behavioral baseline requires 10 polling cycles (~5 minutes) before it starts flagging anomalies. During learning, it catalogs:
- All known MAC addresses and hostnames
- OUI (manufacturer) prefixes
- Client population trends over time
- Network assignments per device

---

## Blackboard MCP Integration

Joshua communicates with other agents via the Blackboard MCP server using JSON-RPC over SSE transport:

```python
# Protocol: JSON-RPC 2.0 over HTTP POST to /mcp
# Response: Server-Sent Events (SSE) with data: lines containing JSON-RPC results
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "send_message",
        "arguments": {
            "from_agent": "local_joshua",
            "to_agent": "operator",
            "content": "WOPR ONLINE. All subsystems nominal.",
            "message_type": "status"
        }
    }
}
```

### Blackboard Capabilities

- **Messaging** — send/receive messages between agents and operator
- **Task Management** — claim, update, and complete assigned tasks
- **Findings** — post security findings with severity, evidence, remediation
- **Training Data** — submit structured training examples for future fine-tuning
- **Activity Log** — post timestamped activity entries

---

## Learning System

Every tool interaction generates a structured training example:

```
context     →  What the operator asked for
reasoning   →  Why Joshua chose this tool/approach
action      →  The tool call executed
observation →  Generalized result summary (PII-stripped)
conclusion  →  Joshua's analysis of the result
```

Training examples are batched and flushed to Blackboard after each message cycle. The Blackboard aggregates examples from all agents for periodic QLoRA fine-tuning.

---

## Voice Integration

Joshua speaks through an F5-TTS voice clone server over TCP:

```
┌──────────┐    TCP :9876    ┌──────────────┐    CUDA    ┌─────────┐
│  Joshua  │ ──── text ────→ │ F5-TTS Voice │ ────────→  │  Audio  │
│  Agent   │ ←─── "OK" ──── │   Server     │            │ Playback│
└──────────┘                 └──────────────┘            └─────────┘
```

- Text sent as UTF-8 line over TCP socket
- Server responds with `OK` after synthesis and playback
- 500-character limit per utterance (longer text is truncated)
- Auto-disables on connection refused (re-checks periodically)

---

## File Structure

```
Joshua-AI/
├── agent.py               # Main agent loop (poll → think → act → respond)
├── blackboard.py          # Blackboard MCP JSON-RPC client (SSE transport)
├── config.py              # Configuration and system prompt
├── tools.py               # 25 tool wrappers (OSINT + MCP services)
├── unifi_defense.py       # AI-augmented network defense module
├── voice.py               # F5-TTS voice client (TCP)
├── memory.py              # Sliding window conversation memory
├── learning.py            # Training example auto-generation
├── joshua.modelfile       # Ollama Modelfile (dolphin-mistral + WOPR persona)
├── local-joshua.service   # Systemd user service unit
├── setup.sh               # One-command setup script
├── requirements.txt       # Dependencies (stdlib only — no pip packages)
└── __init__.py
```

---

## Model

Joshua runs on **dolphin-mistral:7b-v2.8** — an uncensored Mistral 7B variant optimized for instruction following without refusal behaviors. The WOPR/Joshua personality is injected via Ollama Modelfile system prompt (~100 lines of character definition, operational rules, and tool usage instructions).

**Resource requirements:**
- Disk: ~4.1 GB (GGUF quantized)
- VRAM: ~4.5 GB (CUDA) or ~6 GB RAM (CPU mode)
- Inference: ~2-5s per response on RTX 4070, ~15-30s on CPU

---

## Deployment Targets

| Platform | Model | Notes |
|----------|-------|-------|
| Kali Workstation | dolphin-mistral:7b-v2.8 (Q4) | Full GPU acceleration, all OSINT tools |
| Jetson Orin Nano 8GB | Phi-3-mini-4k (Q4) or Mistral 7B (Q3) | ARM64 Ollama, sequential GPU sharing with voice |
| USB Live Boot | Same as workstation | Kali persistence + encrypted data partition |

---

## License

For authorized security testing, CTF competitions, and educational use only.
