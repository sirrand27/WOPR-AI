#!/usr/bin/env bash
# ╔══════════════════════════════════════════════╗
# ║  W.O.P.R. LAUNCH SEQUENCE                   ║
# ║  Starts Joshua + all MCP services            ║
# ╚══════════════════════════════════════════════╝

DIR="$(dirname "$(readlink -f "$0")")"
PENTEST_DIR="$(dirname "$DIR")"
LOG_DIR="/tmp"

launch_service() {
    local name="$1"
    local check="$2"
    local cmd="$3"
    local log="$4"

    if pgrep -f "$check" >/dev/null 2>&1; then
        echo "[WOPR] $name — already running"
    else
        eval "$cmd" &>"$log" &
        sleep 1
        if pgrep -f "$check" >/dev/null 2>&1; then
            echo "[WOPR] $name — ONLINE"
        else
            echo "[WOPR] $name — FAILED (see $log)"
        fi
    fi
}

echo "╔══════════════════════════════════════╗"
echo "║     W.O.P.R. LAUNCH SEQUENCE        ║"
echo "╚══════════════════════════════════════╝"
echo ""

# 1. Ollama (systemd service)
if systemctl is-active ollama >/dev/null 2>&1; then
    echo "[WOPR] Ollama LLM — already running"
else
    sudo systemctl start ollama
    sleep 2
    echo "[WOPR] Ollama LLM — ONLINE"
fi

# 2. Blackboard MCP (port 9700)
launch_service \
    "Blackboard MCP (:9700)" \
    "python3.*blackboard.*server.py" \
    "cd '$PENTEST_DIR/blackboard' && python3 server.py" \
    "$LOG_DIR/blackboard_server.log"

# 3. Blackboard Monitor GUI
if ! pgrep -f "monitor.py" >/dev/null 2>&1; then
    export DISPLAY="${DISPLAY:-:0.0}"
    cd "$PENTEST_DIR/blackboard" && python3 monitor.py &>/dev/null &
    echo "[WOPR] Blackboard Monitor — ONLINE"
else
    echo "[WOPR] Blackboard Monitor — already running"
fi

# 4. UniFi MCP (port 9600)
launch_service \
    "UniFi MCP (:9600)" \
    "python3.*unifi_mcp.*server.py" \
    "cd '$PENTEST_DIR/unifi_mcp' && bash run.sh" \
    "$LOG_DIR/unifi_mcp.log"

# 5. Joshua Voice Server (port 9876)
if systemctl --user is-active joshua-voice >/dev/null 2>&1; then
    echo "[WOPR] Joshua Voice (:9876) — already running"
else
    systemctl --user start joshua-voice 2>/dev/null || echo "[WOPR] Joshua Voice (:9876) — no service (manual start needed)"
fi

# 6. Local Joshua Agent
launch_service \
    "Local Joshua Agent" \
    "python3.*agent.py.*joshua" \
    "cd '$DIR' && python3 agent.py" \
    "$LOG_DIR/joshua.log"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   W.O.P.R. ONLINE — ALL SYSTEMS GO  ║"
echo "╚══════════════════════════════════════╝"

# Keep terminal open if launched from desktop
if [ -n "$LAUNCHED_FROM_DESKTOP" ]; then
    echo ""
    echo "Press Enter to close this window..."
    read -r
fi
