#!/bin/bash
# Local Joshua AI Agent — Setup Script
# Run as: bash setup.sh

set -e

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=== Local Joshua AI Agent Setup ==="
echo "Install directory: $INSTALL_DIR"

# 1. Create venv (stdlib only, no pip packages needed)
echo "[1/5] Creating Python venv..."
python3 -m venv "$INSTALL_DIR/venv"

# 2. Create Ollama model
echo "[2/5] Creating Ollama model from Modelfile..."
if command -v ollama &>/dev/null; then
    ollama create joshua -f "$INSTALL_DIR/joshua.modelfile"
    echo "Model 'joshua:latest' created."
else
    echo "WARNING: Ollama not installed. Install with: curl -fsSL https://ollama.com/install.sh | sh"
    echo "Then run: ollama pull dolphin-mistral:7b-v2.8 && ollama create joshua -f $INSTALL_DIR/joshua.modelfile"
fi

# 3. Install systemd service
echo "[3/5] Installing systemd user service..."
mkdir -p ~/.config/systemd/user/
cp "$INSTALL_DIR/local-joshua.service" ~/.config/systemd/user/
systemctl --user daemon-reload
echo "Service installed. Enable with: systemctl --user enable local-joshua"

# 4. Test connectivity
echo "[4/5] Testing service connectivity..."
echo -n "  Blackboard (localhost:9700): "
curl -s -o /dev/null -w "%{http_code}" http://localhost:9700/status 2>/dev/null || echo "OFFLINE"
echo -n "  Court Records (localhost:9800): "
curl -s -o /dev/null -w "%{http_code}" http://localhost:9800/mcp 2>/dev/null || echo "OFFLINE"
echo -n "  Voice (localhost:9876): "
(echo "" | nc -w1 localhost 9876 >/dev/null 2>&1 && echo "ONLINE") || echo "OFFLINE"

# 5. Test agent
echo "[5/5] Testing agent status check..."
cd "$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/python" agent.py --status

echo ""
echo "=== Setup Complete ==="
echo "Start agent:  systemctl --user start local-joshua"
echo "View logs:    journalctl --user -u local-joshua -f"
echo "Test:         python agent.py --test"
echo "Manual run:   python agent.py"
