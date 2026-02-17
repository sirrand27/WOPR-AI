#!/bin/bash
# ═══════════════════════════════════════════════════════════
# W.O.P.R. Jetson Orin Nano — First-Boot Setup Script
# ═══════════════════════════════════════════════════════════
#
# Run this ON the Jetson after flashing JetPack 6.x to SD card.
# Installs Docker, nvidia-container-toolkit, creates swap,
# tunes performance, deploys the full WOPR sentry stack.
#
# Usage:
#   sudo bash jetson-first-boot.sh [OPTIONS]
#
# Options:
#   --swap-size GB    Swap file size (default: 16, max safe for 128GB SD)
#   --skip-docker     Skip Docker installation (if already installed)
#   --pull-model      Import joshua:cybersec GGUF into Ollama after startup
#   --upgrade-jetpack Upgrade to latest JetPack 6.2.x via apt

set -euo pipefail

# ─── Configuration ────────────────────────────────────────
SWAP_SIZE=16  # GB — conservative for 128GB SD (32GB needs NVMe)
WOPR_DIR="/opt/wopr"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()     { echo -e "${CYAN}[WOPR-SETUP]${NC} $1"; }
success() { echo -e "${GREEN}[WOPR-SETUP]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WOPR-SETUP]${NC} $1"; }
error()   { echo -e "${RED}[WOPR-SETUP]${NC} $1"; }

SKIP_DOCKER=false
PULL_MODEL=false
UPGRADE_JETPACK=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --swap-size)    SWAP_SIZE="$2"; shift 2 ;;
        --skip-docker)  SKIP_DOCKER=true; shift ;;
        --pull-model)   PULL_MODEL=true; shift ;;
        --upgrade-jetpack) UPGRADE_JETPACK=true; shift ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Root Check ───────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    error "Must run as root: sudo bash $0"
    exit 1
fi

# ─── Jetson Detection ─────────────────────────────────────
echo ""
log "═══════════════════════════════════════════════════════"
log " W.O.P.R. STANDALONE SENTRY — FIRST BOOT SETUP"
log " Jetson Orin Nano 8GB"
log "═══════════════════════════════════════════════════════"
echo ""

if [ -f /etc/nv_tegra_release ]; then
    log "Jetson detected:"
    cat /etc/nv_tegra_release
elif [ -f /proc/device-tree/model ]; then
    log "Device: $(cat /proc/device-tree/model)"
else
    warn "Not detected as Jetson hardware. Continuing anyway..."
fi

ARCH=$(uname -m)
if [ "$ARCH" != "aarch64" ]; then
    error "Architecture is $ARCH, expected aarch64. Aborting."
    exit 1
fi

# ─── Step 1: System Update & Dependencies ─────────────────
log "[1/8] Installing system dependencies..."
apt-get update
apt-get install -y \
    curl \
    wget \
    git \
    jq \
    htop \
    nvtop \
    python3 \
    python3-pip \
    net-tools \
    openssh-server \
    ca-certificates \
    gnupg \
    lsb-release

# Enable SSH for remote management
systemctl enable ssh
systemctl start ssh
success "System dependencies installed."

# ─── Step 2: Extended Swap File ───────────────────────────
log "[2/8] Configuring extended swap (${SWAP_SIZE}GB)..."

# Disable default zram swap (Jetson uses this by default, it's tiny)
if systemctl is-active --quiet nvzramconfig 2>/dev/null; then
    systemctl stop nvzramconfig
    systemctl disable nvzramconfig
    warn "Disabled default nvzramconfig (zram). Replacing with disk swap."
fi

# Remove any existing small zram devices
swapoff -a 2>/dev/null || true

if [ ! -f /swapfile ] || [ "$(stat -c%s /swapfile 2>/dev/null)" -lt $((SWAP_SIZE * 1024 * 1024 * 1024)) ]; then
    rm -f /swapfile 2>/dev/null || true
    log "  Allocating ${SWAP_SIZE}GB swap file (this takes a minute)..."
    fallocate -l ${SWAP_SIZE}G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    success "  Swap file created: ${SWAP_SIZE}GB"
else
    log "  Swap file already exists at correct size."
fi

swapon /swapfile

# Ensure fstab entry exists
if ! grep -q '/swapfile' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# Tune swappiness — 60 is good for running LLMs that spill beyond GPU VRAM
sysctl vm.swappiness=60
if ! grep -q 'vm.swappiness' /etc/sysctl.conf; then
    echo 'vm.swappiness=60' >> /etc/sysctl.conf
fi

success "Swap configured: $(free -h | grep Swap | awk '{print $2}') total."

# ─── Step 3: Performance Tuning ──────────────────────────
log "[3/8] Tuning Jetson performance..."

# Set maximum performance power mode (15W for Orin Nano 8GB)
if command -v nvpmodel &>/dev/null; then
    nvpmodel -m 0
    success "  Power mode: MAXN (maximum performance)"
fi

# Lock clocks to max frequency
if command -v jetson_clocks &>/dev/null; then
    jetson_clocks
    success "  Clocks: locked to maximum"
fi

# Create a boot service to re-apply performance settings
cat > /etc/systemd/system/jetson-perf.service << 'PERFEOF'
[Unit]
Description=Jetson Performance Tuning (WOPR)
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'nvpmodel -m 0 2>/dev/null; jetson_clocks 2>/dev/null; sysctl vm.swappiness=60'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
PERFEOF
systemctl daemon-reload
systemctl enable jetson-perf
success "Performance tuning applied and persisted."

# ─── Step 4: Docker Installation ─────────────────────────
if [ "$SKIP_DOCKER" = false ]; then
    log "[4/8] Installing Docker..."

    if ! command -v docker &>/dev/null; then
        curl -fsSL https://get.docker.com | sh
        success "  Docker installed."
    else
        log "  Docker already installed: $(docker --version)"
    fi

    # Add default user to docker group
    JETSON_USER=$(logname 2>/dev/null || echo "")
    if [ -n "$JETSON_USER" ] && [ "$JETSON_USER" != "root" ]; then
        usermod -aG docker "$JETSON_USER"
        success "  Added $JETSON_USER to docker group."
    fi

    # Install nvidia-container-toolkit for GPU passthrough
    log "  Installing nvidia-container-toolkit..."
    if ! dpkg -l | grep -q nvidia-container-toolkit; then
        # NVIDIA Container Toolkit repo
        curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | \
            gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
        curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
            sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
            tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
        apt-get update
        apt-get install -y nvidia-container-toolkit
        nvidia-ctk runtime configure --runtime=docker
        systemctl restart docker
        success "  nvidia-container-toolkit installed and configured."
    else
        log "  nvidia-container-toolkit already installed."
    fi

    # Install docker compose plugin
    if ! docker compose version &>/dev/null; then
        apt-get install -y docker-compose-plugin
        success "  docker-compose plugin installed."
    fi
else
    log "[4/8] Skipping Docker installation (--skip-docker)."
fi

success "Docker ready: $(docker --version 2>/dev/null || echo 'skipped')"

# ─── Step 5: JetPack Upgrade (optional) ──────────────────
if [ "$UPGRADE_JETPACK" = true ]; then
    log "[5/8] Upgrading JetPack to latest 6.2.x..."
    apt-get update
    apt-get dist-upgrade -y
    success "JetPack upgraded. Reboot recommended after setup completes."
else
    log "[5/8] Skipping JetPack upgrade (use --upgrade-jetpack to enable)."
fi

# ─── Step 6: Deploy WOPR Stack ───────────────────────────
log "[6/8] Deploying WOPR sentry stack..."

mkdir -p "$WOPR_DIR"

# Copy the entire wopr-jetson project
if [ -d "$PROJECT_DIR" ]; then
    cp -r "$PROJECT_DIR"/* "$WOPR_DIR/"
    # Make scripts executable
    chmod +x "$WOPR_DIR/scripts/"*.sh 2>/dev/null || true
    success "  WOPR stack copied to $WOPR_DIR"
else
    error "Cannot find project directory at $PROJECT_DIR"
    error "Copy the wopr-jetson/ directory to the Jetson first."
    exit 1
fi

# ─── Step 7: Install systemd Service ─────────────────────
log "[7/8] Installing WOPR systemd service..."

cat > /etc/systemd/system/wopr-jetson.service << SVCEOF
[Unit]
Description=W.O.P.R. Standalone Sentry (Docker Compose)
Requires=docker.service
After=docker.service network-online.target jetson-perf.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$WOPR_DIR
ExecStart=/usr/bin/docker compose --env-file $WOPR_DIR/.env up -d --build
ExecStop=/usr/bin/docker compose --env-file $WOPR_DIR/.env down
TimeoutStartSec=300
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable wopr-jetson
success "WOPR systemd service installed and enabled."

# ─── Step 8: Build & Start Stack ─────────────────────────
log "[8/8] Building and starting WOPR stack..."

cd "$WOPR_DIR"
docker compose --env-file .env build
docker compose --env-file .env up -d

# Wait for Ollama to be healthy
log "  Waiting for Ollama..."
TRIES=0
MAX_TRIES=30
while [ $TRIES -lt $MAX_TRIES ]; do
    if docker exec wopr-ollama curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
        success "  Ollama: HEALTHY"
        break
    fi
    sleep 5
    TRIES=$((TRIES + 1))
done

if [ $TRIES -ge $MAX_TRIES ]; then
    warn "  Ollama did not become healthy in time. Check: docker logs wopr-ollama"
fi

# Import model if requested
if [ "$PULL_MODEL" = true ]; then
    log "  Importing joshua:cybersec model..."
    GGUF_FILE=$(find "$WOPR_DIR" -name "*.gguf" -type f | head -1)
    MODELFILE=$(find "$WOPR_DIR" -name "*.Modelfile" -type f | head -1)

    if [ -n "$GGUF_FILE" ] && [ -n "$MODELFILE" ]; then
        # Copy into Ollama container
        docker cp "$GGUF_FILE" wopr-ollama:/tmp/
        docker cp "$MODELFILE" wopr-ollama:/tmp/
        GGUF_NAME=$(basename "$GGUF_FILE")
        MF_NAME=$(basename "$MODELFILE")
        # Update Modelfile FROM path to point to container location
        docker exec wopr-ollama sed -i "s|^FROM .*|FROM /tmp/$GGUF_NAME|" "/tmp/$MF_NAME"
        docker exec wopr-ollama ollama create joshua:cybersec -f "/tmp/$MF_NAME"
        success "  Model joshua:cybersec imported."
    else
        warn "  GGUF or Modelfile not found in $WOPR_DIR."
        warn "  SCP the model from Kali: scp sirrand@192.168.100.173:/tmp/jetson_audit/joshua_cybersec.gguf $WOPR_DIR/"
    fi
fi

# ─── Final Status Report ─────────────────────────────────
echo ""
log "═══════════════════════════════════════════════════════"
log " W.O.P.R. STANDALONE SENTRY — SETUP COMPLETE"
log "═══════════════════════════════════════════════════════"
echo ""

JETSON_IP=$(hostname -I | awk '{print $1}')

success "System:"
echo "  Memory:  $(free -h | grep Mem | awk '{print $2}')"
echo "  Swap:    $(free -h | grep Swap | awk '{print $2}')"
echo "  Disk:    $(df -h / | tail -1 | awk '{print $4}') free"
echo "  GPU:     $(cat /proc/device-tree/model 2>/dev/null || echo 'Jetson Orin Nano')"
echo "  Arch:    $(uname -m)"
echo ""

success "Services:"
docker compose --env-file .env ps 2>/dev/null || true
echo ""

success "Endpoints:"
echo "  Blackboard PWA:   http://${JETSON_IP}:9700"
echo "  UniFi MCP:        http://${JETSON_IP}:9600"
echo "  Ollama API:       http://${JETSON_IP}:11434"
echo "  Voice (Piper):    tcp://${JETSON_IP}:9876"
echo ""

success "Management:"
echo "  Stack status:     docker compose -f $WOPR_DIR/docker-compose.yml ps"
echo "  Stack logs:       docker compose -f $WOPR_DIR/docker-compose.yml logs -f"
echo "  Restart stack:    sudo systemctl restart wopr-jetson"
echo "  Import model:     sudo bash $WOPR_DIR/scripts/jetson-first-boot.sh --pull-model --skip-docker"
echo ""

if [ "$UPGRADE_JETPACK" = true ]; then
    warn "JetPack was upgraded. A reboot is recommended:"
    echo "  sudo reboot"
fi

log "═══════════════════════════════════════════════════════"
