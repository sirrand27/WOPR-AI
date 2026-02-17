#!/bin/bash
# ═══════════════════════════════════════════════════════════
# W.O.P.R. Jetson Orin Nano — One-Command Deployment
# ═══════════════════════════════════════════════════════════
#
# Usage: ./deploy.sh [--pull-model] [--reset]
#
# Prerequisites:
#   - Docker + docker-compose installed
#   - nvidia-container-toolkit installed (for GPU passthrough)
#   - JetPack 6.x (Ubuntu 22.04)
#   - 30GB+ free disk space
#
# Flags:
#   --pull-model   Pull joshua:cybersec model into Ollama after startup
#   --reset        Remove all volumes and start fresh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.yml"
ENV_FILE="$PROJECT_DIR/.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[WOPR]${NC} $1"; }
success() { echo -e "${GREEN}[WOPR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WOPR]${NC} $1"; }
error() { echo -e "${RED}[WOPR]${NC} $1"; }

PULL_MODEL=false
RESET=false

for arg in "$@"; do
    case $arg in
        --pull-model) PULL_MODEL=true ;;
        --reset) RESET=true ;;
        *) error "Unknown flag: $arg"; exit 1 ;;
    esac
done

# ─── Preflight Checks ─────────────────────────────────────
log "Running preflight checks..."

if ! command -v docker &>/dev/null; then
    error "Docker not found. Install with: curl -fsSL https://get.docker.com | sh"
    exit 1
fi

if ! command -v docker compose &>/dev/null && ! command -v docker-compose &>/dev/null; then
    error "docker-compose not found. Install with: apt install docker-compose-plugin"
    exit 1
fi

if ! docker info 2>/dev/null | grep -q "Runtimes.*nvidia"; then
    warn "nvidia-container-toolkit not detected. GPU passthrough may fail."
    warn "Install with: apt install nvidia-container-toolkit && systemctl restart docker"
fi

# Check disk space (need 30GB+)
FREE_GB=$(df -BG "$PROJECT_DIR" | tail -1 | awk '{print $4}' | tr -d 'G')
if [ "$FREE_GB" -lt 30 ]; then
    warn "Only ${FREE_GB}GB free disk space. Recommended: 30GB+"
fi

# Check architecture
ARCH=$(uname -m)
if [ "$ARCH" != "aarch64" ]; then
    warn "Architecture is $ARCH, not aarch64. This stack is designed for Jetson ARM64."
fi

success "Preflight checks complete."

# ─── Reset (if requested) ─────────────────────────────────
if [ "$RESET" = true ]; then
    warn "Resetting all volumes and containers..."
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down -v 2>/dev/null || true
    success "Reset complete."
fi

# ─── Build & Start ─────────────────────────────────────────
log "Building containers..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" build

log "Starting stack..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d

# ─── Wait for Health ───────────────────────────────────────
log "Waiting for services to become healthy..."

MAX_WAIT=120
ELAPSED=0
SERVICES=("wopr-ollama" "wopr-blackboard" "wopr-unifi-mcp" "wopr-agent" "wopr-voice")

for svc in "${SERVICES[@]}"; do
    while [ "$ELAPSED" -lt "$MAX_WAIT" ]; do
        STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$svc" 2>/dev/null || echo "not_found")
        case $STATUS in
            healthy)
                success "$svc: HEALTHY"
                break
                ;;
            unhealthy)
                error "$svc: UNHEALTHY"
                docker logs --tail 20 "$svc"
                break
                ;;
            not_found)
                warn "$svc: not found (may not have healthcheck)"
                break
                ;;
            *)
                sleep 5
                ELAPSED=$((ELAPSED + 5))
                ;;
        esac
    done
done

# ─── Import Model ──────────────────────────────────────────
if [ "$PULL_MODEL" = true ]; then
    log "Importing joshua:cybersec model into Ollama..."

    MODELFILE="/data/ollama/joshua_cybersec.Modelfile"
    if docker exec wopr-ollama test -f "$MODELFILE" 2>/dev/null; then
        docker exec wopr-ollama ollama create joshua:cybersec -f "$MODELFILE"
        success "Model joshua:cybersec imported."
    else
        warn "Modelfile not found at $MODELFILE."
        warn "Copy joshua_cybersec.gguf and joshua_cybersec.Modelfile to the ollama volume,"
        warn "then run: docker exec wopr-ollama ollama create joshua:cybersec -f <modelfile>"
    fi
fi

# ─── Status Report ─────────────────────────────────────────
echo ""
log "═══════════════════════════════════════════════════════"
log " W.O.P.R. STANDALONE SENTRY — DEPLOYMENT STATUS"
log "═══════════════════════════════════════════════════════"
echo ""

docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps

echo ""
success "Services:"
success "  Blackboard PWA:  http://$(hostname -I | awk '{print $1}'):9700"
success "  UniFi MCP:       http://$(hostname -I | awk '{print $1}'):9600"
success "  Ollama API:      http://$(hostname -I | awk '{print $1}'):11434"
success "  Voice (Piper):   tcp://$(hostname -I | awk '{print $1}'):9876"
echo ""
log "═══════════════════════════════════════════════════════"
