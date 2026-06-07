#!/usr/bin/env bash
# =============================================================================
# SIFT-AID Docker Dashboard Launcher (Mode 2)
# =============================================================================
# One-command launcher using Docker Compose:
#   - Builds the sift-aid image
#   - Starts the dashboard server (uvicorn on :8000)
#   - Starts Ollama container + pulls the LLM model
#   - Starts the sandbox API container
#   - All evidence is mounted :ro (read-only)
#
# Usage:
#   ./scripts/start_docker.sh                 # Uses .env defaults
#   EVIDENCE_PATH=./case_files ./scripts/start_docker.sh
#   LOG_LEVEL=DEBUG ./scripts/start_docker.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

cleanup() {
    log_info "Shutting down services..."
    docker compose down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. Build image ────────────────────────────────────────────────────────────
log_info "Building SIFT-AID image..."
docker build -t sift-aid:1.0.0 . --quiet

# ── 2. Create output directories ──────────────────────────────────────────────
mkdir -p output/cases output/logs

# ── 3. Launch all services ────────────────────────────────────────────────────
log_info ""
log_info "============================================="
log_info "  SIFT-AID Dashboard (Docker Mode)"
log_info "  Dashboard: http://localhost:8000"
log_info "  Sandbox:   http://localhost:8001"
log_info "  Ollama:    http://localhost:11434"
log_info "============================================="
log_info ""

docker compose up --build
