#!/usr/bin/env bash
# =============================================================================
# SIFT-AID Native Dashboard Launcher
# =============================================================================
# One-command launcher for Mode 1 (native/uvicorn):
#   - Creates Python venv + installs deps if missing
#   - Checks/installs Ollama, starts it, pulls the LLM model
#   - Launches the dashboard on http://localhost:8000
#   - Per-sample sandbox containers are created on-demand by the dashboard
#
# Usage:
#   ./scripts/start_native.sh [--port 8000] [--model qwen:1.8b] [--venv-dir ./venv]
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
PORT=${1:-8000}
MODEL="${OLLAMA_MODEL:-qwen:1.8b}"
VENV_DIR="./venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

cleanup() {
    log_info "Shutting down..."
    if [[ -n "${OLLAMA_PID:-}" ]]; then
        kill "$OLLAMA_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

cd "$SCRIPT_DIR"

# Load environment variables from .env if present
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ ! "$line" =~ ^# ]] && [[ "$line" =~ = ]]; then
            key=$(echo "$line" | cut -d'=' -f1)
            val=$(echo "$line" | cut -d'=' -f2-)
            val="${val%\"}"
            val="${val#\"}"
            val="${val%\'}"
            val="${val#\'}"
            if [[ -z "${!key:-}" ]]; then
                export "$key"="$val"
            fi
        fi
    done < "${SCRIPT_DIR}/.env"
fi
# Re-read MODEL from (potentially updated) env
MODEL="${OLLAMA_MODEL:-qwen:1.8b}"

# ── 1. Python + venv ──────────────────────────────────────────────────────────
PYTHON=""
for candidate in python3.11 python3.12 python3; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [[ -z "$PYTHON" ]]; then
    log_error "Python 3 not found. Install python3 and try again."
    exit 1
fi

log_info "Using Python: $PYTHON"

if [[ ! -d "$VENV_DIR" ]]; then
    log_info "Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

if ! command -v uv &>/dev/null; then
    log_info "Installing uv..."
    pip install -q uv
fi

if [[ ! -f "$VENV_DIR/.deps_installed" ]]; then
    log_info "Installing dependencies..."
    uv pip install -q -r requirements.txt
    touch "$VENV_DIR/.deps_installed"
fi

export PYTHONPATH="$SCRIPT_DIR"

# ── 2. Ollama ─────────────────────────────────────────────────────────────────
if command -v ollama &>/dev/null; then
    log_info "Ollama found"

    if ! curl -sf http://localhost:11434/api/tags &>/dev/null; then
        log_info "Starting Ollama server..."
        ollama serve &
        OLLAMA_PID=$!
        sleep 3
    fi

    # Show available models
    log_info "Available Ollama models:"
    ollama list 2>/dev/null || echo "  (none)"

    # Export model list as JSON for the dashboard (fallback if /api/ollama/models unavailable)
    if command -v jq &>/dev/null; then
        export OLLAMA_MODEL_LIST=$(ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' | jq -R -s -c 'split("\n") | map(select(length > 0))' 2>/dev/null || echo "[]")
    else
        export OLLAMA_MODEL_LIST="[]"
    fi

    # Check if model is already pulled
    if ! ollama list 2>/dev/null | grep -q "$(echo "$MODEL" | cut -d: -f1)"; then
        log_info "Pulling model '$MODEL' (this may take a while)..."
        ollama pull "$MODEL"
    else
        log_info "Model '$MODEL' already present"
    fi
else
    log_warn "Ollama not found — LLM-assisted analysis disabled."
    log_warn "Install: curl -fsSL https://ollama.com/install.sh | sh"
    log_warn "Then pull a model: ollama pull $MODEL"
fi

# ── 3. Docker check (needed for per-sample sandbox containers) ────────────────
if command -v docker &>/dev/null; then
    log_info "Docker found — per-sample sandbox containers available"
    # Build the base image (used by SandboxOrchestrator for ephemeral containers)
    if ! docker image inspect sift-aid:1.0.0 &>/dev/null; then
        log_info "Building sift-aid:1.0.0 image..."
        docker build -t sift-aid:1.0.0 . --quiet
    fi
else
    log_warn "Docker not found — sandbox analysis will use mock mode only."
    log_warn "Install Docker for per-sample ephemeral sandbox containers."
fi

# ── 4. Launch dashboard ───────────────────────────────────────────────────────
MODEL_COUNT=$(ollama list 2>/dev/null | wc -l | tr -d ' ')

log_info ""
log_info "============================================="
log_info "  SIFT-AID Dashboard (Native Mode)"
log_info "  URL:    http://localhost:${PORT}"
log_info "  Model:  ${MODEL} ($MODEL_COUNT available)"
log_info "  Python: $(which python)"
log_info "============================================="
log_info ""

cd dashboard
exec uvicorn app:app --host 0.0.0.0 --port "$PORT" --reload
