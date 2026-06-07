#!/usr/bin/env bash
# =============================================================================
# SIFT-AID run.sh — One-click triage launcher
# =============================================================================
# Usage:
#   ./run.sh --sample <path> [--memory <path>] [--max-time 480] [--log-level DEBUG]
#   ./run.sh --help
#   ./run.sh --native --sample /evidence/sample.exe   # run without Docker
#
# The script enforces the read-only evidence mount constraint.
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
SAMPLE_PATH=""
MEMORY_PATH=""
MAX_TIME=480
LOG_LEVEL="INFO"
INCIDENT_ID=""
USE_DOCKER=true
CASES_DIR="$(pwd)/output/cases"
VT_API_KEY="${VT_API_KEY:-}"

# Load environment variables from .env if present
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# Re-evaluate VT_API_KEY
VT_API_KEY="${VT_API_KEY:-}"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  ███████╗██╗███████╗████████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ███████╗██║█████╗     ██║       ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ╚════██║██║██╔══╝     ██║       ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████║██║██║        ██║       ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚═╝╚═╝        ╚═╝       ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
  Autonomous Malware Triage & Containment Agent — FIND EVIL! Hackathon
EOF
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 --sample <path> [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  --sample <path>       Path to malware sample (read-only)"
    echo ""
    echo "Optional:"
    echo "  --memory <path>       Path to memory image/dump (read-only)"
    echo "  --max-time <secs>     Wall-clock timeout (default: 480)"
    echo "  --log-level <level>   DEBUG|INFO|WARNING|ERROR (default: INFO)"
    echo "  --incident-id <id>    Custom incident ID"
    echo "  --cases-dir <dir>     Output directory (default: ./output/cases)"
    echo "  --native              Run natively without Docker"
    echo "  --no-pull             Skip Docker pull"
    echo "  --help                Show this help"
    echo ""
    echo "Examples:"
    echo "  ./run.sh --sample ./sample_data/malware.exe"
    echo "  ./run.sh --sample ./sample_data/malware.exe --memory ./sample_data/mem.raw --log-level DEBUG"
    echo "  ./run.sh --native --sample /evidence/suspicious.exe --max-time 300"
}

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sample)       SAMPLE_PATH="$2"; shift 2 ;;
        --memory)       MEMORY_PATH="$2"; shift 2 ;;
        --max-time)     MAX_TIME="$2"; shift 2 ;;
        --log-level)    LOG_LEVEL="$2"; shift 2 ;;
        --incident-id)  INCIDENT_ID="$2"; shift 2 ;;
        --cases-dir)    CASES_DIR="$2"; shift 2 ;;
        --native)       USE_DOCKER=false; shift ;;
        --no-pull)      NO_PULL=true; shift ;;
        --help|-h)      print_banner; usage; exit 0 ;;
        *)              log_error "Unknown flag: $1"; usage; exit 1 ;;
    esac
done

print_banner

# ── Validate required arguments ───────────────────────────────────────────────
if [[ -z "$SAMPLE_PATH" ]]; then
    log_error "--sample is required"
    usage
    exit 1
fi

if [[ ! -f "$SAMPLE_PATH" ]]; then
    log_error "Sample file not found: $SAMPLE_PATH"
    exit 1
fi

SAMPLE_ABS=$(realpath "$SAMPLE_PATH")
log_info "Sample: $SAMPLE_ABS"

MEMORY_ARGS=""
if [[ -n "$MEMORY_PATH" ]]; then
    if [[ ! -f "$MEMORY_PATH" ]]; then
        log_warn "Memory image not found: $MEMORY_PATH — proceeding without memory analysis"
    else
        MEMORY_ABS=$(realpath "$MEMORY_PATH")
        MEMORY_ARGS="--memory $MEMORY_ABS"
        log_info "Memory image: $MEMORY_ABS"
    fi
fi

if [[ -n "$VT_API_KEY" ]]; then
    log_info "VirusTotal: API key detected (live lookups enabled)"
else
    log_warn "VirusTotal: VT_API_KEY not set — offline mode (hash lookup only)"
fi

mkdir -p "$CASES_DIR"

# ── Build CLI args ─────────────────────────────────────────────────────────────
CLI_ARGS=(
    "--sample" "$SAMPLE_ABS"
    "--max-time" "$MAX_TIME"
    "--log-level" "$LOG_LEVEL"
)
[[ -n "$MEMORY_ARGS" ]] && CLI_ARGS+=("--memory" "$MEMORY_ABS")
[[ -n "$INCIDENT_ID" ]] && CLI_ARGS+=("--incident-id" "$INCIDENT_ID")

# ── Docker mode ────────────────────────────────────────────────────────────────
if $USE_DOCKER; then
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Use --native flag to run without Docker."
        exit 1
    fi

    log_info "Building Docker image..."
    docker build -t sift-aid:1.0.0 . --quiet

    log_info "Starting Ollama model server..."
    docker compose up -d ollama

    log_info "Waiting for Ollama to be ready..."
    timeout 60 bash -c 'until docker compose exec ollama curl -sf http://localhost:11434/api/tags > /dev/null; do sleep 2; done' || \
        log_warn "Ollama not ready — proceeding in heuristic mode"

    log_info "Running SIFT-AID triage (max ${MAX_TIME}s)..."
    log_info "Evidence mount: $SAMPLE_ABS → /cases (READ-ONLY)"
    echo ""

    # Mount evidence directory as read-only
    EVIDENCE_DIR=$(dirname "$SAMPLE_ABS")
    EVIDENCE_BASENAME=$(basename "$SAMPLE_ABS")

    docker run --rm \
        --name sift-aid-triage-$$ \
        -e VT_API_KEY="$VT_API_KEY" \
        -e LOG_LEVEL="$LOG_LEVEL" \
        -e EVIDENCE_ROOT=/cases \
        -e CASES_DIR=/output \
        -v "${EVIDENCE_DIR}:/cases:ro" \
        -v "${CASES_DIR}:/output:rw" \
        -v "$(pwd)/yara_rules:/yara_rules:ro" \
        --network sift-aid_default \
        sift-aid:1.0.0 \
        --sample "/cases/${EVIDENCE_BASENAME}" \
        --cases-dir "/output" \
        "${CLI_ARGS[@]:2}"

    EXIT_CODE=$?
    echo ""

# ── Native mode ────────────────────────────────────────────────────────────────
else
    PYTHON_EXEC="python3"
    if [[ -f "venv/bin/python" ]]; then
        PYTHON_EXEC="venv/bin/python"
    elif [[ -f "venv/bin/python3" ]]; then
        PYTHON_EXEC="venv/bin/python3"
    elif ! command -v python3 &> /dev/null; then
        log_error "python3 not found"
        exit 1
    fi

    log_info "Running natively (no Docker)"

    export EVIDENCE_ROOT=$(dirname "$SAMPLE_ABS")
    export CASES_DIR="$CASES_DIR"
    export LOG_LEVEL="$LOG_LEVEL"
    export VT_API_KEY="$VT_API_KEY"
    export YARA_RULES_DIR="$(pwd)/yara_rules"
    export PYTHONPATH="$(pwd)"

    $PYTHON_EXEC main.py "${CLI_ARGS[@]}" --cases-dir "$CASES_DIR"
    EXIT_CODE=$?
fi

# ── Exit summary ───────────────────────────────────────────────────────────────
echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    log_info "Triage completed successfully"
    log_info "Reports saved to: $CASES_DIR"
    log_info "  - JSON:      $CASES_DIR/*/report/report.json"
    log_info "  - Markdown:  $CASES_DIR/*/report/report.md"
    log_info "  - STIX 2.1:  $CASES_DIR/*/report/stix_bundle.json"
elif [[ $EXIT_CODE -eq 124 ]]; then
    log_warn "Triage interrupted by wall-clock timeout (${MAX_TIME}s)"
    log_warn "Partial results may be available in: $CASES_DIR"
else
    log_error "Triage failed with exit code $EXIT_CODE"
fi

exit $EXIT_CODE
