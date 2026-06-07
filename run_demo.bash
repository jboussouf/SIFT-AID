#!/usr/bin/env bash
# =============================================================================
# run_demo.bash — SIFT-AID Full Demo Runner
# =============================================================================
# Runs all forensic dataset triage tests sequentially and prints a summary.
# Usage:
#   chmod +x run_demo.bash
#   ./run_demo.bash
#
# Datasets covered:
#   1. SCHARDT.005              — NIST CFReDS Hacking Case (635 MB, raw DD)
#   2. 2020JimmyWilson.E01      — E01 forensic image (295 MB)
#   3. cfreds_2015_data_leakage_rm#2.E01 — NIST Data Leakage Case (243 MB)
#   4. DFRWS2005-RODEO/RHINOUSB.dd — DFRWS 2005 Rodeo USB image (247 MB)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VF_DIR="${SCRIPT_DIR}/vf_datasets"

PYTHON="${SCRIPT_DIR}/venv/bin/python"
RESULTS_DIR="${SCRIPT_DIR}/output/demo_results"
SUMMARY_FILE="${RESULTS_DIR}/demo_summary_$(date +%Y%m%d_%H%M%S).txt"

# Load environment variables from .env if present
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    echo -e "\033[0;36m[*] Loading environment variables from .env...\033[0m"
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Ignore comments and empty lines
        if [[ ! "$line" =~ ^# ]] && [[ "$line" =~ = ]]; then
            key=$(echo "$line" | cut -d'=' -f1)
            val=$(echo "$line" | cut -d'=' -f2-)
            # Strip surrounding quotes
            val="${val%\"}"
            val="${val#\"}"
            val="${val%\'}"
            val="${val#\'}"
            export "$key"="$val"
        fi
    done < "${SCRIPT_DIR}/.env"
fi

# Colour helpers
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

banner() {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}  $1${RESET}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════════${RESET}\n"
}

check_prereqs() {
    banner "SIFT-AID — Full Demo Runner"
    echo -e "${BOLD}Checking prerequisites...${RESET}"

    if [[ ! -f "${PYTHON}" ]]; then
        echo -e "${RED}[-] Virtual environment not found at ${PYTHON}${RESET}"
        echo "    Run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
        exit 1
    fi
    echo -e "${GREEN}[+] Python venv found: ${PYTHON}${RESET}"

    mkdir -p "${RESULTS_DIR}"
    echo -e "${GREEN}[+] Results directory: ${RESULTS_DIR}${RESET}"
    echo ""
}

# Associative arrays for results
declare -A TEST_STATUS
declare -A TEST_WALLTIME
declare -A TEST_CONFIDENCE
declare -A TEST_FINDINGS
declare -A TEST_INCIDENT

run_test() {
    local name="$1"
    local script="$2"
    local dataset="$3"
    # Sanitise name: replace any '/' with '_' so it stays a flat filename
    local safe_name="${name//\//_}"
    local log_file="${RESULTS_DIR}/${safe_name}.log"

    echo -e "${BOLD}▶  Running: ${name}${RESET}"
    echo -e "   Dataset : ${dataset}"
    echo -e "   Script  : ${script}"
    echo -e "   Log     : ${log_file}"
    echo ""

    # Check dataset exists before running
    if [[ ! -f "${SCRIPT_DIR}/${dataset}" ]]; then
        echo -e "${RED}   [-] Dataset not found — SKIPPED${RESET}\n"
        TEST_STATUS["${name}"]="SKIPPED"
        TEST_WALLTIME["${name}"]="N/A"
        TEST_CONFIDENCE["${name}"]="N/A"
        TEST_FINDINGS["${name}"]="N/A"
        TEST_INCIDENT["${name}"]="N/A"
        return
    fi

    local t_start t_end exit_code
    t_start=$(date +%s)

    if "${PYTHON}" "${SCRIPT_DIR}/${script}" 2>&1 | tee "${log_file}"; then
        exit_code=0
    else
        exit_code=$?
    fi

    t_end=$(date +%s)
    local wall_time=$(( t_end - t_start ))

    # Parse key fields from the log
    local confidence findings incident status
    confidence=$(grep -oP "Confidence score:\s+\K[0-9.]+%" "${log_file}" 2>/dev/null | head -1 || echo "N/A")
    findings=$(grep -oP "Confirmed findings:\K[0-9]+" "${log_file}" 2>/dev/null | head -1 || echo "N/A")
    incident=$(grep -oP "Incident ID:\s+\KINC-\S+" "${log_file}" 2>/dev/null | head -1 || echo "N/A")

    if [[ ${exit_code} -eq 0 ]]; then
        status="${GREEN}PASSED${RESET}"
        TEST_STATUS["${name}"]="PASSED"
    else
        status="${RED}FAILED (exit ${exit_code})${RESET}"
        TEST_STATUS["${name}"]="FAILED"
    fi

    TEST_WALLTIME["${name}"]="${wall_time}s"
    TEST_CONFIDENCE["${name}"]="${confidence}"
    TEST_FINDINGS["${name}"]="${findings}"
    TEST_INCIDENT["${name}"]="${incident}"

    echo -e "   Status     : ${status}"
    echo -e "   Wall time  : ${wall_time}s"
    echo -e "   Confidence : ${confidence}"
    echo -e "   Findings   : ${findings} confirmed"
    echo -e "   Incident   : ${incident}"
    echo ""
}

print_summary() {
    banner "DEMO SUMMARY"

    printf "%-45s %-10s %-10s %-12s %-12s %s\n" \
        "TEST" "STATUS" "TIME" "CONFIDENCE" "FINDINGS" "INCIDENT ID"
    printf "%-45s %-10s %-10s %-12s %-12s %s\n" \
        "─────────────────────────────────────────────" "──────────" "──────────" "────────────" "────────────" "────────────────────"

    for name in \
        "SCHARDT.005" \
        "2020JimmyWilson.E01" \
        "cfreds_2015_data_leakage_rm2.E01" \
        "RHINOUSB.dd"; do

        local st="${TEST_STATUS[${name}]:-N/A}"
        local colour="${RESET}"
        [[ "${st}" == "PASSED" ]] && colour="${GREEN}"
        [[ "${st}" == "FAILED" ]] && colour="${RED}"
        [[ "${st}" == "SKIPPED" ]] && colour="${YELLOW}"

        printf "${colour}%-45s %-10s %-10s %-12s %-12s %s${RESET}\n" \
            "${name}" \
            "${TEST_STATUS[${name}]:-N/A}" \
            "${TEST_WALLTIME[${name}]:-N/A}" \
            "${TEST_CONFIDENCE[${name}]:-N/A}" \
            "${TEST_FINDINGS[${name}]:-N/A}" \
            "${TEST_INCIDENT[${name}]:-N/A}"
    done

    echo ""
    echo -e "${BOLD}Reports are saved under:${RESET} ${SCRIPT_DIR}/output/cases/"
    echo -e "${BOLD}Full demo logs:${RESET}         ${RESULTS_DIR}/"
    echo ""

    # Write plain-text summary file
    {
        echo "SIFT-AID Demo Summary — $(date)"
        echo "======================================"
        for name in \
            "SCHARDT.005" \
            "2020JimmyWilson.E01" \
            "cfreds_2015_data_leakage_rm2.E01" \
            "RHINOUSB.dd"; do
            echo ""
            echo "Dataset   : ${name}"
            echo "Status    : ${TEST_STATUS[${name}]:-N/A}"
            echo "Wall time : ${TEST_WALLTIME[${name}]:-N/A}"
            echo "Confidence: ${TEST_CONFIDENCE[${name}]:-N/A}"
            echo "Findings  : ${TEST_FINDINGS[${name}]:-N/A}"
            echo "Incident  : ${TEST_INCIDENT[${name}]:-N/A}"
        done
    } > "${SUMMARY_FILE}"
    echo -e "${GREEN}[+] Summary written to: ${SUMMARY_FILE}${RESET}"
}

# =============================================================================
# MAIN
# =============================================================================

check_prereqs

# Test 1 — NIST CFReDS Hacking Case
run_test \
    "SCHARDT.005" \
    "SCHARDT.py" \
    "vf_datasets/SCHARDT.005"

# Test 2 — 2020 Jimmy Wilson E01
run_test \
    "2020JimmyWilson.E01" \
    "2020JimmyWilson.py" \
    "vf_datasets/2020JimmyWilson.E01"

# Test 3 — NIST CFReDS Data Leakage 2015
run_test \
    "cfreds_2015_data_leakage_rm2.E01" \
    "cfreds_2015_data_leakage_rm#2.py" \
    "vf_datasets/cfreds_2015_data_leakage_rm#2.E01"

# Test 4 — DFRWS 2005 Rodeo USB
run_test \
    "RHINOUSB.dd" \
    "DFRWS2005_RODEO.py" \
    "vf_datasets/RHINOUSB.dd"

print_summary
