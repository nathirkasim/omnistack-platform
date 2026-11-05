#!/usr/bin/env bash
# ==============================================================================
# run_scan.sh - Run target IaC security scanner over iac-tests corpus
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORPUS_DIR="${REPO_ROOT}/iac-tests"
REPORTS_DIR="${REPO_ROOT}/reports"

mkdir -p "${REPORTS_DIR}"

OUTPUT_FILE="${1:-${REPORTS_DIR}/scanner_output.json}"
SCANNER_TYPE="${SCANNER_TYPE:-checkov}"

# Check for custom SCANNER_CMD environment variable
if [[ -n "${SCANNER_CMD:-}" ]]; then
    echo "=================================================================="
    echo "Executing custom target scanner command via SCANNER_CMD:"
    echo "Command: ${SCANNER_CMD}"
    echo "Target:  ${CORPUS_DIR}"
    echo "Output:  ${OUTPUT_FILE}"
    echo "=================================================================="
    eval "${SCANNER_CMD}" > "${OUTPUT_FILE}" || true
    echo "Scan complete. Output written to ${OUTPUT_FILE}"
    exit 0
fi

# Baseline scanners execution
echo "=================================================================="
echo "Executing baseline scanner: ${SCANNER_TYPE}"
echo "Corpus:   ${CORPUS_DIR}"
echo "Output:   ${OUTPUT_FILE}"
echo "=================================================================="

export PATH="$HOME/.local/bin:$PATH"

if [[ "${SCANNER_TYPE}" == "checkov" ]]; then
    if command -v checkov >/dev/null 2>&1; then
        echo "Running Checkov scanner..."
        checkov -d "${CORPUS_DIR}" --output json --soft-fail > "${OUTPUT_FILE}" 2>/dev/null || true
    else
        echo "ERROR: checkov not found. Install via 'pip install checkov' or specify SCANNER_CMD."
        exit 1
    fi
elif [[ "${SCANNER_TYPE}" == "trivy" ]]; then
    if command -v trivy >/dev/null 2>&1; then
        echo "Running Trivy scanner..."
        trivy config --format json "${CORPUS_DIR}" > "${OUTPUT_FILE}" 2>/dev/null || true
    else
        echo "ERROR: trivy not found in PATH or specify SCANNER_CMD."
        exit 1
    fi
else
    echo "Unknown scanner type: ${SCANNER_TYPE}. Use 'checkov', 'trivy', or set SCANNER_CMD."
    exit 1
fi

echo "Scan complete. Results written to: ${OUTPUT_FILE}"
