#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORTS_DIR="$ROOT_DIR/reports"
RAW_DIR="$REPORTS_DIR/raw"

mkdir -p "$RAW_DIR"

echo "============================================================"
echo "TigerGate Regex/Pattern Test Suite Runner"
echo "============================================================"
echo "Target directory: $ROOT_DIR"
echo "Output raw reports: $RAW_DIR"

if [[ -n "${SCANNER_CMD:-}" ]]; then
    echo "Executing SCANNER_CMD: $SCANNER_CMD"
    OUTPUT_FILE="$RAW_DIR/scanner_output.json"
    eval "$SCANNER_CMD" > "$OUTPUT_FILE" 2>&1 || true
    echo "Raw scan results saved to: $OUTPUT_FILE"
    echo "Running scorer..."
    python3 "$SCRIPT_DIR/score.py" --report "$OUTPUT_FILE"
    exit 0
fi

if [[ $# -gt 0 ]]; then
    CMD="$1"
    if [[ "$CMD" == "checkov" ]]; then
        echo "Running Checkov scan on $ROOT_DIR..."
        OUTPUT_FILE="$RAW_DIR/checkov_results.json"
        checkov -d "$ROOT_DIR" --output json --soft-fail > "$OUTPUT_FILE" 2>/dev/null || true
        echo "Checkov scan complete: $OUTPUT_FILE"
        python3 "$SCRIPT_DIR/score.py" --report "$OUTPUT_FILE"
        exit 0
    elif [[ "$CMD" == "trivy" ]]; then
        echo "Running Trivy scan on $ROOT_DIR..."
        OUTPUT_FILE="$RAW_DIR/trivy_results.json"
        trivy fs "$ROOT_DIR" --format json --security-checks vuln,config,secret > "$OUTPUT_FILE" 2>/dev/null || true
        echo "Trivy scan complete: $OUTPUT_FILE"
        python3 "$SCRIPT_DIR/score.py" --report "$OUTPUT_FILE"
        exit 0
    else
        echo "Executing custom command: $*"
        OUTPUT_FILE="$RAW_DIR/custom_results.json"
        "$@" > "$OUTPUT_FILE" 2>&1 || true
        echo "Scan complete: $OUTPUT_FILE"
        python3 "$SCRIPT_DIR/score.py" --report "$OUTPUT_FILE"
        exit 0
    fi
fi

echo "No SCANNER_CMD or arguments provided."
echo "Usage:"
echo "  SCANNER_CMD='tigergate scan .' ./scripts/run_scan.sh"
echo "  ./scripts/run_scan.sh checkov"
echo "  ./scripts/run_scan.sh trivy"
echo ""
echo "Attempting baseline Checkov run..."
if command -v checkov >/dev/null 2>&1; then
    OUTPUT_FILE="$RAW_DIR/checkov_results.json"
    checkov -d "$ROOT_DIR" --output json --soft-fail > "$OUTPUT_FILE" 2>&1 || true
    echo "Checkov baseline complete: $OUTPUT_FILE"
    python3 "$SCRIPT_DIR/score.py" --report "$OUTPUT_FILE"
fi
