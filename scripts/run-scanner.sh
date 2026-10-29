#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# TigerGate Test Execution Runner
# Runs security scans and collects output into reports/
# ==============================================================================

REPORTS_DIR="$(pwd)/reports"
mkdir -p "$REPORTS_DIR"

echo "=== TigerGate Security Benchmark Scanner Runner ==="

# Check if docker is available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is required to run the tigergate-cli container." >&2
    exit 1
fi

API_KEY="${TIGERGATE_API_KEY:-}"
API_URL="${TIGERGATE_API_URL:-https://api.tigergate.dev/api/ci}"
REGION="${TIGERGATE_REGION:-us1}"

echo "Starting scan suite against repository fixtures..."
echo "Target: $(pwd)"
echo "Region: $REGION"

SCAN_TYPES=("sast" "sca" "secrets" "iac")

for SCAN_TYPE in "${SCAN_TYPES[@]}"; do
    echo "----------------------------------------------------"
    echo "Executing scan type: $SCAN_TYPE"
    echo "----------------------------------------------------"

    OUTPUT_LOG="$REPORTS_DIR/raw_scan_${SCAN_TYPE}.log"

    docker run --rm \
        -v "$(pwd)":/workspace \
        -w /workspace \
        -e TIGERGATE_API_KEY="$API_KEY" \
        -e TIGERGATE_API_URL="$API_URL" \
        tigergate/tigergate-cli:latest \
        scan \
        --type "$SCAN_TYPE" \
        --scan-scope full \
        --upload=false \
        --repo "nathir-selfhosted/code-security-testing" \
        > "$OUTPUT_LOG" 2>&1 || true

    echo "Saved scan output to $OUTPUT_LOG"
done

echo "----------------------------------------------------"
echo "Running local offline evaluation comparison..."
python3 scripts/evaluate-results.py

echo "Scan runner complete. Check reports/evaluation-report.md"
