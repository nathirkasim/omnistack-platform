# TigerGate Security Evaluation Reports

This directory houses the execution logs, scanner outputs, and analytical evaluation reports generated from the test suite.

## Artifacts in this Directory

- [`evaluation-report.md`](evaluation-report.md): The primary comparison report containing the full adversarial test matrix, execution results, confusion matrix, precision/recall metrics, and identified gaps.
- `raw_scan_*.log`: Raw stdout and stderr logs captured directly from executions of `tigergate-cli` or underlying scanning engines.

## Reproducing the Benchmark Evaluation

To execute the test suite against TigerGate and update the evaluation report:

```bash
# 1. Provide TigerGate credentials (if available)
export TIGERGATE_API_KEY="your-api-key"
export TIGERGATE_API_URL="https://api.tigergate.dev/api/ci"

# 2. Run the runner script
./scripts/run-scanner.sh

# 3. View the generated evaluation report
cat reports/evaluation-report.md
```
