#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================================"
echo "Validating Syntax for fp-regex-tests Fixtures"
echo "============================================================"

PASSED=0
FAILED=0
SKIPPED=0

check_file() {
    local file="$1"
    local ext="${file##*.}"
    local filename="$(basename "$file")"

    # Python syntax check
    if [[ "$ext" == "py" ]]; then
        if python3 -m py_compile "$file" 2>/dev/null; then
            PASSED=$((PASSED + 1))
        else
            echo "[FAIL] Python compile error: $file"
            FAILED=$((FAILED + 1))
        fi

    # JavaScript syntax check
    elif [[ "$ext" == "js" ]]; then
        if command -v node >/dev/null 2>&1; then
            if node --check "$file" 2>/dev/null; then
                PASSED=$((PASSED + 1))
            else
                echo "[FAIL] Node syntax error: $file"
                FAILED=$((FAILED + 1))
            fi
        else
            SKIPPED=$((SKIPPED + 1))
        fi

    # Shell script syntax check
    elif [[ "$ext" == "sh" ]]; then
        if bash -n "$file" 2>/dev/null; then
            PASSED=$((PASSED + 1))
        else
            echo "[FAIL] Bash syntax error: $file"
            FAILED=$((FAILED + 1))
        fi

    # Go syntax check
    elif [[ "$ext" == "go" ]]; then
        if command -v go >/dev/null 2>&1; then
            if gofmt -e "$file" >/dev/null 2>&1; then
                PASSED=$((PASSED + 1))
            else
                echo "[FAIL] Go syntax error: $file"
                FAILED=$((FAILED + 1))
            fi
        else
            SKIPPED=$((SKIPPED + 1))
        fi

    # Terraform HCL check
    elif [[ "$ext" == "tf" ]]; then
        if command -v terraform >/dev/null 2>&1; then
            if terraform fmt -check "$file" >/dev/null 2>&1; then
                PASSED=$((PASSED + 1))
            else
                # Run fmt to inspect if there's any parsing error
                if terraform fmt "$file" >/dev/null 2>&1; then
                    PASSED=$((PASSED + 1))
                else
                    echo "[FAIL] Terraform syntax error: $file"
                    FAILED=$((FAILED + 1))
                fi
            fi
        else
            SKIPPED=$((SKIPPED + 1))
        fi

    # JSON syntax check
    elif [[ "$ext" == "json" ]]; then
        if python3 -m json.tool "$file" >/dev/null 2>&1; then
            PASSED=$((PASSED + 1))
        else
            echo "[FAIL] JSON syntax error: $file"
            FAILED=$((FAILED + 1))
        fi

    # YAML syntax check
    elif [[ "$ext" == "yaml" || "$ext" == "yml" ]]; then
        if python3 -c "import yaml; list(yaml.safe_load_all(open('$file', 'r', encoding='utf-8')))" >/dev/null 2>&1; then
            PASSED=$((PASSED + 1))
        else
            echo "[FAIL] YAML parse error: $file"
            FAILED=$((FAILED + 1))
        fi

    # Dockerfile syntax check
    elif [[ "$filename" == *"Dockerfile"* ]]; then
        if grep -q "^FROM " "$file"; then
            PASSED=$((PASSED + 1))
        else
            echo "[FAIL] Dockerfile missing FROM directive: $file"
            FAILED=$((FAILED + 1))
        fi

    # Miscellaneous valid fixtures (.env, .pem, .conf, .md, .xml)
    else
        PASSED=$((PASSED + 1))
    fi
}

# Scan all fixtures in l1_basic, l2_intermediate, l3_advanced
while IFS= read -r file; do
    check_file "$file"
done < <(find "$ROOT_DIR/l1_basic" "$ROOT_DIR/l2_intermediate" "$ROOT_DIR/l3_advanced" -type f)

echo "------------------------------------------------------------"
echo "VALIDATION SUMMARY:"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo "------------------------------------------------------------"

if [[ $FAILED -eq 0 ]]; then
    echo "[PASS] All fixtures passed syntax validation!"
    exit 0
else
    echo "[FAIL] $FAILED fixture(s) failed syntax validation."
    exit 1
fi
