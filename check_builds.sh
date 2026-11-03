#!/usr/bin/env bash
# check_builds.sh - Verify that all code in codesec-benchmark parses and compiles cleanly.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILURES=0

echo "=========================================================="
echo " Running codesec-benchmark compilation and build checks"
echo "=========================================================="

# 1. Python compilation check (py_compile)
echo -n "[1/4] Checking Python syntax and compilation... "
PY_FILES=$(find "$REPO_ROOT/basic" "$REPO_ROOT/advanced" -name "*.py" -not -path "*/history-repo/*")
for f in $PY_FILES; do
    if ! python3 -m py_compile "$f" 2>/dev/null; then
        echo "FAILED: $f"
        FAILURES=$((FAILURES + 1))
    fi
done
if [ $FAILURES -eq 0 ]; then
    echo "OK"
fi

# 2. Java compilation check (javac with stubs classpath)
echo -n "[2/4] Checking Java compilation with javac... "
JAVA_STUBS="$REPO_ROOT/basic/sast/java/stubs"
JAVA_DIRS=$(find "$REPO_ROOT/basic" "$REPO_ROOT/advanced" -name "*.java" -not -path "*/stubs/*" -not -path "*/history-repo/*" -exec dirname {} \; | sort -u)
for d in $JAVA_DIRS; do
    if ! javac -cp "$JAVA_STUBS" -d /tmp "$d"/*.java 2>/dev/null; then
        echo "FAILED: $d"
        FAILURES=$((FAILURES + 1))
    fi
done
if [ $FAILURES -eq 0 ]; then
    echo "OK"
fi

# 3. Go build check (go build for apps, go mod verify/parse for sca manifests)
echo -n "[3/4] Checking Go package builds... "
GO_DIRS=$(find "$REPO_ROOT/basic" "$REPO_ROOT/advanced" -name "go.mod" -not -path "*/history-repo/*" -exec dirname {} \;)
for d in $GO_DIRS; do
    if [ -f "$d/main.go" ]; then
        if ! (cd "$d" && go vet ./... 2>/dev/null && go build -o /dev/null ./... 2>/dev/null); then
            echo "FAILED app: $d"
            FAILURES=$((FAILURES + 1))
        fi
    elif [ -f "$d/mutants.go" ]; then
        if ! (cd "$d" && go build -o /dev/null ./... 2>/dev/null); then
            echo "FAILED mutants: $d"
            FAILURES=$((FAILURES + 1))
        fi
    else
        # SCA go.mod verification
        if ! (cd "$d" && go mod edit -json >/dev/null 2>&1); then
            echo "FAILED go.mod: $d"
            FAILURES=$((FAILURES + 1))
        fi
    fi
done
if [ $FAILURES -eq 0 ]; then
    echo "OK"
fi

# 4. Node.js syntax parsing check (node --check)
echo -n "[4/4] Checking Node.js syntax parsing... "
JS_FILES=$(find "$REPO_ROOT/basic" "$REPO_ROOT/advanced" -name "*.js" -not -path "*/history-repo/*" -not -path "*/node_modules/*")
for f in $JS_FILES; do
    if ! node --check "$f" 2>/dev/null; then
        echo "FAILED: $f"
        FAILURES=$((FAILURES + 1))
    fi
done
if [ $FAILURES -eq 0 ]; then
    echo "OK"
fi

# Clean up any temporary class files created in /tmp
rm -f /tmp/com/example/benchmark/*.class 2>/dev/null || true

echo "=========================================================="
if [ $FAILURES -eq 0 ]; then
    echo "[SUCCESS] All build checks passed cleanly across Python, Java, Go, and Node!"
    exit 0
else
    echo "[FAILURE] $FAILURES compilation/syntax error(s) detected!"
    exit 1
fi
