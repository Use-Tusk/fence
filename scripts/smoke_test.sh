#!/bin/bash
# smoke_test.sh - Run smoke tests against the fence binary
#
# This script tests the compiled fence binary to ensure basic functionality works.
# Unlike integration tests (which test internal APIs), smoke tests verify the
# final artifact behaves correctly.
#
# Usage:
#   ./scripts/smoke_test.sh [path-to-fence-binary]
#
# If no path is provided, it will look for ./fence or use 'go run'.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
SKIPPED=0

FENCE_BIN="${1:-}"
if [[ -z "$FENCE_BIN" ]]; then
    if [[ -x "./fence" ]]; then
        FENCE_BIN="./fence"
    elif [[ -x "./dist/fence" ]]; then
        FENCE_BIN="./dist/fence"
    else
        echo "Building fence..."
        go build -o ./fence ./cmd/fence
        FENCE_BIN="./fence"
    fi
fi

if [[ ! -x "$FENCE_BIN" ]]; then
    echo "Error: fence binary not found at $FENCE_BIN"
    exit 1
fi

echo "Using fence binary: $FENCE_BIN"
echo "=============================================="

# Create temp workspace in current directory (not /tmp, which gets overlaid by bwrap --tmpfs)
WORKSPACE=$(mktemp -d -p .)
trap "rm -rf $WORKSPACE" EXIT

run_test() {
    local name="$1"
    local expected_result="$2"  # "pass" or "fail"
    shift 2
    
    echo -n "Testing: $name... "
    
    # Run command and capture result (use "$@" to preserve argument quoting)
    set +e
    output=$("$@" 2>&1)
    exit_code=$?
    set -e
    
    if [[ "$expected_result" == "pass" ]]; then
        if [[ $exit_code -eq 0 ]]; then
            echo -e "${GREEN}PASS${NC}"
            PASSED=$((PASSED + 1))
            return 0
        else
            echo -e "${RED}FAIL${NC} (expected success, got exit code $exit_code)"
            echo "  Output: ${output:0:200}"
            FAILED=$((FAILED + 1))
            return 1
        fi
    else
        if [[ $exit_code -ne 0 ]]; then
            echo -e "${GREEN}PASS${NC} (correctly failed)"
            PASSED=$((PASSED + 1))
            return 0
        else
            echo -e "${RED}FAIL${NC} (expected failure, but command succeeded)"
            echo "  Output: ${output:0:200}"
            FAILED=$((FAILED + 1))
            return 1
        fi
    fi
}

command_exists() {
    command -v "$1" &> /dev/null
}

skip_test() {
    local name="$1"
    local reason="$2"
    echo -e "Testing: $name... ${YELLOW}SKIPPED${NC} ($reason)"
    SKIPPED=$((SKIPPED + 1))
}

echo ""
echo "=== Basic Functionality ==="
echo ""

# Test: Version flag works
run_test "version flag" "pass" "$FENCE_BIN" --version

# Test: Echo works
run_test "echo command" "pass" "$FENCE_BIN" -c "echo hello"

# Test: ls works
run_test "ls command" "pass" "$FENCE_BIN" -- ls

# Test: pwd works
run_test "pwd command" "pass" "$FENCE_BIN" -- pwd

echo ""
echo "=== Filesystem Restrictions ==="
echo ""

# Test: Read existing file works
echo "test content" > "$WORKSPACE/test.txt"
run_test "read file in workspace" "pass" "$FENCE_BIN" -c "cat $WORKSPACE/test.txt"

# Test: Write outside workspace blocked
# Create a settings file that only allows write to current workspace
SETTINGS_FILE="$WORKSPACE/fence.json"
cat > "$SETTINGS_FILE" << EOF
{
  "filesystem": {
    "allowWrite": ["$WORKSPACE"]
  }
}
EOF

# Note: Fence blocks writes outside workspace + /tmp/fence
OUTSIDE_FILE="/tmp/outside-fence-test-$$.txt"
run_test "write outside workspace blocked" "fail" "$FENCE_BIN" -s "$SETTINGS_FILE" -c "touch $OUTSIDE_FILE"

# Cleanup in case it wasn't blocked
rm -f "$OUTSIDE_FILE" 2>/dev/null || true

# Test: Write inside workspace allowed (using the workspace path in -c)
run_test "write inside workspace allowed" "pass" "$FENCE_BIN" -s "$SETTINGS_FILE" -c "touch $WORKSPACE/new-file.txt"

# Check file was actually created
if [[ -f "$WORKSPACE/new-file.txt" ]]; then
    echo -e "Testing: file actually created... ${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "Testing: file actually created... ${RED}FAIL${NC} (file does not exist)"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Command Blocking ==="
echo ""

# Create settings with command deny list
cat > "$SETTINGS_FILE" << EOF
{
  "filesystem": {
    "allowWrite": ["$WORKSPACE"]
  },
  "command": {
    "deny": ["rm -rf", "dangerous-command"]
  }
}
EOF

# Test: Denied command is blocked
run_test "blocked command (rm -rf)" "fail" "$FENCE_BIN" -s "$SETTINGS_FILE" -c "rm -rf /tmp/test"

# Test: Similar but not blocked command works (rm without -rf)
run_test "allowed command (echo)" "pass" "$FENCE_BIN" -s "$SETTINGS_FILE" -c "echo safe command"

# Test: Chained command with blocked command
run_test "chained blocked command" "fail" "$FENCE_BIN" -s "$SETTINGS_FILE" -c "ls && rm -rf /tmp/test"

# Test: Nested shell with blocked command
run_test "nested shell blocked command" "fail" "$FENCE_BIN" -s "$SETTINGS_FILE" -c 'bash -c "rm -rf /tmp/test"'

echo ""
echo "=== Network Restrictions ==="
echo ""

# Reset settings to default (no domains allowed)
cat > "$SETTINGS_FILE" << EOF
{
  "network": {
    "allowedDomains": []
  },
  "filesystem": {
    "allowWrite": ["$WORKSPACE"]
  }
}
EOF

if command_exists curl; then
    # Test: Network blocked by default - curl should fail or return blocked message
    # Use curl's own timeout (no need for external timeout command)
    output=$("$FENCE_BIN" -s "$SETTINGS_FILE" -c "curl -s --connect-timeout 2 --max-time 3 http://example.com" 2>&1) || true
    if echo "$output" | grep -qi "blocked\|refused\|denied\|timeout\|error"; then
        echo -e "Testing: network blocked (curl)... ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    elif [[ -z "$output" ]]; then
        # Empty output is also okay - network was blocked
        echo -e "Testing: network blocked (curl)... ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        # Check if it's actually blocked content vs real response
        if echo "$output" | grep -qi "doctype\|html\|example domain"; then
            echo -e "Testing: network blocked (curl)... ${RED}FAIL${NC} (got actual response)"
            FAILED=$((FAILED + 1))
        else
            echo -e "Testing: network blocked (curl)... ${GREEN}PASS${NC} (no real response)"
            PASSED=$((PASSED + 1))
        fi
    fi
else
    skip_test "network blocked (curl)" "curl not installed"
fi

# Test with allowed domain (only if FENCE_TEST_NETWORK is set)
if [[ "${FENCE_TEST_NETWORK:-}" == "1" ]]; then
    cat > "$SETTINGS_FILE" << EOF
{
  "network": {
    "allowedDomains": ["httpbin.org"]
  },
  "filesystem": {
    "allowWrite": ["$WORKSPACE"]
  }
}
EOF
    if command_exists curl; then
        run_test "allowed domain works" "pass" "$FENCE_BIN" -s "$SETTINGS_FILE" -c "curl -s --connect-timeout 5 --max-time 10 https://httpbin.org/get"
    else
        skip_test "allowed domain works" "curl not installed"
    fi
else
    skip_test "allowed domain works" "FENCE_TEST_NETWORK not set"
fi

echo ""
echo "=== Tool Compatibility ==="
echo ""

if command_exists python3; then
    run_test "python3 works" "pass" "$FENCE_BIN" -c "python3 -c 'print(1+1)'"
else
    skip_test "python3 works" "python3 not installed"
fi

if command_exists node; then
    run_test "node works" "pass" "$FENCE_BIN" -c "node -e 'console.log(1+1)'"
else
    skip_test "node works" "node not installed"
fi

if command_exists git; then
    run_test "git version works" "pass" "$FENCE_BIN" -- git --version
else
    skip_test "git version works" "git not installed"
fi

if command_exists rg; then
    run_test "ripgrep works" "pass" "$FENCE_BIN" -- rg --version
else
    skip_test "ripgrep works" "rg not installed"
fi

echo ""
echo "=== Environment ==="
echo ""

# Test: FENCE_SANDBOX env var is set
run_test "FENCE_SANDBOX set" "pass" "$FENCE_BIN" -c 'test "$FENCE_SANDBOX" = "1"'

# Test: Proxy env vars are set when network is configured
cat > "$SETTINGS_FILE" << EOF
{
  "network": {
    "allowedDomains": ["example.com"]
  },
  "filesystem": {
    "allowWrite": ["$WORKSPACE"]
  }
}
EOF

run_test "HTTP_PROXY set" "pass" "$FENCE_BIN" -s "$SETTINGS_FILE" -c 'test -n "$HTTP_PROXY"'

echo ""
echo "=============================================="
echo ""
echo -e "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}, ${YELLOW}$SKIPPED skipped${NC}"
echo ""
