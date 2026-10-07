#!/usr/bin/env bash
# Shared helpers for the ExecGuard test suite.
# Source this from each test script: . "$(dirname "$0")/../lib.sh"

TESTS_RUN=0
TESTS_PASS=0
TESTS_FAIL=0

# Colour only when writing to a terminal, so captured logs in results/ stay
# plain text. NO_COLOR (https://no-color.org) is honoured as well.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    _green() { printf '\033[32m%s\033[0m' "$*"; }
    _red()   { printf '\033[31m%s\033[0m' "$*"; }
    _yellow(){ printf '\033[33m%s\033[0m' "$*"; }
else
    _green() { printf '%s' "$*"; }
    _red()   { printf '%s' "$*"; }
    _yellow(){ printf '%s' "$*"; }
fi

# Abort with a clear message if prerequisites are missing.
require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This test must run as root. Try: sudo $0" >&2
        exit 1
    fi
}

require_daemon() {
    if ! egctl status >/dev/null 2>&1; then
        echo "$(_yellow SKIP): ExecGuard daemon not reachable." >&2
        echo "Start it with: sudo systemctl start execguard" >&2
        exit 77   # automake convention for "skipped"
    fi
}

# ok "<description>" <expected> <actual>
ok() {
    local desc="$1" expected="$2" actual="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    printf '  %-52s ' "$desc"
    if [[ "$expected" == "$actual" ]]; then
        echo "[$(_green PASS)]"
        TESTS_PASS=$((TESTS_PASS + 1))
    else
        echo "[$(_red FAIL)] (expected '$expected', got '$actual')"
        TESTS_FAIL=$((TESTS_FAIL + 1))
    fi
}

# Returns "blocked" if the command fails (EPERM), "allowed" if it succeeds.
run_expect() {
    if "$@" >/dev/null 2>&1; then
        echo "allowed"
    else
        echo "blocked"
    fi
}

summary() {
    echo
    echo "-----------------------------------------------------------"
    printf 'Total: %d   %s: %d   %s: %d\n' \
        "$TESTS_RUN" "$(_green PASS)" "$TESTS_PASS" "$(_red FAIL)" "$TESTS_FAIL"
    [[ $TESTS_FAIL -eq 0 ]]
}
