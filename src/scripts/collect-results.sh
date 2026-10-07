#!/usr/bin/env bash
# ExecGuard evidence pipeline.
#
# Builds the project from clean, classifies the host, runs every test suite and
# (where possible) the benchmark, and writes all raw output plus a summary to
#
#     results/<hostname>-<UTC timestamp>/
#
# Nothing is estimated or pre-filled: every file is the captured output of a
# command run on this host during this invocation.
#
# Behaviour by host capability:
#   - Any host that can build:   build log, environment report, unit tests.
#   - Root on a BPF-LSM host:    if no ExecGuard daemon is running, a temporary
#                                one is started from build/ with an empty policy
#                                and a private audit log, the kernel suites and
#                                benchmark run against it, and it is stopped
#                                afterwards. An installed, running daemon is
#                                used as-is and left running.
#   - Otherwise:                 kernel suites are recorded as SKIP with the
#                                reason, and the daemon load attempt is logged.
#
# Usage (from the repository root):
#   make results                       # or: sudo make results
#   ITERS=50000 sudo make results      # shorter benchmark
#   RESULTS_LABEL=vm-review2 sudo make results   # name the output folder
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="${RESULTS_LABEL:-$(hostname -s 2>/dev/null || hostname)}"
OUT="$ROOT/results/${HOST}-${STAMP}"
mkdir -p "$OUT/tests"
export NO_COLOR=1

log() { printf '==> %s\n' "$*"; }

TMPBIN=""
DAEMON_PID=""
cleanup() {
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
    fi
    [[ -n "$TMPBIN" ]] && rm -rf "$TMPBIN"
}
trap cleanup EXIT

# ------------------------------------------------------------ 1. system --
log "Recording system information"
{
    echo "collected_utc: $STAMP"
    echo "hostname:      $HOST"
    echo "user:          $(id -un) (euid $EUID)"
    echo "kernel:        $(uname -srmo)"
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release; echo "os:            ${PRETTY_NAME:-unknown}"
    fi
    echo "cpu:           $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//') ($(nproc) logical)"
    echo "memory:        $(awk '/MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo 2>/dev/null)"
    echo "virtualization: $(systemd-detect-virt 2>/dev/null || echo unknown)"
    echo
    echo "active LSMs:   $(cat /sys/kernel/security/lsm 2>/dev/null || echo 'unavailable (securityfs not mounted or no access)')"
    echo "kernel BTF:    $([[ -f /sys/kernel/btf/vmlinux ]] && echo present || echo absent)"
    echo
    echo "clang:         $(clang --version 2>/dev/null | head -1 || echo missing)"
    echo "gcc:           $(gcc --version 2>/dev/null | head -1 || echo missing)"
    echo "bpftool:       $(${BPFTOOL:-bpftool} version 2>/dev/null | head -1 || echo missing)"
    echo "libbpf:        $(pkg-config --modversion libbpf 2>/dev/null || dpkg-query -W -f='${Version}' libbpf-dev 2>/dev/null || echo unknown)"
    echo "openssl:       $(openssl version 2>/dev/null || echo missing)"
    echo "git commit:    $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout')"
} > "$OUT/system.txt"

# --------------------------------------------------------- 2. check-env --
log "Classifying host (src/scripts/check-env.sh)"
"$ROOT/src/scripts/check-env.sh" > "$OUT/check-env.log" 2>&1
ENV_RC=$?
case $ENV_RC in
    0) ENV_MODE="EBPF_LSM" ;;
    1) ENV_MODE="FANOTIFY_FALLBACK" ;;
    2) ENV_MODE="UNSUPPORTED" ;;
    *) ENV_MODE="UNKNOWN (exit $ENV_RC)" ;;
esac

# ------------------------------------------------------------- 3. build --
log "Building from clean"
BUILD_START=$(date +%s.%N)
{ make clean && make vmlinux && make; } > "$OUT/build.log" 2>&1
BUILD_RC=$?
BUILD_SECS=$(awk -v s="$BUILD_START" -v e="$(date +%s.%N)" 'BEGIN{printf "%.1f", e-s}')
WARNINGS=$(grep -c -i 'warning:' "$OUT/build.log" || true)
if [[ $BUILD_RC -eq 0 ]]; then
    ls -l build/ > "$OUT/build-artifacts.txt"
    sha256sum build/execguard build/eg-updater build/execguard.bpf.o >> "$OUT/build-artifacts.txt"
    readelf -SW build/execguard.bpf.o | grep -E ' (lsm/|\.maps|license|\.BTF)' \
        > "$OUT/bpf-sections.txt" 2>&1
fi

# ------------------------------------------------- 4. daemon for kernel --
DAEMON_MODE="not started"
if [[ $BUILD_RC -eq 0 && $EUID -eq 0 ]]; then
    TMPBIN=$(mktemp -d /tmp/execguard-results.XXXXXX)
    ln -s "$ROOT/build/execguard" "$TMPBIN/egctl"
    ln -s "$ROOT/build/execguard" "$TMPBIN/execguardd"
    export PATH="$TMPBIN:$PATH"

    if [[ -S /run/execguard/control.sock ]] && egctl status >/dev/null 2>&1; then
        DAEMON_MODE="existing daemon (left running)"
    else
        printf '# Temporary policy for results collection: tests add their own files.\nMODE enforce\n' \
            > "$TMPBIN/policy.conf"
        log "Starting temporary daemon from build/"
        "$TMPBIN/execguardd" --config "$TMPBIN/policy.conf" \
            --audit "$OUT/audit.jsonl" --baseline "$TMPBIN/baseline.jsonl" \
            > "$OUT/daemon.log" 2>&1 &
        DAEMON_PID=$!
        for _ in $(seq 1 30); do
            egctl status >/dev/null 2>&1 && break
            kill -0 "$DAEMON_PID" 2>/dev/null || break
            sleep 0.2
        done
        if egctl status >/dev/null 2>&1; then
            DAEMON_MODE="temporary daemon (pid $DAEMON_PID)"
        else
            wait "$DAEMON_PID" 2>/dev/null
            DAEMON_MODE="failed to start (see daemon.log)"
            DAEMON_PID=""
        fi
    fi
elif [[ $EUID -ne 0 ]]; then
    DAEMON_MODE="not started (not root)"
fi

# ------------------------------------------------------------- 5. tests --
log "Running test suites"
if [[ $BUILD_RC -eq 0 ]]; then
    LOG_DIR="$OUT/tests" bash "$ROOT/src/tests/run-all.sh" > "$OUT/tests/summary.log" 2>&1
fi
suite_verdict() {
    local s="$1"
    grep -E "^  $s " "$OUT/tests/summary.log" 2>/dev/null | sed -E "s/^  $s +//" || true
}
suite_counts() {
    local f="$OUT/tests/$1.log"
    [[ -f "$f" ]] || { echo "-"; return; }
    grep -E '^Total:' "$f" | tail -1 | sed -E 's/Total: ([0-9]+) +PASS: ([0-9]+) +FAIL: ([0-9]+)/\2 \/ \1 passed, \3 failed/'
}

# --------------------------------------------------------- 6. benchmark --
BENCH="skipped (no reachable daemon)"
if egctl status >/dev/null 2>&1; then
    log "Running benchmark (ITERS=${ITERS:-200000})"
    bash "$ROOT/src/benchmarks/bench.sh" > "$OUT/benchmark.log" 2>&1 \
        && BENCH="completed (see benchmark.log)" || BENCH="failed (see benchmark.log)"
    egctl status > "$OUT/egctl-status.txt" 2>&1
fi

# A daemon that never loaded leaves an empty audit log behind; drop it.
[[ -f "$OUT/audit.jsonl" && ! -s "$OUT/audit.jsonl" ]] && rm -f "$OUT/audit.jsonl"

# ----------------------------------------------------------- 7. summary --
log "Writing summary"
{
    echo "# ExecGuard results: $HOST, $STAMP"
    echo
    echo "| Item | Outcome |"
    echo "|---|---|"
    echo "| Host | $(sed -n 's/^os: *//p' "$OUT/system.txt"), kernel $(uname -r) |"
    echo "| Enforcement mode (check-env) | $ENV_MODE |"
    echo "| Build from clean | $([[ $BUILD_RC -eq 0 ]] && echo "OK in ${BUILD_SECS}s, $WARNINGS warning(s)" || echo "FAILED (exit $BUILD_RC)") |"
    echo "| Daemon | $DAEMON_MODE |"
    for s in unit functional security bypass; do
        v=$(suite_verdict "$s")
        echo "| Tests: $s | ${v:-not run}$( [[ -f "$OUT/tests/$s.log" ]] && grep -q '^Total:' "$OUT/tests/$s.log" && echo " ($(suite_counts "$s"))") |"
    done
    echo "| Benchmark | $BENCH |"
    if [[ -f "$OUT/audit.jsonl" ]]; then
        echo "| Audit events captured | $(wc -l < "$OUT/audit.jsonl" | tr -d ' ') (audit.jsonl) |"
    fi
    echo
    echo "## Files"
    echo
    (cd "$OUT" && find . -type f ! -name summary.md | sort | sed 's#^\./#- `#; s#$#`#')
} > "$OUT/summary.md"

cat "$OUT/summary.md"
echo
echo "Results written to: ${OUT#$ROOT/}"
