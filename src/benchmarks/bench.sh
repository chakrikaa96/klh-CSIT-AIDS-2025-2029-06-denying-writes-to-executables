#!/usr/bin/env bash
# ExecGuard performance benchmarks.
#
# IMPORTANT: this script MEASURES; it prints no pre-baked figures. All numbers
# come from the machine it runs on, right now. Results depend heavily on CPU,
# kernel version, and cache state - treat them as relative, not absolute.
#
# What it measures:
#   1. Allow-path overhead: latency of open()-for-read on a PROTECTED file vs an
#      UNPROTECTED file. The difference is the cost of the LSM hook plus the
#      in-kernel (dev,ino) map lookup on the common "allowed" path.
#   2. Deny-path latency: latency of an open()-for-write that is blocked.
#   3. Integrity scan throughput: wall time to SHA-256 the protected set.
set -uo pipefail

ITERS="${ITERS:-200000}"

if ! egctl status >/dev/null 2>&1; then
    echo "ExecGuard daemon not reachable; start it before benchmarking." >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required for the microbenchmark timing." >&2
    exit 1
fi

SBX=$(mktemp -d /tmp/execguard-bench.XXXXXX)
U="$SBX/plain"
P="$SBX/protected"
cleanup() { egctl unprotect "$P" >/dev/null 2>&1 || true; rm -rf "$SBX"; }
trap cleanup EXIT

head -c 4096 /dev/urandom > "$U"
head -c 4096 /dev/urandom > "$P"
egctl protect "$P" >/dev/null

echo "ExecGuard benchmark"
echo "  iterations : $ITERS"
echo "  kernel     : $(uname -r)"
echo "  cpu        : $(nproc) logical core(s)"
echo "-----------------------------------------------------------"

python3 - "$U" "$P" "$ITERS" <<'PY'
import os, sys, time

plain, prot, iters = sys.argv[1], sys.argv[2], int(sys.argv[3])

def time_read_open(path, n):
    # Warm up
    for _ in range(1000):
        fd = os.open(path, os.O_RDONLY); os.close(fd)
    t0 = time.perf_counter_ns()
    for _ in range(n):
        fd = os.open(path, os.O_RDONLY); os.close(fd)
    t1 = time.perf_counter_ns()
    return (t1 - t0) / n

def time_write_deny(path, n):
    ok = 0
    t0 = time.perf_counter_ns()
    for _ in range(n):
        try:
            fd = os.open(path, os.O_WRONLY); os.close(fd)
        except PermissionError:
            ok += 1
    t1 = time.perf_counter_ns()
    return (t1 - t0) / n, ok

r_plain = time_read_open(plain, iters)
r_prot  = time_read_open(prot, iters)
w_deny, denied = time_write_deny(prot, max(1000, iters // 10))

print(f"1. Allow-path (open-for-read) latency")
print(f"     unprotected file : {r_plain:8.1f} ns/op")
print(f"     protected file   : {r_prot:8.1f} ns/op")
print(f"     hook+lookup delta: {r_prot - r_plain:8.1f} ns/op")
print()
print(f"2. Deny-path (blocked open-for-write) latency")
print(f"     protected file   : {w_deny:8.1f} ns/op")
print(f"     (denied {denied} / {max(1000, iters//10)} attempts)")
PY

echo "-----------------------------------------------------------"
echo "3. Integrity scan throughput"
egctl integrity baseline >/dev/null 2>&1 || true
# Time a scan of whatever is in the current baseline.
START=$(date +%s.%N)
egctl integrity scan >/dev/null 2>&1 || true
END=$(date +%s.%N)
printf '     baseline scan wall time: %.3f s\n' "$(echo "$END - $START" | bc)"

echo "-----------------------------------------------------------"
echo "Note: microbenchmark on a single machine with warm caches."
echo "The allow-path delta is the per-syscall cost paid on protected files;"
echo "unprotected files return before any map lookup and pay ~zero overhead."
