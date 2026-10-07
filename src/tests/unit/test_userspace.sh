#!/usr/bin/env bash
# ExecGuard userspace and build-artifact tests.
#
# These tests need no BPF-LSM support, no root, and no running daemon. They
# cover everything that can be verified without in-kernel enforcement:
#
#   1. Core library unit tests (src/tests/unit/test_core.c)
#   2. egctl CLI behaviour: exit codes, policy validation, integrity workflow
#   3. eg-updater behaviour on an unprotected file
#   4. The compiled BPF object: LSM sections, license, maps, and that the BTF
#      layout of the shared structs matches what userspace was compiled with
#
# Kernel enforcement itself is covered by src/tests/{functional,security,bypass}.
#
# Usage: src/tests/unit/test_userspace.sh        (run "make" first)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
. "$HERE/../lib.sh"

BUILD="$ROOT/build"
EG="$BUILD/execguard"
UPD="$BUILD/eg-updater"
BPF_OBJ="$BUILD/execguard.bpf.o"

for f in "$EG" "$UPD" "$BPF_OBJ"; do
    [[ -e "$f" ]] || { echo "missing $f; run 'make' first" >&2; exit 1; }
done

SCRATCH=$(mktemp -d /tmp/execguard-unit.XXXXXX)
trap 'rm -rf "$SCRATCH"' EXIT

# Prepare fixtures with explicit modes (independent of checkout permissions).
cp -r "$ROOT/data/fixtures/sandbox" "$SCRATCH/sandbox"
chmod 0755 "$SCRATCH/sandbox/bin/app"
chmod 0644 "$SCRATCH/sandbox/bin/tool.sh" "$SCRATCH/sandbox/bin/elf-noexec" \
           "$SCRATCH/sandbox/lib/readme.txt"
sed "s#@FIXTURES@#$SCRATCH/sandbox#g" "$ROOT/data/policies/fixtures.conf.in" \
    > "$SCRATCH/fixtures.conf"

# expect_rc "<description>" <expected-exit-code> <command...>
expect_rc() {
    local desc="$1" want="$2"; shift 2
    "$@" >"$SCRATCH/last.out" 2>&1
    ok "$desc" "rc=$want" "rc=$?"
}

# expect_out "<description>" "<regex>"   (matches the previous command's output)
expect_out() {
    local desc="$1" re="$2"
    if grep -Eq -- "$re" "$SCRATCH/last.out"; then
        ok "$desc" "match" "match"
    else
        ok "$desc" "match" "no-match: $(head -c 120 "$SCRATCH/last.out" | tr '\n' ' ')"
    fi
}

# ---------------------------------------------------------------- 1. core --
echo "1. Core library"
CC_BIN="$BUILD/test_core"
if [[ ! -x "$CC_BIN" || "$HERE/test_core.c" -nt "$CC_BIN" || \
      "$ROOT/src/userspace/execguard.c" -nt "$CC_BIN" ]]; then
    ${CC:-gcc} -O1 -g -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
        -I"$ROOT/src/include" -I"$BUILD" "$HERE/test_core.c" -o "$CC_BIN" \
        -lbpf -lelf -lz -lcrypto -lpthread || { echo "test_core build failed" >&2; exit 1; }
fi
"$CC_BIN" "$ROOT" "$SCRATCH" | tee "$SCRATCH/core.out" | sed 's/^/    /'
core_rc=${PIPESTATUS[0]}
ok "core unit tests (see above)" "rc=0" "rc=$core_rc"

# ----------------------------------------------------------------- 2. CLI --
echo
echo "2. egctl command-line interface"
expect_rc "version exits 0"                         0 "$EG" version
expect_out "version string printed"                 '^egctl [0-9]+\.[0-9]+\.[0-9]+'
expect_rc "--help exits 0"                          0 "$EG" --help
expect_out "help documents env overrides"           'EG_CONFIG'
expect_rc "no arguments exits 2 (usage)"            2 "$EG"
expect_rc "unknown command exits 2"                 2 "$EG" frobnicate
expect_rc "protect with no path exits 2"            2 "$EG" protect

for p in demo audit-rollout system-enforce empty-but-valid; do
    expect_rc "policy validate: $p.conf"            0 env EG_CONFIG="$ROOT/data/policies/$p.conf" "$EG" policy validate
done
for p in "$ROOT"/data/policies/invalid/*.conf; do
    expect_rc "policy reject: invalid/$(basename "$p")" 1 env EG_CONFIG="$p" "$EG" policy validate
    expect_out "  reports file:line"                 "$(basename "$p"):[0-9]+: invalid directive"
done
expect_rc "policy validate: missing file exits 1"   1 env EG_CONFIG=/nonexistent "$EG" policy validate

expect_rc "maintenance: invalid duration exits 2"  2 "$EG" maintenance enable --duration 5x
expect_rc "maintenance: no subcommand exits 2"     2 "$EG" maintenance

# Daemon-backed commands must fail cleanly when no daemon is reachable.
if [[ -S /run/execguard/control.sock ]] && "$EG" status >/dev/null 2>&1; then
    printf '  %-52s [%s] (daemon is running)\n' "status without daemon" "$(_yellow SKIP)"
else
    expect_rc "status without daemon exits 1"       1 "$EG" status
    expect_out "  explains daemon is unreachable"   'cannot reach execguardd'
fi

echo
echo "   integrity workflow (EG_CONFIG=fixtures.conf)"
export EG_CONFIG="$SCRATCH/fixtures.conf" EG_BASELINE="$SCRATCH/state/baseline.jsonl"
expect_rc "integrity baseline exits 0"              0 "$EG" integrity baseline
expect_out "  3 files recorded"                     'baseline written: 3 file'
python3 - "$EG_BASELINE" <<'PY' >"$SCRATCH/last.out" 2>&1
import json, re, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 3, rows
for r in rows:
    assert set(r) == {"path", "sha256", "size"}, r
    assert re.fullmatch(r"[0-9a-f]{64}", r["sha256"]), r
    assert isinstance(r["size"], int) and r["size"] > 0, r
print("schema ok")
PY
expect_out "  baseline lines match baseline-entry schema" 'schema ok'
expect_rc "integrity scan (clean) exits 0"          0 "$EG" integrity scan
expect_out "  3 ok, 0 changed, 0 missing"           '3 ok, 0 changed, 0 missing'
expect_rc "verify unchanged file exits 0"           0 "$EG" verify "$SCRATCH/sandbox/bin/app"
expect_out "  reports OK"                           '^OK '
printf '#!/bin/sh\necho trojan\n' > "$SCRATCH/sandbox/bin/app"
expect_rc "verify tampered file exits 1"            1 "$EG" verify "$SCRATCH/sandbox/bin/app"
expect_out "  reports CHANGED"                      '^CHANGED '
rm -f "$SCRATCH/sandbox/bin/tool.sh"
expect_rc "integrity scan (tampered) exits 1"       1 "$EG" integrity scan
expect_out "  1 ok, 1 changed, 1 missing"           '1 ok, 1 changed, 1 missing'
expect_rc "verify path not in baseline exits 1"     1 "$EG" verify /etc/hostname
expect_out "  reports UNKNOWN"                      '^UNKNOWN '
unset EG_CONFIG EG_BASELINE

echo
echo "   audit log tail (EG_AUDIT_LOG)"
LOG="$SCRATCH/audit.jsonl"
for i in $(seq 1 25); do
    printf '{"ts_ns":%d,"decision":"DENY","op":"WRITE","reason":"protected executable"}\n' "$i"
done > "$LOG"
expect_rc "logs -n 5 exits 0"                       0 env EG_AUDIT_LOG="$LOG" "$EG" logs -n 5
ok "  prints exactly the last 5 events" "5:21" \
   "$(wc -l < "$SCRATCH/last.out" | tr -d ' '):$(head -1 "$SCRATCH/last.out" | sed 's/.*"ts_ns":\([0-9]*\).*/\1/')"
expect_rc "logs default prints 20"                  0 env EG_AUDIT_LOG="$LOG" "$EG" logs
ok "  default tail length is 20" "20" "$(wc -l < "$SCRATCH/last.out" | tr -d ' ')"
expect_rc "logs on missing file exits 1"            1 env EG_AUDIT_LOG=/nonexistent "$EG" logs

# ---------------------------------------------------------- 3. eg-updater --
echo
echo "3. eg-updater (no ExecGuard involvement: target is unprotected)"
expect_rc "usage error exits 2"                     2 "$UPD" only-one-arg
T="$SCRATCH/updater-target"
expect_rc "rewrites an unprotected file"            0 "$UPD" "$T" "v2-content"
ok "  file holds exactly the new content" "v2-content" "$(cat "$T")"
ok "  created with mode 0755" "755" "$(stat -c %a "$T")"
expect_rc "unwritable directory exits 1"            1 "$UPD" /nonexistent/dir/file x

# ---------------------------------------------------------- 4. BPF object --
echo
echo "4. Compiled BPF object ($(basename "$BPF_OBJ"))"
SECTIONS=$(readelf -SW "$BPF_OBJ" 2>/dev/null)
for s in lsm/file_open lsm/inode_unlink lsm/inode_rename lsm/inode_setattr; do
    ok "section $s present" "yes" "$(grep -q " $s " <<<"$SECTIONS" && echo yes || echo no)"
done
ok "license section is GPL" "GPL" \
   "$(readelf -x license "$BPF_OBJ" 2>/dev/null | grep -o 'GPL' | head -1)"
ok ".maps section present" "yes" "$(grep -q ' \.maps ' <<<"$SECTIONS" && echo yes || echo no)"
ok "BTF present (needed for CO-RE)" "yes" "$(grep -q ' \.BTF ' <<<"$SECTIONS" && echo yes || echo no)"

BPFTOOL_BIN="${BPFTOOL:-bpftool}"
if command -v "$BPFTOOL_BIN" >/dev/null 2>&1 && "$BPFTOOL_BIN" version >/dev/null 2>&1; then
    BTF=$("$BPFTOOL_BIN" btf dump file "$BPF_OBJ" 2>/dev/null)
    # struct eg_event is not emitted to BTF (only used in an inlined helper);
    # its layout is pinned by _Static_assert in eg_common.h on both compilers.
    for spec in "eg_file_key:16" "eg_file_val:8" "eg_state:16"; do
        name=${spec%%:*}; want=${spec##*:}
        got=$(grep -E "STRUCT '$name' size=" <<<"$BTF" | sed -E 's/.*size=([0-9]+).*/\1/' | head -1)
        ok "BTF: struct $name size matches userspace" "$want" "${got:-absent}"
    done
    ok "eg_event layout pinned by _Static_assert in ABI header" "yes" \
       "$(grep -q 'sizeof(struct eg_event) *== 336' "$ROOT/src/include/execguard/eg_common.h" && echo yes || echo no)"
    for m in protected_inodes trusted_exes state events; do
        ok "map '$m' defined" "yes" "$(grep -q "VAR '$m'" <<<"$BTF" && echo yes || echo no)"
    done
else
    printf '  %-52s [%s] (bpftool not usable)\n' "BTF struct layout checks" "$(_yellow SKIP)"
fi

summary
