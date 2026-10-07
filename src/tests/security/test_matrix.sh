#!/usr/bin/env bash
# Security enforcement matrix.
#
# Verifies the full DENY/ALLOW decision table:
#   protected + untrusted caller  -> every mutation BLOCKED
#   unprotected file              -> every mutation ALLOWED
#   protected + trusted updater   -> mutation ALLOWED
#   maintenance window active     -> mutation ALLOWED
#   global audit-only mode        -> mutation ALLOWED (but logged)
set -uo pipefail
. "$(dirname "$0")/../lib.sh"

require_root
require_daemon

SBX=$(mktemp -d /tmp/execguard-matrix.XXXXXX)
PROT="$SBX/protected"
UNPROT="$SBX/plain"
UPDATER="$SBX/eg-updater"

cleanup() {
    egctl unprotect "$PROT" >/dev/null 2>&1 || true
    egctl untrust  "$UPDATER" >/dev/null 2>&1 || true
    egctl maintenance disable >/dev/null 2>&1 || true
    egctl enforce 1 >/dev/null 2>&1 || true
    rm -rf "$SBX"
}
trap cleanup EXIT

# Locate the trusted updater binary.
SRC_UPDATER=""
for c in /usr/local/libexec/execguard/eg-updater \
         "$(dirname "$0")/../../../build/eg-updater"; do
    [[ -x "$c" ]] && SRC_UPDATER="$c" && break
done
[[ -z "$SRC_UPDATER" ]] && { echo "eg-updater not found; run make" >&2; exit 1; }

reset_files() {
    printf 'protected v1\n' > "$PROT"; chmod 0755 "$PROT"
    printf 'plain v1\n'     > "$UNPROT"; chmod 0755 "$UNPROT"
}
reset_files
install -m 0755 "$SRC_UPDATER" "$UPDATER"

egctl protect "$PROT" >/dev/null
egctl trust   "$UPDATER" >/dev/null

echo "Matrix A: protected file, untrusted caller (expect BLOCKED)"
ok "write"     "blocked" "$(run_expect sh -c "echo x > '$PROT'")"
ok "append"    "blocked" "$(run_expect sh -c "echo x >> '$PROT'")"
ok "truncate"  "blocked" "$(run_expect truncate -s 0 "$PROT")"
reset_files
ok "delete"    "blocked" "$(run_expect rm -f "$PROT")"
echo evil > "$SBX/tmp"; 
ok "rename-over" "blocked" "$(run_expect mv -f "$SBX/tmp" "$PROT")"
reset_files

echo "Matrix B: unprotected file, any caller (expect ALLOWED)"
ok "write"     "allowed" "$(run_expect sh -c "echo x > '$UNPROT'")"
ok "truncate"  "allowed" "$(run_expect truncate -s 0 "$UNPROT")"
ok "delete"    "allowed" "$(run_expect rm -f "$UNPROT")"

echo "Matrix C: protected file, trusted updater (expect ALLOWED)"
ok "trusted rewrite" "allowed" \
   "$(run_expect "$UPDATER" "$PROT" "rewritten by trusted updater")"
reset_files

echo "Matrix D: maintenance window active (expect ALLOWED)"
egctl maintenance enable --duration 30s >/dev/null
ok "write during maintenance" "allowed" \
   "$(run_expect sh -c "echo x > '$PROT'")"
egctl maintenance disable >/dev/null
reset_files
ok "write after maintenance disabled" "blocked" \
   "$(run_expect sh -c "echo x > '$PROT'")"
reset_files

echo "Matrix E: global audit-only mode (expect ALLOWED but logged)"
egctl enforce 0 >/dev/null
ok "write in audit-only mode" "allowed" \
   "$(run_expect sh -c "echo x > '$PROT'")"
egctl enforce 1 >/dev/null
reset_files
ok "write after re-enabling enforce" "blocked" \
   "$(run_expect sh -c "echo x > '$PROT'")"

summary
