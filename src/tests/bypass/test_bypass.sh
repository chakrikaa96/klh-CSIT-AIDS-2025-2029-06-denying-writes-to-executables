#!/usr/bin/env bash
# Adversarial bypass attempts.
#
# Each case is a technique an attacker (running as an ordinary or even root
# user, but NOT as a trusted updater) might use to modify a protected file.
# Every one must be BLOCKED. The hardlink case is the important one: because
# ExecGuard keys on the inode, a second name for the same inode is still
# protected - a path-based tool would miss this.
set -uo pipefail
. "$(dirname "$0")/../lib.sh"

require_root
require_daemon

SBX=$(mktemp -d /tmp/execguard-bypass.XXXXXX)
TGT="$SBX/app"
cleanup() { egctl unprotect "$TGT" >/dev/null 2>&1 || true; rm -rf "$SBX"; }
trap cleanup EXIT

reset() { printf 'v1\n' > "$TGT"; chmod 0755 "$TGT"; }
reset
egctl protect "$TGT" >/dev/null

echo "Bypass attempts (all must be BLOCKED)"

ok "shell redirect overwrite" "blocked" \
   "$(run_expect sh -c "echo pwned > '$TGT'")"

ok "python open('w')" "blocked" \
   "$(run_expect python3 -c "open('$TGT','w').write('pwned')")"

ok "python os.open O_WRONLY|O_TRUNC" "blocked" \
   "$(run_expect python3 -c "import os;os.close(os.open('$TGT',os.O_WRONLY|os.O_TRUNC))")"

ok "dd overwrite" "blocked" \
   "$(run_expect dd if=/dev/zero of="$TGT" bs=1 count=1 conv=notrunc)"

ok "truncate() syscall (setattr)" "blocked" \
   "$(run_expect truncate -s 0 "$TGT")"

ok "in-place editor (sed -i temp+rename)" "blocked" \
   "$(run_expect sed -i 's/v1/v2/' "$TGT")"

# Editor-style replace: write a new file, then rename it over the protected one.
printf 'pwned\n' > "$SBX/newver"
ok "temp-file replace via rename-over" "blocked" \
   "$(run_expect mv -f "$SBX/newver" "$TGT")"
reset

ok "delete then recreate (rm)" "blocked" \
   "$(run_expect rm -f "$TGT")"
reset

# Hardlink alias: a different path, the SAME inode. Must still be blocked.
if ln "$TGT" "$SBX/alias" 2>/dev/null; then
    ok "write via hardlink alias (same inode)" "blocked" \
       "$(run_expect sh -c "echo pwned > '$SBX/alias'")"
    rm -f "$SBX/alias"
else
    printf '  %-52s [%s] (cross-nothing; hardlink not created)\n' \
        "write via hardlink alias" "$(_yellow SKIP)"
fi
reset

ok "chmod-then-write is still blocked on write" "blocked" \
   "$(run_expect sh -c "chmod 0777 '$TGT' 2>/dev/null; echo pwned > '$TGT'")"

summary
