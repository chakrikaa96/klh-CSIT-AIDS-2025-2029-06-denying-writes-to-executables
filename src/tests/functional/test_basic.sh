#!/usr/bin/env bash
# Functional smoke test: basic protect/unprotect lifecycle and read access.
set -uo pipefail
. "$(dirname "$0")/../lib.sh"

require_root
require_daemon

SBX=$(mktemp -d /tmp/execguard-func.XXXXXX)
TGT="$SBX/app"
cleanup() { egctl unprotect "$TGT" >/dev/null 2>&1 || true; rm -rf "$SBX"; }
trap cleanup EXIT

printf '#!/bin/sh\necho hello\n' > "$TGT"
chmod 0755 "$TGT"

echo "Functional: protect/unprotect lifecycle"

# Before protection, writing must work.
ok "write allowed before protection" \
   "allowed" "$(run_expect sh -c "echo x >> '$TGT'")"

egctl protect "$TGT" >/dev/null

# Reading and executing a protected file must still work.
ok "read allowed while protected" \
   "allowed" "$(run_expect cat "$TGT")"
ok "execute allowed while protected" \
   "allowed" "$(run_expect "$TGT")"

# Writing must now be blocked.
ok "write blocked while protected" \
   "blocked" "$(run_expect sh -c "echo x >> '$TGT'")"

egctl unprotect "$TGT" >/dev/null

# After unprotect, writing works again.
ok "write allowed after unprotect" \
   "allowed" "$(run_expect sh -c "echo x >> '$TGT'")"

# Status command responds.
ok "status command succeeds" \
   "allowed" "$(run_expect egctl status)"

summary
