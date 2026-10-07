#!/usr/bin/env bash
# ExecGuard interactive demonstration.
#
# YOU type the commands. ExecGuard (in the kernel) really allows or blocks them,
# and this shell then reads the real audit log and explains, in plain language,
# WHY each attempt was allowed or denied.
#
# Nothing is faked: the block is performed by the kernel LSM hooks. This wrapper
# only runs the command you typed and then reports the kernel's decision.
#
# Requires: root, and the ExecGuard daemon running.
#   sudo systemctl start execguard
#   sudo ./src/scripts/interactive-demo.sh
set -uo pipefail

DEMO=/opt/execguard-demo
PROT="$DEMO/protected"
export FILE="$PROT/app"          # the protected file you will attack
UPDATER="$DEMO/eg-updater"       # the trusted updater (allowed to change it)
AUDIT=/var/log/execguard/audit.jsonl

# --- colours ---------------------------------------------------------------
if [[ -t 1 ]]; then
    R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'
    C=$'\033[36m'; D=$'\033[2m'; Z=$'\033[0m'
else
    R=""; G=""; Y=""; B=""; C=""; D=""; Z=""
fi

# --- prerequisites ---------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi
if ! egctl status >/dev/null 2>&1; then
    echo "ExecGuard daemon is not reachable. Start it first:" >&2
    echo "  sudo systemctl start execguard" >&2
    exit 1
fi

# Locate the trusted-updater binary and stage the sandbox.
SRC_UPDATER=""
for c in /usr/local/libexec/execguard/eg-updater "$(dirname "$0")/../../build/eg-updater"; do
    [[ -x "$c" ]] && SRC_UPDATER="$c" && break
done

mkdir -p "$PROT"
printf '#!/bin/sh\necho "hello from the protected app"\n' > "$FILE"
chmod 0755 "$FILE"
[[ -n "$SRC_UPDATER" ]] && install -m 0755 "$SRC_UPDATER" "$UPDATER"

egctl protect "$FILE" >/dev/null 2>&1 || true
[[ -n "$SRC_UPDATER" ]] && egctl trust "$UPDATER" >/dev/null 2>&1 || true

# --- helpers ---------------------------------------------------------------
# Extract a "key":"value" or "key":number field from a JSON line.
jfield() { sed -n 's/.*"'"$2"'":"\{0,1\}\([^",}]*\)"\{0,1\}.*/\1/p' <<<"$1"; }

human_op() {
    case "$1" in
        WRITE)    echo "modify the contents of" ;;
        TRUNCATE) echo "truncate (empty) " ;;
        UNLINK)   echo "delete" ;;
        RENAME)   echo "rename / replace" ;;
        *)        echo "modify" ;;
    esac
}

banner() {
    echo
    echo "${B}${C}==============================================================${Z}"
    echo "${B}${C}            ExecGuard - interactive demonstration            ${Z}"
    echo "${B}${C}==============================================================${Z}"
    echo
    echo "A protected executable has been created for you:"
    echo "    ${B}$FILE${Z}"
    echo
    echo "Type commands that try to modify, replace, or delete it."
    echo "ExecGuard will allow or block each one and explain why."
    echo "You can refer to the file as ${B}\$FILE${Z} in your commands."
    echo
    echo "${D}Try these (copy/paste one at a time):${Z}"
    echo "    echo pwned > \$FILE            ${D}# overwrite  -> should be DENIED${Z}"
    echo "    echo more >> \$FILE            ${D}# append     -> should be DENIED${Z}"
    echo "    truncate -s 0 \$FILE           ${D}# truncate   -> should be DENIED${Z}"
    echo "    rm -f \$FILE                   ${D}# delete     -> should be DENIED${Z}"
    echo "    sed -i s/hello/HACKED/ \$FILE  ${D}# edit       -> should be DENIED${Z}"
    echo "    cat \$FILE                     ${D}# read       -> ALLOWED (reading is fine)${Z}"
    if [[ -n "$SRC_UPDATER" ]]; then
    echo "    \$UPDATER \$FILE \"new text\"     ${D}# trusted updater -> ALLOWED${Z}"
    fi
    echo
    echo "${D}Commands: 'help' shows this again, 'log' shows recent decisions,${Z}"
    echo "${D}          'reset' restores the file, 'exit' quits.${Z}"
    echo
}

show_log() {
    echo "${D}--- recent ExecGuard decisions ---${Z}"
    tail -n 6 "$AUDIT" 2>/dev/null | while IFS= read -r l; do
        local dec op tgt; dec="$(jfield "$l" decision)"; op="$(jfield "$l" op)"
        tgt="$(jfield "$l" target_path)"
        printf '  %s %-8s %s\n' "$dec" "$op" "$tgt"
    done
    echo
}

export UPDATER

# --- main loop -------------------------------------------------------------
banner

while true; do
    # Snapshot the audit log size so we can tell whether ExecGuard weighed in.
    before=$(wc -l < "$AUDIT" 2>/dev/null || echo 0)

    printf '%b' "${B}${Y}try> ${Z}"
    IFS= read -r -e CMD || break
    [[ -z "${CMD// }" ]] && continue

    case "$CMD" in
        exit|quit|q) break ;;
        help|h)      banner; continue ;;
        log)         show_log; continue ;;
        reset)
            egctl unprotect "$FILE" >/dev/null 2>&1 || true
            printf '#!/bin/sh\necho "hello from the protected app"\n' > "$FILE"
            chmod 0755 "$FILE"
            egctl protect "$FILE" >/dev/null 2>&1 || true
            echo "${G}File restored and re-protected.${Z}"; echo; continue ;;
    esac

    # Run exactly what the user typed. The kernel is what enforces; we only
    # observe the result and the audit trail.
    out="$(bash -c "$CMD" 2>&1)"; rc=$?
    after=$(wc -l < "$AUDIT" 2>/dev/null || echo 0)

    newline=""
    if (( after > before )); then
        newline="$(tail -n 1 "$AUDIT" 2>/dev/null)"
    fi

    echo
    if [[ -n "$newline" ]]; then
        dec="$(jfield "$newline" decision)"
        op="$(jfield "$newline" op)"
        reason="$(jfield "$newline" reason)"
        comm="$(jfield "$newline" comm)"
        tgt="$(jfield "$newline" target_path)"
        verb="$(human_op "$op")"

        if [[ "$dec" == "DENY" ]]; then
            echo "${B}${R}  BLOCKED by ExecGuard${Z}"
            echo "  ${R}Your process '${comm}' tried to ${verb} a protected executable.${Z}"
            echo "  ${R}Reason : ${reason}${Z}"
            echo "  ${R}Target : ${tgt}${Z}"
            echo "  ${D}The operation returned 'Permission denied' from the kernel;${Z}"
            echo "  ${D}the file was never changed.${Z}"
        elif [[ "$dec" == "ALLOW" ]]; then
            echo "${B}${G}  ALLOWED by ExecGuard${Z}"
            echo "  ${G}'${comm}' was permitted to ${verb} the file.${Z}"
            echo "  ${G}Reason : ${reason}${Z}"
        else
            echo "${B}${Y}  AUDITED (would block, audit-only mode)${Z}"
            echo "  ${Y}Reason : ${reason}${Z}"
        fi
    else
        # ExecGuard did not weigh in: either a read/allowed op on a protected
        # file, or a normal command. Report the shell's own result.
        if (( rc == 0 )); then
            echo "${G}  Command succeeded (ExecGuard did not need to intervene).${Z}"
            [[ -n "$out" ]] && echo "${D}  output: $out${Z}"
        else
            echo "${Y}  Command failed, but not because of ExecGuard.${Z}"
            [[ -n "$out" ]] && echo "${D}  $out${Z}"
        fi
    fi
    echo
done

echo
echo "Cleaning up the demo sandbox..."
egctl unprotect "$FILE" >/dev/null 2>&1 || true
echo "Done. (The file lived under $DEMO; remove it with: sudo rm -rf $DEMO)"
