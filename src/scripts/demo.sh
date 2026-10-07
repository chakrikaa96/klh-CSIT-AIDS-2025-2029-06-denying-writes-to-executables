#!/usr/bin/env bash
# ExecGuard safe demonstration.
#
# Creates an isolated sandbox under /opt/execguard-demo, protects two files,
# then attempts every tampering vector and shows each one being blocked - while
# a trusted updater succeeds. Nothing outside the sandbox is touched.
#
# Requires: ExecGuard daemon running (sudo systemctl start execguard) and root.
set -uo pipefail

# ---------------------------------------------------------------------------
# Always run in a SEPARATE terminal.
#
# When you launch this script, it re-launches itself in its own terminal and
# shows all output there; the shell you started from is not used for the demo.
# There is no inline fallback. It opens, in order:
#   1. a graphical terminal window   (if a desktop/DISPLAY is present)
#   2. a tmux session                (headless machines, e.g. a VM) - REQUIRED
# If neither is possible it stops with instructions rather than running here.
#
# The EG_IN_TERM guard prevents an infinite relaunch loop: the second copy runs
# the actual demo below.
# ---------------------------------------------------------------------------
if [[ -z "${EG_IN_TERM:-}" ]]; then
    SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"

    # Write a small wrapper script that the new terminal will run. Using a file
    # (instead of a long, nested-quoted -c string) avoids all quoting problems,
    # which is what caused an earlier version to close instantly. The wrapper
    # runs the demo, then holds the terminal open until you press Enter, then
    # cleans itself up.
    WRAP="$(mktemp /tmp/eg-demo-run.XXXXXX.sh)"
    {
        echo '#!/usr/bin/env bash'
        echo "export EG_IN_TERM=1"
        echo "bash \"$SELF\""
        echo 'echo'
        echo "read -r -p 'Demo finished. Press Enter to close this terminal... ' _"
        echo "rm -f \"$WRAP\""
    } > "$WRAP"
    chmod +x "$WRAP"

    # 1. Graphical terminal window (desktop sessions only).
    if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        for term in x-terminal-emulator gnome-terminal konsole xfce4-terminal \
                    mate-terminal tilix xterm; do
            if command -v "$term" >/dev/null 2>&1; then
                case "$term" in
                    gnome-terminal|tilix)
                        "$term" -- bash "$WRAP" >/dev/null 2>&1 & ;;
                    *)
                        "$term" -e bash "$WRAP" >/dev/null 2>&1 & ;;
                esac
                echo "ExecGuard demo opened in a new $term window."
                exit 0
            fi
        done
    fi

    # 2. tmux session (works headless, e.g. inside a VM over SSH).
    if command -v tmux >/dev/null 2>&1; then
        SESSION="execguard-demo"
        if [[ -n "${TMUX:-}" ]]; then
            # Already inside tmux: open the demo as a new window.
            tmux new-window -n execguard "bash '$WRAP'"
            echo "ExecGuard demo opened in a new tmux window (Ctrl-b then n/p to switch)."
            exit 0
        fi
        tmux kill-session -t "$SESSION" 2>/dev/null || true
        tmux new-session -d -s "$SESSION" "bash '$WRAP'"
        echo "ExecGuard demo running in a separate tmux terminal. Attaching now."
        echo "(Detach anytime with Ctrl-b then d; your original shell returns.)"
        sleep 1
        exec tmux attach -t "$SESSION"
    fi

    # No separate terminal is possible: stop (no inline fallback).
    rm -f "$WRAP"
    echo "ERROR: cannot open a separate terminal on this machine." >&2
    echo "This demo only runs in its own terminal. Install tmux and retry:" >&2
    echo "    sudo apt-get install -y tmux" >&2
    echo "    sudo ./src/scripts/demo.sh" >&2
    exit 1
fi

DEMO=/opt/execguard-demo
PROT="$DEMO/protected"
UPDATER="$DEMO/eg-updater"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n'  "$*"; }
rule()  { printf -- '---------------------------------------------------------\n'; }

if [[ $EUID -ne 0 ]]; then
    echo "Run the demo as root: sudo ./src/scripts/demo.sh" >&2
    exit 1
fi

if ! egctl status >/dev/null 2>&1; then
    echo "ExecGuard daemon is not reachable. Start it first:" >&2
    echo "  sudo systemctl start execguard" >&2
    exit 1
fi

# Locate the trusted-updater binary (installed or freshly built).
SRC_UPDATER=""
for cand in /usr/local/libexec/execguard/eg-updater \
            "$(dirname "$0")/../../build/eg-updater"; do
    [[ -x "$cand" ]] && SRC_UPDATER="$cand" && break
done
if [[ -z "$SRC_UPDATER" ]]; then
    echo "eg-updater not found. Build first: make" >&2
    exit 1
fi

bold "==> Setting up sandbox at $DEMO"
mkdir -p "$PROT"
cat > "$PROT/app" <<'EOF'
#!/bin/sh
echo "I am the protected application, version 1."
EOF
chmod 0755 "$PROT/app"
cat > "$PROT/script.sh" <<'EOF'
#!/bin/sh
echo "protected script"
EOF
chmod 0755 "$PROT/script.sh"
install -m 0755 "$SRC_UPDATER" "$UPDATER"

bold "==> Registering protection (runtime)"
egctl protect "$PROT/app"
egctl protect "$PROT/script.sh"
egctl trust   "$UPDATER"
rule

# Helper: run a command that SHOULD be blocked; report the outcome.
expect_blocked() {
    local desc="$1"; shift
    printf '  %-46s ' "$desc"
    if "$@" >/dev/null 2>&1; then
        red "ALLOWED  (unexpected!)"
    else
        green "BLOCKED  (Permission denied)"
    fi
}

bold "==> Attempting unauthorized modifications (all should be BLOCKED)"
expect_blocked "Direct write (shell redirect)" \
    sh -c "echo malicious > '$PROT/app'"
expect_blocked "Append to file" \
    sh -c "echo more >> '$PROT/app'"
expect_blocked "Truncate file" \
    truncate -s 0 "$PROT/app"
expect_blocked "In-place edit (sed -i)" \
    sed -i 's/version 1/HACKED/' "$PROT/app"
echo "malware" > /tmp/eg_demo_evil 2>/dev/null || true
expect_blocked "Replace via rename (mv over target)" \
    mv -f /tmp/eg_demo_evil "$PROT/app"
expect_blocked "Delete file (rm)" \
    rm -f "$PROT/app"
expect_blocked "Delete via unlink" \
    sh -c "python3 -c \"import os; os.unlink('$PROT/app')\""
rule

bold "==> Authorized update via trusted updater (should SUCCEED)"
printf '  %-46s ' "eg-updater rewrites protected app"
if "$UPDATER" "$PROT/app" "I am the protected application, version 2." >/dev/null 2>&1; then
    green "ALLOWED  (trusted updater)"
else
    red "BLOCKED  (unexpected - is $UPDATER trusted?)"
fi
echo "  Current contents:"
sed 's/^/    /' "$PROT/app"
rule

bold "==> Integrity baseline and verification"
egctl integrity baseline
egctl integrity scan
rule

bold "==> Recent audit events"
egctl logs -n 12
rule

bold "==> Verifying the protected app still runs"
"$PROT/app" | sed 's/^/  /'
rule

green "Demo complete."
echo "Protection remains active on the sandbox files for further exploration."
echo "To clean up: sudo egctl unprotect $PROT/app; sudo rm -rf $DEMO"
