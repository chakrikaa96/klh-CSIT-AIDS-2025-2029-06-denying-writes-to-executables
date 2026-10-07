#!/usr/bin/env bash
# ExecGuard - demo launcher.
#
# Runs a demo in a SEPARATE terminal so your current shell stays clean.
# It picks the best method available on this machine, in order:
#
#   1. A graphical terminal window   (needs a desktop session / DISPLAY)
#   2. A tmux session                (works headless, e.g. inside a VM over SSH)
#   3. Neither -> it tells you how to proceed
#
# Usage:
#   sudo ./src/scripts/launch-demo.sh                 # runs src/scripts/demo.sh
#   sudo ./src/scripts/launch-demo.sh web             # runs src/scripts/web-demo.sh instead
#
# Notes:
#   - Run with sudo; the demo needs root for enforcement.
#   - In a VM (no desktop), method 2 (tmux) is used: the demo runs in its own
#     tmux session and this launcher attaches you to it. When the demo ends (or
#     you press Ctrl-b then d to detach), you return to your original, untouched
#     shell.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Choose which demo to run.
case "${1:-terminal}" in
    web)  TARGET="$HERE/web-demo.sh" ;;
    *)    TARGET="$HERE/demo.sh" ;;
esac

if [[ ! -f "$TARGET" ]]; then
    echo "Cannot find demo script: $TARGET" >&2
    exit 1
fi

# The command the new terminal will run. Keep root: if we are already root,
# call bash directly; otherwise use sudo inside the new terminal.
if [[ $EUID -eq 0 ]]; then
    INNER="bash '$TARGET'"
else
    INNER="sudo bash '$TARGET'"
fi
# Keep the window open after the demo finishes so results stay visible.
RUN="$INNER; echo; read -r -p 'Demo finished. Press Enter to close this window… ' _"

# --- Method 1: a graphical terminal window ----------------------------------
if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
    for term in x-terminal-emulator gnome-terminal konsole xfce4-terminal mate-terminal tilix xterm; do
        if command -v "$term" >/dev/null 2>&1; then
            case "$term" in
                gnome-terminal|tilix)
                    "$term" -- bash -lc "$RUN" >/dev/null 2>&1 & ;;
                *)
                    "$term" -e bash -lc "$RUN" >/dev/null 2>&1 & ;;
            esac
            echo "Opened the demo in a new $term window."
            echo "This terminal is free."
            exit 0
        fi
    done
    echo "A desktop session was detected, but no known terminal emulator was found."
    echo "Falling back to tmux…"
fi

# --- Method 2: tmux (works without a GUI) -----------------------------------
if command -v tmux >/dev/null 2>&1; then
    SESSION="execguard-demo"

    # If we are already inside tmux, open the demo as a NEW window in this
    # session (visible immediately, current pane untouched).
    if [[ -n "${TMUX:-}" ]]; then
        tmux new-window -n execguard "bash -lc \"$RUN\""
        echo "Opened the demo in a new tmux window. Your current pane is untouched."
        echo "Switch windows with Ctrl-b then n (next) / p (previous)."
        exit 0
    fi

    # Not inside tmux: start the demo in its own detached session, then attach
    # so you watch it in a separate terminal session. Your original shell is
    # preserved and returns when you detach or the demo ends.
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    tmux new-session -d -s "$SESSION" "bash -lc \"$RUN\""
    echo "Starting the demo in a separate tmux session ('$SESSION')."
    echo "Attaching now. Detach anytime with:  Ctrl-b  then  d"
    echo "Your original shell will be waiting for you when you return."
    sleep 1
    exec tmux attach -t "$SESSION"
fi

# --- Method 3: nothing available --------------------------------------------
cat <<EOF
Could not open a separate terminal on this machine:
  - No graphical desktop is available (so no new window can pop up), and
  - tmux is not installed (so no separate text session can be created).

You are almost certainly inside a headless VM. Pick one:

  1. Install tmux, then re-run this launcher (recommended for a VM):
         sudo apt-get install -y tmux
         sudo ./src/scripts/launch-demo.sh

  2. Open a SECOND terminal yourself and run the demo there:
         (on your Mac, in a new tab)  multipass shell execguard-test
         cd ~/execguard && sudo ./src/scripts/demo.sh

  3. Use the live web page instead (results leave the terminal entirely):
         sudo ./src/scripts/web-demo.sh
EOF
exit 1
