#!/usr/bin/env bash
# ExecGuard installer.
# Builds the project and installs the daemon, CLI, config, and systemd unit.
set -euo pipefail

cd "$(dirname "$0")/../.."   # repository root

if [[ $EUID -ne 0 ]]; then
    echo "This installer must run as root (it installs system files)." >&2
    echo "Try: sudo make install" >&2
    exit 1
fi

echo "==> Checking environment"
# Capture the classifier's exit code explicitly. (Reading $? inside
# "if ! cmd; then" yields the negated status, which is always 0.)
env_rc=0
./src/scripts/check-env.sh || env_rc=$?
if [[ $env_rc -eq 2 ]]; then
    echo "Environment is UNSUPPORTED. Aborting." >&2
    exit 1
elif [[ $env_rc -ne 0 ]]; then
    echo "Note: environment check returned $env_rc. Continuing may yield" >&2
    echo "reduced functionality; see the output above." >&2
fi

echo "==> Building"
make vmlinux
make -j"$(nproc)"

echo "==> Installing binaries"
# One multi-call binary; execguardd and egctl are symlinks to it. The program
# decides whether to act as the daemon or the CLI from the name it is called by.
install -D -m 0755 build/execguard  /usr/local/bin/execguard
install -d -m 0755 /usr/local/sbin
ln -sf /usr/local/bin/execguard /usr/local/sbin/execguardd
ln -sf /usr/local/bin/execguard /usr/local/bin/egctl
install -D -m 0755 build/eg-updater /usr/local/libexec/execguard/eg-updater

echo "==> Installing configuration"
install -d -m 0750 /etc/execguard
if [[ ! -f /etc/execguard/execguard.conf ]]; then
    install -m 0640 src/config/execguard.conf /etc/execguard/execguard.conf
else
    echo "    keeping existing /etc/execguard/execguard.conf"
fi

echo "==> Creating state and log directories"
install -d -m 0750 /var/lib/execguard
install -d -m 0750 /var/log/execguard
install -d -m 0750 /run/execguard

echo "==> Installing documentation"
install -d -m 0755 /usr/local/share/doc/execguard
install -m 0644 README.md /usr/local/share/doc/execguard/README.md
install -m 0644 docs/*.md /usr/local/share/doc/execguard/

echo "==> Installing systemd unit"
install -m 0644 src/systemd/execguard.service /etc/systemd/system/execguard.service
systemctl daemon-reload

cat <<'EOF'

ExecGuard installed.

Next steps:
  1. Edit the policy:      sudo nano /etc/execguard/execguard.conf
  2. Validate it:          egctl policy validate
  3. Start the service:    sudo systemctl enable --now execguard
  4. Check status:         egctl status
  5. Try the safe demo:    sudo ./src/scripts/demo.sh

To uninstall:             sudo make uninstall
EOF
