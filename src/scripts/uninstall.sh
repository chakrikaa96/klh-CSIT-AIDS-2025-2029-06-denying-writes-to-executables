#!/usr/bin/env bash
# ExecGuard uninstaller. Reverses install.sh.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This uninstaller must run as root." >&2
    echo "Try: sudo make uninstall" >&2
    exit 1
fi

echo "==> Stopping and disabling service"
systemctl disable --now execguard 2>/dev/null || true

echo "==> Removing systemd unit"
rm -f /etc/systemd/system/execguard.service
systemctl daemon-reload 2>/dev/null || true

echo "==> Removing binaries"
rm -f /usr/local/sbin/execguardd
rm -f /usr/local/bin/egctl
rm -f /usr/local/bin/execguard
rm -f /usr/local/libexec/execguard/eg-updater
rmdir /usr/local/libexec/execguard 2>/dev/null || true

echo "==> Removing documentation"
rm -rf /usr/local/share/doc/execguard

echo "==> Removing runtime directory"
rm -rf /run/execguard

# Preserve config, baseline, and audit logs unless explicitly asked to purge.
if [[ "${1:-}" == "--purge" ]]; then
    echo "==> Purging configuration, baseline, and logs"
    rm -rf /etc/execguard /var/lib/execguard /var/log/execguard
else
    echo
    echo "Kept /etc/execguard, /var/lib/execguard, and /var/log/execguard."
    echo "Run 'sudo ./src/scripts/uninstall.sh --purge' to remove those as well."
fi

echo "ExecGuard uninstalled."
