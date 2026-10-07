#!/usr/bin/env bash
# Run every ExecGuard test suite and report a per-suite verdict.
#
#   unit        userspace + build artifacts   (no root, no daemon needed)
#   functional  protect/unprotect lifecycle   (root + running daemon)
#   security    full DENY/ALLOW matrix        (root + running daemon)
#   bypass      adversarial techniques        (root + running daemon)
#
# A suite that cannot run on this host (exit 77) is reported as SKIP, not FAIL.
# Optional: LOG_DIR=<dir> writes each suite's full output to <dir>/<suite>.log.
#
# Exit status: 0 if no suite failed, 1 otherwise.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${LOG_DIR:-}"
[[ -n "$LOG_DIR" ]] && mkdir -p "$LOG_DIR"

declare -a NAMES=(unit functional security bypass)
declare -A SCRIPT=(
    [unit]="$HERE/unit/test_userspace.sh"
    [functional]="$HERE/functional/test_basic.sh"
    [security]="$HERE/security/test_matrix.sh"
    [bypass]="$HERE/bypass/test_bypass.sh"
)
declare -A VERDICT

failed=0
for s in "${NAMES[@]}"; do
    echo "=================================================================="
    echo " suite: $s"
    echo "=================================================================="
    if [[ "$s" != unit && $EUID -ne 0 ]]; then
        echo "SKIP: requires root"
        VERDICT[$s]="SKIP (requires root)"
        continue
    fi
    if [[ -n "$LOG_DIR" ]]; then
        bash "${SCRIPT[$s]}" 2>&1 | tee "$LOG_DIR/$s.log"
        rc=${PIPESTATUS[0]}
    else
        bash "${SCRIPT[$s]}"
        rc=$?
    fi
    case $rc in
        0)  VERDICT[$s]="PASS" ;;
        77) VERDICT[$s]="SKIP (daemon not reachable / kernel lacks BPF-LSM)" ;;
        *)  VERDICT[$s]="FAIL (exit $rc)"; failed=1 ;;
    esac
    echo
done

echo "=================================================================="
echo " summary"
echo "=================================================================="
for s in "${NAMES[@]}"; do
    printf '  %-12s %s\n' "$s" "${VERDICT[$s]}"
done
exit $failed
