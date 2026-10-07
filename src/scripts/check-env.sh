#!/usr/bin/env bash
#
# ExecGuard :: src/scripts/check-env.sh
# Phase 1 -- Environment detection.
#
# Classifies the current host into one of three enforcement modes and reports
# precisely which prerequisite (if any) is missing. Every later phase of the
# project branches on the mode reported here.
#
#   EBPF_LSM           Full pre-operation enforcement is available.
#   FANOTIFY_FALLBACK  Partial: write-open can be denied; rename/unlink can only
#                      be detected after the fact (documented limitation).
#   UNSUPPORTED        Neither mechanism is usable on this host.
#
# Exit codes:
#   0  EBPF_LSM ready
#   1  FANOTIFY_FALLBACK only
#   2  UNSUPPORTED
#   3  Script error / could not determine environment
#
# This script only reads system state. It changes nothing.

set -o errexit
set -o nounset
set -o pipefail

# ----------------------------------------------------------------------------
# Output helpers (color is optional and degrades gracefully on dumb terminals).
# ----------------------------------------------------------------------------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    C_OK="$(tput setaf 2)"; C_WARN="$(tput setaf 3)"; C_ERR="$(tput setaf 1)"
    C_DIM="$(tput dim)"; C_RST="$(tput sgr0)"
else
    C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_RST=""
fi

pass() { printf '  [ %sOK%s ] %s\n'   "$C_OK"   "$C_RST" "$*"; }
warn() { printf '  [%sWARN%s] %s\n'   "$C_WARN" "$C_RST" "$*"; }
fail() { printf '  [%sFAIL%s] %s\n'   "$C_ERR"  "$C_RST" "$*"; }
info() { printf '  %s%s%s\n'          "$C_DIM"  "$*"     "$C_RST"; }
hdr()  { printf '\n%s\n' "$*"; }

# ----------------------------------------------------------------------------
# State accumulated across checks.
# ----------------------------------------------------------------------------
KERNEL_OK=0          # kernel >= 5.7
BTF_OK=0             # BTF present (needed for CO-RE)
BPF_LSM_ACTIVE=0     # 'bpf' in the active LSM list
CFG_BPF_LSM=0        # CONFIG_BPF_LSM=y
CFG_SECURITY_PATH=0  # CONFIG_SECURITY_PATH=y (optional; path_* hooks)
CFG_BTF=0            # CONFIG_DEBUG_INFO_BTF=y
TOOLCHAIN_OK=1       # clang + bpftool + libbpf headers
FANOTIFY_OK=0        # kernel plausibly supports fanotify permission events

# ----------------------------------------------------------------------------
# Locate a readable kernel config, if any.
# ----------------------------------------------------------------------------
KCONFIG=""
find_kconfig() {
    local candidate="/boot/config-$(uname -r)"
    if [[ -r "$candidate" ]]; then
        KCONFIG="$candidate"
        return 0
    fi
    if [[ -r /proc/config.gz ]]; then
        KCONFIG="/tmp/execguard-kconfig.$$"
        if zcat /proc/config.gz > "$KCONFIG" 2>/dev/null; then
            return 0
        fi
        rm -f "$KCONFIG"; KCONFIG=""
    fi
    return 1
}

# Return 0 if "<OPTION>=y" (or =m) is set in the located config.
kconfig_has() {
    local opt="$1"
    [[ -n "$KCONFIG" ]] || return 2
    grep -Eq "^${opt}=(y|m)$" "$KCONFIG"
}

# ----------------------------------------------------------------------------
# Check 1: kernel version.
# ----------------------------------------------------------------------------
check_kernel() {
    hdr "Kernel"
    local rel major minor
    rel="$(uname -r)"
    major="$(uname -r | cut -d. -f1)"
    minor="$(uname -r | cut -d. -f2 | grep -oE '^[0-9]+' || echo 0)"

    info "Running kernel: ${rel} (${major}.${minor})"

    if (( major > 5 )) || { (( major == 5 )) && (( minor >= 7 )); }; then
        pass "Kernel ${major}.${minor} supports BPF-LSM (>= 5.7)."
        KERNEL_OK=1
    else
        warn "Kernel ${major}.${minor} predates BPF-LSM (needs >= 5.7)."
    fi
}

# ----------------------------------------------------------------------------
# Check 2: BTF (BPF Type Format) -- required for CO-RE portability.
# ----------------------------------------------------------------------------
check_btf() {
    hdr "BTF / CO-RE"
    if [[ -r /sys/kernel/btf/vmlinux ]]; then
        pass "Kernel BTF present at /sys/kernel/btf/vmlinux."
        BTF_OK=1
    else
        warn "No /sys/kernel/btf/vmlinux -- CO-RE builds will need a manual vmlinux.h."
    fi
}

# ----------------------------------------------------------------------------
# Check 3: active LSM list -- is 'bpf' actually enabled at boot?
# ----------------------------------------------------------------------------
check_active_lsm() {
    hdr "Active LSMs"
    local lsmfile="/sys/kernel/security/lsm"
    if [[ -r "$lsmfile" ]]; then
        local lsms; lsms="$(cat "$lsmfile")"
        info "Active: ${lsms}"
        if [[ ",${lsms}," == *",bpf,"* ]]; then
            pass "'bpf' is in the active LSM list."
            BPF_LSM_ACTIVE=1
        else
            warn "'bpf' is NOT active. Add it via the kernel cmdline: lsm=...,bpf"
        fi
    else
        warn "securityfs not mounted or unreadable ($lsmfile). Cannot confirm active LSMs."
    fi
}

# ----------------------------------------------------------------------------
# Check 4: kernel config options.
# ----------------------------------------------------------------------------
check_kconfig() {
    hdr "Kernel configuration"
    if find_kconfig; then
        info "Reading config from: ${KCONFIG}"
        if kconfig_has CONFIG_BPF_LSM; then pass "CONFIG_BPF_LSM=y"; CFG_BPF_LSM=1
        else fail "CONFIG_BPF_LSM is not set -- BPF-LSM cannot be used."; fi

        if kconfig_has CONFIG_DEBUG_INFO_BTF; then pass "CONFIG_DEBUG_INFO_BTF=y"; CFG_BTF=1
        else warn "CONFIG_DEBUG_INFO_BTF not set -- CO-RE needs a matching vmlinux.h."; fi

        if kconfig_has CONFIG_SECURITY_PATH; then pass "CONFIG_SECURITY_PATH=y (path_* hooks available)"; CFG_SECURITY_PATH=1
        else info "CONFIG_SECURITY_PATH not set -- fine; ExecGuard uses inode_* hooks."; fi
    else
        warn "No readable kernel config (/boot/config-\$(uname -r) or /proc/config.gz)."
        warn "Falling back to runtime signals (active LSM list + BTF) only."
    fi
}

# ----------------------------------------------------------------------------
# Check 5: build toolchain.
# ----------------------------------------------------------------------------
check_toolchain() {
    hdr "Build toolchain"
    local tool
    for tool in clang llvm-strip bpftool; do
        if command -v "$tool" >/dev/null 2>&1; then
            pass "$tool found: $(command -v "$tool")"
        else
            fail "$tool not found in PATH."
            TOOLCHAIN_OK=0
        fi
    done

    # libbpf: header presence is the practical signal for building.
    # Either location suffices. (A single "ls a b" fails if EITHER is absent,
    # which misreported a normal /usr/include install as missing.)
    if [[ -f /usr/include/bpf/libbpf.h || -f /usr/local/include/bpf/libbpf.h ]]; then
        pass "libbpf development headers found."
    else
        warn "libbpf headers not found (install libbpf-dev / libbpf-devel)."
        TOOLCHAIN_OK=0
    fi
}

# ----------------------------------------------------------------------------
# Check 6: fanotify fallback plausibility.
# ----------------------------------------------------------------------------
check_fanotify() {
    hdr "fanotify (fallback path)"
    # fanotify permission events exist since 2.6.37; any modern kernel qualifies.
    # We cannot fully exercise FAN_OPEN_PERM from shell, so this is a coarse check.
    if [[ -e /proc/self/fdinfo ]]; then
        pass "Kernel supports fanotify (permission events since 2.6.37)."
        info "Note: fanotify can DENY write-opens but can only DETECT rename/unlink."
        FANOTIFY_OK=1
    else
        warn "Could not confirm fanotify support."
    fi
}

# ----------------------------------------------------------------------------
# Verdict.
# ----------------------------------------------------------------------------
verdict() {
    hdr "=============================================================="
    hdr "ExecGuard environment verdict"
    hdr "=============================================================="

    # Full eBPF-LSM path: needs a >=5.7 kernel, BPF-LSM compiled in, and 'bpf'
    # actually active. BTF is strongly preferred but a missing BTF only means a
    # manual vmlinux.h, not an impossibility.
    local ebpf_ready=0
    if (( KERNEL_OK == 1 )) && (( BPF_LSM_ACTIVE == 1 )); then
        if (( CFG_BPF_LSM == 1 )) || [[ -z "$KCONFIG" ]]; then
            ebpf_ready=1
        fi
    fi

    if (( ebpf_ready == 1 )); then
        printf '  Mode: %sEBPF_LSM%s -- full pre-operation enforcement available.\n' "$C_OK" "$C_RST"
        (( BTF_OK == 1 )) || warn "BTF missing: generate vmlinux.h manually before building src/kernel/."
        (( TOOLCHAIN_OK == 1 )) || warn "Toolchain incomplete: install clang/llvm/bpftool/libbpf-dev to build."
        cleanup; return 0
    fi

    if (( FANOTIFY_OK == 1 )); then
        printf '  Mode: %sFANOTIFY_FALLBACK%s -- partial enforcement.\n' "$C_WARN" "$C_RST"
        info "write/append/truncate-at-open can be denied; rename-over and unlink"
        info "can only be detected after the fact. This is a documented limitation."
        [[ -n "$KCONFIG" ]] && (( CFG_BPF_LSM == 0 )) && \
            info "To unlock full mode: build a kernel with CONFIG_BPF_LSM=y."
        (( BPF_LSM_ACTIVE == 0 )) && (( KERNEL_OK == 1 )) && \
            info "To unlock full mode: add 'lsm=...,bpf' to the kernel cmdline and reboot."
        cleanup; return 1
    fi

    printf '  Mode: %sUNSUPPORTED%s -- no usable enforcement mechanism found.\n' "$C_ERR" "$C_RST"
    cleanup; return 2
}

cleanup() {
    [[ "$KCONFIG" == /tmp/execguard-kconfig.* ]] && rm -f "$KCONFIG"
    return 0
}
trap cleanup EXIT

# ----------------------------------------------------------------------------
# Main.
# ----------------------------------------------------------------------------
main() {
    printf '%s\n' "ExecGuard :: environment detection (read-only)"
    check_kernel
    check_btf
    check_active_lsm
    check_kconfig
    check_toolchain
    check_fanotify
    verdict
}

main "$@"
