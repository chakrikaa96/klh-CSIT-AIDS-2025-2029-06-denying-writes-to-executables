#!/usr/bin/env bash
# Generate build/vmlinux.h from the running kernel's BTF.
# CO-RE (Compile Once, Run Everywhere) needs kernel type definitions; rather
# than vendoring a huge header, we generate one matching THIS kernel.
set -euo pipefail

cd "$(dirname "$0")/../.."
mkdir -p build

if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    echo "ERROR: /sys/kernel/btf/vmlinux not found." >&2
    echo "Your kernel lacks BTF (need CONFIG_DEBUG_INFO_BTF=y)." >&2
    echo "Run src/scripts/check-env.sh for a full diagnosis." >&2
    exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
    echo "ERROR: bpftool not found (install linux-tools / bpftool)." >&2
    exit 1
fi

bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/vmlinux.h
echo "Generated build/vmlinux.h ($(wc -l < build/vmlinux.h) lines) for kernel $(uname -r)."
