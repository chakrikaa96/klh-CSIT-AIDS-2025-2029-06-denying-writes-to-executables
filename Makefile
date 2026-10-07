# SPDX-License-Identifier: GPL-2.0
# ExecGuard build system.
#
# Repository layout:
#   src/kernel/      eBPF-LSM enforcement program (compiled for the BPF target)
#   src/include/     ABI header shared by kernel and userspace
#   src/userspace/   multi-call userspace binary (daemon + egctl CLI)
#   src/tools/       eg-updater, the trusted-updater demonstration ELF
#   data/            policies, test-case catalogue, fixtures, schemas
#   results/         captured outputs of builds, tests, and benchmarks
#
# Generated files (vmlinux.h, the BPF skeleton, objects, binaries) are written
# to build/ only, so src/ always contains hand-written source and nothing else.
#
# Targets:
#   make              build everything (BPF object, skeleton, execguard, updater)
#   make bpf          build only the BPF object and skeleton
#   make vmlinux      (re)generate build/vmlinux.h from the running kernel's BTF
#   make check-env    classify this host (BPF-LSM / fanotify fallback / unsupported)
#   make test-unit    userspace tests that need no kernel enforcement
#   make test         full suite (root + running daemon; kernel tests skip if absent)
#   make bench        performance harness (root + running daemon)
#   make results      run the evidence pipeline and write results/<host>-<timestamp>/
#   make install      install binaries, config, and systemd unit (root)
#   make uninstall    remove the installation (root)
#   make clean        remove build artifacts
#
# Requirements: clang >= 12, llvm, bpftool, libbpf-dev (>= 1.0), libelf-dev,
# zlib1g-dev, libssl-dev, gcc, make, and a kernel with BTF at
# /sys/kernel/btf/vmlinux.

CLANG      ?= clang
BPFTOOL    ?= bpftool
CC         ?= gcc
LLVM_STRIP ?= llvm-strip

SRC        := src
BUILD      := build
INCLUDE    := $(SRC)/include
BPF_SRC    := $(SRC)/kernel/execguard.bpf.c
USER_SRC   := $(SRC)/userspace/execguard.c
UPD_SRC    := $(SRC)/tools/eg-updater.c
ABI_H      := $(INCLUDE)/execguard/eg_common.h

BPF_OBJ    := $(BUILD)/execguard.bpf.o
VMLINUX_H  := $(BUILD)/vmlinux.h
SKEL_H     := $(BUILD)/execguard.skel.h

# Map uname -m to the clang BPF target architecture macro.
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips.*/mips/;s/s390x/s390/')

CFLAGS   ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
CPPFLAGS := -I$(INCLUDE) -I$(BUILD)
LDLIBS   := -lbpf -lelf -lz -lcrypto -lpthread

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I$(INCLUDE) -I$(BUILD) -Wall

.PHONY: all bpf vmlinux check-env test-unit test bench results \
        install uninstall clean

all: $(BUILD)/execguard $(BUILD)/eg-updater

# --- vmlinux.h (kernel type definitions for CO-RE) --------------------------
$(VMLINUX_H):
	@mkdir -p $(BUILD)
	@echo "  GEN     $(VMLINUX_H)"
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "ERROR: /sys/kernel/btf/vmlinux missing (need CONFIG_DEBUG_INFO_BTF=y)"; \
		exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

vmlinux:
	@rm -f $(VMLINUX_H)
	@$(MAKE) --no-print-directory $(VMLINUX_H)

# --- BPF object + skeleton --------------------------------------------------
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H) $(ABI_H)
	@mkdir -p $(BUILD)
	@echo "  BPF     $@"
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@
	$(LLVM_STRIP) -g $@

$(SKEL_H): $(BPF_OBJ)
	@echo "  SKEL    $@"
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@

bpf: $(SKEL_H)

# --- Userspace: one source, one binary --------------------------------------
$(BUILD)/execguard: $(USER_SRC) $(SKEL_H) $(ABI_H)
	@mkdir -p $(BUILD)
	@echo "  CC/LINK $@"
	$(CC) $(CFLAGS) $(CPPFLAGS) $(USER_SRC) -o $@ $(LDLIBS)

# --- Trusted-updater helper (separate binary by design) ---------------------
$(BUILD)/eg-updater: $(UPD_SRC)
	@mkdir -p $(BUILD)
	@echo "  CC/LINK $@"
	$(CC) $(CFLAGS) $< -o $@

# --- Verification and evidence ----------------------------------------------
check-env:
	@$(SRC)/scripts/check-env.sh

test-unit: all
	@$(SRC)/tests/unit/test_userspace.sh

test: all
	@$(SRC)/tests/run-all.sh

bench: all
	@$(SRC)/benchmarks/bench.sh

results:
	@$(SRC)/scripts/collect-results.sh

# --- Installation -----------------------------------------------------------
install:
	@$(SRC)/scripts/install.sh

uninstall:
	@$(SRC)/scripts/uninstall.sh

clean:
	rm -rf $(BUILD)
	@echo "cleaned build/"
