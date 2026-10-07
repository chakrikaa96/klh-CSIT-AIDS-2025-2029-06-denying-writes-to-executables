# Build and run

This guide takes a fresh machine to a running, verified ExecGuard installation.
Development and evaluation use an Ubuntu 24.04 virtual machine; ExecGuard
modifies kernel security state and should not be evaluated on a workstation you
depend on.

## 1. Prepare a test VM (macOS host, Multipass)

```sh
# On the Mac
brew install --cask multipass
multipass launch 24.04 --name execguard-test --cpus 2 --memory 4G --disk 15G
multipass transfer -r ./execguard execguard-test:/home/ubuntu/   # or: multipass mount
multipass shell execguard-test
```

Any Ubuntu 24.04 machine (UTM, VirtualBox, a cloud instance) works the same way
from step 2 onward. Containers (Docker, LXC) do **not** work: the container
runtime denies `bpf(BPF_PROG_LOAD)` for LSM programs even to root.

## 2. Enable BPF-LSM

Ubuntu 24.04 kernels are built with `CONFIG_BPF_LSM=y`, but `bpf` is not in the
default list of active LSMs. Check:

```sh
cat /sys/kernel/security/lsm
```

If `bpf` is absent, append it to the current list on the kernel command line
and reboot:

```sh
LSMS="$(cat /sys/kernel/security/lsm),bpf"
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"\$GRUB_CMDLINE_LINUX_DEFAULT lsm=${LSMS}\"" \
  | sudo tee /etc/default/grub.d/99-execguard-bpf-lsm.cfg
sudo update-grub
sudo reboot
```

After reconnecting, `cat /sys/kernel/security/lsm` must end in `bpf`.
Appending to the existing list preserves AppArmor, Yama, Landlock, and the
other LSMs already in use.

## 3. Install the toolchain

```sh
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
    libssl-dev linux-tools-common linux-tools-generic make gcc bc python3
```

## 4. Classify the host

```sh
cd ~/execguard
make check-env        # exit 0 = EBPF_LSM, 1 = FANOTIFY_FALLBACK, 2 = UNSUPPORTED
```

Proceed only when the verdict is `EBPF_LSM`.

## 5. Build

```sh
make                  # generates build/vmlinux.h, the BPF object, the skeleton,
                      # build/execguard (daemon + egctl) and build/eg-updater
make test-unit        # 63 checks; no root needed
```

All generated files go to `build/`; `src/` holds only hand-written source.
If `bpftool` reports a kernel-version mismatch, call the versioned binary
directly: `make BPFTOOL=/usr/lib/linux-tools-*/bpftool`.

## 6. Install and start

```sh
sudo make install                       # binaries, config, systemd unit
egctl policy validate
sudo systemctl enable --now execguard
egctl status
```

The default policy protects only the demo sandbox. For system-wide protection
use the staged rollout in `data/policies/`:

```sh
sudo install -m 0640 data/policies/audit-rollout.conf /etc/execguard/execguard.conf
sudo egctl reload
# ... use the system normally, then review what WOULD have been blocked:
egctl logs -n 200 | grep '"decision":"AUDIT"'
# when only expected writers remain:
sudo install -m 0640 data/policies/system-enforce.conf /etc/execguard/execguard.conf
sudo egctl reload
```

See `docs/limitations.md` section 9 before protecting package-managed binaries.

## 7. Demonstrate and collect evidence

```sh
sudo ./src/scripts/demo.sh              # scripted attack demonstration
sudo ./src/scripts/web-demo.sh          # same, rendered live in a browser
sudo RESULTS_LABEL=vm make results      # full evidence run -> results/vm-<timestamp>/
```

`make results` works with or without an installed daemon: if none is running it
starts a temporary one from `build/`, runs every suite and the benchmark
against it, and stops it afterwards.

## 8. Remove

```sh
sudo make uninstall                     # keeps /etc, /var/lib, /var/log state
sudo ./src/scripts/uninstall.sh --purge # removes that state too
```
