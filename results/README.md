# results/

Captured evidence. Each folder is one run of `make results`
(`src/scripts/collect-results.sh`) and contains only the raw output of commands
executed on that host at that time, plus a `summary.md` generated from it.
Nothing in this directory is written by hand or estimated.

## Runs

| Run | Host | Mode | Build | Unit | Functional | Security | Bypass | Benchmark |
|---|---|---|---|---|---|---|---|---|
| [`cloud-build-container-20261007T030825Z`](cloud-build-container-20261007T030825Z/summary.md) | Docker container, Ubuntu 24.04.5, kernel 6.18 | FANOTIFY_FALLBACK (see note) | OK, 0 warnings | **63/63 PASS** | SKIP | SKIP | SKIP | not run |
| *pending: `vm-<timestamp>`* | Multipass VM, Ubuntu 24.04, BPF-LSM enabled | EBPF_LSM expected | | | 6 cases | 13 cases | 10 cases | |

### Reading the build-container run

This run establishes that the project builds from clean with zero warnings and
that all userspace logic and the compiled BPF object are correct. It does
**not** exercise in-kernel enforcement, and says so:

- `check-env.log` reports `FANOTIFY_FALLBACK` because the container has no
  securityfs, so the active LSM list cannot be read, even though the kernel
  config reports `CONFIG_BPF_LSM=y`.
- `daemon.log` shows `BPF program load failed: Operation not permitted` for
  `eg_file_open`. The container runtime filters `bpf(BPF_PROG_LOAD)` for LSM
  programs even for root. This is an environment restriction, not a defect in
  the program; it is the reason kernel testing uses a full VM.
- The three kernel suites therefore exit 77 and are recorded as `SKIP`, not as
  passes.

## Producing the enforcement run

On the test VM, after following [docs/build-and-run.md](../docs/build-and-run.md)
sections 1 to 4 (`make check-env` must report `EBPF_LSM`):

```sh
cd ~/execguard
sudo RESULTS_LABEL=vm make results
```

The run starts a temporary daemon from `build/` if none is installed, executes
all four suites and the benchmark, captures every audit event the kernel
emitted to `audit.jsonl`, and stops the daemon. Copy the new folder back to the
repository (`multipass transfer -r execguard-test:/home/ubuntu/execguard/results/vm-<timestamp> results/`)
and add a row to the table above.

## Files in a run folder

| File | Contents |
|---|---|
| `summary.md` | One-table overview of the run |
| `system.txt` | OS, kernel, CPU, memory, virtualization, active LSMs, toolchain versions |
| `check-env.log` | Full output of the environment classifier |
| `build.log` | `make clean && make vmlinux && make` output |
| `build-artifacts.txt` | Sizes and SHA-256 of the built binaries and BPF object |
| `bpf-sections.txt` | ELF sections of the BPF object (one per LSM hook, maps, license, BTF) |
| `daemon.log` | Output of the temporary daemon (load/attach result, policy applied) |
| `tests/<suite>.log` | Full output of each suite |
| `tests/summary.log` | Per-suite verdicts from `src/tests/run-all.sh` |
| `audit.jsonl` | Kernel audit events emitted during the run (enforcement hosts only) |
| `benchmark.log` | Allow-path, deny-path and integrity-scan measurements (enforcement hosts only) |
| `egctl-status.txt` | Daemon counters after the run (enforcement hosts only) |
