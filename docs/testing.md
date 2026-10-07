# Testing

ExecGuard's correctness claim has two halves, and the test suite is split the
same way:

1. **The userspace logic and build artifacts are correct**: policies parse and
   expand as specified, paths resolve to the same `(dev, ino)` key the kernel
   computes, hashes are correct, the CLI behaves predictably, and the compiled
   BPF object has the programs, maps and ABI the userspace expects.
2. **The kernel enforces the policy**: every mutation vector against a protected
   inode is denied unless an explicit exception applies, and nothing else is
   affected.

Half 1 runs anywhere the project builds. Half 2 needs a BPF-LSM host.

## Suites

| Suite | Script | Needs | Checks | What it proves |
|---|---|---|---|---|
| unit | `src/tests/unit/test_userspace.sh` (+ `test_core.c`) | build only | 63 (incl. 71 core assertions) | Userspace correctness, BPF object structure, ABI agreement |
| functional | `src/tests/functional/test_basic.sh` | root, daemon | 6 | Protect/unprotect lifecycle; reads and execution unaffected |
| security | `src/tests/security/test_matrix.sh` | root, daemon | 13 | Full decision table: untrusted, unprotected, trusted, maintenance, audit-only |
| bypass | `src/tests/bypass/test_bypass.sh` | root, daemon | 10 | Adversarial techniques, including the hardlink alias |

Every kernel-level case is catalogued in `data/test-cases/attack-matrix.csv`
with its command, the syscalls it issues, the LSM hook that mediates it, the
expected decision, and the audit reason that must appear in the log.

```sh
make test-unit          # half 1
sudo make test          # all suites; kernel suites exit 77 (SKIP) without BPF-LSM
sudo make results       # all suites + benchmark, captured to results/
```

## Unit suite coverage

| Area | Representative checks |
|---|---|
| ABI layout | `sizeof`/`offsetof` of `eg_file_key`, `eg_file_val`, `eg_state`, `eg_event` on the host; the same sizes read back from the BPF object's BTF; `_Static_assert` pins in `eg_common.h` fail either compiler on drift |
| Device encoding | `eg_encode_kdev` against hand-computed `(major << 20) \| minor` values, including a minor wider than 8 bits; proof that glibc's encoding differs (so the helper is necessary) |
| SHA-256 | FIPS 180-2 vectors: empty, `abc`, 448-bit, and one million `a` (crosses the 64 KiB read buffer) |
| Executable detection | execute bit, shebang without execute bit, ELF magic without execute bit, plain text, directory, missing path |
| Policy | three shipped policies load with the expected mode and counts; four malformed policies are rejected with `file:line`; secure default is `enforce`; whitespace, comments, case sensitivity |
| Glob expansion | fixture tree expands to exactly the three executables; non-executables and missing literals are excluded |
| Integrity | baseline, clean scan, single-file verify, tamper detection (`CHANGED`), deletion detection (`MISSING`), path not in baseline (`UNKNOWN`), baseline lines validate against `data/schemas/baseline-entry.schema.json` |
| CLI contract | exit codes 0/1/2 for success, failure and usage errors; daemon-unreachable message; maintenance duration parsing; `logs -n` tail |
| Daemon mirror | `RELOAD` is idempotent and does not inflate the protected-file count |
| BPF object | `lsm/file_open`, `lsm/inode_unlink`, `lsm/inode_rename`, `lsm/inode_setattr` sections; GPL license; the four maps; BTF present for CO-RE |

## Exit-code conventions

| Code | Meaning |
|---|---|
| 0 | all checks passed |
| 1 | one or more checks failed |
| 77 | suite skipped: prerequisite (daemon / BPF-LSM) not available on this host |

`src/tests/run-all.sh` reports `SKIP` for 77 rather than `FAIL`, so a run on a
build machine is distinguishable from a run where enforcement is broken.

## Writing a new kernel test

1. Add a row to `data/test-cases/attack-matrix.csv` first: what is attempted,
   which hook should see it, what decision and reason are expected.
2. Add the case to the matching suite using `ok "<desc>" <blocked|allowed>
   "$(run_expect <command>)"` from `src/tests/lib.sh`.
3. Run `sudo make results` on the VM and confirm the new audit event appears in
   `results/<run>/audit.jsonl` with the expected `op`, `decision` and `reason`.
