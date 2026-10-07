# Architecture

## Components and data flow

ExecGuard is split cleanly between a kernel enforcement plane and a userspace
control plane. The kernel plane makes every decision; userspace only configures
it and records what happened.

### Kernel plane (`src/kernel/execguard.bpf.c`)

Four BPF programs attach to inode-level LSM hooks:

- `lsm/file_open` denies write-intent opens (`FMODE_WRITE`) of protected files.
  This single hook covers `write`, `pwrite`, append, truncate-at-open
  (`O_TRUNC`), and the writable file descriptor that `ftruncate` and writable
  `mmap` require.
- `lsm/inode_unlink` denies deletion.
- `lsm/inode_rename` denies replacing a protected file via rename-over and
  denies relocating a protected file away from its path.
- `lsm/inode_setattr` denies size changes (`ATTR_SIZE`), catching `truncate`
  and `ftruncate` that do not pass through a fresh write-open.

The programs share four maps:

- `protected_inodes`: hash map keyed by `struct eg_file_key { u64 dev; u64 ino; }`,
  value is a flags word. Presence means "protected."
- `trusted_exes`: hash map keyed by the same inode key, holding the inodes of
  trusted updater executables.
- `state`: a single-entry array holding the global enforce flag and the
  maintenance-window deadline.
- `events`: a ring buffer carrying one `struct eg_event` per decision to
  userspace.

### Userspace plane

- `execguardd` (daemon section of `src/userspace/execguard.c`) loads and attaches the BPF programs via the
  generated CO-RE skeleton, translates the policy file into map entries, drains
  the ring buffer into a JSON-lines audit log, and serves a root-owned Unix
  control socket.
- `egctl` (CLI section of `src/userspace/execguard.c`) is the operator interface. Control operations go
  to the daemon over the socket; integrity and policy-validation operations run
  locally against files.
- `eg-updater` (`src/tools/eg-updater.c`) is a minimal trusted-updater ELF used by
  the demo and tests.
- The dashboard (`src/dashboard/`) is an optional read-only viewer.

## Why (device, inode) keys

The kernel receives no paths. The daemon resolves each configured path to its
`(device, inode)` identity with `stat(2)` and installs that key. Three
consequences follow:

1. **Correctness under aliasing.** A hard link is a second name for the same
   inode; a symlink resolves to it; a rename changes the name but not the inode.
   Because protection is keyed on the inode, all of these still resolve to the
   same protected object. A path-string approach would have to enumerate and
   re-check every alias.
2. **Speed.** In-kernel enforcement is one hash-map lookup. There is no path
   walking or string comparison on the hot syscall path.
3. **A deliberate limitation.** The identity is bound at policy-load time. If a
   protected path is deleted and a *new* file is later created at the same path,
   that new file has a different inode and is not automatically protected until
   the policy is reloaded. This trade-off, and the TOCTOU window it implies, are
   discussed in [limitations.md](limitations.md).

## Device number encoding

The kernel's `inode->i_sb->s_dev` uses the `dev_t` encoding
`(major << 20) | minor`. glibc's `stat(2)` returns `st_dev` in a different,
wider layout. Userspace must decompose `st_dev` with `major()`/`minor()` and
re-encode to the kernel form before building a map key, or every lookup silently
misses. This conversion lives in one audited function, `eg_encode_kdev()` in
`src/userspace/execguard.c`.

## Maintenance window

Maintenance mode is a deadline, not a flag that must be turned off. The daemon
stores `maintenance_until_ns` as a `CLOCK_MONOTONIC` timestamp; the kernel
compares it against `bpf_ktime_get_ns()` (also monotonic) on each decision.
When the deadline passes, enforcement resumes automatically with no further
action. This makes it impossible to leave the system unprotected by forgetting
to disable maintenance, and it is immune to wall-clock changes.

## Failure behavior

If `execguardd` crashes, the already-attached BPF programs keep enforcing with
the last-synced maps; only new audit events stop being recorded. systemd
restarts the daemon, which re-syncs. If the daemon is stopped cleanly it detaches
the programs (via skeleton destroy), which removes protection - a deliberate
choice so that `systemctl stop execguard` fully disables the tool. Persisting
enforcement across daemon exit would require pinning the BPF links, which is
noted as possible future work.
