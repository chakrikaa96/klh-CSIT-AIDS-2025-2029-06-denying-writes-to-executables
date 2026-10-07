# Threat model

## Assets

- The integrity of protected executables on disk (their contents and their
  continued existence at the expected inode).
- The audit trail of attempts against them.

## What ExecGuard defends against

ExecGuard is designed to stop an adversary who has **code execution on the
running system, up to and including root**, from tampering with protected
executables through the normal filesystem interface, and to record the attempt.

| Adversary capability | Outcome |
|---|---|
| Unprivileged process writes to a protected file | Blocked at `file_open`; logged |
| Privileged (root) process overwrites a protected file | Blocked at `file_open`; logged |
| Attacker truncates a protected file (`truncate`/`ftruncate`) | Blocked at `inode_setattr`/`file_open`; logged |
| Attacker deletes a protected file | Blocked at `inode_unlink`; logged |
| Attacker stages a trojan and renames it over the target | Blocked at `inode_rename`; logged |
| Attacker writes through a hard link to the protected inode | Blocked (inode-keyed); logged |
| Attacker edits via an in-place editor (write temp + rename) | Blocked at `inode_rename`; logged |
| Compromise of a non-trusted service running as root | Cannot modify protected files |

The key property is **pre-operation prevention**: the file is never modified,
because the syscall returns `-EPERM` before the change is committed.

## What ExecGuard does NOT defend against

This is an honest boundary, not a marketing one.

1. **An attacker who unloads the enforcement.** Root can stop the daemon,
   detach the BPF programs (`bpftool prog detach` / removing the links), or kill
   `execguardd`. Because a clean daemon stop detaches the programs, root can
   disable protection. Mitigations require protecting the mechanism itself (see
   below) and are out of scope.
2. **Offline tampering.** An attacker who can boot another OS, mount the disk,
   or edit it from a live environment bypasses a runtime kernel control
   entirely. The SHA-256 baseline is the detective control for this case: on the
   next boot, `egctl integrity scan` reveals the change.
3. **A different kernel.** Booting a kernel without `CONFIG_BPF_LSM`, or with
   `bpf` removed from the LSM list, means the programs never attach.
   Complementary controls: Secure Boot plus a signed kernel and a locked
   bootloader.
4. **Abuse of a legitimately trusted updater.** If an attacker can invoke a
   trusted updater with attacker-controlled input (a confused-deputy attack),
   the updater may modify protected files on their behalf. Keep the trusted set
   minimal and prefer updaters that authenticate their inputs (for example, a
   package manager verifying signatures).
5. **In-memory attacks.** ExecGuard protects files on disk. It does not prevent
   code injection into a running process, `ptrace`-based hijacking, or execution
   of a malicious binary from a writable, unprotected location.
6. **Kernel-level compromise.** An attacker with the ability to load kernel
   modules or exploit the kernel can disable any in-kernel control.

## Raising the bar further

For deployments that need to defend the mechanism against root, combine
ExecGuard with:

- **IMA/EVM** with a signed policy and appraisal, so modified binaries fail to
  execute even if written.
- **Secure Boot** and **kernel lockdown** (`lockdown=confidentiality`) to
  constrain root's ability to alter the kernel and its LSM configuration.
- **Immutable infrastructure**: read-only root filesystems, `dm-verity` for the
  base image.

ExecGuard is a strong, auditable, runtime layer within that stack, not a
replacement for it.
