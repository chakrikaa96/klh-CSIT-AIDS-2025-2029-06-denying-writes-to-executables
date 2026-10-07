# Limitations and honest caveats

This document states what ExecGuard does not do, and where its guarantees end.
It is deliberately explicit; a security tool that overstates itself is worse
than one that is honest about its edges.

## 1. It does not defend against an attacker who can unload it

Root can stop the daemon or detach the BPF programs, which disables enforcement.
ExecGuard raises the cost and guarantees an audit trail up to that point, but it
is not self-protecting against root. Defending the mechanism requires IMA/EVM,
Secure Boot, and kernel lockdown (see [threat-model.md](threat-model.md)).

## 2. Inode identity is bound at load time (TOCTOU on new files)

Protection is keyed on `(device, inode)` resolved when the policy is loaded or
when `egctl protect` runs. Implications:

- If a protected file is deleted (which ExecGuard blocks) the mapping remains,
  but if protection is removed or the daemon is not running, a *new* file created
  at the same path gets a new inode and is not protected until reload.
- There is a race window between a file being created and the policy being
  reloaded to cover it. For a fixed set of system executables this is a
  non-issue; for paths that are frequently recreated it matters. A future
  enhancement could watch directories with fanotify and auto-protect new files
  matching a pattern.

## 3. Kernel version and configuration dependence

- Requires `CONFIG_BPF_LSM=y`, BTF, and `bpf` in the active LSM list. Without
  these the programs do not attach. `src/scripts/check-env.sh` diagnoses this.
- The `inode_setattr` LSM hook signature is version-sensitive. The code targets
  Linux 6.x, where the hook takes a leading `struct mnt_idmap *idmap` argument.
  On 5.12-6.2 that argument is `struct user_namespace *mnt_userns`; before 5.12
  it is absent. If you build on an older kernel, adjust the `eg_inode_setattr`
  signature in `src/kernel/execguard.bpf.c` accordingly. The other three hooks
  (`file_open`, `inode_unlink`, `inode_rename`) have stable signatures.

## 4. The fanotify fallback is strictly weaker

On kernels without BPF-LSM, a fanotify-based approach can block write-opens
(`FAN_OPEN_PERM`) but **cannot** block `rename` or `unlink` - those are
notification-only in fanotify. A fallback built on fanotify could therefore
prevent in-place overwrites but only *detect* deletion and rename-over
replacement after the fact. Because that is a materially weaker guarantee,
ExecGuard's primary implementation requires BPF-LSM, and `check-env.sh` reports
the fallback as a distinct, reduced-capability tier rather than an equivalent.

## 5. Confused-deputy risk in the trusted set

A trusted updater is fully trusted for all protected files while it runs. If an
attacker can make a trusted updater act on their behalf with attacker-chosen
inputs, they inherit that trust. Keep the trusted set as small as possible and
prefer updaters that validate their inputs (for example, signature-verifying
package managers).

## 6. Trust is per-executable-inode and breaks on updater upgrade

Because a trusted updater is identified by inode, upgrading that updater (which
replaces it with a new inode) invalidates the trust until the policy is
reloaded. This is a safety feature (a swapped-in binary is not automatically
trusted) but requires an operational step after updating a trusted tool.

## 7. Scope is on-disk executables via the filesystem interface

ExecGuard does not address in-memory attacks (code injection, `ptrace`
hijacking), execution of malware from writable locations, or kernel-level
compromise. It protects the integrity of specific files on disk, accessed
through the VFS.

## 8. What cannot be validated without a BPF-LSM host

The BPF object itself compiles on any machine with clang and a kernel that
exposes BTF; `make` generates `build/vmlinux.h` and the CO-RE skeleton from the
build host. Loading and attaching the LSM programs, however, requires a booted
kernel with `CONFIG_BPF_LSM=y`, `bpf` in the active LSM list, and
`CAP_BPF`/`CAP_SYS_ADMIN` that a container runtime has not filtered out.

The test suite is split along exactly this line:

- `src/tests/unit/` validates the userspace logic (policy parsing, glob
  expansion, device encoding, SHA-256 integrity, CLI exit codes, the audit-log
  reader) and the compiled BPF object (LSM sections, license, maps, ABI layout).
  It runs anywhere the project builds, without root.
- `src/tests/{functional,security,bypass}` validate in-kernel enforcement and
  must run as root on a BPF-LSM host with the daemon active. They exit 77
  (skipped) elsewhere.

`make results` records which tiers ran on a given host; see `results/README.md`.

## 9. Package-manager upgrades re-key the protected file

Trusted updaters such as `dpkg` do not rewrite a binary in place. They write the
new version to a temporary file and `rename(2)` it over the old path. ExecGuard
correctly allows this for a trusted caller, but the result is a **new inode** at
the protected path. The old `(dev, ino)` entry now refers to an unlinked file,
and the new binary is not in `protected_inodes` until the policy is re-applied.

Consequences and mitigation:

- Immediately after an upgrade, the upgraded executables are unprotected until
  `egctl reload` runs (or the daemon restarts).
- Stale entries for replaced inodes remain in the map until the daemon restarts.
  They are harmless (an unlinked inode cannot be opened by path) but consume map
  capacity.
- Operationally, re-apply the policy after every package transaction, for
  example with an APT hook:

  ```
  # /etc/apt/apt.conf.d/99execguard
  DPkg::Post-Invoke { "/usr/local/bin/egctl reload || true"; };
  ```

- `egctl reload` is additive. It protects every file the policy currently
  matches, but does not unprotect files that were removed from the policy file;
  use `egctl unprotect <path>` or restart the daemon for that.
- A future enhancement would have the daemon observe `ALLOW`/`RENAME` events with
  reason `trusted updater` and re-resolve the affected path automatically.
