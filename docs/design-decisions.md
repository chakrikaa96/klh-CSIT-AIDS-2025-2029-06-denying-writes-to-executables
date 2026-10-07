# Design decisions

Each decision below records the alternatives considered and why the chosen
approach won. These are the load-bearing choices of the project.

## D1. Enforcement mechanism: BPF-LSM

**Alternatives considered**

| Option | Pre-op block on write? | On delete/rename? | Portable (no kernel rebuild)? | Verdict |
|---|---|---|---|---|
| Out-of-tree LSM kernel module | Yes | Yes | No - `security_hook_heads` is not exported to modules; in-tree needs a kernel patch/rebuild | Rejected |
| fanotify (userspace) | Yes (`FAN_OPEN_PERM`) | No - notification only | Yes | Fallback only |
| **BPF-LSM (KRSI)** | Yes | Yes | Yes (kernel >= 5.7 with `CONFIG_BPF_LSM`) | **Chosen** |

BPF-LSM is the only option that delivers real pre-operation prevention on *all*
required vectors (write, truncate, delete, rename) without patching or rebuilding
the kernel. fanotify cannot block deletion or rename, so it is documented as a
strictly weaker fallback rather than an equivalent. See
[limitations.md](limitations.md).

## D2. File identity: (device, inode), not path

Protection is keyed on the inode, resolved from the path in userspace at load
time. This makes in-kernel enforcement an O(1) map lookup with no path walking,
and it is inherently correct under symlink, hardlink, and rename aliasing - a
second name for the same inode is still the same protected object. The cost is
that identity is bound at load time (a new file at a reused path needs a reload),
which is an acceptable trade-off for the target use case of protecting a stable
set of executables. See [architecture.md](architecture.md) and the TOCTOU
discussion in [limitations.md](limitations.md).

## D3. Hooks: `inode_*`, not `path_*`

The `path_*` LSM hooks (`path_unlink`, `path_rename`, `path_truncate`) exist but
require `CONFIG_SECURITY_PATH`, which is not universally enabled. The `inode_*`
hooks are always present. Choosing `inode_*` maximizes portability across stock
kernels at no loss of coverage for our needs.

## D4. Write coverage anchored on `file_open`

Rather than hooking every write-like operation, ExecGuard denies the *write-
intent open* itself (`FMODE_WRITE` in `file_open`). A process that cannot obtain
a writable file descriptor cannot `write`, `pwrite`, append, `ftruncate`, or
create a writable `mmap`. This collapses many attack vectors into one stable,
version-independent hook. `inode_setattr` (for `ATTR_SIZE`) is added to catch
`truncate` by path, which does not open the file for writing.

## D5. Trusted updater identified by executable inode

**Alternatives**: trust by process name (spoofable), by path of the invoked
script (wrong - the running executable is the interpreter), or by user (too
broad).

The acting task's executable image inode (`task->mm->exe_file`) is a stable,
kernel-visible identity that cannot be spoofed by renaming a process. The
important corollary is that trusting a *script* would trust its interpreter for
every process, so the bundled `eg-updater` is a compiled ELF with its own inode.
This is the single narrowest identity the kernel can cheaply check on the acting
process.

## D6. Maintenance mode as a self-expiring deadline

**Alternative**: a boolean "maintenance on/off" flag.

A boolean can be left on, silently disabling protection indefinitely. Instead,
maintenance is a `CLOCK_MONOTONIC` deadline compared in-kernel against
`bpf_ktime_get_ns()`. It cannot get stuck enabled, requires no timer or cleanup
thread, and is immune to wall-clock changes. This turns a common operational
footgun into a safe default.

## D7. Userspace language: C with libbpf CO-RE

**Alternative**: Rust with libbpf-rs, or a BCC/Python loader.

C with libbpf and a generated CO-RE skeleton gives a single toolchain, the
smallest runtime dependency footprint, and a "compile once, run everywhere"
binary that adapts to the target kernel via BTF. BCC would require a compiler on
every target; Rust is a reasonable alternative but adds toolchain weight for no
functional gain here. The skeleton is generated at build time so the daemon
embeds the exact BPF object it loads.

## D8. Text control protocol over a root-only Unix socket

**Alternative**: a binary IPC or a D-Bus interface.

A line-based text protocol over a `0600` Unix socket is trivially debuggable
(drivable with `socat`), keeps the trust boundary obvious (only root can open
the socket), and adds no dependencies. The performance of control operations is
irrelevant; clarity and auditability win.

## D9. Integrity as a secondary, detective layer

SHA-256 baselining does not gate operations; prevention is the BPF-LSM layer's
job. Baselining exists to confirm files are unchanged and to catch tampering
that happened while ExecGuard was not loaded (offline edits). Keeping the two
layers distinct avoids conflating "prevented" with "detected," which is a common
source of overclaiming in integrity tools.
