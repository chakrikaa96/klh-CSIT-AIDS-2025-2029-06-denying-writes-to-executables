# Mapping to operating-systems concepts

This project is a concrete instance of several core operating-systems topics.
The table maps each ExecGuard component to the concept it embodies, followed by
short explanations.

| ExecGuard component | Operating-systems concept |
|---|---|
| BPF-LSM enforcement core (`src/kernel/execguard.bpf.c`) | Reference monitor / complete mediation |
| LSM hooks on `open`/`unlink`/`rename`/`setattr` | System-call interposition; the user/kernel boundary |
| `(device, inode)` protection keys | The inode abstraction; file identity vs. directory entries |
| `protected_inodes` / `trusted_exes` maps | Access-control policy as a subject/object matrix |
| Trusted-updater grant by executable inode | Principals and the confused-deputy problem |
| Daemon capabilities (`CAP_BPF`, `CAP_SYS_ADMIN`) | Privilege separation and least privilege |
| Maintenance window as a monotonic deadline | Time-bounded capabilities; monotonic vs. wall-clock time |
| Ring buffer -> audit log | Kernel-to-user event streaming; auditing |
| SHA-256 baseline | Cryptographic integrity verification |
| `-EPERM` return propagating to the syscall | Error handling across the protection boundary |

## Reference monitor and complete mediation

The classic reference-monitor model requires that every access to a protected
object be mediated. ExecGuard realizes this with LSM hooks, which the kernel
invokes on the relevant filesystem operations regardless of the requesting
process. The decision function is the monitor; the maps are its policy database.

## System-call interposition and the kernel boundary

A user process cannot modify a file without asking the kernel via a syscall.
LSM hooks are interposition points inside that syscall path, after argument
resolution but before the operation commits. This is the textbook location for
enforcing a security policy: at the boundary the untrusted subject cannot avoid.

## The inode abstraction

A path is a directory entry that points at an inode; the inode is the file. By
keying on `(device, inode)`, ExecGuard protects the object itself rather than one
of its names. This is a direct application of the Unix inode abstraction and
explains why hard links and renames cannot bypass protection.

## Access control as a matrix

The maps encode a small access-control matrix: subjects are executables
(identified by inode), objects are protected files (identified by inode), and the
allowed operations are "modify" for trusted subjects and "none" for the rest.
Enforcement is a membership test in that matrix.

## Principals and the confused deputy

Trusting an updater is granting a principal authority over protected objects.
Identifying that principal by executable inode - and refusing to identify it by a
spoofable process name or by a script whose real identity is its interpreter -
is a direct engagement with how principals are named and how a trusted deputy can
be confused into misusing its authority.

## Privilege separation and least privilege

The daemon holds exactly the capabilities needed to load BPF and manage maps,
and no more; it never needs write access to the files it protects. The trusted
grant is scoped to one executable, not a user or a directory. Both are
applications of least privilege.

## Monotonic time and time-bounded authority

Maintenance mode is a capability that expires. It is expressed against the
monotonic clock so it is immune to administrators changing the wall clock, and it
is evaluated in the kernel at decision time. This is the operating-systems
distinction between monotonic and real-time clocks put to a security use.

## Auditing via kernel-to-user streaming

The BPF ring buffer is the mechanism by which the kernel streams structured
events to a userspace consumer with low overhead and no polling of shared
memory. ExecGuard uses it to produce a tamper-evident-friendly, append-only
audit log - the accounting half of a protection system.
