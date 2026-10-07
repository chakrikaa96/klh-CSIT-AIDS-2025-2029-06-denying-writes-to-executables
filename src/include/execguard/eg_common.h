/* SPDX-License-Identifier: GPL-2.0 */
/*
 * eg_common.h - ABI shared between the BPF-LSM programs and userspace.
 *
 * This header is included from two very different compilation contexts:
 *
 *   1. The BPF program (src/kernel/execguard.bpf.c), where "vmlinux.h" has already
 *      defined the fixed-width kernel types (__u8, __u32, __u64).
 *   2. Userspace C, which must "#include <linux/types.h>" BEFORE this header
 *      so those same types exist.
 *
 * Keep every struct here composed only of fixed-width integers and char
 * arrays. Do not add pointers or host-width types; the two sides must agree
 * on the exact byte layout because these structs travel through BPF maps and
 * the ring buffer.
 */
#ifndef EXECGUARD_EG_COMMON_H
#define EXECGUARD_EG_COMMON_H

/* Bounds shared by both sides. */
#define EG_COMM_LEN      16   /* matches TASK_COMM_LEN */
#define EG_TARGET_LEN    256  /* best-effort dentry name captured in-kernel */

/*
 * File identity key.
 *
 * We key protection on (device, inode) rather than on a path string. A path is
 * just a directory entry; the file itself is the inode. Keying on the inode is
 * O(1) in the kernel, needs no in-kernel path resolution, and is immune to
 * symlink/hardlink/rename aliasing. See docs/design-decisions.md.
 *
 * IMPORTANT: "dev" here is the kernel's dev_t encoding, i.e.
 * (major << 20) | minor. Userspace must reconstruct this from stat(2)'s
 * st_dev using major()/minor() and re-encode it identically; the glibc st_dev
 * bit layout is NOT the same as the kernel's. See eg_encode_kdev() in src/userspace/execguard.c.
 */
struct eg_file_key {
	__u64 dev;
	__u64 ino;
};

/* Per-protected-file policy flags (room to extend later). */
enum eg_file_flags {
	EG_F_PROTECTED = 1u << 0,
};

struct eg_file_val {
	__u32 flags;
	__u32 _pad;
};

/* Global enforcement state (single-entry ARRAY map, index 0). */
struct eg_state {
	__u64 maintenance_until_ns; /* CLOCK_MONOTONIC ns; 0 = no maintenance */
	__u32 enforcing;            /* 1 = enforce, 0 = global AUDIT_ONLY     */
	__u32 _pad;
};

/* Which operation triggered a decision. */
enum eg_op {
	EG_OP_OPEN_WRITE = 1, /* open() with write intent (covers write/append/O_TRUNC) */
	EG_OP_UNLINK     = 2, /* unlink()/unlinkat() (delete)                           */
	EG_OP_RENAME     = 3, /* rename()/renameat2() (incl. rename-over replacement)   */
	EG_OP_TRUNCATE   = 4, /* truncate()/ftruncate() via inode_setattr ATTR_SIZE     */
};

/* The decision recorded for an event. */
enum eg_decision {
	EG_DECISION_DENY  = 0,
	EG_DECISION_ALLOW = 1,
	EG_DECISION_AUDIT = 2, /* would-deny, but global AUDIT_ONLY is active */
};

/* Why the decision was made (for the audit trail). */
enum eg_reason {
	EG_REASON_NOT_PROTECTED = 0, /* never emitted; allow path returns early */
	EG_REASON_PROTECTED     = 1, /* protected file, untrusted caller -> deny */
	EG_REASON_TRUSTED       = 2, /* caller executable is a trusted updater   */
	EG_REASON_MAINTENANCE   = 3, /* maintenance window active                */
	EG_REASON_AUDIT_ONLY    = 4, /* global audit-only mode                   */
};

/*
 * One security event, produced in-kernel and consumed by the daemon.
 * "target" is a best-effort short name taken from the dentry; the daemon
 * resolves (dev,ino) back to the configured path for the human-readable log.
 * "caller_*" identifies the acting process's executable image by inode.
 */
struct eg_event {
	__u64 ts_ns;       /* CLOCK_MONOTONIC ns at decision time */
	__u64 dev;         /* target file device (kernel encoding) */
	__u64 ino;         /* target file inode                    */
	__u64 caller_dev;  /* acting process exe device            */
	__u64 caller_ino;  /* acting process exe inode             */
	__u32 pid;         /* thread id (kernel pid)               */
	__u32 tgid;        /* process id (kernel tgid)             */
	__u32 uid;         /* real uid of acting task              */
	__u32 op;          /* enum eg_op                           */
	__u32 decision;    /* enum eg_decision                     */
	__u32 reason;      /* enum eg_reason                       */
	char  comm[EG_COMM_LEN];
	char  target[EG_TARGET_LEN];
};

/*
 * Layout pins. This header is compiled by both clang (-target bpf) and the host
 * compiler, so these assertions make either build fail if the two sides could
 * ever disagree on a struct crossing the kernel/user boundary. struct eg_event
 * is only used inside an inlined helper and is therefore not emitted into the
 * BPF object's BTF; this is the check that covers it.
 */
_Static_assert(sizeof(struct eg_file_key) == 16,  "eg_file_key ABI changed");
_Static_assert(sizeof(struct eg_file_val) == 8,   "eg_file_val ABI changed");
_Static_assert(sizeof(struct eg_state)    == 16,  "eg_state ABI changed");
_Static_assert(sizeof(struct eg_event)    == 336, "eg_event ABI changed");
_Static_assert(__builtin_offsetof(struct eg_event, comm)   == 64, "eg_event.comm moved");
_Static_assert(__builtin_offsetof(struct eg_event, target) == 80, "eg_event.target moved");

#endif /* EXECGUARD_EG_COMMON_H */
