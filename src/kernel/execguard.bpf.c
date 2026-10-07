// SPDX-License-Identifier: GPL-2.0
/*
 * execguard.bpf.c - ExecGuard kernel-side enforcement (BPF-LSM / KRSI).
 *
 * These programs attach to Linux Security Module hooks via the BPF-LSM
 * mechanism (kernel >= 5.7, requires CONFIG_BPF_LSM=y and "bpf" in the active
 * LSM list). For an LSM-type ("lsm/<hook>") program the return value is the security decision:
 *   0            -> allow
 *   -EPERM (-1)  -> deny, and the offending syscall returns EPERM to userspace
 *
 * Enforcement therefore happens BEFORE the operation commits - this is real
 * pre-operation prevention, not after-the-fact detection.
 *
 * KERNEL VERSION NOTE
 * -------------------
 * The hook signatures below are correct for Linux 6.x (developed/tested against
 * 6.8, Ubuntu 24.04). One hook is version-sensitive: inode_setattr gained a
 * leading "struct mnt_idmap *idmap" argument in the 6.x series (idmapped
 * mounts). On 5.12-6.2 that argument is "struct user_namespace *mnt_userns";
 * on pre-5.12 kernels it is absent. If you build on an older kernel, adjust the
 * eg_inode_setattr signature accordingly - see docs/limitations.md. The other
 * three hooks (file_open, inode_unlink, inode_rename) have stable signatures.
 *
 * We deliberately use inode_* hooks (always present) rather than path_* hooks
 * (which require CONFIG_SECURITY_PATH), so ExecGuard works on stock kernels.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "execguard/eg_common.h"

char LICENSE[] SEC("license") = "GPL"; /* BPF-LSM helpers are GPL-only */

/* Constants normally living in kernel headers that are not exported as macros
 * through BTF. Values are part of the stable kernel UAPI/ABI. */
#define EG_EPERM        1        /* errno EPERM; we return the negative form */
#define FMODE_WRITE     0x2      /* include/linux/fs.h: file opened writable  */
#define ATTR_SIZE       (1 << 3) /* include/linux/fs.h: iattr changes i_size  */

/* ------------------------------------------------------------------ maps -- */

/* (dev,ino) -> policy value for every protected executable. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct eg_file_key);
	__type(value, struct eg_file_val);
} protected_inodes SEC(".maps");

/* (dev,ino) of trusted updater executables -> presence marker. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct eg_file_key);
	__type(value, __u8);
} trusted_exes SEC(".maps");

/* Single-entry global state (enforce flag + maintenance deadline). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct eg_state);
} state SEC(".maps");

/* Audit events streamed to the daemon. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* --------------------------------------------------------------- helpers -- */

static __always_inline void inode_to_key(struct inode *inode,
					 struct eg_file_key *k)
{
	k->ino = BPF_CORE_READ(inode, i_ino);
	/* s_dev is already the kernel dev_t encoding (major<<20 | minor). */
	k->dev = (__u64)BPF_CORE_READ(inode, i_sb, s_dev);
}

/* Identify the acting process by the inode of its executable image.
 * Kernel threads have no mm/exe_file; those get a zeroed key (never trusted). */
static __always_inline void caller_exe_key(struct eg_file_key *k)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct file *exe = BPF_CORE_READ(task, mm, exe_file);

	k->dev = 0;
	k->ino = 0;
	if (exe) {
		struct inode *ei = BPF_CORE_READ(exe, f_inode);
		if (ei)
			inode_to_key(ei, k);
	}
}

static __always_inline void emit_event(struct eg_file_key *tgt,
				       struct eg_file_key *caller,
				       __u32 op, __u32 decision, __u32 reason,
				       struct dentry *name_dentry)
{
	struct eg_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return; /* ring full: drop the audit record, never the decision */

	__u64 id = bpf_get_current_pid_tgid();
	e->ts_ns      = bpf_ktime_get_ns();
	e->dev        = tgt->dev;
	e->ino        = tgt->ino;
	e->caller_dev = caller->dev;
	e->caller_ino = caller->ino;
	e->pid        = (__u32)id;
	e->tgid       = (__u32)(id >> 32);
	e->uid        = (__u32)bpf_get_current_uid_gid();
	e->op         = op;
	e->decision   = decision;
	e->reason     = reason;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	e->target[0] = '\0';
	if (name_dentry) {
		const unsigned char *nm = BPF_CORE_READ(name_dentry, d_name.name);
		if (nm)
			bpf_probe_read_kernel_str(&e->target,
						  sizeof(e->target), nm);
	}
	bpf_ringbuf_submit(e, 0);
}

/*
 * Core decision. Returns 0 to allow, -EPERM to deny.
 * Emits an audit event for every decision on a protected file.
 */
static __always_inline int decide(struct inode *target, __u32 op,
				  struct dentry *name_dentry)
{
	if (!target)
		return 0;

	struct eg_file_key tkey = {};
	inode_to_key(target, &tkey);

	struct eg_file_val *pv = bpf_map_lookup_elem(&protected_inodes, &tkey);
	if (!pv)
		return 0; /* not a protected file: fast allow, no audit noise */

	struct eg_file_key ckey = {};
	caller_exe_key(&ckey);

	__u32 zero = 0;
	struct eg_state *st = bpf_map_lookup_elem(&state, &zero);
	__u64 now = bpf_ktime_get_ns();

	__u32 decision, reason;

	if (bpf_map_lookup_elem(&trusted_exes, &ckey)) {
		decision = EG_DECISION_ALLOW;
		reason   = EG_REASON_TRUSTED;
	} else if (st && st->maintenance_until_ns &&
		   now < st->maintenance_until_ns) {
		decision = EG_DECISION_ALLOW;
		reason   = EG_REASON_MAINTENANCE;
	} else if (st && st->enforcing == 0) {
		decision = EG_DECISION_AUDIT; /* would deny, but audit-only */
		reason   = EG_REASON_AUDIT_ONLY;
	} else {
		decision = EG_DECISION_DENY;
		reason   = EG_REASON_PROTECTED;
	}

	emit_event(&tkey, &ckey, op, decision, reason, name_dentry);

	return (decision == EG_DECISION_DENY) ? -EG_EPERM : 0;
}

/* ----------------------------------------------------------------- hooks -- */

/*
 * file_open: fires on every open. We only care about write-intent opens.
 * Blocking write-opens covers write(), pwrite(), append (O_APPEND), and
 * truncate-at-open (O_TRUNC), and it also blocks the prerequisite for
 * ftruncate() and writable mmap (both need an already-writable fd).
 */
SEC("lsm/file_open")
int BPF_PROG(eg_file_open, struct file *file, int ret)
{
	if (ret) /* an earlier LSM already decided; respect it */
		return ret;

	unsigned int fmode = BPF_CORE_READ(file, f_mode);
	if (!(fmode & FMODE_WRITE))
		return 0;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
	return decide(inode, EG_OP_OPEN_WRITE, de);
}

/*
 * inode_unlink: fires on unlink()/unlinkat(). Blocks deletion of a protected
 * executable.
 */
SEC("lsm/inode_unlink")
int BPF_PROG(eg_inode_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
	if (ret)
		return ret;

	struct inode *victim = BPF_CORE_READ(dentry, d_inode);
	return decide(victim, EG_OP_UNLINK, dentry);
}

/*
 * inode_rename: fires on rename()/renameat2(). Two protected cases:
 *   - the destination already holds a protected inode  -> rename-over replace
 *   - the source is a protected inode being moved away  -> relocation tamper
 */
SEC("lsm/inode_rename")
int BPF_PROG(eg_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry, int ret)
{
	if (ret)
		return ret;

	struct inode *dst = BPF_CORE_READ(new_dentry, d_inode);
	int r = decide(dst, EG_OP_RENAME, new_dentry);
	if (r)
		return r;

	struct inode *src = BPF_CORE_READ(old_dentry, d_inode);
	return decide(src, EG_OP_RENAME, old_dentry);
}

/*
 * inode_setattr: fires on chmod/chown/truncate. We enforce only on size
 * changes (ATTR_SIZE), which is how truncate()/ftruncate() shrink or grow a
 * file. See the KERNEL VERSION NOTE at the top of this file regarding the
 * leading idmap argument.
 */
SEC("lsm/inode_setattr")
int BPF_PROG(eg_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     struct iattr *attr, int ret)
{
	if (ret)
		return ret;

	unsigned int valid = BPF_CORE_READ(attr, ia_valid);
	if (!(valid & ATTR_SIZE))
		return 0;

	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	return decide(inode, EG_OP_TRUNCATE, dentry);
}
