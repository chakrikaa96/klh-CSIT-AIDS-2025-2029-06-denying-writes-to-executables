// SPDX-License-Identifier: GPL-2.0
/*
 * execguard.c - Consolidated ExecGuard userspace program.
 *
 * This single source file contains the entire userspace side of ExecGuard:
 *   - utility helpers (device encoding, inode resolution, SHA-256, JSON)
 *   - the policy-file parser and glob expansion
 *   - the SHA-256 integrity baseline subsystem
 *   - the enforcement daemon (loads BPF, syncs maps, serves the control socket)
 *   - the egctl command-line client
 *
 * It builds into ONE binary that behaves as the daemon or the CLI depending on
 * how it is invoked (a "multi-call" binary, like busybox):
 *   - invoked as "execguardd"        -> runs the daemon
 *   - invoked as "execguard daemon"  -> runs the daemon
 *   - anything else (e.g. "egctl …") -> runs the CLI
 * src/scripts/install.sh creates execguardd and egctl as symlinks to this binary.
 *
 * The kernel enforcement program (src/kernel/execguard.bpf.c) is necessarily a
 * separate file: it is compiled for the BPF target, not the host CPU. The
 * shared ABI header (src/include/execguard/eg_common.h) is also separate because
 * the kernel program includes it too.
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <libgen.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/un.h>

#include <linux/types.h>
#include <openssl/evp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "execguard/eg_common.h"
#include "execguard.skel.h" /* generated into build/ by bpftool gen skeleton */

/* ---- shared definitions ------------------------------------------------ */
#define EG_CONTROL_SOCKET   "/run/execguard/control.sock"
#define EG_MAX_LINE         512
#define EG_MAX_PATH         4096
#define EG_BASELINE_DEFAULT "/var/lib/execguard/baseline.jsonl"

struct eg_str_list {
	char   **items;
	size_t   count;
	size_t   cap;
};

struct eg_policy {
	struct eg_str_list protect_patterns;
	struct eg_str_list trust_paths;
	struct eg_str_list deny_users;
	bool               enforce;
	char               path[EG_MAX_PATH];
};

/* ---- forward declarations ---------------------------------------------- */
__u64 eg_encode_kdev(__u64 st_dev);
int  eg_path_to_key(const char *path, struct eg_file_key *out);
int  eg_sha256_file(const char *path, char hex_out[65]);
bool eg_is_executable(const char *path);
void eg_json_escape(const char *in, char *out, size_t out_sz);
const char *eg_op_name(__u32 op);
const char *eg_decision_name(__u32 decision);
const char *eg_reason_name(__u32 reason);

int  eg_policy_load(const char *path, struct eg_policy *pol);
int  eg_policy_validate(const char *path);
int  eg_policy_expand_protected(const struct eg_policy *pol, struct eg_str_list *out_files);
void eg_policy_free(struct eg_policy *pol);
int  eg_str_list_add(struct eg_str_list *l, const char *s);
void eg_str_list_free(struct eg_str_list *l);

int eg_integrity_baseline(const char *baseline_path, const struct eg_str_list *files);
int eg_integrity_verify(const char *baseline_path, int *ok, int *changed, int *missing);
int eg_integrity_verify_one(const char *baseline_path, const char *file);


/* ============================ utilities ================================= */
/*
 * Userspace helpers: device encoding, inode resolution, SHA-256,
 * executable detection, and JSON escaping.
 */

/*
 * The kernel encodes dev_t as (major << 20) | minor (MINORBITS == 20), which
 * is exactly what BPF reads from inode->i_sb->s_dev. glibc's st_dev uses a
 * wider, different bit layout, so we must decompose with major()/minor() and
 * re-encode to match the kernel. Getting this wrong silently breaks every map
 * lookup, so it lives in one audited place.
 */
__u64 eg_encode_kdev(__u64 st_dev)
{
	unsigned int maj = major((dev_t)st_dev);
	unsigned int min = minor((dev_t)st_dev);
	/* Kernel MKDEV: MINORBITS == 20, i.e. (major << 20) | minor. */
	return ((__u64)maj << 20) | (__u64)min;
}

int eg_path_to_key(const char *path, struct eg_file_key *out)
{
	struct stat st;

	if (!path || !out)
		return -EINVAL;
	if (stat(path, &st) != 0)
		return -errno;

	out->dev = eg_encode_kdev((__u64)st.st_dev);
	out->ino = (__u64)st.st_ino;
	return 0;
}

int eg_sha256_file(const char *path, char hex_out[65])
{
	int rc = 0;
	unsigned char buf[64 * 1024];
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	EVP_MD_CTX *ctx = NULL;
	FILE *f = NULL;
	size_t n;

	f = fopen(path, "rb");
	if (!f)
		return -errno;

	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		rc = -ENOMEM;
		goto out;
	}
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		rc = -EIO;
		goto out;
	}
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
		if (EVP_DigestUpdate(ctx, buf, n) != 1) {
			rc = -EIO;
			goto out;
		}
	}
	if (ferror(f)) {
		rc = -EIO;
		goto out;
	}
	if (EVP_DigestFinal_ex(ctx, digest, &dlen) != 1) {
		rc = -EIO;
		goto out;
	}
	for (unsigned int i = 0; i < dlen; i++)
		snprintf(hex_out + (i * 2), 3, "%02x", digest[i]);
	hex_out[dlen * 2] = '\0';

out:
	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (f)
		fclose(f);
	return rc;
}

bool eg_is_executable(const char *path)
{
	struct stat st;
	int fd;
	unsigned char head[4] = {0};
	ssize_t r;

	if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
		return false;

	/* Any execute bit set -> treat as executable. */
	if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
		return true;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	r = read(fd, head, sizeof(head));
	close(fd);
	if (r < 2)
		return false;

	/* ELF magic 0x7f 'E' 'L' 'F'. */
	if (r == 4 && head[0] == 0x7f && head[1] == 'E' &&
	    head[2] == 'L' && head[3] == 'F')
		return true;

	/* Shebang script. */
	if (head[0] == '#' && head[1] == '!')
		return true;

	return false;
}

void eg_json_escape(const char *in, char *out, size_t out_sz)
{
	size_t o = 0;

	if (out_sz == 0)
		return;
	for (size_t i = 0; in && in[i] && o + 2 < out_sz; i++) {
		unsigned char c = (unsigned char)in[i];
		switch (c) {
		case '"':  if (o + 2 < out_sz) { out[o++]='\\'; out[o++]='"'; } break;
		case '\\': if (o + 2 < out_sz) { out[o++]='\\'; out[o++]='\\'; } break;
		case '\n': if (o + 2 < out_sz) { out[o++]='\\'; out[o++]='n'; } break;
		case '\r': if (o + 2 < out_sz) { out[o++]='\\'; out[o++]='r'; } break;
		case '\t': if (o + 2 < out_sz) { out[o++]='\\'; out[o++]='t'; } break;
		default:
			if (c < 0x20) {
				if (o + 6 < out_sz)
					o += snprintf(out + o, out_sz - o,
						      "\\u%04x", c);
			} else {
				out[o++] = (char)c;
			}
		}
	}
	out[o < out_sz ? o : out_sz - 1] = '\0';
}

const char *eg_op_name(__u32 op)
{
	switch (op) {
	case EG_OP_OPEN_WRITE: return "WRITE";
	case EG_OP_UNLINK:     return "UNLINK";
	case EG_OP_RENAME:     return "RENAME";
	case EG_OP_TRUNCATE:   return "TRUNCATE";
	default:               return "UNKNOWN";
	}
}

const char *eg_decision_name(__u32 decision)
{
	switch (decision) {
	case EG_DECISION_DENY:  return "DENY";
	case EG_DECISION_ALLOW: return "ALLOW";
	case EG_DECISION_AUDIT: return "AUDIT";
	default:                return "UNKNOWN";
	}
}

const char *eg_reason_name(__u32 reason)
{
	switch (reason) {
	case EG_REASON_PROTECTED:   return "protected executable";
	case EG_REASON_TRUSTED:     return "trusted updater";
	case EG_REASON_MAINTENANCE: return "maintenance window";
	case EG_REASON_AUDIT_ONLY:  return "audit-only mode";
	default:                    return "unknown";
	}
}

/* ============================ policy engine ============================= */
/*
 * Policy file parsing, validation, and glob expansion.
 */


/* ---------------------------------------------------------- string list -- */

int eg_str_list_add(struct eg_str_list *l, const char *s)
{
	if (l->count == l->cap) {
		size_t ncap = l->cap ? l->cap * 2 : 16;
		char **ni = realloc(l->items, ncap * sizeof(*ni));
		if (!ni)
			return -ENOMEM;
		l->items = ni;
		l->cap = ncap;
	}
	l->items[l->count] = strdup(s);
	if (!l->items[l->count])
		return -ENOMEM;
	l->count++;
	return 0;
}

void eg_str_list_free(struct eg_str_list *l)
{
	if (!l)
		return;
	for (size_t i = 0; i < l->count; i++)
		free(l->items[i]);
	free(l->items);
	l->items = NULL;
	l->count = 0;
	l->cap = 0;
}

/* ---------------------------------------------------------------- parse -- */

static char *trim(char *s)
{
	while (*s && isspace((unsigned char)*s))
		s++;
	if (!*s)
		return s;
	char *end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		*end-- = '\0';
	return s;
}

/* Parse one directive line. Returns 0 on success, -EINVAL on a bad line,
 * or +1 if the line is blank/comment and should be skipped. */
static int parse_line(char *line, struct eg_policy *pol)
{
	char *s = trim(line);
	if (*s == '\0' || *s == '#')
		return 1;

	char *sp = strpbrk(s, " \t");
	if (!sp) {
		/* MODE with no argument is the only bare-keyword case we reject */
		return -EINVAL;
	}
	*sp = '\0';
	char *arg = trim(sp + 1);
	if (*arg == '\0')
		return -EINVAL;

	if (strcmp(s, "PROTECT") == 0)
		return eg_str_list_add(&pol->protect_patterns, arg);
	if (strcmp(s, "TRUST") == 0)
		return eg_str_list_add(&pol->trust_paths, arg);
	if (strcmp(s, "DENY") == 0) {
		if (strncmp(arg, "user=", 5) == 0)
			return eg_str_list_add(&pol->deny_users, arg + 5);
		return -EINVAL;
	}
	if (strcmp(s, "MODE") == 0) {
		if (strcmp(arg, "enforce") == 0) { pol->enforce = true;  return 0; }
		if (strcmp(arg, "audit")   == 0) { pol->enforce = false; return 0; }
		return -EINVAL;
	}
	return -EINVAL; /* unknown directive */
}

int eg_policy_load(const char *path, struct eg_policy *pol)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	int rc = 0;

	memset(pol, 0, sizeof(*pol));
	pol->enforce = true; /* secure default */
	snprintf(pol->path, sizeof(pol->path), "%s", path);

	f = fopen(path, "r");
	if (!f)
		return -errno;

	while ((n = getline(&line, &cap, f)) != -1) {
		int r = parse_line(line, pol);
		if (r < 0) {
			rc = r;
			break;
		}
	}
	free(line);
	fclose(f);
	if (rc)
		eg_policy_free(pol);
	return rc;
}

int eg_policy_validate(const char *path)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	int lineno = 0, bad = 0;
	struct eg_policy scratch = { .enforce = true };

	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "cannot open policy %s: %s\n", path,
			strerror(errno));
		return -errno;
	}
	while ((n = getline(&line, &cap, f)) != -1) {
		lineno++;
		char tmp[EG_MAX_PATH * 2];
		snprintf(tmp, sizeof(tmp), "%s", line);
		int r = parse_line(tmp, &scratch);
		if (r < 0) {
			fprintf(stderr, "policy %s:%d: invalid directive\n",
				path, lineno);
			bad++;
		}
	}
	free(line);
	fclose(f);
	eg_policy_free(&scratch);

	if (bad) {
		fprintf(stderr, "%d invalid line(s)\n", bad);
		return -EINVAL;
	}
	return 0;
}

int eg_policy_expand_protected(const struct eg_policy *pol,
			       struct eg_str_list *out_files)
{
	memset(out_files, 0, sizeof(*out_files));

	for (size_t i = 0; i < pol->protect_patterns.count; i++) {
		const char *pat = pol->protect_patterns.items[i];
		glob_t g;
		int gr = glob(pat, GLOB_NOSORT, NULL, &g);

		if (gr == GLOB_NOMATCH) {
			/* Not a glob, or nothing there yet: treat literally if
			 * it exists and qualifies. */
			if (eg_is_executable(pat))
				eg_str_list_add(out_files, pat);
			continue;
		}
		if (gr != 0)
			continue; /* GLOB_ABORTED etc: skip this pattern */

		for (size_t j = 0; j < g.gl_pathc; j++) {
			if (eg_is_executable(g.gl_pathv[j]))
				eg_str_list_add(out_files, g.gl_pathv[j]);
		}
		globfree(&g);
	}
	return 0;
}

void eg_policy_free(struct eg_policy *pol)
{
	if (!pol)
		return;
	eg_str_list_free(&pol->protect_patterns);
	eg_str_list_free(&pol->trust_paths);
	eg_str_list_free(&pol->deny_users);
}

/* ============================ integrity baseline ======================== */
/*
 * SHA-256 baseline creation and verification.
 */


/* Ensure the parent directory of "path" exists (mode 0750). Best-effort. */
static void ensure_parent_dir(const char *path)
{
	char tmp[EG_MAX_PATH];
	snprintf(tmp, sizeof(tmp), "%s", path);
	char *dir = dirname(tmp);
	mkdir(dir, 0750); /* ignore EEXIST */
}

int eg_integrity_baseline(const char *baseline_path,
			  const struct eg_str_list *files)
{
	FILE *out;
	int count = 0;

	ensure_parent_dir(baseline_path);
	out = fopen(baseline_path, "w");
	if (!out)
		return -errno;

	for (size_t i = 0; i < files->count; i++) {
		const char *p = files->items[i];
		char hex[65];
		struct stat st;
		char esc[EG_MAX_PATH * 2];

		if (eg_sha256_file(p, hex) != 0)
			continue;
		if (stat(p, &st) != 0)
			continue;
		eg_json_escape(p, esc, sizeof(esc));
		fprintf(out, "{\"path\":\"%s\",\"sha256\":\"%s\",\"size\":%lld}\n",
			esc, hex, (long long)st.st_size);
		count++;
	}
	fclose(out);
	return count;
}

/* Extract a "key":"value" string field from a JSON line. Minimal, tolerant of
 * this file's own output format only (we control what we write). */
static int json_get_str(const char *line, const char *key, char *out,
			size_t out_sz)
{
	char pat[64];
	snprintf(pat, sizeof(pat), "\"%s\":\"", key);
	const char *p = strstr(line, pat);
	if (!p)
		return -ENOENT;
	p += strlen(pat);
	size_t o = 0;
	while (*p && *p != '"' && o + 1 < out_sz) {
		if (*p == '\\' && p[1])
			p++; /* unescape one level */
		out[o++] = *p++;
	}
	out[o] = '\0';
	return 0;
}

int eg_integrity_verify(const char *baseline_path,
			int *ok, int *changed, int *missing)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	int drift = 0;

	*ok = *changed = *missing = 0;

	f = fopen(baseline_path, "r");
	if (!f)
		return -errno;

	while ((n = getline(&line, &cap, f)) != -1) {
		char path[EG_MAX_PATH], want[65], have[65];

		if (json_get_str(line, "path", path, sizeof(path)) != 0)
			continue;
		if (json_get_str(line, "sha256", want, sizeof(want)) != 0)
			continue;

		if (eg_sha256_file(path, have) != 0) {
			printf("  MISSING  %s\n", path);
			(*missing)++;
			drift = 1;
			continue;
		}
		if (strcmp(want, have) != 0) {
			printf("  CHANGED  %s\n", path);
			printf("           baseline %s\n", want);
			printf("           current  %s\n", have);
			(*changed)++;
			drift = 1;
		} else {
			(*ok)++;
		}
	}
	free(line);
	fclose(f);
	return drift;
}

int eg_integrity_verify_one(const char *baseline_path, const char *file)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	int rc = 2; /* not found by default */

	f = fopen(baseline_path, "r");
	if (!f)
		return -errno;

	while ((n = getline(&line, &cap, f)) != -1) {
		char path[EG_MAX_PATH], want[65], have[65];

		if (json_get_str(line, "path", path, sizeof(path)) != 0)
			continue;
		if (strcmp(path, file) != 0)
			continue;
		if (json_get_str(line, "sha256", want, sizeof(want)) != 0)
			continue;
		if (eg_sha256_file(file, have) != 0) {
			rc = -errno;
			break;
		}
		rc = (strcmp(want, have) == 0) ? 0 : 1;
		break;
	}
	free(line);
	fclose(f);
	return rc;
}

/* ============================ daemon ==================================== */
/*
 * execguardd - ExecGuard userspace daemon.
 *
 * Responsibilities:
 *   1. Load and attach the BPF-LSM programs (via the generated skeleton).
 *   2. Translate the policy file into (dev,ino) map entries the kernel enforces.
 *   3. Consume audit events from the ring buffer and write a structured log.
 *   4. Serve a root-owned Unix control socket for egctl (status, protect,
 *      trust, maintenance, enforce mode, reload).
 *
 * The daemon holds no enforcement logic itself; enforcement is entirely in the
 * kernel. If the daemon dies, the already-loaded BPF programs keep enforcing
 * with the last-synced maps (the link is pinned by the running kernel until the
 * programs are detached), but no new events are logged. install.sh runs the
 * daemon under systemd with automatic restart.
 */

/* --------------------------------------------------------------- globals -- */

static volatile sig_atomic_t g_exiting;

struct prot_entry {
	struct eg_file_key key;
	char path[EG_MAX_PATH];
};

static struct {
	struct execguard_bpf *skel;
	struct ring_buffer   *rb;

	struct prot_entry *prot;   /* userspace mirror for reverse-lookup */
	size_t             prot_n;
	size_t             prot_cap;

	char config_path[EG_MAX_PATH];
	char baseline_path[EG_MAX_PATH];
	char audit_path[EG_MAX_PATH];
	FILE *audit_fp;

	unsigned long long blocked;
	unsigned long long allowed;
	unsigned long long audited;
} G = {
	.config_path   = "/etc/execguard/execguard.conf",
	.baseline_path = "/var/lib/execguard/baseline.jsonl",
	.audit_path    = "/var/log/execguard/audit.jsonl",
};

/* ---------------------------------------------------------------- clocks -- */

static __u64 monotonic_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

/* ------------------------------------------------------------ state map -- */

static int read_state(struct eg_state *st)
{
	__u32 zero = 0;
	int fd = bpf_map__fd(G.skel->maps.state);
	return bpf_map_lookup_elem(fd, &zero, st);
}

static int write_state(const struct eg_state *st)
{
	__u32 zero = 0;
	int fd = bpf_map__fd(G.skel->maps.state);
	return bpf_map_update_elem(fd, &zero, st, BPF_ANY);
}

static int set_enforcing(int enforce)
{
	struct eg_state st = {0};
	read_state(&st);
	st.enforcing = enforce ? 1 : 0;
	return write_state(&st);
}

static int set_maintenance(int seconds)
{
	struct eg_state st = {0};
	read_state(&st);
	st.maintenance_until_ns =
		seconds > 0 ? monotonic_ns() + (__u64)seconds * 1000000000ULL : 0;
	return write_state(&st);
}

/* --------------------------------------------------- protected/trusted -- */

static int prot_mirror_add(const struct eg_file_key *k, const char *path)
{
	/* Idempotent: RELOAD and repeated PROTECT re-add files that are already
	 * mirrored. Refresh the path instead of appending a duplicate, so the
	 * protected-file count and LIST_PROTECTED stay accurate. */
	for (size_t i = 0; i < G.prot_n; i++) {
		if (G.prot[i].key.dev == k->dev && G.prot[i].key.ino == k->ino) {
			snprintf(G.prot[i].path, EG_MAX_PATH, "%s", path);
			return 0;
		}
	}

	if (G.prot_n == G.prot_cap) {
		size_t ncap = G.prot_cap ? G.prot_cap * 2 : 256;
		struct prot_entry *np = realloc(G.prot, ncap * sizeof(*np));
		if (!np)
			return -ENOMEM;
		G.prot = np;
		G.prot_cap = ncap;
	}
	G.prot[G.prot_n].key = *k;
	snprintf(G.prot[G.prot_n].path, EG_MAX_PATH, "%s", path);
	G.prot_n++;
	return 0;
}

static const char *prot_mirror_path(__u64 dev, __u64 ino)
{
	for (size_t i = 0; i < G.prot_n; i++)
		if (G.prot[i].key.dev == dev && G.prot[i].key.ino == ino)
			return G.prot[i].path;
	return NULL;
}

static int add_protected(const char *path)
{
	struct eg_file_key k;
	struct eg_file_val v = { .flags = EG_F_PROTECTED };
	int rc = eg_path_to_key(path, &k);
	if (rc)
		return rc;
	rc = bpf_map_update_elem(bpf_map__fd(G.skel->maps.protected_inodes),
				 &k, &v, BPF_ANY);
	if (rc)
		return -errno;
	prot_mirror_add(&k, path);
	return 0;
}

static int remove_protected(const char *path)
{
	struct eg_file_key k;
	int rc = eg_path_to_key(path, &k);
	if (rc)
		return rc;
	rc = bpf_map_delete_elem(bpf_map__fd(G.skel->maps.protected_inodes), &k);
	for (size_t i = 0; i < G.prot_n; i++) {
		if (G.prot[i].key.dev == k.dev && G.prot[i].key.ino == k.ino) {
			G.prot[i] = G.prot[--G.prot_n];
			break;
		}
	}
	return rc ? -errno : 0;
}

static int add_trusted(const char *path)
{
	struct eg_file_key k;
	__u8 one = 1;
	int rc = eg_path_to_key(path, &k);
	if (rc)
		return rc;
	rc = bpf_map_update_elem(bpf_map__fd(G.skel->maps.trusted_exes),
				 &k, &one, BPF_ANY);
	return rc ? -errno : 0;
}

static int remove_trusted(const char *path)
{
	struct eg_file_key k;
	int rc = eg_path_to_key(path, &k);
	if (rc)
		return rc;
	rc = bpf_map_delete_elem(bpf_map__fd(G.skel->maps.trusted_exes), &k);
	return rc ? -errno : 0;
}

/* -------------------------------------------------------- policy -> maps -- */

static int sync_from_policy(void)
{
	struct eg_policy pol;
	struct eg_str_list files;
	int rc, added = 0;

	rc = eg_policy_load(G.config_path, &pol);
	if (rc) {
		fprintf(stderr, "policy load failed: %s\n", strerror(-rc));
		return rc;
	}

	rc = eg_policy_expand_protected(&pol, &files);
	if (rc) {
		eg_policy_free(&pol);
		return rc;
	}
	for (size_t i = 0; i < files.count; i++)
		if (add_protected(files.items[i]) == 0)
			added++;
	eg_str_list_free(&files);

	for (size_t i = 0; i < pol.trust_paths.count; i++)
		add_trusted(pol.trust_paths.items[i]);

	set_enforcing(pol.enforce);

	fprintf(stderr, "policy applied: %d protected file(s), %zu trusted exe(s), mode=%s\n",
		added, pol.trust_paths.count, pol.enforce ? "enforce" : "audit");
	eg_policy_free(&pol);
	return 0;
}

/* ------------------------------------------------------------ audit sink -- */

static void audit_write(const struct eg_event *e)
{
	const char *path = prot_mirror_path(e->dev, e->ino);
	char comm_esc[64], name_esc[EG_TARGET_LEN * 2], path_esc[EG_MAX_PATH * 2];

	eg_json_escape(e->comm, comm_esc, sizeof(comm_esc));
	eg_json_escape(e->target, name_esc, sizeof(name_esc));
	eg_json_escape(path ? path : "", path_esc, sizeof(path_esc));

	if (G.audit_fp) {
		fprintf(G.audit_fp,
			"{\"ts_ns\":%llu,\"decision\":\"%s\",\"op\":\"%s\","
			"\"reason\":\"%s\",\"uid\":%u,\"pid\":%u,\"tgid\":%u,"
			"\"comm\":\"%s\",\"target_name\":\"%s\","
			"\"target_path\":\"%s\",\"target_dev\":%llu,"
			"\"target_ino\":%llu,\"caller_dev\":%llu,"
			"\"caller_ino\":%llu}\n",
			(unsigned long long)e->ts_ns,
			eg_decision_name(e->decision), eg_op_name(e->op),
			eg_reason_name(e->reason), e->uid, e->pid, e->tgid,
			comm_esc, name_esc, path_esc,
			(unsigned long long)e->dev, (unsigned long long)e->ino,
			(unsigned long long)e->caller_dev,
			(unsigned long long)e->caller_ino);
		fflush(G.audit_fp);
	}
}

static int handle_event(void *ctx, void *data, size_t size)
{
	(void)ctx;
	if (size < sizeof(struct eg_event))
		return 0;
	const struct eg_event *e = data;

	switch (e->decision) {
	case EG_DECISION_DENY:  G.blocked++; break;
	case EG_DECISION_ALLOW: G.allowed++; break;
	case EG_DECISION_AUDIT: G.audited++; break;
	}
	audit_write(e);
	return 0;
}

/* -------------------------------------------------------- control server -- */

static void reply(int fd, const char *fmt, ...)
{
	char buf[EG_MAX_LINE * 4];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n > 0)
		(void)!write(fd, buf, (size_t)n);
}

static void handle_command(int cfd)
{
	char line[EG_MAX_LINE];
	ssize_t n = read(cfd, line, sizeof(line) - 1);
	if (n <= 0)
		return;
	line[n] = '\0';
	line[strcspn(line, "\r\n")] = '\0';

	char *cmd = strtok(line, " ");
	char *arg = strtok(NULL, "");
	if (!cmd) {
		reply(cfd, "ERR empty command\n");
		return;
	}

	if (strcmp(cmd, "STATUS") == 0) {
		struct eg_state st = {0};
		read_state(&st);
		__u64 now = monotonic_ns();
		int maint = (st.maintenance_until_ns &&
			     now < st.maintenance_until_ns);
		reply(cfd,
		      "OK\nprotected_files %zu\nblocked %llu\nallowed %llu\n"
		      "audited %llu\nenforcing %u\nmaintenance %s\n",
		      G.prot_n, G.blocked, G.allowed, G.audited,
		      st.enforcing, maint ? "ENABLED" : "DISABLED");
	} else if (strcmp(cmd, "PROTECT") == 0 && arg) {
		int rc = add_protected(arg);
		reply(cfd, rc ? "ERR %s\n" : "OK protected %s\n",
		      rc ? strerror(-rc) : arg);
	} else if (strcmp(cmd, "UNPROTECT") == 0 && arg) {
		int rc = remove_protected(arg);
		reply(cfd, rc ? "ERR %s\n" : "OK unprotected %s\n",
		      rc ? strerror(-rc) : arg);
	} else if (strcmp(cmd, "TRUST") == 0 && arg) {
		int rc = add_trusted(arg);
		reply(cfd, rc ? "ERR %s\n" : "OK trusted %s\n",
		      rc ? strerror(-rc) : arg);
	} else if (strcmp(cmd, "UNTRUST") == 0 && arg) {
		int rc = remove_trusted(arg);
		reply(cfd, rc ? "ERR %s\n" : "OK untrusted %s\n",
		      rc ? strerror(-rc) : arg);
	} else if (strcmp(cmd, "MAINT_ENABLE") == 0 && arg) {
		int secs = atoi(arg);
		if (secs <= 0) {
			reply(cfd, "ERR invalid duration\n");
		} else {
			set_maintenance(secs);
			reply(cfd, "OK maintenance enabled for %ds\n", secs);
		}
	} else if (strcmp(cmd, "MAINT_DISABLE") == 0) {
		set_maintenance(0);
		reply(cfd, "OK maintenance disabled\n");
	} else if (strcmp(cmd, "ENFORCE") == 0 && arg) {
		set_enforcing(atoi(arg));
		reply(cfd, "OK enforcing=%d\n", atoi(arg));
	} else if (strcmp(cmd, "LIST_PROTECTED") == 0) {
		reply(cfd, "OK %zu\n", G.prot_n);
		for (size_t i = 0; i < G.prot_n; i++)
			reply(cfd, "%s\n", G.prot[i].path);
	} else if (strcmp(cmd, "RELOAD") == 0) {
		int rc = sync_from_policy();
		reply(cfd, rc ? "ERR reload failed\n" : "OK reloaded\n");
	} else {
		reply(cfd, "ERR unknown command\n");
	}
}

static int control_listen(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	mkdir("/run/execguard", 0750);
	unlink(EG_CONTROL_SOCKET);
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", EG_CONTROL_SOCKET);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -errno;
	}
	/* root-only control surface */
	chmod(EG_CONTROL_SOCKET, 0600);
	if (listen(fd, 8) < 0) {
		close(fd);
		return -errno;
	}
	return fd;
}

/* ----------------------------------------------------------------- setup -- */

static void on_signal(int sig) { (void)sig; g_exiting = 1; }

static int open_audit_log(void)
{
	char dir[EG_MAX_PATH];
	snprintf(dir, sizeof(dir), "%s", G.audit_path);
	char *slash = strrchr(dir, '/');
	if (slash) {
		*slash = '\0';
		mkdir(dir, 0750);
	}
	G.audit_fp = fopen(G.audit_path, "a");
	return G.audit_fp ? 0 : -errno;
}

static int load_bpf(void)
{
	int err;

	G.skel = execguard_bpf__open();
	if (!G.skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return -1;
	}
	err = execguard_bpf__load(G.skel);
	if (err) {
		fprintf(stderr,
			"failed to load BPF programs (err=%d). Is CONFIG_BPF_LSM=y "
			"and 'bpf' in /sys/kernel/security/lsm? Run src/scripts/check-env.sh.\n",
			err);
		return err;
	}
	err = execguard_bpf__attach(G.skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF-LSM programs (err=%d)\n", err);
		return err;
	}
	G.rb = ring_buffer__new(bpf_map__fd(G.skel->maps.events),
				handle_event, NULL, NULL);
	if (!G.rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		return -1;
	}
	return 0;
}

static void daemon_usage(const char *p)
{
	fprintf(stderr,
		"Usage: %s [--config PATH] [--baseline PATH] [--audit PATH]\n"
		"          [--foreground]\n", p);
}

static int run_daemon(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "config",     required_argument, 0, 'c' },
		{ "baseline",   required_argument, 0, 'b' },
		{ "audit",      required_argument, 0, 'a' },
		{ "foreground", no_argument,       0, 'f' },
		{ "help",       no_argument,       0, 'h' },
		{ 0, 0, 0, 0 }
	};
	int c, lfd, epfd, rc = 1;

	while ((c = getopt_long(argc, argv, "c:b:a:fh", opts, NULL)) != -1) {
		switch (c) {
		case 'c': snprintf(G.config_path, EG_MAX_PATH, "%s", optarg); break;
		case 'b': snprintf(G.baseline_path, EG_MAX_PATH, "%s", optarg); break;
		case 'a': snprintf(G.audit_path, EG_MAX_PATH, "%s", optarg); break;
		case 'f': break; /* systemd runs us in foreground anyway */
		case 'h': daemon_usage(argv[0]); return 0;
		default:  daemon_usage(argv[0]); return 2;
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "execguardd must run as root (needs CAP_SYS_ADMIN/CAP_BPF)\n");
		return 1;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	if (open_audit_log() != 0)
		fprintf(stderr, "warning: cannot open audit log %s: %s\n",
			G.audit_path, strerror(errno));

	if (load_bpf() != 0)
		goto cleanup;

	/* Default to enforcing; policy may downgrade to audit. */
	{ struct eg_state st = { .enforcing = 1 }; write_state(&st); }

	if (sync_from_policy() != 0)
		fprintf(stderr, "warning: continuing with empty policy\n");

	lfd = control_listen();
	if (lfd < 0) {
		fprintf(stderr, "control socket failed: %s\n", strerror(-lfd));
		goto cleanup;
	}

	epfd = epoll_create1(EPOLL_CLOEXEC);
	{
		struct epoll_event ev;
		int rbfd = ring_buffer__epoll_fd(G.rb);
		ev.events = EPOLLIN; ev.data.fd = rbfd;
		epoll_ctl(epfd, EPOLL_CTL_ADD, rbfd, &ev);
		ev.events = EPOLLIN; ev.data.fd = lfd;
		epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &ev);
	}

	fprintf(stderr, "ExecGuard daemon active. Protecting %zu file(s).\n",
		G.prot_n);

	while (!g_exiting) {
		struct epoll_event evs[8];
		int nfds = epoll_wait(epfd, evs, 8, 1000);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (int i = 0; i < nfds; i++) {
			if (evs[i].data.fd == ring_buffer__epoll_fd(G.rb)) {
				ring_buffer__consume(G.rb);
			} else if (evs[i].data.fd == lfd) {
				int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
				if (cfd >= 0) {
					handle_command(cfd);
					close(cfd);
				}
			}
		}
	}
	rc = 0;

cleanup:
	if (G.rb)
		ring_buffer__free(G.rb);
	if (G.skel)
		execguard_bpf__destroy(G.skel); /* detaches programs */
	if (G.audit_fp)
		fclose(G.audit_fp);
	free(G.prot);
	unlink(EG_CONTROL_SOCKET);
	fprintf(stderr, "ExecGuard daemon stopped.\n");
	return rc;
}

/* ============================ CLI (egctl) =============================== */
/*
 * egctl - ExecGuard control CLI.
 *
 * Most subcommands are thin wrappers over the daemon's Unix control socket.
 * A few (policy validate, integrity verify/scan/baseline, logs) run locally
 * because they only read files and do not need the running kernel state.
 */


#define EG_VERSION "0.1.0"

static const char *g_config   = "/etc/execguard/execguard.conf";
static const char *g_baseline = EG_BASELINE_DEFAULT;
static const char *g_audit    = "/var/log/execguard/audit.jsonl";

/*
 * Optional environment overrides for the file-based subcommands. They let the
 * policy, integrity, and log commands run against fixtures (see data/ and
 * src/tests/unit/) without touching /etc or /var. They have no effect on the
 * daemon, whose paths are set by its own command-line options.
 */
static void cli_apply_env_overrides(void)
{
	const char *v;

	if ((v = getenv("EG_CONFIG")) && *v)
		g_config = v;
	if ((v = getenv("EG_BASELINE")) && *v)
		g_baseline = v;
	if ((v = getenv("EG_AUDIT_LOG")) && *v)
		g_audit = v;
}

/* -------------------------------------------------- control socket client -- */

/* Send one command line; copy the daemon's full response into resp.
 * Returns 0 on success (response starts with "OK"), 1 on "ERR", -errno on I/O
 * failure or if the daemon is unreachable. */
static int daemon_cmd(const char *cmd, char *resp, size_t resp_sz)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd, rc = 0;
	size_t off = 0;
	ssize_t n;
	char line[EG_MAX_LINE];

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", EG_CONTROL_SOCKET);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -errno;
	}
	snprintf(line, sizeof(line), "%s\n", cmd);
	if (write(fd, line, strlen(line)) < 0) {
		close(fd);
		return -errno;
	}
	while ((n = read(fd, resp + off, resp_sz - 1 - off)) > 0) {
		off += (size_t)n;
		if (off >= resp_sz - 1)
			break;
	}
	resp[off] = '\0';
	close(fd);

	if (strncmp(resp, "OK", 2) == 0)
		rc = 0;
	else
		rc = 1;
	return rc;
}

static int require_daemon(void)
{
	char resp[256];
	int rc = daemon_cmd("STATUS", resp, sizeof(resp));
	if (rc < 0) {
		fprintf(stderr,
			"error: cannot reach execguardd at %s (%s).\n"
			"Is the daemon running? Try: sudo systemctl status execguard\n",
			EG_CONTROL_SOCKET, strerror(-rc));
		return -1;
	}
	return 0;
}

/* --------------------------------------------------------------- helpers -- */

/* Parse durations like "30s", "5m", "1h", or a bare integer (seconds). */
static int parse_duration(const char *s)
{
	char *end = NULL;
	long v = strtol(s, &end, 10);
	if (v <= 0)
		return -1;
	if (!end || *end == '\0' || strcmp(end, "s") == 0)
		return (int)v;
	if (strcmp(end, "m") == 0)
		return (int)(v * 60);
	if (strcmp(end, "h") == 0)
		return (int)(v * 3600);
	return -1;
}

static const char *field(const char *resp, const char *key, char *out, size_t sz)
{
	const char *p = strstr(resp, key);
	out[0] = '\0';
	if (!p)
		return out;
	p += strlen(key);
	while (*p == ' ')
		p++;
	size_t o = 0;
	while (*p && *p != '\n' && o + 1 < sz)
		out[o++] = *p++;
	out[o] = '\0';
	return out;
}

/* -------------------------------------------------------------- commands -- */

static int cmd_status(void)
{
	char resp[512];
	if (require_daemon())
		return 1;
	daemon_cmd("STATUS", resp, sizeof(resp));

	char files[32], blocked[32], allowed[32], enf[32], maint[32];
	field(resp, "protected_files", files, sizeof(files));
	field(resp, "blocked", blocked, sizeof(blocked));
	field(resp, "allowed", allowed, sizeof(allowed));
	field(resp, "enforcing", enf, sizeof(enf));
	field(resp, "maintenance", maint, sizeof(maint));

	const char *pstatus = (strcmp(enf, "1") == 0) ? "ACTIVE" : "AUDIT-ONLY";

	printf("+----------------------------------------------+\n");
	printf("|                  ExecGuard                   |\n");
	printf("+----------------------------------------------+\n");
	printf("| Protection Status : %-24s |\n", pstatus);
	printf("| Protected Files   : %-24s |\n", files);
	printf("| Blocked Attempts  : %-24s |\n", blocked);
	printf("| Allowed Updates   : %-24s |\n", allowed);
	printf("| Maintenance Mode  : %-24s |\n", maint);
	printf("+----------------------------------------------+\n");
	return 0;
}

static int cmd_simple(const char *verb, const char *arg)
{
	char cmd[EG_MAX_LINE], resp[512];
	if (require_daemon())
		return 1;
	snprintf(cmd, sizeof(cmd), "%s %s", verb, arg);
	int rc = daemon_cmd(cmd, resp, sizeof(resp));
	fputs(resp, stdout);
	return rc == 0 ? 0 : 1;
}

static int cmd_policy(int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "usage: egctl policy <list|validate>\n");
		return 2;
	}
	if (strcmp(argv[0], "validate") == 0) {
		int rc = eg_policy_validate(g_config);
		if (rc == 0)
			printf("policy OK: %s\n", g_config);
		return rc == 0 ? 0 : 1;
	}
	if (strcmp(argv[0], "list") == 0) {
		char resp[64 * 1024];
		if (require_daemon())
			return 1;
		daemon_cmd("LIST_PROTECTED", resp, sizeof(resp));
		fputs(resp, stdout);
		return 0;
	}
	fprintf(stderr, "unknown policy subcommand: %s\n", argv[0]);
	return 2;
}

static int cmd_maintenance(int argc, char **argv)
{
	if (argc >= 1 && strcmp(argv[0], "disable") == 0)
		return cmd_simple("MAINT_DISABLE", "");
	if (argc >= 2 && strcmp(argv[0], "enable") == 0) {
		/* forms: enable <dur>  |  enable --duration <dur> */
		const char *dstr = argv[1];
		if (strcmp(argv[1], "--duration") == 0 && argc >= 3)
			dstr = argv[2];
		int secs = parse_duration(dstr);
		if (secs <= 0) {
			fprintf(stderr, "invalid duration: %s\n", dstr);
			return 2;
		}
		char arg[32];
		snprintf(arg, sizeof(arg), "%d", secs);
		return cmd_simple("MAINT_ENABLE", arg);
	}
	fprintf(stderr,
		"usage: egctl maintenance enable --duration <30s|5m|1h>\n"
		"       egctl maintenance disable\n");
	return 2;
}

static int cmd_verify(const char *file)
{
	int rc = eg_integrity_verify_one(g_baseline, file);
	switch (rc) {
	case 0: printf("OK       %s (matches baseline)\n", file);    return 0;
	case 1: printf("CHANGED  %s (does NOT match baseline)\n", file); return 1;
	case 2: printf("UNKNOWN  %s (not in baseline)\n", file);     return 1;
	default:
		fprintf(stderr, "verify error: %s\n", strerror(-rc));
		return 1;
	}
}

static int cmd_integrity(int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "usage: egctl integrity <scan|baseline>\n");
		return 2;
	}
	if (strcmp(argv[0], "scan") == 0) {
		int ok, changed, missing;
		int rc = eg_integrity_verify(g_baseline, &ok, &changed, &missing);
		if (rc < 0) {
			fprintf(stderr, "cannot read baseline %s: %s\n",
				g_baseline, strerror(-rc));
			return 1;
		}
		printf("integrity scan: %d ok, %d changed, %d missing\n",
		       ok, changed, missing);
		return rc == 0 ? 0 : 1;
	}
	if (strcmp(argv[0], "baseline") == 0) {
		struct eg_policy pol;
		struct eg_str_list files;
		if (eg_policy_load(g_config, &pol) != 0) {
			fprintf(stderr, "cannot load policy\n");
			return 1;
		}
		eg_policy_expand_protected(&pol, &files);
		int n = eg_integrity_baseline(g_baseline, &files);
		eg_str_list_free(&files);
		eg_policy_free(&pol);
		if (n < 0) {
			fprintf(stderr, "baseline failed: %s\n", strerror(-n));
			return 1;
		}
		printf("baseline written: %d file(s) -> %s\n", n, g_baseline);
		return 0;
	}
	fprintf(stderr, "unknown integrity subcommand: %s\n", argv[0]);
	return 2;
}

static int cmd_logs(int argc, char **argv)
{
	int tail = 20;
	if (argc >= 2 && strcmp(argv[0], "-n") == 0)
		tail = atoi(argv[1]);
	if (tail <= 0)
		tail = 20;

	/* Simple tail: read all lines, print the last "tail" of them. */
	FILE *f = fopen(g_audit, "r");
	if (!f) {
		fprintf(stderr, "cannot open %s: %s\n", g_audit, strerror(errno));
		return 1;
	}
	char **buf = NULL;
	size_t n = 0, cap = 0;
	char *line = NULL;
	size_t lc = 0;
	while (getline(&line, &lc, f) != -1) {
		if (n == cap) {
			size_t ncap = cap ? cap * 2 : 128;
			char **nb = realloc(buf, ncap * sizeof(*nb));
			if (!nb) {
				fprintf(stderr, "out of memory reading %s\n", g_audit);
				break;
			}
			buf = nb;
			cap = ncap;
		}
		char *dup = strdup(line);
		if (!dup)
			break;
		buf[n++] = dup;
	}
	free(line);
	fclose(f);
	size_t start = (n > (size_t)tail) ? n - (size_t)tail : 0;
	for (size_t i = start; i < n; i++) {
		fputs(buf[i], stdout);
		free(buf[i]);
	}
	for (size_t i = 0; i < start; i++)
		free(buf[i]);
	free(buf);
	return 0;
}

static void cli_usage(void)
{
	printf(
"ExecGuard control (egctl) " EG_VERSION "\n"
"\n"
"Usage: egctl <command> [args]\n"
"\n"
"Commands:\n"
"  status                         Show protection status\n"
"  protect <path>                 Add a file to protection at runtime\n"
"  unprotect <path>               Remove a file from protection\n"
"  trust <exe-path>               Register a trusted updater executable\n"
"  untrust <exe-path>             Remove a trusted updater\n"
"  policy list                    List currently protected files\n"
"  policy validate                Validate the policy file syntax\n"
"  reload                         Re-read the policy file\n"
"  enforce <0|1>                  0 = audit-only, 1 = enforce\n"
"  verify <file>                  Check one file against the integrity baseline\n"
"  integrity scan                 Verify all files against the baseline\n"
"  integrity baseline             (Re)build the integrity baseline\n"
"  maintenance enable --duration <30s|5m|1h>\n"
"  maintenance disable\n"
"  logs [-n N]                    Show the last N audit events (default 20)\n"
"  version                        Print version\n"
"  --help                         This help\n"
"\n"
"Environment (file-based commands only):\n"
"  EG_CONFIG     policy file      (default /etc/execguard/execguard.conf)\n"
"  EG_BASELINE   baseline file    (default /var/lib/execguard/baseline.jsonl)\n"
"  EG_AUDIT_LOG  audit log        (default /var/log/execguard/audit.jsonl)\n");
}

static int run_cli(int argc, char **argv)
{
	cli_apply_env_overrides();

	if (argc < 2 || strcmp(argv[1], "--help") == 0 ||
	    strcmp(argv[1], "-h") == 0) {
		cli_usage();
		return argc < 2 ? 2 : 0;
	}
	const char *c = argv[1];
	int rest_argc = argc - 2;
	char **rest = argv + 2;

	if (strcmp(c, "version") == 0) { printf("egctl " EG_VERSION "\n"); return 0; }
	if (strcmp(c, "status") == 0)  return cmd_status();
	if (strcmp(c, "reload") == 0)  return cmd_simple("RELOAD", "");

	if (strcmp(c, "protect") == 0 && rest_argc == 1)
		return cmd_simple("PROTECT", rest[0]);
	if (strcmp(c, "unprotect") == 0 && rest_argc == 1)
		return cmd_simple("UNPROTECT", rest[0]);
	if (strcmp(c, "trust") == 0 && rest_argc == 1)
		return cmd_simple("TRUST", rest[0]);
	if (strcmp(c, "untrust") == 0 && rest_argc == 1)
		return cmd_simple("UNTRUST", rest[0]);
	if (strcmp(c, "enforce") == 0 && rest_argc == 1)
		return cmd_simple("ENFORCE", rest[0]);
	if (strcmp(c, "policy") == 0)      return cmd_policy(rest_argc, rest);
	if (strcmp(c, "maintenance") == 0) return cmd_maintenance(rest_argc, rest);
	if (strcmp(c, "integrity") == 0)   return cmd_integrity(rest_argc, rest);
	if (strcmp(c, "verify") == 0 && rest_argc == 1)
		return cmd_verify(rest[0]);
	if (strcmp(c, "logs") == 0)        return cmd_logs(rest_argc, rest);

	fprintf(stderr, "unknown or malformed command: %s (try --help)\n", c);
	return 2;
}

/* ============================ entry point =============================== */
/*
 * Multi-call dispatch. The daemon and the CLI share this one binary; which one
 * runs is decided by the program name it was invoked under (via symlink) or by
 * an explicit "daemon" first argument.
 */
int main(int argc, char **argv)
{
	const char *slash = strrchr(argv[0], '/');
	const char *base = slash ? slash + 1 : argv[0];

	if (strcmp(base, "execguardd") == 0)
		return run_daemon(argc, argv);

	if (argc > 1 && strcmp(argv[1], "daemon") == 0) {
		/* shift off "daemon" so run_daemon sees a normal argv */
		argv[1] = argv[0];
		return run_daemon(argc - 1, argv + 1);
	}

	return run_cli(argc, argv);
}

