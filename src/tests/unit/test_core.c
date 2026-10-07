// SPDX-License-Identifier: GPL-2.0
/*
 * test_core.c - unit tests for the ExecGuard userspace core.
 *
 * The userspace program is a single translation unit, so this harness includes
 * it directly with its main() renamed. That gives the tests access to static
 * helpers (parse_duration, parse_line, json_get_str) without exporting them
 * from the production binary.
 *
 * Nothing here loads BPF or needs root; it runs on any host that can build the
 * project. Kernel-side enforcement is covered by src/tests/{functional,
 * security,bypass}.
 *
 * Usage: test_core <repo-root> <scratch-dir>
 *   repo-root   checkout root (for data/policies)
 *   scratch-dir prepared by test_userspace.sh: contains sandbox/ (a copy of
 *               data/fixtures/sandbox with modes set) and fixtures.conf
 * Exit status: 0 if every check passed, 1 otherwise.
 */
#define main execguard_program_main
#include "../../userspace/execguard.c"
#undef main

#include <stddef.h>

/* ------------------------------------------------------------ framework -- */

static int t_run, t_fail;
static const char *g_root, *g_scratch;

#define CHECK(cond, ...)                                                    \
	do {                                                                \
		t_run++;                                                    \
		if (cond) {                                                 \
			printf("  PASS  ");                                 \
		} else {                                                    \
			printf("  FAIL  ");                                 \
			t_fail++;                                           \
		}                                                           \
		printf(__VA_ARGS__);                                        \
		printf("\n");                                               \
	} while (0)

static void section(const char *name) { printf("\n[%s]\n", name); }

static void path_join(char *out, size_t sz, const char *a, const char *b)
{
	snprintf(out, sz, "%s/%s", a, b);
}

static int write_file(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	if (!f)
		return -1;
	fputs(content, f);
	return fclose(f);
}

/* ------------------------------------------------------- ABI agreement -- */

/*
 * These structs cross the kernel/user boundary through BPF maps and the ring
 * buffer. If any size or offset drifts, map lookups silently miss and events
 * are misparsed. The BPF object's BTF is checked against the same numbers in
 * test_userspace.sh, so both compilers are pinned to one layout.
 */
static void test_abi_layout(void)
{
	section("ABI layout shared with the BPF program");
	CHECK(sizeof(struct eg_file_key) == 16, "sizeof(eg_file_key) == 16 (got %zu)",
	      sizeof(struct eg_file_key));
	CHECK(sizeof(struct eg_file_val) == 8, "sizeof(eg_file_val) == 8 (got %zu)",
	      sizeof(struct eg_file_val));
	CHECK(sizeof(struct eg_state) == 16, "sizeof(eg_state) == 16 (got %zu)",
	      sizeof(struct eg_state));
	CHECK(sizeof(struct eg_event) == 336, "sizeof(eg_event) == 336 (got %zu)",
	      sizeof(struct eg_event));
	CHECK(offsetof(struct eg_event, pid) == 40, "offsetof(eg_event.pid) == 40");
	CHECK(offsetof(struct eg_event, comm) == 64, "offsetof(eg_event.comm) == 64");
	CHECK(offsetof(struct eg_event, target) == 80, "offsetof(eg_event.target) == 80");
}

/* --------------------------------------------------- device encoding -- */

static void test_kdev(void)
{
	section("eg_encode_kdev: glibc st_dev -> kernel (major<<20)|minor");
	CHECK(eg_encode_kdev(makedev(8, 1)) == ((8ULL << 20) | 1),
	      "sda1 (8:1) -> %llu", (unsigned long long)((8ULL << 20) | 1));
	CHECK(eg_encode_kdev(makedev(259, 3)) == ((259ULL << 20) | 3),
	      "nvme0n1p3 (259:3) -> %llu", (unsigned long long)((259ULL << 20) | 3));
	CHECK(eg_encode_kdev(makedev(253, 65536)) == ((253ULL << 20) | 65536),
	      "dm (253:65536) keeps a minor wider than 8 bits");
	CHECK(eg_encode_kdev(makedev(0, 0)) == 0, "0:0 -> 0");
	/* glibc and kernel encodings genuinely differ for these values, which is
	 * the reason the helper exists. */
	CHECK((unsigned long long)makedev(8, 1) != ((8ULL << 20) | 1),
	      "glibc encoding differs from kernel encoding (helper is required)");

	char p[EG_MAX_PATH];
	struct eg_file_key k;
	struct stat st;
	path_join(p, sizeof(p), g_scratch, "sandbox/bin/app");
	stat(p, &st);
	CHECK(eg_path_to_key(p, &k) == 0 && k.ino == (__u64)st.st_ino &&
	      k.dev == eg_encode_kdev(st.st_dev),
	      "eg_path_to_key resolves (dev,ino) of a real file");
	CHECK(eg_path_to_key("/nonexistent/execguard", &k) == -ENOENT,
	      "eg_path_to_key on a missing path returns -ENOENT");
	CHECK(eg_path_to_key(NULL, &k) == -EINVAL, "eg_path_to_key(NULL) returns -EINVAL");
}

/* ------------------------------------------------------------- SHA-256 -- */

static void test_sha256(void)
{
	section("eg_sha256_file (FIPS 180-2 test vectors)");
	char p[EG_MAX_PATH], hex[65];

	path_join(p, sizeof(p), g_scratch, "vec-empty");
	write_file(p, "");
	CHECK(eg_sha256_file(p, hex) == 0 &&
	      strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
	      "SHA-256(\"\")");

	path_join(p, sizeof(p), g_scratch, "vec-abc");
	write_file(p, "abc");
	CHECK(eg_sha256_file(p, hex) == 0 &&
	      strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
	      "SHA-256(\"abc\")");

	path_join(p, sizeof(p), g_scratch, "vec-448");
	write_file(p, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
	CHECK(eg_sha256_file(p, hex) == 0 &&
	      strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
	      "SHA-256(448-bit message)");

	/* 1,000,000 x 'a' crosses the 64 KiB read buffer many times. */
	path_join(p, sizeof(p), g_scratch, "vec-million");
	FILE *f = fopen(p, "w");
	for (int i = 0; f && i < 1000000; i++)
		fputc('a', f);
	if (f)
		fclose(f);
	CHECK(eg_sha256_file(p, hex) == 0 &&
	      strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0,
	      "SHA-256(1,000,000 x 'a') across buffer boundaries");

	CHECK(eg_sha256_file("/nonexistent/execguard", hex) == -ENOENT,
	      "missing file returns -ENOENT");
}

/* -------------------------------------------------- executable detection -- */

static void test_is_executable(void)
{
	section("eg_is_executable");
	char p[EG_MAX_PATH];

	path_join(p, sizeof(p), g_scratch, "sandbox/bin/app");
	CHECK(eg_is_executable(p), "0755 script -> executable (execute bit)");
	path_join(p, sizeof(p), g_scratch, "sandbox/bin/tool.sh");
	CHECK(eg_is_executable(p), "0644 file with #! -> executable (shebang)");
	path_join(p, sizeof(p), g_scratch, "sandbox/bin/elf-noexec");
	CHECK(eg_is_executable(p), "0644 file with ELF magic -> executable");
	path_join(p, sizeof(p), g_scratch, "sandbox/lib/readme.txt");
	CHECK(!eg_is_executable(p), "0644 plain text -> not executable");
	path_join(p, sizeof(p), g_scratch, "sandbox/bin");
	CHECK(!eg_is_executable(p), "directory -> not executable");
	CHECK(!eg_is_executable("/nonexistent/execguard"), "missing path -> not executable");
}

/* ------------------------------------------------------------------ JSON -- */

static void test_json(void)
{
	section("eg_json_escape and json_get_str round trip");
	char out[128], back[128];

	eg_json_escape("a\"b\\c\nd\te\x01", out, sizeof(out));
	CHECK(strcmp(out, "a\\\"b\\\\c\\nd\\te\\u0001") == 0,
	      "escapes quote, backslash, newline, tab, control char");

	eg_json_escape("plain/path", out, sizeof(out));
	CHECK(strcmp(out, "plain/path") == 0, "plain text unchanged");

	char tiny[6];
	eg_json_escape("abcdefghij", tiny, sizeof(tiny));
	CHECK(strlen(tiny) < sizeof(tiny), "output is bounded and NUL-terminated");

	char line[256];
	eg_json_escape("/opt/a \"b\"", out, sizeof(out));
	snprintf(line, sizeof(line), "{\"path\":\"%s\",\"sha256\":\"00\"}", out);
	CHECK(json_get_str(line, "path", back, sizeof(back)) == 0 &&
	      strcmp(back, "/opt/a \"b\"") == 0,
	      "json_get_str recovers an escaped path");
	CHECK(json_get_str(line, "absent", back, sizeof(back)) == -ENOENT,
	      "json_get_str on a missing key returns -ENOENT");
}

/* ----------------------------------------------------------- enum names -- */

static void test_names(void)
{
	section("audit-log enum rendering (must match data/schemas/enums.csv)");
	CHECK(!strcmp(eg_op_name(EG_OP_OPEN_WRITE), "WRITE") &&
	      !strcmp(eg_op_name(EG_OP_UNLINK), "UNLINK") &&
	      !strcmp(eg_op_name(EG_OP_RENAME), "RENAME") &&
	      !strcmp(eg_op_name(EG_OP_TRUNCATE), "TRUNCATE") &&
	      !strcmp(eg_op_name(99), "UNKNOWN"), "eg_op_name");
	CHECK(!strcmp(eg_decision_name(EG_DECISION_DENY), "DENY") &&
	      !strcmp(eg_decision_name(EG_DECISION_ALLOW), "ALLOW") &&
	      !strcmp(eg_decision_name(EG_DECISION_AUDIT), "AUDIT"), "eg_decision_name");
	CHECK(!strcmp(eg_reason_name(EG_REASON_PROTECTED), "protected executable") &&
	      !strcmp(eg_reason_name(EG_REASON_TRUSTED), "trusted updater") &&
	      !strcmp(eg_reason_name(EG_REASON_MAINTENANCE), "maintenance window") &&
	      !strcmp(eg_reason_name(EG_REASON_AUDIT_ONLY), "audit-only mode"),
	      "eg_reason_name");
}

/* -------------------------------------------------------------- duration -- */

static void test_duration(void)
{
	section("parse_duration (maintenance window)");
	CHECK(parse_duration("30s") == 30, "30s -> 30");
	CHECK(parse_duration("5m") == 300, "5m -> 300");
	CHECK(parse_duration("1h") == 3600, "1h -> 3600");
	CHECK(parse_duration("45") == 45, "45 -> 45 (bare seconds)");
	CHECK(parse_duration("0") == -1, "0 rejected");
	CHECK(parse_duration("-5m") == -1, "negative rejected");
	CHECK(parse_duration("5x") == -1, "unknown unit rejected");
	CHECK(parse_duration("m") == -1, "unit without number rejected");
}

/* ---------------------------------------------------------------- policy -- */

static void test_policy(void)
{
	section("policy parsing and validation");
	char p[EG_MAX_PATH];
	struct eg_policy pol;

	path_join(p, sizeof(p), g_root, "data/policies/audit-rollout.conf");
	CHECK(eg_policy_load(p, &pol) == 0 && !pol.enforce &&
	      pol.protect_patterns.count == 3 && pol.trust_paths.count == 3,
	      "audit-rollout.conf: MODE audit, 3 PROTECT, 3 TRUST");
	eg_policy_free(&pol);

	path_join(p, sizeof(p), g_root, "data/policies/system-enforce.conf");
	CHECK(eg_policy_load(p, &pol) == 0 && pol.enforce, "system-enforce.conf: MODE enforce");
	eg_policy_free(&pol);

	path_join(p, sizeof(p), g_root, "data/policies/empty-but-valid.conf");
	CHECK(eg_policy_load(p, &pol) == 0 && pol.enforce &&
	      pol.protect_patterns.count == 0,
	      "empty policy loads and defaults to enforce (secure default)");
	eg_policy_free(&pol);

	static const char *bad[] = {
		"unknown-directive.conf", "bad-mode.conf",
		"missing-argument.conf", "bad-deny-selector.conf",
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		char rel[256];
		snprintf(rel, sizeof(rel), "data/policies/invalid/%s", bad[i]);
		path_join(p, sizeof(p), g_root, rel);
		int lr = eg_policy_load(p, &pol);
		CHECK(lr == -EINVAL, "invalid/%s rejected by loader", bad[i]);
	}

	CHECK(eg_policy_load("/nonexistent/execguard.conf", &pol) == -ENOENT,
	      "missing policy file returns -ENOENT");

	section("parse_line edge cases");
	struct eg_policy s = { .enforce = true };
	char l1[] = "   PROTECT\t/usr/bin/x   \n";
	CHECK(parse_line(l1, &s) == 0 && s.protect_patterns.count == 1 &&
	      strcmp(s.protect_patterns.items[0], "/usr/bin/x") == 0,
	      "surrounding whitespace and tab separator are trimmed");
	char l2[] = "# PROTECT /x";
	CHECK(parse_line(l2, &s) == 1, "comment line is skipped");
	char l3[] = "    ";
	CHECK(parse_line(l3, &s) == 1, "blank line is skipped");
	char l4[] = "protect /x";
	CHECK(parse_line(l4, &s) == -EINVAL, "directives are case-sensitive");
	char l5[] = "DENY user=mallory";
	CHECK(parse_line(l5, &s) == 0 && s.deny_users.count == 1 &&
	      strcmp(s.deny_users.items[0], "mallory") == 0,
	      "DENY user=<name> stores the user name");
	char l6[] = "MODE audit";
	CHECK(parse_line(l6, &s) == 0 && !s.enforce, "MODE audit clears enforce");
	eg_policy_free(&s);
}

static void test_expand(void)
{
	section("glob expansion over data/fixtures/sandbox");
	char p[EG_MAX_PATH];
	struct eg_policy pol;
	struct eg_str_list files;

	path_join(p, sizeof(p), g_scratch, "fixtures.conf");
	if (eg_policy_load(p, &pol) != 0) {
		CHECK(0, "fixtures.conf loads");
		return;
	}
	eg_policy_expand_protected(&pol, &files);
	CHECK(files.count == 3, "exactly 3 executables expanded (got %zu)", files.count);

	int app = 0, tool = 0, elf = 0, readme = 0, missing = 0;
	for (size_t i = 0; i < files.count; i++) {
		const char *f = files.items[i];
		app     += strstr(f, "/bin/app") != NULL;
		tool    += strstr(f, "/bin/tool.sh") != NULL;
		elf     += strstr(f, "/bin/elf-noexec") != NULL;
		readme  += strstr(f, "readme.txt") != NULL;
		missing += strstr(f, "/bin/missing") != NULL;
	}
	CHECK(app == 1 && tool == 1 && elf == 1, "bin/app, bin/tool.sh, bin/elf-noexec included");
	CHECK(readme == 0, "lib/readme.txt excluded (not executable)");
	CHECK(missing == 0, "bin/missing excluded (does not exist)");
	CHECK(pol.trust_paths.count == 1, "one TRUST entry parsed");

	eg_str_list_free(&files);
	eg_policy_free(&pol);
}

/* ------------------------------------------------------------- integrity -- */

static void test_integrity(void)
{
	section("integrity baseline and verification");
	char base[EG_MAX_PATH], a[EG_MAX_PATH], b[EG_MAX_PATH];
	struct eg_str_list files = {0};
	int ok, changed, missing;

	path_join(base, sizeof(base), g_scratch, "state/baseline.jsonl");
	path_join(a, sizeof(a), g_scratch, "integ-a");
	path_join(b, sizeof(b), g_scratch, "integ-b");
	write_file(a, "#!/bin/sh\necho a\n");
	write_file(b, "#!/bin/sh\necho b\n");
	eg_str_list_add(&files, a);
	eg_str_list_add(&files, b);
	eg_str_list_add(&files, "/nonexistent/execguard");

	CHECK(eg_integrity_baseline(base, &files) == 2,
	      "baseline records 2 files and skips the unreadable one");
	CHECK(eg_integrity_verify(base, &ok, &changed, &missing) == 0 &&
	      ok == 2 && changed == 0 && missing == 0,
	      "fresh scan: 2 ok, 0 changed, 0 missing");
	CHECK(eg_integrity_verify_one(base, a) == 0, "verify_one: unchanged file -> 0");

	write_file(a, "#!/bin/sh\necho tampered\n");
	CHECK(eg_integrity_verify_one(base, a) == 1, "verify_one: modified file -> 1");
	unlink(b);
	CHECK(eg_integrity_verify(base, &ok, &changed, &missing) == 1 &&
	      ok == 0 && changed == 1 && missing == 1,
	      "after tamper+delete: 0 ok, 1 changed, 1 missing");
	CHECK(eg_integrity_verify_one(base, "/not/in/baseline") == 2,
	      "verify_one: path absent from baseline -> 2");
	CHECK(eg_integrity_verify("/nonexistent/baseline", &ok, &changed, &missing) == -ENOENT,
	      "missing baseline file -> -ENOENT");

	eg_str_list_free(&files);
}

/* --------------------------------------------------------- daemon mirror -- */

static void test_mirror(void)
{
	section("daemon path mirror (reload idempotence)");
	struct eg_file_key a = { .dev = 1, .ino = 100 }, b = { .dev = 1, .ino = 200 };

	prot_mirror_add(&a, "/opt/a");
	prot_mirror_add(&b, "/opt/b");
	prot_mirror_add(&a, "/opt/a");          /* simulated RELOAD */
	prot_mirror_add(&b, "/opt/b-renamed");  /* same inode, new name */
	CHECK(G.prot_n == 2, "re-adding known inodes does not grow the mirror (n=%zu)", G.prot_n);
	CHECK(prot_mirror_path(1, 200) && !strcmp(prot_mirror_path(1, 200), "/opt/b-renamed"),
	      "re-adding refreshes the stored path");
	CHECK(prot_mirror_path(1, 999) == NULL, "unknown inode resolves to NULL");
	free(G.prot);
	G.prot = NULL;
	G.prot_n = G.prot_cap = 0;
}

/* ------------------------------------------------------------------ main -- */

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <repo-root> <scratch-dir>\n", argv[0]);
		return 2;
	}
	g_root = argv[1];
	g_scratch = argv[2];

	printf("ExecGuard userspace core unit tests\n");
	test_abi_layout();
	test_kdev();
	test_sha256();
	test_is_executable();
	test_json();
	test_names();
	test_duration();
	test_policy();
	test_expand();
	test_integrity();
	test_mirror();

	printf("\ncore: %d checks, %d passed, %d failed\n", t_run, t_run - t_fail, t_fail);
	return t_fail ? 1 : 0;
}
