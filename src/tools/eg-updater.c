// SPDX-License-Identifier: GPL-2.0
/*
 * eg-updater - a minimal, purpose-built "authorized updater" for demos/tests.
 *
 * Why this exists as a compiled ELF rather than a shell script:
 * ExecGuard identifies a trusted updater by the INODE of the executable image
 * the calling task is running (task->mm->exe_file). When you run a shell
 * script, the running executable is the interpreter (e.g. /usr/bin/bash), not
 * the script. Trusting a script would therefore mean trusting bash for every
 * process on the system - far too broad. A dedicated ELF gives the trust a
 * single, narrow inode identity. See docs/design-decisions.md.
 *
 * Usage: eg-updater <target-file> <string-to-write>
 * It opens the target for writing and replaces its contents. If ExecGuard has
 * this binary's inode in the trusted map, the write is ALLOWED even though the
 * target is protected.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <target-file> <content>\n", argv[0]);
		return 2;
	}

	int fd = open(argv[1], O_WRONLY | O_TRUNC | O_CREAT, 0755);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	size_t len = strlen(argv[2]);
	ssize_t w = write(fd, argv[2], len);
	if (w < 0 || (size_t)w != len) {
		perror("write");
		close(fd);
		return 1;
	}

	close(fd);
	printf("eg-updater: updated %s (%zu bytes)\n", argv[1], len);
	return 0;
}
