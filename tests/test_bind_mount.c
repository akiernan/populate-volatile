/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Integration tests for pv_bind_mount.
 *
 * These tests call mount(MS_BIND) and therefore require CAP_SYS_ADMIN.
 * When the capability is absent the binary exits with code 77, which meson
 * and automake both treat as "SKIP".
 *
 * Run via:  meson test -C build --print-errorlogs bind_mount
 * Or in a privileged container where all tests run normally.
 */
#define _POSIX_C_SOURCE 200809L

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "unity.h"
#include "pv/config.h"
#include "pv/ops.h"
#include "pv/path.h"

/* Exit code 77 is the TAP/automake "skip" convention; meson honours it. */
#define EXIT_SKIP 77

static char    tmpbase[PATH_MAX];
static char    dst_full[PATH_MAX]; /* absolute path of dst dir for pv_is_mounted */
static int     rootfd = -1;
static pv_ctx_t ctx;

void setUp(void)
{
	pv_saved_umask = umask(0);

	snprintf(tmpbase, sizeof(tmpbase), "/tmp/pv_bm_XXXXXX");
	if (mkdtemp(tmpbase) == NULL)
		err(1, "mkdtemp");

	/*
	 * Canonicalise tmpbase so ctx.rootdir and dst_full use the real path.
	 * The kernel resolves symlinks when recording mount points in
	 * /proc/self/mountinfo, so pv_is_mounted() must compare against the
	 * same canonical path (e.g. /tmp may be a symlink to /run/tmp).
	 */
	char resolved[PATH_MAX];
	if (realpath(tmpbase, resolved) == NULL)
		err(1, "realpath");
	snprintf(tmpbase, sizeof(tmpbase), "%s", resolved);

	rootfd = open(tmpbase, O_RDONLY | O_DIRECTORY);
	if (rootfd == -1)
		err(1, "open tmpbase");

	/* Create src and dst directories inside the temp tree. */
	if (pv_mkdirtree(rootfd, "src", 0755) == -1 ||
	    pv_mkdirtree(rootfd, "dst", 0755) == -1)
		err(1, "pv_mkdirtree");

	snprintf(dst_full, sizeof(dst_full), "%s/dst", tmpbase);

	ctx.rootfd      = rootfd;
	ctx.rootdir     = tmpbase;
	ctx.verbose     = 0;
	ctx.dry_run     = 0;
	ctx.rootfs_mode = 0;
}

void tearDown(void)
{
	/* Detach any bind mount before removing the temp tree. */
	if (pv_is_mounted(dst_full) == 1)
		umount2(dst_full, MNT_DETACH);

	if (rootfd != -1) {
		close(rootfd);
		rootfd = -1;
	}
	pv_rmtree(AT_FDCWD, tmpbase);
	umask(022);
}

/* -------------------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------------- */

static void test_bind_mount_creates_mount(void)
{
	pv_entry_t e;
	memset(&e, 0, sizeof(e));
	e.type = PV_TYPE_BIND;
	strcpy(e.name,    "/dst");
	strcpy(e.ltarget, "/src");

	int r = pv_bind_mount(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_INT(1, pv_is_mounted(dst_full));
}

static void test_apply_entry_dispatches_bind(void)
{
	pv_entry_t e;
	memset(&e, 0, sizeof(e));
	e.type = PV_TYPE_BIND;
	strcpy(e.user,    "root");
	strcpy(e.group,   "root");
	e.mode = 0755;
	strcpy(e.name,    "/dst");
	strcpy(e.ltarget, "/src");

	int r = pv_apply_entry(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_INT(1, pv_is_mounted(dst_full));
}

/* -------------------------------------------------------------------------
 * Test runner
 * ---------------------------------------------------------------------- */

int main(void)
{
	/*
	 * Privilege check: attempt a small tmpfs mount on a throw-away
	 * directory.  Exit with EXIT_SKIP when CAP_SYS_ADMIN is absent so
	 * that meson reports the test as skipped rather than failed.
	 */
	char canary[PATH_MAX];
	snprintf(canary, sizeof(canary), "/tmp/pv_cap_XXXXXX");
	if (mkdtemp(canary) == NULL)
		err(1, "mkdtemp(canary)");

	int rc = mount("none", canary, "tmpfs", 0, "size=4k");
	int saved_errno = errno;
	if (rc == 0)
		umount2(canary, MNT_DETACH);
	rmdir(canary);

	if (rc == -1) {
		if (saved_errno == EPERM || saved_errno == EACCES) {
			fprintf(stderr,
			        "SKIP: CAP_SYS_ADMIN not available\n");
			return EXIT_SKIP;
		}
		errno = saved_errno;
		err(1, "capability check: unexpected mount error");
	}

	UNITY_BEGIN();
	RUN_TEST(test_bind_mount_creates_mount);
	RUN_TEST(test_apply_entry_dispatches_bind);
	return UNITY_END();
}
