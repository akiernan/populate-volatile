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
/* tmpbase plus a short suffix: headroom keeps -Wformat-truncation happy */
static char    dst_full[PATH_MAX + 16];
static char    dstfile_full[PATH_MAX + 16];
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

	/*
	 * Regular files for the file-bind-mount test.  A file bind mount
	 * requires the destination to already exist as a regular file, so
	 * both are created up front.
	 */
	int fd = openat(rootfd, "srcfile", O_CREAT | O_WRONLY, 0644);
	if (fd == -1)
		err(1, "openat srcfile");
	close(fd);
	fd = openat(rootfd, "dstfile", O_CREAT | O_WRONLY, 0644);
	if (fd == -1)
		err(1, "openat dstfile");
	close(fd);

	snprintf(dst_full, sizeof(dst_full), "%s/dst", tmpbase);
	snprintf(dstfile_full, sizeof(dstfile_full), "%s/dstfile", tmpbase);

	ctx.rootfd      = rootfd;
	ctx.rootdir     = tmpbase;
	ctx.verbose     = 0;
	ctx.dry_run     = 0;
	ctx.rootfs_mode = 0;
}

void tearDown(void)
{
	/*
	 * Detach any bind mount before removing the temp tree.  Loop, since a
	 * test may intentionally stack mounts; one detach would leave a layer
	 * behind and block pv_rmtree.
	 */
	while (pv_is_mounted(dst_full) == 1)
		if (umount2(dst_full, MNT_DETACH) == -1)
			break;
	while (pv_is_mounted(dstfile_full) == 1)
		if (umount2(dstfile_full, MNT_DETACH) == -1)
			break;

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

static void test_bind_mount_idempotent(void)
{
	pv_entry_t e;
	memset(&e, 0, sizeof(e));
	e.type = PV_TYPE_BIND;
	strcpy(e.name,    "/dst");
	strcpy(e.ltarget, "/src");

	TEST_ASSERT_EQUAL_INT(0, pv_bind_mount(&ctx, &e));
	TEST_ASSERT_EQUAL_INT(0, pv_bind_mount(&ctx, &e));

	/*
	 * If the second call stacked another mount, one umount would leave
	 * the destination still mounted.
	 */
	TEST_ASSERT_EQUAL_INT(0, umount2(dst_full, MNT_DETACH));
	TEST_ASSERT_EQUAL_INT(0, pv_is_mounted(dst_full));
}

static void test_bind_mount_file_idempotent(void)
{
	pv_entry_t e;
	memset(&e, 0, sizeof(e));
	e.type = PV_TYPE_BIND;
	strcpy(e.name,    "/dstfile");
	strcpy(e.ltarget, "/srcfile");

	/*
	 * A file bind mount (regular file onto regular file) must be detected
	 * as already-mounted on the second call, exactly like a directory
	 * mount.  statx() reports STATX_ATTR_MOUNT_ROOT on the file's own
	 * inode and mountinfo records the file path in field 5, so neither
	 * detection path depends on the mountpoint being a directory.
	 */
	TEST_ASSERT_EQUAL_INT(0, pv_bind_mount(&ctx, &e));
	TEST_ASSERT_EQUAL_INT(1, pv_is_mounted(dstfile_full));
	TEST_ASSERT_EQUAL_INT(0, pv_bind_mount(&ctx, &e));

	/*
	 * If the second call stacked another mount, one umount would leave
	 * the destination still mounted.
	 */
	TEST_ASSERT_EQUAL_INT(0, umount2(dstfile_full, MNT_DETACH));
	TEST_ASSERT_EQUAL_INT(0, pv_is_mounted(dstfile_full));
}

static void test_bind_mount_stacks_on_wrong_source(void)
{
	pv_entry_t e;
	char src_full[sizeof(tmpbase) + 16];
	char src2_full[sizeof(tmpbase) + 16];

	if (pv_mkdirtree(rootfd, "src2", 0755) == -1)
		err(1, "pv_mkdirtree src2");
	snprintf(src_full,  sizeof(src_full),  "%s/src",  tmpbase);
	snprintf(src2_full, sizeof(src2_full), "%s/src2", tmpbase);

	/* First bind: /src -> /dst */
	memset(&e, 0, sizeof(e));
	e.type = PV_TYPE_BIND;
	strcpy(e.name,    "/dst");
	strcpy(e.ltarget, "/src");
	TEST_ASSERT_EQUAL_INT(0, pv_bind_mount(&ctx, &e));

	/* Re-binding the SAME source is a no-op: it must not stack a layer. */
	TEST_ASSERT_EQUAL_INT(0, pv_bind_mount(&ctx, &e));

	/* A DIFFERENT source must NOT be skipped: it stacks on top so the
	 * intended source becomes visible, matching upstream's unconditional
	 * mount. */
	strcpy(e.ltarget, "/src2");
	TEST_ASSERT_EQUAL_INT(0, pv_bind_mount(&ctx, &e));

	/* Top of the stack now resolves to /src2... */
	TEST_ASSERT_EQUAL_INT(1, pv_same_inode(dst_full, src2_full));

	/* ...and a single detach reveals /src still mounted underneath,
	 * proving exactly one extra layer was added (the same-source re-bind
	 * above added none). */
	TEST_ASSERT_EQUAL_INT(0, umount2(dst_full, MNT_DETACH));
	TEST_ASSERT_EQUAL_INT(1, pv_is_mounted(dst_full));
	TEST_ASSERT_EQUAL_INT(1, pv_same_inode(dst_full, src_full));

	/* Final detach clears the original mount. */
	TEST_ASSERT_EQUAL_INT(0, umount2(dst_full, MNT_DETACH));
	TEST_ASSERT_EQUAL_INT(0, pv_is_mounted(dst_full));
}

static void test_is_mounted_mountinfo_file(void)
{
	pv_entry_t e;
	memset(&e, 0, sizeof(e));
	e.type = PV_TYPE_BIND;
	strcpy(e.name,    "/dstfile");
	strcpy(e.ltarget, "/srcfile");
	TEST_ASSERT_EQUAL_INT(0, pv_bind_mount(&ctx, &e));

	/*
	 * Pin the mountinfo fallback directly (not just the statx-preferred
	 * pv_is_mounted) for a file mountpoint: the kernel records the file
	 * path in field 5 exactly like a directory, so the field-5 comparison
	 * must match it.
	 */
	TEST_ASSERT_EQUAL_INT(1, pv_is_mounted_mountinfo(dstfile_full));
}

static void test_is_mounted_via_symlinked_path(void)
{
	pv_entry_t e;
	memset(&e, 0, sizeof(e));
	e.type = PV_TYPE_BIND;
	strcpy(e.name,    "/dst");
	strcpy(e.ltarget, "/src");
	TEST_ASSERT_EQUAL_INT(0, pv_bind_mount(&ctx, &e));

	/*
	 * Query the mountpoint through a symlink: mountinfo records the
	 * canonical path, so a literal comparison would miss it.
	 */
	TEST_ASSERT_EQUAL_INT(0, symlinkat("dst", rootfd, "lnk"));

	char lnk[sizeof(tmpbase) + 16];
	snprintf(lnk, sizeof(lnk), "%s/lnk", tmpbase);

	TEST_ASSERT_EQUAL_INT(1, pv_is_mounted(lnk));
	TEST_ASSERT_EQUAL_INT(1, pv_is_mounted_mountinfo(lnk));
}

static void test_link_file_skips_mounted_dir(void)
{
	pv_entry_t e;

	/* Make dst a mountpoint... */
	memset(&e, 0, sizeof(e));
	e.type = PV_TYPE_BIND;
	strcpy(e.name,    "/dst");
	strcpy(e.ltarget, "/src");
	TEST_ASSERT_EQUAL_INT(0, pv_bind_mount(&ctx, &e));

	/* ...then ask for it to be migrated to a symlink */
	memset(&e, 0, sizeof(e));
	e.type = PV_TYPE_LINK;
	strcpy(e.name,    "/dst");
	strcpy(e.ltarget, "/elsewhere");
	TEST_ASSERT_EQUAL_INT(0, pv_link_file(&ctx, &e));

	/* Still a directory and still mounted - not rmtree'd */
	struct stat st;
	TEST_ASSERT_EQUAL_INT(0, fstatat(rootfd, "dst", &st,
	                                 AT_SYMLINK_NOFOLLOW));
	TEST_ASSERT_TRUE(S_ISDIR(st.st_mode));
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
	RUN_TEST(test_bind_mount_idempotent);
	RUN_TEST(test_bind_mount_file_idempotent);
	RUN_TEST(test_bind_mount_stacks_on_wrong_source);
	RUN_TEST(test_is_mounted_mountinfo_file);
	RUN_TEST(test_is_mounted_via_symlinked_path);
	RUN_TEST(test_link_file_skips_mounted_dir);
	RUN_TEST(test_apply_entry_dispatches_bind);
	return UNITY_END();
}
