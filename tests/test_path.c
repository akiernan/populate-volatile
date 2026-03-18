/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "unity.h"
#include "pv/path.h"

/*
 * Each test creates a fresh temporary directory (tmpbase) and opens a fd
 * to it (tmpfd).  tearDown() removes the tree and closes tmpfd.
 */
static char tmpbase[256];
static int  tmpfd = -1;

void setUp(void)
{
	pv_saved_umask = umask(0);

	snprintf(tmpbase, sizeof(tmpbase), "/tmp/pv_path_test_XXXXXX");
	if (mkdtemp(tmpbase) == NULL)
		err(1, "mkdtemp");

	tmpfd = open(tmpbase, O_RDONLY | O_DIRECTORY);
	if (tmpfd == -1)
		err(1, "open tmpbase");
}

void tearDown(void)
{
	if (tmpfd != -1) {
		pv_rmtree(AT_FDCWD, tmpbase);
		close(tmpfd);
		tmpfd = -1;
	}
	/* Restore default umask */
	umask(022);
}

/* -------------------------------------------------------------------------
 * pv_mkdirtree tests
 * ---------------------------------------------------------------------- */

static void test_mkdirtree_single(void)
{
	int r = pv_mkdirtree(tmpfd, "alpha", 0755);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "alpha", &st, 0));
	TEST_ASSERT_TRUE(S_ISDIR(st.st_mode));
	TEST_ASSERT_EQUAL_UINT(0755, st.st_mode & 07777);
}

static void test_mkdirtree_deep(void)
{
	int r = pv_mkdirtree(tmpfd, "a/b/c/d", 0700);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "a/b/c/d", &st, 0));
	TEST_ASSERT_TRUE(S_ISDIR(st.st_mode));
	TEST_ASSERT_EQUAL_UINT(0700, st.st_mode & 07777);
}

static void test_mkdirtree_idempotent(void)
{
	TEST_ASSERT_EQUAL_INT(0, pv_mkdirtree(tmpfd, "exist", 0755));
	TEST_ASSERT_EQUAL_INT(0, pv_mkdirtree(tmpfd, "exist", 0755));
}

static void test_mkdirtree_intermediate_mode(void)
{
	/*
	 * Intermediate directories get (0777 & ~pv_saved_umask).
	 * setUp() calls umask(0) which saves the old umask into pv_saved_umask,
	 * so we compute the expected mode dynamically rather than hard-coding it.
	 */
	TEST_ASSERT_EQUAL_INT(0, pv_mkdirtree(tmpfd, "p/q/leaf", 0750));

	struct stat st;
	mode_t expected_intermediate = 0777 & ~pv_saved_umask;
	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "p", &st, 0));
	TEST_ASSERT_EQUAL_UINT(expected_intermediate, st.st_mode & 07777);

	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "p/q/leaf", &st, 0));
	TEST_ASSERT_EQUAL_UINT(0750, st.st_mode & 07777);
}

static void test_mkdirtree_leading_slash_ignored(void)
{
	/* Absolute-looking path should be treated relative to dirfd */
	int r = pv_mkdirtree(tmpfd, "/slashed", 0755);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "slashed", &st, 0));
	TEST_ASSERT_TRUE(S_ISDIR(st.st_mode));
}

/* -------------------------------------------------------------------------
 * pv_rmtree tests
 * ---------------------------------------------------------------------- */

static void test_rmtree_flat(void)
{
	/* Create dir with a couple of files */
	mkdirat(tmpfd, "flat", 0755);
	int f = openat(tmpfd, "flat/file1", O_CREAT | O_WRONLY, 0644);
	close(f);
	f = openat(tmpfd, "flat/file2", O_CREAT | O_WRONLY, 0644);
	close(f);

	int r = pv_rmtree(tmpfd, "flat");
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(-1, fstatat(tmpfd, "flat", &st, AT_SYMLINK_NOFOLLOW));
	TEST_ASSERT_EQUAL_INT(ENOENT, errno);
}

static void test_rmtree_nested(void)
{
	/* Create a nested structure */
	pv_mkdirtree(tmpfd, "nest/a/b", 0755);
	int f = openat(tmpfd, "nest/a/b/deep_file", O_CREAT | O_WRONLY, 0644);
	close(f);
	f = openat(tmpfd, "nest/top_file", O_CREAT | O_WRONLY, 0644);
	close(f);

	int r = pv_rmtree(tmpfd, "nest");
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(-1, fstatat(tmpfd, "nest", &st, 0));
}

static void test_rmtree_does_not_follow_symlinks(void)
{
	/* Create a directory and a symlink to something outside */
	mkdirat(tmpfd, "real_target", 0755);
	int f = openat(tmpfd, "real_target/precious", O_CREAT | O_WRONLY, 0644);
	close(f);

	mkdirat(tmpfd, "symdir", 0755);
	/* Create symlink inside symdir pointing to real_target */
	symlinkat("../real_target", tmpfd, "symdir/link");

	int r = pv_rmtree(tmpfd, "symdir");
	TEST_ASSERT_EQUAL_INT(0, r);

	/* real_target should still exist */
	struct stat st;
	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "real_target/precious", &st, 0));
}

/* -------------------------------------------------------------------------
 * pv_readlink_abs tests
 * ---------------------------------------------------------------------- */

static void test_readlink_abs_absolute_target(void)
{
	/* Create symlink: tmpbase/lnk -> /etc/passwd */
	symlinkat("/etc/passwd", tmpfd, "lnk");

	char buf[256];
	int r = pv_readlink_abs(tmpfd, "/lnk", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_STRING("/etc/passwd", buf);
}

static void test_readlink_abs_relative_target(void)
{
	/* Create symlink: tmpbase/var/run -> ../volatile/run */
	pv_mkdirtree(tmpfd, "var", 0755);
	symlinkat("../volatile/run", tmpfd, "var/run");

	char buf[256];
	int r = pv_readlink_abs(tmpfd, "/var/run", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_STRING("/var/../volatile/run", buf);
}

static void test_readlink_abs_toplevel_relative(void)
{
	/* Symlink directly under root: /foo -> bar (relative) */
	symlinkat("bar", tmpfd, "foo");

	char buf[256];
	int r = pv_readlink_abs(tmpfd, "/foo", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_STRING("/bar", buf);
}

static void test_readlink_abs_missing(void)
{
	char buf[256];
	int r = pv_readlink_abs(tmpfd, "/nonexistent", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(-1, r);
}

/* -------------------------------------------------------------------------
 * pv_resolve_path tests
 * ---------------------------------------------------------------------- */

static void test_resolve_path_no_symlinks(void)
{
	/* Plain directory tree with no symlinks: path passes through unchanged */
	pv_mkdirtree(tmpfd, "var/run", 0755);

	char buf[256];
	int r = pv_resolve_path(tmpfd, "/var/run/foo", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_STRING("/var/run/foo", buf);
}

static void test_resolve_path_absolute_intermediate_symlink(void)
{
	/*
	 * Simulate: var/log -> /var/volatile/log  (as in a real OE rootfs).
	 * pv_resolve_path should rewrite /var/log/wtmp
	 * -> /var/volatile/log/wtmp within tmpfd.
	 */
	pv_mkdirtree(tmpfd, "var/volatile/log", 0755);
	symlinkat("/var/volatile/log", tmpfd, "var/log");

	char buf[256];
	int r = pv_resolve_path(tmpfd, "/var/log/wtmp", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_STRING("/var/volatile/log/wtmp", buf);
}

static void test_resolve_path_final_component_not_resolved(void)
{
	/*
	 * When the path itself is the symlink (final component), it must be
	 * returned verbatim — the caller may be creating or inspecting it.
	 */
	pv_mkdirtree(tmpfd, "var", 0755);
	symlinkat("/var/volatile/log", tmpfd, "var/log");

	char buf[256];
	int r = pv_resolve_path(tmpfd, "/var/log", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_STRING("/var/log", buf);
}

static void test_resolve_path_chained_absolute_symlinks(void)
{
	/*
	 * var/run -> /run  and  run -> /var/volatile/run
	 * /var/run/foo should resolve to /var/volatile/run/foo.
	 */
	pv_mkdirtree(tmpfd, "var/volatile/run", 0755);
	symlinkat("/var/volatile/run", tmpfd, "run");
	symlinkat("/run", tmpfd, "var/run");

	char buf[256];
	int r = pv_resolve_path(tmpfd, "/var/run/foo", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_STRING("/var/volatile/run/foo", buf);
}

static void test_resolve_path_nonexistent_intermediate(void)
{
	/*
	 * Intermediate component doesn't exist yet: pass through unchanged
	 * (the subsequent *at() call will produce the real error).
	 */
	char buf[256];
	int r = pv_resolve_path(tmpfd, "/nonexistent/path/file", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_STRING("/nonexistent/path/file", buf);
}

/* -------------------------------------------------------------------------
 * pv_unescape_mountinfo tests
 * ---------------------------------------------------------------------- */

static void test_unescape_space(void)
{
	char s[] = "/tmp/a\\040b";
	pv_unescape_mountinfo(s);
	TEST_ASSERT_EQUAL_STRING("/tmp/a b", s);
}

static void test_unescape_no_escapes(void)
{
	char s[] = "/var/run";
	pv_unescape_mountinfo(s);
	TEST_ASSERT_EQUAL_STRING("/var/run", s);
}

static void test_unescape_multiple(void)
{
	/* Two embedded spaces: /tmp/a b c */
	char s[] = "/tmp/a\\040b\\040c";
	pv_unescape_mountinfo(s);
	TEST_ASSERT_EQUAL_STRING("/tmp/a b c", s);
}

static void test_unescape_other_octal(void)
{
	/* \011 = horizontal tab */
	char s[] = "foo\\011bar";
	pv_unescape_mountinfo(s);
	TEST_ASSERT_EQUAL_STRING("foo\tbar", s);
}

static void test_unescape_backslash_not_octal(void)
{
	/* Backslash not followed by three octal digits is left alone */
	char s[] = "foo\\xbar";
	pv_unescape_mountinfo(s);
	TEST_ASSERT_EQUAL_STRING("foo\\xbar", s);
}

/* -------------------------------------------------------------------------
 * pv_is_mounted tests
 *
 * We cannot easily mount/unmount without root.  Instead, we verify that
 * "/" is always listed in /proc/self/mountinfo, and that a path that is
 * certainly not a mountpoint (our tmpbase) returns 0.
 * ---------------------------------------------------------------------- */

static void test_is_mounted_root(void)
{
	int r = pv_is_mounted("/");
	TEST_ASSERT_EQUAL_INT(1, r);
}

static void test_is_mounted_not_mounted(void)
{
	int r = pv_is_mounted(tmpbase);
	TEST_ASSERT_EQUAL_INT(0, r);
}

/* -------------------------------------------------------------------------
 * Test runner
 * ---------------------------------------------------------------------- */

int main(void)
{
	UNITY_BEGIN();

	RUN_TEST(test_mkdirtree_single);
	RUN_TEST(test_mkdirtree_deep);
	RUN_TEST(test_mkdirtree_idempotent);
	RUN_TEST(test_mkdirtree_intermediate_mode);
	RUN_TEST(test_mkdirtree_leading_slash_ignored);
	RUN_TEST(test_rmtree_flat);
	RUN_TEST(test_rmtree_nested);
	RUN_TEST(test_rmtree_does_not_follow_symlinks);
	RUN_TEST(test_readlink_abs_absolute_target);
	RUN_TEST(test_readlink_abs_relative_target);
	RUN_TEST(test_readlink_abs_toplevel_relative);
	RUN_TEST(test_readlink_abs_missing);
	RUN_TEST(test_resolve_path_no_symlinks);
	RUN_TEST(test_resolve_path_absolute_intermediate_symlink);
	RUN_TEST(test_resolve_path_final_component_not_resolved);
	RUN_TEST(test_resolve_path_chained_absolute_symlinks);
	RUN_TEST(test_resolve_path_nonexistent_intermediate);
	RUN_TEST(test_unescape_space);
	RUN_TEST(test_unescape_no_escapes);
	RUN_TEST(test_unescape_multiple);
	RUN_TEST(test_unescape_other_octal);
	RUN_TEST(test_unescape_backslash_not_octal);
	RUN_TEST(test_is_mounted_root);
	RUN_TEST(test_is_mounted_not_mounted);

	return UNITY_END();
}
