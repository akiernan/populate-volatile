/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "unity.h"
#include "pv/config.h"
#include "pv/ops.h"
#include "pv/path.h"

/*
 * All tests operate inside a temporary directory (tmpbase / tmpfd).
 * ctx.rootdir points to tmpbase; ctx.rootfd = tmpfd.
 *
 * We resolve the current process's uid/gid to names via getpwuid/getgrgid
 * and use those throughout so that chown() succeeds without root privileges.
 */

static char    tmpbase[PATH_MAX];
static int     tmpfd = -1;
static pv_ctx_t ctx;
static char    test_user[LOGIN_NAME_MAX];
static char    test_group[LOGIN_NAME_MAX];

void setUp(void)
{
	pv_saved_umask = umask(0);

	/* Resolve current uid/gid to names so chown() succeeds without root. */
	if (test_user[0] == '\0') {
		struct passwd *pw = getpwuid(getuid());
		if (pw == NULL)
			err(1, "getpwuid");
		strncpy(test_user, pw->pw_name, sizeof(test_user) - 1);

		struct group *gr = getgrgid(getgid());
		if (gr == NULL)
			err(1, "getgrgid");
		strncpy(test_group, gr->gr_name, sizeof(test_group) - 1);
	}

	snprintf(tmpbase, sizeof(tmpbase), "/tmp/pv_ops_test_XXXXXX");
	if (mkdtemp(tmpbase) == NULL)
		err(1, "mkdtemp");

	tmpfd = open(tmpbase, O_RDONLY | O_DIRECTORY);
	if (tmpfd == -1)
		err(1, "open tmpbase");

	ctx.rootfd      = tmpfd;
	ctx.rootdir     = tmpbase;
	ctx.verbose     = 0;
	ctx.dry_run     = 0;
	ctx.rootfs_mode = 0;
}

void tearDown(void)
{
	if (tmpfd != -1) {
		close(tmpfd);
		tmpfd = -1;
	}
	pv_rmtree(AT_FDCWD, tmpbase);
	umask(022);
}

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static pv_entry_t make_entry(pv_type_t type, const char *user,
                             const char *group, mode_t mode,
                             const char *name, const char *ltarget)
{
	pv_entry_t e;
	memset(&e, 0, sizeof(e));
	e.type = type;
	strcpy(e.user,    user);
	strcpy(e.group,   group);
	e.mode = mode;
	strcpy(e.name,    name);
	if (ltarget)
		strcpy(e.ltarget, ltarget);
	return e;
}

/* -------------------------------------------------------------------------
 * pv_create_file tests
 * ---------------------------------------------------------------------- */

static void test_create_file_empty(void)
{
	pv_entry_t e = make_entry(PV_TYPE_FILE, test_user, test_group,
	                           0644, "/newfile", NULL);
	int r = pv_create_file(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "newfile", &st, AT_SYMLINK_NOFOLLOW));
	TEST_ASSERT_TRUE(S_ISREG(st.st_mode));
	TEST_ASSERT_EQUAL_UINT(0644, st.st_mode & 07777);
	TEST_ASSERT_EQUAL_UINT(0, st.st_size);
}

static void test_create_file_copy_source(void)
{
	/* Create source file at <rootdir>/source.txt with known content */
	int srcfd = openat(tmpfd, "source.txt", O_WRONLY | O_CREAT, 0644);
	const char *content = "hello world\n";
	write(srcfd, content, strlen(content));
	close(srcfd);

	/*
	 * ltarget is an absolute path within the rootdir.  ops.c strips the
	 * leading '/' and opens it relative to ctx->rootfd, so "/source.txt"
	 * resolves to <rootdir>/source.txt — which is where we created it.
	 */
	pv_entry_t e = make_entry(PV_TYPE_FILE, test_user, test_group,
	                           0644, "/dest.txt", "/source.txt");
	int r = pv_create_file(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	/* Read back and verify */
	int dstfd = openat(tmpfd, "dest.txt", O_RDONLY);
	TEST_ASSERT_NOT_EQUAL(-1, dstfd);
	char buf[64];
	ssize_t n = read(dstfd, buf, sizeof(buf) - 1);
	buf[n] = '\0';
	close(dstfd);
	TEST_ASSERT_EQUAL_STRING("hello world\n", buf);
}

static void test_create_file_skips_existing(void)
{
	/* Pre-create the target */
	int fd = openat(tmpfd, "exists", O_WRONLY | O_CREAT, 0644);
	write(fd, "original", 8);
	close(fd);

	pv_entry_t e = make_entry(PV_TYPE_FILE, test_user, test_group,
	                           0644, "/exists", NULL);
	int r = pv_create_file(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	/* File must still have original content */
	fd = openat(tmpfd, "exists", O_RDONLY);
	char buf[16];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	buf[n] = '\0';
	close(fd);
	TEST_ASSERT_EQUAL_STRING("original", buf);
}

static void test_create_file_dry_run(void)
{
	pv_ctx_t dry_ctx = ctx;
	dry_ctx.dry_run = 1;
	dry_ctx.verbose = 1;

	pv_entry_t e = make_entry(PV_TYPE_FILE, test_user, test_group,
	                           0644, "/dryfile", NULL);
	int r = pv_create_file(&dry_ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	/* File must NOT have been created */
	struct stat st;
	TEST_ASSERT_EQUAL_INT(-1, fstatat(tmpfd, "dryfile", &st, 0));
	TEST_ASSERT_EQUAL_INT(ENOENT, errno);
}

/* -------------------------------------------------------------------------
 * pv_mkdir tests
 * ---------------------------------------------------------------------- */

static void test_mkdir_creates_dir(void)
{
	pv_entry_t e = make_entry(PV_TYPE_DIR, test_user, test_group,
	                           0755, "/mydir", NULL);
	int r = pv_mkdir(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "mydir", &st, 0));
	TEST_ASSERT_TRUE(S_ISDIR(st.st_mode));
	TEST_ASSERT_EQUAL_UINT(0755, st.st_mode & 07777);
}

static void test_mkdir_creates_deep(void)
{
	pv_entry_t e = make_entry(PV_TYPE_DIR, test_user, test_group,
	                           0700, "/deep/nested/dir", NULL);
	int r = pv_mkdir(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "deep/nested/dir", &st, 0));
	TEST_ASSERT_TRUE(S_ISDIR(st.st_mode));
}

static void test_mkdir_skips_existing(void)
{
	mkdirat(tmpfd, "prexist", 0700);

	pv_entry_t e = make_entry(PV_TYPE_DIR, test_user, test_group,
	                           0755, "/prexist", NULL);
	int r = pv_mkdir(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	/* Mode should NOT have been changed (skipped) */
	struct stat st;
	fstatat(tmpfd, "prexist", &st, 0);
	TEST_ASSERT_EQUAL_UINT(0700, st.st_mode & 07777);
}

static void test_mkdir_dry_run(void)
{
	pv_ctx_t dry_ctx = ctx;
	dry_ctx.dry_run = 1;
	dry_ctx.verbose = 1;

	pv_entry_t e = make_entry(PV_TYPE_DIR, test_user, test_group,
	                           0755, "/drydir", NULL);
	int r = pv_mkdir(&dry_ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(-1, fstatat(tmpfd, "drydir", &st, 0));
	TEST_ASSERT_EQUAL_INT(ENOENT, errno);
}

/* -------------------------------------------------------------------------
 * pv_link_file tests
 * ---------------------------------------------------------------------- */

static void test_link_file_create_new(void)
{
	/* Ensure parent directory of name exists */
	pv_mkdirtree(tmpfd, "var", 0755);

	pv_entry_t e = make_entry(PV_TYPE_LINK, test_user, test_group,
	                           0755, "/var/run", "/var/volatile/run");
	int r = pv_link_file(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "var/run", &st,
	                                  AT_SYMLINK_NOFOLLOW));
	TEST_ASSERT_TRUE(S_ISLNK(st.st_mode));

	char target[256];
	ssize_t len = readlinkat(tmpfd, "var/run", target, sizeof(target) - 1);
	target[len] = '\0';
	TEST_ASSERT_EQUAL_STRING("/var/volatile/run", target);
}

static void test_link_file_correct_existing(void)
{
	pv_mkdirtree(tmpfd, "var", 0755);
	symlinkat("/var/volatile/log", tmpfd, "var/log");

	pv_entry_t e = make_entry(PV_TYPE_LINK, test_user, test_group,
	                           0755, "/var/log", "/var/volatile/log");
	int r = pv_link_file(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	/* Symlink still exists and still points to the right place */
	char target[256];
	ssize_t len = readlinkat(tmpfd, "var/log", target, sizeof(target) - 1);
	target[len] = '\0';
	TEST_ASSERT_EQUAL_STRING("/var/volatile/log", target);
}

static void test_link_file_wrong_existing(void)
{
	pv_mkdirtree(tmpfd, "var", 0755);
	symlinkat("/wrong/target", tmpfd, "var/log");

	pv_entry_t e = make_entry(PV_TYPE_LINK, test_user, test_group,
	                           0755, "/var/log", "/var/volatile/log");
	int r = pv_link_file(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	char target[256];
	ssize_t len = readlinkat(tmpfd, "var/log", target, sizeof(target) - 1);
	target[len] = '\0';
	TEST_ASSERT_EQUAL_STRING("/var/volatile/log", target);
}

static void test_link_file_migrate_directory(void)
{
	/*
	 * Set up: /var/log is a real directory with a file inside.
	 * After pv_link_file(), /var/log should be a symlink to
	 * /var/volatile/log, and the file should have been copied there.
	 */
	pv_mkdirtree(tmpfd, "var/log", 0755);
	int fd = openat(tmpfd, "var/log/messages", O_WRONLY | O_CREAT, 0644);
	write(fd, "log content", 11);
	close(fd);

	/* Ensure the target volatile directory exists */
	pv_mkdirtree(tmpfd, "var/volatile/log", 0755);

	pv_entry_t e = make_entry(PV_TYPE_LINK, test_user, test_group,
	                           0755, "/var/log", "/var/volatile/log");
	int r = pv_link_file(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	/* var/log must now be a symlink */
	struct stat st;
	TEST_ASSERT_EQUAL_INT(0, fstatat(tmpfd, "var/log", &st,
	                                  AT_SYMLINK_NOFOLLOW));
	TEST_ASSERT_TRUE(S_ISLNK(st.st_mode));

	/* The copied file must exist in the target */
	TEST_ASSERT_EQUAL_INT(0,
	    fstatat(tmpfd, "var/volatile/log/messages", &st, 0));
}

static void test_link_file_dry_run_new(void)
{
	pv_ctx_t dry_ctx = ctx;
	dry_ctx.dry_run = 1;
	dry_ctx.verbose = 1;

	pv_mkdirtree(tmpfd, "var", 0755);

	pv_entry_t e = make_entry(PV_TYPE_LINK, test_user, test_group,
	                           0755, "/var/run", "/var/volatile/run");
	int r = pv_link_file(&dry_ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	/* Symlink must NOT have been created */
	struct stat st;
	TEST_ASSERT_EQUAL_INT(-1, fstatat(tmpfd, "var/run", &st,
	                                   AT_SYMLINK_NOFOLLOW));
}

static void test_link_file_dry_run_migrate(void)
{
	pv_ctx_t dry_ctx = ctx;
	dry_ctx.dry_run = 1;
	dry_ctx.verbose = 1;

	pv_mkdirtree(tmpfd, "var/log", 0755);
	int fd = openat(tmpfd, "var/log/messages", O_WRONLY | O_CREAT, 0644);
	close(fd);
	pv_mkdirtree(tmpfd, "var/volatile/log", 0755);

	pv_entry_t e = make_entry(PV_TYPE_LINK, test_user, test_group,
	                           0755, "/var/log", "/var/volatile/log");
	int r = pv_link_file(&dry_ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	/* var/log must still be a directory (not migrated) */
	struct stat st;
	fstatat(tmpfd, "var/log", &st, AT_SYMLINK_NOFOLLOW);
	TEST_ASSERT_TRUE(S_ISDIR(st.st_mode));
}

/* -------------------------------------------------------------------------
 * pv_bind_mount tests (dry-run and rootfs-mode paths; no mount needed)
 * ---------------------------------------------------------------------- */

static void test_bind_mount_dry_run(void)
{
	pv_ctx_t dry_ctx = ctx;
	dry_ctx.dry_run = 1;
	dry_ctx.verbose = 1;

	pv_entry_t e = make_entry(PV_TYPE_BIND, test_user, test_group,
	                           0755, "/bmdst", "/bmsrc");
	int r = pv_bind_mount(&dry_ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	/* Must not have been mounted */
	char dst[PATH_MAX];
	snprintf(dst, sizeof(dst), "%s/bmdst", tmpbase);
	TEST_ASSERT_EQUAL_INT(0, pv_is_mounted(dst));
}

static void test_bind_mount_rootfs_mode(void)
{
	pv_ctx_t rfs_ctx = ctx;
	rfs_ctx.rootfs_mode = 1;
	rfs_ctx.verbose     = 1;

	pv_entry_t e = make_entry(PV_TYPE_BIND, test_user, test_group,
	                           0755, "/rfdst", "/rfsrc");
	int r = pv_bind_mount(&rfs_ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	char dst[PATH_MAX];
	snprintf(dst, sizeof(dst), "%s/rfdst", tmpbase);
	TEST_ASSERT_EQUAL_INT(0, pv_is_mounted(dst));
}

/* -------------------------------------------------------------------------
 * pv_apply_entry dispatch tests
 * ---------------------------------------------------------------------- */

static void test_apply_entry_dispatches_file(void)
{
	pv_entry_t e = make_entry(PV_TYPE_FILE, test_user, test_group,
	                           0644, "/dispatch_file", NULL);
	int r = pv_apply_entry(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(0,
	    fstatat(tmpfd, "dispatch_file", &st, AT_SYMLINK_NOFOLLOW));
	TEST_ASSERT_TRUE(S_ISREG(st.st_mode));
}

static void test_apply_entry_dispatches_dir(void)
{
	pv_entry_t e = make_entry(PV_TYPE_DIR, test_user, test_group,
	                           0755, "/dispatch_dir", NULL);
	int r = pv_apply_entry(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(0,
	    fstatat(tmpfd, "dispatch_dir", &st, 0));
	TEST_ASSERT_TRUE(S_ISDIR(st.st_mode));
}

static void test_apply_entry_dispatches_link(void)
{
	pv_mkdirtree(tmpfd, "lnkdir", 0755);
	pv_entry_t e = make_entry(PV_TYPE_LINK, test_user, test_group,
	                           0755, "/lnkdir/run", "/lnkdir/volatile/run");
	int r = pv_apply_entry(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	struct stat st;
	TEST_ASSERT_EQUAL_INT(0,
	    fstatat(tmpfd, "lnkdir/run", &st, AT_SYMLINK_NOFOLLOW));
	TEST_ASSERT_TRUE(S_ISLNK(st.st_mode));
}

static void test_apply_entry_dispatches_bind_dry_run(void)
{
	pv_ctx_t dry_ctx = ctx;
	dry_ctx.dry_run = 1;
	dry_ctx.verbose = 1;

	pv_entry_t e = make_entry(PV_TYPE_BIND, test_user, test_group,
	                           0755, "/addst", "/adsrc");
	int r = pv_apply_entry(&dry_ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);

	char dst[PATH_MAX];
	snprintf(dst, sizeof(dst), "%s/addst", tmpbase);
	TEST_ASSERT_EQUAL_INT(0, pv_is_mounted(dst));
}

static void test_apply_entry_follows_symlink_for_file(void)
{
	/*
	 * If entry->name is itself a symlink, apply_entry should resolve it
	 * and create the file at the resolved location.
	 *
	 * Setup: /real -> /actual_dir (symlink)
	 *        entry: f ... /real/file
	 * Expected: /actual_dir/file is created.
	 */
	pv_mkdirtree(tmpfd, "actual_dir", 0755);
	symlinkat("actual_dir", tmpfd, "real"); /* /real -> actual_dir (relative) */

	/* The config says to create /real/file, but /real is a symlink */
	pv_entry_t e = make_entry(PV_TYPE_FILE, test_user, test_group,
	                           0644, "/real/target_file", NULL);
	/* We need parent to exist - real/target_file -> actual_dir/target_file */
	/* Since /real is a symlink to actual_dir, the kernel follows it */
	int r = pv_apply_entry(&ctx, &e);
	TEST_ASSERT_EQUAL_INT(0, r);
}

/* -------------------------------------------------------------------------
 * Test runner
 * ---------------------------------------------------------------------- */

int main(void)
{
	UNITY_BEGIN();

	RUN_TEST(test_create_file_empty);
	RUN_TEST(test_create_file_copy_source);
	RUN_TEST(test_create_file_skips_existing);
	RUN_TEST(test_create_file_dry_run);
	RUN_TEST(test_mkdir_creates_dir);
	RUN_TEST(test_mkdir_creates_deep);
	RUN_TEST(test_mkdir_skips_existing);
	RUN_TEST(test_mkdir_dry_run);
	RUN_TEST(test_link_file_create_new);
	RUN_TEST(test_link_file_correct_existing);
	RUN_TEST(test_link_file_wrong_existing);
	RUN_TEST(test_link_file_migrate_directory);
	RUN_TEST(test_link_file_dry_run_new);
	RUN_TEST(test_link_file_dry_run_migrate);
	RUN_TEST(test_bind_mount_dry_run);
	RUN_TEST(test_bind_mount_rootfs_mode);
	RUN_TEST(test_apply_entry_dispatches_file);
	RUN_TEST(test_apply_entry_dispatches_dir);
	RUN_TEST(test_apply_entry_dispatches_link);
	RUN_TEST(test_apply_entry_dispatches_bind_dry_run);
	RUN_TEST(test_apply_entry_follows_symlink_for_file);

	return UNITY_END();
}
