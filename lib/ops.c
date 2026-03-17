/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Filesystem operations: create file, create directory, create/update symlink,
 * bind mount.  All operations are relative to ctx->rootfd so that the binary
 * works correctly both at runtime (rootfd = open("/")) and at rootfs build
 * time (rootfd = open("/path/to/staging/dir")).
 *
 * Rootfs build-time notes:
 *   - Runs under pseudo (https://git.yoctoproject.org/pseudo), which intercepts
 *     chown/chmod/mknod/stat etc. to maintain a fake-root database.  All *at()
 *     metadata calls are therefore safe to make without real root privileges.
 *   - Bind mounts are meaningless during rootfs construction (the staging tree
 *     is not a live filesystem) and pseudo does not wrap mount(2), so 'b'-type
 *     entries are logged and skipped when ctx->rootfs_mode is set.
 *   - Non-fatal errors are suppressed so that do_rootfs does not abort; the
 *     target will re-run the binary at first boot to fix up any gaps.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pv/config.h"
#include "pv/ops.h"
#include "pv/path.h"

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/*
 * Resolve username -> uid and groupname -> gid via getpwnam_r / getgrnam_r.
 *
 * At runtime the process IS the target environment so this is correct
 * directly.  At rootfs build time pseudo sets PSEUDO_PASSWD so that
 * getpwnam_r resolves against the target image rather than the host.
 */
static int resolve_ids(const char *user, const char *group,
                       uid_t *uid, gid_t *gid)
{
	static long pw_bufsz;
	static long gr_bufsz;
	struct passwd pwd, *pwdp;
	struct group  grp, *grpp;
	char *buf;
	int r;

	if (pw_bufsz == 0) {
		pw_bufsz = sysconf(_SC_GETPW_R_SIZE_MAX);
		if (pw_bufsz <= 0)
			pw_bufsz = 4096;
	}
	buf = malloc((size_t)pw_bufsz);
	if (buf == NULL) {
		warn("malloc");
		return -1;
	}
	r = getpwnam_r(user, &pwd, buf, (size_t)pw_bufsz, &pwdp);
	free(buf);
	if (r != 0 || pwdp == NULL) {
		warnx("unknown user '%s'", user);
		return -1;
	}
	*uid = pwdp->pw_uid;

	if (gr_bufsz == 0) {
		gr_bufsz = sysconf(_SC_GETGR_R_SIZE_MAX);
		if (gr_bufsz <= 0)
			gr_bufsz = 4096;
	}
	buf = malloc((size_t)gr_bufsz);
	if (buf == NULL) {
		warn("malloc");
		return -1;
	}
	r = getgrnam_r(group, &grp, buf, (size_t)gr_bufsz, &grpp);
	free(buf);
	if (r != 0 || grpp == NULL) {
		warnx("unknown group '%s'", group);
		return -1;
	}
	*gid = grpp->gr_gid;

	return 0;
}

/*
 * Copy srcfd -> dstfd using a read/write loop.
 * Handles EINTR on both syscalls.
 */
static int copy_fd(int srcfd, int dstfd)
{
	char buf[65536];
	ssize_t nr;

	while ((nr = read(srcfd, buf, sizeof(buf))) > 0) {
		char *p = buf;
		ssize_t remaining = nr;
		while (remaining > 0) {
			ssize_t nw = write(dstfd, p, (size_t)remaining);
			if (nw == -1) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			p += nw;
			remaining -= nw;
		}
	}
	if (nr == -1)
		return -1;
	return 0;
}

/*
 * Apply ownership and permissions to relpath (relative to ctx->rootfd).
 * Errors are warned; in rootfs_mode they are non-fatal (return 0).
 */
static int apply_meta(const pv_ctx_t *ctx, const char *relpath,
                      uid_t uid, gid_t gid, mode_t mode)
{
	int r = 0;

	if (fchownat(ctx->rootfd, relpath, uid, gid, AT_SYMLINK_NOFOLLOW) == -1) {
		warn("chown %u:%u %s", (unsigned)uid, (unsigned)gid, relpath);
		if (!ctx->rootfs_mode)
			r = -1;
	}
	if (fchmodat(ctx->rootfd, relpath, mode, 0) == -1) {
		warn("chmod %04o %s", (unsigned)mode, relpath);
		if (!ctx->rootfs_mode)
			r = -1;
	}
	return r;
}

/*
 * exec_cp_a -- fork/exec "cp -a <src>/. <dst>" to copy directory contents.
 * Errors from cp are warned but treated as non-fatal (the source directory
 * may have been empty).
 */
static int exec_cp_a(const char *src, const char *dst)
{
	char src_dot[PATH_MAX + 2];
	pid_t pid;
	int status;

	if ((size_t)snprintf(src_dot, sizeof(src_dot), "%s/.", src)
	    >= sizeof(src_dot)) {
		warnx("exec_cp_a: path too long: %s", src);
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		warn("fork");
		return -1;
	}
	if (pid == 0) {
		/* Child */
		execlp("cp", "cp", "-a", src_dot, dst, (char *)NULL);
		err(EXIT_FAILURE, "execlp: cp");
	}

	/* Parent */
	if (waitpid(pid, &status, 0) == -1) {
		warn("waitpid(cp)");
		return -1;
	}
	/* cp may exit non-zero if the source was empty; that is acceptable */
	if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
		warnx("cp -a '%s/.' '%s' exited %d (may be empty — continuing)",
		      src, dst, WEXITSTATUS(status));
	return 0;
}

/*
 * Build the host-visible absolute path for an entry->name by concatenating
 * ctx->rootdir and the absolute path within the rootdir.
 * Writes into buf[bufsz].  Returns 0 or -1.
 */
static int full_path(const pv_ctx_t *ctx, const char *name,
                     char *buf, size_t bufsz)
{
	int n;

	if (name[0] != '/') {
		warnx("full_path: name must be absolute: %s", name);
		return -1;
	}
	/* rootdir ends without trailing slash (normalised in main) */
	n = snprintf(buf, bufsz, "%s%s", ctx->rootdir, name);
	if (n < 0 || (size_t)n >= bufsz) {
		warnx("full_path: path too long: %s%s", ctx->rootdir, name);
		return -1;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

int pv_create_file(const pv_ctx_t *ctx, const pv_entry_t *entry)
{
	const char *relname = entry->name + 1; /* skip leading '/' */
	uid_t uid = 0;
	gid_t gid = 0;
	int fd;

	/* Check whether target already exists */
	struct stat st;
	if (fstatat(ctx->rootfd, relname, &st, AT_SYMLINK_NOFOLLOW) == 0) {
		if (ctx->verbose)
			printf("Target already exists, skipping: %s\n",
			       entry->name);
		return 0;
	}
	if (errno != ENOENT) {
		warn("fstatat: %s", entry->name);
		return ctx->rootfs_mode ? 0 : -1;
	}

	if (ctx->dry_run) {
		if (entry->ltarget[0] != '\0')
			printf("[dry-run] cp %s %s"
			       "  (mode=%04o, owner=%s:%s)\n",
			       entry->ltarget, entry->name,
			       (unsigned)entry->mode,
			       entry->user, entry->group);
		else
			printf("[dry-run] touch %s"
			       "  (mode=%04o, owner=%s:%s)\n",
			       entry->name,
			       (unsigned)entry->mode,
			       entry->user, entry->group);
		return 0;
	}

	if (resolve_ids(entry->user, entry->group, &uid, &gid) == -1) {
		if (!ctx->rootfs_mode)
			return -1;
		/* rootfs mode: proceed with uid=0/gid=0 */
	}

	if (entry->ltarget[0] != '\0') {
		/* Copy from source */
		const char *relsrc = entry->ltarget[0] == '/'
		                     ? entry->ltarget + 1
		                     : entry->ltarget;
		int srcfd = openat(ctx->rootfd, relsrc, O_RDONLY);
		if (srcfd == -1) {
			warn("open source: %s", entry->ltarget);
			return ctx->rootfs_mode ? 0 : -1;
		}
		fd = openat(ctx->rootfd, relname,
		            O_WRONLY | O_CREAT | O_EXCL, entry->mode);
		if (fd == -1) {
			warn("create: %s", entry->name);
			close(srcfd);
			return ctx->rootfs_mode ? 0 : -1;
		}
		if (copy_fd(srcfd, fd) == -1) {
			warn("copy: %s -> %s", entry->ltarget, entry->name);
			close(srcfd);
			close(fd);
			return ctx->rootfs_mode ? 0 : -1;
		}
		close(srcfd);
		close(fd);
	} else {
		/* Touch: create empty file */
		fd = openat(ctx->rootfd, relname,
		            O_WRONLY | O_CREAT | O_EXCL, entry->mode);
		if (fd == -1) {
			warn("touch: %s", entry->name);
			return ctx->rootfs_mode ? 0 : -1;
		}
		close(fd);
	}

	if (ctx->verbose)
		printf("Created file: %s\n", entry->name);

	return apply_meta(ctx, relname, uid, gid, entry->mode);
}

int pv_mkdir(const pv_ctx_t *ctx, const pv_entry_t *entry)
{
	const char *relname = entry->name + 1;
	uid_t uid = 0;
	gid_t gid = 0;

	/* Check whether target already exists */
	struct stat st;
	if (fstatat(ctx->rootfd, relname, &st, AT_SYMLINK_NOFOLLOW) == 0) {
		if (ctx->verbose)
			printf("Target already exists, skipping: %s\n",
			       entry->name);
		return 0;
	}
	if (errno != ENOENT) {
		warn("fstatat: %s", entry->name);
		return ctx->rootfs_mode ? 0 : -1;
	}

	if (ctx->dry_run) {
		printf("[dry-run] mkdir -p %s  (mode=%04o, owner=%s:%s)\n",
		       entry->name, (unsigned)entry->mode,
		       entry->user, entry->group);
		return 0;
	}

	if (resolve_ids(entry->user, entry->group, &uid, &gid) == -1) {
		if (!ctx->rootfs_mode)
			return -1;
	}

	if (pv_mkdirtree(ctx->rootfd, relname, entry->mode) == -1) {
		if (!ctx->rootfs_mode)
			return -1;
		return 0;
	}

	if (ctx->verbose)
		printf("Created directory: %s\n", entry->name);

	return apply_meta(ctx, relname, uid, gid, entry->mode);
}

int pv_link_file(const pv_ctx_t *ctx, const pv_entry_t *entry)
{
	const char *relname = entry->name + 1;
	struct stat st;
	int r;

	r = fstatat(ctx->rootfd, relname, &st, AT_SYMLINK_NOFOLLOW);

	if (r == 0 && S_ISLNK(st.st_mode)) {
		/* --- Case 1 / 2: existing symlink --- */
		char current[PATH_MAX];
		ssize_t len = readlinkat(ctx->rootfd, relname,
		                         current, sizeof(current) - 1);
		if (len == -1) {
			warn("readlinkat: %s", entry->name);
			return -1;
		}
		current[len] = '\0';

		if (strcmp(current, entry->ltarget) == 0) {
			if (ctx->verbose)
				printf("Symlink already correct: %s -> %s\n",
				       entry->name, entry->ltarget);
			return 0;
		}

		/* Wrong target */
		if (ctx->dry_run) {
			printf("[dry-run] ln -sf %s %s"
			       "  (replacing wrong target '%s')\n",
			       entry->ltarget, entry->name, current);
			return 0;
		}
		if (ctx->verbose)
			printf("Updating symlink: %s -> %s (was %s)\n",
			       entry->name, entry->ltarget, current);
		if (unlinkat(ctx->rootfd, relname, 0) == -1) {
			warn("unlinkat: %s", entry->name);
			return -1;
		}
		if (symlinkat(entry->ltarget, ctx->rootfd, relname) == -1) {
			warn("symlinkat: %s -> %s",
			     entry->name, entry->ltarget);
			return -1;
		}
		return 0;

	} else if (r == 0 && S_ISDIR(st.st_mode)) {
		/* --- Case 3: existing directory --- */
		char fullname[PATH_MAX];
		if (full_path(ctx, entry->name, fullname, sizeof(fullname)) == -1)
			return -1;

		if (!ctx->rootfs_mode && pv_is_mounted(fullname)) {
			warnx("link_file: %s is a mountpoint, skipping",
			      entry->name);
			return 0;
		}

		/*
		 * Migrate: copy contents to link target, remove old dir,
		 * create symlink.
		 */
		char fulltgt[PATH_MAX];
		if (full_path(ctx, entry->ltarget, fulltgt, sizeof(fulltgt)) == -1)
			return -1;

		if (ctx->dry_run) {
			printf("[dry-run] cp -a %s/. %s\n",
			       fullname, fulltgt);
			printf("[dry-run] rmtree %s"
			       "  (existing dir, migrating to symlink)\n",
			       entry->name);
			printf("[dry-run] ln -sf %s %s\n",
			       entry->ltarget, entry->name);
			return 0;
		}

		/* Ensure target directory exists */
		const char *reltgt = entry->ltarget[0] == '/'
		                     ? entry->ltarget + 1
		                     : entry->ltarget;
		if (pv_mkdirtree(ctx->rootfd, reltgt, 0755) == -1)
			return -1;

		if (exec_cp_a(fullname, fulltgt) == -1)
			return -1;

		if (pv_rmtree(ctx->rootfd, relname) == -1)
			return -1;

		if (ctx->verbose)
			printf("Migrated dir %s -> symlink to %s\n",
			       entry->name, entry->ltarget);

	} else if (r == -1 && errno != ENOENT) {
		warn("fstatat: %s", entry->name);
		return ctx->rootfs_mode ? 0 : -1;
	}

	/* --- Case 3 (after migration) or Case 4: create symlink --- */
	if (ctx->dry_run) {
		printf("[dry-run] ln -sf %s %s\n",
		       entry->ltarget, entry->name);
		return 0;
	}

	/* Ensure parent directory exists */
	char parent[PATH_MAX];
	if (strlen(entry->name) >= sizeof(parent)) {
		warnx("link_file: path too long: %s", entry->name);
		return -1;
	}
	strcpy(parent, entry->name + 1); /* relative */
	char *slash = strrchr(parent, '/');
	if (slash != NULL && slash != parent) {
		*slash = '\0';
		if (pv_mkdirtree(ctx->rootfd, parent, 0755) == -1 &&
		    errno != EEXIST) {
			if (!ctx->rootfs_mode)
				return -1;
		}
	}

	if (symlinkat(entry->ltarget, ctx->rootfd, relname) == -1) {
		if (errno == EEXIST && ctx->rootfs_mode)
			return 0;
		warn("symlinkat: %s -> %s", entry->name, entry->ltarget);
		return ctx->rootfs_mode ? 0 : -1;
	}

	if (ctx->verbose)
		printf("Created symlink: %s -> %s\n",
		       entry->name, entry->ltarget);
	return 0;
}

int pv_bind_mount(const pv_ctx_t *ctx, const pv_entry_t *entry)
{
	char fulldst[PATH_MAX];
	char fullsrc[PATH_MAX];

	if (full_path(ctx, entry->name,    fulldst, sizeof(fulldst)) == -1 ||
	    full_path(ctx, entry->ltarget, fullsrc, sizeof(fullsrc)) == -1)
		return -1;

	/*
	 * During rootfs construction the staging tree is not a live filesystem,
	 * and pseudo does not wrap mount(2), so bind mounts are both meaningless
	 * and would fail.  Log the intended operation and skip.
	 */
	if (ctx->rootfs_mode) {
		printf("Skipping bind mount (rootfs mode): mount --bind %s %s\n",
		       fullsrc, fulldst);
		return 0;
	}

	if (ctx->dry_run) {
		printf("[dry-run] mount --bind %s %s\n", fullsrc, fulldst);
		return 0;
	}

	if (mount(fullsrc, fulldst, NULL, MS_BIND, NULL) == -1)
		err(EXIT_FAILURE, "mount --bind %s %s", fullsrc, fulldst);

	if (ctx->verbose)
		printf("Bind-mounted: %s -> %s\n", fullsrc, fulldst);
	return 0;
}

int pv_apply_entry(const pv_ctx_t *ctx, const pv_entry_t *entry)
{
	pv_entry_t e = *entry; /* work on a mutable copy */

	if (e.name[0] != '/') {
		warnx("apply_entry: name must be absolute: %s", e.name);
		return -1;
	}

	/* Symlink and bind types are dispatched immediately */
	if (e.type == PV_TYPE_LINK) {
		if (ctx->verbose)
			printf("Checking for -%s-.\n", e.name);
		return pv_link_file(ctx, &e);
	}
	if (e.type == PV_TYPE_BIND) {
		if (ctx->verbose)
			printf("Checking for -%s-.\n", e.name);
		return pv_bind_mount(ctx, &e);
	}

	/*
	 * For f and d types: if entry->name itself is a symlink in the target
	 * rootfs, follow it and operate on the resolved path instead.
	 * This matches the shell script's "Found link" logic.
	 */
	struct stat st;
	if (fstatat(ctx->rootfd, e.name + 1, &st, AT_SYMLINK_NOFOLLOW) == 0
	    && S_ISLNK(st.st_mode)) {
		char resolved[PATH_MAX];
		if (pv_readlink_abs(ctx->rootfd, e.name,
		                    resolved, sizeof(resolved)) == -1)
			return ctx->rootfs_mode ? 0 : -1;

		if (ctx->verbose)
			printf("Found link. Resolved %s -> %s\n",
			       e.name, resolved);

		if (strlen(resolved) >= sizeof(e.name)) {
			warnx("apply_entry: resolved path too long: %s", resolved);
			return -1;
		}
		if (resolved[0] == '/') {
			strcpy(e.name, resolved);
		} else {
			/* resolved is relative: prefix with '/' */
			memmove(e.name + 1, resolved, strlen(resolved) + 1);
			e.name[0] = '/';
		}
	}

	if (ctx->verbose)
		printf("Checking for -%s-.\n", e.name);

	switch (e.type) {
	case PV_TYPE_FILE:
		return pv_create_file(ctx, &e);
	case PV_TYPE_DIR:
		return pv_mkdir(ctx, &e);
	default:
		warnx("apply_entry: unhandled type '%c'", (char)e.type);
		return -1;
	}
}
