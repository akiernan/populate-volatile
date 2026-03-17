/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Path utilities: recursive mkdir, recursive rmdir, symlink resolution,
 * mount-point detection.
 *
 * Directory creation uses an iterative component-walk with openat/mkdirat so
 * that all operations are relative to a caller-supplied directory fd (rootfd),
 * with no dependence on the process working directory or absolute host paths.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <limits.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pv/path.h"

mode_t pv_saved_umask;

/*
 * pv_mkdirtree_fd -- create a directory tree component by component.
 *
 * Walks path relative to dirfd, calling mkdirat() for each component.
 * Intermediate directories receive (rwxrwxrwx & ~pv_saved_umask); the
 * leaf receives exactly mode (umask is cleared to 0 at startup).
 *
 * Returns an open O_DIRECTORY fd for the leaf, or -1 on error.
 */
int pv_mkdirtree_fd(int dirfd, const char *path, mode_t mode)
{
	char *buf;
	char *p, *slash;
	int fd, newfd;
	mode_t imask;

	imask = (S_IRWXU | S_IRWXG | S_IRWXO) & ~pv_saved_umask;

	if ((buf = strdup(path)) == NULL) {
		warn("strdup");
		return -1;
	}

	/*
	 * Dup dirfd so we can close fd at each step without affecting the
	 * caller's fd. For AT_FDCWD, open "." explicitly instead.
	 */
	if (dirfd == AT_FDCWD)
		fd = open(".", O_RDONLY | O_DIRECTORY);
	else
		fd = dup(dirfd);

	if (fd == -1) {
		warn("dup/open(dirfd)");
		free(buf);
		return -1;
	}

	p = buf;
	if (*p == '/')
		p++; /* skip leading slash: path is relative to dirfd */

	while (*p != '\0') {
		/* Find the next component boundary */
		slash = strchr(p, '/');
		if (slash != NULL)
			*slash = '\0';

		/* Skip empty components (consecutive slashes) */
		if (*p == '\0') {
			p = slash + 1;
			continue;
		}

		/*
		 * Intermediate components get imask permissions; the leaf
		 * gets the requested mode.
		 */
		if (mkdirat(fd, p, (slash != NULL) ? imask : mode) == -1
		    && errno != EEXIST) {
			warn("mkdirat: %s", p);
			close(fd);
			free(buf);
			return -1;
		}

		newfd = openat(fd, p, O_RDONLY | O_DIRECTORY);
		close(fd);
		if (newfd == -1) {
			warn("openat: %s", p);
			free(buf);
			return -1;
		}
		fd = newfd;

		if (slash != NULL)
			p = slash + 1;
		else
			break;
	}

	free(buf);
	return fd;
}

int pv_mkdirtree(int dirfd, const char *path, mode_t mode)
{
	int fd = pv_mkdirtree_fd(dirfd, path, mode);

	if (fd == -1)
		return -1;
	close(fd);
	return 0;
}

/*
 * pv_rmtree -- recursively remove a directory tree.
 *
 * Opens parentfd/name as a directory, iterates its entries:
 *   - regular files / symlinks / other non-dirs: unlinkat()
 *   - subdirectories: recurse
 * Then unlinkat(parentfd, name, AT_REMOVEDIR).
 *
 * Does not follow symlinks (O_NOFOLLOW on the directory open).
 * On filesystems that return DT_UNKNOWN, falls back to fstatat().
 */
int pv_rmtree(int parentfd, const char *name)
{
	int fd, ret;
	DIR *dir;
	struct dirent *ent;

	fd = openat(parentfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (fd == -1) {
		warn("openat(rmtree): %s", name);
		return -1;
	}

	dir = fdopendir(fd);
	if (dir == NULL) {
		warn("fdopendir: %s", name);
		close(fd);
		return -1;
	}
	/* fd is now owned by dir; don't close it separately */

	ret = 0;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0)
			continue;

		if (ent->d_type == DT_DIR) {
			if (pv_rmtree(fd, ent->d_name) == -1)
				ret = -1;
		} else if (ent->d_type == DT_UNKNOWN) {
			/* Filesystem doesn't provide d_type; use fstatat */
			struct stat st;
			if (fstatat(fd, ent->d_name, &st,
			            AT_SYMLINK_NOFOLLOW) == -1) {
				warn("fstatat: %s", ent->d_name);
				ret = -1;
				continue;
			}
			if (S_ISDIR(st.st_mode)) {
				if (pv_rmtree(fd, ent->d_name) == -1)
					ret = -1;
			} else {
				if (unlinkat(fd, ent->d_name, 0) == -1) {
					warn("unlinkat: %s", ent->d_name);
					ret = -1;
				}
			}
		} else {
			if (unlinkat(fd, ent->d_name, 0) == -1) {
				warn("unlinkat: %s", ent->d_name);
				ret = -1;
			}
		}
	}

	closedir(dir); /* also closes fd */

	if (unlinkat(parentfd, name, AT_REMOVEDIR) == -1) {
		warn("unlinkat(AT_REMOVEDIR): %s", name);
		ret = -1;
	}
	return ret;
}

/*
 * pv_readlink_abs -- read a symlink and return an absolute-within-rootdir path.
 *
 * abspath is an absolute path such as "/var/run".
 * dirfd is rootfd; we call readlinkat(dirfd, abspath+1, ...) internally.
 *
 * If the link target is already absolute, it is copied to buf unchanged.
 * If the link target is relative, we prepend dirname(abspath) so that the
 * result is an absolute path within the rootdir tree that the kernel can
 * follow correctly via subsequent *at() calls (it handles ".." components).
 *
 * Example:
 *   abspath = "/var/run",  target = "../volatile/run"
 *   result  = "/var/../volatile/run"
 */
int pv_readlink_abs(int dirfd, const char *abspath, char *buf, size_t bufsz)
{
	char target[PATH_MAX];
	ssize_t len;
	int n;

	if (abspath[0] != '/') {
		warnx("pv_readlink_abs: path must be absolute: %s", abspath);
		return -1;
	}

	len = readlinkat(dirfd, abspath + 1, target, sizeof(target) - 1);
	if (len == -1) {
		warn("readlinkat: %s", abspath);
		return -1;
	}
	target[len] = '\0';

	if (target[0] == '/') {
		/* Absolute link target */
		if ((size_t)len >= bufsz) {
			warnx("pv_readlink_abs: path too long: %s", target);
			return -1;
		}
		memcpy(buf, target, (size_t)len + 1);
		return 0;
	}

	/*
	 * Relative link target: prepend dirname(abspath).
	 * We work on a copy so we don't modify the caller's string.
	 */
	char abscopy[PATH_MAX];
	if (strlen(abspath) >= sizeof(abscopy)) {
		warnx("pv_readlink_abs: path too long: %s", abspath);
		return -1;
	}
	strcpy(abscopy, abspath);

	char *slash = strrchr(abscopy, '/');
	if (slash == abscopy) {
		/* symlink is directly under root, e.g. "/foo" -> dirname is "/" */
		n = snprintf(buf, bufsz, "/%s", target);
	} else if (slash != NULL) {
		*slash = '\0'; /* abscopy is now the dirname */
		n = snprintf(buf, bufsz, "%s/%s", abscopy, target);
	} else {
		/* no slash at all — shouldn't happen since abspath starts with '/' */
		n = snprintf(buf, bufsz, "/%s", target);
	}

	if (n < 0 || (size_t)n >= bufsz) {
		warnx("pv_readlink_abs: resolved path too long");
		return -1;
	}
	return 0;
}

/*
 * pv_unescape_mountinfo -- decode \NNN octal escapes in-place.
 *
 * /proc/self/mountinfo encodes special characters (including spaces) as
 * \NNN octal sequences.  For example, a mount point of "/tmp/a b" appears
 * as "/tmp/a\040b".  Decode in-place so we can strcmp against a plain path.
 */
void pv_unescape_mountinfo(char *s)
{
	char *r = s, *w = s;

	while (*r) {
		if (r[0] == '\\' &&
		    r[1] >= '0' && r[1] <= '7' &&
		    r[2] >= '0' && r[2] <= '7' &&
		    r[3] >= '0' && r[3] <= '7') {
			*w++ = (char)(((r[1] - '0') << 6) |
			              ((r[2] - '0') << 3) |
			               (r[3] - '0'));
			r += 4;
		} else {
			*w++ = *r++;
		}
	}
	*w = '\0';
}

/*
 * pv_is_mounted -- check whether path is a mountpoint.
 *
 * Parses /proc/self/mountinfo and checks field 5 (the mount point)
 * against path.  Field numbering is 1-based per the kernel docs.
 *
 * Mount point names with embedded spaces are encoded as \NNN octal
 * sequences in mountinfo; we unescape before comparing.
 *
 * Returns 1 if path is a mountpoint, 0 if not, -1 on error.
 */
int pv_is_mounted(const char *path)
{
	FILE *f;
	char line[4096];
	int found = 0;

	f = fopen("/proc/self/mountinfo", "r");
	if (f == NULL) {
		warn("fopen: /proc/self/mountinfo");
		return -1;
	}

	while (!found && fgets(line, sizeof(line), f) != NULL) {
		/*
		 * Fields are space-separated.  We want field 5 (0-based: 4).
		 *
		 *  36 30 8:1 / /boot rw,relatime - ext4 /dev/sda1 rw
		 *  ^0 ^1 ^2  ^3 ^4
		 */
		char *saveptr;
		char *tok = strtok_r(line, " \t", &saveptr);
		int field = 0;

		while (tok != NULL) {
			if (field == 4) {
				pv_unescape_mountinfo(tok);
				if (strcmp(tok, path) == 0)
					found = 1;
				break;
			}
			tok = strtok_r(NULL, " \t", &saveptr);
			field++;
		}
	}

	fclose(f);
	return found;
}
