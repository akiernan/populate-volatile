/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PV_PATH_H
#define PV_PATH_H

#include <sys/types.h>
#include <stddef.h>

/*
 * Saved umask from startup. Set once in main() via umask(0).
 * Used by pv_mkdirtree_fd() when creating intermediate directories.
 */
extern mode_t pv_saved_umask;

/*
 * Create a directory tree at dirfd-relative path, component by component.
 * Intermediate directories get (rwxrwxrwx & ~pv_saved_umask); the leaf
 * gets exactly mode (umask is cleared at startup).
 *
 * Returns an open O_DIRECTORY fd for the leaf, or -1 on error.
 * Caller must close() the returned fd.
 */
int pv_mkdirtree_fd(int dirfd, const char *path, mode_t mode);

/*
 * As pv_mkdirtree_fd() but closes the returned fd.
 * Returns 0 on success, -1 on error.
 */
int pv_mkdirtree(int dirfd, const char *path, mode_t mode);

/*
 * Recursively remove the directory named `name` relative to parentfd.
 * Uses openat/readdir/unlinkat(AT_REMOVEDIR) — no execv.
 * Does not follow symlinks out of the tree.
 * Returns 0 on success, -1 if any removal fails (continues on partial error).
 */
int pv_rmtree(int parentfd, const char *name);

/*
 * Read the symlink at abspath (an absolute path such as "/var/run").
 * Uses dirfd for the readlinkat() call (pass rootfd; use abspath+1 internally).
 * If the link target is relative, resolves it to an absolute path by
 * prepending dirname(abspath), e.g. "/var" + "/" + "../run" -> "/var/../run".
 * The caller may pass the result directly back as entry->name; the kernel
 * handles ".." components correctly in subsequent *at() calls.
 *
 * Writes the result into buf[bufsz]. Returns 0 or -1.
 */
int pv_readlink_abs(int dirfd, const char *abspath, char *buf, size_t bufsz);

/*
 * Decode \NNN octal escape sequences in-place, as used in
 * /proc/self/mountinfo (e.g. \040 -> space).
 */
void pv_unescape_mountinfo(char *s);

/*
 * Check whether path appears as a mountpoint (field 5) in
 * /proc/self/mountinfo.
 * Returns 1 if mounted, 0 if not, -1 on error.
 */
int pv_is_mounted(const char *path);

#endif /* PV_PATH_H */
