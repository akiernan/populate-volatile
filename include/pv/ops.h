/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PV_OPS_H
#define PV_OPS_H

#include <stdbool.h>
#include "pv/config.h"

/*
 * Operation context threaded through all pv_* ops functions.
 */
typedef struct {
	int  rootfd;       /* open O_DIRECTORY fd for the root prefix */
	const char *rootdir; /* absolute path of rootfd (for execv args and
	                      * pv_is_mounted() which needs a full path) */
	bool verbose;
	bool dry_run;      /* log actions but make no filesystem changes */
	bool rootfs_mode;  /* true -> rootdir is a rootfs image being built;
	                    * suppress non-fatal errors so do_rootfs doesn't fail */
} pv_ctx_t;

/*
 * Create the file described by entry.
 *   entry->ltarget == ""   -> create empty file (touch semantics)
 *   entry->ltarget != ""   -> copy from rootdir+ltarget
 * Skips silently if the target already exists.
 * Applies entry->mode, entry->user, entry->group.
 */
int pv_create_file(const pv_ctx_t *ctx, const pv_entry_t *entry);

/*
 * Create the directory tree for entry->name and apply
 * entry->mode, entry->user, entry->group to the leaf.
 * Skips silently if the target already exists.
 */
int pv_mkdir(const pv_ctx_t *ctx, const pv_entry_t *entry);

/*
 * Create or update the symlink entry->name -> entry->ltarget.
 *
 * Three cases:
 *   1. entry->name is already a symlink pointing to entry->ltarget -> no-op.
 *   2. entry->name is a symlink pointing elsewhere -> unlink + recreate.
 *   3. entry->name is an existing directory and is not a mountpoint ->
 *      copy its contents into entry->ltarget via execv("cp -a src/. dst/"),
 *      remove the directory with pv_rmtree(), then create the symlink.
 *      If the directory is mounted, skip with a warning.
 *   4. entry->name does not exist -> symlinkat().
 *
 * In dry_run mode all filesystem-modifying steps are logged but not executed.
 * bind-mount check always uses /proc/self/mountinfo.
 */
int pv_link_file(const pv_ctx_t *ctx, const pv_entry_t *entry);

/*
 * Bind-mount entry->ltarget onto entry->name via mount(MS_BIND).
 * Calls err() on failure — assumes caller has CAP_SYS_ADMIN.
 */
int pv_bind_mount(const pv_ctx_t *ctx, const pv_entry_t *entry);

/*
 * Dispatcher: resolves symlinks in entry->name for f/d types, then
 * calls the appropriate pv_create_file / pv_mkdir / pv_link_file /
 * pv_bind_mount.
 */
int pv_apply_entry(const pv_ctx_t *ctx, const pv_entry_t *entry);

#endif /* PV_OPS_H */
