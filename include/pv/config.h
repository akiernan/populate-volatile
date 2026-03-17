/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PV_CONFIG_H
#define PV_CONFIG_H

#include <sys/types.h>
#include <stddef.h>

#ifndef LOGIN_NAME_MAX
#define LOGIN_NAME_MAX 256
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef enum {
	PV_TYPE_FILE = 'f',
	PV_TYPE_DIR  = 'd',
	PV_TYPE_LINK = 'l',
	PV_TYPE_BIND = 'b',
} pv_type_t;

/*
 * One parsed entry from a volatiles config file.
 *
 * Config file format (space-separated):
 *   TYPE  USER  GROUP  MODE  NAME  LTARGET
 *
 *   TYPE    : f=file, d=directory, l=symlink, b=bind-mount
 *   USER    : owner username
 *   GROUP   : owner group name
 *   MODE    : octal permission bits (e.g. 0755)
 *   NAME    : absolute destination path (no rootdir prefix)
 *   LTARGET : source path for f/b, link target for l; "none" -> empty
 */
typedef struct {
	pv_type_t type;
	char      user[LOGIN_NAME_MAX];
	char      group[LOGIN_NAME_MAX];
	mode_t    mode;
	char      name[PATH_MAX];    /* absolute path, no rootdir prefix */
	char      ltarget[PATH_MAX]; /* source/target; empty if "none" */
} pv_entry_t;

/*
 * Parse a single config line into *out.
 * Strips trailing comments (# to end-of-line).
 * Returns:
 *   0  - valid entry written to *out
 *   1  - blank/comment/short line, skip
 *  -1  - parse error (warnx() called)
 */
int pv_parse_line(const char *line, pv_entry_t *out);

/*
 * Callback invoked for each successfully parsed entry.
 * Return 0 to continue processing, non-zero to abort.
 */
typedef int (*pv_entry_cb)(const pv_entry_t *entry, void *userdata);

/*
 * Open cfgfd/path and call cb(entry, userdata) for each valid entry.
 * Parse errors are warned but do not abort processing.
 * Returns 0 on success, -1 on I/O error, or the last non-zero cb return value.
 */
int pv_parse_config(int cfgfd, const char *path,
                    pv_entry_cb cb, void *userdata);

#endif /* PV_CONFIG_H */
