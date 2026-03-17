/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * User and group validation.
 *
 * Uses getpwnam_r / getgrnam_r rather than parsing /etc/passwd directly.
 * This is correct in both execution contexts:
 *
 *   Runtime: the process runs on the target system; getpwnam_r reads the
 *            target's /etc/passwd directly.
 *
 *   Rootfs build time (under pseudo): pseudo sets PSEUDO_PASSWD to the
 *            target rootfs's passwd path, so getpwnam_r resolves against
 *            the target image, not the host.
 */

#include <sys/types.h>

#include <err.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#include "pv/config.h"
#include "pv/validate.h"

int pv_user_exists(const char *user)
{
	static long bufsz;
	struct passwd pwd, *result;
	char *buf;
	int r;

	if (bufsz == 0) {
		bufsz = sysconf(_SC_GETPW_R_SIZE_MAX);
		if (bufsz <= 0)
			bufsz = 4096;
	}

	buf = malloc((size_t)bufsz);
	if (buf == NULL) {
		warn("malloc");
		return -1;
	}

	r = getpwnam_r(user, &pwd, buf, (size_t)bufsz, &result);
	free(buf);

	if (r != 0) {
		warn("getpwnam_r: %s", user);
		return -1;
	}
	return result != NULL ? 1 : 0;
}

int pv_group_exists(const char *group)
{
	static long bufsz;
	struct group grp, *result;
	char *buf;
	int r;

	if (bufsz == 0) {
		bufsz = sysconf(_SC_GETGR_R_SIZE_MAX);
		if (bufsz <= 0)
			bufsz = 4096;
	}

	buf = malloc((size_t)bufsz);
	if (buf == NULL) {
		warn("malloc");
		return -1;
	}

	r = getgrnam_r(group, &grp, buf, (size_t)bufsz, &result);
	free(buf);

	if (r != 0) {
		warn("getgrnam_r: %s", group);
		return -1;
	}
	return result != NULL ? 1 : 0;
}

int pv_check_requirements(const pv_entry_t *entries, size_t nentries)
{
	size_t i;
	int result = 0;

	for (i = 0; i < nentries; i++) {
		int r;

		r = pv_user_exists(entries[i].user);
		if (r == -1) {
			result = 1;
		} else if (r == 0) {
			warnx("undefined user '%s' (referenced by %s)",
			      entries[i].user, entries[i].name);
			result = 1;
		}

		r = pv_group_exists(entries[i].group);
		if (r == -1) {
			result = 1;
		} else if (r == 0) {
			warnx("undefined group '%s' (referenced by %s)",
			      entries[i].group, entries[i].name);
			result = 1;
		}
	}

	return result;
}
