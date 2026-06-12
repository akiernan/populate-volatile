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
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#include "pv/config.h"
#include "pv/trace.h"
#include "pv/validate.h"

/*
 * Upper bound for the getpwnam_r/getgrnam_r buffer when retrying on
 * ERANGE.  Large enough for any sane passwd/group entry (groups with
 * thousands of members fit well within this).
 */
#define LOOKUP_BUFSZ_MAX (1024 * 1024)

static long initial_bufsz(int name)
{
	long bufsz = sysconf(name);

	if (bufsz <= 0)
		bufsz = 4096;
	return bufsz;
}

int pv_resolve_user(const char *user, uid_t *uid)
{
	struct passwd pwd, *result;
	long bufsz = initial_bufsz(_SC_GETPW_R_SIZE_MAX);
	char *buf;
	int r;

	for (;;) {
		buf = malloc((size_t)bufsz);
		if (buf == NULL) {
			warn("malloc");
			return -1;
		}
		r = getpwnam_r(user, &pwd, buf, (size_t)bufsz, &result);
		if (r != ERANGE)
			break;
		/* Buffer too small (e.g. long GECOS); retry with double */
		free(buf);
		bufsz *= 2;
		if (bufsz > LOOKUP_BUFSZ_MAX) {
			warnx("getpwnam_r: %s: entry too large", user);
			return -1;
		}
	}

	if (r != 0) {
		free(buf);
		errno = r;
		warn("getpwnam_r: %s", user);
		return -1;
	}
	if (result == NULL) {
		free(buf);
		TRACE("user=\"%s\" -> not found", user);
		return 0;
	}
	if (uid != NULL)
		*uid = result->pw_uid;
	TRACE("user=\"%s\" -> uid=%u", user, (unsigned)result->pw_uid);
	free(buf);
	return 1;
}

int pv_resolve_group(const char *group, gid_t *gid)
{
	struct group grp, *result;
	long bufsz = initial_bufsz(_SC_GETGR_R_SIZE_MAX);
	char *buf;
	int r;

	for (;;) {
		buf = malloc((size_t)bufsz);
		if (buf == NULL) {
			warn("malloc");
			return -1;
		}
		r = getgrnam_r(group, &grp, buf, (size_t)bufsz, &result);
		if (r != ERANGE)
			break;
		/* Buffer too small (e.g. group with many members) */
		free(buf);
		bufsz *= 2;
		if (bufsz > LOOKUP_BUFSZ_MAX) {
			warnx("getgrnam_r: %s: entry too large", group);
			return -1;
		}
	}

	if (r != 0) {
		free(buf);
		errno = r;
		warn("getgrnam_r: %s", group);
		return -1;
	}
	if (result == NULL) {
		free(buf);
		TRACE("group=\"%s\" -> not found", group);
		return 0;
	}
	if (gid != NULL)
		*gid = result->gr_gid;
	TRACE("group=\"%s\" -> gid=%u", group, (unsigned)result->gr_gid);
	free(buf);
	return 1;
}

int pv_user_exists(const char *user)
{
	return pv_resolve_user(user, NULL);
}

int pv_group_exists(const char *group)
{
	return pv_resolve_group(group, NULL);
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
