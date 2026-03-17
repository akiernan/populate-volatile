/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Config file parser for /etc/default/volatiles/ entries.
 *
 * Line format (space-separated, comments stripped):
 *   TYPE  USER  GROUP  MODE  NAME  LTARGET
 */

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pv/config.h"

int pv_parse_line(const char *line, pv_entry_t *out)
{
	char buf[PATH_MAX * 3]; /* generous: holds up to 3 PATH_MAX tokens */
	char *fields[6];
	char *p, *saveptr;
	char *endp;
	long m;
	int i;

	/* Copy and strip trailing comment */
	strncpy(buf, line, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';
	p = strchr(buf, '#');
	if (p != NULL)
		*p = '\0';

	/* Tokenize on whitespace */
	i = 0;
	p = strtok_r(buf, " \t\r\n", &saveptr);
	while (p != NULL && i < 6) {
		fields[i++] = p;
		p = strtok_r(NULL, " \t\r\n", &saveptr);
	}

	if (i == 0)
		return 1; /* blank or comment-only — skip */
	if (i < 6) {
		warnx("config: too few fields (%d, need 6): %s", i, line);
		return -1;
	}

	/* --- TYPE --- */
	if (fields[0][0] == '\0' || fields[0][1] != '\0') {
		warnx("config: invalid type field '%s'", fields[0]);
		return -1;
	}
	switch (fields[0][0]) {
	case 'f': out->type = PV_TYPE_FILE; break;
	case 'd': out->type = PV_TYPE_DIR;  break;
	case 'l': out->type = PV_TYPE_LINK; break;
	case 'b': out->type = PV_TYPE_BIND; break;
	default:
		warnx("config: unknown type '%c'", fields[0][0]);
		return -1;
	}

	/* --- USER --- */
	if (strlen(fields[1]) >= sizeof(out->user)) {
		warnx("config: user name too long: %s", fields[1]);
		return -1;
	}
	strcpy(out->user, fields[1]);

	/* --- GROUP --- */
	if (strlen(fields[2]) >= sizeof(out->group)) {
		warnx("config: group name too long: %s", fields[2]);
		return -1;
	}
	strcpy(out->group, fields[2]);

	/* --- MODE (octal) --- */
	errno = 0;
	m = strtol(fields[3], &endp, 8);
	if (errno != 0 || *endp != '\0' || m < 0 || m > 07777) {
		warnx("config: invalid mode '%s'", fields[3]);
		return -1;
	}
	out->mode = (mode_t)m;

	/* --- NAME --- */
	if (strlen(fields[4]) >= sizeof(out->name)) {
		warnx("config: name path too long: %s", fields[4]);
		return -1;
	}
	strcpy(out->name, fields[4]);

	/* --- LTARGET --- */
	if (strcmp(fields[5], "none") == 0) {
		out->ltarget[0] = '\0';
	} else {
		if (strlen(fields[5]) >= sizeof(out->ltarget)) {
			warnx("config: ltarget path too long: %s", fields[5]);
			return -1;
		}
		strcpy(out->ltarget, fields[5]);
	}

	return 0;
}

int pv_parse_config(int cfgfd, const char *path,
                    pv_entry_cb cb, void *userdata)
{
	int fd;
	FILE *f;
	char line[PATH_MAX * 3];
	pv_entry_t entry;
	int ret = 0;

	fd = openat(cfgfd, path, O_RDONLY);
	if (fd == -1) {
		warn("openat: %s", path);
		return -1;
	}

	f = fdopen(fd, "r");
	if (f == NULL) {
		warn("fdopen: %s", path);
		close(fd);
		return -1;
	}
	/* fd is now owned by f */

	while (fgets(line, sizeof(line), f) != NULL) {
		int r = pv_parse_line(line, &entry);
		if (r == 1)
			continue; /* skip blank/comment */
		if (r == -1)
			continue; /* parse error already warned; keep going */

		r = cb(&entry, userdata);
		if (r != 0) {
			ret = r;
			break;
		}
	}

	fclose(f);
	return ret;
}
