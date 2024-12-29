// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright Alex Kiernan <alex.kiernan@gmail.com>
 */

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

// With glibc, one gets the POSIX version of basename() when <libgen.h> is included, and the GNU version otherwise.
#include <libgen.h>

#define xstr(s) str(s)
#define str(s) #s

#define MAX_LINE_LENGTH 16384

mode_t saved_umask;

enum {
	MODE_BIND_MOUNT,
	MODE_CREATE_DIRECTORY,
	MODE_CREATE_FILE,
	MODE_CREATE_SYMLINK,
};

struct tmpfile {
	struct tmpfile *next;
	const char *cfgfile;
	int ttype;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	char *tname;
	char *tltarget;
};

int do_cp(const char *source, const char *dest)
{
	pid_t pid;
	int status;
	int r;

	pid = fork();
	if (pid == 0) {
		umask(saved_umask);
		r = execlp("cp", source, dest, NULL);
		if (r == 1)
			err(EX_OSERR, "exec failed");
	}

	waitpid(pid, &status, 0);
	return 0;
}

#define MOUNTINFO_PATH "/proc/self/mountinfo"

int is_mountpoint(const char *path)
{
	char line[MAX_LINE_LENGTH];
	bool is_mount = false;

	FILE *fp = fopen(MOUNTINFO_PATH, "r");
	if (!fp) {
		warn("fopen: " MOUNTINFO_PATH);
		return false;
	}

	while (fgets(line, sizeof(line), fp)) {
		// Ensure the line is null-terminated
		line[strcspn(line, "\n")] = '\0';

		char *mount_point = strstr(line, " - "); // Find separator for mount options
		if (mount_point) {
			*mount_point = '\0'; // Split the string before " - "
		}

		// Mountinfo fields:
		// [1] mount ID
		// [2] parent ID
		// [3] major:minor
		// [4] root
		// [5] mount point
		// Skipping other fields for simplicity
		char *tokens[10];
		int i = 0;
		char *token = strtok(line, " ");
		while (token && i < (int)(sizeof tokens / sizeof tokens[0])) {
			tokens[i++] = token;
			token = strtok(NULL, " ");
		}

		if (i < 5) {
			continue; // Ensure we have at least enough fields for parsing
		}

		// Field 5 is the mount point
		const char *mount_path = tokens[4];

		// Check if the mount point matches the given path
		if (strcmp(mount_path, path) == 0) {
			is_mount = true;
			break;
		}
	}

	fclose(fp);
	return is_mount;
}

static int _mkdirtree(char *dir, mode_t mode)
{
	int r, fd;
	char *name;

	name = basename(dir);
	dir = dirname(dir);
	// Check for / or .
	r = mkdir(dir, (S_IRWXU | S_IRWXG | S_IRWXO) & ~saved_umask);
	if (r == 0 || errno == EEXIST) {
		fd = open(dir, O_DIRECTORY);
		if (fd == -1)
			warn("open");
	} else {
		fd = _mkdirtree(dir, (S_IRWXU | S_IRWXG | S_IRWXO) & ~saved_umask);
	}
	if (fd == -1)
		return -1;

	r = mkdirat(fd, name, mode);
	if (r == -1 && errno != EEXIST) {
		warn("mkdirat");
		close(fd);
		return -1;
	} else {
		r = openat(fd, name, O_DIRECTORY);
		close(fd);
		if (r == -1)
			warn("openat");
		fd = r;
	}
	return fd;
}

int mkdirtree(char *dir, mode_t mode)
{
	int fd = _mkdirtree(dir, mode);

	if (fd == -1)
		return -1;

	close(fd);
	return 0;
}

int link_file(const char *tsource, char *tname)
{
	int r;
	char linkname[PATH_MAX + 1];

	r = readlink(tname, linkname, PATH_MAX);
	if (r != -1) {
		// if [ -L \"$2\" ]; then
		//         [ \"\$(readlink \"$2\")\" != \"$1\" ] && { rm -f \"$2\"; ln -sf \"$1\" \"$2\"; };
		if (r == PATH_MAX) {
			// overflow
			warnx("readlink: %s: buffer overflow", tname);
		} else {
			linkname[r] = '\0';
			if (strcmp(linkname, tsource)) {
				if (unlink(tname) == -1 && errno != ENOENT) {
					warn("unlink: %s", tname);
				} else if (symlink(tsource, tname) == -1) {
					warn("symlink: %s -> %s", tname, tsource);
				}
			}
		}
	} else {
		// elif [ -d \"$2\" ]; then
		//	if awk '\$2 == \"$2\" {exit 1}' /proc/mounts; then
		//		cp -a $2/* $1 2>/dev/null;
		//		cp -a $2/.[!.]* $1 2>/dev/null;
		//		rm -rf \"$2\";
		//		ln -sf \"$1\" \"$2\";
		//	fi
		struct stat sb;

		r = stat(tname, &sb);
		if (r == 0 && S_ISDIR(sb.st_mode)) {
			if (!is_mountpoint(tname)) {
				// TODO
			}
		} else {
			// else
			//	ln -sf \"$1\" \"$2\";
			if (unlink(tname) == -1 && errno != ENOENT)
				warn("unlink: %s", tname);
			else if (symlink(tsource, tname) == -1)
				warn("symlink: %s -> %s", tname, tsource);
		}
	}
	// FIXME
	return 0;
}

void handle_object(int ttype, uid_t uid, gid_t gid, mode_t mode, char *tname, const char *tltarget)
{
	int r;
	char linkname[PATH_MAX + 1];
	char newname[PATH_MAX + 1];

	switch (ttype) {
	case MODE_BIND_MOUNT:
		r = mount(tname, tltarget, NULL, MS_BIND, NULL);
		if (r == -1)
			warn("mount: %s -> %s", tname, tltarget);
		return;

	case MODE_CREATE_SYMLINK:
		link_file(tltarget, tname);
		return;
	}

	/* When populate-volatile is to verify/create a directory or file, it
	 * will first check it's existence. If a link is found to exist in the
	 * place of the target, the path of the target is replaced with the
	 * target the link points to. Thus, if a link is in the place to be
	 * verified, the object will be created in the place the link points to
	 * instead.
	 * 
	 * # A linking example:
	 * # l root root 0777 /var/test /tmp/testfile
	 * # f root root 0644 /var/test none
	 *
	 * This explains the order of "link before object" as in the example
	 * above, where a link will be created at /var/test pointing to
	 * /tmp/testfile and due to this link the file defined as /var/test
	 * will actually be created as /tmp/testfile. */

	r = readlink(tname, linkname, PATH_MAX);
	if (r > 0) {
		// is a link
		if (r == PATH_MAX) {
			// overflow
			warnx("readlink: %s", tname);
		} else {
			linkname[r] = '\0';
			if (*linkname == '/') {
				tname = linkname;
			} else {
				char *dname = dirname(tname);

				snprintf(newname, sizeof newname, "%s/%s", dname, tname);
				tname = newname;
			}
		}
	}

	switch (ttype) {
	case MODE_CREATE_DIRECTORY:
		r = mkdir(tname, mode);
		if (r == -1) {
			switch (errno) {
			case EEXIST:
				if (chmod(tname, mode) == -1)
					warn("chmod: %s", tname);
				break;

			case ENOENT:
				mkdirtree(tname, mode);
				break;

			default:
				warn("mkdir failed");
				break;
			}
		}
		break;

	case MODE_CREATE_FILE:
		if (!tltarget[0] || !strcmp(tltarget, "none")) {
			r = mknod(tname, S_IFREG | mode, 0);
			if (r == -1) {
				switch (errno) {
				case EEXIST:
					r = chmod(tname, mode);
					if (r == -1)
						warn("chmod: %s", tname);
					break;

				default:
					warn("mknod: %s", tname);
					break;
				}
			}
		} else {
			do_cp(tname, tltarget);
			r = chmod(tname, mode);
			if (r == -1)
				warn("chmod: %s", tname);
		}
		break;

	default:
		// TODO
		;
	}
	r = chown(tname, uid, gid);
	if (r == -1)
		warn("chown: %s", tname);
}

//   sysconf(_SC_GETPW_R_SIZE_MAX)

struct tmpfile *free_tmpfile(struct tmpfile *tmpfile)
{
	struct tmpfile *tmpnext = tmpfile->next;

	free(tmpfile->tname);
	free(tmpfile->tltarget);
	tmpnext = tmpfile->next;
	free(tmpfile);

	return tmpnext;
}

void free_cfglist(struct tmpfile *cfglist)
{
	while (cfglist)
		cfglist = free_tmpfile(cfglist);
}

struct tmpfile *parse_cfgfile(FILE *fp, const char *cfgfile)
{
	char line[MAX_LINE_LENGTH + 1];
	struct tmpfile *cfglist = NULL, *tmpprev;

	while (fgets(line, sizeof line - 1, fp)) {
		if (line[0] == '#')
			continue;

		// Ensure the line is null-terminated
		line[strcspn(line, "\n")] = '\0';

		char *tokens[6];
		int i = 0;
		char *token = strtok(line, " ");
		while (token && i < (int)(sizeof tokens / sizeof tokens[0])) {
			tokens[i++] = token;
			token = strtok(NULL, " ");
		}
		if (i >= 5) {
			int ttype;
			char *tuser, *tgroup, *tname, *tltarget;
			mode_t mode;

			if (!strcmp(tokens[0], "b")) {
				ttype = MODE_BIND_MOUNT;
			} else if (!strcmp(tokens[0], "d")) {
				ttype = MODE_CREATE_DIRECTORY;
			} else if (!strcmp(tokens[0], "f")) {
				ttype = MODE_CREATE_FILE;
			} else if (!strcmp(tokens[0], "l")) {
				ttype = MODE_CREATE_SYMLINK;
			} else {
				warn("%s: unknown type: %s", cfgfile, tokens[0]);
				free_cfglist(cfglist);
				return NULL;
			}

			tuser = tokens[1];
			tgroup = tokens[2];
			// FIXME
			mode = (int)strtol(tokens[3], NULL, 8);
			tname = tokens[4];
			tltarget = (i == 6) ? tokens[5] : NULL;

			printf("Parsed fields: TTYPE=%d, TUSER=%s, TGROUP=%s, MODE=%#o, TNAME=%s, TLTARGET=%s\n", ttype,
			       tuser, tgroup, mode, tname, tltarget);
			uid_t uid = -1;
			gid_t gid = -1;
			if (strcmp(tuser, "-")) {
				struct passwd *pwd = getpwnam(tuser);

				if (!pwd) {
					warn("%s: unknown user: %s", cfgfile, tuser);
					free_cfglist(cfglist);
					return NULL;
				}
				uid = pwd->pw_uid;
			}
			if (strcmp(tgroup, "-")) {
				struct group *grp = getgrnam(tgroup);

				if (!grp) {
					warn("%s: unknown group: %s", cfgfile, tgroup);
					free_cfglist(cfglist);
					return NULL;
				}
				gid = grp->gr_gid;
			}
			struct tmpfile *tmpfile = malloc(sizeof *tmpfile);
			if (tmpfile) {
				tmpfile->ttype = ttype;
				tmpfile->uid = uid;
				tmpfile->gid = gid;
				tmpfile->mode = mode;
				tmpfile->tname = strdup(tname);
				if (tltarget) {
					tmpfile->tltarget = strdup(tltarget);
				} else {
					tmpfile->tltarget = NULL;
				}
				tmpfile->next = NULL;
				if (!cfglist)
					cfglist = tmpfile;
				else
					tmpprev->next = tmpfile;
				tmpprev = tmpfile;
			} else {
				// TODO
			}
		}
	}
	return cfglist;
}

void process_cfglist(struct tmpfile *cfglist)
{
	while (cfglist) {
		int ttype = cfglist->ttype;
		uid_t uid = cfglist->uid;
		gid_t gid = cfglist->gid;
		mode_t mode = cfglist->mode;
		char *tname = cfglist->tname;
		char *tltarget = cfglist->tltarget;

		printf("Process fields: TTYPE=%d, USER=%d, GROUP=%d, MODE=%#o, TNAME=%s, TLTARGET=%s\n", ttype, uid,
		       gid, mode, tname, tltarget);
		handle_object(ttype, uid, gid, mode, tname, tltarget);
		cfglist = free_tmpfile(cfglist);
	}
}

int main(int argc, const char *argv[])
{
	struct tmpfile *cfglist = NULL;

	saved_umask = umask(0);

	if (argc == 1) {
		cfglist = parse_cfgfile(stdin, "<stdin>");
	} else {
		for (const char *cfgfile = *++argv; cfgfile; cfgfile = *++argv) {
			FILE *fp = fopen(cfgfile, "r");
			if (fp == NULL) {
				warn("%s: fopen failed", cfgfile);
				continue;
			}
			cfglist = parse_cfgfile(fp, cfgfile);
			fclose(fp);
		}
	}
	if (cfglist)
		process_cfglist(cfglist);
	return EXIT_SUCCESS;
}
