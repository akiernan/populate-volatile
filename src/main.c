/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * populate-volatile -- set up volatile (tmpfs/ramfs) directories, files and
 * symlinks from declarative config files in /etc/default/volatiles/.
 *
 * Usage:
 *   populate-volatile [-v] [-n] [-r <rootdir>] [-C <cfgdir>] [<cfgfile> ...]
 *
 *   -r <rootdir>   Root directory prefix (default: /).  When set the binary
 *                  is assumed to be running at rootfs build time; non-fatal
 *                  errors are suppressed so do_rootfs doesn't abort.
 *                  Runs under pseudo (https://git.yoctoproject.org/pseudo)
 *                  which intercepts ownership/permission syscalls to maintain
 *                  a fake-root database for the staged rootfs.
 *   -C <cfgdir>    Config directory (default: <rootdir>/etc/default/volatiles).
 *   -v             Verbose: log each action.
 *   -n             Dry-run: log what would happen; make no filesystem changes.
 *                  Implies -v.
 *   <cfgfile>...   Process only these config files (paths relative to cfgdir).
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pv/config.h"
#include "pv/ops.h"
#include "pv/path.h"
#include "pv/trace.h"
#include "pv/validate.h"

#define COREDEF "00_core"
#define DEFAULT_CFGSUBDIR "etc/default/volatiles"

/* Return a copy of s with trailing slashes stripped (except bare "/"). */
static const char *strip_trailing_slashes(const char *s)
{
	char *buf = strdup(s);
	if (buf == NULL)
		err(EXIT_FAILURE, "strdup");
	size_t len = strlen(buf);
	while (len > 1 && buf[len - 1] == '/')
		buf[--len] = '\0';
	return buf; /* intentional leak; lives for the process */
}

/* -------------------------------------------------------------------------
 * Entry list: a growable array of pv_entry_t for batch requirement checking.
 * ---------------------------------------------------------------------- */

typedef struct {
	pv_entry_t *data;
	size_t      len;
	size_t      cap;
} entry_list_t;

static int entry_list_push(entry_list_t *list, const pv_entry_t *e)
{
	if (list->len >= list->cap) {
		size_t newcap = list->cap == 0 ? 64 : list->cap * 2;
		pv_entry_t *newdata = realloc(list->data,
		                              newcap * sizeof(pv_entry_t));
		if (newdata == NULL) {
			warn("realloc");
			return -1;
		}
		list->data = newdata;
		list->cap  = newcap;
	}
	list->data[list->len++] = *e;
	return 0;
}

static void entry_list_free(entry_list_t *list)
{
	free(list->data);
	list->data = NULL;
	list->len  = 0;
	list->cap  = 0;
}

/* pv_parse_config callback that appends entries to an entry_list_t */
static int collect_cb(const pv_entry_t *entry, void *userdata)
{
	return entry_list_push((entry_list_t *)userdata, entry);
}

/* pv_parse_config callback that applies entries immediately via pv_apply_entry */
static int apply_cb(const pv_entry_t *entry, void *userdata)
{
	/* userdata is pv_ctx_t * — errors are non-fatal here; keep going */
	pv_apply_entry((pv_ctx_t *)userdata, entry);
	return 0;
}

/* -------------------------------------------------------------------------
 * Config file discovery and sorting
 * ---------------------------------------------------------------------- */

/*
 * Collect the names of regular files in dirfd (already open).
 * Sorts them alphabetically, with COREDEF ("00_core") always first.
 * Writes results into *names_out (caller must free each element and the array).
 * Returns the count, or -1 on error.
 */
static int cmp_name(const void *a, const void *b)
{
	const char *sa = *(const char *const *)a;
	const char *sb = *(const char *const *)b;
	int a_core = strcmp(sa, COREDEF) == 0;
	int b_core = strcmp(sb, COREDEF) == 0;
	if (a_core && !b_core) return -1;
	if (!a_core && b_core) return  1;
	return strcmp(sa, sb);
}

static int discover_cfgfiles(int cfgfd, char ***names_out)
{
	DIR *dir;
	struct dirent *ent;
	char **names = NULL;
	size_t count = 0, cap = 0;
	int tmpfd;

	/* fdopendir takes ownership; dup so we keep cfgfd usable */
	tmpfd = dup(cfgfd);
	if (tmpfd == -1) {
		warn("dup(cfgfd)");
		return -1;
	}
	dir = fdopendir(tmpfd);
	if (dir == NULL) {
		warn("fdopendir(cfgdir)");
		close(tmpfd);
		return -1;
	}

	while ((ent = readdir(dir)) != NULL) {
		if (ent->d_name[0] == '.')
			continue; /* skip . .. and hidden files */

		/* Only process regular files */
		if (ent->d_type != DT_REG && ent->d_type != DT_UNKNOWN) {
			if (ent->d_type == DT_UNKNOWN) {
				struct stat st;
				if (fstatat(cfgfd, ent->d_name, &st,
				            AT_SYMLINK_NOFOLLOW) == -1)
					continue;
				if (!S_ISREG(st.st_mode))
					continue;
			} else {
				continue;
			}
		}

		if (count >= cap) {
			size_t newcap = cap == 0 ? 32 : cap * 2;
			char **newnames = realloc(names,
			                          newcap * sizeof(char *));
			if (newnames == NULL) {
				warn("realloc");
				closedir(dir);
				for (size_t i = 0; i < count; i++)
					free(names[i]);
				free(names);
				return -1;
			}
			names = newnames;
			cap   = newcap;
		}
		names[count] = strdup(ent->d_name);
		if (names[count] == NULL) {
			warn("strdup");
			closedir(dir);
			for (size_t i = 0; i < count; i++)
				free(names[i]);
			free(names);
			return -1;
		}
		count++;
	}
	closedir(dir);

	if (count > 0)
		qsort(names, count, sizeof(char *), cmp_name);

	*names_out = names;
	return (int)count;
}

/* -------------------------------------------------------------------------
 * Processing helpers
 * ---------------------------------------------------------------------- */

/*
 * Apply a single config file.
 *   skip_reqs = 1 -> skip requirement checking (used for 00_core).
 * Returns 0 on success, 1 if requirements check fails (file skipped).
 */
static int process_cfgfile(const pv_ctx_t *ctx, int cfgfd,
                            const char *name, int skip_reqs)
{
	if (ctx->verbose)
		printf("Applying %s\n", name);

	if (!skip_reqs) {
		/* Collect all entries, then apply each one individually
		 * after checking its own user/group requirements.
		 * This matches the shell script's behaviour of skipping
		 * individual bad entries rather than the whole file. */
		entry_list_t list = {NULL, 0, 0};

		if (pv_parse_config(cfgfd, name, collect_cb, &list) == -1) {
			entry_list_free(&list);
			return 0; /* I/O error already warned */
		}
		for (size_t i = 0; i < list.len; i++) {
			if (pv_check_requirements(&list.data[i], 1) != 0) {
				warnx("Skipping %s %s (undefined user/group)",
				      name, list.data[i].name);
				continue;
			}
			pv_apply_entry(ctx, &list.data[i]);
		}
		entry_list_free(&list);
	} else {
		pv_parse_config(cfgfd, name, apply_cb, (void *)ctx);
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

static void usage(const char *prog)
{
	fprintf(stderr,
	        "usage: %s [-v] [-n] [-T] [-r rootdir] [-C cfgdir] [cfgfile ...]\n",
	        prog);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	const char *rootdir = "/";
	char cfgdir_buf[PATH_MAX];
	const char *cfgdir  = NULL;
	int verbose  = 0;
	int dry_run  = 0;
	int opt;

	while ((opt = getopt(argc, argv, "vnTr:C:")) != -1) {
		switch (opt) {
		case 'v': verbose = 1; break;
		case 'n': dry_run = 1; verbose = 1; break;
		case 'T': pv_trace = 1; break;
		case 'r': rootdir = optarg; break;
		case 'C': cfgdir  = optarg; break;
		default:  usage(argv[0]);
		}
	}
	/* remaining argv[optind..] are explicit cfgfile names */
	int nexplicit = argc - optind;
	char **explicit_files = argv + optind;

	rootdir = strip_trailing_slashes(rootdir);

	/* Default cfgdir */
	if (cfgdir == NULL) {
		int n = snprintf(cfgdir_buf, sizeof(cfgdir_buf),
		                 "%s/" DEFAULT_CFGSUBDIR,
		                 strcmp(rootdir, "/") == 0 ? "" : rootdir);
		if (n < 0 || (size_t)n >= sizeof(cfgdir_buf))
			errx(EXIT_FAILURE, "cfgdir path too long");
		cfgdir = cfgdir_buf;
	}

	/* Clear umask; save original for intermediate mkdir permissions */
	pv_saved_umask = umask(0);

	/* Open rootfd */
	int rootfd = open(rootdir, O_RDONLY | O_DIRECTORY);
	if (rootfd == -1)
		err(EXIT_FAILURE, "open rootdir: %s", rootdir);

	/* Open cfgfd */
	int cfgfd = open(cfgdir, O_RDONLY | O_DIRECTORY);
	if (cfgfd == -1)
		err(EXIT_FAILURE, "open cfgdir: %s", cfgdir);

	int rootfs_mode = strcmp(rootdir, "/") != 0;

	pv_ctx_t ctx = {
		.rootfd      = rootfd,
		.rootdir     = rootdir,
		.verbose     = (verbose  != 0),
		.dry_run     = (dry_run  != 0),
		.rootfs_mode = (rootfs_mode != 0),
	};

	if (verbose)
		printf("Populating volatile filesystems.\n");

	/* ----------------------------------------------------------------
	 * Discover or use explicit config file list
	 * -------------------------------------------------------------- */
	char **names  = NULL;
	int    nnames = 0;

	if (nexplicit > 0) {
		/* Caller supplied explicit file names */
		names  = explicit_files;
		nnames = nexplicit;
		/* No 00_core special case when files are explicitly listed */
		for (int i = 0; i < nnames; i++)
			process_cfgfile(&ctx, cfgfd, names[i], 0);
		goto done;
	}

	nnames = discover_cfgfiles(cfgfd, &names);
	if (nnames < 0)
		err(EXIT_FAILURE, "discover_cfgfiles");

	/* ----------------------------------------------------------------
	 * Step 1: apply 00_core unconditionally and without req checking.
	 * It sets up /var/volatile/tmp which check_requirements() needs.
	 * -------------------------------------------------------------- */
	int core_idx = -1;
	for (int i = 0; i < nnames; i++) {
		if (strcmp(names[i], COREDEF) == 0) {
			core_idx = i;
			break;
		}
	}
	if (core_idx >= 0)
		process_cfgfile(&ctx, cfgfd, names[core_idx], 1 /* skip_reqs */);

	/* ----------------------------------------------------------------
	 * Step 2: apply each non-core file individually.
	 * Files whose users/groups don't exist are skipped.
	 * -------------------------------------------------------------- */
	for (int i = 0; i < nnames; i++) {
		if (i == core_idx)
			continue;
		process_cfgfile(&ctx, cfgfd, names[i], 0);
	}

	/* Free discovered names (not freed when explicit_files used) */
	for (int i = 0; i < nnames; i++)
		free(names[i]);
	free(names);

done:
	close(cfgfd);
	close(rootfd);
	return EXIT_SUCCESS;
}
