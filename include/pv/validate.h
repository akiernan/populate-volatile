/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PV_VALIDATE_H
#define PV_VALIDATE_H

#include <stddef.h>
#include "pv/config.h"

/*
 * Check whether username exists using getpwnam_r().
 *
 * At runtime the calling process IS the target environment so this is
 * trivially correct.  At rootfs build time the process runs under pseudo
 * (https://git.yoctoproject.org/pseudo) which sets PSEUDO_PASSWD to point
 * at the target rootfs's passwd database, so getpwnam_r() resolves against
 * the target image rather than the host.
 *
 * Returns 1 if found, 0 if not found, -1 on error.
 */
int pv_user_exists(const char *user);

/*
 * Check whether groupname exists using getgrnam_r().
 * Same environment rationale as pv_user_exists().
 *
 * Returns 1 if found, 0 if not found, -1 on error.
 */
int pv_group_exists(const char *group);

/*
 * Validate that every user and group referenced in entries[0..nentries-1]
 * can be resolved.  Prints each missing name to stderr.
 *
 * Returns 0 if all users and groups are present, 1 if any are missing.
 */
int pv_check_requirements(const pv_entry_t *entries, size_t nentries);

#endif /* PV_VALIDATE_H */
