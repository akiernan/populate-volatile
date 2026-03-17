/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Tests for pv_user_exists, pv_group_exists, pv_check_requirements.
 *
 * All three functions now use getpwnam_r / getgrnam_r, so tests run against
 * the real NSS database of the current process.  At rootfs build time this
 * is the target's database (pseudo sets PSEUDO_PASSWD); at runtime and in
 * CI it is the host/container's database.
 *
 * We only rely on names that are guaranteed to exist in any Linux environment:
 *   user  "root"   (uid 0)
 *   group "root"   (gid 0)
 * and names that are guaranteed not to exist:
 *   "this_user_will_never_exist_xyzzy"
 *   "this_group_will_never_exist_xyzzy"
 */

#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>

#include <stddef.h>
#include <string.h>

#include "unity.h"
#include "pv/config.h"
#include "pv/validate.h"

void setUp(void) {}
void tearDown(void) {}

/* -------------------------------------------------------------------------
 * pv_user_exists
 * ---------------------------------------------------------------------- */

static void test_user_exists_root(void)
{
	TEST_ASSERT_EQUAL_INT(1, pv_user_exists("root"));
}

static void test_user_exists_nonexistent(void)
{
	TEST_ASSERT_EQUAL_INT(0,
	    pv_user_exists("this_user_will_never_exist_xyzzy"));
}

/* -------------------------------------------------------------------------
 * pv_group_exists
 * ---------------------------------------------------------------------- */

static void test_group_exists_root(void)
{
	TEST_ASSERT_EQUAL_INT(1, pv_group_exists("root"));
}

static void test_group_exists_nonexistent(void)
{
	TEST_ASSERT_EQUAL_INT(0,
	    pv_group_exists("this_group_will_never_exist_xyzzy"));
}

/* -------------------------------------------------------------------------
 * pv_check_requirements
 * ---------------------------------------------------------------------- */

static void test_check_requirements_all_valid(void)
{
	pv_entry_t entries[2];
	memset(entries, 0, sizeof(entries));

	strcpy(entries[0].user,  "root");
	strcpy(entries[0].group, "root");
	strcpy(entries[0].name,  "/var/run/utmp");

	strcpy(entries[1].user,  "root");
	strcpy(entries[1].group, "root");
	strcpy(entries[1].name,  "/tmp");

	TEST_ASSERT_EQUAL_INT(0, pv_check_requirements(entries, 2));
}

static void test_check_requirements_missing_user(void)
{
	pv_entry_t entry;
	memset(&entry, 0, sizeof(entry));
	strcpy(entry.user,  "this_user_will_never_exist_xyzzy");
	strcpy(entry.group, "root");
	strcpy(entry.name,  "/var/www");

	TEST_ASSERT_EQUAL_INT(1, pv_check_requirements(&entry, 1));
}

static void test_check_requirements_missing_group(void)
{
	pv_entry_t entry;
	memset(&entry, 0, sizeof(entry));
	strcpy(entry.user,  "root");
	strcpy(entry.group, "this_group_will_never_exist_xyzzy");
	strcpy(entry.name,  "/etc/sudoers");

	TEST_ASSERT_EQUAL_INT(1, pv_check_requirements(&entry, 1));
}

static void test_check_requirements_empty_list(void)
{
	TEST_ASSERT_EQUAL_INT(0, pv_check_requirements(NULL, 0));
}

static void test_check_requirements_multiple_one_bad(void)
{
	pv_entry_t entries[3];
	memset(entries, 0, sizeof(entries));

	strcpy(entries[0].user, "root");
	strcpy(entries[0].group, "root");

	strcpy(entries[1].user, "this_user_will_never_exist_xyzzy");
	strcpy(entries[1].group, "root");

	strcpy(entries[2].user, "root");
	strcpy(entries[2].group, "root");

	TEST_ASSERT_EQUAL_INT(1, pv_check_requirements(entries, 3));
}

/* -------------------------------------------------------------------------
 * Test runner
 * ---------------------------------------------------------------------- */

int main(void)
{
	UNITY_BEGIN();

	RUN_TEST(test_user_exists_root);
	RUN_TEST(test_user_exists_nonexistent);
	RUN_TEST(test_group_exists_root);
	RUN_TEST(test_group_exists_nonexistent);
	RUN_TEST(test_check_requirements_all_valid);
	RUN_TEST(test_check_requirements_missing_user);
	RUN_TEST(test_check_requirements_missing_group);
	RUN_TEST(test_check_requirements_empty_list);
	RUN_TEST(test_check_requirements_multiple_one_bad);

	return UNITY_END();
}
