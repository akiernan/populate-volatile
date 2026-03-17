/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "unity.h"
#include "pv/config.h"

void setUp(void) {}
void tearDown(void) {}

/* -------------------------------------------------------------------------
 * pv_parse_line tests
 * ---------------------------------------------------------------------- */

static void test_parse_line_file(void)
{
	pv_entry_t e;
	int r = pv_parse_line("f root root 0644 /var/run/utmp none", &e);
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_INT(PV_TYPE_FILE, e.type);
	TEST_ASSERT_EQUAL_STRING("root", e.user);
	TEST_ASSERT_EQUAL_STRING("root", e.group);
	TEST_ASSERT_EQUAL_UINT(0644, e.mode);
	TEST_ASSERT_EQUAL_STRING("/var/run/utmp", e.name);
	TEST_ASSERT_EQUAL_STRING("", e.ltarget); /* "none" -> empty */
}

static void test_parse_line_dir(void)
{
	pv_entry_t e;
	int r = pv_parse_line("d root root 0755 /var/volatile/tmp none", &e);
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_INT(PV_TYPE_DIR, e.type);
	TEST_ASSERT_EQUAL_STRING("/var/volatile/tmp", e.name);
	TEST_ASSERT_EQUAL_UINT(0755, e.mode);
	TEST_ASSERT_EQUAL_STRING("", e.ltarget);
}

static void test_parse_line_link(void)
{
	pv_entry_t e;
	int r = pv_parse_line("l root root 0755 /var/log /var/volatile/log", &e);
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_INT(PV_TYPE_LINK, e.type);
	TEST_ASSERT_EQUAL_STRING("/var/log", e.name);
	TEST_ASSERT_EQUAL_STRING("/var/volatile/log", e.ltarget);
}

static void test_parse_line_bind(void)
{
	pv_entry_t e;
	int r = pv_parse_line("b root root 0755 /mnt/data /data", &e);
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_INT(PV_TYPE_BIND, e.type);
	TEST_ASSERT_EQUAL_STRING("/mnt/data", e.name);
	TEST_ASSERT_EQUAL_STRING("/data", e.ltarget);
}

static void test_parse_line_ltarget_none_becomes_empty(void)
{
	pv_entry_t e;
	pv_parse_line("f root root 0640 /var/run/wtmp none", &e);
	TEST_ASSERT_EQUAL_STRING("", e.ltarget);
}

static void test_parse_line_ltarget_path_preserved(void)
{
	pv_entry_t e;
	pv_parse_line("f root root 0644 /etc/nologin /etc/nologin.tmpl", &e);
	TEST_ASSERT_EQUAL_STRING("/etc/nologin.tmpl", e.ltarget);
}

static void test_parse_line_skip_comment(void)
{
	pv_entry_t e;
	int r = pv_parse_line("# this is a comment", &e);
	TEST_ASSERT_EQUAL_INT(1, r);
}

static void test_parse_line_skip_blank(void)
{
	pv_entry_t e;
	int r = pv_parse_line("   \t\n", &e);
	TEST_ASSERT_EQUAL_INT(1, r);
}

static void test_parse_line_skip_empty(void)
{
	pv_entry_t e;
	int r = pv_parse_line("", &e);
	TEST_ASSERT_EQUAL_INT(1, r);
}

static void test_parse_line_inline_comment_stripped(void)
{
	pv_entry_t e;
	/* comment after fields */
	int r = pv_parse_line("d root root 0700 /run/lock none # locking dir", &e);
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_STRING("/run/lock", e.name);
}

static void test_parse_line_unknown_type(void)
{
	pv_entry_t e;
	int r = pv_parse_line("x root root 0644 /foo none", &e);
	TEST_ASSERT_EQUAL_INT(-1, r);
}

static void test_parse_line_too_few_fields(void)
{
	pv_entry_t e;
	int r = pv_parse_line("d root root 0755 /var/run", &e); /* missing ltarget */
	TEST_ASSERT_EQUAL_INT(-1, r);
}

static void test_parse_line_mode_octal(void)
{
	pv_entry_t e;
	pv_parse_line("d root root 0750 /var/lib/foo none", &e);
	TEST_ASSERT_EQUAL_UINT(0750, e.mode);
}

static void test_parse_line_invalid_mode(void)
{
	pv_entry_t e;
	int r = pv_parse_line("d root root 0999 /var/lib/foo none", &e);
	TEST_ASSERT_EQUAL_INT(-1, r);
}

/* -------------------------------------------------------------------------
 * pv_parse_config tests
 * ---------------------------------------------------------------------- */

typedef struct {
	pv_entry_t *entries;
	int count;
	int capacity;
} cb_state_t;

static int collect_entries(const pv_entry_t *e, void *ud)
{
	cb_state_t *s = (cb_state_t *)ud;
	if (s->count >= s->capacity)
		return -1;
	s->entries[s->count++] = *e;
	return 0;
}

static void test_parse_config_multiline(void)
{
	/* Write a temporary config file */
	char tmppath[] = "/tmp/pv_test_config_XXXXXX";
	int fd = mkstemp(tmppath);
	TEST_ASSERT_NOT_EQUAL(-1, fd);

	const char *content =
		"# volatiles config\n"
		"d root root 0755 /var/volatile none\n"
		"\n"
		"f root utmp 0664 /var/run/utmp none\n"
		"l root root 0755 /var/log /var/volatile/log\n";

	write(fd, content, strlen(content));
	close(fd);

	pv_entry_t buf[16];
	cb_state_t state = { buf, 0, 16 };

	int r = pv_parse_config(AT_FDCWD, tmppath, collect_entries, &state);
	TEST_ASSERT_EQUAL_INT(0, r);
	TEST_ASSERT_EQUAL_INT(3, state.count);

	TEST_ASSERT_EQUAL_INT(PV_TYPE_DIR,  state.entries[0].type);
	TEST_ASSERT_EQUAL_INT(PV_TYPE_FILE, state.entries[1].type);
	TEST_ASSERT_EQUAL_INT(PV_TYPE_LINK, state.entries[2].type);

	unlink(tmppath);
}

static void test_parse_config_missing_file(void)
{
	pv_entry_t buf[4];
	cb_state_t state = { buf, 0, 4 };
	int r = pv_parse_config(AT_FDCWD, "/nonexistent/path/volatile.conf",
	                        collect_entries, &state);
	TEST_ASSERT_EQUAL_INT(-1, r);
}

static void test_parse_config_callback_abort(void)
{
	char tmppath[] = "/tmp/pv_test_config_abort_XXXXXX";
	int fd = mkstemp(tmppath);
	TEST_ASSERT_NOT_EQUAL(-1, fd);

	const char *content =
		"d root root 0755 /a none\n"
		"d root root 0755 /b none\n"
		"d root root 0755 /c none\n";
	write(fd, content, strlen(content));
	close(fd);

	/* Callback that aborts after first entry */
	pv_entry_t buf[16];
	cb_state_t state = { buf, 0, 1 }; /* capacity=1 -> abort after first */

	int r = pv_parse_config(AT_FDCWD, tmppath, collect_entries, &state);
	TEST_ASSERT_EQUAL_INT(-1, r);
	TEST_ASSERT_EQUAL_INT(1, state.count);

	unlink(tmppath);
}

/* -------------------------------------------------------------------------
 * Test runner
 * ---------------------------------------------------------------------- */

int main(void)
{
	UNITY_BEGIN();

	RUN_TEST(test_parse_line_file);
	RUN_TEST(test_parse_line_dir);
	RUN_TEST(test_parse_line_link);
	RUN_TEST(test_parse_line_bind);
	RUN_TEST(test_parse_line_ltarget_none_becomes_empty);
	RUN_TEST(test_parse_line_ltarget_path_preserved);
	RUN_TEST(test_parse_line_skip_comment);
	RUN_TEST(test_parse_line_skip_blank);
	RUN_TEST(test_parse_line_skip_empty);
	RUN_TEST(test_parse_line_inline_comment_stripped);
	RUN_TEST(test_parse_line_unknown_type);
	RUN_TEST(test_parse_line_too_few_fields);
	RUN_TEST(test_parse_line_mode_octal);
	RUN_TEST(test_parse_line_invalid_mode);
	RUN_TEST(test_parse_config_multiline);
	RUN_TEST(test_parse_config_missing_file);
	RUN_TEST(test_parse_config_callback_abort);

	return UNITY_END();
}
