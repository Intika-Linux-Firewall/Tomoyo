/*
 * ccs_rewrite_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2   2011/06/20
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
#include "include.h"

static int should_fail = 0;

static void show_prompt(const char *str)
{
	printf("Testing %35s: (%s) ", str,
	       should_fail ? "must fail" : "must success");
	errno = 0;
}

static void show_result(int result)
{
	if (should_fail) {
		if (result == EOF) {
			if (errno == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("BUG!\n");
		} else {
			printf("BUG!\n");
		}
	} else {
		if (result != EOF)
			printf("OK\n");
		else
			printf("BUG!\n");
	}
}

#define REWRITE_PATH "/tmp/rewrite_test"

static void stage_rewrite_test(void)
{
	int fd;

	/* Start up */
	write_domain_policy("file read " REWRITE_PATH, 0);
	write_domain_policy("file append " REWRITE_PATH, 0);
	write_domain_policy("file truncate " REWRITE_PATH, 0);
	write_domain_policy("file create " REWRITE_PATH " 0600", 0);
	write_domain_policy("file unlink " REWRITE_PATH, 0);
	set_profile(3, "file::open");
	set_profile(3, "file::create");
	set_profile(3, "file::truncate");
	set_profile(3, "file::unlink");
	close(open(REWRITE_PATH, O_WRONLY | O_APPEND | O_CREAT, 0600));

	/* Enforce mode */
	should_fail = 0;

	show_prompt("open(O_RDONLY)");
	fd = open(REWRITE_PATH, O_RDONLY);
	show_result(fd);
	close(fd);

	show_prompt("open(O_WRONLY | O_APPEND)");
	fd = open(REWRITE_PATH, O_WRONLY | O_APPEND);
	show_result(fd);
	close(fd);

	should_fail = 1;
	show_prompt("open(O_WRONLY)");
	fd = open(REWRITE_PATH, O_WRONLY);
	show_result(fd);
	close(fd);

	show_prompt("open(O_WRONLY | O_TRUNC)");
	fd = open(REWRITE_PATH, O_WRONLY | O_TRUNC);
	show_result(fd);
	close(fd);

	/* Permissive mode */
	set_profile(2, "file::open");
	set_profile(2, "file::create");
	set_profile(2, "file::truncate");
	set_profile(2, "file::unlink");
	should_fail = 0;

	show_prompt("open(O_RDONLY)");
	fd = open(REWRITE_PATH, O_RDONLY);
	show_result(fd);
	close(fd);

	show_prompt("open(O_WRONLY | O_APPEND)");
	fd = open(REWRITE_PATH, O_WRONLY | O_APPEND);
	show_result(fd);
	close(fd);

	show_prompt("open(O_WRONLY)");
	fd = open(REWRITE_PATH, O_WRONLY);
	show_result(fd);
	close(fd);

	show_prompt("open(O_WRONLY | O_TRUNC)");
	fd = open(REWRITE_PATH, O_WRONLY | O_TRUNC);
	show_result(fd);
	close(fd);

	/* Clean up */
	unlink(REWRITE_PATH);
	printf("\n\n");
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	stage_rewrite_test();
	clear_status();
	if (0) /* To suppress "defined but not used" warnings. */
		write_exception_policy("", 0);
	return 0;
}
