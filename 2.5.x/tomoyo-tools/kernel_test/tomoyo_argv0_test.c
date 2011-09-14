/*
 * ccs_argv0_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0   2011/08/06
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

static int is_enforce = 0;

static void show_prompt(const char *str)
{
	printf("Testing %40s: (%s) ", str,
	       is_enforce ? "must fail" : "should success");
	errno = 0;
}

static void show_result(int result)
{
	if (is_enforce) {
		if (result == EOF) {
			if (errno == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("FAILED: %s\n", strerror(errno));
		} else {
			printf("BUG!\n");
		}
	} else {
		if (result != EOF)
			printf("OK\n");
		else
			printf("%s\n", strerror(errno));
	}
}

static void stage_argv0_test(void)
{
	static char buffer[1024];
	char *argv[2] = { "false", NULL };
	int status = 0;
	memset(buffer, 0, sizeof(buffer));
	{
		is_enforce = 0;
		set_profile(2, "file::execute");
		fflush(stdout);
		if (fork() == 0) {
			execv("/bin/true", argv);
			_exit(errno);
		}
		snprintf(buffer, sizeof(buffer) - 1,
			 "Executing /bin/true in permissive mode");
		show_prompt(buffer);
		wait(&status);
		errno = WEXITSTATUS(status);
		show_result(errno ? EOF : 0);

		is_enforce = 1;
		set_profile(3, "file::execute");
		fflush(stdout);
		if (fork() == 0) {
			execv("/bin/true", argv);
			_exit(errno);
		}
		snprintf(buffer, sizeof(buffer) - 1,
			 "Executing /bin/true in enforce mode");
		show_prompt(buffer);
		wait(&status);
		errno = WEXITSTATUS(status);
		show_result(errno ? EOF : 0);

		write_domain_policy("file execute /bin/true", 0);
		is_enforce = 0;
		fflush(stdout);
		if (fork() == 0) {
			argv[0] = "";
			execv("/bin/true", argv);
			_exit(errno);
		}
		snprintf(buffer, sizeof(buffer) - 1,
			 "Executing /bin/true in enforce mode");
		show_prompt(buffer);
		wait(&status);
		errno = WEXITSTATUS(status);
		show_result(errno ? EOF : 0);
		write_domain_policy("file execute /bin/true", 1);
	}
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	stage_argv0_test();
	clear_status();
	if (0) /* To suppress "defined but not used" warnings. */
		write_exception_policy("", 0);
	return 0;
}
