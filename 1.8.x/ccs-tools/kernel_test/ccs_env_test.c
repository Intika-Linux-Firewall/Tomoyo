/*
 * ccs_env_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.4   2015/05/05
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
	printf("Testing %40s: (%s) ", str,
	       should_fail ? "must fail" : "should success");
	errno = 0;
}

static void show_result(int result)
{
	if (should_fail) {
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

static void stage_env_test(void)
{
	static char buffer[1024];
	char *argv[2] = { "true", NULL };
	char *envp[2] = { "env-test", NULL };
	int status = 0;
	memset(buffer, 0, sizeof(buffer));
	{
		should_fail = 0;
		set_profile(2, "misc::env");
		if (fork() == 0) {
			execve(BINDIR "/true", argv, envp);
			_exit(errno);
		}
		snprintf(buffer, sizeof(buffer) - 1,
			 "Executing " BINDIR "/true in permissive mode");
		show_prompt(buffer);
		wait(&status);
		errno = WEXITSTATUS(status);
		show_result(errno ? EOF : 0);

		should_fail = 1;
		set_profile(3, "misc::env");
		if (fork() == 0) {
			execve(BINDIR "/true", argv, envp);
			_exit(errno);
		}
		snprintf(buffer, sizeof(buffer) - 1,
			 "Executing " BINDIR "/true in enforce mode");
		show_prompt(buffer);
		wait(&status);
		errno = WEXITSTATUS(status);
		show_result(errno ? EOF : 0);

		should_fail = 0;
		if (fork() == 0) {
			envp[0] = "";
			execve(BINDIR "/true", argv, envp);
			_exit(errno);
		}
		snprintf(buffer, sizeof(buffer) - 1,
			 "Executing " BINDIR "/true in enforce mode");
		show_prompt(buffer);
		wait(&status);
		errno = WEXITSTATUS(status);
		show_result(errno ? EOF : 0);
	}
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	stage_env_test();
	clear_status();
	if (0) { /* To suppress "defined but not used" warnings. */
		write_domain_policy("", 0);
		write_exception_policy("", 0);
	}
	return 0;
}
