/*
 * ccs_env_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
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
			execve("/bin/true", argv, envp);
			_exit(errno);
		}
		snprintf(buffer, sizeof(buffer) - 1,
			 "Executing /bin/true in permissive mode");
		show_prompt(buffer);
		wait(&status);
		errno = WEXITSTATUS(status);
		show_result(errno ? EOF : 0);

		should_fail = 1;
		set_profile(3, "misc::env");
		if (fork() == 0) {
			execve("/bin/true", argv, envp);
			_exit(errno);
		}
		snprintf(buffer, sizeof(buffer) - 1,
			 "Executing /bin/true in enforce mode");
		show_prompt(buffer);
		wait(&status);
		errno = WEXITSTATUS(status);
		show_result(errno ? EOF : 0);

		should_fail = 0;
		if (fork() == 0) {
			envp[0] = "";
			execve("/bin/true", argv, envp);
			_exit(errno);
		}
		snprintf(buffer, sizeof(buffer) - 1,
			 "Executing /bin/true in enforce mode");
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
	return 0;
}
