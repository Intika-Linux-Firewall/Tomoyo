/*
 * tomoyo_env_test.c
 *
 * Testing program for fs/tomoyo_env.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.8   2009/05/28
 *
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

static void stage_env_test(void)
{
	static char buffer[1024];
	char *argv[2] = { "true", NULL };
	char *envp[2] = { "env-test", NULL };
	int status = 0;
	memset(buffer, 0, sizeof(buffer));
	{
		is_enforce = 0;
		write_status("MAC_FOR_ENV=permissive\n");
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

		is_enforce = 1;
		write_status("MAC_FOR_ENV=enforcing\n");
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

		is_enforce = 0;
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
	if (access(proc_policy_domain_policy, F_OK)) {
		fprintf(stderr, "You can't use this program for this kernel."
			"\n");
		return 1;
	}
	stage_env_test();
	clear_status();
	return 0;
}
