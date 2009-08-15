/*
 * tomoyo_rewrite_test.c
 *
 * Testing program for fs/tomoyo_file.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
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

static void add_domain_policy(const char *data)
{
	fprintf(profile_fp, "255-MAC_FOR_FILE=disabled\n");
	fprintf(domain_fp, "%s\n", data);
}

static void add_exception_policy(const char *data)
{
	fprintf(profile_fp, "255-MAC_FOR_FILE=disabled\n");
	fprintf(exception_fp, "%s\n", data);
}

#define REWRITE_PATH "/tmp/rewrite_test"

static void stage_rewrite_test(void)
{
	int fd;

	/* Start up */
	add_domain_policy("6 " REWRITE_PATH);
	add_domain_policy("allow_truncate " REWRITE_PATH);
	add_domain_policy("allow_create " REWRITE_PATH);
	add_domain_policy("allow_unlink " REWRITE_PATH);
	add_exception_policy("deny_rewrite " REWRITE_PATH);
	close(open(REWRITE_PATH, O_WRONLY | O_APPEND | O_CREAT, 0600));

	/* Enforce mode */
	fprintf(profile_fp, "255-MAC_FOR_FILE=enforcing\n");
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

	show_prompt("open(O_WRONLY | O_TRUNC | O_APPEND)");
	fd = open(REWRITE_PATH, O_WRONLY | O_TRUNC | O_APPEND);
	show_result(fd);
	close(fd);

	show_prompt("truncate()");
	show_result(truncate(REWRITE_PATH, 0));

	fd = open(REWRITE_PATH, O_WRONLY | O_APPEND);
	show_prompt("ftruncate()");
	show_result(ftruncate(fd, 0));

	show_prompt("fcntl(F_SETFL, ~O_APPEND)");
	show_result(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_APPEND));
	close(fd);

	/* Permissive mode */
	fprintf(profile_fp, "255-MAC_FOR_FILE=permissive\n");
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

	show_prompt("open(O_WRONLY | O_TRUNC | O_APPEND)");
	fd = open(REWRITE_PATH, O_WRONLY | O_TRUNC | O_APPEND);
	show_result(fd);
	close(fd);

	show_prompt("truncate()");
	show_result(truncate(REWRITE_PATH, 0));

	fd = open(REWRITE_PATH, O_WRONLY | O_APPEND);
	show_prompt("ftruncate()");
	show_result(ftruncate(fd, 0));

	show_prompt("fcntl(F_SETFL, ~O_APPEND)");
	show_result(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_APPEND));
	close(fd);

	/* Clean up */
	unlink(REWRITE_PATH);
	add_exception_policy("delete " "deny_rewrite " REWRITE_PATH);
	printf("\n\n");
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	if (access(proc_policy_domain_policy, F_OK)) {
		fprintf(stderr, "You can't use this program for this kernel."
			"\n");
		return 1;
	}
	stage_rewrite_test();
	clear_status();
	return 0;
}
