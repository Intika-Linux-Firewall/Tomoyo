/*
 * ccs_execute_handler_test.c
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

int main(int raw_argc, char *raw_argv[])
{
	char buffer[4096];
	char *cp;
	int error;
	memset(buffer, 0, sizeof(buffer));
	{
		void *ret_ignored;
		FILE *fp = fopen(proc_policy_process_status, "r+");
		if (!fp) {
			printf("BUG: Can't open %s\n",
			       proc_policy_process_status);
			return 1;
		}
		fprintf(fp, "info %d\n", getpid());
		fflush(fp);
		ret_ignored = fgets(buffer, sizeof(buffer) - 1, fp);
		fclose(fp);
	}
	if (strstr(buffer, " execute_handler=yes")) {
		int i;
		int argc;
		int envc;
		char *filename;
		char **argv;
		char **envp;
		if (raw_argc < 7)
			return 1;
		filename = raw_argv[4];
		argc = atoi(raw_argv[5]);
		envc = atoi(raw_argv[6]);
		if (raw_argc != argc + envc + 7)
			return 1;
		for (i = 5; i < argc + 5; i++)
			raw_argv[i] = raw_argv[i + 2];
		raw_argv[argc + 5] = NULL;
		for (i = argc + 6; i < argc + envc + 6; i++)
			raw_argv[i] = raw_argv[i + 1];
		raw_argv[argc + envc + 6] = NULL;
		argv = raw_argv + 5;
		envp = raw_argv + argc + 6;
		/*
		 * Check parameters passed to execve() request.
		 */
		if (0) {
			fprintf(stderr, "Domain = %s\n", raw_argv[1]);
			fprintf(stderr, "Caller Program = %s\n", raw_argv[2]);
			fprintf(stderr, "Process Status = %s\n", raw_argv[3]);
			fprintf(stderr, "Requested Program = %s\n", filename);
			fprintf(stderr, "argc=%d\n", argc);
			fprintf(stderr, "envc=%d\n", envc);
			for (i = 0; i < argc; i++)
				fprintf(stderr, "argv[%d] = %s\n", i, argv[i]);
			for (i = 0; i < envc; i++)
				fprintf(stderr, "envp[%d] = %s\n", i, envp[i]);
			fprintf(stderr, "\n");
		}
		/*
		 * Continue if filename and argv[] and envp[] are appropriate.
		 */
		if (1)
			execve(filename, argv, envp);
		return 1;
	}
	ccs_test_init();
	cp = strrchr(self_domain, ' ');
	if (!cp)
		return 1;
	cp++;
	fprintf(domain_fp, "task auto_execute_handler %s\n", cp);
	fprintf(domain_fp, "%s %s\n", self_domain, cp);
	fprintf(domain_fp, "use_profile 0\n");
	fprintf(domain_fp, "use_group 0\n");
	fflush(domain_fp);
	set_profile(3, "file::open");
	if (fork() == 0) {
		char *arg[3] = { "echo", "OK: execute handler succeeded",
				 NULL };
		char *env[2] = { "execute_handler", NULL };
		execve(BINDIR "/echo", arg, env);
		_exit(1);
	}
	wait(&error);
	set_profile(0, "file::open");
	error = WIFEXITED(error) ? WEXITSTATUS(error) : -1;
	if (error) {
		printf("BUG: execute handler failed\n");
		fflush(stdout);
	}
	fprintf(domain_fp, "delete task auto_execute_handler %s\n", cp);
	fprintf(domain_fp, "task denied_execute_handler %s\n", cp);
	fprintf(domain_fp, "delete file execute " BINDIR "/echo\n");
	set_profile(3, "file::execute");
	set_profile(3, "file::open");
	if (fork() == 0) {
		char *arg[3] = { "echo", "OK: denied execute handler succeeded",
				 NULL };
		char *env[2] = { "denied_execute_handler", NULL };
		execve(BINDIR "/echo", arg, env);
		_exit(1);
	}
	wait(&error);
	set_profile(0, "file::open");
	error = WIFEXITED(error) ? WEXITSTATUS(error) : -1;
	if (error) {
		printf("BUG: denied execute handler failed\n");
		fflush(stdout);
	}
	set_profile(0, "file::execute");
	fprintf(domain_fp, "delete task denied_execute_handler %s\n", cp);
	clear_status();
	if (0) { /* To suppress "defined but not used" warnings. */
		write_domain_policy("", 0);
		write_exception_policy("", 0);
	}
	return 0;
}
