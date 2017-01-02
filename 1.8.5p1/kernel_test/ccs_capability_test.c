/*
 * ccs_capability_test.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.8.5   2015/11/11
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

static int should_success = 0;
static int is_enforce = 0;

static void show_prompt(const char *str)
{
	if (should_success)
		printf("Testing %34s: (%s) ", str, "should success");
	else
		printf("Testing %34s: (%s) ", str,
		       is_enforce ? "must fail" : "should success");
	errno = 0;
}

static void show_result(int result)
{
	if (should_success) {
		if (result != EOF)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
	} else if (is_enforce) {
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
			printf("FAILED: %s\n", strerror(errno));
	}
}

static void set_capability(const char *capability)
{
	char buffer[128];
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "capability::%s", capability);
	set_profile(is_enforce ? 3 : 2, buffer);
	if (should_success)
		fprintf(domain_fp, "capability %s\n", capability);
}

static void unset_capability(const char *capability)
{
	char buffer[128];
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "capability::%s", capability);
	set_profile(0, buffer);
	if (should_success)
		fprintf(domain_fp, "delete capability %s\n", capability);
}

static void stage_capability_test(void)
{
	int fd;
	char tmp1[128];
	char tmp2[128];
	int ret_ignored;
	memset(tmp1, 0, sizeof(tmp1));
	memset(tmp2, 0, sizeof(tmp2));

	set_capability("use_route");
	show_prompt("use_route");
	fd = socket(AF_ROUTE, SOCK_RAW, 0);
	show_result(fd);
	if (fd != EOF)
		close(fd);
	unset_capability("use_route");

	set_capability("use_packet");
	show_prompt("use_packet");
	fd = socket(AF_PACKET, SOCK_RAW, 0);
	show_result(fd);
	if (fd != EOF)
		close(fd);
	unset_capability("use_packet");

	set_capability("use_kernel_module");
	if (!is_kernel26) {
		show_prompt("use_kernel_module(create_module())");
		show_result((long) create_module("", 0));
	}
	show_prompt("use_kernel_module(init_module())");
	show_result(init_module("", NULL));
	show_prompt("use_kernel_module(delete_module())");
	show_result(delete_module(""));
	unset_capability("use_kernel_module");

	set_capability("SYS_REBOOT");
	show_prompt("SYS_REBOOT");
	{
		FILE *fp = fopen("/proc/sys/kernel/ctrl-alt-del", "a+");
		unsigned int c;
		if (fp && fscanf(fp, "%u", &c) == 1) {
			show_result(reboot(LINUX_REBOOT_CMD_CAD_ON));
			rewind(fp);
			fprintf(fp, "%u\n", c);
		} else {
			/* Use invalid value */
			show_result(reboot(0x0000C0DE));
		}
		if (fp)
			fclose(fp);
	}
	unset_capability("SYS_REBOOT");

	set_capability("SYS_KEXEC_LOAD");
	if (is_kernel26) {
#ifdef __NR_sys_kexec_load
		show_prompt("SYS_KEXEC_LOAD");
		show_result(sys_kexec_load(0, 0, NULL, 0));
#endif
	}
	unset_capability("SYS_KEXEC_LOAD");

	{
		int status = 0;
		int pipe_fd[2] = { EOF, EOF };
		ret_ignored = pipe(pipe_fd);
		set_capability("SYS_VHANGUP");
		switch (fork()) {
		case 0:
			setsid();
			errno = 0;
			vhangup();
			status = errno;
			ret_ignored = write(pipe_fd[1], &status,
					    sizeof(status));
			_exit(0);
		case -1:
			fprintf(stderr, "fork() failed.\n");
			break;
		default:
			close(pipe_fd[1]);
			ret_ignored = read(pipe_fd[0], &status, sizeof(status));
			wait(NULL);
			close(pipe_fd[0]);
			show_prompt("SYS_VHANGUP");
			errno = status;
			show_result(status ? EOF : 0);
		}
		unset_capability("SYS_VHANGUP");
	}

	{
		struct timeval tv;
		struct timezone tz;
		struct timex buf;
		time_t now = time(NULL);
		set_capability("SYS_TIME");
		show_prompt("SYS_TIME(stime())");
		show_result(stime(&now));
		gettimeofday(&tv, &tz);
		show_prompt("SYS_TIME(settimeofday())");
		show_result(settimeofday(&tv, &tz));
		memset(&buf, 0, sizeof(buf));
		buf.modes = 0x100; /* Use invalid value so that the clock won't
				      change. */
		show_prompt("SYS_TIME(adjtimex())");
		show_result(adjtimex(&buf));
		unset_capability("SYS_TIME");
	}

	set_capability("SYS_NICE");
	show_prompt("SYS_NICE(nice())");
	show_result(nice(0));
	show_prompt("SYS_NICE(setpriority())");
	show_result(setpriority(PRIO_PROCESS, pid,
			       getpriority(PRIO_PROCESS, pid)));
	unset_capability("SYS_NICE");

	{
		char buffer[4096];
		memset(buffer, 0, sizeof(buffer));
		set_capability("SYS_SETHOSTNAME");
		gethostname(buffer, sizeof(buffer) - 1);
		show_prompt("SYS_SETHOSTNAME(sethostname())");
		show_result(sethostname(buffer, strlen(buffer)));
		ret_ignored = getdomainname(buffer, sizeof(buffer) - 1);
		show_prompt("SYS_SETHOSTNAME(setdomainname())");
		show_result(setdomainname(buffer, strlen(buffer)));
		unset_capability("SYS_SETHOSTNAME");
	}

	{
		int status = 0;
		int pipe_fd[2] = { EOF, EOF };
		ret_ignored = pipe(pipe_fd);
		set_capability("SYS_PTRACE");
		switch (fork()) {
		case 0:
			errno = 0;
			ptrace(PTRACE_TRACEME, 0, NULL, NULL);
			status = errno;
			ret_ignored = write(pipe_fd[1], &status,
					    sizeof(status));
			_exit(0);
		case -1:
			fprintf(stderr, "fork() failed.\n");
			break;
		default:
			close(pipe_fd[1]);
			ret_ignored = read(pipe_fd[0], &status, sizeof(status));
			wait(NULL);
			close(pipe_fd[0]);
			show_prompt("SYS_PTRACE");
			errno = status;
			show_result(status ? EOF : 0);
		}
		unset_capability("SYS_PTRACE");
	}
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	printf("***** Testing capability hooks in enforce mode. *****\n");
	is_enforce = 1;
	stage_capability_test();
	printf("\n\n");
	printf("***** Testing capability hooks in permissive mode. *****\n");
	is_enforce = 0;
	stage_capability_test();
	printf("\n\n");
	should_success = 1;
	printf("***** Testing capability hooks in enforce mode with policy. "
	       "*****\n");
	is_enforce = 1;
	fprintf(domain_fp, "select pid=%u\n", getpid());
	stage_capability_test();
	printf("\n\n");
	clear_status();
	if (0) { /* To suppress "defined but not used" warnings. */
		write_domain_policy("", 0);
		write_exception_policy("", 0);
	}
	return 0;
}
