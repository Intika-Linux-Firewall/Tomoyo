/*
 * ccs_new_capability_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.5.0   2011/09/29
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

static const char *capability = "";

static int write_policy(void)
{
	FILE *fp = fopen(proc_policy_domain_policy, "r");
	char buffer[8192];
	int domain_found = 0;
	int policy_found = 0;
	memset(buffer, 0, sizeof(buffer));
	fprintf(domain_fp, "capability %s\n", capability);
	fflush(domain_fp);
	if (!fp) {
		printf("capability %s : BUG: capability read failed\n",
		       capability);
		return 0;
	}
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!strncmp(buffer, "<kernel>", 8))
			domain_found = !strcmp(self_domain, buffer);
		if (!domain_found)
			continue;
		if (!strncmp(buffer, "capability ", 11) &&
		    !strcmp(buffer + 11, capability)) {
			policy_found = 1;
			break;
		}
	}
	fclose(fp);
	if (!policy_found) {
		printf("capability %s : BUG: capability write failed\n",
		       capability);
		return 0;
	}
	errno = 0;
	return 1;
}

static void delete_policy(void)
{
	fprintf(domain_fp, "delete capability %s\n",
		capability);
	fflush(domain_fp);
}

static void show_result(int result, char should_success)
{
	int err = errno;
	printf("capability %s : ", capability);
	if (should_success) {
		if (result != EOF)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(err));
	} else {
		if (result == EOF) {
			if (err == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("FAILED: %s\n", strerror(err));
		} else {
			printf("BUG\n");
		}
	}
}

static void set_capability(void)
{
	char buffer[128];
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "capability::%s", capability);
	set_profile(3, buffer);
}

static void unset_capability(void)
{
	char buffer[128];
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "capability::%s", capability);
	set_profile(0, buffer);
}

static void stage_capability_test(void)
{
	char tmp1[128];
	char tmp2[128];
	int ret_ignored;
	memset(tmp1, 0, sizeof(tmp1));
	memset(tmp2, 0, sizeof(tmp2));

	capability = "use_route";
	set_capability();
	if (write_policy()) {
		int fd = socket(AF_ROUTE, SOCK_RAW, 0);
		show_result(fd, 1);
		if (fd != EOF)
			close(fd);
		delete_policy();
		fd = socket(AF_ROUTE, SOCK_RAW, 0);
		show_result(fd, 0);
		if (fd != EOF)
			close(fd);
	}
	unset_capability();

	capability = "use_packet";
	set_capability();
	if (write_policy()) {
		int fd = socket(AF_PACKET, SOCK_RAW, 0);
		show_result(fd, 1);
		if (fd != EOF)
			close(fd);
		delete_policy();
		fd = socket(AF_PACKET, SOCK_RAW, 0);
		show_result(fd, 0);
		if (fd != EOF)
			close(fd);
	}
	unset_capability();

	capability = "use_kernel_module";
	set_capability();
	if (write_policy()) {
		if (!is_kernel26)
			show_result((int) create_module("", 0), 1);
		show_result(init_module("", NULL), 1);
		show_result(delete_module(""), 1);
		delete_policy();
		if (!is_kernel26)
			show_result((int) create_module("", 0), 0);
		show_result(init_module("", NULL), 0);
		show_result(delete_module(""), 0);
	}
	unset_capability();

	capability = "SYS_REBOOT";
	set_capability();
	if (write_policy()) {
		FILE *fp = fopen("/proc/sys/kernel/ctrl-alt-del", "a+");
		unsigned int c;
		if (fp && fscanf(fp, "%u", &c) == 1) {
			show_result(reboot(LINUX_REBOOT_CMD_CAD_ON), 1);
			delete_policy();
			show_result(reboot(LINUX_REBOOT_CMD_CAD_ON), 0);
			fprintf(fp, "%u\n", c);
		} else {
			/* Use invalid value */
			show_result(reboot(0x0000C0DE), 1);
			delete_policy();
			show_result(reboot(0x0000C0DE), 0);
		}
		if (fp)
			fclose(fp);
	}
	unset_capability();

	capability = "SYS_KEXEC_LOAD";
	set_capability();
	if (write_policy()) {
#ifdef __NR_sys_kexec_load
		if (is_kernel26)
			show_result(sys_kexec_load(0, 0, NULL, 0), 1);
#endif
		delete_policy();
#ifdef __NR_sys_kexec_load
		if (is_kernel26)
			show_result(sys_kexec_load(0, 0, NULL, 0), 0);
#endif
	}
	unset_capability();

	capability = "SYS_VHANGUP";
	set_capability();
	if (write_policy()) {
		int pty_fd = EOF, status = 0;
		int pipe_fd[2] = { EOF, EOF };
		ret_ignored = pipe(pipe_fd);
		switch (forkpty(&pty_fd, NULL, NULL, NULL)) {
		case 0:
			errno = 0;
			vhangup();
			/* Unreachable if vhangup() succeeded. */
			status = errno;
			ret_ignored = write(pipe_fd[1], &status,
					    sizeof(status));
			_exit(0);
		case -1:
			fprintf(stderr, "forkpty() failed.\n");
			break;
		default:
			close(pipe_fd[1]);
			ret_ignored = read(pipe_fd[0], &status, sizeof(status));
			wait(NULL);
			close(pipe_fd[0]);
			close(pty_fd);
			errno = status;
			show_result(status ? EOF : 0, 1);
		}
		delete_policy();
		status = 0;
		ret_ignored = pipe(pipe_fd);
		switch (forkpty(&pty_fd, NULL, NULL, NULL)) {
		case 0:
			errno = 0;
			vhangup();
			/* Unreachable if vhangup() succeeded. */
			status = errno;
			ret_ignored = write(pipe_fd[1], &status,
					    sizeof(status));
			_exit(0);
		case -1:
			fprintf(stderr, "forkpty() failed.\n");
			break;
		default:
			close(pipe_fd[1]);
			ret_ignored = read(pipe_fd[0], &status, sizeof(status));
			wait(NULL);
			close(pipe_fd[0]);
			close(pty_fd);
			errno = status;
			show_result(status ? EOF : 0, 0);
		}
	}
	unset_capability();

	capability = "SYS_TIME";
	set_capability();
	if (write_policy()) {
		struct timeval tv;
		struct timezone tz;
		struct timex buf;
		time_t now = time(NULL);
		show_result(stime(&now), 1);
		gettimeofday(&tv, &tz);
		show_result(settimeofday(&tv, &tz), 1);
		memset(&buf, 0, sizeof(buf));
		buf.modes = 0x100; /* Use invalid value so that the clock
				      won't change. */
		show_result(adjtimex(&buf), 1);
		delete_policy();
		now = time(NULL);
		show_result(stime(&now), 0);
		gettimeofday(&tv, &tz);
		show_result(settimeofday(&tv, &tz), 0);
		memset(&buf, 0, sizeof(buf));
		buf.modes = 0x100; /* Use invalid value so that the clock
				      won't change. */
		show_result(adjtimex(&buf), 0);
	}
	unset_capability();

	capability = "SYS_NICE";
	set_capability();
	if (write_policy()) {
		show_result(nice(0), 1);
		show_result(setpriority(PRIO_PROCESS, pid,
					getpriority(PRIO_PROCESS, pid)), 1);
		delete_policy();
		show_result(nice(0), 0);
		show_result(setpriority(PRIO_PROCESS, pid,
					getpriority(PRIO_PROCESS, pid)), 0);
	}
	unset_capability();

	capability = "SYS_SETHOSTNAME";
	set_capability();
	if (write_policy()) {
		char buffer[4096];
		memset(buffer, 0, sizeof(buffer));
		gethostname(buffer, sizeof(buffer) - 1);
		show_result(sethostname(buffer, strlen(buffer)), 1);
		ret_ignored = getdomainname(buffer, sizeof(buffer) - 1);
		show_result(setdomainname(buffer, strlen(buffer)), 1);
		delete_policy();
		gethostname(buffer, sizeof(buffer) - 1);
		show_result(sethostname(buffer, strlen(buffer)), 0);
		ret_ignored = getdomainname(buffer, sizeof(buffer) - 1);
		show_result(setdomainname(buffer, strlen(buffer)), 0);
	}
	unset_capability();

	capability = "SYS_PTRACE";
	set_capability();
	if (write_policy()) {
		int status = 0;
		int pipe_fd[2] = { EOF, EOF };
		ret_ignored = pipe(pipe_fd);
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
			errno = status;
			show_result(status ? EOF : 0, 1);
		}
		delete_policy();
		status = 0;
		ret_ignored = pipe(pipe_fd);
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
			errno = status;
			show_result(status ? EOF : 0, 0);
		}
	}
	unset_capability();
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	stage_capability_test();
	clear_status();
	if (0) { /* To suppress "defined but not used" warnings. */
		write_domain_policy("", 0);
		write_exception_policy("", 0);
	}
	return 0;
}
