/*
 * audit-exec-param.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int raw_argc, char *raw_argv[])
{
	int i;
	int argc;
	int envc;
	char *filename;
	char **argv;
	char **envp;
	if (1) {
		int fd = open("/proc/ccs/.execute_handler", 0);
		close(fd);
		if (fd == EOF) {
			fprintf(stderr, "FATAL: I'm not execute_handler.\n");
			return 1;
		}
	} else {
		int ret_ignored;
		char buffer[1024];
		int fd = open("/proc/ccs/.process_status", O_RDWR);
		memset(buffer, 0, sizeof(buffer));
		snprintf(buffer, sizeof(buffer) - 1, "info %d\n", getpid());
		ret_ignored = write(fd, buffer, strlen(buffer));
		buffer[0] = '\0';
		ret_ignored = read(fd, buffer, sizeof(buffer) - 1);
		close(fd);
		if (!strstr(buffer, " execute_handler=yes")) {
			fprintf(stderr, "FATAL: I'm not execute_handler.\n");
			return 1;
		}
	}
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
	if (1) {
		openlog(raw_argv[0], LOG_NDELAY, LOG_USER);
		syslog(LOG_INFO, "Domain = %s\n", raw_argv[1]);
		syslog(LOG_INFO, "Caller Program = %s\n", raw_argv[2]);
		syslog(LOG_INFO, "Process Status = %s\n", raw_argv[3]);
		syslog(LOG_INFO, "Requested Program = %s\n", filename);
		syslog(LOG_INFO, "argc=%d\n", argc);
		syslog(LOG_INFO, "envc=%d\n", envc);
		for (i = 0; i < argc; i++)
			syslog(LOG_INFO, "argv[%d] = %s\n", i, argv[i]);
		for (i = 0; i < envc; i++)
			syslog(LOG_INFO, "envp[%d] = %s\n", i, envp[i]);
		closelog();
	}
	/*
	 * Continue if filename and argv[] and envp[] are appropriate.
	 */
	if (1)
		execve(filename, argv, envp);
	return 1;
}
