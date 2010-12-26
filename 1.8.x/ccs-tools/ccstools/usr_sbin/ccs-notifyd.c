/*
 * ccs-notifyd.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0+   2010/12/26
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
#include "ccstools.h"
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>

#define CCS_NOTIFYD_CONF "/etc/ccs/tools/notifyd.conf"

static const char *proc_policy_query = "/proc/ccs/query";
static int query_fd = EOF;
static int time_to_wait = 0;
static const char *action_to_take = NULL;
static int minimal_interval = 0;

static void ccs_notifyd_init_rules(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	unsigned int line_no = 0;
	if (!fp) {
		fprintf(stderr, "Can't open %s for reading.\n", filename);
		exit(1);
	}
	ccs_get();
	while (true) {
		char *line = ccs_freadline(fp);
		if (!line)
			break;
		line_no++;
		ccs_normalize_line(line);
		if (*line == '#' || !*line)
			continue;
		if (sscanf(line, "time_to_wait %u", &time_to_wait) == 1 ||
		    sscanf(line, "minimal_interval %u", &minimal_interval)
		    == 1)
			continue;
		if (!ccs_str_starts(line, "action_to_take "))
			continue;
		if (!*line)
			goto invalid_rule;
		if (action_to_take)
			goto invalid_rule;
		action_to_take = strdup(line);
		if (!action_to_take)
			ccs_out_of_memory();
	}
	ccs_put();
	fclose(fp);
	if (!action_to_take) {
		fprintf(stderr, "No actions defined in %s .\n", filename);
		exit(1);
	}
	return;
invalid_rule:
	fprintf(stderr, "Invalid rule at line %u in %s .\n", line_no,
		filename);
	exit(1);
}

static void main_loop(void)
{
	static char buffer[32768];
	while (1) {
		pid_t pid;
		while (1) {
			fd_set rfds;
			sleep(1);
			/* Wait for query. */
			FD_ZERO(&rfds);
			FD_SET(query_fd, &rfds);
			select(query_fd + 1, &rfds, NULL, NULL, NULL);
			if (!FD_ISSET(query_fd, &rfds))
				continue;
			/* Read query. */
			memset(buffer, 0, sizeof(buffer));
			if (read(query_fd, buffer, sizeof(buffer) - 1) <= 0)
				continue;
			break;
		}
		pid = fork();
		if (pid == -1) {
			syslog(LOG_WARNING, "Can't execute %s\n",
			       action_to_take);
			return;
		}
		if (!pid) {
			FILE *fp;
			close(query_fd);
			fp = popen(action_to_take, "w");
			if (!fp) {
				syslog(LOG_WARNING, "Can't execute %s\n",
				       action_to_take);
				closelog();
				_exit(1);
			}
			fprintf(fp, "%s\n", buffer);
			pclose(fp);
			_exit(0);
		}
		while (time_to_wait-- > 0) {
			int ret_ignored;
			sleep(1);
			ret_ignored = write(query_fd, "\n", 1);
		}
		close(query_fd);
		while (waitpid(pid, NULL, __WALL) == EOF && errno == EINTR);
		sleep(minimal_interval);
		query_fd = open(proc_policy_query, O_RDWR);
	}
}

int main(int argc, char *argv[])
{
	unsetenv("SHELLOPTS"); /* Make sure popen() executes commands. */
	if (argc != 1)
		goto usage;
	ccs_notifyd_init_rules(CCS_NOTIFYD_CONF);
	umask(0);
	switch (fork()) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "Can't fork()\n");
		return 1;
	default:
		return 0;
	}
	if (setsid() == EOF) {
		fprintf(stderr, "Can't setsid()\n");
		return 1;
	}
	switch (fork()) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "Can't fork()\n");
		return 1;
	default:
		return 0;
	}
	if (chdir("/")) {
		fprintf(stderr, "Can't chdir()\n");
		return 1;
	}
	{ /* Get exclusive lock. */
		int fd = open("/proc/self/exe", O_RDONLY);
		if (flock(fd, LOCK_EX | LOCK_NB) == EOF)
			return 0;
	}
	query_fd = open(proc_policy_query, O_RDWR);
	if (query_fd == EOF) {
		fprintf(stderr, "You can't run this utility for this kernel."
			"\n");
		return 1;
	} else if (time_to_wait && write(query_fd, "", 0) != 0) {
		fprintf(stderr, "You need to register this program to %s to "
			"run this program.\n", "/proc/ccs/manager");
		return 1;
	}
	close(0);
	close(1);
	close(2);
	openlog("ccs-notifyd", 0,  LOG_USER);
	syslog(LOG_WARNING, "Started. (%d, %s)\n", time_to_wait,
	       action_to_take);
	main_loop();
	syslog(LOG_WARNING, "Terminated.\n");
	closelog();
	return 0;
usage:
	fprintf(stderr, "%s\n  See %s for configuration.\n", argv[0],
		CCS_NOTIFYD_CONF);
	return 1;
}
