/*
 * ccs-notifyd.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2-pre   2011/06/08
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
#include <signal.h>
#include <syslog.h>
#include <poll.h>

#define CCS_NOTIFYD_CONF "/etc/ccs/tools/notifyd.conf"

static const char *proc_policy_query = "/proc/ccs/query";
static int query_fd = EOF;
static int time_to_wait = 0;
static char **action_to_take = NULL;
static int minimal_interval = 0;

static void ccs_notifyd_init_rules(const char *filename)
{
	static _Bool first = 1;
	FILE *fp = fopen(filename, "r");
	unsigned int line_no = 0;
	char *action = NULL;
	if (!first) {
		free(action_to_take);
		action_to_take = NULL;
		time_to_wait = 0;
		minimal_interval = 0;
	}
	if (!fp) {
		if (first)
			fprintf(stderr, "Can't open %s for reading.\n",
				filename);
		else
			syslog(LOG_WARNING, "Can't open %s for reading.\n",
			       filename);
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
		if (action)
			goto invalid_rule;
		action = ccs_strdup(line);
	}
	ccs_put();
	fclose(fp);
	if (!action) {
		if (first)
			fprintf(stderr, "No actions defined in %s .\n",
				filename);
		else
			syslog(LOG_WARNING, "No actions defined in %s .\n",
			       filename);
		exit(1);
	}
	{
		int count = 0;
		char *sp = action;
		while (true) {
			char *cp = strsep(&sp, " ");
			action_to_take = ccs_realloc(action_to_take,
						     sizeof(char *) * ++count);
			action_to_take[count - 1] = cp;
			if (!cp)
				break;
			if (!ccs_decode(cp, cp))
				goto invalid_rule;
		}
	}
	first = 0;
	return;
invalid_rule:
	if (first)
		fprintf(stderr, "Invalid rule at line %u in %s .\n", line_no,
			filename);
	else
		syslog(LOG_WARNING, "Invalid rule at line %u in %s .\n",
		       line_no, filename);
	exit(1);
}

static void block_sighup(const _Bool block)
{
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGHUP);
	sigprocmask(block ? SIG_BLOCK : SIG_UNBLOCK, &sigset, NULL);
}

static void main_loop(void)
{
	static char buffer[32768];
	while (query_fd != EOF) {
		int pipe_fd[2];
		pid_t pid;
		memset(buffer, 0, sizeof(buffer));
		while (read(query_fd, buffer, sizeof(buffer) - 1) <= 0) {
			/* Wait for data. */
			struct pollfd pfd = {
				.fd = query_fd,
				.events = POLLIN,
			};
			if (poll(&pfd, 1, -1) == EOF && errno != EINTR)
				return;
		}
		if (pipe(pipe_fd) == EOF) {
			syslog(LOG_WARNING, "Can't create pipe.\n");
			return;
		}
		block_sighup(1);
		pid = fork();
		if (pid == -1) {
			syslog(LOG_WARNING, "Can't fork().\n");
			return;
		}
		if (!pid) {
			int ret_ignored;
			ret_ignored = close(query_fd);
			ret_ignored = close(pipe_fd[1]);
			ret_ignored = close(0);
			ret_ignored = dup2(pipe_fd[0], 0);
			ret_ignored = close(pipe_fd[0]);
			execvp(action_to_take[0], action_to_take);
			syslog(LOG_WARNING, "Can't execute %s\n",
			       action_to_take[0]);
			closelog();
			_exit(1);
		} else {
			int ret_ignored;
			int len = strlen(buffer);
			close(pipe_fd[0]);
			/* This is OK because read() < sizeof(buffer). */
			buffer[len++] = '\n';
			ret_ignored = write(pipe_fd[1], buffer, len);
			close(pipe_fd[1]);
		}
		block_sighup(0);
		while (time_to_wait-- > 0) {
			int ret_ignored;
			sleep(1);
			ret_ignored = write(query_fd, "\n", 1);
		}
		close(query_fd);
		while (waitpid(pid, NULL, __WALL) == EOF && errno == EINTR);
		sleep(minimal_interval);
		do {
			query_fd = open(proc_policy_query, O_RDWR);
		} while (query_fd == EOF && errno == EINTR);
	}
}

static void ccs_reload_config(int sig)
{
	block_sighup(1);
	syslog(LOG_WARNING, "Reloading congiguration file.\n");
	ccs_notifyd_init_rules(CCS_NOTIFYD_CONF);
	block_sighup(0);
}

int main(int argc, char *argv[])
{
	unsetenv("SHELLOPTS"); /* Make sure popen() executes commands. */
	if (argc != 1)
		goto usage;
	ccs_notifyd_init_rules(CCS_NOTIFYD_CONF);
	query_fd = open(proc_policy_query, O_RDWR);
	if (query_fd == EOF) {
		fprintf(stderr, "You can't run this daemon for this kernel."
			"\n");
		return 1;
	} else if (time_to_wait && write(query_fd, "", 0) != 0) {
		fprintf(stderr, "You need to register this program to %s to "
			"run this program.\n", "/proc/ccs/manager");
		return 1;
	}
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
	close(0);
	close(1);
	close(2);
	openlog("ccs-notifyd", 0,  LOG_USER);
	syslog(LOG_WARNING, "Started.\n");
	signal(SIGHUP, ccs_reload_config);
	main_loop();
	syslog(LOG_WARNING, "Terminated.\n");
	closelog();
	return 1;
usage:
	fprintf(stderr, "%s\n  See %s for configuration.\n", argv[0],
		CCS_NOTIFYD_CONF);
	return 1;
}
