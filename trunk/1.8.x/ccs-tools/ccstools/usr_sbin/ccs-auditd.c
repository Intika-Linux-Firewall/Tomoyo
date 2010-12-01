/*
 * ccs-auditd.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0+   2010/12/01
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
#include <syslog.h>
#include <poll.h>

#define CCS_AUDITD_CONF "/etc/ccs/tools/auditd.conf"

struct ccs_sort_rules {
	const char *rule[3];
	const char *pathname;
	int fd;
};

static struct ccs_sort_rules *rules = NULL;
static int rules_len = 0;

static void ccs_auditd_init_rules(void)
{
	FILE *fp = fopen(CCS_AUDITD_CONF, "r");
	unsigned int line_no = 0;
	if (!fp) {
		fprintf(stderr, "Can't open %s for reading.\n",
			CCS_AUDITD_CONF);
		exit(1);
	}
	ccs_get();
	while (true) {
		char *line = ccs_freadline(fp);
		u8 i;
		if (!line)
			break;
		line_no++;
		if (!ccs_str_starts(line, "rule "))
			continue;
		rules = realloc(rules, sizeof(struct ccs_sort_rules) *
				(rules_len + 1));
		if (!rules)
			ccs_out_of_memory();
		for (i = 0; i < 3; i++) {
			char *cp = strstr(line, " | ");
			if (!cp)
				goto invalid_rule;
			*cp = '\0';
			ccs_normalize_line(line);
			if (!*line)
				goto invalid_rule;
			if (strcmp(line, "*")) {
				line = strdup(line);
				if (!line)
					ccs_out_of_memory();
			} else {
				line = NULL;
			}
			rules[rules_len].rule[i] = line;
			line = cp + 2;
		}
		ccs_normalize_line(line);
		if (*line != '/')
			goto invalid_rule;
		line = strdup(line);
		if (!line)
			ccs_out_of_memory();
		rules[rules_len++].pathname = line;
	}
	ccs_put();
	fclose(fp);
	if (!rules_len) {
		fprintf(stderr, "No rules defined in %s .\n", CCS_AUDITD_CONF);
		exit(1);
	}
	return;
invalid_rule:
	fprintf(stderr, "Invalid rule at line %u in %s.\n", line_no,
		CCS_AUDITD_CONF);
	exit(1);
}

static int ccs_check_rules(char *buffer)
{
	char *cp1 = strchr(buffer, '\n');
	char *cp2;
	int i;
	if (!cp1)
		return rules_len;
	*cp1++ = '\0';
	cp2 = strchr(cp1, '\n');
	if (!cp2)
		return rules_len;
	*cp2++ = '\0';
	for (i = 0; i < rules_len; i++) {
		const char *match = rules[i].rule[0];
		if (match && !strstr(buffer, match))
			continue;
		match = rules[i].rule[1];
		if (match) {
			const int len = strlen(match);
			if (strncmp(cp1, match, len) ||
			    (cp1[len] && cp1[len] != ' '))
				continue;
		}
		match = rules[i].rule[2];
		if (match && !strstr(cp2, match))
			continue;
		break;
	}
	*--cp2 = '\n';
	*--cp1 = '\n';
	return i;
}

static _Bool ccs_write_log(const int i, char *buffer)
{
	int len = strlen(buffer);
	/* Create destination file if needed. */
	if (access(rules[i].pathname, F_OK)) {
		close(rules[i].fd);
		rules[i].fd = open(rules[i].pathname,
				   O_WRONLY | O_APPEND | O_CREAT, 0600);
		if (rules[i].fd == EOF) {
			syslog(LOG_WARNING, "Can't open %s for writing.\n",
			       rules[i].pathname);
			return 0;
		}
	}
	/*
	 * This is OK because we read only up to sizeof(buffer) - 1 is bytes.
	 */
	buffer[len++] = '\n';
	if (write(rules[i].fd, buffer, len) == len)
		return 1;
	syslog(LOG_WARNING, "Can't write to %s .\n", rules[i].pathname);
	return 0;
}

int main(int argc, char *argv[])
{
	int i;
	int fd_in;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (!cp)
			goto usage;
		*cp++ = '\0';
		if (ccs_network_mode)
			goto usage;
		ccs_network_ip = inet_addr(ptr);
		ccs_network_port = htons(atoi(cp));
		ccs_network_mode = true;
		if (!ccs_check_remote_host())
			return 1;
	}
	ccs_auditd_init_rules();
	if (ccs_network_mode)
		goto start;
	if (access(CCS_PROC_POLICY_AUDIT, R_OK)) {
		fprintf(stderr, "You can't run this daemon for this kernel."
			"\n");
		return 0;
	}
	{ /* Get exclusive lock. */
		int fd = open("/proc/self/exe", O_RDONLY);
		if (flock(fd, LOCK_EX | LOCK_NB) == EOF)
			return 0;
	}
 start:
	if (ccs_network_mode)
		fd_in = ccs_open_stream("proc:audit");
	else
		fd_in = open(CCS_PROC_POLICY_AUDIT, O_RDONLY);
	if (fd_in == EOF) {
		fprintf(stderr, "Can't open %s for reading.\n",
			CCS_PROC_POLICY_AUDIT);
		return 1;
	}
	for (i = 0; i < rules_len; i++) {
		rules[i].fd = open(rules[i].pathname,
				   O_WRONLY | O_APPEND | O_CREAT, 0600);
		if (rules[i].fd == EOF) {
			fprintf(stderr, "Can't open %s for writing.\n",
				rules[i].pathname);
			return 1;
		}
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
	close(0);
	close(1);
	close(2);
	openlog("ccs-auditd", 0,  LOG_USER);
	syslog(LOG_WARNING, "Started.\n");
	while (true) {
		static char buffer[32768];
		memset(buffer, 0, sizeof(buffer));
		if (ccs_network_mode) {
			int j;
			for (j = 0; j < sizeof(buffer) - 1; j++) {
				if (read(fd_in, buffer + j, 1) != 1)
					goto out;
				if (!buffer[j])
					break;
			}
			if (j == sizeof(buffer) - 1)
				goto out;
		} else {
			while (read(fd_in, buffer, sizeof(buffer) - 1) <= 0) {
				/* Wait for data. */
				struct pollfd pfd = {
					.fd = fd_in,
					.events = POLLIN,
				};
				if (poll(&pfd, 1, -1) == EOF)
					goto out;
			}
		}
		/* Check for filtering rules. */
		i = ccs_check_rules(buffer);
		if (i == rules_len)
			continue;
		/* Write the audit log. */
		if (!ccs_write_log(i, buffer))
			break;
	}
out:
	syslog(LOG_WARNING, "Terminated.\n");
	closelog();
	return 0;
usage:
	fprintf(stderr, "%s [remote_ip:remote_port]\n"
		"  See %s for filsorting rules and destination pathnames.\n",
		argv[0], CCS_AUDITD_CONF);
	return 0;
}
