/*
 * ccs-auditd.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2   2011/06/20
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
#include <signal.h>
#include <syslog.h>
#include <poll.h>

#define CCS_AUDITD_CONF "/etc/ccs/tools/auditd.conf"

struct ccs_destination {
	const char *pathname;
	int fd;
};

static struct ccs_destination *destination_list = NULL;
static unsigned int destination_list_len = 0;

enum ccs_rule_types {
	CCS_SORT_RULE_HEADER,
	CCS_SORT_RULE_DOMAIN,
	CCS_SORT_RULE_ACL,
	CCS_SORT_RULE_DESTINATION,
};

enum ccs_operator_types {
	CCS_SORT_OPERATOR_CONTAINS,
	CCS_SORT_OPERATOR_EQUALS,
	CCS_SORT_OPERATOR_STARTS,
};

struct ccs_sort_rules {
	enum ccs_rule_types type;
	enum ccs_operator_types operation;
	unsigned int index;
	const char *string;
	unsigned int string_len; /* strlen(string). */
};

static struct ccs_sort_rules *rules = NULL;
static unsigned int rules_len = 0;

static void ccs_auditd_init_rules(const char *filename)
{
	static _Bool first = 1;
	FILE *fp = fopen(filename, "r");
	unsigned int line_no = 0;
	unsigned int i;
	if (!first) {
		for (i = 0; i < rules_len; i++)
			free((void *) rules[i].string);
		rules_len = 0;
		for (i = 0; i < destination_list_len; i++) {
			free((void *) destination_list[i].pathname);
			close(destination_list[i].fd);
		}
		destination_list_len = 0;
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
		struct ccs_sort_rules *ptr;
		unsigned char c;
		if (!line)
			break;
		line_no++;
		ccs_normalize_line(line);
		if (*line == '#' || !*line)
			continue;
		rules = ccs_realloc(rules, sizeof(struct ccs_sort_rules) *
				    (rules_len + 1));
		ptr = &rules[rules_len++];
		memset(ptr, 0, sizeof(*ptr));
		if (ccs_str_starts(line, "destination ")) {
			if (*line != '/')
				goto invalid_rule;
			for (i = 0; i < destination_list_len; i++)
				if (!strcmp(destination_list[i].pathname,
					    line))
					break;
			if (i < destination_list_len)
				goto store_destination;
			destination_list =
				ccs_realloc(destination_list,
					    ++destination_list_len *
					    sizeof(struct ccs_destination));
			if (!ccs_decode(line, line))
				goto invalid_rule;
			destination_list[i].pathname = ccs_strdup(line);
			destination_list[i].fd = EOF;
store_destination:
			ptr->type = CCS_SORT_RULE_DESTINATION;
			ptr->index = i;
			continue;
		}
		if (ccs_str_starts(line, "header"))
			ptr->type = CCS_SORT_RULE_HEADER;
		else if (ccs_str_starts(line, "domain"))
			ptr->type = CCS_SORT_RULE_DOMAIN;
		else if (ccs_str_starts(line, "acl"))
			ptr->type = CCS_SORT_RULE_ACL;
		else
			goto invalid_rule;
		switch (sscanf(line, "[%u%c", &ptr->index, &c)) {
		case 0:
			break;
		case 2:
			if (c == ']') {
				char *cp = strchr(line, ']') + 1;
				memmove(line, cp, strlen(cp) + 1);
				break;
			}
		default:
			goto invalid_rule;
		}
		if (ccs_str_starts(line, ".contains "))
			ptr->operation = CCS_SORT_OPERATOR_CONTAINS;
		else if (ccs_str_starts(line, ".equals "))
			ptr->operation = CCS_SORT_OPERATOR_EQUALS;
		else if (ccs_str_starts(line, ".starts "))
			ptr->operation = CCS_SORT_OPERATOR_STARTS;
		else
			goto invalid_rule;
		if (!*line)
			goto invalid_rule;
		line = ccs_strdup(line);
		ptr->string = line;
		ptr->string_len = strlen(line);
	}
	ccs_put();
	fclose(fp);
	if (!rules_len) {
		if (first)
			fprintf(stderr, "No rules defined in %s .\n",
				filename);
		else
			syslog(LOG_WARNING, "No rules defined in %s .\n",
			       filename);
		exit(1);
	}
	for (i = 0; i < destination_list_len; i++) {
		struct ccs_destination *ptr = &destination_list[i];
		const char *path = ptr->pathname;
		/* This is OK because path is a strdup()ed string. */
		char *pos = (char *) path;
		while (*pos) {
			int ret_ignored;
			if (*pos++ != '/')
				continue;
			*(pos - 1) = '\0';
			ret_ignored = mkdir(path, 0700);
			*(pos - 1) = '/';
		}
		do {
			ptr->fd = open(path, O_WRONLY | O_APPEND | O_CREAT,
				       0600);
		} while (ptr->fd == EOF && errno == EINTR);
		if (ptr->fd == EOF) {
			if (first)
				fprintf(stderr, "Can't open %s for writing.\n",
					path);
			else
				syslog(LOG_WARNING,
				       "Can't open %s for writing.\n", path);
			exit(1);
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

static int ccs_check_rules(char *header, char *domain, char *acl)
{
	unsigned int i;
	_Bool matched = true;
	for (i = 0; i < rules_len; i++) {
		const struct ccs_sort_rules *ptr = &rules[i];
		char *line;
		unsigned int index = ptr->index;
		const char *find = ptr->string;
		unsigned int find_len = ptr->string_len;
		switch (ptr->type) {
		case CCS_SORT_RULE_HEADER:
			line = header;
			break;
		case CCS_SORT_RULE_DOMAIN:
			line = domain;
			break;
		case CCS_SORT_RULE_ACL:
			line = acl;
			break;
		default: /* CCS_SORT_RULE_DESTINATION */
			if (matched)
				return ptr->index;
			matched = true;
			continue;
		}
		if (!matched)
			continue;
		if (!index) {
			switch (ptr->operation) {
			case CCS_SORT_OPERATOR_CONTAINS:
				while (1) {
					char *cp = strstr(line, find);
					if (!cp) {
						matched = false;
						break;
					}
					if ((cp == line || *(cp - 1) == ' ') &&
					    (!cp[find_len] ||
					     cp[find_len] == ' '))
						break;
					line = cp + 1;
				}
				break;
			case CCS_SORT_OPERATOR_EQUALS:
				matched = !strcmp(line, find);
				break;
			default: /* CCS_SORT_OPERATOR_STARTS */
				matched = !strncmp(line, find, find_len) &&
					(!line[find_len] ||
					 line[find_len] == ' ');
			}
		} else {
			char *word = line;
			char *word_end;
			while (--index) {
				char *cp = strchr(word, ' ');
				if (!cp) {
					matched = false;
					break;
				}
				word = cp + 1;
			}
			if (!matched)
				continue;
			word_end = strchr(word, ' ');
			if (word_end)
				*word_end = '\0';
			switch (ptr->operation) {
			case CCS_SORT_OPERATOR_CONTAINS:
				matched = strstr(word, find) != NULL;
				break;
			case CCS_SORT_OPERATOR_EQUALS:
				matched = !strcmp(word, find);
				break;
			default: /* CCS_SORT_OPERATOR_STARTS */
				matched = !strncmp(word, find, find_len);
				break;
			}
			if (word_end)
				*word_end = ' ';
		}
	}
	return EOF;
}

static _Bool ccs_write_log(const int i, char *buffer)
{
	int len = strlen(buffer);
	int ret;
	struct ccs_destination *ptr = &destination_list[i];
	/* Create destination file if needed. */
	if (access(ptr->pathname, F_OK)) {
		close(ptr->fd);
		do {
			ptr->fd = open(ptr->pathname,
				       O_WRONLY | O_APPEND | O_CREAT, 0600);
		} while (ptr->fd == EOF && errno == EINTR);
		if (ptr->fd == EOF) {
			syslog(LOG_WARNING, "Can't open %s for writing.\n",
			       ptr->pathname);
			return 0;
		}
	}
	/*
	 * This is OK because we read only up to sizeof(buffer) - 1 bytes.
	 */
	buffer[len++] = '\n';
	do {
		ret = write(ptr->fd, buffer, len);
		if (ret == len)
			return 1;
	} while (ret == EOF && errno == EINTR);
	syslog(LOG_WARNING, "Can't write to %s .\n", ptr->pathname);
	return 0;
}

static void block_sighup(const _Bool block)
{
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGHUP);
	sigprocmask(block ? SIG_BLOCK : SIG_UNBLOCK, &sigset, NULL);
}

static void ccs_reload_config(int sig)
{
	block_sighup(1);
	syslog(LOG_WARNING, "Reloading configuration file.\n");
	ccs_auditd_init_rules(CCS_AUDITD_CONF);
	block_sighup(0);
}

int main(int argc, char *argv[])
{
	unsigned int i;
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
	ccs_auditd_init_rules(CCS_AUDITD_CONF);
	if (ccs_network_mode)
		goto start;
	if (access(CCS_PROC_POLICY_AUDIT, R_OK)) {
		fprintf(stderr, "You can't run this daemon for this kernel."
			"\n");
		return 1;
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
	signal(SIGHUP, ccs_reload_config);
	while (true) {
		static char buffer[32768];
		char *domain;
		char *acl;
		char *tail;
		int ret;
		memset(buffer, 0, sizeof(buffer));
		if (ccs_network_mode) {
			int j;
			for (j = 0; j < sizeof(buffer) - 1; j++) {
				do {
					ret = read(fd_in, buffer + j, 1);
				} while (ret == EOF && errno == EINTR);
				if (ret != 1)
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
				if (poll(&pfd, 1, -1) == EOF && errno != EINTR)
					goto out;
			}
		}
		/* Split into three lines. */
		domain = strchr(buffer, '\n');
		if (!domain)
			continue;
		*domain++ = '\0';
		acl = strchr(domain, '\n');
		if (!acl)
			continue;
		*acl++ = '\0';
		tail = strchr(acl, '\n');
		if (!tail)
			continue;
		*tail = '\0';
		block_sighup(1);
		/* Check for filtering rules. */
		i = ccs_check_rules(buffer, domain, acl);
		if (i != EOF) {
			*tail = '\n';
			*--acl = '\n';
			*--domain = '\n';
			/* Write the audit log. */
			if (!ccs_write_log(i, buffer))
				break;
		}
		block_sighup(0);
	}
out:
	syslog(LOG_WARNING, "Terminated.\n");
	closelog();
	return 1;
usage:
	fprintf(stderr, "%s [remote_ip:remote_port]\n"
		"  See %s for configuration.\n", argv[0], CCS_AUDITD_CONF);
	return 1;
}
