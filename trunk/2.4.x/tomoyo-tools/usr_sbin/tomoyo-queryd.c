/*
 * tomoyo-queryd.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0-pre   2011/06/09
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
#include "tomoyotools.h"
#include "readline.h"

/* Prototypes */

static void tomoyo_printw(const char *fmt, ...)
	__attribute__ ((format(printf, 1, 2)));
static _Bool tomoyo_handle_query(unsigned int serial);

/* Utility functions */

static void tomoyo_printw(const char *fmt, ...)
{
	va_list args;
	int i;
	int len;
	char *buffer;
	va_start(args, fmt);
	len = vsnprintf((char *) &i, sizeof(i) - 1, fmt, args) + 16;
	va_end(args);
	buffer = tomoyo_malloc(len);
	va_start(args, fmt);
	len = vsnprintf(buffer, len, fmt, args);
	va_end(args);
	for (i = 0; i < len; i++) {
		addch(buffer[i]);
		refresh();
	}
	free(buffer);
}

static void tomoyo_send_keepalive(void)
{
	static time_t previous = 0;
	time_t now = time(NULL);
	if (previous != now || !previous) {
		int ret_ignored;
		previous = now;
		ret_ignored = write(tomoyo_query_fd, "\n", 1);
	}
}

/* Variables */

static unsigned short int tomoyo_retries = 0;

static FILE *tomoyo_domain_fp = NULL;
static int tomoyo_domain_policy_fd = EOF;
#define TOMOYO_MAX_READLINE_HISTORY 20
static const char **tomoyo_readline_history = NULL;
static int tomoyo_readline_history_count = 0;
static char tomoyo_buffer[32768];

/* Main functions */

static _Bool tomoyo_handle_query(unsigned int serial)
{
	int c = 0;
	int y;
	int x;
	int ret_ignored;
	char *line = NULL;
	static unsigned int prev_pid = 0;
	unsigned int pid;
	char pidbuf[128];
	char *cp = strstr(tomoyo_buffer, " (global-pid=");
	if (!cp || sscanf(cp + 13, "%u", &pid) != 1) {
		tomoyo_printw("ERROR: Unsupported query.\n");
		return false;
	}
	cp = tomoyo_buffer + strlen(tomoyo_buffer);
	if (*(cp - 1) != '\n') {
		tomoyo_printw("ERROR: Unsupported query.\n");
		return false;
	}
	*(cp - 1) = '\0';
	if (pid != prev_pid) {
		if (prev_pid)
			tomoyo_printw("----------------------------------------"
				   "\n");
		prev_pid = pid;
	}
	tomoyo_printw("%s\n", tomoyo_buffer);
	/* Is this domain query? */
	if (strstr(tomoyo_buffer, "\n#"))
		goto not_domain_query;
	memset(pidbuf, 0, sizeof(pidbuf));
	snprintf(pidbuf, sizeof(pidbuf) - 1, "select global-pid=%u\n", pid);
	tomoyo_printw("Allow? ('Y'es/'N'o/'R'etry/'S'how policy/'A'dd to policy "
		   "and retry):");
	while (true) {
		c = tomoyo_getch2();
		if (c == 'Y' || c == 'y' || c == 'N' || c == 'n' || c == 'R' ||
		    c == 'r' || c == 'A' || c == 'a' || c == 'S' || c == 's')
			break;
		tomoyo_send_keepalive();
	}
	tomoyo_printw("%c\n", c);

	if (c == 'S' || c == 's') {
		if (tomoyo_network_mode) {
			fprintf(tomoyo_domain_fp, "%s", pidbuf);
			fputc(0, tomoyo_domain_fp);
			fflush(tomoyo_domain_fp);
			rewind(tomoyo_domain_fp);
			while (1) {
				char c;
				if (fread(&c, 1, 1, tomoyo_domain_fp) != 1 || !c)
					break;
				addch(c);
				refresh();
				tomoyo_send_keepalive();
			}
		} else {
			ret_ignored = write(tomoyo_domain_policy_fd, pidbuf,
					    strlen(pidbuf));
			while (1) {
				int i;
				int len = read(tomoyo_domain_policy_fd,
					       tomoyo_buffer,
					       sizeof(tomoyo_buffer) - 1);
				if (len <= 0)
					break;
				for (i = 0; i < len; i++) {
					addch(tomoyo_buffer[i]);
					refresh();
				}
				tomoyo_send_keepalive();
			}
		}
		c = 'r';
	}

	/* Append to domain policy. */
	if (c != 'A' && c != 'a')
		goto not_append;
	c = 'r';
	getyx(stdscr, y, x);
	cp = strrchr(tomoyo_buffer, '\n');
	if (!cp)
		return false;
	*cp++ = '\0';
	tomoyo_initial_readline_data = cp;
	tomoyo_readline_history_count =
		tomoyo_add_history(cp, tomoyo_readline_history,
				tomoyo_readline_history_count,
				TOMOYO_MAX_READLINE_HISTORY);
	line = tomoyo_readline(y, 0, "Enter new entry> ", tomoyo_readline_history,
			    tomoyo_readline_history_count, 128000, 8);
	scrollok(stdscr, TRUE);
	tomoyo_printw("\n");
	if (!line || !*line) {
		tomoyo_printw("None added.\n");
		goto not_append;
	}
	tomoyo_readline_history_count =
		tomoyo_add_history(line, tomoyo_readline_history,
				tomoyo_readline_history_count,
				TOMOYO_MAX_READLINE_HISTORY);
	if (tomoyo_network_mode) {
		fprintf(tomoyo_domain_fp, "%s%s\n", pidbuf, line);
		fflush(tomoyo_domain_fp);
	} else {
		ret_ignored = write(tomoyo_domain_policy_fd, pidbuf,
				    strlen(pidbuf));
		ret_ignored = write(tomoyo_domain_policy_fd, line, strlen(line));
		ret_ignored = write(tomoyo_domain_policy_fd, "\n", 1);
	}
	tomoyo_printw("Added '%s'.\n", line);
not_append:
	free(line);
write_answer:
	/* Write answer. */
	if (c == 'Y' || c == 'y' || c == 'A' || c == 'a')
		c = 1;
	else if (c == 'R' || c == 'r')
		c = 3;
	else
		c = 2;
	snprintf(tomoyo_buffer, sizeof(tomoyo_buffer) - 1, "A%u=%u\n", serial, c);
	ret_ignored = write(tomoyo_query_fd, tomoyo_buffer, strlen(tomoyo_buffer));
	tomoyo_printw("\n");
	return true;
not_domain_query:
	tomoyo_printw("Allow? ('Y'es/'N'o/'R'etry):");
	while (true) {
		c = tomoyo_getch2();
		if (c == 'Y' || c == 'y' || c == 'N' || c == 'n' ||
		    c == 'R' || c == 'r')
			break;
		tomoyo_send_keepalive();
	}
	tomoyo_printw("%c\n", c);
	goto write_answer;
}

int main(int argc, char *argv[])
{
	if (argc == 1)
		goto ok;
	{
		char *cp = strchr(argv[1], ':');
		if (cp) {
			*cp++ = '\0';
			tomoyo_network_ip = inet_addr(argv[1]);
			tomoyo_network_port = htons(atoi(cp));
			tomoyo_network_mode = true;
			if (!tomoyo_check_remote_host())
				return 1;
			goto ok;
		}
	}
	printf("Usage: %s [remote_ip:remote_port]\n\n", argv[0]);
	printf("This program is used for granting access requests manually."
	       "\n");
	printf("This program shows access requests that are about to rejected "
	       "by the kernel's decision.\n");
	printf("If you answer before the kernel's decision taken effect, your "
	       "decision will take effect.\n");
	printf("You can use this program to respond to accidental access "
	       "requests triggered by non-routine tasks (such as restarting "
	       "daemons after updating).\n");
	printf("To terminate this program, use 'Ctrl-C'.\n");
	return 0;
ok:
	if (tomoyo_network_mode) {
		tomoyo_query_fd = tomoyo_open_stream("proc:query");
		tomoyo_domain_fp = tomoyo_open_write(TOMOYO_PROC_POLICY_DOMAIN_POLICY);
	} else {
		tomoyo_mount_securityfs();
		tomoyo_query_fd = open(TOMOYO_PROC_POLICY_QUERY, O_RDWR);
		tomoyo_domain_policy_fd = open(TOMOYO_PROC_POLICY_DOMAIN_POLICY,
					    O_RDWR);
	}
	if (tomoyo_query_fd == EOF) {
		fprintf(stderr,
			"You can't run this utility for this kernel.\n");
		return 1;
	} else if (!tomoyo_network_mode && write(tomoyo_query_fd, "", 0) != 0) {
		fprintf(stderr, "You need to register this program to %s to "
			"run this program.\n", TOMOYO_PROC_POLICY_MANAGER);
		return 1;
	}
	tomoyo_readline_history = tomoyo_malloc(TOMOYO_MAX_READLINE_HISTORY *
					  sizeof(const char *));
	tomoyo_send_keepalive();
	initscr();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	clear();
	refresh();
	scrollok(stdscr, TRUE);
	if (tomoyo_network_mode) {
		const u32 ip = ntohl(tomoyo_network_ip);
		tomoyo_printw("Monitoring /sys/kernel/security/tomoyo/query via %u.%u.%u.%u:%u.",
			   (u8) (ip >> 24), (u8) (ip >> 16), (u8) (ip >> 8),
			   (u8) ip, ntohs(tomoyo_network_port));
	} else
		tomoyo_printw("Monitoring /sys/kernel/security/tomoyo/query .");
	tomoyo_printw(" Press Ctrl-C to terminate.\n\n");
	while (true) {
		unsigned int serial;
		char *cp;
		/* Wait for query and read query. */
		memset(tomoyo_buffer, 0, sizeof(tomoyo_buffer));
		if (tomoyo_network_mode) {
			int i;
			int ret_ignored;
			ret_ignored = write(tomoyo_query_fd, "", 1);
			for (i = 0; i < sizeof(tomoyo_buffer) - 1; i++) {
				if (read(tomoyo_query_fd, tomoyo_buffer + i, 1) != 1)
					break;
				if (!tomoyo_buffer[i])
					goto read_ok;
			}
			break;
		} else {
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(tomoyo_query_fd, &rfds);
			select(tomoyo_query_fd + 1, &rfds, NULL, NULL, NULL);
			if (!FD_ISSET(tomoyo_query_fd, &rfds))
				continue;
			if (read(tomoyo_query_fd, tomoyo_buffer,
				 sizeof(tomoyo_buffer) - 1) <= 0)
				continue;
		}
read_ok:
		cp = strchr(tomoyo_buffer, '\n');
		if (!cp)
			continue;
		*cp = '\0';

		/* Get query number. */
		if (sscanf(tomoyo_buffer, "Q%u-%hu", &serial, &tomoyo_retries) != 2)
			continue;
		memmove(tomoyo_buffer, cp + 1, strlen(cp + 1) + 1);

		/* Clear pending input. */;
		timeout(0);
		while (true) {
			int c = tomoyo_getch2();
			if (c == EOF || c == ERR)
				break;
		}
		timeout(1000);
		if (tomoyo_handle_query(serial))
			continue;
		break;
	}
	endwin();
	return 0;
}
