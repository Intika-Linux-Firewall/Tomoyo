/*
 * ccs-queryd.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/08/01
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
#include "readline.h"

/* Prototypes */

static void ccs_printw(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));
/*
static _Bool ccs_convert_path_info(FILE *fp, const struct ccs_path_info *pattern, const char *new);
*/
static _Bool ccs_handle_query(unsigned int serial);

/* Utility functions */

static void ccs_printw(const char *fmt, ...)
{
	va_list args;
	int i;
	int len;
	char *buffer;
	va_start(args, fmt);
	len = vsnprintf((char *) &i, sizeof(i) - 1, fmt, args) + 16;
	va_end(args);
	buffer = malloc(len);
	if (!buffer)
		ccs_out_of_memory();
	va_start(args, fmt);
	len = vsnprintf(buffer, len, fmt, args);
	va_end(args);
	for (i = 0; i < len; i++) {
		addch(buffer[i]);
		refresh();
	}
	free(buffer);
}

#if 0
static _Bool ccs_check_path_info(const char *buffer)
{
	_Bool modified = false;
	static struct ccs_path_info *update_list = NULL;
	static int update_list_len = 0;
	char *sp = strdup(buffer);
	char *str = sp;
	const char *path_list[2] = {
		CCS_PROC_POLICY_EXCEPTION_POLICY,
		CCS_PROC_POLICY_DOMAIN_POLICY
	};
	if (!str)
		return false;
	while (true) {
		int i;
		char *cp = strsep(&sp, " ");
		if (!cp)
			break;
		for (i = 0; i < update_list_len; i++) {
			int j;
			struct ccs_path_info old;
			/* TODO: split cp at upadte_list's depth. */
			old.name = cp;
			ccs_fill_path_info(&old);
			if (!ccs_path_matches_pattern(&old, &update_list[i]))
				continue;
			for (j = 0; j < 2; j++) {
				FILE *fp = fopen(path_list[j], "r+");
				if (!fp)
					continue;
				if (convert_path_info(fp, &update_list[i], cp))
					modified = true;
				fclose(fp);
			}
		}
	}
	free(str);
	return modified;
}
#endif

#if 0
static _Bool ccs_convert_path_info(FILE *fp, const struct ccs_path_info *pattern,
				   const char *new)
{
	_Bool modified = false;
	const char *cp = pattern->name;
	int depth = 0;
	while (*cp)
		if (*cp++ == '/')
			depth++;
	while (true) {
		int d = depth;
		char buffer[4096];
		char *cp;
		if (fscanf(fp, "%4095s", buffer) != 1)
			break;
		if (buffer[0] != '/')
			goto out;
		cp = buffer;
		while (*cp) {
			char c;
			struct ccs_path_info old;
			_Bool matched;
			if (*cp != '/' || --d)
				continue;
			cp++;
			c = *cp;
			*cp = '\0';
			old.name = buffer;
			ccs_fill_path_info(&old);
			matched = ccs_path_matches_pattern(&old, pattern);
			*cp = c;
			if (matched) {
				fprintf(fp, "%s%s", new, cp);
				modified = true;
				buffer[0] = '\0';
				break;
			}
		}
out:
		fprintf(fp, "%s ", buffer);
	}
	return modified;
}
#endif

static void ccs_send_keepalive(void)
{
	static time_t previous = 0;
	time_t now = time(NULL);
	if (previous != now || !previous) {
		previous = now;
		write(ccs_query_fd, "\n", 1);
	}
}

/* Variables */

static unsigned short int ccs_retries = 0;

static FILE *ccs_domain_fp = NULL;
static int ccs_domain_policy_fd = EOF;
#define CCS_MAX_READLINE_HISTORY 20
static const char **ccs_readline_history = NULL;
static int ccs_readline_history_count = 0;
static const int ccs_buffer_len = 32768;
static char *ccs_buffer = NULL;

/* Main functions */

static _Bool ccs_handle_query(unsigned int serial)
{
	int c = 0;
	int y;
	int x;
	char *line = NULL;
	static unsigned int prev_pid = 0;
	unsigned int pid;
	char pidbuf[128];
	char *cp = strstr(ccs_buffer, " (global-pid=");
	if (!cp || sscanf(cp + 13, "%u", &pid) != 1) {
		ccs_printw("ERROR: Unsupported query.\n");
		return false;
	}
	cp = ccs_buffer + strlen(ccs_buffer);
	if (*(cp - 1) != '\n') {
		ccs_printw("ERROR: Unsupported query.\n");
		return false;
	}
	*(cp - 1) = '\0';
	/*
	if (0 && !ccs_retries && check_path_info(ccs_buffer)) {
		c = 'r';
		goto write_answer;
	}
	*/
	if (pid != prev_pid) {
		if (prev_pid)
			ccs_printw("----------------------------------------\n");
		prev_pid = pid;
	}
	ccs_printw("%s\n", ccs_buffer);
	/* Is this domain query? */
	if (strstr(ccs_buffer, "\n#"))
		goto not_domain_query;
	memset(pidbuf, 0, sizeof(pidbuf));
	snprintf(pidbuf, sizeof(pidbuf) - 1, "select global-pid=%u\n", pid);
	ccs_printw("Allow? ('Y'es/'N'o/'R'etry/'S'how policy/'A'dd to policy "
		   "and retry):");
	while (true) {
		c = ccs_getch2();
		if (c == 'Y' || c == 'y' || c == 'N' || c == 'n' || c == 'R' ||
		    c == 'r' || c == 'A' || c == 'a' || c == 'S' || c == 's')
			break;
		ccs_send_keepalive();
	}
	ccs_printw("%c\n", c);

	if (c == 'S' || c == 's') {
		if (ccs_network_mode) {
			fprintf(ccs_domain_fp, "%s", pidbuf);
			fputc(0, ccs_domain_fp);
			fflush(ccs_domain_fp);
			rewind(ccs_domain_fp);
			while (1) {
				char c;
				if (fread(&c, 1, 1, ccs_domain_fp) != 1 || !c)
					break;
				addch(c);
				refresh();
				ccs_send_keepalive();
			}
		} else {
			write(ccs_domain_policy_fd, pidbuf, strlen(pidbuf));
			while (1) {
				int i;
				int len = read(ccs_domain_policy_fd, ccs_buffer,
					       ccs_buffer_len - 1);
				if (len <= 0)
					break;
				for (i = 0; i < len; i++) {
					addch(ccs_buffer[i]);
					refresh();
				}
				ccs_send_keepalive();
			}
		}
		c = 'r';
	}

	/* Append to domain policy. */
	if (c != 'A' && c != 'a')
		goto not_append;
	c = 'r';
	getyx(stdscr, y, x);
	cp = strrchr(ccs_buffer, '\n');
	if (!cp)
		return false;
	*cp++ = '\0';
	ccs_initial_readline_data = cp;
	ccs_readline_history_count = ccs_add_history(cp, ccs_readline_history,
						     ccs_readline_history_count,
						     CCS_MAX_READLINE_HISTORY);
	line = ccs_readline(y, 0, "Enter new entry> ", ccs_readline_history,
			    ccs_readline_history_count, 128000, 8);
	scrollok(stdscr, TRUE);
	ccs_printw("\n");
	if (!line || !*line) {
		ccs_printw("None added.\n");
		goto not_append;
	}
	ccs_readline_history_count = ccs_add_history(line, ccs_readline_history,
						     ccs_readline_history_count,
						     CCS_MAX_READLINE_HISTORY);
	if (ccs_network_mode) {
		fprintf(ccs_domain_fp, "%s%s\n", pidbuf, line);
		fflush(ccs_domain_fp);
	} else {
		write(ccs_domain_policy_fd, pidbuf, strlen(pidbuf));
		write(ccs_domain_policy_fd, line, strlen(line));
		write(ccs_domain_policy_fd, "\n", 1);
	}
	ccs_printw("Added '%s'.\n", line);
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
	snprintf(ccs_buffer, ccs_buffer_len - 1, "A%u=%u\n", serial, c);
	write(ccs_query_fd, ccs_buffer, strlen(ccs_buffer));
	ccs_printw("\n");
	return true;
not_domain_query:
	ccs_printw("Allow? ('Y'es/'N'o/'R'etry):");
	while (true) {
		c = ccs_getch2();
		if (c == 'Y' || c == 'y' || c == 'N' || c == 'n' ||
		    c == 'R' || c == 'r')
			break;
		ccs_send_keepalive();
	}
	ccs_printw("%c\n", c);
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
			ccs_network_ip = inet_addr(argv[1]);
			ccs_network_port = htons(atoi(cp));
			ccs_network_mode = true;
			if (!ccs_check_remote_host())
				return 1;
			goto ok;
		}
	}
	printf("Usage: %s [remote_ip:remote_port]\n\n",
	       argv[0]);
	printf("This program is used for granting access requests manually.\n");
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
	if (ccs_network_mode) {
		ccs_query_fd = ccs_open_stream("proc:query");
		ccs_domain_fp = ccs_open_write(CCS_PROC_POLICY_DOMAIN_POLICY);
	} else {
		ccs_query_fd = open(CCS_PROC_POLICY_QUERY, O_RDWR);
		ccs_domain_policy_fd = open(CCS_PROC_POLICY_DOMAIN_POLICY, O_RDWR);
	}
	if (ccs_query_fd == EOF) {
		fprintf(stderr,
			"You can't run this utility for this kernel.\n");
		return 1;
	} else if (!ccs_network_mode && write(ccs_query_fd, "", 0) != 0) {
		fprintf(stderr, "You need to register this program to %s to "
			"run this program.\n", CCS_PROC_POLICY_MANAGER);
		return 1;
	}
	ccs_readline_history = malloc(CCS_MAX_READLINE_HISTORY * sizeof(const char *));
	if (!ccs_readline_history)
		ccs_out_of_memory();
	ccs_send_keepalive();
	initscr();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	clear();
	refresh();
	scrollok(stdscr, TRUE);
	if (ccs_network_mode) {
		const u32 ip = ntohl(ccs_network_ip);
		ccs_printw("Monitoring /proc/ccs/query via %u.%u.%u.%u:%u.",
			   (u8) (ip >> 24), (u8) (ip >> 16), (u8) (ip >> 8),
			   (u8) ip, ntohs(ccs_network_port));
	} else
		ccs_printw("Monitoring /proc/ccs/query .");
	ccs_printw(" Press Ctrl-C to terminate.\n\n");
	while (true) {
		static _Bool first = true;
		static unsigned int prev_serial = 0;
		fd_set rfds;
		unsigned int serial;
		char *cp;
		if (!ccs_buffer) {
			ccs_buffer = malloc(ccs_buffer_len);
			if (!ccs_buffer)
				break;
		}
		/* Wait for query. */
		if (ccs_network_mode) {
			int i;
			write(ccs_query_fd, "", 1);
			memset(ccs_buffer, 0, ccs_buffer_len);
			for (i = 0; i < ccs_buffer_len - 1; i++) {
				if (read(ccs_query_fd, ccs_buffer + i, 1) != 1)
					break;
				if (!ccs_buffer[i])
					goto read_ok;
			}
			break;
		}
		FD_ZERO(&rfds);
		FD_SET(ccs_query_fd, &rfds);
		select(ccs_query_fd + 1, &rfds, NULL, NULL, NULL);
		if (!FD_ISSET(ccs_query_fd, &rfds))
			continue;

		/* Read query. */
		memset(ccs_buffer, 0, ccs_buffer_len);
		if (read(ccs_query_fd, ccs_buffer, ccs_buffer_len - 1) <= 0)
			continue;
read_ok:
		cp = strchr(ccs_buffer, '\n');
		if (!cp)
			continue;
		*cp = '\0';

		/* Get query number. */
		if (sscanf(ccs_buffer, "Q%u-%hu", &serial, &ccs_retries) != 2)
			continue;
		memmove(ccs_buffer, cp + 1, strlen(cp + 1) + 1);

		first = false;
		prev_serial = serial;
		/* Clear pending input. */;
		timeout(0);
		while (true) {
			int c = ccs_getch2();
			if (c == EOF || c == ERR)
				break;
		}
		timeout(1000);
		if (ccs_handle_query(serial))
			continue;
		break;
	}
	endwin();
	return 0;
}
