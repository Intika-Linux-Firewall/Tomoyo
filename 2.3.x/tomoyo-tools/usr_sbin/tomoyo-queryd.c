/*
 * tomoyo-queryd.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.3.0+   2011/09/29
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

#define CCS_GLOBALLY_READABLE_FILES_UPDATE_NONE 0
#define CCS_GLOBALLY_READABLE_FILES_UPDATE_ASK  1
#define CCS_GLOBALLY_READABLE_FILES_UPDATE_AUTO 2

/* Prototypes */

static void tomoyo_printw(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));
static void tomoyo_do_check_update(const int fd);
static void tomoyo_handle_update(const int tomoyo_check_update, const int fd);
/*
static _Bool tomoyo_convert_path_info(FILE *fp, const struct tomoyo_path_info *pattern, const char *new);
*/
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
	buffer = malloc(len);
	if (!buffer)
		tomoyo_out_of_memory();
	va_start(args, fmt);
	len = vsnprintf(buffer, len, fmt, args);
	va_end(args);
	for (i = 0; i < len; i++) {
		addch(buffer[i]);
		refresh();
	}
	free(buffer);
}

static char *tomoyo_encode(const char *sp)
{
	char *dp = malloc(strlen(sp) * 4 + 1);
	char * const str = dp;
	if (!dp)
		tomoyo_out_of_memory();
	while (true) {
		unsigned char c = *(const unsigned char *) sp++;
		if (!c) {
			*dp++ = '\0';
			break;
		} else if (c == '\\') {
			*dp++ = '\\';
			*dp++ = '\\';
		} else if (c > ' ' && c < 127) {
			*dp++ = c;
		} else {
			*dp++ = '\\';
			*dp++ = (c >> 6) + '0';
			*dp++ = ((c >> 3) & 7) + '0';
			*dp++ = (c & 7) + '0';
		}
	}
	return str;
}

#if 0
static _Bool tomoyo_check_path_info(const char *buffer)
{
	_Bool modified = false;
	static struct tomoyo_path_info *update_list = NULL;
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
			struct tomoyo_path_info old;
			/* TODO: split cp at upadte_list's depth. */
			old.name = cp;
			tomoyo_fill_path_info(&old);
			if (!tomoyo_path_matches_pattern(&old, &update_list[i]))
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

static void tomoyo_do_check_update(const int fd)
{
	FILE *fp_in = fopen(CCS_PROC_POLICY_EXCEPTION_POLICY, "r");
	struct tomoyo_path_info *pathnames = NULL;
	int pathnames_len = 0;
	char buffer[16384];
	memset(buffer, 0, sizeof(buffer));
	if (!fp_in) {
		fprintf(stderr, "Can't open policy file.\n");
		return;
	}
	while (fgets(buffer, sizeof(buffer) - 1, fp_in)) {
		char *cp = strchr(buffer, '\n');
		if (!cp)
			break;
		*cp = '\0';
		if (!tomoyo_str_starts(buffer, CCS_KEYWORD_ALLOW_READ))
			continue;
		if (!tomoyo_correct_path(buffer))
			continue;
		pathnames = realloc(pathnames,
				    sizeof(struct tomoyo_path_info) *
				    (pathnames_len + 1));
		if (!pathnames)
			tomoyo_out_of_memory();
		pathnames[pathnames_len].name = strdup(buffer);
		if (!pathnames[pathnames_len].name)
			tomoyo_out_of_memory();
		tomoyo_fill_path_info(&pathnames[pathnames_len]);
		pathnames_len++;
	}
	fclose(fp_in);
	while (true) {
		struct stat64 buf;
		static time_t last_modified = 0;
		int i;
		sleep(1);
		for (i = 0; i < pathnames_len; i++) {
			int j;
			if (pathnames[i].is_patterned ||
			    pathnames[i].total_len + 1 >= sizeof(buffer) ||
			    !tomoyo_decode(pathnames[i].name, buffer) ||
			    !stat64(buffer, &buf))
				continue;
			send(fd, "-", 1, 0);
			send(fd, pathnames[i].name, pathnames[i].total_len, 0);
			free((char *) pathnames[i].name);
			pathnames_len--;
			for (j = i; j < pathnames_len; j++)
				pathnames[j] = pathnames[j + 1];
			i--;
		}
		if (stat64("/etc/ld.so.cache", &buf) ||
		    buf.st_mtime == last_modified)
			continue;
		fp_in = popen("/sbin/ldconfig -NXp", "r");
		if (!fp_in)
			continue;
		last_modified = buf.st_mtime;
		memset(buffer, 0, sizeof(buffer));
		while (fgets(buffer, sizeof(buffer) - 1, fp_in)) {
			char *cp = strchr(buffer, '\n');
			struct tomoyo_path_info real_pathname;
			if (!cp)
				break;
			*cp = '\0';
			cp = strrchr(buffer, ' ');
			if (!cp || *++cp != '/')
				continue;
			if (stat64(cp, &buf))
				continue;
			cp = realpath(cp, NULL);
			if (!cp)
				continue;
			real_pathname.name = tomoyo_encode(cp);
			free(cp);
			tomoyo_fill_path_info(&real_pathname); 
			for (i = 0; i < pathnames_len; i++) {
				if (tomoyo_path_matches_pattern(&real_pathname,
								&pathnames[i]))
					break;
			}
			if (i < pathnames_len) {
				free((char *) real_pathname.name);
				continue;
			}
			pathnames = realloc(pathnames,
					    sizeof(struct tomoyo_path_info) *
					    ++pathnames_len);
			if (!pathnames)
				tomoyo_out_of_memory();
			pathnames[i] = real_pathname;
			send(fd, "+", 1, 0);
			send(fd, pathnames[i].name, pathnames[i].total_len, 0);
		}
		pclose(fp_in);
	}
}

#if 0
static _Bool tomoyo_convert_path_info(FILE *fp, const struct tomoyo_path_info *pattern,
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
			struct tomoyo_path_info old;
			_Bool matched;
			if (*cp != '/' || --d)
				continue;
			cp++;
			c = *cp;
			*cp = '\0';
			old.name = buffer;
			tomoyo_fill_path_info(&old);
			matched = tomoyo_path_matches_pattern(&old, pattern);
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

static void tomoyo_send_keepalive(void)
{
	static time_t previous = 0;
	time_t now = time(NULL);
	if (previous != now || !previous) {
		previous = now;
		write(tomoyo_query_fd, "\n", 1);
	}
}

static void tomoyo_handle_update(const int check_update, const int fd)
{
	static FILE *fp = NULL;
	char pathname[8192];
	int c;
	if (!fp)
		fp = fopen(CCS_PROC_POLICY_EXCEPTION_POLICY, "w");
	memset(pathname, 0, sizeof(pathname));
	if (recv(fd, pathname, 1, 0) == EOF ||
	    recv(fd, pathname + 1, sizeof(pathname) - 2, 0) == EOF)
		return;
	if (check_update == CCS_GLOBALLY_READABLE_FILES_UPDATE_AUTO) {
		if (pathname[0] == '-')
			fprintf(fp, CCS_KEYWORD_DELETE);
		fprintf(fp, CCS_KEYWORD_ALLOW_READ "%s\n", pathname + 1);
		fflush(fp);
		tomoyo_printw("The pathname %s was %s globally readable file.\n\n",
		       pathname + 1, (pathname[0] == '-') ?
		       "deleted. Deleted from" : "created. Appended to");
		return;
	}
	tomoyo_printw("The pathname %s was %s globally readable file? ('Y'es/'N'o):",
	       pathname + 1, (pathname[0] == '-') ?
	       "deleted. Delete from" : "created. Append to");
	while (true) {
		c = tomoyo_getch2();
		if (c == 'Y' || c == 'y' || c == 'N' || c == 'n')
			break;
		tomoyo_send_keepalive();
	}
	tomoyo_printw("%c\n", c);
	if (c == 'Y' || c == 'y') {
		if (pathname[0] == '-')
			fprintf(fp, CCS_KEYWORD_DELETE);
		fprintf(fp, CCS_KEYWORD_ALLOW_READ "%s\n", pathname + 1);
		fflush(fp);
	}
	tomoyo_printw("\n");
}

/* Variables */

static unsigned short int tomoyo_retries = 0;

static int tomoyo_check_update = CCS_GLOBALLY_READABLE_FILES_UPDATE_AUTO;

static FILE *tomoyo_domain_fp = NULL;
static int tomoyo_domain_policy_fd = EOF;
#define CCS_MAX_READLINE_HISTORY 20
static const char **tomoyo_readline_history = NULL;
static int tomoyo_readline_history_count = 0;
static const int tomoyo_buffer_len = 32768;
static char *tomoyo_buffer = NULL;

/* Main functions */

static _Bool tomoyo_handle_query(unsigned int serial)
{
	int c = 0;
	int y;
	int x;
	char *line = NULL;
	static unsigned int prev_pid = 0;
	unsigned int pid;
	time_t stamp;
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
	/*
	if (0 && !tomoyo_retries && check_path_info(tomoyo_buffer)) {
		c = 'r';
		goto write_answer;
	}
	*/
	if (pid != prev_pid) {
		if (prev_pid)
			tomoyo_printw("----------------------------------------\n");
		prev_pid = pid;
	}
	if (sscanf(tomoyo_buffer, "#timestamp=%lu", &stamp) == 1) {
		cp = strchr(tomoyo_buffer, ' ');
		if (cp) {
			struct tm *tm = localtime(&stamp);
			tomoyo_printw("#%04d-%02d-%02d %02d:%02d:%02d#",
				   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				   tm->tm_hour, tm->tm_min, tm->tm_sec);
			memmove(tomoyo_buffer, cp, strlen(cp) + 1);
		}
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
			write(tomoyo_domain_policy_fd, pidbuf, strlen(pidbuf));
			while (1) {
				int i;
				int len = read(tomoyo_domain_policy_fd, tomoyo_buffer,
					       tomoyo_buffer_len - 1);
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
	tomoyo_readline_history_count = tomoyo_add_history(cp, tomoyo_readline_history,
						     tomoyo_readline_history_count,
						     CCS_MAX_READLINE_HISTORY);
	line = tomoyo_readline(y, 0, "Enter new entry> ", tomoyo_readline_history,
			    tomoyo_readline_history_count, 128000, 8);
	scrollok(stdscr, TRUE);
	tomoyo_printw("\n");
	if (!line || !*line) {
		tomoyo_printw("None added.\n");
		goto not_append;
	}
	tomoyo_readline_history_count = tomoyo_add_history(line, tomoyo_readline_history,
						     tomoyo_readline_history_count,
						     CCS_MAX_READLINE_HISTORY);
	if (tomoyo_network_mode) {
		fprintf(tomoyo_domain_fp, "%s%s\n", pidbuf, line);
		fflush(tomoyo_domain_fp);
	} else {
		write(tomoyo_domain_policy_fd, pidbuf, strlen(pidbuf));
		write(tomoyo_domain_policy_fd, line, strlen(line));
		write(tomoyo_domain_policy_fd, "\n", 1);
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
	snprintf(tomoyo_buffer, tomoyo_buffer_len - 1, "A%u=%u\n", serial, c);
	write(tomoyo_query_fd, tomoyo_buffer, strlen(tomoyo_buffer));
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
	int pipe_fd[2] = { EOF, EOF };
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
			tomoyo_check_update = CCS_GLOBALLY_READABLE_FILES_UPDATE_NONE;
			goto ok;
		}
	}
	if (!strcmp(argv[1], "--no-update")) {
		tomoyo_check_update = CCS_GLOBALLY_READABLE_FILES_UPDATE_NONE;
		goto ok;
	}
	if (!strcmp(argv[1], "--ask-update")) {
		tomoyo_check_update = CCS_GLOBALLY_READABLE_FILES_UPDATE_ASK;
		goto ok;
	}
	printf("Usage: %s [--no-update|--ask-update|remote_ip:remote_port]\n\n",
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
	if (tomoyo_network_mode) {
		tomoyo_query_fd = tomoyo_open_stream("proc:query");
		tomoyo_domain_fp = tomoyo_open_write(CCS_PROC_POLICY_DOMAIN_POLICY);
	} else {
		tomoyo_mount_securityfs();
		tomoyo_query_fd = open(CCS_PROC_POLICY_QUERY, O_RDWR);
		tomoyo_domain_policy_fd = open(CCS_PROC_POLICY_DOMAIN_POLICY, O_RDWR);
	}
	if (tomoyo_query_fd == EOF) {
		fprintf(stderr,
			"You can't run this utility for this kernel.\n");
		return 1;
	} else if (!tomoyo_network_mode && write(tomoyo_query_fd, "", 0) != 0) {
		fprintf(stderr, "You need to register this program to %s to "
			"run this program.\n", CCS_PROC_POLICY_MANAGER);
		return 1;
	}
	if (tomoyo_check_update != CCS_GLOBALLY_READABLE_FILES_UPDATE_NONE) {
		socketpair(AF_UNIX, SOCK_DGRAM, 0, pipe_fd);
		switch (fork()) {
		case 0:
			if (tomoyo_domain_fp)
				fclose(tomoyo_domain_fp);
			else
				close(tomoyo_domain_policy_fd);
			close(tomoyo_query_fd);
			close(pipe_fd[0]);
			tomoyo_do_check_update(pipe_fd[1]);
			_exit(0);
		case -1:
			fprintf(stderr, "Can't fork().\n");
			return 1;
		}
		close(pipe_fd[1]);
		pipe_fd[1] = EOF;
	}
	tomoyo_readline_history = malloc(CCS_MAX_READLINE_HISTORY * sizeof(const char *));
	if (!tomoyo_readline_history)
		tomoyo_out_of_memory();
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
		tomoyo_printw("Monitoring /sys/kernel/security/tomoyo/query %s.",
			   tomoyo_check_update != CCS_GLOBALLY_READABLE_FILES_UPDATE_NONE ?
			   "and /etc/ld.so.cache " : "");
	tomoyo_printw(" Press Ctrl-C to terminate.\n\n");
	while (true) {
		static _Bool first = true;
		static unsigned int prev_serial = 0;
		fd_set rfds;
		unsigned int serial;
		char *cp;
		if (!tomoyo_buffer) {
			tomoyo_buffer = malloc(tomoyo_buffer_len);
			if (!tomoyo_buffer)
				break;
		}
		/* Wait for query. */
		if (tomoyo_network_mode) {
			int i;
			write(tomoyo_query_fd, "", 1);
			memset(tomoyo_buffer, 0, tomoyo_buffer_len);
			for (i = 0; i < tomoyo_buffer_len - 1; i++) {
				if (read(tomoyo_query_fd, tomoyo_buffer + i, 1) != 1)
					break;
				if (!tomoyo_buffer[i])
					goto read_ok;
			}
			break;
		}
		FD_ZERO(&rfds);
		FD_SET(tomoyo_query_fd, &rfds);
		if (pipe_fd[0] != EOF)
			FD_SET(pipe_fd[0], &rfds);
		select(tomoyo_query_fd > pipe_fd[0] ? tomoyo_query_fd + 1 : pipe_fd[0] + 1,
		       &rfds, NULL, NULL, NULL);
		if (pipe_fd[0] != EOF && FD_ISSET(pipe_fd[0], &rfds))
			tomoyo_handle_update(tomoyo_check_update, pipe_fd[0]);
		if (!FD_ISSET(tomoyo_query_fd, &rfds))
			continue;

		/* Read query. */
		memset(tomoyo_buffer, 0, tomoyo_buffer_len);
		if (read(tomoyo_query_fd, tomoyo_buffer, tomoyo_buffer_len - 1) <= 0)
			continue;
read_ok:
		cp = strchr(tomoyo_buffer, '\n');
		if (!cp)
			continue;
		*cp = '\0';

		/* Get query number. */
		if (sscanf(tomoyo_buffer, "Q%u-%hu", &serial, &tomoyo_retries) != 2)
			continue;
		memmove(tomoyo_buffer, cp + 1, strlen(cp + 1) + 1);

		first = false;
		prev_serial = serial;
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
