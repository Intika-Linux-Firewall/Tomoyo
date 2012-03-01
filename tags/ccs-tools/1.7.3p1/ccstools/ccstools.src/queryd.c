/*
 * queryd.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.7.3+   2012/03/01
 *
 */
#include "ccstools.h"

#define GLOBALLY_READABLE_FILES_UPDATE_NONE 0
#define GLOBALLY_READABLE_FILES_UPDATE_ASK  1
#define GLOBALLY_READABLE_FILES_UPDATE_AUTO 2

/* Prototypes */

static void _printw(const char *fmt, ...)
     __attribute__ ((format(printf, 1, 2)));
static void do_check_update(const int fd);
static void handle_update(const int check_update, const int fd);
/*
static _Bool convert_path_info(FILE *fp, const struct path_info *pattern,
			       const char *new);
*/
static _Bool handle_query(unsigned int serial);

/* Utility functions */

static void _printw(const char *fmt, ...)
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
		out_of_memory();
	va_start(args, fmt);
	len = vsnprintf(buffer, len, fmt, args);
	va_end(args);
	for (i = 0; i < len; i++) {
		addch(buffer[i]);
		refresh();
	}
	free(buffer);
}

static char *encode(const char *sp)
{
	char *dp = malloc(strlen(sp) * 4 + 1);
	char * const str = dp;
	if (!dp)
		out_of_memory();
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
static _Bool check_path_info(const char *buffer)
{
	_Bool modified = false;
	static struct path_info *update_list = NULL;
	static int update_list_len = 0;
	char *sp = strdup(buffer);
	char *str = sp;
	const char *path_list[2] = {
		proc_policy_exception_policy,
		proc_policy_domain_policy
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
			struct path_info old;
			/* TODO: split cp at upadte_list's depth. */
			old.name = cp;
			fill_path_info(&old);
			if (!path_matches_pattern(&old, &update_list[i]))
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

static void do_check_update(const int fd)
{
	FILE *fp_in = fopen(proc_policy_exception_policy, "r");
	struct path_info *pathnames = NULL;
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
		if (!str_starts(buffer, KEYWORD_ALLOW_READ))
			continue;
		if (!is_correct_path(buffer, 1, 0, 0))
			continue;
		pathnames = realloc(pathnames,
				    sizeof(struct path_info) *
				    (pathnames_len + 1));
		if (!pathnames)
			out_of_memory();
		pathnames[pathnames_len].name = strdup(buffer);
		if (!pathnames[pathnames_len].name)
			out_of_memory();
		fill_path_info(&pathnames[pathnames_len]);
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
			    !decode(pathnames[i].name, buffer) ||
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
			struct path_info real_pathname;
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
			real_pathname.name = encode(cp);
			free(cp);
			fill_path_info(&real_pathname);
			for (i = 0; i < pathnames_len; i++) {
				if (!path_matches_pattern(&real_pathname,
							  &pathnames[i]))
					break;
			}
			if (i < pathnames_len) {
				free((char *) real_pathname.name);
				continue;
			}
			pathnames = realloc(pathnames,
					    sizeof(struct path_info) *
					    ++pathnames_len);
			if (!pathnames)
				out_of_memory();
			pathnames[i] = real_pathname;
			send(fd, "+", 1, 0);
			send(fd, pathnames[i].name, pathnames[i].total_len, 0);
		}
		pclose(fp_in);
	}
}

#if 0
static _Bool convert_path_info(FILE *fp, const struct path_info *pattern,
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
			struct path_info old;
			_Bool matched;
			if (*cp != '/' || --d)
				continue;
			cp++;
			c = *cp;
			*cp = '\0';
			old.name = buffer;
			fill_path_info(&old);
			matched = path_matches_pattern(&old, pattern);
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

static void send_keepalive(void)
{
	static time_t previous = 0;
	time_t now = time(NULL);
	if (previous != now || !previous) {
		previous = now;
		write(query_fd, "\n", 1);
	}
}

static void handle_update(const int check_update, const int fd)
{
	static FILE *fp = NULL;
	char pathname[8192];
	int c;
	if (!fp)
		fp = fopen(proc_policy_exception_policy, "w");
	memset(pathname, 0, sizeof(pathname));
	if (recv(fd, pathname, 1, 0) == EOF ||
	    recv(fd, pathname + 1, sizeof(pathname) - 2, 0) == EOF)
		return;
	if (check_update == GLOBALLY_READABLE_FILES_UPDATE_AUTO) {
		if (pathname[0] == '-')
			fprintf(fp, KEYWORD_DELETE);
		fprintf(fp, KEYWORD_ALLOW_READ "%s\n", pathname + 1);
		fflush(fp);
		_printw("The pathname %s was %s globally readable file.\n\n",
		       pathname + 1, (pathname[0] == '-') ?
		       "deleted. Deleted from" : "created. Appended to");
		return;
	}
	_printw("The pathname %s was %s globally readable file? ('Y'es/'N'o):",
	       pathname + 1, (pathname[0] == '-') ?
	       "deleted. Delete from" : "created. Append to");
	while (true) {
		c = getch2();
		if (c == 'Y' || c == 'y' || c == 'N' || c == 'n')
			break;
		send_keepalive();
	}
	_printw("%c\n", c);
	if (c == 'Y' || c == 'y') {
		if (pathname[0] == '-')
			fprintf(fp, KEYWORD_DELETE);
		fprintf(fp, KEYWORD_ALLOW_READ "%s\n", pathname + 1);
		fflush(fp);
	}
	_printw("\n");
}

/* Variables */

static unsigned short int retries = 0;

static int check_update = GLOBALLY_READABLE_FILES_UPDATE_AUTO;

static FILE *domain_fp = NULL;
static int domain_policy_fd = EOF;
static const int max_readline_history = 20;
static const char **readline_history = NULL;
static int readline_history_count = 0;
static const int buffer_len = 32768;
static char *buffer = NULL;

/* Main functions */

static _Bool handle_query(unsigned int serial)
{
	int c = 0;
	int y;
	int x;
	char *line = NULL;
	static unsigned int prev_pid = 0;
	unsigned int pid;
	time_t stamp;
	char pidbuf[128];
	char *cp = strstr(buffer, " (global-pid=");
	if (!cp || sscanf(cp + 13, "%u", &pid) != 1) {
		_printw("ERROR: Unsupported query.\n");
		return false;
	}
	cp = buffer + strlen(buffer);
	if (*(cp - 1) != '\n') {
		_printw("ERROR: Unsupported query.\n");
		return false;
	}
	*(cp - 1) = '\0';
	/*
	if (0 && !retries && check_path_info(buffer)) {
		c = 'r';
		goto write_answer;
	}
	*/
	if (pid != prev_pid) {
		if (prev_pid)
			_printw("----------------------------------------\n");
		prev_pid = pid;
	}
	if (sscanf(buffer, "#timestamp=%lu", &stamp) == 1) {
		cp = strchr(buffer, ' ');
		if (cp) {
			struct tm *tm = localtime(&stamp);
			_printw("#%04d-%02d-%02d %02d:%02d:%02d#",
			       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			       tm->tm_hour, tm->tm_min, tm->tm_sec);
			memmove(buffer, cp, strlen(cp) + 1);
		}
	}
	_printw("%s\n", buffer);
	/* Is this domain query? */
	if (strstr(buffer, "\n#"))
		goto not_domain_query;
	memset(pidbuf, 0, sizeof(pidbuf));
	snprintf(pidbuf, sizeof(pidbuf) - 1, "select global-pid=%u\n", pid);
	_printw("Allow? ('Y'es/'N'o/'R'etry/'S'how policy/'A'dd to policy "
		"and retry):");
	while (true) {
		c = getch2();
		if (c == 'Y' || c == 'y' || c == 'N' || c == 'n' || c == 'R' ||
		    c == 'r' || c == 'A' || c == 'a' || c == 'S' || c == 's')
			break;
		send_keepalive();
	}
	_printw("%c\n", c);

	if (c == 'S' || c == 's') {
		if (network_mode) {
			fprintf(domain_fp, "%s", pidbuf);
			fputc(0, domain_fp);
			fflush(domain_fp);
			rewind(domain_fp);
			while (1) {
				char c;
				if (fread(&c, 1, 1, domain_fp) != 1 || !c)
					break;
				addch(c);
				refresh();
				send_keepalive();
			}
		} else {
			write(domain_policy_fd, pidbuf, strlen(pidbuf));
			while (1) {
				int i;
				int len = read(domain_policy_fd, buffer,
					       buffer_len - 1);
				if (len <= 0)
					break;
				for (i = 0; i < len; i++) {
					addch(buffer[i]);
					refresh();
				}
				send_keepalive();
			}
		}
		c = 'r';
	}

	/* Append to domain policy. */
	if (c != 'A' && c != 'a')
		goto not_append;
	c = 'r';
	getyx(stdscr, y, x);
	cp = strrchr(buffer, '\n');
	if (!cp)
		return false;
	*cp++ = '\0';
	initial_readline_data = cp;
	readline_history_count = simple_add_history(cp, readline_history,
						    readline_history_count,
						    max_readline_history);
	line = simple_readline(y, 0, "Enter new entry> ", readline_history,
			       readline_history_count, 128000, 8);
	scrollok(stdscr, TRUE);
	_printw("\n");
	if (!line || !*line) {
		_printw("None added.\n");
		goto not_append;
	}
	readline_history_count = simple_add_history(line, readline_history,
						    readline_history_count,
						    max_readline_history);
	if (network_mode) {
		fprintf(domain_fp, "%s%s\n", pidbuf, line);
		fflush(domain_fp);
	} else {
		write(domain_policy_fd, pidbuf, strlen(pidbuf));
		write(domain_policy_fd, line, strlen(line));
		write(domain_policy_fd, "\n", 1);
	}
	_printw("Added '%s'.\n", line);
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
	snprintf(buffer, buffer_len - 1, "A%u=%u\n", serial, c);
	write(query_fd, buffer, strlen(buffer));
	_printw("\n");
	return true;
not_domain_query:
	_printw("Allow? ('Y'es/'N'o/'R'etry):");
	while (true) {
		c = getch2();
		if (c == 'Y' || c == 'y' || c == 'N' || c == 'n' ||
		    c == 'R' || c == 'r')
			break;
		send_keepalive();
	}
	_printw("%c\n", c);
	goto write_answer;
}

int queryd_main(int argc, char *argv[])
{
	int pipe_fd[2] = { EOF, EOF };
	if (argc == 1)
		goto ok;
	{
		char *cp = strchr(argv[1], ':');
		if (cp) {
			*cp++ = '\0';
			network_ip = inet_addr(argv[1]);
			network_port = htons(atoi(cp));
			network_mode = true;
			if (!check_remote_host())
				return 1;
			check_update = GLOBALLY_READABLE_FILES_UPDATE_NONE;
			goto ok;
		}
	}
	if (!strcmp(argv[1], "--no-update")) {
		check_update = GLOBALLY_READABLE_FILES_UPDATE_NONE;
		goto ok;
	}
	if (!strcmp(argv[1], "--ask-update")) {
		check_update = GLOBALLY_READABLE_FILES_UPDATE_ASK;
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
	if (network_mode) {
		query_fd = open_stream("proc:query");
		domain_fp = open_write(proc_policy_domain_policy);
	} else {
		query_fd = open(proc_policy_query, O_RDWR);
		domain_policy_fd = open(proc_policy_domain_policy, O_RDWR);
	}
	if (query_fd == EOF) {
		fprintf(stderr,
			"You can't run this utility for this kernel.\n");
		return 1;
	} else if (!network_mode && write(query_fd, "", 0) != 0) {
		fprintf(stderr, "You need to register this program to %s to "
			"run this program.\n", proc_policy_manager);
		return 1;
	}
	if (check_update != GLOBALLY_READABLE_FILES_UPDATE_NONE) {
		socketpair(AF_UNIX, SOCK_DGRAM, 0, pipe_fd);
		switch (fork()) {
		case 0:
			if (domain_fp)
				fclose(domain_fp);
			else
				close(domain_policy_fd);
			close(query_fd);
			close(pipe_fd[0]);
			do_check_update(pipe_fd[1]);
			_exit(0);
		case -1:
			fprintf(stderr, "Can't fork().\n");
			return 1;
		}
		close(pipe_fd[1]);
		pipe_fd[1] = EOF;
	}
	readline_history = malloc(max_readline_history * sizeof(const char *));
	if (!readline_history)
		out_of_memory();
	send_keepalive();
	initscr();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	clear();
	refresh();
	scrollok(stdscr, TRUE);
	if (network_mode) {
		const u32 ip = ntohl(network_ip);
		_printw("Monitoring /proc/ccs/query via %u.%u.%u.%u:%u.",
			(u8) (ip >> 24), (u8) (ip >> 16), (u8) (ip >> 8),
			(u8) ip, ntohs(network_port));
	} else
		_printw("Monitoring /proc/ccs/query %s.",
			check_update != GLOBALLY_READABLE_FILES_UPDATE_NONE ?
			"and /etc/ld.so.cache " : "");
	_printw(" Press Ctrl-C to terminate.\n\n");
	while (true) {
		static _Bool first = true;
		static unsigned int prev_serial = 0;
		fd_set rfds;
		unsigned int serial;
		char *cp;
		if (!buffer) {
			buffer = malloc(buffer_len);
			if (!buffer)
				break;
		}
		/* Wait for query. */
		if (network_mode) {
			int i;
			write(query_fd, "", 1);
			memset(buffer, 0, buffer_len);
			for (i = 0; i < buffer_len - 1; i++) {
				if (read(query_fd, buffer + i, 1) != 1)
					break;
				if (!buffer[i])
					goto read_ok;
			}
			break;
		}
		FD_ZERO(&rfds);
		FD_SET(query_fd, &rfds);
		if (pipe_fd[0] != EOF)
			FD_SET(pipe_fd[0], &rfds);
		select(query_fd > pipe_fd[0] ? query_fd + 1 : pipe_fd[0] + 1,
		       &rfds, NULL, NULL, NULL);
		if (pipe_fd[0] != EOF && FD_ISSET(pipe_fd[0], &rfds))
			handle_update(check_update, pipe_fd[0]);
		if (!FD_ISSET(query_fd, &rfds))
			continue;

		/* Read query. */
		memset(buffer, 0, buffer_len);
		if (read(query_fd, buffer, buffer_len - 1) <= 0)
			continue;
read_ok:
		cp = strchr(buffer, '\n');
		if (!cp)
			continue;
		*cp = '\0';

		/* Get query number. */
		if (sscanf(buffer, "Q%u-%hu", &serial, &retries) != 2)
			continue;
		memmove(buffer, cp + 1, strlen(cp + 1) + 1);

		first = false;
		prev_serial = serial;
		/* Clear pending input. */;
		timeout(0);
		while (true) {
			int c = getch2();
			if (c == EOF || c == ERR)
				break;
		}
		timeout(1000);
		if (handle_query(serial))
			continue;
		break;
	}
	endwin();
	return 0;
}
