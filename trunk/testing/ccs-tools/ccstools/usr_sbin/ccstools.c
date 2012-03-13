/*
 * ccstools.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.8.3+   2012/03/13
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

/* Use ccs-editpolicy-agent process? */
_Bool ccs_network_mode = false;
/* The IPv4 address of the remote host running the ccs-editpolicy-agent . */
u32 ccs_network_ip = INADDR_NONE;
/* The port number of the remote host running the ccs-editpolicy-agent . */
u16 ccs_network_port = 0;
/* The list of processes currently running. */
struct ccs_task_entry *ccs_task_list = NULL;
/* The length of ccs_task_list . */
int ccs_task_list_len = 0;

/* Prototypes */

/* Utility functions */

/**
 * ccs_out_of_memory - Print error message and abort.
 *
 * This function does not return.
 */
static void ccs_out_of_memory(void)
{
	fprintf(stderr, "Out of memory. Aborted.\n");
	exit(1);
}

/**
 * ccs_strdup - strdup() with abort on error.
 *
 * @string: String to duplicate.
 *
 * Returns copy of @string on success, abort otherwise.
 */
char *ccs_strdup(const char *string)
{
	char *cp = strdup(string);
	if (!cp)
		ccs_out_of_memory();
	return cp;
}

/**
 * ccs_realloc - realloc() with abort on error.
 *
 * @ptr:  Pointer to void.
 * @size: New size.
 *
 * Returns return value of realloc() on success, abort otherwise.
 */
void *ccs_realloc(void *ptr, const size_t size)
{
	void *vp = realloc(ptr, size);
	if (!vp)
		ccs_out_of_memory();
	return vp;
}

/**
 * ccs_malloc - malloc() with abort on error.
 *
 * @size: Size to allocate.
 *
 * Returns return value of malloc() on success, abort otherwise.
 *
 * Allocated memory is cleared with 0.
 */
void *ccs_malloc(const size_t size)
{
	void *vp = malloc(size);
	if (!vp)
		ccs_out_of_memory();
	memset(vp, 0, size);
	return vp;
}

/**
 * ccs_str_starts - Check whether the given string starts with the given keyword.
 *
 * @str:   Pointer to "char *".
 * @begin: Pointer to "const char *".
 *
 * Returns true if @str starts with @begin, false otherwise.
 *
 * Note that @begin will be removed from @str before returning true. Therefore,
 * @str must not be "const char *".
 *
 * Note that this function in kernel source has different arguments and behaves
 * differently.
 */
_Bool ccs_str_starts(char *str, const char *begin)
{
	const int len = strlen(begin);
	if (strncmp(str, begin, len))
		return false;
	memmove(str, str + len, strlen(str + len) + 1);
	return true;
}

/**
 * ccs_normalize_line - Format string.
 *
 * @buffer: The line to normalize.
 *
 * Returns nothing.
 *
 * Leading and trailing whitespaces are removed.
 * Multiple whitespaces are packed into single space.
 */
void ccs_normalize_line(char *buffer)
{
	unsigned char *sp = (unsigned char *) buffer;
	unsigned char *dp = (unsigned char *) buffer;
	_Bool first = true;
	while (*sp && (*sp <= ' ' || 127 <= *sp))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (' ' < *sp && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || 127 <= *sp))
			sp++;
	}
	*dp = '\0';
}

/**
 * ccs_decode - Decode a string in TOMOYO's rule to a string in C.
 *
 * @ascii: Pointer to "const char".
 * @bin:   Pointer to "char". Must not contain wildcards nor '\000'.
 *
 * Returns true if @ascii was successfully decoded, false otherwise.
 *
 * Note that it is legal to pass @ascii == @bin if the caller want to decode
 * a string in a temporary buffer.
 */
_Bool ccs_decode(const char *ascii, char *bin)
{
	while (true) {
		char c = *ascii++;
		*bin++ = c;
		if (!c)
			break;
		if (c == '\\') {
			char d;
			char e;
			u8 f;
			c = *ascii++;
			switch (c) {
			case '0':       /* "\ooo" */
			case '1':
			case '2':
			case '3':
				d = *ascii++;
				if (d < '0' || d > '7')
					break;
				e = *ascii++;
				if (e < '0' || e > '7')
					break;
				f = (u8) ((c - '0') << 6) +
					(((u8) (d - '0')) << 3) +
					(((u8) (e - '0')));
				if (f <= ' ' || f >= 127) {
					*(bin - 1) = f;
					continue;
				}
			}
			return false;
		} else if (c <= ' ' || c >= 127) {
			return false;
		}
	}
	return true;
}

/**
 * ccs_open_stream - Establish IP connection.
 *
 * @filename: String to send to remote ccs-editpolicy-agent program.
 *
 * Retruns file descriptor on success, EOF otherwise.
 */
int ccs_open_stream(const char *filename)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	char c;
	int len = strlen(filename) + 1;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ccs_network_ip;
	addr.sin_port = ccs_network_port;
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) ||
	    write(fd, filename, len) != len || read(fd, &c, 1) != 1 || c) {
		close(fd);
		return EOF;
	}
	return fd;
}

/**
 * ccs_get_ppid - Get PPID of the given PID.
 *
 * @pid: A pid_t value.
 *
 * Returns PPID value.
 */
static pid_t ccs_get_ppid(const pid_t pid)
{
	char buffer[1024];
	FILE *fp;
	pid_t ppid = 1;
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "/proc/%u/status", pid);
	fp = fopen(buffer, "r");
	if (fp) {
		while (memset(buffer, 0, sizeof(buffer)) &&
		       fgets(buffer, sizeof(buffer) - 1, fp)) {
			if (sscanf(buffer, "PPid: %u", &ppid) == 1)
				break;
		}
		fclose(fp);
	}
	return ppid;
}

/**
 * ccs_get_name - Get comm name of the given PID.
 *
 * @pid: A pid_t value.
 *
 * Returns comm name using on success, NULL otherwise.
 *
 * The caller must free() the returned pointer.
 */
static char *ccs_get_name(const pid_t pid)
{
	char buffer[1024];
	FILE *fp;
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "/proc/%u/status", pid);
	fp = fopen(buffer, "r");
	if (fp) {
		static const int offset = sizeof(buffer) / 6;
		while (memset(buffer, 0, sizeof(buffer)) &&
		       fgets(buffer, sizeof(buffer) - 1, fp)) {
			if (!strncmp(buffer, "Name:\t", 6)) {
				char *cp = buffer + 6;
				memmove(buffer, cp, strlen(cp) + 1);
				cp = strchr(buffer, '\n');
				if (cp)
					*cp = '\0';
				break;
			}
		}
		fclose(fp);
		if (buffer[0] && strlen(buffer) < offset - 1) {
			const char *src = buffer;
			char *dest = buffer + offset;
			while (1) {
				unsigned char c = *src++;
				if (!c) {
					*dest = '\0';
					break;
				}
				if (c == '\\') {
					c = *src++;
					if (c == '\\') {
						memmove(dest, "\\134", 4);
						dest += 4;
					} else if (c == 'n') {
						memmove(dest, "\\012", 4);
						dest += 4;
					} else {
						break;
					}
				} else if (c > ' ' && c <= 126) {
					*dest++ = c;
				} else {
					*dest++ = '\\';
					*dest++ = (c >> 6) + '0';
					*dest++ = ((c >> 3) & 7) + '0';
					*dest++ = (c & 7) + '0';
				}
			}
			return strdup(buffer + offset);
		}
	}
	return NULL;
}

/* Serial number for sorting ccs_task_list . */
static int ccs_dump_index = 0;

/**
 * ccs_sort_process_entry - Sort ccs_tasklist list.
 *
 * @pid:   Pid to search.
 * @depth: Depth of the process for printing like pstree command.
 *
 * Returns nothing.
 */
static void ccs_sort_process_entry(const pid_t pid, const int depth)
{
	int i;
	for (i = 0; i < ccs_task_list_len; i++) {
		if (pid != ccs_task_list[i].pid)
			continue;
		ccs_task_list[i].index = ccs_dump_index++;
		ccs_task_list[i].depth = depth;
		ccs_task_list[i].selected = true;
	}
	for (i = 0; i < ccs_task_list_len; i++) {
		if (pid != ccs_task_list[i].ppid)
			continue;
		ccs_sort_process_entry(ccs_task_list[i].pid, depth + 1);
	}
}

/**
 * ccs_task_entry_compare - Compare routine for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns index diff value.
 */
static int ccs_task_entry_compare(const void *a, const void *b)
{
	const struct ccs_task_entry *a0 = (struct ccs_task_entry *) a;
	const struct ccs_task_entry *b0 = (struct ccs_task_entry *) b;
	return a0->index - b0->index;
}

/**
 * ccs_add_process_entry - Add entry for running processes.
 *
 * @line:    A line containing PID and domainname.
 * @ppid:    Parent PID.
 * @name:    Comm name (allocated by strdup()).
 *
 * Returns nothing.
 *
 * @name is free()d on failure.
 */
static void ccs_add_process_entry(const char *line, const pid_t ppid,
				  char *name)
{
	int index;
	unsigned int pid = 0;
	char *domain;
	if (!line || sscanf(line, "%u", &pid) != 1) {
		free(name);
		return;
	}
	domain = strchr(line, ' ');
	if (domain++)
		domain = ccs_strdup(domain);
	else
		domain = ccs_strdup("<UNKNOWN>");
	index = ccs_task_list_len++;
	ccs_task_list = ccs_realloc(ccs_task_list, ccs_task_list_len *
				    sizeof(struct ccs_task_entry));
	memset(&ccs_task_list[index], 0, sizeof(ccs_task_list[0]));
	ccs_task_list[index].pid = pid;
	ccs_task_list[index].ppid = ppid;
	ccs_task_list[index].name = name;
	ccs_task_list[index].domain = domain;
}

/**
 * ccs_read_process_list - Read all process's information.
 *
 * @show_all: Ture if kernel threads should be included, false otherwise.
 *
 * Returns nothing.
 */
void ccs_read_process_list(_Bool show_all)
{
	int i;
	while (ccs_task_list_len) {
		ccs_task_list_len--;
		free((void *) ccs_task_list[ccs_task_list_len].name);
		free((void *) ccs_task_list[ccs_task_list_len].domain);
	}
	ccs_dump_index = 0;
	if (ccs_network_mode) {
		FILE *fp = ccs_open_write(show_all ?
					  "proc:all_process_status" :
					  "proc:process_status");
		if (!fp)
			return;
		ccs_get();
		while (true) {
			char *line = ccs_freadline(fp);
			unsigned int pid = 0;
			unsigned int ppid = 0;
			char *name;
			if (!line)
				break;
			sscanf(line, "PID=%u PPID=%u", &pid, &ppid);
			name = strstr(line, "NAME=");
			if (name)
				name = ccs_strdup(name + 5);
			else
				name = ccs_strdup("<UNKNOWN>");
			line = ccs_freadline(fp);
			ccs_add_process_entry(line, ppid, name);
		}
		ccs_put();
		fclose(fp);
	} else {
		static const int line_len = 8192;
		char *line;
		int status_fd = open(CCS_PROC_POLICY_PROCESS_STATUS, O_RDWR);
		DIR *dir = opendir("/proc/");
		if (status_fd == EOF || !dir) {
			if (status_fd != EOF)
				close(status_fd);
			if (dir)
				closedir(dir);
			return;
		}
		line = ccs_malloc(line_len);
		while (1) {
			char *name;
			int ret_ignored;
			unsigned int pid = 0;
			char buffer[128];
			char test[16];
			struct dirent *dent = readdir(dir);
			if (!dent)
				break;
			if (dent->d_type != DT_DIR ||
			    sscanf(dent->d_name, "%u", &pid) != 1 || !pid)
				continue;
			memset(buffer, 0, sizeof(buffer));
			if (!show_all) {
				snprintf(buffer, sizeof(buffer) - 1,
					 "/proc/%u/exe", pid);
				if (readlink(buffer, test, sizeof(test)) <= 0)
					continue;
			}
			name = ccs_get_name(pid);
			if (!name)
				name = ccs_strdup("<UNKNOWN>");
			snprintf(buffer, sizeof(buffer) - 1, "%u\n", pid);
			ret_ignored = write(status_fd, buffer, strlen(buffer));
			memset(line, 0, line_len);
			ret_ignored = read(status_fd, line, line_len - 1);
			ccs_add_process_entry(line, ccs_get_ppid(pid), name);
		}
		free(line);
		closedir(dir);
		close(status_fd);
	}
	ccs_sort_process_entry(1, 0);
	for (i = 0; i < ccs_task_list_len; i++) {
		if (ccs_task_list[i].selected) {
			ccs_task_list[i].selected = false;
			continue;
		}
		ccs_task_list[i].index = ccs_dump_index++;
		ccs_task_list[i].depth = 0;
	}
	qsort(ccs_task_list, ccs_task_list_len, sizeof(struct ccs_task_entry),
	      ccs_task_entry_compare);
}

/**
 * ccs_open_write - Open a file for writing.
 *
 * @filename: String to send to remote ccs-editpolicy-agent program if using
 *            network mode, file to open for writing otherwise.
 *
 * Returns pointer to "FILE" on success, NULL otherwise.
 */
FILE *ccs_open_write(const char *filename)
{
	if (ccs_network_mode) {
		const int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in addr;
		FILE *fp;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = ccs_network_ip;
		addr.sin_port = ccs_network_port;
		if (connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
			close(fd);
			return NULL;
		}
		fp = fdopen(fd, "r+");
		/* setbuf(fp, NULL); */
		fprintf(fp, "%s", filename);
		fputc(0, fp);
		fflush(fp);
		if (fgetc(fp) != 0) {
			fclose(fp);
			return NULL;
		}
		return fp;
	} else {
		return fdopen(open(filename, O_WRONLY), "w");
	}
}

/**
 * ccs_close_write - Close stream opened by ccs_open_write().
 *
 * @fp: Pointer to "FILE".
 *
 * Returns true on success, false otherwise.
 */
_Bool ccs_close_write(FILE *fp)
{
	_Bool result = true;
	if (ccs_network_mode) {
		if (fputc(0, fp) == EOF)
			result = false;
		if (fflush(fp) == EOF)
			result = false;
		if (fgetc(fp) == EOF)
			result = false;
	}
	if (fclose(fp) == EOF)
		result = false;
	return result;
}


/**
 * ccs_open_read - Open a file for reading.
 *
 * @filename: String to send to remote ccs-editpolicy-agent program if using
 *            network mode, file to open for reading otherwise.
 *
 * Returns pointer to "FILE" on success, NULL otherwise.
 */
FILE *ccs_open_read(const char *filename)
{
	if (ccs_network_mode) {
		FILE *fp = ccs_open_write(filename);
		if (fp) {
			fputc(0, fp);
			fflush(fp);
		}
		return fp;
	} else {
		return fopen(filename, "r");
	}
}

/**
 * ccs_move_proc_to_file - Save /proc/ccs/ to /etc/ccs/ .
 *
 * @src:  Filename to save from.
 * @dest: Filename to save to.
 *
 * Returns true on success, false otherwise.
 */
_Bool ccs_move_proc_to_file(const char *src, const char *dest)
{
	FILE *proc_fp = ccs_open_read(src);
	FILE *file_fp;
	_Bool result = true;
	if (!proc_fp) {
		fprintf(stderr, "Can't open %s for reading.\n", src);
		return false;
	}
	file_fp = dest ? fopen(dest, "w") : stdout;
	if (!file_fp) {
		fprintf(stderr, "Can't open %s for writing.\n", dest);
		fclose(proc_fp);
		return false;
	}
	while (true) {
		const int c = fgetc(proc_fp);
		if (ccs_network_mode && !c)
			break;
		if (c == EOF)
			break;
		if (fputc(c, file_fp) == EOF)
			result = false;
	}
	fclose(proc_fp);
	if (file_fp != stdout)
		if (fclose(file_fp) == EOF)
			result = false;
	return result;
}

/* Is the shared buffer for ccs_freadline() owned? */
static _Bool ccs_buffer_locked = false;

/**
 * ccs_get - Mark the shared buffer for ccs_freadline() owned.
 *
 * Returns nothing.
 *
 * This is for avoiding accidental overwriting.
 * ccs_freadline() have their own memory buffer.
 */
void ccs_get(void)
{
	if (ccs_buffer_locked)
		ccs_out_of_memory();
	ccs_buffer_locked = true;
}

/**
 * ccs_put - Mark the shared buffer for ccs_freadline() no longer owned.
 *
 * Returns nothing.
 *
 * This is for avoiding accidental overwriting.
 * ccs_freadline() have their own memory buffer.
 */
void ccs_put(void)
{
	if (!ccs_buffer_locked)
		ccs_out_of_memory();
	ccs_buffer_locked = false;
}

/**
 * ccs_freadline - Read a line from file to dynamically allocated buffer.
 *
 * @fp: Pointer to "FILE".
 *
 * Returns pointer to dynamically allocated buffer on success, NULL otherwise.
 *
 * The caller must not free() the returned pointer.
 */
char *ccs_freadline(FILE *fp)
{
	static char *policy = NULL;
	int pos = 0;
	while (true) {
		static int max_policy_len = 0;
		const int c = fgetc(fp);
		if (c == EOF)
			return NULL;
		if (ccs_network_mode && !c)
			return NULL;
		if (pos == max_policy_len) {
			max_policy_len += 4096;
			policy = ccs_realloc(policy, max_policy_len);
		}
		policy[pos++] = (char) c;
		if (c == '\n') {
			policy[--pos] = '\0';
			break;
		}
	}
	ccs_normalize_line(policy);
	return policy;
}

/**
 * ccs_check_remote_host - Check whether the remote host is running with the TOMOYO 1.8 kernel or not.
 *
 * Returns true if running with TOMOYO 1.8 kernel, false otherwise.
 */
_Bool ccs_check_remote_host(void)
{
	int major = 0;
	int minor = 0;
	int rev = 0;
	FILE *fp = ccs_open_read("version");
	if (!fp ||
	    fscanf(fp, "%u.%u.%u", &major, &minor, &rev) < 2 ||
	    major != 1 || minor != 8) {
		const u32 ip = ntohl(ccs_network_ip);
		fprintf(stderr, "Can't connect to %u.%u.%u.%u:%u\n",
			(u8) (ip >> 24), (u8) (ip >> 16),
			(u8) (ip >> 8), (u8) ip, ntohs(ccs_network_port));
		if (fp)
			fclose(fp);
		return false;
	}
	fclose(fp);
	return true;
}
