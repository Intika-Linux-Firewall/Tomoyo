/*
 * ccs-pstree.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
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

struct ccs_task_entry {
	pid_t pid;
	pid_t ppid;
	char *name;
	char *domain;
	_Bool selected;
	int index;
	int depth;
};

/* The list of processes currently running. */
static struct ccs_task_entry *ccs_task_list = NULL;
/* The length of ccs_task_list . */
static int ccs_task_list_len = 0;

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

/**
 * ccs_read_process_list - Read all process's information.
 *
 * @show_all: Ture if kernel threads should be included, false otherwise.
 *
 * Returns nothing.
 */
static void ccs_read_process_list(_Bool show_all)
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

static void ccs_dump(const pid_t pid, const int depth)
{
	int i;
	for (i = 0; i < ccs_task_list_len; i++) {
		int j;
		if (pid != ccs_task_list[i].pid)
			continue;
		for (j = 0; j < depth - 1; j++)
			printf("    ");
		for (; j < depth; j++)
			printf("  +-");
		printf(" %s (%u) %s\n", ccs_task_list[i].name,
		       ccs_task_list[i].pid, ccs_task_list[i].domain);
		ccs_task_list[i].selected = true;
	}
	for (i = 0; i < ccs_task_list_len; i++) {
		if (pid != ccs_task_list[i].ppid)
			continue;
		ccs_dump(ccs_task_list[i].pid, depth + 1);
	}
}

int main(int argc, char *argv[])
{
	static _Bool show_all = false;
	int i;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (cp) {
			*cp++ = '\0';
			if (ccs_network_mode)
				goto usage;
			ccs_network_ip = inet_addr(ptr);
			ccs_network_port = htons(atoi(cp));
			ccs_network_mode = true;
			if (!ccs_check_remote_host())
				return 1;
		} else if (!strcmp(ptr, "-a")) {
			show_all = true;
		} else {
usage:
			fprintf(stderr, "Usage: %s "
				"[-a] [remote_ip:remote_port]\n", argv[0]);
			return 0;
		}
	}
	ccs_read_process_list(show_all);
	if (!ccs_task_list_len) {
		if (ccs_network_mode) {
			fprintf(stderr, "Can't connect.\n");
			return 1;
		} else {
			fprintf(stderr, "You can't use this command "
				"for this kernel.\n");
			return 1;
		}
	}
	ccs_dump(1, 0);
	for (i = 0; i < ccs_task_list_len; i++) {
		if (ccs_task_list[i].selected)
			continue;
		printf(" %s (%u) %s\n", ccs_task_list[i].name,
		       ccs_task_list[i].pid, ccs_task_list[i].domain);
		ccs_task_list[i].selected = true;
	}
	while (ccs_task_list_len) {
		ccs_task_list_len--;
		free((void *) ccs_task_list[ccs_task_list_len].name);
		free((void *) ccs_task_list[ccs_task_list_len].domain);
	}
	free(ccs_task_list);
	ccs_task_list = NULL;
	return 0;
}
