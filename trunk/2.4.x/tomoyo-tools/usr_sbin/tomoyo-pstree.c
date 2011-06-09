/*
 * tomoyo-pstree.c
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

static void tomoyo_dump(const pid_t pid, const int depth)
{
	int i;
	for (i = 0; i < tomoyo_task_list_len; i++) {
		int j;
		if (pid != tomoyo_task_list[i].pid)
			continue;
		printf("%3d", tomoyo_task_list[i].profile);
		for (j = 0; j < depth - 1; j++)
			printf("    ");
		for (; j < depth; j++)
			printf("  +-");
		printf(" %s (%u) %s\n", tomoyo_task_list[i].name,
		       tomoyo_task_list[i].pid, tomoyo_task_list[i].domain);
		tomoyo_task_list[i].selected = true;
	}
	for (i = 0; i < tomoyo_task_list_len; i++) {
		if (pid != tomoyo_task_list[i].ppid)
			continue;
		tomoyo_dump(tomoyo_task_list[i].pid, depth + 1);
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
			if (tomoyo_network_mode)
				goto usage;
			tomoyo_network_ip = inet_addr(ptr);
			tomoyo_network_port = htons(atoi(cp));
			tomoyo_network_mode = true;
			if (!tomoyo_check_remote_host())
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
	if (!tomoyo_network_mode)
		tomoyo_mount_securityfs();
	tomoyo_read_process_list(show_all);
	if (!tomoyo_task_list_len) {
		if (tomoyo_network_mode) {
			fprintf(stderr, "Can't connect.\n");
			return 1;
		} else {
			fprintf(stderr, "You can't use this command "
				"for this kernel.\n");
			return 1;
		}
	}
	tomoyo_dump(1, 0);
	for (i = 0; i < tomoyo_task_list_len; i++) {
		if (tomoyo_task_list[i].selected)
			continue;
		printf("%3d %s (%u) %s\n",
		       tomoyo_task_list[i].profile, tomoyo_task_list[i].name,
		       tomoyo_task_list[i].pid, tomoyo_task_list[i].domain);
		tomoyo_task_list[i].selected = true;
	}
	while (tomoyo_task_list_len) {
		tomoyo_task_list_len--;
		free((void *) tomoyo_task_list[tomoyo_task_list_len].name);
		free((void *) tomoyo_task_list[tomoyo_task_list_len].domain);
	}
	free(tomoyo_task_list);
	tomoyo_task_list = NULL;
	return 0;
}
