/*
 * pstree.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include "ccstools.h"

static void dump(const pid_t pid, const int depth)
{
	int i;
	for (i = 0; i < task_list_len; i++) {
		int j;
		if (pid != task_list[i].pid)
			continue;
		printf("%3d", task_list[i].profile);
		for (j = 0; j < depth - 1; j++)
			printf("    ");
		for (; j < depth; j++)
			printf("  +-");
		printf(" %s (%u) %s\n", task_list[i].name,
		       task_list[i].pid, task_list[i].domain);
		task_list[i].selected = true;
	}
	for (i = 0; i < task_list_len; i++) {
		if (pid != task_list[i].ppid)
			continue;
		dump(task_list[i].pid, depth + 1);
	}
}

int pstree_main(int argc, char *argv[])
{
	static _Bool show_all = false;
	int i;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (cp) {
			*cp++ = '\0';
			if (network_mode)
				goto usage;
			network_ip = inet_addr(ptr);
			network_port = htons(atoi(cp));
			network_mode = true;
			if (!check_remote_host())
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
	read_process_list(show_all);
	if (!task_list_len) {
		if (network_mode) {
			fprintf(stderr, "Can't connect.\n");
			return 1;
		} else {
			fprintf(stderr, "You can't use this command "
				"for this kernel.\n");
			return 1;
		}
	}
	dump(1, 0);
	for (i = 0; i < task_list_len; i++) {
		if (task_list[i].selected)
			continue;
		printf("%3d %s (%u) %s\n",
		       task_list[i].profile, task_list[i].name,
		       task_list[i].pid, task_list[i].domain);
		task_list[i].selected = true;
	}
	while (task_list_len) {
		task_list_len--;
		free((void *) task_list[task_list_len].name);
		free((void *) task_list[task_list_len].domain);
	}
	free(task_list);
	task_list = NULL;
	return 0;
}
