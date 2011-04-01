/*
 * convert-audit-log.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char buffer[65536];
static char *cond = NULL;
static int cond_len = 0;

static void realloc_buffer(const int len)
{
	cond = realloc(cond, cond_len + len);
	if (!cond)
		exit(1);
}

static void handle_task_condition(void)
{
	while (fscanf(stdin, "%65534s", buffer) == 1 && strcmp(buffer, "}")) {
		realloc_buffer(strlen(buffer) + 7);
		cond_len += sprintf(cond + cond_len, " task.%s", buffer);
	}
}

static void handle_path_condition(const char *path)
{
	const int len0 = strlen(path) + 2;
	while (fscanf(stdin, "%65534s", buffer) == 1 && strcmp(buffer, "}")) {
		realloc_buffer(len0 + strlen(buffer));
		cond_len += sprintf(cond + cond_len, " %s%s", path, buffer);
	}
}

static void handle_argv_condition(void)
{
	int i = 0;
	while (fscanf(stdin, "%65534s", buffer) == 1 && strcmp(buffer, "}")
	       && strcmp(buffer, "...")) {
		realloc_buffer(strlen(buffer) + 34);
		cond_len += sprintf(cond + cond_len, " exec.argv[%u]=%s", i++,
				    buffer);
	}
}

static void handle_envp_condition(void)
{
	while (fscanf(stdin, "%65534s", buffer) == 1 && strcmp(buffer, "}")
	       && strcmp(buffer, "...")) {
		/*
		 * We won't check exec.envp["name"]="value" condition if not in
		 * "name=value" format.
		 * But we check "allow_env name" permission even if not in
		 * "name=value" format.
		 */
		char *cp = strchr(buffer, '=');
		if (!cp)
			continue;
		realloc_buffer(strlen(buffer) + 16);
		*cp++ = '\0';
		cond_len += sprintf(cond + cond_len, " exec.envp[%s\"]=\"%s",
				    buffer, cp);
	}
}

static void handle_exec_condition(void)
{
	while (fscanf(stdin, "%65534s", buffer) == 1 && strcmp(buffer, "}")) {
		if (!strcmp(buffer, "argv[]={"))
			handle_argv_condition();
		else if (!strcmp(buffer, "envp[]={"))
			handle_envp_condition();
		else {
			realloc_buffer(strlen(buffer) + 7);
			cond_len += sprintf(cond + cond_len, " exec.%s",
					    buffer);
		}
	}
}

int main(int argc, char *argv[])
{
	char *domainname = NULL;
	memset(buffer, 0, sizeof(buffer));
	if (argc > 1) {
		fprintf(stderr, "Usage: %s < grant_log or reject_log\n",
			argv[0]);
		return 0;
	}
	while (fscanf(stdin, "%65534s", buffer) == 1) {
		if (!strcmp(buffer, "task={"))
			handle_task_condition();
		else if (!strcmp(buffer, "path1={"))
			handle_path_condition("path1.");
		else if (!strcmp(buffer, "path1.parent={"))
			handle_path_condition("path1.parent.");
		else if (!strcmp(buffer, "path2={"))
			handle_path_condition("path2.");
		else if (!strcmp(buffer, "path2.parent={"))
			handle_path_condition("path2.parent.");
		else if (!strcmp(buffer, "path2.parent={"))
			handle_path_condition("path2.parent.");
		else if (!strcmp(buffer, "exec={"))
			handle_exec_condition();
		else if (!strncmp(buffer, "symlink.target=", 15)) {
			realloc_buffer(strlen(buffer) + 2);
			cond_len += sprintf(cond + cond_len, " %s", buffer);
		} else if (!strcmp(buffer, "<kernel>")) {
			char *cp;
			if (!fgets(buffer, sizeof(buffer) - 1, stdin) ||
			    !strchr(buffer, '\n'))
				break;
			free(domainname);
			domainname = strdup(buffer);
			if (!domainname)
				break;
			if (!fgets(buffer, sizeof(buffer) - 1, stdin))
				break;
			cp = strstr(buffer, " if ");
			if (!cp)
				cp = strchr(buffer, '\n');
			if (!cp)
				break;
			*cp = '\0';
			if (!strncmp(buffer, "use_profile ", 12) ||
			    !strncmp(buffer, "execute_handler ", 16) ||
			    !strncmp(buffer, "denied_execute_handler ", 23)) {
				cond_len = 0;
				continue;
			}
			printf("<kernel>%s", domainname);
			printf("%s", buffer);
			if (cond_len) {
				printf(" if%s", cond);
				cond_len = 0;
			}
			putchar('\n');
		}
	}
	free(domainname);
	free(cond);
	return 0;
}
