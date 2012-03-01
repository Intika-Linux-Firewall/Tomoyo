/*
 * convert-exec-param.c
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

int main(int argc, char *argv[])
{
	char buffer[3][65536];
	int line = 0;
	memset(buffer, 0, sizeof(buffer));
	if (argc > 1) {
		fprintf(stderr, "Usage: %s < /proc/ccs/grant_log or "
			"/proc/ccs/reject_log\n", argv[0]);
		return 0;
	}
	while (1) {
		int i;
		char *cp;
		char *exe;
		char *args;
		int envc;
		char *envs;

		/* Find header line. */
		i = getc(stdin);
		if (i)
			ungetc(i, stdin);
		if (!fgets(buffer[0], sizeof(buffer[0]) - 1, stdin))
			break;
		line++;
		if (!strchr(buffer[0], '\n'))
			goto out;
		if (buffer[0][0] != '#')
			continue;

		/* Check for " argc=" part. */
		cp = strstr(buffer[0], " argc=");
		if (!cp)
			continue;
		/* Get argc value. */
		if (sscanf(cp + 1, "argc=%d", &argc) != 1)
			goto out;

		/* Check for " envc=" part. */
		cp = strstr(buffer[0], " envc=");
		if (!cp)
			continue;
		/* Get envc value. */
		if (sscanf(cp + 1, "envc=%d", &envc) != 1)
			goto out;

		/* Get realpath part. */
		exe = strstr(buffer[0], " realpath=\"");
		if (!exe)
			continue;
		exe++;

		/* Get argv[]= part. */
		cp = strstr(buffer[0], " argv[]={ ");
		if (!cp)
			goto out;
		args = cp + 10;

		/* Get envp[]= part. */
		cp = strstr(buffer[0], " envp[]={ ");
		if (!cp)
			goto out;
		envs = cp + 10;

		/* Terminate realpath part. */
		cp = strchr(exe, ' ');
		if (!cp)
			goto out;
		*cp = '\0';

		/* Terminate argv[] part. */
		cp = strstr(args - 1, " } ");
		if (!cp)
			goto out;
		*cp = '\0';

		/* Terminate envp[] part. */
		cp = strstr(envs - 1, " } ");
		if (!cp)
			goto out;
		*cp = '\0';

		/* Get domainname. */
		line++;
		i = getc(stdin);
		if (i)
			ungetc(i, stdin);
		if (!fgets(buffer[1], sizeof(buffer[1]) - 1, stdin) ||
		    !strchr(buffer[1], '\n'))
			goto out;

		/* Get "allow_execute " line. */
		line++;
		i = getc(stdin);
		if (i)
			ungetc(i, stdin);
		if (!fgets(buffer[2], sizeof(buffer[2]) - 1, stdin))
			goto out;
		cp = strchr(buffer[2], '\n');
		if (!cp)
			goto out;
		*cp-- = '\0';
		while (*cp == ' ')
			*cp-- = '\0';
		if (strncmp(buffer[2], "allow_execute ", 14))
			continue;

		/* Print domainname. */
		printf("%s", buffer[1]);
		/* Print permission and exec.realpath part. */
		printf("%s if exec.%s", buffer[2], exe);
		/* Print exec.argc part. */
		printf(" exec.argc=%d", argc);
		/* Print exec.argv[] part. */
		if (argc) {
			i = 0;
			cp = strtok(args, " ");
			while (cp && *cp == '"') {
				printf(" exec.argv[%d]=%s", i++, cp);
				cp = strtok(NULL, " ");
			}
		}
		/* Print exec.envc part. */
		printf(" exec.envc=%d", envc);
		/* Print exec.envp[] part. */
		if (envc) {
			cp = strtok(envs, " ");
			while (cp && *cp == '"') {
				char c = *(cp + 1);
				char *cp2 = cp + 1;
				if (!c || c == '"' || c == '=')
					goto bad_env;
				while (1) {
					c = *cp2++;
					if (c == '=')
						break;
					if (!c || c == '"')
						goto bad_env;
				}
				if (!*cp2 || *cp2 == '"')
					goto bad_env;
				printf(" exec.envp[");
				while (1) {
					c = *cp++;
					if (c == '=')
						break;
					putchar(c);
				}
				printf("\"]=\"%s", cp);
bad_env:
				cp = strtok(NULL, " ");
			}
		}
		printf("\n\n");
	}
	return 0;
 out:
	fprintf(stderr, "%d: Broken log entry. Aborted.\n", line);
	return 1;
}
