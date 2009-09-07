/*
 * convert-exec-param.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0+   2009/09/07
 *
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	char buffer[3][65536];
	int line = 0;
	memset(buffer, 0, sizeof(buffer));
	while (1) {
		int i;
		char *cp;
		char *exe;
		char *args;

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
		
		/* Get realpath part. */
		exe = strstr(buffer[0], " realpath=\"");
		if (!exe)
			continue;
		
		/* Get argv[]= part. */
		cp = strstr(buffer[0], " argv[]={ ");
		if (!cp)
			goto out;
		args = cp + 10;
		cp = strstr(args, " } ");
		if (!cp)
			goto out;

		/* Check for " ... " part. */
		if (!strncmp(cp - 4, " ... ", 5)) {
			fprintf(stderr, "%d: Too long header. Ignored.\n",
				line);
			continue;
		}
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
		printf("%s", buffer[1]);
		printf("%s if exec.", buffer[2]);
		exe++;
		while (1) {
			const unsigned char c = *exe++;
			if (c <= ' ')
				break;
			putchar(c);
		}
		printf(" exec.argc=%d", argc);
		if (argc) {
			i = 0;
			cp = strtok(args, " ");
			while (cp) {
				printf(" exec.argv[%d]=%s", i++, cp);
				cp = strtok(NULL, " ");
			}
		}
		printf("\n\n");
	}
	if (!line) {
		fprintf(stderr, "Usage: %s < /proc/ccs/grant_log or "
			"/proc/ccs/reject_log\n", argv[0]);
	}
	return 0;
 out:
	fprintf(stderr, "%d: Broken log entry. Aborted.\n", line);
	return 1;
}
