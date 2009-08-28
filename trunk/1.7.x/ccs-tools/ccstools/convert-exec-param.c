/*
 * convert-exec-param.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/24
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
		char *cp1;
		char *cp2;

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
		cp1 = strstr(buffer[0], " argc=");
		if (!cp1)
			continue;

		/* Get argc value. */
		if (sscanf(cp1 + 1, "argc=%d", &argc) != 1)
			goto out;

		if (!argc)
			continue;

		cp1 = strstr(buffer[0], " argv[]={ ");
		if (!cp1)
			goto out;
		cp2 = strstr(cp1 + 10, " } ");
		if (!cp2)
			goto out;

		/* Check for " ... " part. */
		if (!strncmp(cp2 - 4, " ... ", 5)) {
			fprintf(stderr, "%d: Too long header. Ignored.\n",
				line);
			continue;
		}
		*cp2 = '\0';
		memmove(buffer[0], cp1 + 10,  strlen(cp1 + 10) + 1);

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
		cp1 = strchr(buffer[2], '\n');
		if (!cp1)
			goto out;
		*cp1-- = '\0';
		while (*cp1 == ' ')
			*cp1-- = '\0';
		if (strncmp(buffer[2], "allow_execute ", 14))
			continue;
		printf("select %s", buffer[1]);
		{
			char *cond = strstr(buffer[2], " if ");
			if (!cond)
				printf("%s if exec.argc=%d", buffer[2], argc);
			else {
				unsigned char *argv0 =
					strstr(buffer[2], " exec.argv[0]=\"");
				const int len = cond + 4 - buffer[2];
				fwrite(buffer[2], 1, len, stdout);
				if (argv0) {
					argv0++;
					while (*argv0 > ' ')
						*argv0++ = ' ';
				}
				printf("exec.argc=%d", argc);
				fwrite(buffer[2] + len, 1,
				       strlen(buffer[2] + len), stdout);
			}
		}
		i = 0;
		cp1 = strtok(buffer[0], " ");
		while (cp1) {
			printf(" exec.argv[%d]=%s", i++, cp1);
			cp1 = strtok(NULL, " ");
		}
		printf("\n");
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
