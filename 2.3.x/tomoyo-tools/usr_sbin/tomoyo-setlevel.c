/*
 * tomoyo-setlevel.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 2.3.0   2010/08/02
 *
 */
#include "tomoyotools.h"

int main(int argc, char *argv[])
{
	const char *policy_file = CCS_PROC_POLICY_PROFILE;
	int i;
	int fd;
	char c;
	if (access(CCS_PROC_POLICY_DIR, F_OK)) {
		fprintf(stderr, "You can't use this command for this "
			"kernel.\n");
		return 1;
	}
	fd = open(policy_file, O_RDWR);
	if (fd == EOF) {
		fprintf(stderr, "Can't open %s\n", policy_file);
		return 1;
	} else if (write(fd, "", 0) != 0) {
		fprintf(stderr, "You need to register this program to %s to "
			"run this program.\n", CCS_PROC_POLICY_MANAGER);
		return 1;
	}
	if (argc == 1) {
		printf("<<< Access Control Status >>>\n");
		while (read(fd, &c, 1) == 1)
			putchar(c);
	} else {
		FILE *fp = fdopen(fd, "r+");
		if (!fp) {
			fprintf(stderr, "Can't open %s\n", policy_file);
			close(fd);
			return 1;
		}
		for (i = 1; i < argc; i++) {
			char *cp = strchr(argv[i], '=');
			fprintf(fp, "%s\n", argv[i]);
			if (cp)
				*(cp + 1) = '\0';
		}
		fflush(fp);
		tomoyo_get();
		while (true) {
			char *line = tomoyo_freadline(fp);
			if (!line)
				break;
			for (i = 1; i < argc; i++) {
				if (strncmp(line, argv[i], strlen(argv[i])))
					continue;
				printf("%s\n", line);
				break;
			}
		}
		tomoyo_put();
		fclose(fp);
	}
	close(fd);
	return 0;
}
