/*
 * setlevel.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include "ccstools.h"

int setlevel_main(int argc, char *argv[])
{
	const char *policy_file = proc_policy_profile;
	int i;
	int fd;
	char c;
	if (access(proc_policy_dir, F_OK)) {
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
			"run this program.\n", proc_policy_manager);
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
		get();
		while (true) {
			char *line = freadline(fp);
			if (!line)
				break;
			for (i = 1; i < argc; i++) {
				if (strncmp(line, argv[i], strlen(argv[i])))
					continue;
				printf("%s\n", line);
				break;
			}
		}
		put();
		fclose(fp);
	}
	close(fd);
	return 0;
}
