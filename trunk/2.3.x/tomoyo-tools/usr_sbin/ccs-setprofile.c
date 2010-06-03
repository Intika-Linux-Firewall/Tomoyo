/*
 * ccs-setprofile.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/04/06
 *
 */
#include "ccstools.h"

int main(int argc, char *argv[])
{
	FILE *fp_in;
	FILE *fp_out;
	unsigned int profile = 0;
	_Bool recursive = false;
	int i;
	int start = 2;
	if (argc > 1 && !strcmp(argv[1], "-r")) {
		recursive = true;
		start = 3;
	}
	if (argc <= start || sscanf(argv[start - 1], "%u", &profile) != 1) {
		fprintf(stderr, "%s [-r] profile domainname [domainname ...]\n",
			argv[0]);
		return 0;
	}
	for (i = start; i < argc; i++)
		ccs_normalize_line(argv[i]);
	{
		const int fd = open(CCS_PROC_POLICY_DOMAIN_STATUS, O_RDWR);
		if (fd == EOF) {
			fprintf(stderr, "You can't run this command for this "
				"kernel.\n");
			return 1;
		} else if (write(fd, "", 0) != 0) {
			fprintf(stderr, "You need to register this program to "
				"%s to run this program.\n",
				CCS_PROC_POLICY_MANAGER);
			return 1;
		}
		close(fd);
	}
	{
		_Bool profile_found = false;
		FILE *fp = fopen(CCS_PROC_POLICY_PROFILE, "r");
		if (!fp) {
			fprintf(stderr, "Can't open policy file.\n");
			exit(1);
		}
		ccs_get();
		while (true) {
			char *line = ccs_freadline(fp);
			if (!line)
				break;
			if (atoi(line) != profile)
				continue;
			profile_found = true;
			break;
		}
		ccs_put();
		fclose(fp);
		if (!profile_found) {
			fprintf(stderr, "Profile %u not defined.\n", profile);
			exit(1);
		}
	}
	fp_in = fopen(CCS_PROC_POLICY_DOMAIN_STATUS, "r");
	fp_out = fopen(CCS_PROC_POLICY_DOMAIN_STATUS, "w");
	if (!fp_in || !fp_out) {
		fprintf(stderr, "Can't open policy file.\n");
		exit(1);
	}
	ccs_get();
	while (true) {
		char *cp;
		char *line = ccs_freadline(fp_in);
		if (!line)
			break;
		cp = strchr(line, ' ');
		if (!cp)
			break;
		*cp++ = '\0';
		for (i = start; i < argc; i++) {
			const int len = strlen(argv[i]);
			if (strncmp(cp, argv[i], len))
				continue;
			if (!recursive) {
				if (cp[len])
					continue;
			} else {
				if (cp[len] && cp[len] != ' ')
					continue;
			}
			fprintf(fp_out, "%u %s\n", profile, cp);
			printf("%u %s\n", profile, cp);
		}
	}
	ccs_put();
	fclose(fp_in);
	fclose(fp_out);
	return 0;
}
