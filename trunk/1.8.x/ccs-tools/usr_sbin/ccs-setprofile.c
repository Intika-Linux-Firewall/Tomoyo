/*
 * ccs-setprofile.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.5   2015/11/11
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

int main(int argc, char *argv[])
{
	unsigned int profile = 0;
	_Bool recursive = false;
	int try;
	int i;
	int start = 2;
	if (argc > 1 && !strcmp(argv[1], "-r")) {
		recursive = true;
		start = 3;
	}
	if (argc <= start || sscanf(argv[start - 1], "%u", &profile) != 1) {
		fprintf(stderr,
			"%s [-r] profile domainname [domainname ...]\n",
			argv[0]);
		return 0;
	}
	for (i = start; i < argc; i++)
		ccs_normalize_line(argv[i]);
	{
		const int fd = open(CCS_PROC_POLICY_DOMAIN_POLICY, O_RDWR);
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
	for (try = 0; try < 2; try++) {
		FILE *fp_in = fopen(CCS_PROC_POLICY_DOMAIN_POLICY, "r");
		FILE *fp_out = fopen(CCS_PROC_POLICY_DOMAIN_POLICY, "w");
		char *domainname = NULL;
		if (!fp_in || !fp_out) {
			fprintf(stderr, "Can't open policy file.\n");
			exit(1);
		}
		ccs_get();
		while (true) {
			char *line = ccs_freadline(fp_in);
			if (!line)
				break;
			if (domainname) {
				if (sscanf(line, "use_profile %u", &profile)
				    != 1)
					continue;
				printf("%u %s\n", profile, domainname);
				free(domainname);
				domainname = NULL;
				continue;
			}
			if (*line != '<')
				continue;
			for (i = start; i < argc; i++) {
				const int len = strlen(argv[i]);
				if (strncmp(line, argv[i], len))
					continue;
				if (!recursive) {
					if (line[len])
						continue;
				} else {
					if (line[len] && line[len] != ' ')
						continue;
				}
				if (try) {
					domainname = ccs_strdup(line);
					break;
				}
				fprintf(fp_out, "select %s\nuse_profile %u\n",
					line, profile);
				break;
			}
		}
		ccs_put();
		fclose(fp_in);
		fclose(fp_out);
	}
	return 0;
}
