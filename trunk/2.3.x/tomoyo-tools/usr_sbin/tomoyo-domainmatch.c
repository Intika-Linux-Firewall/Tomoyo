/*
 * tomoyo-domainmatch.c
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
	char buffer[16384];
	_Bool flag = 0;
	static char *domain = NULL;
	FILE *fp;
	if (argc != 2) {
		printf("%s string_to_find\n\n", argv[0]);
		return 0;
	}
	tomoyo_mount_securityfs();
	fp = fopen(CCS_PROC_POLICY_DOMAIN_POLICY, "r");
	if (!fp) {
		fprintf(stderr,
			"You can't run this program for this kernel.\n");
		return 0;
	}
	memset(buffer, 0, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!strncmp(buffer, "<kernel>", 8) &&
		    (buffer[8] == ' ' || !buffer[8])) {
			free(domain);
			domain = strdup(buffer);
			if (!domain)
				tomoyo_out_of_memory();
			flag = 0;
			continue;
		}
		if (strstr(buffer, argv[1])) {
			if (!flag)
				printf("\n%s\n", domain);
			flag = 1;
			printf("%s\n", buffer);
		}
	}
	fclose(fp);
	free(domain);
	return 0;
}
