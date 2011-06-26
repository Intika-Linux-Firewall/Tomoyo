/*
 * tomoyo-domainmatch.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0-pre   2011/06/26
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
	ccs_mount_securityfs();
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
		if (ccs_domain_def(buffer)) {
			free(domain);
			domain = ccs_strdup(buffer);
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
