/*
 * tomoyo-ld-watch.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.3.0+   2011/09/29
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

struct tomoyo_dll_pathname_entry {
	char *pathname;
	char *real_pathname;
};

static struct tomoyo_dll_pathname_entry *tomoyo_entry_list = NULL;
static int tomoyo_entry_list_count = 0;

static void tomoyo_update_ld_list(int argc, char *argv[], FILE *fp_policy)
{
	struct stat64 buf;
	static time_t last_modified = 0;
	int i;
	char buffer[16384];
	FILE *fp_ldconfig;
	if (stat64("/etc/ld.so.cache", &buf) || buf.st_mtime == last_modified)
		return;
	fp_ldconfig = popen("/sbin/ldconfig -NXp", "r");
	if (!fp_ldconfig)
		goto out;
	last_modified = buf.st_mtime;
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp_ldconfig)) {
		char *cp;
		char *pathname;
		char *real_pathname;
		cp = strchr(buffer, '\n');
		if (!cp)
			continue;
		*cp = '\0';
		cp = strrchr(buffer, ' ');
		if (!cp || *++cp != '/')
			continue;
		/* Check for duplicated entries. */
		real_pathname = realpath(cp, NULL);
		if (!real_pathname)
			continue;
		for (i = 0; i < tomoyo_entry_list_count; i++) {
			if (!strcmp(tomoyo_entry_list[i].real_pathname, real_pathname))
				break;
		}
		if (i < tomoyo_entry_list_count) {
			free(real_pathname);
			continue;
		}
		/* Exclude if listed by command line. */
		for (i = 1; i < argc; i++) {
			if (!strcmp(argv[i], real_pathname) ||
			    !strcmp(argv[i], cp))
				break;
		}
		if (i < argc) {
			printf("Skipped %s : %s\n", cp, real_pathname);
			free(real_pathname);
			continue;
		}
		/* Add an entry. */
		pathname = strdup(cp);
		if (!pathname)
			tomoyo_out_of_memory();
		tomoyo_entry_list = realloc(tomoyo_entry_list, (tomoyo_entry_list_count + 1) *
				     sizeof(struct tomoyo_dll_pathname_entry));
		if (!tomoyo_entry_list)
			tomoyo_out_of_memory();
		tomoyo_entry_list[tomoyo_entry_list_count].pathname = pathname;
		tomoyo_entry_list[tomoyo_entry_list_count++].real_pathname = real_pathname;
		printf("Added %s : %s\n", pathname, real_pathname);
		fprintf(fp_policy, CCS_KEYWORD_ALLOW_READ);
		tomoyo_fprintf_encoded(fp_policy, real_pathname);
		fprintf(fp_policy, "\n");
		fflush(fp_policy);
	}
	pclose(fp_ldconfig);
out:
	printf("Monitoring %d files.\n", tomoyo_entry_list_count);
}

int main(int argc, char *argv[])
{
	FILE *fp_policy;
	if (argc > 1 && !strcmp(argv[1], "--help"))
		goto usage;
	tomoyo_mount_securityfs();
	{
		const int fd = open(CCS_PROC_POLICY_EXCEPTION_POLICY, O_RDWR);
		if (fd == EOF) {
			fprintf(stderr, "You can't run this program "
				"for this kernel.\n");
			return 1;
		} else if (write(fd, "", 0) != 0) {
			fprintf(stderr, "You need to register this program to "
				"%s to run this program.\n",
				CCS_PROC_POLICY_MANAGER);
			return 1;
		}
		close(fd);
	}
	fp_policy = fopen(CCS_PROC_POLICY_EXCEPTION_POLICY, "w");
	if (!fp_policy) {
		fprintf(stderr, "Can't open policy file.\n");
		exit(1);
	}
	while (true) {
		int i;
		tomoyo_update_ld_list(argc, argv, fp_policy);
		/* Check entries for update. */
		for (i = 0; i < tomoyo_entry_list_count; i++) {
			struct tomoyo_dll_pathname_entry *ptr = &tomoyo_entry_list[i];
			char *real_pathname = realpath(ptr->pathname, NULL);
			if (real_pathname &&
			    strcmp(ptr->real_pathname, real_pathname)) {
				printf("Changed %s : %s -> %s\n",
				       ptr->pathname, ptr->real_pathname,
				       real_pathname);
				fprintf(fp_policy, CCS_KEYWORD_ALLOW_READ);
				tomoyo_fprintf_encoded(fp_policy, real_pathname);
				fprintf(fp_policy, "\n");
				fflush(fp_policy);
				free(ptr->real_pathname);
				ptr->real_pathname = real_pathname;
				real_pathname = NULL;
			}
			free(real_pathname);
		}
		sleep(1);
	}
	fclose(fp_policy);
	return 0;
usage:
	printf("Usage: %s file_to_exclude1 [file_to_exclude2 [...]]\n\n",
	       argv[0]);
	printf("This program automatically registers files shown by "
	       "'ldconfig -NXp' as globally readable files.\n");
	printf("This program registers all files shown by 'ldconfig -NXp' "
	       "by default, but you can specify files that you don't want to "
	       "register by command line.\n");
	printf("For example, if you invoke\n");
	printf("  %s /lib/libcustom-1.0.0.so /lib/libcustom.so.1\n", argv[0]);
	printf("then, /lib/libcustom-1.0.0.so and /lib/libcustom.so.1 will be "
	       "excluded from the result of 'ldconfig -NXp'.\n\n");
	printf("Start this program in one window, then update packages in "
	       "another window.\n");
	printf("After you finished updating, wait for several seconds and "
	       "terminate this program with 'Ctrl-C'.\n");
	return 0;
}
