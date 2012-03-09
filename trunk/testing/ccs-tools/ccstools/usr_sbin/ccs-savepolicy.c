/*
 * ccs-savepolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
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

static const char *ccs_policy_dir = NULL;

static _Bool ccs_cat_file(const char *path)
{
	FILE *fp = ccs_open_read(path);
	_Bool result = true;
	if (!fp) {
		fprintf(stderr, "Can't open %s\n", path);
		return false;
	}
	while (true) {
		int c = fgetc(fp);
		if (ccs_network_mode && !c)
			break;
		if (c == EOF)
			break;
		if (putchar(c) == EOF)
			result = false;
	}
	fclose(fp);
	return result;
}

static _Bool ccs_save_policy(void)
{
	time_t now = time(NULL);
	char stamp[32] = { };
	while (1) {
		struct tm *tm = localtime(&now);
		snprintf(stamp, sizeof(stamp) - 1,
			 "%02d-%02d-%02d.%02d:%02d:%02d",
			 tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday,
			 tm->tm_hour, tm->tm_min, tm->tm_sec);
		if (access(stamp, F_OK))
			break;
		else if (errno == EEXIST)
			now++;
		else {
			fprintf(stderr, "Can't create %s/policy/%s .\n",
				ccs_policy_dir, stamp);
			return false;
		}
	}
	if (!ccs_move_proc_to_file(CCS_PROC_POLICY_POLICY, stamp) ||
	    (rename("current", "previous") && errno != ENOENT) ||
	    symlink(stamp, "current")) {
		fprintf(stderr, "Failed to save policy.\n");
		return false;
	}
	return true;
}

int main(int argc, char *argv[])
{
	_Bool use_stdout = false;
	int i;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (ccs_policy_dir || use_stdout)
				goto usage;
			ccs_policy_dir = ptr;
		} else if (cp) {
			*cp++ = '\0';
			ccs_network_ip = inet_addr(ptr);
			ccs_network_port = htons(atoi(cp));
			if (ccs_network_mode) {
				fprintf(stderr, "You cannot specify multiple "
					"%s at the same time.\n\n",
					"remote agents");
				goto usage;
			}
			ccs_network_mode = true;
		} else if (*ptr++ == '-' && !*ptr) {
			if (ccs_policy_dir || use_stdout)
				goto usage;
			use_stdout = true;
		} else
			goto usage;
	}
	if (ccs_network_mode) {
		if (!ccs_check_remote_host())
			return 1;
	} else if (access(CCS_PROC_POLICY_DIR, F_OK)) {
		fprintf(stderr,
			"You can't run this program for this kernel.\n");
		return 1;
	}
	if (use_stdout)
		return !ccs_cat_file(CCS_PROC_POLICY_POLICY);
	if (!ccs_policy_dir) {
		if (ccs_network_mode && !use_stdout) {
			fprintf(stderr, "You need to specify %s.\n\n",
				"policy directory");
			goto usage;
		}
		ccs_policy_dir = "/etc/ccs/";
	}
	if (chdir(ccs_policy_dir) || chdir("policy/")) {
		fprintf(stderr, "Directory %s/policy/ doesn't exist.\n",
			ccs_policy_dir);
		return 1;
	}
	return !ccs_save_policy();
usage:
	printf("%s [policy_dir|-] [remote_ip:remote_port]]\n\n"
	       "policy_dir : Use policy_dir rather than /etc/ccs/ directory.\n"
	       "- : Print /proc/ccs/policy to stdout.\n"
	       "remote_ip:remote_port : Read from ccs-editpolicy-agent "
	       "listening at remote_ip:remote_port rather than /proc/ccs/ "
	       "directory.\n", argv[0]);
	return 1;
}
