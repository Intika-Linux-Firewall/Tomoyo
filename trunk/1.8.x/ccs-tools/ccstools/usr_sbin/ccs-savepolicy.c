/*
 * ccs-savepolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0+   2010/12/20
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
		putchar(c);
	}
	fclose(fp);
	return true;
}

static void save_policy(void)
{
	time_t now = time(NULL);
	char stamp[32] = { };
	while (1) {
		struct tm *tm = localtime(&now);
		snprintf(stamp, sizeof(stamp) - 1,
			 "%02d-%02d-%02d.%02d:%02d:%02d/",
			 tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday,
			 tm->tm_hour, tm->tm_min, tm->tm_sec);
		if (!mkdir(stamp, 0700))
			break;
		else if (errno == EEXIST)
			now++;
		else {
			fprintf(stderr, "Can't create %s/%s .\n",
				ccs_policy_dir, stamp);
			exit(1);
		}
	}
	if ((symlink("policy/current/profile.conf", "../profile.conf") &&
	     errno != EEXIST) ||
	    (symlink("policy/current/manager.conf", "../manager.conf") &&
	     errno != EEXIST) ||
	    (symlink("policy/current/exception_policy.conf",
		     "../exception_policy.conf") && errno != EEXIST) ||
	    (symlink("policy/current/domain_policy.conf",
		     "../domain_policy.conf") && errno != EEXIST) ||
	    chdir(stamp) ||
	    !ccs_move_proc_to_file(CCS_PROC_POLICY_PROFILE, "profile.conf") ||
	    !ccs_move_proc_to_file(CCS_PROC_POLICY_MANAGER, "manager.conf") ||
	    !ccs_move_proc_to_file(CCS_PROC_POLICY_EXCEPTION_POLICY,
				   "exception_policy.conf") ||
	    !ccs_move_proc_to_file(CCS_PROC_POLICY_DOMAIN_POLICY,
				   "domain_policy.conf") ||
	    chdir("..") ||
	    (rename("current", "previous") && errno != ENOENT) ||
	    symlink(stamp, "current")) {
		fprintf(stderr, "Failed to save policy.\n");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	_Bool write_to_stdout = false;
	u8 save_profile = 0;
	u8 save_manager = 0;
	u8 save_exception_policy = 0;
	u8 save_domain_policy = 0;
	u8 save_meminfo = 0;
	int i;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (ccs_policy_dir)
				goto usage;
			ccs_policy_dir = ptr;
		} else if (!strcmp(ptr, "-e")) {
			save_exception_policy = 1;
			write_to_stdout = true;
		} else if (!strcmp(ptr, "-d")) {
			save_domain_policy = 1;
			write_to_stdout = true;
		} else if (!strcmp(ptr, "-p")) {
			save_profile = 1;
			write_to_stdout = true;
		} else if (!strcmp(ptr, "-m")) {
			save_manager = 1;
			write_to_stdout = true;
		} else if (!strcmp(ptr, "-u")) {
			save_meminfo = 1;
			write_to_stdout = true;
		} else if (cp) {
			*cp++ = '\0';
			ccs_network_ip = inet_addr(ptr);
			ccs_network_port = htons(atoi(cp));
			if (ccs_network_mode)
				goto usage;
			ccs_network_mode = true;
			if (!ccs_check_remote_host())
				return 1;
		} else
			goto usage;
	}
	if (!ccs_network_mode && access(CCS_PROC_POLICY_DIR, F_OK)) {
		fprintf(stderr,
			"You can't run this program for this kernel.\n");
		return 0;
	}
	if (write_to_stdout) {
		if (save_exception_policy + save_domain_policy +
		    save_profile + save_manager + save_meminfo != 1)
			goto usage;
		if (save_profile)
			ccs_cat_file(CCS_PROC_POLICY_PROFILE);
		else if (save_manager)
			ccs_cat_file(CCS_PROC_POLICY_MANAGER);
		else if (save_exception_policy)
			ccs_cat_file(CCS_PROC_POLICY_EXCEPTION_POLICY);
		else if (save_domain_policy)
			ccs_cat_file(CCS_PROC_POLICY_DOMAIN_POLICY);
		else if (save_meminfo)
			ccs_cat_file(CCS_PROC_POLICY_MEMINFO);
		return 0;
	}
	if (!ccs_policy_dir) {
		if (ccs_network_mode) {
			fprintf(stderr, "You must specify policy directory "
				"when using network mode.\n");
			return 1;
		}
		ccs_policy_dir = "/etc/ccs/";
	}
	if (chdir(ccs_policy_dir) || chdir("policy/")) {
		fprintf(stderr, "Directory %s/policy/ doesn't exist.\n",
			ccs_policy_dir);
		return 1;
	}
	save_policy();
	return 0;
usage:
	printf("%s [{-e|-d|-p|-m|-u|policy_dir}] [remote_ip:remote_port]\n"
	       "-e : Print /proc/ccs/exception_policy to stdout.\n"
	       "-d : Print /proc/ccs/domain_policy to stdout.\n"
	       "-p : Print /proc/ccs/profile to stdout.\n"
	       "-m : Print /proc/ccs/manager to stdout.\n"
	       "-u : Print /proc/ccs/meminfo to stdout.\n"
	       "policy_dir : Save to policy_dir rather than /etc/ccs/ .\n"
	       "remote_ip:remote_port : Read from ccs-editpolicy-agent "
	       "listening at remote_ip:remote_port rather than /proc/ccs/ "
	       "directory.\n", argv[0]);
	return 0;
}
