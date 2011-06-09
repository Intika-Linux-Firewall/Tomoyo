/*
 * tomoyo-savepolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0-pre   2011/06/09
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

static const char *tomoyo_policy_dir = NULL;

static _Bool tomoyo_cat_file(const char *path)
{
	FILE *fp = tomoyo_open_read(path);
	_Bool result = true;
	if (!fp) {
		fprintf(stderr, "Can't open %s\n", path);
		return false;
	}
	while (true) {
		int c = fgetc(fp);
		if (tomoyo_network_mode && !c)
			break;
		if (c == EOF)
			break;
		if (putchar(c) == EOF)
			result = false;
	}
	fclose(fp);
	return result;
}

static _Bool tomoyo_save_policy(void)
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
				tomoyo_policy_dir, stamp);
			return false;
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
	    !tomoyo_move_proc_to_file(TOMOYO_PROC_POLICY_PROFILE, "profile.conf") ||
	    !tomoyo_move_proc_to_file(TOMOYO_PROC_POLICY_MANAGER, "manager.conf") ||
	    !tomoyo_move_proc_to_file(TOMOYO_PROC_POLICY_EXCEPTION_POLICY,
				   "exception_policy.conf") ||
	    !tomoyo_move_proc_to_file(TOMOYO_PROC_POLICY_DOMAIN_POLICY,
				   "domain_policy.conf") ||
	    chdir("..") ||
	    (rename("current", "previous") && errno != ENOENT) ||
	    symlink(stamp, "current")) {
		fprintf(stderr, "Failed to save policy.\n");
		return false;
	}
	return true;
}

int main(int argc, char *argv[])
{
	char target = 0;
	int i;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (tomoyo_policy_dir || target) {
				fprintf(stderr, "You cannot specify multiple "
					"%s at the same time.\n\n",
					"policy directories");
				goto usage;
			}
			tomoyo_policy_dir = ptr;
		} else if (cp) {
			*cp++ = '\0';
			tomoyo_network_ip = inet_addr(ptr);
			tomoyo_network_port = htons(atoi(cp));
			if (tomoyo_network_mode) {
				fprintf(stderr, "You cannot specify multiple "
					"%s at the same time.\n\n",
					"remote agents");
				goto usage;
			}
			tomoyo_network_mode = true;
		} else if (*ptr++ == '-' && !target) {
			target = *ptr++;
			if (target != 'e' && target != 'd' && target != 'p' &&
			    target != 'm' && target != 's')
				goto usage;
			if (*ptr || tomoyo_policy_dir) {
				fprintf(stderr, "You cannot specify multiple "
					"%s at the same time.\n\n",
					"policies");
				goto usage;
			}
		} else
			goto usage;
	}
	if (tomoyo_network_mode) {
		if (!tomoyo_check_remote_host())
			return 1;
	} else if (tomoyo_mount_securityfs(),
		   access(TOMOYO_PROC_POLICY_DIR, F_OK)) {
		fprintf(stderr,
			"You can't run this program for this kernel.\n");
		return 1;
	}
	if (target) {
		const char *file;
		switch (target) {
		case 'p':
			file = TOMOYO_PROC_POLICY_PROFILE;
			break;
		case 'm':
			file = TOMOYO_PROC_POLICY_MANAGER;
			break;
		case 'e':
			file = TOMOYO_PROC_POLICY_EXCEPTION_POLICY;
			break;
		case 'd':
			file = TOMOYO_PROC_POLICY_DOMAIN_POLICY;
			break;
		default:
			file = TOMOYO_PROC_POLICY_STAT;
			break;
		}
		return !tomoyo_cat_file(file);
	}
	if (!tomoyo_policy_dir) {
		if (tomoyo_network_mode && !target) {
			fprintf(stderr, "You need to specify %s.\n\n",
				"policy directory");
			goto usage;
		}
		tomoyo_policy_dir = "/etc/tomoyo/";
	}
	if (chdir(tomoyo_policy_dir) || chdir("policy/")) {
		fprintf(stderr, "Directory %s/policy/ doesn't exist.\n",
			tomoyo_policy_dir);
		return 1;
	}
	return !tomoyo_save_policy();
usage:
	printf("%s [policy_dir [remote_ip:remote_port]]\n"
	       "%s [{-e|-d|-p|-m|-s} [remote_ip:remote_port]]\n\n"
	       "policy_dir : Use policy_dir rather than /etc/tomoyo/ directory.\n"
	       "remote_ip:remote_port : Read from tomoyo-editpolicy-agent "
	       "listening at remote_ip:remote_port rather than /sys/kernel/security/tomoyo/ "
	       "directory.\n"
	       "-e : Print /sys/kernel/security/tomoyo/exception_policy to stdout.\n"
	       "-d : Print /sys/kernel/security/tomoyo/domain_policy to stdout.\n"
	       "-p : Print /sys/kernel/security/tomoyo/profile to stdout.\n"
	       "-m : Print /sys/kernel/security/tomoyo/manager to stdout.\n"
	       "-s : Print /sys/kernel/security/tomoyo/stat to stdout.\n",
	       argv[0], argv[0]);
	return 1;
}
