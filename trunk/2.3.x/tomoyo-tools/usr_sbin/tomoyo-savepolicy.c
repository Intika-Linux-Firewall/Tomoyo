/*
 * tomoyo-savepolicy.c
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

static _Bool tomoyo_cat_file(const char *path)
{
	FILE *fp = tomoyo_open_read(path);
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
		putchar(c);
	}
	fclose(fp);
	return true;
}

int main(int argc, char *argv[])
{
	char *filename;
	_Bool write_to_stdout = false;
	int save_profile = 0;
	int save_manager = 0;
	int save_exception_policy = 0;
	int save_domain_policy = 0;
	int save_meminfo = 0;
	_Bool force_save = false;
	time_t now = time(NULL);
	int i;
	const char *tomoyo_policy_dir = NULL;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (tomoyo_policy_dir)
				goto usage;
			tomoyo_policy_dir = ptr;
			argv[i] = "";
		} else if (cp) {
			*cp++ = '\0';
			tomoyo_network_ip = inet_addr(ptr);
			tomoyo_network_port = htons(atoi(cp));
			if (tomoyo_network_mode)
				goto usage;
			tomoyo_network_mode = true;
			if (!tomoyo_check_remote_host())
				return 1;
			argv[i] = "";
		}
	}
	if (!tomoyo_network_mode)
		tomoyo_mount_securityfs();
	if (!tomoyo_network_mode && access(CCS_PROC_POLICY_DIR, F_OK)) {
		fprintf(stderr,
			"You can't run this program for this kernel.\n");
		return 0;
	}
	if (!tomoyo_network_mode && !tomoyo_policy_dir)
		tomoyo_policy_dir = CCS_DISK_POLICY_DIR;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *e = strchr(ptr, 'e');
		char *d = strchr(ptr, 'd');
		char *a = strchr(ptr, 'a');
		char *f = strchr(ptr, 'f');
		char *p = strchr(ptr, 'p');
		char *m = strchr(ptr, 'm');
		char *u = strchr(ptr, 'u');
		char *i = strchr(ptr, '-');
		if (e || a)
			save_exception_policy = 1;
		if (d || a)
			save_domain_policy = 1;
		if (p)
			save_profile = 1;
		if (m)
			save_manager = 1;
		if (u) {
			save_meminfo = 1;
			write_to_stdout = true;
		}
		if (f)
			force_save = true;
		if (i)
			write_to_stdout = true;
		if (strcspn(ptr, "edafpmu-"))
			goto usage;
	}
	if (!write_to_stdout && !tomoyo_policy_dir)
		goto usage;
	if (write_to_stdout &&
	    save_exception_policy + save_domain_policy +
	    save_profile + save_manager + save_meminfo != 1)
		goto usage;
	if (!write_to_stdout && !force_save &&
	    save_exception_policy + save_domain_policy + save_profile +
	    save_manager + save_meminfo == 0) {
		force_save = true;
		save_exception_policy = 1;
		save_domain_policy = 1;
	}
	if (!write_to_stdout && chdir(tomoyo_policy_dir)) {
		printf("Directory %s doesn't exist.\n", tomoyo_policy_dir);
		return 1;
	}

	if (!tomoyo_network_mode) {
		/* Exclude nonexistent policy. */
		if (access(CCS_PROC_POLICY_EXCEPTION_POLICY, R_OK))
			save_exception_policy = 0;
		if (access(CCS_PROC_POLICY_DOMAIN_POLICY, R_OK))
			save_domain_policy = 0;
		if (access(CCS_PROC_POLICY_PROFILE, R_OK))
			save_profile = 0;
		if (access(CCS_PROC_POLICY_MANAGER, R_OK))
			save_manager = 0;
		if (access(CCS_PROC_POLICY_MEMINFO, R_OK))
			save_meminfo = 0;
	}

	if (write_to_stdout) {
		if (save_profile)
			tomoyo_cat_file(CCS_PROC_POLICY_PROFILE);
		else if (save_manager)
			tomoyo_cat_file(CCS_PROC_POLICY_MANAGER);
		else if (save_exception_policy)
			tomoyo_cat_file(CCS_PROC_POLICY_EXCEPTION_POLICY);
		else if (save_domain_policy)
			tomoyo_cat_file(CCS_PROC_POLICY_DOMAIN_POLICY);
		else if (save_meminfo)
			tomoyo_cat_file(CCS_PROC_POLICY_MEMINFO);
		goto done;
	}
	if (save_profile)
		tomoyo_move_proc_to_file(CCS_PROC_POLICY_PROFILE, CCS_DISK_POLICY_PROFILE);
	if (save_manager)
		tomoyo_move_proc_to_file(CCS_PROC_POLICY_MANAGER, CCS_DISK_POLICY_MANAGER);

	if (save_exception_policy) {
		filename = tomoyo_make_filename("exception_policy", now);
		if (tomoyo_move_proc_to_file(CCS_PROC_POLICY_EXCEPTION_POLICY, filename)
		    && !write_to_stdout) {
			if (!force_save &&
			    tomoyo_identical_file("exception_policy.conf",
					      filename)) {
				unlink(filename);
			} else {
				unlink("exception_policy.conf");
				symlink(filename, "exception_policy.conf");
			}
		}
	}

	if (save_domain_policy) {
		filename = tomoyo_make_filename("domain_policy", now);
		if (tomoyo_move_proc_to_file(CCS_PROC_POLICY_DOMAIN_POLICY, filename)
		    && !write_to_stdout) {
			if (!force_save &&
			    tomoyo_identical_file("domain_policy.conf", filename)) {
				unlink(filename);
			} else {
				unlink("domain_policy.conf");
				symlink(filename, "domain_policy.conf");
			}
		}
	}
done:
	return 0;
usage:
	printf("%s [e][d][a][f][p][m][u] [{-|policy_dir} "
	       "[remote_ip:remote_port]]\n"
	       "e : Save exception_policy.\n"
	       "d : Save domain_policy.\n"
	       "a : Save exception_policy,domain_policy.\n"
	       "p : Save profile.\n"
	       "m : Save manager.\n"
	       "u : Write meminfo to stdout. Implies '-'\n"
	       "- : Write policy to stdout. "
	       "(Only one of 'edpmu' is possible when using '-'.)\n"
	       "f : Save even if on-disk policy and on-memory policy "
	       "are the same. (Valid for 'ed'.)\n\n"
	       "If no options given, this program assumes 'a' and 'f' "
	       "are given.\n", argv[0]);
	return 0;
}
