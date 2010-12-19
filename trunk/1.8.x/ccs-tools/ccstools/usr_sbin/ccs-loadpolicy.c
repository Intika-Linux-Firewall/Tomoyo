/*
 * ccs-loadpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0+   2010/12/19
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

static void ccs_close_write(FILE *fp)
{
	if (ccs_network_mode) {
		fputc(0, fp);
		fflush(fp);
		fgetc(fp);
	}
	fclose(fp);
}

static void ccs_move_file_to_proc(const char *src, const char *dest)
{
	FILE *file_fp = stdin;
	FILE *proc_fp = ccs_open_write(dest);
	if (!proc_fp) {
		fprintf(stderr, "Can't open %s\n", dest);
		return;
	}
	if (src) {
		file_fp = fopen(src, "r");
		if (!file_fp) {
			fprintf(stderr, "Can't open %s\n", src);
			fclose(proc_fp);
			return;
		}
	}
	ccs_get();
	while (true) {
		char *line = ccs_freadline(file_fp);
		if (!line)
			break;
		if (line[0])
			fprintf(proc_fp, "%s\n", line);
	}
	ccs_put();
	ccs_close_write(proc_fp);
	if (file_fp != stdin)
		fclose(file_fp);
}

static void ccs_delete_proc_policy(const char *name)
{
	FILE *fp_in;
	FILE *fp_out;
	if (ccs_network_mode) {
		fp_in = ccs_open_read(name);
		fp_out = ccs_open_write(name);
	} else {
		fp_in = fopen(name, "r");
		fp_out = fopen(name, "w");
	}
	if (!fp_in || !fp_out) {
		fprintf(stderr, "Can't open %s\n", name);
		if (fp_in)
			fclose(fp_in);
		if (fp_out)
			fclose(fp_out);
		return;
	}
	ccs_get();
	while (true) {
		char *line = ccs_freadline(fp_in);
		if (!line)
			break;
		fprintf(fp_out, "delete %s\n", line);
	}
	ccs_put();
	fclose(fp_in);
	ccs_close_write(fp_out);
}

static void ccs_update_domain_policy(struct ccs_domain_policy *proc_policy,
				     struct ccs_domain_policy *file_policy,
				     const char *src, const char *dest)
{
	int file_index;
	int proc_index;
	FILE *proc_fp;
	_Bool nm = ccs_network_mode;
	/* Load disk policy to file_policy->list. */
	ccs_network_mode = false;
	ccs_read_domain_policy(file_policy, src);
	ccs_network_mode = nm;
	/* Load proc policy to proc_policy->list. */
	ccs_read_domain_policy(proc_policy, dest);
	proc_fp = ccs_open_write(dest);
	if (!proc_fp) {
		fprintf(stderr, "Can't open %s\n", dest);
		return;
	}
	for (file_index = 0; file_index < file_policy->list_len; file_index++) {
		int i;
		int j;
		const struct ccs_path_info *domainname
			= file_policy->list[file_index].domainname;
		const struct ccs_path_info **file_string_ptr
			= file_policy->list[file_index].string_ptr;
		const int file_string_count
			= file_policy->list[file_index].string_count;
		const struct ccs_path_info **proc_string_ptr;
		int proc_string_count;
		proc_index = ccs_find_domain_by_ptr(proc_policy, domainname);
		fprintf(proc_fp, "%s\n", domainname->name);
		if (proc_index == EOF)
			goto not_found;

		/* Proc policy for this domain found. */
		proc_string_ptr = proc_policy->list[proc_index].string_ptr;
		proc_string_count = proc_policy->list[proc_index].string_count;
		for (j = 0; j < proc_string_count; j++) {
			for (i = 0; i < file_string_count; i++) {
				if (file_string_ptr[i] == proc_string_ptr[j])
					break;
			}
			/* Delete this entry from proc policy if not found
			   in disk policy. */
			if (i == file_string_count)
				fprintf(proc_fp, "delete %s\n",
					proc_string_ptr[j]->name);
		}
		ccs_delete_domain(proc_policy, proc_index);
not_found:
		/* Append entries defined in disk policy. */
		for (i = 0; i < file_string_count; i++)
			fprintf(proc_fp, "%s\n", file_string_ptr[i]->name);
		if (file_policy->list[file_index].profile_assigned)
			fprintf(proc_fp, "use_profile %u\n",
				file_policy->list[file_index].profile);
	}
	/* Delete all domains that are not defined in disk policy. */
	for (proc_index = 0; proc_index < proc_policy->list_len; proc_index++) {
		fprintf(proc_fp, "delete %s\n",
			proc_policy->list[proc_index].domainname->name);
	}
	ccs_close_write(proc_fp);
}

int main(int argc, char *argv[])
{
	struct ccs_domain_policy proc_policy = { NULL, 0, NULL };
	struct ccs_domain_policy file_policy = { NULL, 0, NULL };
	_Bool read_from_stdin = false;
	int load_profile = 0;
	int load_manager = 0;
	int load_exception_policy = 0;
	int load_domain_policy = 0;
	int load_meminfo = 0;
	_Bool refresh_policy = false;
	int i;
	const char *ccs_policy_dir = NULL;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (ccs_policy_dir)
				goto usage;
			ccs_policy_dir = ptr;
			argv[i] = "";
		} else if (cp) {
			*cp++ = '\0';
			ccs_network_ip = inet_addr(ptr);
			ccs_network_port = htons(atoi(cp));
			if (ccs_network_mode)
				goto usage;
			ccs_network_mode = true;
			if (!ccs_check_remote_host())
				return 1;
			argv[i] = "";
		}
	}
	if (!ccs_network_mode && !ccs_policy_dir)
		ccs_policy_dir = CCS_DISK_POLICY_DIR;
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
			load_exception_policy = 1;
		if (d || a)
			load_domain_policy = 1;
		if (p)
			load_profile = 1;
		if (m)
			load_manager = 1;
		if (u)
			load_meminfo = 1;
		if (f)
			refresh_policy = true;
		if (i)
			read_from_stdin = true;
		if (strcspn(ptr, "edafpmu-"))
			goto usage;
	}
	if (!ccs_network_mode && access(CCS_PROC_POLICY_DIR, F_OK)) {
		fprintf(stderr,
			"You can't run this program for this kernel.\n");
		return 0;
	}
	if (!read_from_stdin && !ccs_policy_dir)
		goto usage;
	if (read_from_stdin &&
	    load_exception_policy + load_domain_policy +
	    load_profile + load_manager + load_meminfo != 1)
		goto usage;
	if (load_exception_policy +
	    load_domain_policy + load_profile + load_manager +
	    load_meminfo == 0)
		goto usage;
	if (!read_from_stdin && chdir(ccs_policy_dir)) {
		printf("Directory %s doesn't exist.\n", ccs_policy_dir);
		return 1;
	}

	if (load_profile) {
		if (read_from_stdin)
			ccs_move_file_to_proc(NULL, CCS_PROC_POLICY_PROFILE);
		else
			ccs_move_file_to_proc(CCS_DISK_POLICY_PROFILE,
					      CCS_PROC_POLICY_PROFILE);
	}
	
	if (load_manager) {
		if (read_from_stdin)
			ccs_move_file_to_proc(NULL, CCS_PROC_POLICY_MANAGER);
		else
			ccs_move_file_to_proc(CCS_DISK_POLICY_MANAGER,
					      CCS_PROC_POLICY_MANAGER);
	}
	
	if (load_meminfo) {
		if (read_from_stdin)
			ccs_move_file_to_proc(NULL, CCS_PROC_POLICY_MEMINFO);
		else
			ccs_move_file_to_proc(CCS_DISK_POLICY_MEMINFO,
					      CCS_PROC_POLICY_MEMINFO);
	}

	if (load_exception_policy) {
		if (refresh_policy)
			ccs_delete_proc_policy(CCS_PROC_POLICY_EXCEPTION_POLICY);
		if (read_from_stdin)
			ccs_move_file_to_proc(NULL, CCS_PROC_POLICY_EXCEPTION_POLICY);
		else
			ccs_move_file_to_proc(CCS_DISK_POLICY_EXCEPTION_POLICY,
					      CCS_PROC_POLICY_EXCEPTION_POLICY);
	}
	
	if (load_domain_policy) {
		if (refresh_policy) {
			if (read_from_stdin)
				ccs_update_domain_policy(&proc_policy, &file_policy,
							 NULL,
							 CCS_PROC_POLICY_DOMAIN_POLICY);
			else
				ccs_update_domain_policy(&proc_policy, &file_policy,
							 CCS_DISK_POLICY_DOMAIN_POLICY,
							 CCS_PROC_POLICY_DOMAIN_POLICY);
			ccs_clear_domain_policy(&proc_policy);
			ccs_clear_domain_policy(&file_policy);
		} else {
			if (read_from_stdin)
				ccs_move_file_to_proc(NULL,
						      CCS_PROC_POLICY_DOMAIN_POLICY);
			else
				ccs_move_file_to_proc(CCS_DISK_POLICY_DOMAIN_POLICY,
						      CCS_PROC_POLICY_DOMAIN_POLICY);
		}
	}
	return 0;
usage:
	printf("%s [e][d][a][f][p][m][u] [{-|policy_dir} "
	       "[remote_ip:remote_port]]\n"
	       "e : Load exception_policy.\n"
	       "d : Load domain_policy.\n"
	       "a : Load exception_policy,domain_policy.\n"
	       "p : Load profile.\n"
	       "m : Load manager.\n"
	       "u : Load meminfo.\n"
	       "- : Read policy from stdin. "
	       "(Only one of 'edpmu' is possible when using '-'.)\n"
	       "f : Delete on-memory policy before loading on-disk policy. "
	       "(Valid for 'ed'.)\n\n",
	       argv[0]);
	return 0;
}
