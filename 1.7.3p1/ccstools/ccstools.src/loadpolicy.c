/*
 * loadpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include "ccstools.h"

static void close_write(FILE *fp)
{
	if (network_mode) {
		fputc(0, fp);
		fflush(fp);
		fgetc(fp);
	}
	fclose(fp);
}

static int write_domain_policy(struct domain_policy *dp, const int fd)
{
	int i;
	int j;
	for (i = 0; i < dp->list_len; i++) {
		const struct path_info **string_ptr
			= dp->list[i].string_ptr;
		const int string_count = dp->list[i].string_count;
		write(fd, dp->list[i].domainname->name,
		      dp->list[i].domainname->total_len);
		write(fd, "\n", 1);
		if (dp->list[i].profile_assigned) {
			char buf[128];
			memset(buf, 0, sizeof(buf));
			snprintf(buf, sizeof(buf) - 1, KEYWORD_USE_PROFILE
				 "%u\n\n", dp->list[i].profile);
			write(fd, buf, strlen(buf));
		} else
			write(fd, "\n", 1);
		for (j = 0; j < string_count; j++) {
			write(fd, string_ptr[j]->name,
			      string_ptr[j]->total_len);
			write(fd, "\n", 1);
		}
		write(fd, "\n", 1);
	}
	return 0;
}

/***** sortpolicy start *****/

int sortpolicy_main(int argc, char *argv[])
{
	struct domain_policy dp = { NULL, 0, NULL };
	read_domain_policy(&dp, NULL);
	write_domain_policy(&dp, 1);
	clear_domain_policy(&dp);
	return 0;
}

/***** sortpolicy end *****/

/***** diffpolicy start *****/

int diffpolicy_main(int argc, char *argv[])
{
	struct domain_policy old_policy = { NULL, 0, NULL };
	struct domain_policy new_policy = { NULL, 0, NULL };
	const struct path_info **old_string_ptr;
	const struct path_info **new_string_ptr;
	int old_string_count;
	int new_string_count;
	int old_index;
	int new_index;
	const struct path_info *domainname;
	int i;
	int j;
	const char *old = NULL;
	const char *new = NULL;
	if (argc != 3)
		goto usage;
	old = argv[1];
	new = argv[2];
	if (!strcmp(new, "-"))
		new = NULL;
	if (!strcmp(old, "-"))
		old = NULL;
	if (!new && !old) {
usage:
		printf("%s old_domain_policy new_domain_policy\n"
		       "- : Read policy from stdin.\n", argv[0]);
		return 0;
	}
	read_domain_policy(&old_policy, old);
	read_domain_policy(&new_policy, new);
	for (old_index = 0; old_index < old_policy.list_len; old_index++) {
		domainname = old_policy.list[old_index].domainname;
		new_index = find_domain_by_ptr(&new_policy, domainname);
		if (new_index >= 0)
			continue;
		/* This domain was deleted. */
		printf("delete %s\n\n", domainname->name);
	}
	for (new_index = 0; new_index < new_policy.list_len; new_index++) {
		domainname = new_policy.list[new_index].domainname;
		old_index = find_domain_by_ptr(&old_policy, domainname);
		if (old_index >= 0)
			continue;
		/* This domain was added. */
		printf("%s\n\n", domainname->name);
		if (new_policy.list[new_index].profile_assigned)
			printf(KEYWORD_USE_PROFILE "%u\n",
			       new_policy.list[new_index].profile);
		new_string_ptr = new_policy.list[new_index].string_ptr;
		new_string_count = new_policy.list[new_index].string_count;
		for (i = 0; i < new_string_count; i++)
			printf("%s\n", new_string_ptr[i]->name);
		printf("\n");
	}
	for (old_index = 0; old_index < old_policy.list_len; old_index++) {
		_Bool first = true;
		domainname = old_policy.list[old_index].domainname;
		new_index = find_domain_by_ptr(&new_policy, domainname);
		if (new_index == EOF)
			continue;
		/* This domain exists in both old policy and new policy. */
		old_string_ptr = old_policy.list[old_index].string_ptr;
		old_string_count = old_policy.list[old_index].string_count;
		new_string_ptr = new_policy.list[new_index].string_ptr;
		new_string_count = new_policy.list[new_index].string_count;
		for (i = 0; i < old_string_count; i++) {
			for (j = 0; j < new_string_count; j++) {
				if (old_string_ptr[i] != new_string_ptr[j])
					continue;
				old_string_ptr[i] = NULL;
				new_string_ptr[j] = NULL;
			}
		}
		for (i = 0; i < new_string_count; i++) {
			if (!new_string_ptr[i])
				continue;
			if (first)
				printf("%s\n\n", domainname->name);
			first = false;
			printf("%s\n", new_string_ptr[i]->name);
		}
		for (i = 0; i < old_string_count; i++) {
			if (!old_string_ptr[i])
				continue;
			if (first)
				printf("%s\n\n", domainname->name);
			first = false;
			printf("delete %s\n", old_string_ptr[i]->name);
		}
		if (old_policy.list[old_index].profile !=
		    new_policy.list[new_index].profile) {
			if (first)
				printf("%s\n\n", domainname->name);
			first = false;
			if (new_policy.list[new_index].profile_assigned)
				printf(KEYWORD_USE_PROFILE "%u\n",
				       new_policy.list[new_index].profile);
		}
		if (!first)
			printf("\n");
	}
	return 0;
}

/***** diffpolicy end *****/

/***** selectpolicy start *****/

int selectpolicy_main(int argc, char *argv[])
{
	_Bool recursive = false;
	_Bool matched = false;
	int start = 1;
	int i;
	if (argc > 1 && !strcmp(argv[1], "-r")) {
		recursive = true;
		start++;
	}
	if (argc <= start) {
		fprintf(stderr, "%s [-r] domainname [domainname ...]"
			" < domain_policy\n", argv[0]);
		return 0;
	}
	for (i = start; i < argc; i++)
		normalize_line(argv[i]);
	get();
	while (true) {
		char *line = freadline(stdin);
		if (!line)
			break;
		if (is_domain_def(line)) {
			matched = false;
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
				matched = true;
			}
		}
		if (matched)
			puts(line);
	}
	put();
	return 0;
}

/***** selectpolicy end *****/

/***** savepolicy start *****/

static _Bool cat_file(const char *path)
{
	FILE *fp = open_read(path);
	if (!fp) {
		fprintf(stderr, "Can't open %s\n", path);
		return false;
	}
	while (true) {
		int c = fgetc(fp);
		if (network_mode && !c)
			break;
		if (c == EOF)
			break;
		putchar(c);
	}
	fclose(fp);
	return true;
}

int savepolicy_main(int argc, char *argv[])
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
	policy_dir = NULL;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (policy_dir)
				goto usage;
			policy_dir = ptr;
			argv[i] = "";
		} else if (cp) {
			*cp++ = '\0';
			network_ip = inet_addr(ptr);
			network_port = htons(atoi(cp));
			if (network_mode)
				goto usage;
			network_mode = true;
			if (!check_remote_host())
				return 1;
			argv[i] = "";
		}
	}
	if (!network_mode && access(proc_policy_dir, F_OK)) {
		fprintf(stderr,
			"You can't run this program for this kernel.\n");
		return 0;
	}
	if (!network_mode && !policy_dir)
		policy_dir = disk_policy_dir;
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
	if (!write_to_stdout && !policy_dir)
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
	if (!write_to_stdout && chdir(policy_dir)) {
		printf("Directory %s doesn't exist.\n", policy_dir);
		return 1;
	}

	if (!network_mode) {
		/* Exclude nonexistent policy. */
		if (access(proc_policy_exception_policy, R_OK))
			save_exception_policy = 0;
		if (access(proc_policy_domain_policy, R_OK))
			save_domain_policy = 0;
		if (access(proc_policy_profile, R_OK))
			save_profile = 0;
		if (access(proc_policy_manager, R_OK))
			save_manager = 0;
		if (access(proc_policy_meminfo, R_OK))
			save_meminfo = 0;
	}

	if (write_to_stdout) {
		if (save_profile)
			cat_file(proc_policy_profile);
		else if (save_manager)
			cat_file(proc_policy_manager);
		else if (save_exception_policy)
			cat_file(proc_policy_exception_policy);
		else if (save_domain_policy)
			cat_file(proc_policy_domain_policy);
		else if (save_meminfo)
			cat_file(proc_policy_meminfo);
		goto done;
	}
	if (save_profile)
		move_proc_to_file(proc_policy_profile, DISK_POLICY_PROFILE);
	if (save_manager)
		move_proc_to_file(proc_policy_manager, DISK_POLICY_MANAGER);

	if (save_exception_policy) {
		filename = make_filename("exception_policy", now);
		if (move_proc_to_file(proc_policy_exception_policy, filename)
		    && !write_to_stdout) {
			if (!force_save &&
			    is_identical_file("exception_policy.conf",
					      filename)) {
				unlink(filename);
			} else {
				unlink("exception_policy.conf");
				symlink(filename, "exception_policy.conf");
			}
		}
	}

	if (save_domain_policy) {
		filename = make_filename("domain_policy", now);
		if (move_proc_to_file(proc_policy_domain_policy, filename)
		    && !write_to_stdout) {
			if (!force_save &&
			    is_identical_file("domain_policy.conf", filename)) {
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

/***** savepolicy end *****/

/***** loadpolicy start *****/

static void move_file_to_proc(const char *src, const char *dest)
{
	FILE *file_fp = stdin;
	FILE *proc_fp = open_write(dest);
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
	get();
	while (true) {
		char *line = freadline(file_fp);
		if (!line)
			break;
		if (line[0])
			fprintf(proc_fp, "%s\n", line);
	}
	put();
	close_write(proc_fp);
	if (file_fp != stdin)
		fclose(file_fp);
}

static void delete_proc_policy(const char *name)
{
	FILE *fp_in;
	FILE *fp_out;
	if (network_mode) {
		fp_in = open_read(name);
		fp_out = open_write(name);
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
	get();
	while (true) {
		char *line = freadline(fp_in);
		if (!line)
			break;
		fprintf(fp_out, "delete %s\n", line);
	}
	put();
	fclose(fp_in);
	close_write(fp_out);
}

static void update_domain_policy(struct domain_policy *proc_policy,
				 struct domain_policy *file_policy,
				 const char *src, const char *dest)
{
	int file_index;
	int proc_index;
	FILE *proc_fp;
	_Bool nm = network_mode;
	/* Load disk policy to file_policy->list. */
	network_mode = false;
	read_domain_policy(file_policy, src);
	network_mode = nm;
	/* Load proc policy to proc_policy->list. */
	read_domain_policy(proc_policy, dest);
	proc_fp = open_write(dest);
	if (!proc_fp) {
		fprintf(stderr, "Can't open %s\n", dest);
		return;
	}
	for (file_index = 0; file_index < file_policy->list_len; file_index++) {
		int i;
		int j;
		const struct path_info *domainname
			= file_policy->list[file_index].domainname;
		const struct path_info **file_string_ptr
			= file_policy->list[file_index].string_ptr;
		const int file_string_count
			= file_policy->list[file_index].string_count;
		const struct path_info **proc_string_ptr;
		int proc_string_count;
		proc_index = find_domain_by_ptr(proc_policy, domainname);
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
		delete_domain(proc_policy, proc_index);
not_found:
		/* Append entries defined in disk policy. */
		for (i = 0; i < file_string_count; i++)
			fprintf(proc_fp, "%s\n", file_string_ptr[i]->name);
		if (file_policy->list[file_index].profile_assigned)
			fprintf(proc_fp, KEYWORD_USE_PROFILE "%u\n",
				file_policy->list[file_index].profile);
	}
	/* Delete all domains that are not defined in disk policy. */
	for (proc_index = 0; proc_index < proc_policy->list_len; proc_index++) {
		fprintf(proc_fp, "delete %s\n",
			proc_policy->list[proc_index].domainname->name);
	}
	close_write(proc_fp);
}

int loadpolicy_main(int argc, char *argv[])
{
	struct domain_policy proc_policy = { NULL, 0, NULL };
	struct domain_policy file_policy = { NULL, 0, NULL };
	_Bool read_from_stdin = false;
	int load_profile = 0;
	int load_manager = 0;
	int load_exception_policy = 0;
	int load_domain_policy = 0;
	int load_meminfo = 0;
	_Bool refresh_policy = false;
	int i;
	policy_dir = NULL;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (policy_dir)
				goto usage;
			policy_dir = ptr;
			argv[i] = "";
		} else if (cp) {
			*cp++ = '\0';
			network_ip = inet_addr(ptr);
			network_port = htons(atoi(cp));
			if (network_mode)
				goto usage;
			network_mode = true;
			if (!check_remote_host())
				return 1;
			argv[i] = "";
		}
	}
	if (!network_mode && !policy_dir)
		policy_dir = disk_policy_dir;
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
	if (!read_from_stdin && !policy_dir)
		goto usage;
	if (read_from_stdin &&
	    load_exception_policy + load_domain_policy +
	    load_profile + load_manager + load_meminfo != 1)
		goto usage;
	if (load_exception_policy +
	    load_domain_policy + load_profile + load_manager +
	    load_meminfo == 0)
		goto usage;
	if (!read_from_stdin && chdir(policy_dir)) {
		printf("Directory %s doesn't exist.\n", policy_dir);
		return 1;
	}

	if (load_profile) {
		if (read_from_stdin)
			move_file_to_proc(NULL, proc_policy_profile);
		else
			move_file_to_proc(DISK_POLICY_PROFILE,
					  proc_policy_profile);
	}

	if (load_manager) {
		if (read_from_stdin)
			move_file_to_proc(NULL, proc_policy_manager);
		else
			move_file_to_proc(DISK_POLICY_MANAGER,
					  proc_policy_manager);
	}

	if (load_meminfo) {
		if (read_from_stdin)
			move_file_to_proc(NULL, proc_policy_meminfo);
		else
			move_file_to_proc(DISK_POLICY_MEMINFO,
					  proc_policy_meminfo);
	}

	if (load_exception_policy) {
		if (refresh_policy)
			delete_proc_policy(proc_policy_exception_policy);
		if (read_from_stdin)
			move_file_to_proc(NULL, proc_policy_exception_policy);
		else
			move_file_to_proc(DISK_POLICY_EXCEPTION_POLICY,
					  proc_policy_exception_policy);
	}

	if (load_domain_policy) {
		if (refresh_policy) {
			if (read_from_stdin)
				update_domain_policy(&proc_policy, &file_policy,
						     NULL,
						     proc_policy_domain_policy);
			else
				update_domain_policy(&proc_policy, &file_policy,
						     DISK_POLICY_DOMAIN_POLICY,
						     proc_policy_domain_policy);
			clear_domain_policy(&proc_policy);
			clear_domain_policy(&file_policy);
		} else {
			if (read_from_stdin)
				move_file_to_proc(NULL,
						  proc_policy_domain_policy);
			else
				move_file_to_proc(DISK_POLICY_DOMAIN_POLICY,
						  proc_policy_domain_policy);
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

/***** loadpolicy end *****/
