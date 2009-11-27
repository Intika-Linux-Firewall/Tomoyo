/*
 * security/ccsecurity/domain.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.1   2009/11/11
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#include <linux/mount.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
#include <linux/fs_struct.h>
#endif
#include "internal.h"

/* Variables definitions.*/

/* The initial domain. */
struct ccs_domain_info ccs_kernel_domain;

/* The list for "struct ccs_domain_info". */
LIST_HEAD(ccs_domain_list);

/**
 * ccs_audit_execute_handler_log - Audit execute_handler log.
 *
 * @ee:         Pointer to "struct ccs_execve_entry".
 * @is_default: True if it is "execute_handler" log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_execute_handler_log(struct ccs_execve_entry *ee,
					 const bool is_default)
{
	struct ccs_request_info *r = &ee->r;
	const char *handler = ee->handler->name;
	r->mode = ccs_get_mode(r->profile, CCS_MAC_FILE_EXECUTE);
	return ccs_write_audit_log(true, r, "%s %s\n",
				   is_default ? CCS_KEYWORD_EXECUTE_HANDLER :
				   CCS_KEYWORD_DENIED_EXECUTE_HANDLER, handler);
}

/**
 * ccs_audit_domain_creation_log - Audit domain creation log.
 *
 * @domain:  Pointer to "struct ccs_domain_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_domain_creation_log(struct ccs_domain_info *domain)
{
	int error;
	struct ccs_request_info r;
	ccs_init_request_info(&r, domain, CCS_MAC_FILE_EXECUTE);
	error = ccs_write_audit_log(false, &r, "use_profile %u\n", r.profile);
	return error;
}

/* The list for "struct ccs_domain_initializer_entry". */
LIST_HEAD(ccs_domain_initializer_list);

/**
 * ccs_update_domain_initializer_entry - Update "struct ccs_domain_initializer_entry" list.
 *
 * @domainname: The name of domain. May be NULL.
 * @program:    The name of program.
 * @is_not:     True if it is "no_initialize_domain" entry.
 * @is_delete:  True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_domain_initializer_entry(const char *domainname,
					       const char *program,
					       const bool is_not,
					       const bool is_delete)
{
	struct ccs_domain_initializer_entry *entry = NULL;
	struct ccs_domain_initializer_entry *ptr;
	struct ccs_domain_initializer_entry e = { .is_not = is_not };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(program, 1, -1, -1))
		return -EINVAL; /* No patterns allowed. */
	if (domainname) {
		if (!ccs_is_domain_def(domainname) &&
		    ccs_is_correct_path(domainname, 1, -1, -1))
			e.is_last_name = true;
		else if (!ccs_is_correct_domain(domainname))
			return -EINVAL;
		e.domainname = ccs_get_name(domainname);
		if (!e.domainname)
			goto out;
	}
	e.program = ccs_get_name(program);
	if (!e.program)
		goto out;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_domain_initializer_list, list) {
		if (ccs_memcmp(ptr, &e, offsetof(typeof(e), is_not),
			       sizeof(e)))
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		list_add_tail_rcu(&entry->list, &ccs_domain_initializer_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.domainname);
	ccs_put_name(e.program);
	kfree(entry);
	return error;
}

/**
 * ccs_read_domain_initializer_policy - Read "struct ccs_domain_initializer_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_domain_initializer_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	list_for_each_cookie(pos, head->read_var2,
			     &ccs_domain_initializer_list) {
		const char *no;
		const char *from = "";
		const char *domain = "";
		struct ccs_domain_initializer_entry *ptr;
		ptr = list_entry(pos, struct ccs_domain_initializer_entry,
				 list);
		if (ptr->is_deleted)
			continue;
		no = ptr->is_not ? "no_" : "";
		if (ptr->domainname) {
			from = " from ";
			domain = ptr->domainname->name;
		}
		done = ccs_io_printf(head, "%s" CCS_KEYWORD_INITIALIZE_DOMAIN
				     "%s%s%s\n", no, ptr->program->name, from,
				     domain);
		if (!done)
			break;
	}
	return done;
}

/**
 * ccs_write_domain_initializer_policy - Write "struct ccs_domain_initializer_entry" list.
 *
 * @data:      String to parse.
 * @is_not:    True if it is "no_initialize_domain" entry.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_domain_initializer_policy(char *data, const bool is_not,
					const bool is_delete)
{
	char *cp = strstr(data, " from ");
	if (cp) {
		*cp = '\0';
		return ccs_update_domain_initializer_entry(cp + 6, data,
							   is_not, is_delete);
	}
	return ccs_update_domain_initializer_entry(NULL, data, is_not,
						   is_delete);
}

/**
 * ccs_is_domain_initializer - Check whether the given program causes domainname reinitialization.
 *
 * @domainname: The name of domain.
 * @program:    The name of program.
 * @last_name:  The last component of @domainname.
 *
 * Returns true if executing @program reinitializes domain transition,
 * false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_is_domain_initializer(const struct ccs_path_info *domainname,
				      const struct ccs_path_info *program,
				      const struct ccs_path_info *last_name)
{
	struct ccs_domain_initializer_entry *ptr;
	bool flag = false;
	list_for_each_entry_rcu(ptr, &ccs_domain_initializer_list, list) {
		if (ptr->is_deleted)
			continue;
		if (ptr->domainname) {
			if (!ptr->is_last_name) {
				if (ptr->domainname != domainname)
					continue;
			} else {
				if (ccs_pathcmp(ptr->domainname, last_name))
					continue;
			}
		}
		if (ccs_pathcmp(ptr->program, program))
			continue;
		if (ptr->is_not) {
			flag = false;
			break;
		}
		flag = true;
	}
	return flag;
}

/* The list for "struct ccs_domain_keeper_entry". */
LIST_HEAD(ccs_domain_keeper_list);

/**
 * ccs_update_domain_keeper_entry - Update "struct ccs_domain_keeper_entry" list.
 *
 * @domainname: The name of domain.
 * @program:    The name of program. May be NULL.
 * @is_not:     True if it is "no_keep_domain" entry.
 * @is_delete:  True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_domain_keeper_entry(const char *domainname,
					  const char *program,
					  const bool is_not,
					  const bool is_delete)
{
	struct ccs_domain_keeper_entry *entry = NULL;
	struct ccs_domain_keeper_entry *ptr;
	struct ccs_domain_keeper_entry e = { .is_not = is_not };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_domain_def(domainname) &&
	    ccs_is_correct_path(domainname, 1, -1, -1))
		e.is_last_name = true;
	else if (!ccs_is_correct_domain(domainname))
		return -EINVAL;
	if (program) {
		if (!ccs_is_correct_path(program, 1, -1, -1))
			return -EINVAL;
		e.program = ccs_get_name(program);
		if (!e.program)
			goto out;
	}
	e.domainname = ccs_get_name(domainname);
	if (!e.domainname)
		goto out;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_domain_keeper_list, list) {
		if (ccs_memcmp(ptr, &e, offsetof(typeof(e), is_not),
			       sizeof(e)))
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		list_add_tail_rcu(&entry->list, &ccs_domain_keeper_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.domainname);
	ccs_put_name(e.program);
	kfree(entry);
	return error;
}

/**
 * ccs_write_domain_keeper_policy - Write "struct ccs_domain_keeper_entry" list.
 *
 * @data:      String to parse.
 * @is_not:    True if it is "no_keep_domain" entry.
 * @is_delete: True if it is a delete request.
 *
 */
int ccs_write_domain_keeper_policy(char *data, const bool is_not,
				   const bool is_delete)
{
	char *cp = strstr(data, " from ");
	if (cp) {
		*cp = '\0';
		return ccs_update_domain_keeper_entry(cp + 6, data,
						      is_not, is_delete);
	}
	return ccs_update_domain_keeper_entry(data, NULL, is_not, is_delete);
}

/**
 * ccs_read_domain_keeper_policy - Read "struct ccs_domain_keeper_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_domain_keeper_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	list_for_each_cookie(pos, head->read_var2,
			     &ccs_domain_keeper_list) {
		struct ccs_domain_keeper_entry *ptr;
		const char *no;
		const char *from = "";
		const char *program = "";
		ptr = list_entry(pos, struct ccs_domain_keeper_entry, list);
		if (ptr->is_deleted)
			continue;
		no = ptr->is_not ? "no_" : "";
		if (ptr->program) {
			from = " from ";
			program = ptr->program->name;
		}
		done = ccs_io_printf(head, "%s" CCS_KEYWORD_KEEP_DOMAIN
				     "%s%s%s\n", no, program, from,
				     ptr->domainname->name);
		if (!done)
			break;
	}
	return done;
}

/**
 * ccs_is_domain_keeper - Check whether the given program causes domain transition suppression.
 *
 * @domainname: The name of domain.
 * @program:    The name of program.
 * @last_name:  The last component of @domainname.
 *
 * Returns true if executing @program supresses domain transition,
 * false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_is_domain_keeper(const struct ccs_path_info *domainname,
				 const struct ccs_path_info *program,
				 const struct ccs_path_info *last_name)
{
	struct ccs_domain_keeper_entry *ptr;
	bool flag = false;
	list_for_each_entry_rcu(ptr, &ccs_domain_keeper_list, list) {
		if (ptr->is_deleted)
			continue;
		if (!ptr->is_last_name) {
			if (ptr->domainname != domainname)
				continue;
		} else {
			if (ccs_pathcmp(ptr->domainname, last_name))
				continue;
		}
		if (ptr->program && ccs_pathcmp(ptr->program, program))
			continue;
		if (ptr->is_not) {
			flag = false;
			break;
		}
		flag = true;
	}
	return flag;
}

/* The list for "struct ccs_aggregator_entry". */
LIST_HEAD(ccs_aggregator_list);

/**
 * ccs_update_aggregator_entry - Update "struct ccs_aggregator_entry" list.
 *
 * @original_name:   The original program's name.
 * @aggregated_name: The aggregated program's name.
 * @is_delete:       True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_aggregator_entry(const char *original_name,
				       const char *aggregated_name,
				       const bool is_delete)
{
	struct ccs_aggregator_entry *entry = NULL;
	struct ccs_aggregator_entry *ptr;
	struct ccs_aggregator_entry e = { };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(original_name, 1, 0, -1) ||
	    !ccs_is_correct_path(aggregated_name, 1, -1, -1))
		return -EINVAL;
	e.original_name = ccs_get_name(original_name);
	e.aggregated_name = ccs_get_name(aggregated_name);
	if (!e.original_name || !e.aggregated_name)
		goto out;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_aggregator_list, list) {
		if (ccs_memcmp(ptr, &e, offsetof(typeof(e), original_name),
			       sizeof(e)))
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		list_add_tail_rcu(&entry->list, &ccs_aggregator_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.original_name);
	ccs_put_name(e.aggregated_name);
	kfree(entry);
	return error;
}

/**
 * ccs_read_aggregator_policy - Read "struct ccs_aggregator_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_aggregator_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	list_for_each_cookie(pos, head->read_var2, &ccs_aggregator_list) {
		struct ccs_aggregator_entry *ptr;
		ptr = list_entry(pos, struct ccs_aggregator_entry, list);
		if (ptr->is_deleted)
			continue;
		done = ccs_io_printf(head, CCS_KEYWORD_AGGREGATOR "%s %s\n",
				     ptr->original_name->name,
				     ptr->aggregated_name->name);
		if (!done)
			break;
	}
	return done;
}

/**
 * ccs_write_aggregator_policy - Write "struct ccs_aggregator_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_aggregator_policy(char *data, const bool is_delete)
{
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	return ccs_update_aggregator_entry(w[0], w[1], is_delete);
}

/* Domain create/delete handler. */

/**
 * ccs_delete_domain - Delete a domain.
 *
 * @domainname: The name of domain.
 *
 * Returns 0.
 */
int ccs_delete_domain(char *domainname)
{
	struct ccs_domain_info *domain;
	struct ccs_path_info name;
	name.name = domainname;
	ccs_fill_path_info(&name);
	mutex_lock(&ccs_policy_lock);
	/* Is there an active domain? */
	list_for_each_entry_rcu(domain, &ccs_domain_list, list) {
		/* Never delete ccs_kernel_domain */
		if (domain == &ccs_kernel_domain)
			continue;
		if (domain->is_deleted ||
		    ccs_pathcmp(domain->domainname, &name))
			continue;
		domain->is_deleted = true;
		break;
	}
	mutex_unlock(&ccs_policy_lock);
	return 0;
}

/**
 * ccs_find_or_assign_new_domain - Create a domain.
 *
 * @domainname: The name of domain.
 * @profile:    Profile number to assign if the domain was newly created.
 *
 * Returns pointer to "struct ccs_domain_info" on success, NULL otherwise.
 */
struct ccs_domain_info *ccs_find_or_assign_new_domain(const char *domainname,
						      const u8 profile)
{
	struct ccs_domain_info *entry;
	struct ccs_domain_info *domain;
	const struct ccs_path_info *saved_domainname;
	bool found = false;

	if (!ccs_is_correct_domain(domainname))
		return NULL;
	saved_domainname = ccs_get_name(domainname);
	if (!saved_domainname)
		return NULL;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(domain, &ccs_domain_list, list) {
		if (domain->is_deleted ||
		    ccs_pathcmp(saved_domainname, domain->domainname))
			continue;
		found = true;
		break;
	}
	if (!found && ccs_memory_ok(entry, sizeof(*entry))) {
		INIT_LIST_HEAD(&entry->acl_info_list);
		entry->domainname = saved_domainname;
		saved_domainname = NULL;
		entry->profile = profile;
		list_add_tail_rcu(&entry->list, &ccs_domain_list);
		domain = entry;
		entry = NULL;
		found = true;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(saved_domainname);
	kfree(entry);
	return found ? domain : NULL;
}

/**
 * ccs_find_next_domain - Find a domain.
 *
 * @ee: Pointer to "struct ccs_execve_entry".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_find_next_domain(struct ccs_execve_entry *ee)
{
	struct ccs_request_info *r = &ee->r;
	const struct ccs_path_info *handler = ee->handler;
	struct ccs_domain_info *domain = NULL;
	const char *old_domain_name = r->domain->domainname->name;
	struct linux_binprm *bprm = ee->bprm;
	const u32 ccs_flags = current->ccs_flags;
	struct ccs_path_info rn = { }; /* real name */
	struct ccs_path_info ln; /* last name */
	int retval;
	bool need_kfree = false;
	ln.name = ccs_last_word(old_domain_name);
	ccs_fill_path_info(&ln);
 retry:
	current->ccs_flags = ccs_flags;
	r->cond = NULL;
	if (need_kfree) {
		kfree(rn.name);
		need_kfree = false;
	}

	/* Get symlink's pathname of program. */
	retval = ccs_symlink_path(bprm->filename, &rn);
	if (retval < 0)
		goto out;
	need_kfree = true;

	if (handler) {
		if (ccs_pathcmp(&rn, handler)) {
			/* Failed to verify execute handler. */
			static u8 counter = 20;
			if (counter) {
				counter--;
				printk(KERN_WARNING "Failed to verify: %s\n",
				       handler->name);
			}
			goto out;
		}
	} else {
		struct ccs_aggregator_entry *ptr;
		/* Check 'aggregator' directive. */
		list_for_each_entry_rcu(ptr, &ccs_aggregator_list, list) {
			if (ptr->is_deleted ||
			    !ccs_path_matches_pattern(&rn, ptr->original_name))
				continue;
			kfree(rn.name);
			need_kfree = false;
			/* This is OK because it is read only. */
			rn = *ptr->aggregated_name;
			break;
		}

		/* Check execute permission. */
		retval = ccs_exec_perm(r, &rn);
		if (retval == 1)
			goto retry;
		if (retval < 0)
			goto out;
	}

	/* Calculate domain to transit to. */
	if (ccs_is_domain_initializer(r->domain->domainname, &rn, &ln)) {
		/* Transit to the child of ccs_kernel_domain domain. */
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, ROOT_NAME " " "%s",
			 rn.name);
	} else if (r->domain == &ccs_kernel_domain && !ccs_policy_loaded) {
		/*
		 * Needn't to transit from kernel domain before starting
		 * /sbin/init. But transit from kernel domain if executing
		 * initializers because they might start before /sbin/init.
		 */
		domain = r->domain;
	} else if (ccs_is_domain_keeper(r->domain->domainname, &rn, &ln)) {
		/* Keep current domain. */
		domain = r->domain;
	} else {
		/* Normal domain transition. */
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "%s %s",
			 old_domain_name, rn.name);
	}
	if (domain || strlen(ee->tmp) >= CCS_EXEC_TMPSIZE - 10)
		goto done;
	domain = ccs_find_domain(ee->tmp);
	if (domain)
		goto done;
	if (r->mode == CCS_CONFIG_ENFORCING) {
		int error = ccs_supervisor(r, "# wants to create domain\n"
					   "%s\n", ee->tmp);
		if (error == 1)
			goto retry;
		if (error < 0)
			goto done;
	}
	domain = ccs_find_or_assign_new_domain(ee->tmp, r->profile);
	if (domain)
		ccs_audit_domain_creation_log(domain);
 done:
	if (!domain) {
		printk(KERN_WARNING "ERROR: Domain '%s' not defined.\n",
		       ee->tmp);
		if (r->mode == CCS_CONFIG_ENFORCING)
			retval = -EPERM;
		else {
			retval = 0;
			r->domain->domain_transition_failed = true;
		}
	} else {
		retval = 0;
	}
 out:
	if (domain)
		r->domain = domain;
	if (need_kfree)
		kfree(rn.name);
	return retval;
}

/**
 * ccs_environ - Check permission for environment variable names.
 *
 * @ee: Pointer to "struct ccs_execve_entry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_environ(struct ccs_execve_entry *ee)
{
	struct ccs_request_info *r = &ee->r;
	struct linux_binprm *bprm = ee->bprm;
	/* env_page->data is allocated by ccs_dump_page(). */
	struct ccs_page_dump env_page = { };
	char *arg_ptr; /* Size is CCS_EXEC_TMPSIZE bytes */
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	/* printk(KERN_DEBUG "start %d %d\n", argv_count, envp_count); */
	int error = -ENOMEM;
	if (!r->mode || !envp_count)
		return 0;
	arg_ptr = kzalloc(CCS_EXEC_TMPSIZE, GFP_KERNEL);
	if (!arg_ptr)
		goto out;
	while (error == -ENOMEM) {
		if (!ccs_dump_page(bprm, pos, &env_page))
			goto out;
		pos += PAGE_SIZE - offset;
		/* Read. */
		while (argv_count && offset < PAGE_SIZE) {
			if (!env_page.data[offset++])
				argv_count--;
		}
		if (argv_count) {
			offset = 0;
			continue;
		}
		while (offset < PAGE_SIZE) {
			const unsigned char c = env_page.data[offset++];
			if (c && arg_len < CCS_EXEC_TMPSIZE - 10) {
				if (c == '=') {
					arg_ptr[arg_len++] = '\0';
				} else if (c == '\\') {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = '\\';
				} else if (c > ' ' && c < 127) {
					arg_ptr[arg_len++] = c;
				} else {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = (c >> 6) + '0';
					arg_ptr[arg_len++]
						= ((c >> 3) & 7) + '0';
					arg_ptr[arg_len++] = (c & 7) + '0';
				}
			} else {
				arg_ptr[arg_len] = '\0';
			}
			if (c)
				continue;
			if (ccs_env_perm(r, arg_ptr)) {
				error = -EPERM;
				break;
			}
			if (!--envp_count) {
				error = 0;
				break;
			}
			arg_len = 0;
		}
		offset = 0;
	}
 out:
	if (r->mode != 3)
		error = 0;
	kfree(env_page.data);
	return error;
}

/**
 * ccs_unescape - Unescape escaped string.
 *
 * @dest: String to unescape.
 *
 * Returns nothing.
 */
static void ccs_unescape(unsigned char *dest)
{
	unsigned char *src = dest;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	while (1) {
		c = *src++;
		if (!c)
			break;
		if (c != '\\') {
			*dest++ = c;
			continue;
		}
		c = *src++;
		if (c == '\\') {
			*dest++ = c;
			continue;
		}
		if (c < '0' || c > '3')
			break;
		d = *src++;
		if (d < '0' || d > '7')
			break;
		e = *src++;
		if (e < '0' || e > '7')
			break;
		*dest++ = ((c - '0') << 6) + ((d - '0') << 3) + (e - '0');
	}
	*dest = '\0';
}

/**
 * ccs_root_depth - Get number of directories to strip.
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 *
 * Returns number of directories to strip.
 */
static inline int ccs_root_depth(struct dentry *dentry, struct vfsmount *vfsmnt)
{
	int depth = 0;
	ccs_realpath_lock();
	for (;;) {
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
			if (vfsmnt->mnt_parent == vfsmnt)
				break;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		dentry = dentry->d_parent;
		depth++;
	}
	ccs_realpath_unlock();
	return depth;
}

/**
 * ccs_get_root_depth - return the depth of root directory.
 *
 * Returns number of directories to strip.
 */
static int ccs_get_root_depth(void)
{
	int depth;
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	struct path root;
#endif
	read_lock(&current->fs->lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	root = current->fs->root;
	path_get(&current->fs->root);
	dentry = root.dentry;
	vfsmnt = root.mnt;
#else
	dentry = dget(current->fs->root);
	vfsmnt = mntget(current->fs->rootmnt);
#endif
	read_unlock(&current->fs->lock);
	depth = ccs_root_depth(dentry, vfsmnt);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	path_put(&root);
#else
	dput(dentry);
	mntput(vfsmnt);
#endif
	return depth;
}

/**
 * ccs_try_alt_exec - Try to start execute handler.
 *
 * @ee: Pointer to "struct ccs_execve_entry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_try_alt_exec(struct ccs_execve_entry *ee)
{
	/*
	 * Contents of modified bprm.
	 * The envp[] in original bprm is moved to argv[] so that
	 * the alternatively executed program won't be affected by
	 * some dangerous environment variables like LD_PRELOAD.
	 *
	 * modified bprm->argc
	 *    = original bprm->argc + original bprm->envc + 7
	 * modified bprm->envc
	 *    = 0
	 *
	 * modified bprm->argv[0]
	 *    = the program's name specified by execute_handler
	 * modified bprm->argv[1]
	 *    = ccs_current_domain()->domainname->name
	 * modified bprm->argv[2]
	 *    = the current process's name
	 * modified bprm->argv[3]
	 *    = the current process's information (e.g. uid/gid).
	 * modified bprm->argv[4]
	 *    = original bprm->filename
	 * modified bprm->argv[5]
	 *    = original bprm->argc in string expression
	 * modified bprm->argv[6]
	 *    = original bprm->envc in string expression
	 * modified bprm->argv[7]
	 *    = original bprm->argv[0]
	 *  ...
	 * modified bprm->argv[bprm->argc + 6]
	 *     = original bprm->argv[bprm->argc - 1]
	 * modified bprm->argv[bprm->argc + 7]
	 *     = original bprm->envp[0]
	 *  ...
	 * modified bprm->argv[bprm->envc + bprm->argc + 6]
	 *     = original bprm->envp[bprm->envc - 1]
	 */
	struct linux_binprm *bprm = ee->bprm;
	struct file *filp;
	int retval;
	const int original_argc = bprm->argc;
	const int original_envc = bprm->envc;
	struct task_struct *task = current;

	/* Close the requested program's dentry. */
	ee->obj.path1.dentry = NULL;
	ee->obj.path1.mnt = NULL;
	ee->obj.validate_done = false;
	allow_write_access(bprm->file);
	fput(bprm->file);
	bprm->file = NULL;

	/* Invalidate page dump cache. */
	ee->dump.page = NULL;

	/* Move envp[] to argv[] */
	bprm->argc += bprm->envc;
	bprm->envc = 0;

	/* Set argv[6] */
	{
		char *cp = ee->tmp;
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "%d", original_envc);
		retval = copy_strings_kernel(1, &cp, bprm);
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[5] */
	{
		char *cp = ee->tmp;
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "%d", original_argc);
		retval = copy_strings_kernel(1, &cp, bprm);
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[4] */
	{
		retval = copy_strings_kernel(1, &bprm->filename, bprm);
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[3] */
	{
		char *cp = ee->tmp;
		const u32 ccs_flags = task->ccs_flags;
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1,
			 "pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d "
			 "sgid=%d fsuid=%d fsgid=%d state[0]=%u "
			 "state[1]=%u state[2]=%u",
			 (pid_t) sys_getpid(), current_uid(), current_gid(),
			 current_euid(), current_egid(), current_suid(),
			 current_sgid(), current_fsuid(), current_fsgid(),
			 (u8) (ccs_flags >> 24), (u8) (ccs_flags >> 16),
			 (u8) (ccs_flags >> 8));
		retval = copy_strings_kernel(1, &cp, bprm);
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[2] */
	{
		char *exe = (char *) ccs_get_exe();
		if (exe) {
			retval = copy_strings_kernel(1, &exe, bprm);
			kfree(exe);
		} else {
			exe = ee->tmp;
			snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "<unknown>");
			retval = copy_strings_kernel(1, &exe, bprm);
		}
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[1] */
	{
		char *cp = ee->tmp;
		snprintf(ee->tmp, CCS_EXEC_TMPSIZE - 1, "%s",
			 ccs_current_domain()->domainname->name);
		retval = copy_strings_kernel(1, &cp, bprm);
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[0] */
	{
		int depth = ccs_get_root_depth();
		int len = ee->handler->total_len + 1;
		char *cp = kmalloc(len, GFP_KERNEL);
		if (!cp) {
			retval = -ENOMEM;
			goto out;
		}
		ee->handler_path = cp;
		memmove(cp, ee->handler->name, len);
		ccs_unescape(cp);
		retval = -ENOENT;
		if (!*cp || *cp != '/')
			goto out;
		/* Adjust root directory for open_exec(). */
		while (depth) {
			cp = strchr(cp + 1, '/');
			if (!cp)
				goto out;
			depth--;
		}
		memmove(ee->handler_path, cp, strlen(cp) + 1);
		cp = ee->handler_path;
		retval = copy_strings_kernel(1, &cp, bprm);
		if (retval < 0)
			goto out;
		bprm->argc++;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
	bprm->argv_len = bprm->exec - bprm->p;
#endif
#endif

	/* OK, now restart the process with execute handler program's dentry. */
	filp = open_exec(ee->handler_path);
	if (IS_ERR(filp)) {
		retval = PTR_ERR(filp);
		goto out;
	}
	ee->obj.path1.dentry = filp->f_dentry;
	ee->obj.path1.mnt = filp->f_vfsmnt;
	bprm->file = filp;
	bprm->filename = ee->handler_path;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	bprm->interp = bprm->filename;
#endif
	retval = prepare_binprm(bprm);
	if (retval < 0)
		goto out;
	task->ccs_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	retval = ccs_find_next_domain(ee);
	task->ccs_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
 out:
	return retval;
}

/**
 * ccs_find_execute_handler - Find an execute handler.
 *
 * @ee:   Pointer to "struct ccs_execve_entry".
 * @type: Type of execute handler.
 *
 * Returns true if found, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_find_execute_handler(struct ccs_execve_entry *ee,
				     const u8 type)
{
	struct task_struct *task = current;
	const struct ccs_domain_info *domain = ccs_current_domain();
	struct ccs_acl_info *ptr;
	bool found = false;
	/*
	 * Don't use execute handler if the current process is
	 * marked as execute handler to avoid infinite execute handler loop.
	 */
	if (task->ccs_flags & CCS_TASK_IS_EXECUTE_HANDLER)
		return false;
	list_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct ccs_execute_handler_record *acl;
		if (ptr->type != type)
			continue;
		acl = container_of(ptr, struct ccs_execute_handler_record,
				   head);
		ee->handler = acl->handler;
		found = true;
		break;
	}
	return found;
}

/**
 * ccs_dump_page - Dump a page to buffer.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @pos:  Location to dump.
 * @dump: Poiner to "struct ccs_page_dump".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_dump_page(struct linux_binprm *bprm, unsigned long pos,
		   struct ccs_page_dump *dump)
{
	struct page *page;
	/* dump->data is released by ccs_finish_execve(). */
	if (!dump->data) {
		dump->data = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!dump->data)
			return false;
	}
	/* Same with get_arg_page(bprm, pos, 0) in fs/exec.c */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
	if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page, NULL) <= 0)
		return false;
#elif defined(RHEL_MAJOR) && RHEL_MAJOR == 5 && defined(RHEL_MINOR) && RHEL_MINOR >= 3 && defined(CONFIG_MMU)
	if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page, NULL) <= 0)
		return false;
#elif defined(AX_MAJOR) && AX_MAJOR == 3 && defined(AX_MINOR) && AX_MINOR >= 2 && defined(CONFIG_MMU)
	if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page, NULL) <= 0)
		return false;
#else
	page = bprm->page[pos / PAGE_SIZE];
#endif
	if (page != dump->page) {
		const unsigned int offset = pos % PAGE_SIZE;
		/*
		 * Maybe kmap()/kunmap() should be used here.
		 * But remove_arg_zero() uses kmap_atomic()/kunmap_atomic().
		 * So do I.
		 */
		char *kaddr = kmap_atomic(page, KM_USER0);
		dump->page = page;
		memcpy(dump->data + offset, kaddr + offset, PAGE_SIZE - offset);
		kunmap_atomic(kaddr, KM_USER0);
	}
	/* Same with put_arg_page(page) in fs/exec.c */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
	put_page(page);
#elif defined(RHEL_MAJOR) && RHEL_MAJOR == 5 && defined(RHEL_MINOR) && RHEL_MINOR >= 3 && defined(CONFIG_MMU)
	put_page(page);
#elif defined(AX_MAJOR) && AX_MAJOR == 3 && defined(AX_MINOR) && AX_MINOR >= 2 && defined(CONFIG_MMU)
	put_page(page);
#endif
	return true;
}

/**
 * ccs_start_execve - Prepare for execve() operation.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @eep:  Pointer to "struct ccs_execve_entry *".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_start_execve(struct linux_binprm *bprm, struct ccs_execve_entry **eep)
{
	int retval;
	struct task_struct *task = current;
	struct ccs_execve_entry *ee;
	*eep = NULL;
	if (!ccs_policy_loaded)
		ccs_load_policy(bprm->filename);
	ee = kzalloc(sizeof(*ee), GFP_KERNEL);
	if (!ee)
		return -ENOMEM;
	ee->tmp = kzalloc(CCS_EXEC_TMPSIZE, GFP_KERNEL);
	if (!ee->tmp) {
		kfree(ee);
		return -ENOMEM;
	}
	ee->reader_idx = ccs_read_lock();
	/* ee->dump->data is allocated by ccs_dump_page(). */
	ee->previous_domain = task->ccs_domain_info;
	/* Clear manager flag. */
	task->ccs_flags &= ~CCS_TASK_IS_POLICY_MANAGER;
	/* Tell GC that I started execve(). */
	task->ccs_flags |= CCS_TASK_IS_IN_EXECVE;
	/*
	 * Make task->ccs_flags visible to GC before changing
	 * task->ccs_domain_info .
	 */
	smp_mb();
	*eep = ee;
	ccs_init_request_info(&ee->r, NULL, CCS_MAC_FILE_EXECUTE);
	ee->r.ee = ee;
	ee->bprm = bprm;
	ee->r.obj = &ee->obj;
	ee->obj.path1.dentry = bprm->file->f_dentry;
	ee->obj.path1.mnt = bprm->file->f_vfsmnt;
	if (ccs_find_execute_handler(ee, CCS_TYPE_EXECUTE_HANDLER)) {
		retval = ccs_try_alt_exec(ee);
		if (!retval)
			ccs_audit_execute_handler_log(ee, true);
		goto ok;
	}
	retval = ccs_find_next_domain(ee);
	if (retval != -EPERM)
		goto ok;
	if (ccs_find_execute_handler(ee, CCS_TYPE_DENIED_EXECUTE_HANDLER)) {
		retval = ccs_try_alt_exec(ee);
		if (!retval)
			ccs_audit_execute_handler_log(ee, false);
	}
 ok:
	if (retval < 0)
		goto out;
	/*
	 * Proceed to the next domain in order to allow reaching via PID.
	 * It will be reverted if execve() failed. Reverting is not good.
	 * But it is better than being unable to reach via PID in interactive
	 * enforcing mode.
	 */
	task->ccs_domain_info = ee->r.domain;
	ee->r.mode = ccs_get_mode(ee->r.domain->profile, CCS_MAC_ENVIRON);
	retval = ccs_environ(ee);
	if (retval < 0)
		goto out;
	retval = 0;
 out:
	return retval;
}

/**
 * ccs_finish_execve - Clean up execve() operation.
 *
 * @retval: Return code of an execve() operation.
 * @ee:     Pointer to "struct ccs_execve_entry".
 *
 * Caller holds ccs_read_lock().
 */
void ccs_finish_execve(int retval, struct ccs_execve_entry *ee)
{
	struct task_struct *task = current;
	if (!ee)
		return;
	if (retval < 0) {
		task->ccs_domain_info = ee->previous_domain;
		/*
		 * Make task->ccs_domain_info visible to GC before changing
		 * task->ccs_flags .
		 */
		smp_mb();
	} else {
		/* Mark the current process as execute handler. */
		if (ee->handler)
			task->ccs_flags |= CCS_TASK_IS_EXECUTE_HANDLER;
		/* Mark the current process as normal process. */
		else
			task->ccs_flags &= ~CCS_TASK_IS_EXECUTE_HANDLER;
	}
	/* Tell GC that I finished execve(). */
	task->ccs_flags &= ~CCS_TASK_IS_IN_EXECVE;
	ccs_read_unlock(ee->reader_idx);
	kfree(ee->handler_path);
	kfree(ee->tmp);
	kfree(ee->dump.data);
	kfree(ee);
}
