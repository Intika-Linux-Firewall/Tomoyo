/*
 * fs/tomoyo_domain.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2011/05/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#include <linux/highmem.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#include <linux/mount.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
#include <linux/fs_struct.h>
#endif

/* For compatibility with older kernels. */
#ifndef for_each_process
#define for_each_process for_each_task
#endif

/* Variables definitions.*/

/* The initial domain. */
struct ccs_domain_info ccs_kernel_domain;

/* The list for "struct ccs_domain_info". */
LIST1_HEAD(ccs_domain_list);

#ifdef CONFIG_TOMOYO

/* Domain creation lock. */
static DEFINE_MUTEX(ccs_domain_list_lock);

/* Structure for "initialize_domain" and "no_initialize_domain" keyword. */
struct ccs_domain_initializer_entry {
	struct list1_head list;
	const struct ccs_path_info *domainname;    /* This may be NULL */
	const struct ccs_path_info *program;
	bool is_deleted;
	bool is_not;       /* True if this entry is "no_initialize_domain".  */
	bool is_last_name; /* True if the domainname is ccs_get_last_name(). */
};

/* Structure for "keep_domain" and "no_keep_domain" keyword. */
struct ccs_domain_keeper_entry {
	struct list1_head list;
	const struct ccs_path_info *domainname;
	const struct ccs_path_info *program;       /* This may be NULL */
	bool is_deleted;
	bool is_not;       /* True if this entry is "no_keep_domain".        */
	bool is_last_name; /* True if the domainname is ccs_get_last_name(). */
};

/* Structure for "aggregator" keyword. */
struct ccs_aggregator_entry {
	struct list1_head list;
	const struct ccs_path_info *original_name;
	const struct ccs_path_info *aggregated_name;
	bool is_deleted;
};

/* Structure for "alias" keyword. */
struct ccs_alias_entry {
	struct list1_head list;
	const struct ccs_path_info *original_name;
	const struct ccs_path_info *aliased_name;
	bool is_deleted;
};

/**
 * ccs_set_domain_flag - Set or clear domain's attribute flags.
 *
 * @domain:    Pointer to "struct ccs_domain_info".
 * @is_delete: True if it is a delete request.
 * @flags:     Flags to set or clear.
 *
 * Returns nothing.
 */
void ccs_set_domain_flag(struct ccs_domain_info *domain, const bool is_delete,
			 const u8 flags)
{
	/* We need to serialize because this is bitfield operation. */
	static DEFINE_SPINLOCK(lock);
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	if (!is_delete)
		domain->flags |= flags;
	else
		domain->flags &= ~flags;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
}

/**
 * ccs_get_last_name - Get last component of a domainname.
 *
 * @domain: Pointer to "struct ccs_domain_info".
 *
 * Returns the last component of the domainname.
 */
const char *ccs_get_last_name(const struct ccs_domain_info *domain)
{
	const char *cp0 = domain->domainname->name;
	const char *cp1 = strrchr(cp0, ' ');
	if (cp1)
		return cp1 + 1;
	return cp0;
}

/**
 * ccs_add_domain_acl - Add the given ACL to the given domain.
 *
 * @domain: Pointer to "struct ccs_domain_info". May be NULL.
 * @acl:    Pointer to "struct ccs_acl_info".
 *
 * Returns 0.
 */
int ccs_add_domain_acl(struct ccs_domain_info *domain, struct ccs_acl_info *acl)
{
	if (domain) {
		/*
		 * We need to serialize because this function is called by
		 * various update functions.
		 */
		static DEFINE_SPINLOCK(lock);
		/***** CRITICAL SECTION START *****/
		spin_lock(&lock);
		list1_add_tail_mb(&acl->list, &domain->acl_info_list);
		spin_unlock(&lock);
		/***** CRITICAL SECTION END *****/
	} else {
		acl->type &= ~ACL_DELETED;
	}
	ccs_update_counter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

/**
 * ccs_del_domain_acl - Delete the given ACL from the domain.
 *
 * @acl: Pointer to "struct ccs_acl_info". May be NULL.
 *
 * Returns 0.
 */
int ccs_del_domain_acl(struct ccs_acl_info *acl)
{
	if (acl)
		acl->type |= ACL_DELETED;
	ccs_update_counter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

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
	int error;
	struct ccs_request_info *r = &ee->r;
	struct ccs_domain_info *domain = r->domain;
	const char *handler = ee->handler->name;
	r->domain = ccs_current_domain();
	r->mode = ccs_check_flags(r->domain, CCS_MAC_FOR_FILE);
	error = ccs_write_audit_log(true, r, "%s %s\n",
				    is_default ? KEYWORD_EXECUTE_HANDLER :
				    KEYWORD_DENIED_EXECUTE_HANDLER, handler);
	r->domain = domain;
	return error;
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
	struct ccs_request_info r;
	ccs_init_request_info(&r, domain, CCS_MAC_FOR_FILE);
	return ccs_write_audit_log(false, &r, "use_profile %u\n", r.profile);
}

/* The list for "struct ccs_domain_initializer_entry". */
static LIST1_HEAD(ccs_domain_initializer_list);

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
	struct ccs_domain_initializer_entry *new_entry;
	struct ccs_domain_initializer_entry *ptr;
	static DEFINE_MUTEX(lock);
	const struct ccs_path_info *saved_program;
	const struct ccs_path_info *saved_domainname = NULL;
	int error = -ENOMEM;
	bool is_last_name = false;
	if (!ccs_is_correct_path(program, 1, -1, -1, __func__))
		return -EINVAL; /* No patterns allowed. */
	if (domainname) {
		if (!ccs_is_domain_def(domainname) &&
		    ccs_is_correct_path(domainname, 1, -1, -1, __func__))
			is_last_name = true;
		else if (!ccs_is_correct_domain(domainname, __func__))
			return -EINVAL;
		saved_domainname = ccs_save_name(domainname);
		if (!saved_domainname)
			return -ENOMEM;
	}
	saved_program = ccs_save_name(program);
	if (!saved_program)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_domain_initializer_list, list) {
		if (ptr->is_not != is_not ||
		    ptr->domainname != saved_domainname ||
		    ptr->program != saved_program)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		goto out;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	new_entry = ccs_alloc_element(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	new_entry->domainname = saved_domainname;
	new_entry->program = saved_program;
	new_entry->is_not = is_not;
	new_entry->is_last_name = is_last_name;
	list1_add_tail_mb(&new_entry->list, &ccs_domain_initializer_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * ccs_read_domain_initializer_policy - Read "struct ccs_domain_initializer_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_domain_initializer_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2,
			      &ccs_domain_initializer_list) {
		const char *no;
		const char *from = "";
		const char *domain = "";
		struct ccs_domain_initializer_entry *ptr;
		ptr = list1_entry(pos, struct ccs_domain_initializer_entry,
				  list);
		if (ptr->is_deleted)
			continue;
		no = ptr->is_not ? "no_" : "";
		if (ptr->domainname) {
			from = " from ";
			domain = ptr->domainname->name;
		}
		if (!ccs_io_printf(head,
				   "%s" KEYWORD_INITIALIZE_DOMAIN "%s%s%s\n",
				   no, ptr->program->name, from, domain))
			goto out;
	}
	return true;
 out:
	return false;
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
 */
static bool ccs_is_domain_initializer(const struct ccs_path_info *domainname,
				      const struct ccs_path_info *program,
				      const struct ccs_path_info *last_name)
{
	struct ccs_domain_initializer_entry *ptr;
	bool flag = false;
	list1_for_each_entry(ptr, &ccs_domain_initializer_list, list) {
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
		if (ptr->is_not)
			return false;
		flag = true;
	}
	return flag;
}

/* The list for "struct ccs_domain_keeper_entry". */
static LIST1_HEAD(ccs_domain_keeper_list);

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
	struct ccs_domain_keeper_entry *new_entry;
	struct ccs_domain_keeper_entry *ptr;
	const struct ccs_path_info *saved_domainname;
	const struct ccs_path_info *saved_program = NULL;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	bool is_last_name = false;
	if (!ccs_is_domain_def(domainname) &&
	    ccs_is_correct_path(domainname, 1, -1, -1, __func__))
		is_last_name = true;
	else if (!ccs_is_correct_domain(domainname, __func__))
		return -EINVAL;
	if (program) {
		if (!ccs_is_correct_path(program, 1, -1, -1, __func__))
			return -EINVAL;
		saved_program = ccs_save_name(program);
		if (!saved_program)
			return -ENOMEM;
	}
	saved_domainname = ccs_save_name(domainname);
	if (!saved_domainname)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_domain_keeper_list, list) {
		if (ptr->is_not != is_not ||
		    ptr->domainname != saved_domainname ||
		    ptr->program != saved_program)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		goto out;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	new_entry = ccs_alloc_element(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	new_entry->domainname = saved_domainname;
	new_entry->program = saved_program;
	new_entry->is_not = is_not;
	new_entry->is_last_name = is_last_name;
	list1_add_tail_mb(&new_entry->list, &ccs_domain_keeper_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
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
 */
bool ccs_read_domain_keeper_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &ccs_domain_keeper_list) {
		struct ccs_domain_keeper_entry *ptr;
		const char *no;
		const char *from = "";
		const char *program = "";
		ptr = list1_entry(pos, struct ccs_domain_keeper_entry, list);
		if (ptr->is_deleted)
			continue;
		no = ptr->is_not ? "no_" : "";
		if (ptr->program) {
			from = " from ";
			program = ptr->program->name;
		}
		if (!ccs_io_printf(head,
				   "%s" KEYWORD_KEEP_DOMAIN "%s%s%s\n", no,
				   program, from, ptr->domainname->name))
			goto out;
	}
	return true;
 out:
	return false;
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
 */
static bool ccs_is_domain_keeper(const struct ccs_path_info *domainname,
				 const struct ccs_path_info *program,
				 const struct ccs_path_info *last_name)
{
	struct ccs_domain_keeper_entry *ptr;
	bool flag = false;
	list1_for_each_entry(ptr, &ccs_domain_keeper_list, list) {
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
		if (ptr->is_not)
			return false;
		flag = true;
	}
	return flag;
}

/* The list for "struct ccs_alias_entry". */
static LIST1_HEAD(ccs_alias_list);

/**
 * ccs_update_alias_entry - Update "struct ccs_alias_entry" list.
 *
 * @original_name: The original program's real name.
 * @aliased_name:  The symbolic program's symbolic link's name.
 * @is_delete:     True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_alias_entry(const char *original_name,
				  const char *aliased_name,
				  const bool is_delete)
{
	struct ccs_alias_entry *new_entry;
	struct ccs_alias_entry *ptr;
	static DEFINE_MUTEX(lock);
	const struct ccs_path_info *saved_original_name;
	const struct ccs_path_info *saved_aliased_name;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(original_name, 1, -1, -1, __func__) ||
	    !ccs_is_correct_path(aliased_name, 1, -1, -1, __func__))
		return -EINVAL; /* No patterns allowed. */
	saved_original_name = ccs_save_name(original_name);
	saved_aliased_name = ccs_save_name(aliased_name);
	if (!saved_original_name || !saved_aliased_name)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_alias_list, list) {
		if (ptr->original_name != saved_original_name ||
		    ptr->aliased_name != saved_aliased_name)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		goto out;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	new_entry = ccs_alloc_element(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	new_entry->original_name = saved_original_name;
	new_entry->aliased_name = saved_aliased_name;
	list1_add_tail_mb(&new_entry->list, &ccs_alias_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * ccs_read_alias_policy - Read "struct ccs_alias_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_alias_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &ccs_alias_list) {
		struct ccs_alias_entry *ptr;
		ptr = list1_entry(pos, struct ccs_alias_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_ALIAS "%s %s\n",
				   ptr->original_name->name,
				   ptr->aliased_name->name))
			goto out;
	}
	return true;
 out:
	return false;
}

/**
 * ccs_write_alias_policy - Write "struct ccs_alias_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_alias_policy(char *data, const bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return ccs_update_alias_entry(data, cp, is_delete);
}

/* The list for "struct ccs_aggregator_entry". */
static LIST1_HEAD(ccs_aggregator_list);

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
	struct ccs_aggregator_entry *new_entry;
	struct ccs_aggregator_entry *ptr;
	static DEFINE_MUTEX(lock);
	const struct ccs_path_info *saved_original_name;
	const struct ccs_path_info *saved_aggregated_name;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(original_name, 1, 0, -1, __func__) ||
	    !ccs_is_correct_path(aggregated_name, 1, -1, -1, __func__))
		return -EINVAL;
	saved_original_name = ccs_save_name(original_name);
	saved_aggregated_name = ccs_save_name(aggregated_name);
	if (!saved_original_name || !saved_aggregated_name)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_aggregator_list, list) {
		if (ptr->original_name != saved_original_name ||
		    ptr->aggregated_name != saved_aggregated_name)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		goto out;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	new_entry = ccs_alloc_element(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	new_entry->original_name = saved_original_name;
	new_entry->aggregated_name = saved_aggregated_name;
	list1_add_tail_mb(&new_entry->list, &ccs_aggregator_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * ccs_read_aggregator_policy - Read "struct ccs_aggregator_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_aggregator_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &ccs_aggregator_list) {
		struct ccs_aggregator_entry *ptr;
		ptr = list1_entry(pos, struct ccs_aggregator_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_AGGREGATOR "%s %s\n",
				   ptr->original_name->name,
				   ptr->aggregated_name->name))
			goto out;
	}
	return true;
 out:
	return false;
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
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return ccs_update_aggregator_entry(data, cp, is_delete);
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
	mutex_lock(&ccs_domain_list_lock);
	/* Is there an active domain? */
	list1_for_each_entry(domain, &ccs_domain_list, list) {
		/* Never delete ccs_kernel_domain */
		if (domain == &ccs_kernel_domain)
			continue;
		if (domain->is_deleted ||
		    ccs_pathcmp(domain->domainname, &name))
			continue;
		domain->is_deleted = true;
		break;
	}
	mutex_unlock(&ccs_domain_list_lock);
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
	struct ccs_domain_info *domain = NULL;
	const struct ccs_path_info *saved_domainname;
	mutex_lock(&ccs_domain_list_lock);
	domain = ccs_find_domain(domainname);
	if (domain)
		goto out;
	if (!ccs_is_correct_domain(domainname, __func__))
		goto out;
	saved_domainname = ccs_save_name(domainname);
	if (!saved_domainname)
		goto out;
	/* Can I reuse memory of deleted domain? */
	list1_for_each_entry(domain, &ccs_domain_list, list) {
		struct task_struct *p;
		struct ccs_acl_info *ptr;
		bool flag;
		if (!domain->is_deleted ||
		    domain->domainname != saved_domainname)
			continue;
		flag = false;
		/***** CRITICAL SECTION START *****/
		ccs_tasklist_lock();
		for_each_process(p) {
			if (ccs_task_domain(p) != domain)
				continue;
			flag = true;
			break;
		}
		ccs_tasklist_unlock();
		/***** CRITICAL SECTION END *****/
		if (flag)
			continue;
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			ptr->type |= ACL_DELETED;
		}
		ccs_set_domain_flag(domain, true, domain->flags);
		domain->profile = profile;
		domain->quota_warned = false;
		mb(); /* Avoid out-of-order execution. */
		domain->is_deleted = false;
		goto out;
	}
	/* No memory reusable. Create using new memory. */
	domain = ccs_alloc_element(sizeof(*domain));
	if (domain) {
		INIT_LIST1_HEAD(&domain->acl_info_list);
		domain->domainname = saved_domainname;
		domain->profile = profile;
		list1_add_tail_mb(&domain->list, &ccs_domain_list);
	}
 out:
	mutex_unlock(&ccs_domain_list_lock);
	return domain;
}

/**
 * ccs_get_argv0 - Get argv[0].
 *
 * @ee: Pointer to "struct ccs_execve_entry".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_get_argv0(struct ccs_execve_entry *ee)
{
	struct linux_binprm *bprm = ee->bprm;
	char *arg_ptr = ee->tmp;
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	bool done = false;
	if (!bprm->argc)
		goto out;
	while (1) {
		if (!ccs_dump_page(bprm, pos, &ee->dump))
			goto out;
		pos += PAGE_SIZE - offset;
		/* Read. */
		while (offset < PAGE_SIZE) {
			const char *kaddr = ee->dump.data;
			const unsigned char c = kaddr[offset++];
			if (c && arg_len < CCS_MAX_PATHNAME_LEN - 10) {
				if (c == '\\') {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = '\\';
				} else if (c == '/') {
					arg_len = 0;
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
				done = true;
				break;
			}
		}
		offset = 0;
		if (done)
			break;
	}
	return true;
 out:
	return false;
}

/**
 * ccs_find_next_domain - Find a domain.
 *
 * @ee: Pointer to "struct ccs_execve_entry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_find_next_domain(struct ccs_execve_entry *ee)
{
	struct ccs_request_info *r = &ee->r;
	const struct ccs_path_info *handler = ee->handler;
	struct ccs_domain_info *domain = NULL;
	const char *old_domain_name = r->domain->domainname->name;
	struct linux_binprm *bprm = ee->bprm;
	const u8 mode = r->mode;
	const bool is_enforce = (mode == 3);
	const u32 ccs_flags = current->ccs_flags;
	char *new_domain_name = NULL;
	struct ccs_path_info rn; /* real name */
	struct ccs_path_info sn; /* symlink name */
	struct ccs_path_info ln; /* last name */
	int retval;
 retry:
	current->ccs_flags = ccs_flags;
	r->cond = NULL;
	/* Get realpath of program and symbolic link. */
	retval = ccs_realpath_both(bprm->filename, ee);
	if (retval < 0)
		goto out;

	rn.name = ee->program_path;
	ccs_fill_path_info(&rn);
	sn.name = ee->tmp;
	ccs_fill_path_info(&sn);
	ln.name = ccs_get_last_name(r->domain);
	ccs_fill_path_info(&ln);

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
		goto calculate_domain;
	}

	/* Check 'alias' directive. */
	if (ccs_pathcmp(&rn, &sn)) {
		struct ccs_alias_entry *ptr;
		/* Is this program allowed to be called via symbolic links? */
		list1_for_each_entry(ptr, &ccs_alias_list, list) {
			if (ptr->is_deleted ||
			    ccs_pathcmp(&rn, ptr->original_name) ||
			    ccs_pathcmp(&sn, ptr->aliased_name))
				continue;
			strncpy(ee->program_path, ptr->aliased_name->name,
				CCS_MAX_PATHNAME_LEN - 1);
			ccs_fill_path_info(&rn);
			break;
		}
	}
	/* sn will be overwritten after here. */

	/* Compare basename of program_path and argv[0] */
	r->mode = ccs_check_flags(r->domain, CCS_MAC_FOR_ARGV0);
	if (bprm->argc > 0 && r->mode) {
		char *base_argv0 = ee->tmp;
		const char *base_filename;
		retval = -ENOMEM;
		if (!ccs_get_argv0(ee))
			goto out;
		base_filename = strrchr(ee->program_path, '/');
		if (!base_filename)
			base_filename = ee->program_path;
		else
			base_filename++;
		if (strcmp(base_argv0, base_filename)) {
			retval = ccs_check_argv0_perm(r, &rn, base_argv0);
			if (retval == 1)
				goto retry;
			if (retval < 0)
				goto out;
		}
	}

	/* Check 'aggregator' directive. */
	{
		struct ccs_aggregator_entry *ptr;
		/* Is this program allowed to be aggregated? */
		list1_for_each_entry(ptr, &ccs_aggregator_list, list) {
			if (ptr->is_deleted ||
			    !ccs_path_matches_pattern(&rn, ptr->original_name))
				continue;
			strncpy(ee->program_path, ptr->aggregated_name->name,
				CCS_MAX_PATHNAME_LEN - 1);
			ccs_fill_path_info(&rn);
			break;
		}
	}

	/* Check execute permission. */
	r->mode = mode;
	retval = ccs_check_exec_perm(r, &rn);
	if (retval == 1)
		goto retry;
	if (retval < 0)
		goto out;

 calculate_domain:
	new_domain_name = ee->tmp;
	if (ccs_is_domain_initializer(r->domain->domainname, &rn, &ln)) {
		/* Transit to the child of ccs_kernel_domain domain. */
		snprintf(new_domain_name, CCS_EXEC_TMPSIZE - 1,
			 ROOT_NAME " " "%s", ee->program_path);
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
		snprintf(new_domain_name, CCS_EXEC_TMPSIZE - 1,
			 "%s %s", old_domain_name, ee->program_path);
	}
	if (domain || strlen(new_domain_name) >= CCS_MAX_PATHNAME_LEN)
		goto done;
	domain = ccs_find_domain(new_domain_name);
	if (domain)
		goto done;
	if (is_enforce) {
		int error = ccs_check_supervisor(r,
						 "# wants to create domain\n"
						 "%s\n", new_domain_name);
		if (error == 1)
			goto retry;
		if (error < 0)
			goto done;
	}
	domain = ccs_find_or_assign_new_domain(new_domain_name, r->profile);
	if (domain)
		ccs_audit_domain_creation_log(domain);
 done:
	if (!domain) {
		printk(KERN_WARNING "TOMOYO-ERROR: Domain '%s' not defined.\n",
		       new_domain_name);
		if (is_enforce)
			retval = -EPERM;
		else {
			retval = 0;
			ccs_set_domain_flag(r->domain, false,
					    DOMAIN_FLAGS_TRANSITION_FAILED);
		}
	} else {
		retval = 0;
	}
 out:
	if (domain)
		r->domain = domain;
	return retval;
}

/**
 * ccs_check_environ - Check permission for environment variable names.
 *
 * @ee: Pointer to "struct ccs_execve_entry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_environ(struct ccs_execve_entry *ee)
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
			if (c && arg_len < CCS_MAX_PATHNAME_LEN - 10) {
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
			if (ccs_check_env_perm(r, arg_ptr)) {
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
	kfree(arg_ptr);
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
	/***** CRITICAL SECTION START *****/
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
	/***** CRITICAL SECTION END *****/
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
	/***** CRITICAL SECTION START *****/
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
	/***** CRITICAL SECTION END *****/
	depth = ccs_root_depth(dentry, vfsmnt);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	path_put(&root);
#else
	dput(dentry);
	mntput(vfsmnt);
#endif
	return depth;
}

static LIST_HEAD(ccs_execve_list);
static DEFINE_SPINLOCK(ccs_execve_list_lock);

/**
 * ccs_allocate_execve_entry - Allocate memory for execve().
 *
 * Returns pointer to "struct ccs_execve_entry" on success, NULL otherwise.
 */
static struct ccs_execve_entry *ccs_allocate_execve_entry(void)
{
	struct ccs_execve_entry *ee = ccs_alloc(sizeof(*ee), false);
	if (!ee)
		return NULL;
	memset(ee, 0, sizeof(*ee));
	ee->program_path = ccs_alloc(CCS_MAX_PATHNAME_LEN, false);
	ee->tmp = ccs_alloc(CCS_EXEC_TMPSIZE, false);
	if (!ee->program_path || !ee->tmp) {
		ccs_free(ee->program_path);
		ccs_free(ee->tmp);
		ccs_free(ee);
		return NULL;
	}
	/* ee->dump->data is allocated by ccs_dump_page(). */
	ee->task = current;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_execve_list_lock);
	list_add(&ee->list, &ccs_execve_list);
	spin_unlock(&ccs_execve_list_lock);
	/***** CRITICAL SECTION END *****/
	return ee;
}

/**
 * ccs_find_execve_entry - Find ccs_execve_entry of current process.
 *
 * Returns pointer to "struct ccs_execve_entry" on success, NULL otherwise.
 */
static struct ccs_execve_entry *ccs_find_execve_entry(void)
{
	struct task_struct *task = current;
	struct ccs_execve_entry *ee = NULL;
	struct ccs_execve_entry *p;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_execve_list_lock);
	list_for_each_entry(p, &ccs_execve_list, list) {
		if (p->task != task)
			continue;
		ee = p;
		break;
	}
	spin_unlock(&ccs_execve_list_lock);
	/***** CRITICAL SECTION END *****/
	return ee;
}

/**
 * ccs_free_execve_entry - Free memory for execve().
 *
 * @ee: Pointer to "struct ccs_execve_entry".
 */
static void ccs_free_execve_entry(struct ccs_execve_entry *ee)
{
	if (!ee)
		return;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_execve_list_lock);
	list_del(&ee->list);
	spin_unlock(&ccs_execve_list_lock);
	/***** CRITICAL SECTION END *****/
	ccs_free(ee->program_path);
	ccs_free(ee->tmp);
	kfree(ee->dump.data);
	ccs_free(ee);
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
	ee->obj.path1_dentry = NULL;
	ee->obj.path1_vfsmnt = NULL;
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
			ccs_free(exe);
		} else {
			exe = ee->tmp;
			strncpy(ee->tmp, "<unknown>", CCS_EXEC_TMPSIZE - 1);
			retval = copy_strings_kernel(1, &exe, bprm);
		}
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[1] */
	{
		char *cp = ee->tmp;
		strncpy(ee->tmp, ccs_current_domain()->domainname->name,
			CCS_EXEC_TMPSIZE - 1);
		retval = copy_strings_kernel(1, &cp, bprm);
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[0] */
	{
		int depth = ccs_get_root_depth();
		char *cp = ee->program_path;
		strncpy(cp, ee->handler->name, CCS_MAX_PATHNAME_LEN - 1);
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
		memmove(ee->program_path, cp, strlen(cp) + 1);
		cp = ee->program_path;
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
	filp = open_exec(ee->program_path);
	if (IS_ERR(filp)) {
		retval = PTR_ERR(filp);
		goto out;
	}
	ee->obj.path1_dentry = filp->f_dentry;
	ee->obj.path1_vfsmnt = filp->f_vfsmnt;
	bprm->file = filp;
	bprm->filename = ee->program_path;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	bprm->interp = bprm->filename;
#endif
	retval = prepare_binprm(bprm);
	if (retval < 0)
		goto out;
	{
		/*
		 * Backup ee->program_path because ccs_find_next_domain() will
		 * overwrite ee->program_path and ee->tmp.
		 */
		const int len = strlen(ee->program_path) + 1;
		char *cp = kmalloc(len, GFP_KERNEL);
		if (!cp) {
			retval = -ENOMEM;
			goto out;
		}
		memmove(cp, ee->program_path, len);
		bprm->filename = cp;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
		bprm->interp = bprm->filename;
#endif
		task->ccs_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
		retval = ccs_find_next_domain(ee);
		task->ccs_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
		/* Restore ee->program_path for search_binary_handler(). */
		memmove(ee->program_path, cp, len);
		bprm->filename = ee->program_path;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
		bprm->interp = bprm->filename;
#endif
		kfree(cp);
	}
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
 */
static bool ccs_find_execute_handler(struct ccs_execve_entry *ee,
				     const u8 type)
{
	struct task_struct *task = current;
	const struct ccs_domain_info *domain = ccs_current_domain();
	struct ccs_acl_info *ptr;
	/*
	 * Don't use execute handler if the current process is
	 * marked as execute handler to avoid infinite execute handler loop.
	 */
	if (task->ccs_flags & CCS_TASK_IS_EXECUTE_HANDLER)
		return false;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct ccs_execute_handler_record *acl;
		if (ptr->type != type)
			continue;
		acl = container_of(ptr, struct ccs_execute_handler_record,
				   head);
		ee->handler = acl->handler;
		return true;
	}
	return false;
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
	/* dump->data is released by ccs_free_execve_entry(). */
	if (!dump->data) {
		dump->data = kmalloc(PAGE_SIZE, GFP_KERNEL);
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
 * ccs_fetch_next_domain - Fetch next_domain from the list.
 *
 * Returns pointer to "struct ccs_domain_info" which will be used if execve()
 * succeeds. This function does not return NULL.
 */
struct ccs_domain_info *ccs_fetch_next_domain(void)
{
	struct ccs_execve_entry *ee = ccs_find_execve_entry();
	struct ccs_domain_info *next_domain = NULL;
	if (ee)
		next_domain = ee->next_domain;
	if (!next_domain)
		next_domain = ccs_current_domain();
	return next_domain;
}

/**
 * ccs_start_execve - Prepare for execve() operation.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_start_execve(struct linux_binprm *bprm)
{
	int retval;
	struct task_struct *task = current;
	struct ccs_execve_entry *ee = ccs_allocate_execve_entry();
	if (!ccs_policy_loaded)
		ccs_load_policy(bprm->filename);
	if (!ee)
		return -ENOMEM;
	ccs_init_request_info(&ee->r, NULL, CCS_MAC_FOR_FILE);
	ee->r.ee = ee;
	ee->bprm = bprm;
	ee->r.obj = &ee->obj;
	ee->obj.path1_dentry = bprm->file->f_dentry;
	ee->obj.path1_vfsmnt = bprm->file->f_vfsmnt;
	/* Clear manager flag. */
	task->ccs_flags &= ~CCS_TASK_IS_POLICY_MANAGER;
	if (ccs_find_execute_handler(ee, TYPE_EXECUTE_HANDLER)) {
		retval = ccs_try_alt_exec(ee);
		if (!retval)
			ccs_audit_execute_handler_log(ee, true);
		goto ok;
	}
	retval = ccs_find_next_domain(ee);
	if (retval != -EPERM)
		goto ok;
	if (ccs_find_execute_handler(ee, TYPE_DENIED_EXECUTE_HANDLER)) {
		retval = ccs_try_alt_exec(ee);
		if (!retval)
			ccs_audit_execute_handler_log(ee, false);
	}
 ok:
	if (retval < 0)
		goto out;
	ee->r.profile = ee->r.domain->profile;
	ee->r.mode = ccs_check_flags(ee->r.domain, CCS_MAC_FOR_ENV);
	retval = ccs_check_environ(ee);
	if (retval < 0)
		goto out;
	ee->next_domain = ee->r.domain;
	task->ccs_flags |= CCS_CHECK_READ_FOR_OPEN_EXEC;
	retval = 0;
 out:
	if (retval)
		ccs_finish_execve(retval);
	return retval;
}

/**
 * ccs_finish_execve - Clean up execve() operation.
 *
 * @retval: Return code of an execve() operation.
 */
void ccs_finish_execve(int retval)
{
	struct task_struct *task = current;
	struct ccs_execve_entry *ee = ccs_find_execve_entry();
	task->ccs_flags &= ~CCS_CHECK_READ_FOR_OPEN_EXEC;
	if (!ee)
		return;
	if (retval < 0)
		goto out;
	/* Proceed to next domain if execution suceeded. */
	task->ccs_domain_info = ee->r.domain;
	mb(); /* Make domain transition visible to other CPUs. */
	/* Mark the current process as execute handler. */
	if (ee->handler)
		task->ccs_flags |= CCS_TASK_IS_EXECUTE_HANDLER;
	/* Mark the current process as normal process. */
	else
		task->ccs_flags &= ~CCS_TASK_IS_EXECUTE_HANDLER;
 out:
	ccs_free_execve_entry(ee);
}

#else

/**
 * ccs_start_execve - Prepare for execve() operation.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns 0.
 */
int ccs_start_execve(struct linux_binprm *bprm)
{
#ifdef CONFIG_SAKURA
	/* Clear manager flag. */
	current->ccs_flags &= ~CCS_TASK_IS_POLICY_MANAGER;
	if (!ccs_policy_loaded)
		ccs_load_policy(bprm->filename);
#endif
	return 0;
}

/**
 * ccs_finish_execve - Clean up execve() operation.
 *
 * @retval: Unused.
 */
void ccs_finish_execve(int retval)
{
}

#endif
