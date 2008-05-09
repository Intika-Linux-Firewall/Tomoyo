/*
 * fs/tomoyo_domain.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.1   2008/05/10
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#include <linux/highmem.h>
#include <linux/binfmts.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#include <linux/mount.h>
#endif

/* For compatibility with older kernels. */
#ifndef for_each_process
#define for_each_process for_each_task
#endif

/* Variables definitions.*/

/* The initial domain. */
struct domain_info KERNEL_DOMAIN;

/* The list for "struct domain_info". */
LIST1_HEAD(domain_list);

#ifdef CONFIG_TOMOYO

/* Lock for appending domain's ACL. */
DEFINE_MUTEX(domain_acl_lock);

/* Domain creation lock. */
static DEFINE_MUTEX(new_domain_assign_lock);

/* Structure for "initialize_domain" and "no_initialize_domain" keyword. */
struct domain_initializer_entry {
	struct list1_head list;
	const struct path_info *domainname;    /* This may be NULL */
	const struct path_info *program;
	bool is_deleted;
	bool is_not;       /* True if this entry is "no_initialize_domain".  */
	bool is_last_name; /* True if the domainname is ccs_get_last_name(). */
};

/* Structure for "keep_domain" and "no_keep_domain" keyword. */
struct domain_keeper_entry {
	struct list1_head list;
	const struct path_info *domainname;
	const struct path_info *program;       /* This may be NULL */
	bool is_deleted;
	bool is_not;       /* True if this entry is "no_keep_domain".        */
	bool is_last_name; /* True if the domainname is ccs_get_last_name(). */
};

/* Structure for "aggregator" keyword. */
struct aggregator_entry {
	struct list1_head list;
	const struct path_info *original_name;
	const struct path_info *aggregated_name;
	bool is_deleted;
};

/* Structure for "alias" keyword. */
struct alias_entry {
	struct list1_head list;
	const struct path_info *original_name;
	const struct path_info *aliased_name;
	bool is_deleted;
};

/**
 * ccs_set_domain_flag - Set or clear domain's attribute flags.
 *
 * @domain:    Pointer to "struct domain_info".
 * @is_delete: True if it is a delete request.
 * @flags:     Flags to set or clear.
 *
 * Returns nothing.
 */
void ccs_set_domain_flag(struct domain_info *domain, const bool is_delete,
			 const u8 flags)
{
	mutex_lock(&new_domain_assign_lock);
	if (!is_delete)
		domain->flags |= flags;
	else
		domain->flags &= ~flags;
	mutex_unlock(&new_domain_assign_lock);
}

/**
 * ccs_get_last_name - Get last component of a domainname.
 *
 * @domain: Pointer to "struct domain_info".
 *
 * Returns the last component of the domainname.
 */
const char *ccs_get_last_name(const struct domain_info *domain)
{
	const char *cp0 = domain->domainname->name, *cp1 = strrchr(cp0, ' ');
	if (cp1)
		return cp1 + 1;
	return cp0;
}

/**
 * ccs_add_domain_acl - Add the given ACL to the given domain.
 *
 * @domain: Pointer to "struct domain_info". May be NULL.
 * @acl:    Pointer to "struct acl_info".
 *
 * Returns 0.
 */
int ccs_add_domain_acl(struct domain_info *domain, struct acl_info *acl)
{
	if (domain)
		list1_add_tail_mb(&acl->list, &domain->acl_info_list);
	else
		acl->type &= ~ACL_DELETED;
	ccs_update_counter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

/**
 * ccs_del_domain_acl - Delete the given ACL from the domain.
 *
 * @acl: Pointer to "struct acl_info". May be NULL.
 *
 * Returns 0.
 */
int ccs_del_domain_acl(struct acl_info *acl)
{
	if (acl)
		acl->type |= ACL_DELETED;
	ccs_update_counter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

/**
 * audit_execute_handler_log - Audit execute_handler log.
 *
 * @is_default: True if it is "execute_handler" log.
 * @handler:    The realpath of the handler.
 * @bprm:       Pointer to "struct linux_binprm".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int audit_execute_handler_log(const bool is_default,
				     const char *handler,
				     struct linux_binprm *bprm)
{
	char *buf;
	int len;
	int len2;
	u8 profile;
	u8 mode;
	if (ccs_can_save_audit_log(true) < 0)
		return -ENOMEM;
	len = strlen(handler) + 32;
	profile = current->domain_info->profile;
	mode = ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE);
	buf = ccs_init_audit_log(&len, profile, mode, bprm);
	if (!buf)
		return -ENOMEM;
	len2 = strlen(buf);
	snprintf(buf + len2, len - len2 - 1, "%s %s\n",
		 is_default ? KEYWORD_EXECUTE_HANDLER :
		 KEYWORD_DENIED_EXECUTE_HANDLER, handler);
	return ccs_write_audit_log(buf, true);
}

/**
 * audit_domain_creation_log - Audit domain creation log.
 *
 * @domainname: The name of newly created domain.
 * @mode:       Access control mode used.
 * @profile:    Profile number used.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int audit_domain_creation_log(const char *domainname, const u8 mode,
				     const u8 profile)
{
	char *buf;
	char *cp;
	int len;
	int len2;
	if (ccs_can_save_audit_log(false) < 0)
		return -ENOMEM;
	len = strlen(domainname) + 32;
	buf = ccs_init_audit_log(&len, profile, mode, NULL);
	if (!buf)
		return -ENOMEM;
	cp = strchr(buf, '\n');
	if (!cp) {
		ccs_free(buf);
		return -ENOMEM;
	}
	*++cp = '\0';
	len2 = strlen(buf);
	snprintf(buf + len2, len - len2 - 1, "%s\nuse_profile %u\n",
		 domainname, profile);
	return ccs_write_audit_log(buf, false);
}

/* The list for "struct domain_initializer_entry". */
static LIST1_HEAD(domain_initializer_list);

/**
 * update_domain_initializer_entry - Update "struct domain_initializer_entry" list.
 *
 * @domainname: The name of domain. May be NULL.
 * @program:    The name of program.
 * @is_not:     True if it is "no_initialize_domain" entry.
 * @is_delete:  True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_domain_initializer_entry(const char *domainname,
					   const char *program,
					   const bool is_not,
					   const bool is_delete)
{
	struct domain_initializer_entry *new_entry;
	struct domain_initializer_entry *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_program;
	const struct path_info *saved_domainname = NULL;
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
	list1_for_each_entry(ptr, &domain_initializer_list, list) {
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
	list1_add_tail_mb(&new_entry->list, &domain_initializer_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * ccs_read_domain_initializer_policy - Read "struct domain_initializer_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_domain_initializer_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &domain_initializer_list) {
		const char *no;
		const char *from = "";
		const char *domain = "";
		struct domain_initializer_entry *ptr;
		ptr = list1_entry(pos, struct domain_initializer_entry, list);
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
 * ccs_write_domain_initializer_policy - Write "struct domain_initializer_entry" list.
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
		return update_domain_initializer_entry(cp + 6, data, is_not,
						       is_delete);
	}
	return update_domain_initializer_entry(NULL, data, is_not, is_delete);
}

/**
 * is_domain_initializer - Check whether the given program causes domainname reinitialization.
 *
 * @domainname: The name of domain.
 * @program:    The name of program.
 * @last_name:  The last component of @domainname.
 *
 * Returns true if executing @program reinitializes domain transition,
 * false otherwise.
 */
static bool is_domain_initializer(const struct path_info *domainname,
				  const struct path_info *program,
				  const struct path_info *last_name)
{
	struct domain_initializer_entry *ptr;
	bool flag = false;
	list1_for_each_entry(ptr,  &domain_initializer_list, list) {
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

/* The list for "struct domain_keeper_entry". */
static LIST1_HEAD(domain_keeper_list);

/**
 * update_domain_keeper_entry - Update "struct domain_keeper_entry" list.
 *
 * @domainname: The name of domain.
 * @program:    The name of program. May be NULL.
 * @is_not:     True if it is "no_keep_domain" entry.
 * @is_delete:  True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_domain_keeper_entry(const char *domainname,
				      const char *program,
				      const bool is_not, const bool is_delete)
{
	struct domain_keeper_entry *new_entry;
	struct domain_keeper_entry *ptr;
	const struct path_info *saved_domainname;
	const struct path_info *saved_program = NULL;
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
	list1_for_each_entry(ptr, &domain_keeper_list, list) {
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
	list1_add_tail_mb(&new_entry->list, &domain_keeper_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * ccs_write_domain_keeper_policy - Write "struct domain_keeper_entry" list.
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
		return update_domain_keeper_entry(cp + 6, data,
						  is_not, is_delete);
	}
	return update_domain_keeper_entry(data, NULL, is_not, is_delete);
}

/**
 * ccs_read_domain_keeper_policy - Read "struct domain_keeper_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_domain_keeper_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &domain_keeper_list) {
		struct domain_keeper_entry *ptr;
		const char *no;
		const char *from = "";
		const char *program = "";
		ptr = list1_entry(pos, struct domain_keeper_entry, list);
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
 * is_domain_keeper - Check whether the given program causes domain transition suppression.
 *
 * @domainname: The name of domain.
 * @program:    The name of program.
 * @last_name:  The last component of @domainname.
 *
 * Returns true if executing @program supresses domain transition,
 * false otherwise.
 */
static bool is_domain_keeper(const struct path_info *domainname,
			     const struct path_info *program,
			     const struct path_info *last_name)
{
	struct domain_keeper_entry *ptr;
	bool flag = false;
	list1_for_each_entry(ptr, &domain_keeper_list, list) {
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

/* The list for "struct alias_entry". */
static LIST1_HEAD(alias_list);

/**
 * update_alias_entry - Update "struct alias_entry" list.
 *
 * @original_name: The original program's real name.
 * @aliased_name:  The symbolic program's symbolic link's name.
 * @is_delete:     True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_alias_entry(const char *original_name,
			      const char *aliased_name,
			      const bool is_delete)
{
	struct alias_entry *new_entry;
	struct alias_entry *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_original_name;
	const struct path_info *saved_aliased_name;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(original_name, 1, -1, -1, __func__) ||
	    !ccs_is_correct_path(aliased_name, 1, -1, -1, __func__))
		return -EINVAL; /* No patterns allowed. */
	saved_original_name = ccs_save_name(original_name);
	saved_aliased_name = ccs_save_name(aliased_name);
	if (!saved_original_name || !saved_aliased_name)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &alias_list, list) {
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
	list1_add_tail_mb(&new_entry->list, &alias_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * ccs_read_alias_policy - Read "struct alias_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_alias_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &alias_list) {
		struct alias_entry *ptr;
		ptr = list1_entry(pos, struct alias_entry, list);
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
 * ccs_write_alias_policy - Write "struct alias_entry" list.
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
	return update_alias_entry(data, cp, is_delete);
}

/* The list for "struct aggregator_entry". */
static LIST1_HEAD(aggregator_list);

/**
 * update_aggregator_entry - Update "struct aggregator_entry" list.
 *
 * @original_name:   The original program's name.
 * @aggregated_name: The aggregated program's name.
 * @is_delete:       True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_aggregator_entry(const char *original_name,
				   const char *aggregated_name,
				   const bool is_delete)
{
	struct aggregator_entry *new_entry;
	struct aggregator_entry *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_original_name;
	const struct path_info *saved_aggregated_name;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(original_name, 1, 0, -1, __func__) ||
	    !ccs_is_correct_path(aggregated_name, 1, -1, -1, __func__))
		return -EINVAL;
	saved_original_name = ccs_save_name(original_name);
	saved_aggregated_name = ccs_save_name(aggregated_name);
	if (!saved_original_name || !saved_aggregated_name)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &aggregator_list, list) {
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
	list1_add_tail_mb(&new_entry->list, &aggregator_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * ccs_read_aggregator_policy - Read "struct aggregator_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_aggregator_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &aggregator_list) {
		struct aggregator_entry *ptr;
		ptr = list1_entry(pos, struct aggregator_entry, list);
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
 * ccs_write_aggregator_policy - Write "struct aggregator_entry" list.
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
	return update_aggregator_entry(data, cp, is_delete);
}

/* Domain create/delete/undelete handler. */

/* #define DEBUG_DOMAIN_UNDELETE */

/**
 * ccs_delete_domain - Delete a domain.
 *
 * @domainname: The name of domain.
 *
 * Returns 0.
 */
int ccs_delete_domain(char *domainname)
{
	struct domain_info *domain;
	struct path_info name;
	name.name = domainname;
	ccs_fill_path_info(&name);
	mutex_lock(&new_domain_assign_lock);
#ifdef DEBUG_DOMAIN_UNDELETE
	printk(KERN_DEBUG "ccs_delete_domain %s\n", domainname);
	list1_for_each_entry(domain, &domain_list, list) {
		if (ccs_pathcmp(domain->domainname, &name))
			continue;
		printk(KERN_DEBUG "List: %p %u\n", domain, domain->is_deleted);
	}
#endif
	/* Is there an active domain? */
	list1_for_each_entry(domain, &domain_list, list) {
		struct domain_info *domain2;
		/* Never delete KERNEL_DOMAIN */
		if (domain == &KERNEL_DOMAIN)
			continue;
		if (domain->is_deleted ||
		    ccs_pathcmp(domain->domainname, &name))
			continue;
		/* Mark already deleted domains as non undeletable. */
		list1_for_each_entry(domain2, &domain_list, list) {
			if (!domain2->is_deleted ||
			    ccs_pathcmp(domain2->domainname, &name))
				continue;
#ifdef DEBUG_DOMAIN_UNDELETE
			if (domain2->is_deleted != 255)
				printk(KERN_DEBUG
				       "Marked %p as non undeletable\n",
				       domain2);
#endif
			domain2->is_deleted = 255;
		}
		/* Delete and mark active domain as undeletable. */
		domain->is_deleted = 1;
#ifdef DEBUG_DOMAIN_UNDELETE
		printk(KERN_DEBUG "Marked %p as undeletable\n", domain);
#endif
		break;
	}
	mutex_unlock(&new_domain_assign_lock);
	return 0;
}

/**
 * ccs_undelete_domain - Undelete a domain.
 *
 * @domainname: The name of domain.
 *
 * Returns pointer to "struct domain_info" on success, NULL otherwise.
 */
struct domain_info *ccs_undelete_domain(const char *domainname)
{
	struct domain_info *domain;
	struct domain_info *candidate_domain = NULL;
	struct path_info name;
	name.name = domainname;
	ccs_fill_path_info(&name);
	mutex_lock(&new_domain_assign_lock);
#ifdef DEBUG_DOMAIN_UNDELETE
	printk(KERN_DEBUG "ccs_undelete_domain %s\n", domainname);
	list1_for_each_entry(domain, &domain_list, list) {
		if (ccs_pathcmp(domain->domainname, &name))
			continue;
		printk(KERN_DEBUG "List: %p %u\n", domain, domain->is_deleted);
	}
#endif
	list1_for_each_entry(domain, &domain_list, list) {
		if (ccs_pathcmp(&name, domain->domainname))
			continue;
		if (!domain->is_deleted) {
			/* This domain is active. I can't undelete. */
			candidate_domain = NULL;
#ifdef DEBUG_DOMAIN_UNDELETE
			printk(KERN_DEBUG "%p is active. I can't undelete.\n",
			       domain);
#endif
			break;
		}
		/* Is this domain undeletable? */
		if (domain->is_deleted == 1)
			candidate_domain = domain;
	}
	if (candidate_domain) {
		candidate_domain->is_deleted = 0;
#ifdef DEBUG_DOMAIN_UNDELETE
		printk(KERN_DEBUG "%p was undeleted.\n", candidate_domain);
#endif
	}
	mutex_unlock(&new_domain_assign_lock);
	return candidate_domain;
}

/**
 * ccs_find_or_assign_new_domain - Create a domain.
 *
 * @domainname: The name of domain.
 * @profile:    Profile number to assign if the domain was newly created.
 *
 * Returns pointer to "struct domain_info" on success, NULL otherwise.
 */
struct domain_info *ccs_find_or_assign_new_domain(const char *domainname,
						  const u8 profile)
{
	struct domain_info *domain = NULL;
	const struct path_info *saved_domainname;
	mutex_lock(&new_domain_assign_lock);
	domain = ccs_find_domain(domainname);
	if (domain)
		goto out;
	if (!ccs_is_correct_domain(domainname, __func__))
		goto out;
	saved_domainname = ccs_save_name(domainname);
	if (!saved_domainname)
		goto out;
	/* Can I reuse memory of deleted domain? */
	list1_for_each_entry(domain, &domain_list, list) {
		struct task_struct *p;
		struct acl_info *ptr;
		bool flag;
		if (!domain->is_deleted ||
		    domain->domainname != saved_domainname)
			continue;
		flag = false;
		/***** CRITICAL SECTION START *****/
		read_lock(&tasklist_lock);
		for_each_process(p) {
			if (p->domain_info != domain)
				continue;
			flag = true;
			break;
		}
		read_unlock(&tasklist_lock);
		/***** CRITICAL SECTION END *****/
		if (flag)
			continue;
#ifdef DEBUG_DOMAIN_UNDELETE
		printk(KERN_DEBUG "Reusing %p %s\n", domain,
		       domain->domainname->name);
#endif
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			ptr->type |= ACL_DELETED;
		}
		/*
		 * Don't use ccs_set_domain_flag() because
		 * new_domain_assign_lock is held.
		 */
		domain->flags = 0;
		domain->profile = profile;
		domain->quota_warned = false;
		mb(); /* Avoid out-of-order execution. */
		domain->is_deleted = 0;
		goto out;
	}
	/* No memory reusable. Create using new memory. */
	domain = ccs_alloc_element(sizeof(*domain));
	if (domain) {
		INIT_LIST1_HEAD(&domain->acl_info_list);
		domain->domainname = saved_domainname;
		domain->profile = profile;
		list1_add_tail_mb(&domain->list, &domain_list);
	}
 out:
	mutex_unlock(&new_domain_assign_lock);
	return domain;
}

/**
 * get_argv0 - Get argv[0].
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @tmp:  Buffer for temporal use.
 *
 * Returns true on success, false otherwise.
 */
static bool get_argv0(struct linux_binprm *bprm, struct ccs_page_buffer *tmp)
{
	char *arg_ptr = tmp->buffer;
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int i = pos / PAGE_SIZE;
	int offset = pos % PAGE_SIZE;
	bool done = false;
	if (!bprm->argc)
		goto out;
	while (1) {
		struct page *page;
		const char *kaddr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
		if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page,
				   NULL) <= 0)
			goto out;
		pos += PAGE_SIZE - offset;
#else
		page = bprm->page[i];
#endif
		/* Map. */
		kaddr = kmap(page);
		if (!kaddr) { /* Mapping failed. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
			put_page(page);
#endif
			goto out;
		}
		/* Read. */
		while (offset < PAGE_SIZE) {
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
		/* Unmap. */
		kunmap(page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
		put_page(page);
#endif
		i++;
		offset = 0;
		if (done)
			break;
	}
	return true;
 out:
	return false;
}

/**
 * find_next_domain - Find a domain.
 *
 * @bprm:           Pointer to "struct linux_binprm".
 * @next_domain:    Pointer to pointer to "struct domain_info".
 * @path_to_verify: Pathname to verify. May be NULL.
 * @tmp:            Buffer for temporal use.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int find_next_domain(struct linux_binprm *bprm,
			    struct domain_info **next_domain,
			    const struct path_info *path_to_verify,
			    struct ccs_page_buffer *tmp)
{
	/*
	 * This function assumes that the size of buffer returned by
	 * ccs_realpath() = CCS_MAX_PATHNAME_LEN.
	 */
	struct domain_info *old_domain = current->domain_info;
	struct domain_info *domain = NULL;
	const char *old_domain_name = old_domain->domainname->name;
	const char *original_name = bprm->filename;
	char *new_domain_name = NULL;
	char *real_program_name = NULL;
	char *symlink_program_name = NULL;
	const u8 mode = ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE);
	const bool is_enforce = (mode == 3);
	int retval;
	struct path_info r; /* real name */
	struct path_info s; /* symlink name */
	struct path_info l; /* last name */

	{
		/*
		 * Built-in initializers. This is needed because policies are
		 * not loaded until starting /sbin/init.
		 */
		static bool first = true;
		if (first) {
			update_domain_initializer_entry(NULL, "/sbin/hotplug",
							false, false);
			update_domain_initializer_entry(NULL, "/sbin/modprobe",
							false, false);
			first = false;
		}
	}

	/* Get ccs_realpath of program. */
	retval = -ENOENT; /* I hope ccs_realpath() won't fail with -ENOMEM. */
	real_program_name = ccs_realpath(original_name);
	if (!real_program_name)
		goto out;
	/* Get ccs_realpath of symbolic link. */
	symlink_program_name = ccs_realpath_nofollow(original_name);
	if (!symlink_program_name)
		goto out;

	r.name = real_program_name;
	ccs_fill_path_info(&r);
	s.name = symlink_program_name;
	ccs_fill_path_info(&s);
	l.name = ccs_get_last_name(old_domain);
	ccs_fill_path_info(&l);

	if (path_to_verify) {
		if (ccs_pathcmp(&r, path_to_verify)) {
			/* Failed to verify execute handler. */
			static u8 counter = 20;
			if (counter) {
				counter--;
				printk(KERN_WARNING "Failed to verify: %s\n",
				       path_to_verify->name);
			}
			goto out;
		}
		goto calculate_domain;
	}

	/* Check 'alias' directive. */
	if (ccs_pathcmp(&r, &s)) {
		struct alias_entry *ptr;
		/* Is this program allowed to be called via symbolic links? */
		list1_for_each_entry(ptr, &alias_list, list) {
			if (ptr->is_deleted ||
			    ccs_pathcmp(&r, ptr->original_name) ||
			    ccs_pathcmp(&s, ptr->aliased_name))
				continue;
			memset(real_program_name, 0, CCS_MAX_PATHNAME_LEN);
			strncpy(real_program_name, ptr->aliased_name->name,
				CCS_MAX_PATHNAME_LEN - 1);
			ccs_fill_path_info(&r);
			break;
		}
	}

	/* Compare basename of real_program_name and argv[0] */
	if (bprm->argc > 0 && ccs_check_flags(CCS_TOMOYO_MAC_FOR_ARGV0)) {
		char *base_argv0 = tmp->buffer;
		const char *base_filename;
		retval = -ENOMEM;
		if (!get_argv0(bprm, tmp))
			goto out;
		base_filename = strrchr(real_program_name, '/');
		if (!base_filename)
			base_filename = real_program_name;
		else
			base_filename++;
		if (strcmp(base_argv0, base_filename)) {
			retval = ccs_check_argv0_perm(&r, base_argv0);
			if (retval)
				goto out;
		}
	}

	/* Check 'aggregator' directive. */
	{
		struct aggregator_entry *ptr;
		/* Is this program allowed to be aggregated? */
		list1_for_each_entry(ptr, &aggregator_list, list) {
			if (ptr->is_deleted ||
			    !ccs_path_matches_pattern(&r, ptr->original_name))
				continue;
			memset(real_program_name, 0, CCS_MAX_PATHNAME_LEN);
			strncpy(real_program_name, ptr->aggregated_name->name,
				CCS_MAX_PATHNAME_LEN - 1);
			ccs_fill_path_info(&r);
			break;
		}
	}

	/* Check execute permission. */
	retval = ccs_check_exec_perm(&r, bprm, tmp);
	if (retval < 0)
		goto out;

 calculate_domain:
	new_domain_name = tmp->buffer;
	if (is_domain_initializer(old_domain->domainname, &r, &l)) {
		/* Transit to the child of KERNEL_DOMAIN domain. */
		snprintf(new_domain_name, CCS_MAX_PATHNAME_LEN + 1,
			 ROOT_NAME " " "%s", real_program_name);
	} else if (old_domain == &KERNEL_DOMAIN && !sbin_init_started) {
		/*
		 * Needn't to transit from kernel domain before starting
		 * /sbin/init. But transit from kernel domain if executing
		 * initializers because they might start before /sbin/init.
		 */
		domain = old_domain;
	} else if (is_domain_keeper(old_domain->domainname, &r, &l)) {
		/* Keep current domain. */
		domain = old_domain;
	} else {
		/* Normal domain transition. */
		snprintf(new_domain_name, CCS_MAX_PATHNAME_LEN + 1,
			 "%s %s", old_domain_name, real_program_name);
	}
	if (domain || strlen(new_domain_name) >= CCS_MAX_PATHNAME_LEN)
		goto done;
	domain = ccs_find_domain(new_domain_name);
	if (domain)
		goto done;
	if (is_enforce && ccs_check_supervisor("#Need to create domain\n%s\n",
					       new_domain_name))
			goto done;
	domain = ccs_find_or_assign_new_domain(new_domain_name,
					       old_domain->profile);
	if (domain)
		audit_domain_creation_log(new_domain_name, mode,
					  domain->profile);
 done:
	if (!domain) {
		printk(KERN_WARNING "TOMOYO-ERROR: Domain '%s' not defined.\n",
		       new_domain_name);
		if (is_enforce)
			retval = -EPERM;
		else
			ccs_set_domain_flag(old_domain, false,
					    DOMAIN_FLAGS_TRANSITION_FAILED);
	} else {
		retval = 0;
	}
 out:
	ccs_free(real_program_name);
	ccs_free(symlink_program_name);
	*next_domain = domain ? domain : old_domain;
	return retval;
}

/**
 * check_environ - Check permission for environment variable names.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @tmp:  Buffer for temporal use.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int check_environ(struct linux_binprm *bprm, struct ccs_page_buffer *tmp)
{
	const u8 profile = current->domain_info->profile;
	const u8 mode = ccs_check_flags(CCS_TOMOYO_MAC_FOR_ENV);
	char *arg_ptr = tmp->buffer;
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int i = pos / PAGE_SIZE;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	/* printk(KERN_DEBUG "start %d %d\n", argv_count, envp_count); */
	int error = -ENOMEM;
	if (!mode || !envp_count)
		return 0;
	while (error == -ENOMEM) {
		struct page *page;
		const char *kaddr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
		if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page,
				   NULL) <= 0)
			goto out;
		pos += PAGE_SIZE - offset;
#else
		page = bprm->page[i];
#endif
		/* Map. */
		kaddr = kmap(page);
		if (!kaddr) { /* Mapping failed. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
			put_page(page);
#endif
			goto out;
		}
		/* Read. */
		while (argv_count && offset < PAGE_SIZE) {
			if (!kaddr[offset++])
				argv_count--;
		}
		if (argv_count)
			goto unmap_page;
		while (offset < PAGE_SIZE) {
			const unsigned char c = kaddr[offset++];
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
			if (ccs_check_env_perm(arg_ptr, profile, mode)) {
				error = -EPERM;
				break;
			}
			if (!--envp_count) {
				error = 0;
				break;
			}
			arg_len = 0;
		}
 unmap_page:
		/* Unmap. */
		kunmap(page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
		put_page(page);
#endif
		i++;
		offset = 0;
	}
 out:
	if (error && mode != 3)
		error = 0;
	return error;
}

/**
 * unescape - Unescape escaped string.
 *
 * @dest: String to unescape.
 *
 * Returns nothing.
 */
static void unescape(unsigned char *dest)
{
	unsigned char *src = dest;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	while ((c = *src++) != '\0') {
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
 * root_depth - Get number of directories to strip.
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 *
 * Returns number of directories to strip.
 */
static inline int root_depth(struct dentry *dentry, struct vfsmount *vfsmnt)
{
	int depth = 0;
	/***** CRITICAL SECTION START *****/
	spin_lock(&dcache_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	spin_lock(&vfsmount_lock);
#endif
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	spin_unlock(&vfsmount_lock);
#endif
	spin_unlock(&dcache_lock);
	/***** CRITICAL SECTION END *****/
	return depth;
}

/**
 * get_root_depth - return the depth of root directory.
 *
 * Returns number of directories to strip.
 */
static int get_root_depth(void)
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
	depth = root_depth(dentry, vfsmnt);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	path_put(&root);
#else
	dput(dentry);
	mntput(vfsmnt);
#endif
	return depth;
}

/**
 * try_alt_exec - Try to start execute handler.
 *
 * @bprm:        Pointer to "struct linux_binprm".
 * @filename:    The name of requested program.
 * @work:        Pointer to pointer to the name of execute handler.
 * @next_domain: Pointer to pointer to "struct domain_info".
 * @tmp:         Buffer for temporal use.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int try_alt_exec(struct linux_binprm *bprm,
			const struct path_info *filename, char **work,
			struct domain_info **next_domain,
			struct ccs_page_buffer *tmp)
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
	 *    = current->domain_info->domainname->name
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
	struct file *filp;
	int retval;
	const int original_argc = bprm->argc;
	const int original_envc = bprm->envc;
	struct task_struct *task = current;
	char *buffer = tmp->buffer;
	/* Allocate memory for execute handler's pathname. */
	char *execute_handler = ccs_alloc(sizeof(struct ccs_page_buffer));
	*work = execute_handler;
	if (!execute_handler)
		return -ENOMEM;
	strncpy(execute_handler, filename->name,
		sizeof(struct ccs_page_buffer) - 1);
	unescape(execute_handler);

	/* Close the requested program's dentry. */
	allow_write_access(bprm->file);
	fput(bprm->file);
	bprm->file = NULL;

	{ /* Adjust root directory for open_exec(). */
		int depth = get_root_depth();
		char *cp = execute_handler;
		if (!*cp || *cp != '/')
			return -ENOENT;
		while (depth) {
			cp = strchr(cp + 1, '/');
			if (!cp)
				return -ENOENT;
			depth--;
		}
		memmove(execute_handler, cp, strlen(cp) + 1);
	}

	/* Move envp[] to argv[] */
	bprm->argc += bprm->envc;
	bprm->envc = 0;

	/* Set argv[6] */
	{
		snprintf(buffer, sizeof(struct ccs_page_buffer) - 1, "%d",
			 original_envc);
		retval = copy_strings_kernel(1, &buffer, bprm);
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[5] */
	{
		snprintf(buffer, sizeof(struct ccs_page_buffer) - 1, "%d",
			 original_argc);
		retval = copy_strings_kernel(1, &buffer, bprm);
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
		const u32 tomoyo_flags = task->tomoyo_flags;
		snprintf(buffer, sizeof(struct ccs_page_buffer) - 1,
			 "pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d "
			 "sgid=%d fsuid=%d fsgid=%d state[0]=%u "
			 "state[1]=%u state[2]=%u",
			 task->pid, task->uid, task->gid, task->euid,
			 task->egid, task->suid, task->sgid, task->fsuid,
			 task->fsgid, (u8) (tomoyo_flags >> 24),
			 (u8) (tomoyo_flags >> 16), (u8) (tomoyo_flags >> 8));
		retval = copy_strings_kernel(1, &buffer, bprm);
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
			snprintf(buffer, sizeof(struct ccs_page_buffer) - 1,
				 "<unknown>");
			retval = copy_strings_kernel(1, &buffer, bprm);
		}
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[1] */
	{
		strncpy(buffer, task->domain_info->domainname->name,
			sizeof(struct ccs_page_buffer) - 1);
		retval = copy_strings_kernel(1, &buffer, bprm);
		if (retval < 0)
			goto out;
		bprm->argc++;
	}

	/* Set argv[0] */
	{
		retval = copy_strings_kernel(1, &execute_handler, bprm);
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
	filp = open_exec(execute_handler);
	if (IS_ERR(filp)) {
		retval = PTR_ERR(filp);
		goto out;
	}
	bprm->file = filp;
	bprm->filename = execute_handler;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	bprm->interp = execute_handler;
#endif
	retval = prepare_binprm(bprm);
	if (retval < 0)
		goto out;
	task->tomoyo_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	retval = find_next_domain(bprm, next_domain, filename, tmp);
	task->tomoyo_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
 out:
	return retval;
}

/**
 * find_execute_handler - Find an execute handler.
 *
 * @type: Type of execute handler.
 *
 * Returns pointer to "struct path_info" if found, NULL otherwise.
 */
static const struct path_info *find_execute_handler(const u8 type)
{
	struct task_struct *task = current;
	const struct domain_info *domain = task->domain_info;
	struct acl_info *ptr;
	/*
	 * Don't use execute handler if the current process is
	 * marked as execute handler to avoid infinite execute handler loop.
	 */
	if (task->tomoyo_flags & TOMOYO_TASK_IS_EXECUTE_HANDLER)
		return NULL;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct execute_handler_record *acl;
		if (ptr->type != type)
			continue;
		acl = container_of(ptr, struct execute_handler_record, head);
		return acl->handler;
	}
	return NULL;
}

/**
 * search_binary_handler_with_transition - Perform domain transition.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @regs: Pointer to "struct pt_regs".
 *
 * Returns result of search_binary_handler() on success,
 * negative value otherwise.
 */
int search_binary_handler_with_transition(struct linux_binprm *bprm,
					  struct pt_regs *regs)
{
	struct task_struct *task = current;
	struct domain_info *next_domain = NULL;
	struct domain_info *prev_domain = task->domain_info;
	const struct path_info *handler;
	int retval;
	/*
	 * "work" holds path to program.
	 * Thus, keep valid until search_binary_handler() finishes.
	 */
	char *work = NULL;
	struct ccs_page_buffer *buf = ccs_alloc(sizeof(struct ccs_page_buffer));
	ccs_load_policy(bprm->filename);
	if (!buf)
		return -ENOMEM;
	/* printk(KERN_DEBUG "rootdepth=%d\n", get_root_depth()); */
	handler = find_execute_handler(TYPE_EXECUTE_HANDLER);
	if (handler) {
		retval = try_alt_exec(bprm, handler, &work, &next_domain, buf);
		if (!retval)
			audit_execute_handler_log(true, work, bprm);
		goto ok;
	}
	retval = find_next_domain(bprm, &next_domain, NULL, buf);
	if (retval != -EPERM)
		goto ok;
	handler = find_execute_handler(TYPE_DENIED_EXECUTE_HANDLER);
	if (handler) {
		retval = try_alt_exec(bprm, handler, &work, &next_domain, buf);
		if (!retval)
			audit_execute_handler_log(false, work, bprm);
	}
 ok:
	if (retval)
		goto out;
	task->domain_info = next_domain;
	retval = check_environ(bprm, buf);
	if (retval)
		goto out;
	task->tomoyo_flags |= TOMOYO_CHECK_READ_FOR_OPEN_EXEC;
	retval = search_binary_handler(bprm, regs);
	task->tomoyo_flags &= ~TOMOYO_CHECK_READ_FOR_OPEN_EXEC;
 out:
	/* Return to previous domain if execution failed. */
	if (retval < 0)
		task->domain_info = prev_domain;
	/* Mark the current process as execute handler. */
	else if (handler)
		task->tomoyo_flags |= TOMOYO_TASK_IS_EXECUTE_HANDLER;
	/* Mark the current process as normal process. */
	else
		task->tomoyo_flags &= ~TOMOYO_TASK_IS_EXECUTE_HANDLER;
	ccs_free(work);
	ccs_free(buf);
	return retval;
}

#else

/**
 * search_binary_handler_with_transition - Wrapper for search_binary_handler().
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @regs: Pointer to "struct pt_regs".
 *
 * Returns the result of search_binary_handler().
 */
int search_binary_handler_with_transition(struct linux_binprm *bprm,
					  struct pt_regs *regs)
{
#ifdef CONFIG_SAKURA
	ccs_load_policy(bprm->filename);
#endif
	return search_binary_handler(bprm, regs);
}

#endif
