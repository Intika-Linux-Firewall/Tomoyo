/*
 * fs/tomoyo_exec.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.8   2009/05/28
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>

/**
 * ccs_audit_argv0_log - Audit argv[0] log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @filename:   The fullpath of program.
 * @argv0:      The basename of argv[0].
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_argv0_log(struct ccs_request_info *r, const char *filename,
			       const char *argv0, const bool is_granted)
{
	return ccs_write_audit_log(is_granted, r, KEYWORD_ALLOW_ARGV0
				   "%s %s\n", filename, argv0);
}

/**
 * ccs_update_argv0_entry - Update "struct ccs_argv0_acl_record" list.
 *
 * @filename:  The fullpath of the program.
 * @argv0:     The basename of argv[0].
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_argv0_entry(const char *filename, const char *argv0,
				  struct ccs_domain_info *domain,
				  struct ccs_condition *condition,
				  const bool is_delete)
{
	struct ccs_argv0_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
	const struct ccs_path_info *saved_filename;
	const struct ccs_path_info *saved_argv0;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(filename, 1, 0, -1) ||
	    !ccs_is_correct_path(argv0, -1, 0, -1) ||
	    strchr(argv0, '/'))
		return -EINVAL;
	saved_filename = ccs_get_name(filename);
	saved_argv0 = ccs_get_name(argv0);
	if (!saved_filename || !saved_argv0)
		goto out;
	if (is_delete)
		goto delete;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_argv0_acl_record *acl;
		if (ccs_acl_type1(ptr) != TYPE_ARGV0_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_argv0_acl_record, head);
		if (acl->filename != saved_filename ||
		    acl->argv0 != saved_argv0)
			continue;
		error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (error && ccs_memory_ok(entry)) {
		entry->head.type = TYPE_ARGV0_ACL;
		entry->head.cond = condition;	
		entry->filename = saved_filename;
		saved_filename = NULL;
		entry->argv0 = saved_argv0;
		saved_argv0 = NULL;
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	goto out;
 delete:
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_argv0_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_ARGV0_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_argv0_acl_record, head);
		if (acl->filename != saved_filename ||
		    acl->argv0 != saved_argv0)
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(saved_filename);
	ccs_put_name(saved_argv0);
	kfree(entry);
	return error;
}

/**
 * ccs_check_argv0_acl - Check permission for argv[0].
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @filename: The fullpath of the program.
 * @argv0:    The basename of argv[0].
 *
 * Returns 0 on success, -EPERM otherwise.
 *
 * Caller holds srcu_read_lock(&ccs_ss).
 */
static int ccs_check_argv0_acl(struct ccs_request_info *r,
			       const struct ccs_path_info *filename,
			       const char *argv0)
{
	int error = -EPERM;
	struct ccs_domain_info *domain = r->domain;
	struct ccs_acl_info *ptr;
	struct ccs_path_info argv_0;
	argv_0.name = argv0;
	ccs_fill_path_info(&argv_0);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_argv0_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_ARGV0_ACL)
			continue;
		acl = container_of(ptr, struct ccs_argv0_acl_record, head);
		if (!ccs_check_condition(r, ptr) ||
		    !ccs_path_matches_pattern(filename, acl->filename) ||
		    !ccs_path_matches_pattern(&argv_0, acl->argv0))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	return error;
}

/**
 * ccs_check_argv0_perm - Check permission for argv[0].
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @filename: The fullpath of the program.
 * @argv0:    The basename of argv[0].
 *
 * Returns 0 on success, 1 on retry, negative value otherwise.
 */
int ccs_check_argv0_perm(struct ccs_request_info *r,
			 const struct ccs_path_info *filename,
			 const char *argv0)
{
	int error = 0;
	const bool is_enforce = (r->mode == 3);
	if (!ccs_can_sleep())
		return 0;
	if (!filename || !argv0 || !*argv0)
		return 0;
	error = ccs_check_argv0_acl(r, filename, argv0);
	ccs_audit_argv0_log(r, filename->name, argv0, !error);
	if (!error)
		return 0;
	if (ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "TOMOYO-%s: Run %s as %s denied for %s\n",
		       ccs_get_msg(is_enforce), filename->name, argv0,
		       ccs_get_last_name(r->domain));
	if (is_enforce)
		return ccs_check_supervisor(r, KEYWORD_ALLOW_ARGV0 "%s %s\n",
					    filename->name, argv0);
	if (r->mode == 1 && ccs_domain_quota_ok(r->domain)) {
		struct ccs_condition *cond = ccs_handler_cond();
		ccs_update_argv0_entry(filename->name, argv0,
				       r->domain, cond, false);
		ccs_put_condition(cond);
	}
	return 0;
}

/**
 * ccs_write_argv0_policy - Write "struct ccs_argv0_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_argv0_policy(char *data, struct ccs_domain_info *domain,
			   struct ccs_condition *condition,
			   const bool is_delete)
{
	char *argv0 = strchr(data, ' ');
	if (!argv0)
		return -EINVAL;
	*argv0++ = '\0';
	return ccs_update_argv0_entry(data, argv0, domain, condition,
				      is_delete);
}
