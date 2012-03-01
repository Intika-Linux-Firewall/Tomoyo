/*
 * fs/tomoyo_exec.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.6.9   2011/04/01
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
 * @condition: Pointer to "struct ccs_condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_argv0_entry(const char *filename, const char *argv0,
				  struct ccs_domain_info *domain,
				  const struct ccs_condition_list *condition,
				  const bool is_delete)
{
	static DEFINE_MUTEX(lock);
	struct ccs_acl_info *ptr;
	struct ccs_argv0_acl_record *acl;
	const struct ccs_path_info *saved_filename;
	const struct ccs_path_info *saved_argv0;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(filename, 1, 0, -1, __func__) ||
	    !ccs_is_correct_path(argv0, -1, 0, -1, __func__) ||
	    strchr(argv0, '/'))
		return -EINVAL;
	saved_filename = ccs_save_name(filename);
	saved_argv0 = ccs_save_name(argv0);
	if (!saved_filename || !saved_argv0)
		return -ENOMEM;
	mutex_lock(&lock);
	if (is_delete)
		goto delete;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != TYPE_ARGV0_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ccs_argv0_acl_record, head);
		if (acl->filename != saved_filename ||
		    acl->argv0 != saved_argv0)
			continue;
		error = ccs_add_domain_acl(NULL, ptr);
		goto out;
	}
	/* Not found. Append it to the tail. */
	acl = ccs_alloc_acl_element(TYPE_ARGV0_ACL, condition);
	if (!acl)
		goto out;
	acl->filename = saved_filename;
	acl->argv0 = saved_argv0;
	error = ccs_add_domain_acl(domain, &acl->head);
	goto out;
 delete:
	error = -ENOENT;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type2(ptr) != TYPE_ARGV0_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ccs_argv0_acl_record, head);
		if (acl->filename != saved_filename ||
		    acl->argv0 != saved_argv0)
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
 out:
	mutex_unlock(&lock);
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
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct ccs_argv0_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_ARGV0_ACL)
			continue;
		acl = container_of(ptr, struct ccs_argv0_acl_record, head);
		if (!ccs_check_condition(r, ptr) ||
		    !ccs_path_matches_pattern(filename, acl->filename) ||
		    !ccs_path_matches_pattern(&argv_0, acl->argv0))
			continue;
		r->cond = ccs_get_condition_part(ptr);
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
	if (r->mode == 1 && ccs_domain_quota_ok(r->domain))
		ccs_update_argv0_entry(filename->name, argv0, r->domain,
				       ccs_handler_cond(), false);
	return 0;
}

/**
 * ccs_write_argv0_policy - Write "struct ccs_argv0_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_argv0_policy(char *data, struct ccs_domain_info *domain,
			   const struct ccs_condition_list *condition,
			   const bool is_delete)
{
	char *argv0 = strchr(data, ' ');
	if (!argv0)
		return -EINVAL;
	*argv0++ = '\0';
	return ccs_update_argv0_entry(data, argv0, domain, condition,
				      is_delete);
}
