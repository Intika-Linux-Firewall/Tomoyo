/*
 * fs/tomoyo_env.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.8-pre   2009/05/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>

/**
 * ccs_audit_env_log - Audit environment variable name log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @env:        The name of environment variable.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_env_log(struct ccs_request_info *r, const char *env,
			     const bool is_granted)
{
	return ccs_write_audit_log(is_granted, r, KEYWORD_ALLOW_ENV "%s\n",
				   env);
}

/* The list for "struct ccs_globally_usable_env_entry". */
LIST_HEAD(ccs_globally_usable_env_list);

/**
 * ccs_update_globally_usable_env_entry - Update "struct ccs_globally_usable_env_entry" list.
 *
 * @env:       The name of environment variable.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_globally_usable_env_entry(const char *env,
						const bool is_delete)
{
	struct ccs_globally_usable_env_entry *entry = NULL;
	struct ccs_globally_usable_env_entry *ptr;
	const struct ccs_path_info *saved_env;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(env, 0, 0, 0, __func__) || strchr(env, '='))
		return -EINVAL;
	saved_env = ccs_get_name(env);
	if (!saved_env)
		return -ENOMEM;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	/***** WRITER SECTION START *****/
	down_write(&ccs_policy_lock);
	list_for_each_entry(ptr, &ccs_globally_usable_env_list, list) {
		if (ptr->env != saved_env)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry)) {
		entry->env = saved_env;
		saved_env = NULL;
		list_add_tail(&entry->list, &ccs_globally_usable_env_list);
		entry = NULL;
		error = 0;
	}
	up_write(&ccs_policy_lock);
	/***** WRITER SECTION END *****/
	ccs_put_name(saved_env);
	kfree(entry);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * ccs_is_globally_usable_env - Check whether the given environment variable is acceptable for all domains.
 *
 * @env: The name of environment variable.
 *
 * Returns true if @env is globally permitted environment variable's name,
 * false otherwise.
 */
static bool ccs_is_globally_usable_env(const struct ccs_path_info *env)
{
	struct ccs_globally_usable_env_entry *ptr;
	bool found = false;
	/***** READER SECTION START *****/
	down_read(&ccs_policy_lock);
	list_for_each_entry(ptr, &ccs_globally_usable_env_list, list) {
		if (ptr->is_deleted || !ccs_path_matches_pattern(env, ptr->env))
			continue;
		found = true;
		break;
	}
	up_read(&ccs_policy_lock);
	/***** READER SECTION END *****/
	return found;
}

/**
 * ccs_write_globally_usable_env_policy - Write "struct ccs_globally_usable_env_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_globally_usable_env_policy(char *data, const bool is_delete)
{
	return ccs_update_globally_usable_env_entry(data, is_delete);
}

/**
 * ccs_read_globally_usable_env_policy - Read "struct ccs_globally_usable_env_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, false otherwise.
 */
bool ccs_read_globally_usable_env_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	/***** READER SECTION START *****/
	down_read(&ccs_policy_lock);
	list_for_each_cookie(pos, head->read_var2.u.list,
			      &ccs_globally_usable_env_list) {
		struct ccs_globally_usable_env_entry *ptr;
		ptr = list_entry(pos, struct ccs_globally_usable_env_entry,
				  list);
		if (ptr->is_deleted)
			continue;
		done = ccs_io_printf(head, KEYWORD_ALLOW_ENV "%s\n",
				     ptr->env->name);
		if (!done)
			break;
	}
	up_read(&ccs_policy_lock);
	/***** READER SECTION END *****/
	return done;
}

/**
 * ccs_update_env_entry - Update "struct ccs_env_acl_record" list.
 *
 * @env:       The name of environment variable.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_env_entry(const char *env, struct ccs_domain_info *domain,
				const struct ccs_condition_list *condition,
				const bool is_delete)
{
	struct ccs_env_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
	const struct ccs_path_info *saved_env;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(env, 0, 0, 0, __func__) || strchr(env, '='))
		return -EINVAL;
	saved_env = ccs_get_name(env);
	if (!saved_env)
		goto out;
	if (is_delete)
		goto delete;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	/***** WRITER SECTION START *****/
	down_write(&ccs_policy_lock);
	list_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct ccs_env_acl_record *acl;
		if (ccs_acl_type1(ptr) != TYPE_ENV_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_env_acl_record, head);
		if (acl->env != saved_env)
			continue;
		error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (error && ccs_memory_ok(entry)) {
		entry->head.type = TYPE_ENV_ACL;
		entry->head.cond = condition;
		entry->env = saved_env;
		saved_env = NULL;
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	up_write(&ccs_policy_lock);
	/***** WRITER SECTION END *****/
	goto out;
 delete:
	/***** WRITER SECTION START *****/
	down_write(&ccs_policy_lock);
	list_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct ccs_env_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_ENV_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_env_acl_record, head);
		if (acl->env != saved_env)
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
	up_write(&ccs_policy_lock);
	/***** WRITER SECTION END *****/
 out:
	ccs_put_name(saved_env);
	kfree(entry);
	return error;
}

/**
 * ccs_check_env_acl - Check permission for environment variable's name.
 *
 * @r:       Pointer to "struct ccs_request_info".
 * @environ: The name of environment variable.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_env_acl(struct ccs_request_info *r, const char *environ)
{
	const struct ccs_domain_info *domain = r->cookie.u.domain;
	int error = -EPERM;
	struct ccs_acl_info *ptr;
	struct ccs_path_info env;
	env.name = environ;
	ccs_fill_path_info(&env);
	down_read(&ccs_policy_lock);
	list_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct ccs_env_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_ENV_ACL)
			continue;
		acl = container_of(ptr, struct ccs_env_acl_record, head);
		if (!ccs_check_condition(r, ptr) ||
		    !ccs_path_matches_pattern(&env, acl->env))
			continue;
		r->condition_cookie.u.cond = ptr->cond;
		error = 0;
		break;
	}
	up_read(&ccs_policy_lock);
	if (error && !domain->ignore_global_allow_env &&
	    ccs_is_globally_usable_env(&env))
		error = 0;
	return error;
}

/**
 * ccs_check_env_perm - Check permission for environment variable's name.
 *
 * @r:       Pointer to "struct ccs_request_info".
 * @env:     The name of environment variable.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_env_perm(struct ccs_request_info *r, const char *env)
{
	int error = 0;
	const bool is_enforce = (r->mode == 3);
	if (!ccs_can_sleep())
		return 0;
	if (!env || !*env)
		return 0;
 retry:
	error = ccs_check_env_acl(r, env);
	ccs_audit_env_log(r, env, !error);
	if (!error)
		return 0;
	if (ccs_verbose_mode(r->cookie.u.domain))
		printk(KERN_WARNING "TOMOYO-%s: Environ %s denied for %s\n",
		       ccs_get_msg(is_enforce), env,
		       ccs_get_last_name(r->cookie.u.domain));
	if (is_enforce) {
		error = ccs_check_supervisor(r, KEYWORD_ALLOW_ENV "%s\n", env);
		if (error == 1)
			goto retry;
		return error;
	}
	if (r->mode == 1 && ccs_domain_quota_ok(r->cookie.u.domain))
		ccs_update_env_entry(env, r->cookie.u.domain,
				     ccs_handler_cond(), false);
	return 0;
}

/**
 * ccs_write_env_policy - Write "struct ccs_env_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_env_policy(char *data, struct ccs_domain_info *domain,
			 const struct ccs_condition_list *condition,
			 const bool is_delete)
{
	return ccs_update_env_entry(data, domain, condition, is_delete);
}
