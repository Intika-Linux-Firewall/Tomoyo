/*
 * fs/tomoyo_env.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/04/01
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

/* Structure for "allow_env" keyword. */
struct ccs_globally_usable_env_entry {
	struct list1_head list;
	const struct ccs_path_info *env;
	bool is_deleted;
};

/* The list for "struct ccs_globally_usable_env_entry". */
static LIST1_HEAD(ccs_globally_usable_env_list);

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
	struct ccs_globally_usable_env_entry *new_entry;
	struct ccs_globally_usable_env_entry *ptr;
	static DEFINE_MUTEX(lock);
	const struct ccs_path_info *saved_env;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(env, 0, 0, 0, __func__) || strchr(env, '='))
		return -EINVAL;
	saved_env = ccs_save_name(env);
	if (!saved_env)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_globally_usable_env_list, list) {
		if (ptr->env != saved_env)
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
	new_entry->env = saved_env;
	list1_add_tail_mb(&new_entry->list, &ccs_globally_usable_env_list);
	error = 0;
 out:
	mutex_unlock(&lock);
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
	list1_for_each_entry(ptr, &ccs_globally_usable_env_list, list) {
		if (!ptr->is_deleted && ccs_path_matches_pattern(env, ptr->env))
			return true;
	}
	return false;
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
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2,
			      &ccs_globally_usable_env_list) {
		struct ccs_globally_usable_env_entry *ptr;
		ptr = list1_entry(pos, struct ccs_globally_usable_env_entry,
				  list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_ALLOW_ENV "%s\n",
				   ptr->env->name))
			goto out;
	}
	return true;
 out:
	return false;
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
	static DEFINE_MUTEX(lock);
	struct ccs_acl_info *ptr;
	struct ccs_env_acl_record *acl;
	const struct ccs_path_info *saved_env;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(env, 0, 0, 0, __func__) || strchr(env, '='))
		return -EINVAL;
	saved_env = ccs_save_name(env);
	if (!saved_env)
		return -ENOMEM;

	mutex_lock(&lock);
	if (is_delete)
		goto delete;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != TYPE_ENV_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ccs_env_acl_record, head);
		if (acl->env != saved_env)
			continue;
		error = ccs_add_domain_acl(NULL, ptr);
		goto out;
	}
	/* Not found. Append it to the tail. */
	acl = ccs_alloc_acl_element(TYPE_ENV_ACL, condition);
	if (!acl)
		goto out;
	acl->env = saved_env;
	error = ccs_add_domain_acl(domain, &acl->head);
	goto out;
 delete:
	error = -ENOENT;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type2(ptr) != TYPE_ENV_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ccs_env_acl_record, head);
		if (acl->env != saved_env)
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
 out:
	mutex_unlock(&lock);
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
	const struct ccs_domain_info *domain = r->domain;
	int error = -EPERM;
	struct ccs_acl_info *ptr;
	struct ccs_path_info env;
	env.name = environ;
	ccs_fill_path_info(&env);
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct ccs_env_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_ENV_ACL)
			continue;
		acl = container_of(ptr, struct ccs_env_acl_record, head);
		if (!ccs_check_condition(r, ptr) ||
		    !ccs_path_matches_pattern(&env, acl->env))
			continue;
		r->cond = ccs_get_condition_part(ptr);
		error = 0;
		break;
	}
	if (error &&
	    (domain->flags & DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_ENV) == 0 &&
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
	if (ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "TOMOYO-%s: Environ %s denied for %s\n",
		       ccs_get_msg(is_enforce), env,
		       ccs_get_last_name(r->domain));
	if (is_enforce) {
		error = ccs_check_supervisor(r, KEYWORD_ALLOW_ENV "%s\n", env);
		if (error == 1)
			goto retry;
		return error;
	}
	if (r->mode == 1 && ccs_domain_quota_ok(r->domain))
		ccs_update_env_entry(env, r->domain, ccs_handler_cond(), false);
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
