/*
 * security/ccsecurity/environ.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2   2010/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

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
	if (!is_granted)
		ccs_warn_log(r, "environ %s", env);
	return ccs_write_log(is_granted, r, CCS_KEYWORD_ALLOW_ENV "%s\n",
				   env);
}

/**
 * ccs_env_acl - Check permission for environment variable's name.
 *
 * @r:       Pointer to "struct ccs_request_info".
 * @environ: The name of environment variable.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_env_acl(struct ccs_request_info *r, const char *environ)
{
	const struct ccs_domain_info *domain = ccs_current_domain();
	int error = -EPERM;
	struct ccs_acl_info *ptr;
	struct ccs_path_info env;
	env.name = environ;
	ccs_fill_path_info(&env);
 retry:
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_env_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_ENV_ACL)
			continue;
		acl = container_of(ptr, struct ccs_env_acl, head);
		if (!ccs_condition(r, ptr->cond) ||
		    !ccs_path_matches_pattern(&env, acl->env))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	if (error && !domain->ignore_global_allow_env &&
	    domain != &ccs_global_domain) {
		domain = &ccs_global_domain;
		goto retry;
	}
	return error;
}

/**
 * ccs_env_perm - Check permission for environment variable's name.
 *
 * @r:       Pointer to "struct ccs_request_info".
 * @env:     The name of environment variable.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_env_perm(struct ccs_request_info *r, const char *env)
{
	int error;
	if (!env || !*env)
		return 0;
	do {
		error = ccs_env_acl(r, env);
		ccs_audit_env_log(r, env, !error);
		if (!error)
			break;
		error = ccs_supervisor(r, CCS_KEYWORD_ALLOW_ENV "%s\n", env);
	} while (error == CCS_RETRY_REQUEST);
	return error;
}

static bool ccs_same_env_entry(const struct ccs_acl_info *a,
			       const struct ccs_acl_info *b)
{
	const struct ccs_env_acl *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_env_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->head.type == p2->head.type && p1->head.cond == p2->head.cond
		&& p1->head.type == CCS_TYPE_ENV_ACL && p1->env == p2->env;
}

/**
 * ccs_write_env - Write "struct ccs_env_acl" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_env(char *data, struct ccs_domain_info *domain,
		  struct ccs_condition *condition, const bool is_delete)
{
	struct ccs_env_acl e = {
		.head.type = CCS_TYPE_ENV_ACL,
		.head.cond = condition
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_correct_path(data, 0, 0, 0) || strchr(data, '='))
		return -EINVAL;
	e.env = ccs_get_name(data);
	if (!e.env)
		return error;
	error = ccs_update_domain(&e.head, sizeof(e), is_delete, domain,
				  ccs_same_env_entry, NULL);
	ccs_put_name(e.env);
	return error;
}
