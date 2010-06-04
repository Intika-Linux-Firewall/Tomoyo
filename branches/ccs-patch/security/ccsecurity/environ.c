/*
 * security/ccsecurity/environ.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/06/04
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"


static bool ccs_check_env_acl(const struct ccs_request_info *r,
			      const struct ccs_acl_info *ptr)
{
	const struct ccs_env_acl *acl = container_of(ptr, typeof(*acl), head);
	return ccs_path_matches_pattern(r->param.environ.name, acl->env);
}

/**
 * ccs_audit_env_log - Audit environment variable name log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_env_log(struct ccs_request_info *r)
{
	const char *env = r->param.environ.name->name;
	ccs_write_log(r, CCS_KEYWORD_ALLOW_ENV "%s\n", env);
	if (r->granted)
		return 0;
	ccs_warn_log(r, "environ %s", env);
	return ccs_supervisor(r, CCS_KEYWORD_ALLOW_ENV "%s\n", env);
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
	struct ccs_path_info environ;
	int error;
	if (!env || !*env)
		return 0;
	environ.name = env;
	ccs_fill_path_info(&environ);
	r->param_type = CCS_TYPE_ENV_ACL;
	r->param.environ.name = &environ;
	do {
		ccs_check_acl(r, ccs_check_env_acl);
		error = ccs_audit_env_log(r);
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
	if (!ccs_correct_word(data) || strchr(data, '='))
		return -EINVAL;
	e.env = ccs_get_name(data);
	if (!e.env)
		return error;
	error = ccs_update_domain(&e.head, sizeof(e), is_delete, domain,
				  ccs_same_env_entry, NULL);
	ccs_put_name(e.env);
	return error;
}
