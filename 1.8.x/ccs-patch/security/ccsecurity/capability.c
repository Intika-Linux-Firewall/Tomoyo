/*
 * security/ccsecurity/capability.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/09/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

/**
 * ccs_audit_capability_log - Audit capability log.
 *
 * @r:     Pointer to "struct ccs_request_info".
 * @error: Error code.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_capability_log(struct ccs_request_info *r)
{
	const char *operation = ccs_cap2keyword(r->param.capability.operation);
	ccs_write_log(r, "capability %s\n", operation);
	if (r->granted)
		return 0;
	ccs_warn_log(r, "capability %s", operation);
	return ccs_supervisor(r, "capability %s\n", operation);
}

static bool ccs_check_capability_acl(struct ccs_request_info *r,
				     const struct ccs_acl_info *ptr)
{
	const struct ccs_capability_acl *acl =
		container_of(ptr, typeof(*acl), head);
	return acl->operation == r->param.capability.operation;
}
			
/**
 * ccs_capable - Check permission for capability.
 *
 * @operation: Type of operation.
 *
 * Returns true on success, false otherwise.
 */
static bool __ccs_capable(const u8 operation)
{
	struct ccs_request_info r;
	int error = 0;
	const int idx = ccs_read_lock();
	if (ccs_init_request_info(&r, CCS_MAX_MAC_INDEX + operation)
	    != CCS_CONFIG_DISABLED) {
		r.param_type = CCS_TYPE_CAPABILITY_ACL;
		r.param.capability.operation = operation;
		do {
			ccs_check_acl(&r, ccs_check_capability_acl);
			error = ccs_audit_capability_log(&r);
		} while (error == CCS_RETRY_REQUEST);
	}
	ccs_read_unlock(idx);
	return !error;
}

static int __ccs_ptrace_permission(long request, long pid)
{
	return !__ccs_capable(CCS_SYS_PTRACE);
}

static bool ccs_same_capability_entry(const struct ccs_acl_info *a,
				      const struct ccs_acl_info *b)
{
	const struct ccs_capability_acl *p1 = container_of(a, typeof(*p1),
							   head);
	const struct ccs_capability_acl *p2 = container_of(b, typeof(*p2),
							   head);
	return p1->head.type == p2->head.type && p1->head.cond == p2->head.cond
		&& p1->head.type == CCS_TYPE_CAPABILITY_ACL
		&& p1->operation == p2->operation;
}

/**
 * ccs_write_capability - Write "struct ccs_capability_acl" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". Maybe NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_capability(char *data, struct ccs_domain_info *domain,
			 struct ccs_condition *condition, const bool is_delete)
{
	struct ccs_capability_acl e = {
		.head.type = CCS_TYPE_CAPABILITY_ACL,
		.head.cond = condition,
	};
	u8 capability;
	for (capability = 0; capability < CCS_MAX_CAPABILITY_INDEX;
	     capability++) {
		if (strcmp(data, ccs_cap2keyword(capability)))
			continue;
		break;
	}
	if (capability == CCS_MAX_CAPABILITY_INDEX)
		return -EINVAL;
	e.operation = capability;
	return ccs_update_domain(&e.head, sizeof(e), is_delete, domain,
				 ccs_same_capability_entry, NULL);
}

void __init ccs_capability_init(void)
{
	ccsecurity_ops.capable = __ccs_capable;
	ccsecurity_ops.ptrace_permission = __ccs_ptrace_permission;
}
