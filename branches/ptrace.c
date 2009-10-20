/*
 * security/ccsecurity/ptrace.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.1-pre   2009/10/16
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

/* To support PID namespace. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#define find_task_by_pid find_task_by_vpid
#endif

/**
 * ccs_audit_ptrace_log - Audit ptrace log.
 *
 * @r:           Pointer to "struct ccs_request_info".
 * @request:     Request number.
 * @dest_domain: Destination domainname.
 * @is_granted:  True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_ptrace_log(struct ccs_request_info *r,
				const unsigned long request,
				const char *dest_domain, const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "ptrace %lu to %s", request,
			     ccs_last_word(dest_domain));
	return ccs_write_audit_log(is_granted, r, CCS_KEYWORD_ALLOW_PTRACE
				   "%lu %s\n", request, dest_domain);
}

/**
 * ccs_ptrace_acl2 - Check permission for ptrace.
 *
 * @request: Request number.
 * @pid:     Target's PID.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_ptrace_acl2(const unsigned long request, const pid_t pid)
{
	struct ccs_request_info r;
	const struct ccs_path_info *dest = NULL;
	struct ccs_acl_info *ptr;
	int error;
	if (ccs_init_request_info(&r, NULL, CCS_MAC_PTRACE)
	    == CCS_CONFIG_DISABLED)
		return 0;
	{
		struct task_struct *p = NULL;
		read_lock(&tasklist_lock);
		p = find_task_by_pid((pid_t) pid);
		if (p) {
			struct ccs_domain_info *domain = ccs_task_domain(p);
			if (domain)
				dest = domain->domainname;
		}
		read_unlock(&tasklist_lock);
	}
	if (!dest)
		return 0; /* I can't find destinatioin. */
	do {
		error = -EPERM;
		list_for_each_entry_rcu(ptr, &r.domain->acl_info_list, list) {
			struct ccs_ptrace_acl *acl;
			if (ptr->is_deleted ||
			    ptr->type != CCS_TYPE_PTRACE_ACL)
				continue;
			acl = container_of(ptr, struct ccs_ptrace_acl, head);
			if (acl->request != request ||
			    !ccs_condition(&r, ptr) ||
			    !ccs_pathcmp(acl->domainname, dest))
				continue;
			r.cond = ptr->cond;
			error = 0;
			break;
		}
		ccs_audit_ptrace_log(&r, sig, dest_pattern->name, !error);
		if (!error)
			break;
		error = ccs_supervisor(&r, CCS_KEYWORD_ALLOW_PTRACE "%lu %s\n",
				       request, dest);
	} while (error == 1);
	return error;
}

/**
 * ccs_ptrace_permission - Check permission for ptrace.
 *
 * @request: Request number.
 * @pid:     Target's PID.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_ptrace_permission(long request, long pid)
{
	const int idx = ccs_read_lock();
	const int error = ccs_ptrace_acl2((unsigned long) request,
					  (pid_t) pid);
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_write_ptrace_policy - Write "struct ccs_ptrace_acl" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_ptrace_policy(char *data, struct ccs_domain_info *domain,
			    struct ccs_condition *condition,
			    const bool is_delete)
{
	struct ccs_ptrace_acl *entry = NULL;
	struct ccs_acl_info *ptr;
	struct ccs_ptrace_acl e = { .head.type = CCS_TYPE_PTRACE_ACL,
				    .head.cond = condition };
	int error = is_delete ? -ENOENT : -ENOMEM;
	unsigned long req;
	char *domainname = strchr(data, ' ');
	if (!domainname || !ccs_is_correct_domain(domainname + 1) ||
	    !ccs_parse_number_union(mode, &e.request))
		return -EINVAL;
	e.domainname = ccs_get_name(domainname + 1);
	if (!e.domainname)
		goto out;
	if (!is_delete)
		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_ptrace_acl *acl =
			container_of(ptr, struct ccs_ptrace_acl, head);
		if (ptr->type != CCS_TYPE_PTRACE_ACL || ptr->cond != condition
		    || acl->req != req || acl->domainname != e.domainname)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.domainname);
	ccs_put_number_union(&e.request);
	kfree(entry);
	return error;
}
