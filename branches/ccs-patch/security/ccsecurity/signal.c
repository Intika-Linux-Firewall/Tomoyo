/*
 * security/ccsecurity/signal.c
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

/* To support PID namespace. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#define find_task_by_pid ccsecurity_exports.find_task_by_vpid
#endif

/**
 * ccs_audit_signal_log - Audit signal log.
 *
 * @r:           Pointer to "struct ccs_request_info".
 * @signal:      Signal number.
 * @dest_domain: Destination domainname.
 * @is_granted:  True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_signal_log(struct ccs_request_info *r, const int signal,
				const char *dest_domain, const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "signal %d to %s", signal,
			     ccs_last_word(dest_domain));
	return ccs_write_log(is_granted, r, CCS_KEYWORD_ALLOW_SIGNAL
				   "%d %s\n", signal, dest_domain);
}

/**
 * ccs_signal_acl2 - Check permission for signal.
 *
 * @sig: Signal number.
 * @pid: Target's PID.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_signal_acl2(const int sig, const int pid)
{
	struct ccs_request_info r;
	struct ccs_domain_info *dest = NULL;
	const char *dest_pattern;
	struct ccs_acl_info *ptr;
	const u16 hash = sig;
	int error;
	const struct ccs_domain_info * const domain = ccs_current_domain();
	if (ccs_init_request_info(&r, CCS_MAC_SIGNAL) == CCS_CONFIG_DISABLED)
		return 0;
	if (!sig)
		return 0;                /* No check for NULL signal. */
	if (ccsecurity_exports.sys_getpid() == pid) {
		ccs_audit_signal_log(&r, sig, domain->domainname->name,
				     true);
		return 0;                /* No check for self process. */
	}
	{ /* Simplified checking. */
		struct task_struct *p = NULL;
		ccs_tasklist_lock();
		if (pid > 0)
			p = find_task_by_pid((pid_t) pid);
		else if (pid == 0)
			p = current;
		else if (pid == -1)
			dest = &ccs_kernel_domain;
		else
			p = find_task_by_pid((pid_t) -pid);
		if (p)
			dest = ccs_task_domain(p);
		ccs_tasklist_unlock();
	}
	if (!dest)
		return 0; /* I can't find destinatioin. */
	if (domain == dest) {
		ccs_audit_signal_log(&r, sig, domain->domainname->name, true);
		return 0;                /* No check for self domain. */
	}
	dest_pattern = dest->domainname->name;
	do {
		error = -EPERM;
		list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
			struct ccs_signal_acl *acl;
			if (ptr->is_deleted ||
			    ptr->type != CCS_TYPE_SIGNAL_ACL)
				continue;
			acl = container_of(ptr, struct ccs_signal_acl, head);
			if (acl->sig == hash && ccs_condition(&r, ptr->cond)) {
				const int len = acl->domainname->total_len;
				if (strncmp(acl->domainname->name,
					    dest_pattern, len))
					continue;
				switch (dest_pattern[len]) {
				case ' ':
				case '\0':
					break;
				default:
					continue;
				}
				r.cond = ptr->cond;
				error = 0;
				break;
			}
		}
		ccs_audit_signal_log(&r, sig, dest_pattern, !error);
		if (!error)
			break;
		error = ccs_supervisor(&r, CCS_KEYWORD_ALLOW_SIGNAL "%d %s\n",
				       sig, dest_pattern);
	} while (error == CCS_RETRY_REQUEST);
	return error;
}

/**
 * ccs_signal_acl - Check permission for signal.
 *
 * @pid: Target's PID.
 * @sig: Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_signal_acl(const int pid, const int sig)
{
	int error;
	if (!sig)
		error = 0;
	else if (!ccs_capable(CCS_SYS_KILL))
		error = -EPERM;
	else {
		const int idx = ccs_read_lock();
		error = ccs_signal_acl2(sig, pid);
		ccs_read_unlock(idx);
	}
	return error;
}

/**
 * ccs_signal_acl0 - Permission check for signal().
 *
 * @tgid: Unused.
 * @pid:  PID
 * @sig:  Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_signal_acl0(pid_t tgid, pid_t pid, int sig)
{
	return ccs_signal_acl(pid, sig);
}

static bool ccs_same_signal_entry(const struct ccs_acl_info *a,
				  const struct ccs_acl_info *b)
{
	const struct ccs_signal_acl *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_signal_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->head.type == p2->head.type && p1->head.cond == p2->head.cond
		&& p1->head.type == CCS_TYPE_SIGNAL_ACL && p1->sig == p2->sig
		&& p1->domainname == p2->domainname;
}

/**
 * ccs_write_signal - Write "struct ccs_signal_acl" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_signal(char *data, struct ccs_domain_info *domain,
		     struct ccs_condition *condition, const bool is_delete)
{
	struct ccs_signal_acl e = { .head.type = CCS_TYPE_SIGNAL_ACL,
				    .head.cond = condition };
	int error;
	int sig;
	char *domainname = strchr(data, ' ');
	if (sscanf(data, "%d", &sig) != 1 || !domainname ||
	    !ccs_correct_domain(domainname + 1))
		return -EINVAL;
	e.sig = sig;
	e.domainname = ccs_get_name(domainname + 1);
	if (!e.domainname)
		return -ENOMEM;
	error = ccs_update_domain(&e.head, sizeof(e), is_delete, domain,
				  ccs_same_signal_entry, NULL);
	ccs_put_name(e.domainname);
	return error;
}

void __init ccs_signal_init(void)
{
	ccsecurity_ops.kill_permission = ccs_signal_acl;
	ccsecurity_ops.tgkill_permission = ccs_signal_acl0;
	ccsecurity_ops.tkill_permission = ccs_signal_acl;
	ccsecurity_ops.sigqueue_permission = ccs_signal_acl;
	ccsecurity_ops.tgsigqueue_permission = ccs_signal_acl0;
}
