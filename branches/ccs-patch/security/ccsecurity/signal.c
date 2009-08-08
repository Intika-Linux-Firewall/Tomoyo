/*
 * security/ccsecurity/signal.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

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
	if (!is_granted && ccs_verbose_mode(r->domain)) {
		const char *dest = strrchr(dest_domain, ' ');
		if (dest)
			dest++;
		else
			dest = dest_domain;
		printk(KERN_WARNING
		       "TOMOYO-%s: Signal %d to %s denied for %s\n",
		       ccs_get_msg(r->mode == 3), signal, dest,
		       ccs_get_last_name(r->domain));
	}
	return ccs_write_audit_log(is_granted, r, KEYWORD_ALLOW_SIGNAL
				   "%d %s\n", signal, dest_domain);
}

/**
 * ccs_update_signal_acl - Update "struct ccs_signal_acl_record" list.
 *
 * @sig:          Signal number.
 * @dest_pattern: Destination domainname.
 * @domain:       Pointer to "struct ccs_domain_info".
 * @condition:    Pointer to "struct ccs_condition". May be NULL.
 * @is_delete:    True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_signal_acl(const int sig, const char *dest_pattern,
				 struct ccs_domain_info *domain,
				 struct ccs_condition *condition,
				 const bool is_delete)
{
	struct ccs_signal_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
	const struct ccs_path_info *saved_dest_pattern;
	const u16 hash = sig;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!domain)
		return -EINVAL;
	if (!dest_pattern || !ccs_is_correct_domain(dest_pattern))
		return -EINVAL;
	saved_dest_pattern = ccs_get_name(dest_pattern);
	if (!saved_dest_pattern)
		return -ENOMEM;
	if (is_delete)
		goto delete;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_signal_acl_record *acl;
		if (ccs_acl_type1(ptr) != TYPE_SIGNAL_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_signal_acl_record, head);
		if (acl->sig != hash ||
		    ccs_pathcmp(acl->domainname, saved_dest_pattern))
			continue;
		error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->head.type = TYPE_SIGNAL_ACL;
		entry->head.cond = condition;
		entry->sig = hash;
		entry->domainname = saved_dest_pattern;
		saved_dest_pattern = NULL;
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	goto out;
 delete:
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_signal_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_SIGNAL_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_signal_acl_record, head);
		if (acl->sig != hash ||
		    ccs_pathcmp(acl->domainname, saved_dest_pattern))
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(saved_dest_pattern);
	kfree(entry);
	return error;
}

/**
 * ccs_check_signal_acl2 - Check permission for signal.
 *
 * @sig: Signal number.
 * @pid: Target's PID.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_signal_acl2(const int sig, const int pid)
{
	struct ccs_request_info r;
	struct ccs_domain_info *dest = NULL;
	const char *dest_pattern;
	struct ccs_acl_info *ptr;
	const u16 hash = sig;
	bool is_enforce;
	bool found = false;
	ccs_check_read_lock();
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_SIGNAL);
	is_enforce = (r.mode == 3);
	if (!r.mode)
		return 0;
	if (!sig)
		return 0;                /* No check for NULL signal. */
	if (sys_getpid() == pid) {
		ccs_audit_signal_log(&r, sig, r.domain->domainname->name, true);
		return 0;                /* No check for self process. */
	}
	{ /* Simplified checking. */
		struct task_struct *p = NULL;
		/***** CRITICAL SECTION START *****/
		read_lock(&tasklist_lock);
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
		read_unlock(&tasklist_lock);
		/***** CRITICAL SECTION END *****/
	}
	if (!dest)
		return 0; /* I can't find destinatioin. */
	if (r.domain == dest) {
		ccs_audit_signal_log(&r, sig, r.domain->domainname->name, true);
		return 0;                /* No check for self domain. */
	}
	dest_pattern = dest->domainname->name;
 retry:
	list_for_each_entry_rcu(ptr, &r.domain->acl_info_list, list) {
		struct ccs_signal_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_SIGNAL_ACL)
			continue;
		acl = container_of(ptr, struct ccs_signal_acl_record, head);
		if (acl->sig == hash && ccs_check_condition(&r, ptr)) {
			const int len = acl->domainname->total_len;
			if (strncmp(acl->domainname->name, dest_pattern, len))
				continue;
			switch (dest_pattern[len]) {
			case ' ':
			case '\0':
				break;
			default:
				continue;
			}
			r.cond = ptr->cond;
			found = true;
			break;
		}
	}
	ccs_audit_signal_log(&r, sig, dest_pattern, found);
	if (found)
		return 0;
	if (is_enforce) {
		int error = ccs_check_supervisor(&r, KEYWORD_ALLOW_SIGNAL
						 "%d %s\n", sig, dest_pattern);
		if (error == 1)
			goto retry;
		return error;
	} else if (ccs_domain_quota_ok(&r)) {
		struct ccs_condition *cond = ccs_handler_cond();
		ccs_update_signal_acl(sig, dest_pattern, r.domain, cond, false);
		ccs_put_condition(cond);
	}
	return 0;
}

/**
 * ccs_check_signal_acl - Check permission for signal.
 *
 * @sig: Signal number.
 * @pid: Target's PID.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_signal_acl(const int sig, const int pid)
{
	const int idx = ccs_read_lock();
	const int error = ccs_check_signal_acl2(sig, pid);
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_write_signal_policy - Write "struct ccs_signal_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_signal_policy(char *data, struct ccs_domain_info *domain,
			    struct ccs_condition *condition,
			    const bool is_delete)
{
	int sig;
	char *domainname = strchr(data, ' ');
	if (sscanf(data, "%d", &sig) == 1 && domainname &&
	    ccs_is_domain_def(domainname + 1))
		return ccs_update_signal_acl(sig, domainname + 1, domain,
					     condition, is_delete);
	return -EINVAL;
}

/**
 * ccs_kill_permission - Permission check for kill().
 *
 * @pid: PID
 * @sig: Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_kill_permission(pid_t pid, int sig)
{
	if (sig && (!ccs_capable(CCS_SYS_KILL) ||
		    ccs_check_signal_acl(sig, pid)))
		return -EPERM;
	return 0;
}

/**
 * ccs_tgkill_permission - Permission check for tgkill().
 *
 * @tgid: TGID
 * @pid:  PID
 * @sig:  Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_tgkill_permission(pid_t tgid, pid_t pid, int sig)
{
	if (sig && (!ccs_capable(CCS_SYS_KILL) ||
		    ccs_check_signal_acl(sig, pid)))
		return -EPERM;
	return 0;
}

/**
 * ccs_tkill_permission - Permission check for tkill().
 *
 * @pid: PID
 * @sig: Signal number.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_tkill_permission(pid_t pid, int sig)
{
	if (sig && (!ccs_capable(CCS_SYS_KILL) ||
		    ccs_check_signal_acl(sig, pid)))
		return -EPERM;
	return 0;
}
