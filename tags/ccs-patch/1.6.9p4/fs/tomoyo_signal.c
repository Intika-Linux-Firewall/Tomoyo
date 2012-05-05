/*
 * fs/tomoyo_signal.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/05/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#include <linux/version.h>

/* To support PID namespace. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#define find_task_by_pid find_task_by_vpid
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
	return ccs_write_audit_log(is_granted, r, KEYWORD_ALLOW_SIGNAL
				   "%d %s\n", signal, dest_domain);
}

/**
 * ccs_update_signal_acl - Update "struct ccs_signal_acl_record" list.
 *
 * @sig:          Signal number.
 * @dest_pattern: Destination domainname.
 * @domain:       Pointer to "struct ccs_domain_info".
 * @condition:    Pointer to "struct ccs_condition_list". May be NULL.
 * @is_delete:    True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_signal_acl(const int sig, const char *dest_pattern,
				 struct ccs_domain_info *domain,
				 const struct ccs_condition_list *condition,
				 const bool is_delete)
{
	static DEFINE_MUTEX(lock);
	struct ccs_acl_info *ptr;
	struct ccs_signal_acl_record *acl;
	const struct ccs_path_info *saved_dest_pattern;
	const u16 hash = sig;
	int error = -ENOMEM;
	if (!domain)
		return -EINVAL;
	if (!dest_pattern || !ccs_is_correct_domain(dest_pattern, __func__))
		return -EINVAL;
	saved_dest_pattern = ccs_save_name(dest_pattern);
	if (!saved_dest_pattern)
		return -ENOMEM;
	mutex_lock(&lock);
	if (is_delete)
		goto delete;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != TYPE_SIGNAL_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ccs_signal_acl_record, head);
		if (acl->sig != hash ||
		    ccs_pathcmp(acl->domainname, saved_dest_pattern))
			continue;
		error = ccs_add_domain_acl(NULL, ptr);
		goto out;
	}
	/* Not found. Append it to the tail. */
	acl = ccs_alloc_acl_element(TYPE_SIGNAL_ACL, condition);
	if (!acl)
		goto out;
	acl->sig = hash;
	acl->domainname = saved_dest_pattern;
	error = ccs_add_domain_acl(domain, &acl->head);
	goto out;
 delete:
	error = -ENOENT;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type2(ptr) != TYPE_SIGNAL_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ccs_signal_acl_record, head);
		if (acl->sig != hash ||
		    ccs_pathcmp(acl->domainname, saved_dest_pattern))
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
 out:
	mutex_unlock(&lock);
	return error;
}

/**
 * ccs_check_signal_acl - Check permission for signal.
 *
 * @sig: Signal number.
 * @pid: Target's PID.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_signal_acl(const int sig, const int pid)
{
	struct ccs_request_info r;
	struct ccs_domain_info *dest = NULL;
	const char *dest_pattern;
	struct ccs_acl_info *ptr;
	const u16 hash = sig;
	bool is_enforce;
	bool found = false;
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
	list1_for_each_entry(ptr, &r.domain->acl_info_list, list) {
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
			r.cond = ccs_get_condition_part(ptr);
			found = true;
			break;
		}
	}
	ccs_audit_signal_log(&r, sig, dest_pattern, found);
	if (found)
		return 0;
	if (ccs_verbose_mode(r.domain))
		printk(KERN_WARNING "TOMOYO-%s: Signal %d "
		       "to %s denied for %s\n", ccs_get_msg(is_enforce), sig,
		       ccs_get_last_name(dest), ccs_get_last_name(r.domain));
	if (is_enforce) {
		int error = ccs_check_supervisor(&r, KEYWORD_ALLOW_SIGNAL
						 "%d %s\n", sig, dest_pattern);
		if (error == 1)
			goto retry;
		return error;
	}
	if (r.mode == 1 && ccs_domain_quota_ok(r.domain))
		ccs_update_signal_acl(sig, dest_pattern, r.domain,
				      ccs_handler_cond(), false);
	return 0;
}

/**
 * ccs_write_signal_policy - Write "struct ccs_signal_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_signal_policy(char *data, struct ccs_domain_info *domain,
			    const struct ccs_condition_list *condition,
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
