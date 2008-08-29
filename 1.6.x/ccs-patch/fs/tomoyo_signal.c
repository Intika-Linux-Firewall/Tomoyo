/*
 * fs/tomoyo_signal.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.4-rc   2008/08/29
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
 * audit_signal_log - Audit signal log.
 *
 * @signal:      Signal number.
 * @dest_domain: Destination domainname.
 * @is_granted:  True if this is a granted log.
 * @profile:     Profile number used.
 * @mode:        Access control mode used.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int audit_signal_log(const int signal,
			    const struct path_info *dest_domain,
			    const bool is_granted, const u8 profile,
			    const u8 mode)
{
	char *buf;
	int len;
	int len2;
	if (ccs_can_save_audit_log(is_granted) < 0)
		return -ENOMEM;
	len = dest_domain->total_len + 64;
	buf = ccs_init_audit_log(&len, profile, mode, NULL);
	if (!buf)
		return -ENOMEM;
	len2 = strlen(buf);
	snprintf(buf + len2, len - len2 - 1, KEYWORD_ALLOW_SIGNAL "%d %s\n",
		 signal, dest_domain->name);
	return ccs_write_audit_log(buf, is_granted);
}

/**
 * update_signal_acl - Update "struct signal_acl_record" list.
 *
 * @sig:          Signal number.
 * @dest_pattern: Destination domainname.
 * @domain:       Pointer to "struct domain_info".
 * @condition:    Pointer to "struct condition_list". May be NULL.
 * @is_delete:    True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_signal_acl(const int sig, const char *dest_pattern,
			     struct domain_info *domain,
			     const struct condition_list *condition,
			     const bool is_delete)
{
	struct acl_info *ptr;
	struct signal_acl_record *acl;
	const struct path_info *saved_dest_pattern;
	const u16 hash = sig;
	int error = -ENOMEM;
	if (!domain)
		return -EINVAL;
	if (!dest_pattern || !ccs_is_correct_domain(dest_pattern, __func__))
		return -EINVAL;
	saved_dest_pattern = ccs_save_name(dest_pattern);
	if (!saved_dest_pattern)
		return -ENOMEM;
	mutex_lock(&domain_acl_lock);
	if (is_delete)
		goto delete;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != TYPE_SIGNAL_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct signal_acl_record, head);
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
		acl = container_of(ptr, struct signal_acl_record, head);
		if (acl->sig != hash ||
		    ccs_pathcmp(acl->domainname, saved_dest_pattern))
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
 out:
	mutex_unlock(&domain_acl_lock);
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
	struct domain_info *domain = current->domain_info;
	struct domain_info *dest = NULL;
	const char *dest_pattern;
	struct acl_info *ptr;
	const u16 hash = sig;
	const u8 profile = current->domain_info->profile;
	const u8 mode = ccs_check_flags(CCS_TOMOYO_MAC_FOR_SIGNAL);
	const bool is_enforce = (mode == 3);
	bool found = false;
	if (!mode)
		return 0;
	if (!sig)
		return 0;                /* No check for NULL signal. */
	if (current->pid == pid) {
		audit_signal_log(sig, domain->domainname, true, profile, mode);
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
			dest = &KERNEL_DOMAIN;
		else
			p = find_task_by_pid((pid_t) -pid);
		if (p)
			dest = p->domain_info;
		read_unlock(&tasklist_lock);
		/***** CRITICAL SECTION END *****/
		if (!dest)
			return 0; /* I can't find destinatioin. */
	}
	if (domain == dest) {
		audit_signal_log(sig, dest->domainname, true, profile, mode);
		return 0;                /* No check for self domain. */
	}
	dest_pattern = dest->domainname->name;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct signal_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_SIGNAL_ACL)
			continue;
		acl = container_of(ptr, struct signal_acl_record, head);
		if (acl->sig == hash && ccs_check_condition(ptr, NULL)) {
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
			ccs_update_condition(ptr);
			found = true;
			break;
		}
	}
	audit_signal_log(sig, dest->domainname, found, profile, mode);
	if (found)
		return 0;
	if (ccs_verbose_mode())
		printk(KERN_WARNING "TOMOYO-%s: Signal %d "
		       "to %s denied for %s\n", ccs_get_msg(is_enforce), sig,
		       ccs_get_last_name(dest), ccs_get_last_name(domain));
	if (is_enforce)
		return ccs_check_supervisor(NULL, KEYWORD_ALLOW_SIGNAL
					    "%d %s\n", sig, dest_pattern);
	if (mode == 1 && ccs_check_domain_quota(domain))
		update_signal_acl(sig, dest_pattern, domain, NULL, false);
	return 0;
}

/**
 * ccs_write_signal_policy - Write "struct signal_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_signal_policy(char *data, struct domain_info *domain,
			    const struct condition_list *condition,
			    const bool is_delete)
{
	int sig;
	char *domainname = strchr(data, ' ');
	if (sscanf(data, "%d", &sig) == 1 && domainname &&
	    ccs_is_domain_def(domainname + 1))
		return update_signal_acl(sig, domainname + 1, domain,
					 condition, is_delete);
	return -EINVAL;
}
