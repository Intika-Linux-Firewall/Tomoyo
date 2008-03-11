/*
 * fs/tomoyo_signal.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.0-pre   2008/03/04
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define find_task_by_pid find_task_by_vpid
#endif

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditSignalLog(const int signal, const struct path_info *dest_domain, const bool is_granted, const u8 profile, const u8 mode)
{
	char *buf;
	int len;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	len = dest_domain->total_len;
	if ((buf = InitAuditLog(&len, profile, mode, NULL)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_SIGNAL "%d %s\n", signal, dest_domain->name);
	return WriteAuditLog(buf, is_granted);
}

/*************************  SIGNAL ACL HANDLER  *************************/

static int AddSignalEntry(const int sig, const char *dest_pattern, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	struct acl_info *ptr;
	struct signal_acl_record *acl;
	const struct path_info *saved_dest_pattern;
	const u16 hash = sig;
	int error = -ENOMEM;
	if (!domain) return -EINVAL;
	if (!dest_pattern || !IsCorrectDomain(dest_pattern, __FUNCTION__)) return -EINVAL;
	if ((saved_dest_pattern = SaveName(dest_pattern)) == NULL) return -ENOMEM;
	mutex_lock(&domain_acl_lock);
	if (!is_delete) {
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			if ((ptr->type & ~(ACL_DELETED | ACL_WITH_CONDITION)) != TYPE_SIGNAL_ACL) continue;
			if (GetConditionPart(ptr) != condition) continue;
			acl = container_of(ptr, struct signal_acl_record, head);
			if (acl->sig != hash || pathcmp(acl->domainname, saved_dest_pattern)) continue;
			error = AddDomainACL(NULL, ptr);
			goto out;
		}
		/* Not found. Append it to the tail. */
		if ((acl = alloc_acl_element(TYPE_SIGNAL_ACL, condition)) == NULL) goto out;
		acl->sig = hash;
		acl->domainname = saved_dest_pattern;
		error = AddDomainACL(domain, &acl->head);
	} else {
		error = -ENOENT;
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			if ((ptr->type & ~ACL_WITH_CONDITION) != TYPE_SIGNAL_ACL) continue;
			if (GetConditionPart(ptr) != condition) continue;
			acl = container_of(ptr, struct signal_acl_record, head);
			if (acl->sig != hash || pathcmp(acl->domainname, saved_dest_pattern)) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
 out: ;
	mutex_unlock(&domain_acl_lock);
	return error;
}

int CheckSignalACL(const int sig, const int pid)
{
	struct domain_info *domain = current->domain_info;
	struct domain_info *dest = NULL;
	const char *dest_pattern;
	struct acl_info *ptr;
	const u16 hash = sig;
	const u8 profile = current->domain_info->profile;
	const u8 mode = CheckCCSFlags(CCS_TOMOYO_MAC_FOR_SIGNAL);
	const bool is_enforce = (mode == 3);
	bool found = false;
	if (!mode) return 0;
	if (!sig) return 0;                               /* No check for NULL signal. */
	if (current->pid == pid) {
		AuditSignalLog(sig, domain->domainname, 1, profile, mode);
		return 0;                /* No check for self. */
	}
	{ /* Simplified checking. */
		struct task_struct *p = NULL;
		read_lock(&tasklist_lock);
		if (pid > 0) p = find_task_by_pid((pid_t) pid);
		else if (pid == 0) p = current;
		else if (pid == -1) dest = &KERNEL_DOMAIN;
		else p = find_task_by_pid((pid_t) -pid);
		if (p) dest = p->domain_info;
		read_unlock(&tasklist_lock);
		if (!dest) return 0; /* I can't find destinatioin. */
	}
	if (domain == dest) {
		AuditSignalLog(sig, dest->domainname, 1, profile, mode);
		return 0;
	}
	dest_pattern = dest->domainname->name;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct signal_acl_record *acl;
		if ((ptr->type & ~ACL_WITH_CONDITION) != TYPE_SIGNAL_ACL) continue;
		acl = container_of(ptr, struct signal_acl_record, head);
		if (acl->sig == hash && CheckCondition(ptr, NULL)) {
			const int len = acl->domainname->total_len;
			if (strncmp(acl->domainname->name, dest_pattern, len)) continue;
			if (dest_pattern[len] != ' ' && dest_pattern[len] != '\0') continue;
			UpdateCondition(ptr);
			found = true;
			break;
		}
	}
	AuditSignalLog(sig, dest->domainname, found, profile, mode);
	if (found) return 0;
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: Signal %d to %s denied for %s\n", GetMSG(is_enforce), sig, GetLastName(dest), GetLastName(domain));
	}
	if (is_enforce) return CheckSupervisor("%s\n" KEYWORD_ALLOW_SIGNAL "%d %s\n", domain->domainname->name, sig, dest_pattern);
	else if (mode == 1 && CheckDomainQuota(domain)) AddSignalEntry(sig, dest_pattern, domain, NULL, 0);
	return 0;
}

int AddSignalPolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	int sig;
	char *domainname = strchr(data, ' ');
	if (sscanf(data, "%d", &sig) == 1 && domainname && IsDomainDef(domainname + 1)) {
		return AddSignalEntry(sig, domainname + 1, domain, condition, is_delete);
	}
	return -EINVAL;
}

/***** TOMOYO Linux end. *****/
