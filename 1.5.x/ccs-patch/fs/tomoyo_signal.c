/*
 * fs/tomoyo_signal.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.5.5-pre   2008/08/21
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#define find_task_by_pid find_task_by_vpid
#endif

/*************************  VARIABLES  *************************/

/* The initial domain. */
extern struct domain_info KERNEL_DOMAIN;

extern struct semaphore domain_acl_lock;

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditSignalLog(const int signal, const struct path_info *dest_domain, const int is_granted)
{
	char *buf;
	int len;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	len = dest_domain->total_len;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_SIGNAL "%d %s\n", signal, dest_domain->name);
	return WriteAuditLog(buf, is_granted);
}

/*************************  SIGNAL ACL HANDLER  *************************/

static int AddSignalEntry(const int sig, const char *dest_pattern, struct domain_info *domain, const struct condition_list *condition, const u8 is_delete)
{
	struct acl_info *ptr;
	const struct path_info *saved_dest_pattern;
	const u16 hash = sig;
	int error = -ENOMEM;
	if (!domain) return -EINVAL;
	if (!dest_pattern || !IsCorrectDomain(dest_pattern, __FUNCTION__)) return -EINVAL;
	if ((saved_dest_pattern = SaveName(dest_pattern)) == NULL) return -ENOMEM;
	down(&domain_acl_lock);
	if (!is_delete) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			struct signal_acl_record *new_ptr = (struct signal_acl_record *) ptr;
			if (ptr->type == TYPE_SIGNAL_ACL && new_ptr->sig == hash && ptr->cond == condition) {
				if (!pathcmp(new_ptr->domainname, saved_dest_pattern)) {
					ptr->is_deleted = 0;
					/* Found. Nothing to do. */
					error = 0;
					break;
				}
			}
			if (ptr->next) {
				ptr = ptr->next;
				continue;
			}
		first_entry: ;
			/* Not found. Append it to the tail. */
			if ((new_ptr = alloc_element(sizeof(*new_ptr))) == NULL) break;
			new_ptr->head.type = TYPE_SIGNAL_ACL;
			new_ptr->sig = hash;
			new_ptr->head.cond = condition;
			new_ptr->domainname = saved_dest_pattern;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
			struct signal_acl_record *ptr2 = (struct signal_acl_record *) ptr;
			if (ptr->type != TYPE_SIGNAL_ACL || ptr->is_deleted || ptr2->sig != hash || ptr->cond != condition) continue;
			if (pathcmp(ptr2->domainname, saved_dest_pattern)) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
	up(&domain_acl_lock);
	return error;
}

int CheckSignalACL(const int sig, const int pid)
{
	struct domain_info *domain = current->domain_info;
	struct domain_info *dest = NULL;
	const char *dest_pattern;
	struct acl_info *ptr;
	const u16 hash = sig;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_SIGNAL);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_SIGNAL)) return 0;
	if (!sig) return 0;                               /* No check for NULL signal. */
	if (current->pid == pid) {
		AuditSignalLog(sig, domain->domainname, 1);
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
		AuditSignalLog(sig, dest->domainname, 1);
		return 0;
	}
	dest_pattern = dest->domainname->name;
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		struct signal_acl_record *ptr2 = (struct signal_acl_record *) ptr;
		if (ptr->type == TYPE_SIGNAL_ACL && ptr->is_deleted == 0 && ptr2->sig == hash && CheckCondition(ptr->cond, NULL) == 0) {
			const int len = ptr2->domainname->total_len;
			if (strncmp(ptr2->domainname->name, dest_pattern, len) == 0 && (dest_pattern[len] == ' ' || dest_pattern[len] == '\0')) break;
		}
	}
	if (ptr) {
		AuditSignalLog(sig, dest->domainname, 1);
		return 0;
	}
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: Signal %d to %s denied for %s\n", GetMSG(is_enforce), sig, GetLastName(dest), GetLastName(domain));
	}
	AuditSignalLog(sig, dest->domainname, 0);
	if (is_enforce) return CheckSupervisor("%s\n" KEYWORD_ALLOW_SIGNAL "%d %s\n", domain->domainname->name, sig, dest_pattern);
	if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_SIGNAL, domain)) AddSignalEntry(sig, dest_pattern, domain, NULL, 0);
	return 0;
}

int AddSignalPolicy(char *data, struct domain_info *domain, const int is_delete)
{
	int sig;
	char *domainname = strchr(data, ' ');
	if (sscanf(data, "%d", &sig) == 1 && domainname && IsDomainDef(domainname + 1)) {
		const struct condition_list *condition = NULL;
		const char *cp = FindConditionPart(domainname + 1);
		if (cp && (condition = FindOrAssignNewCondition(cp)) == NULL) return -EINVAL;
		return AddSignalEntry(sig, domainname + 1, domain, condition, is_delete);
	}
	return -EINVAL;
}

/***** TOMOYO Linux end. *****/
