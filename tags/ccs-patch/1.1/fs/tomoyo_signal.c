/*
 * fs/tomoyo_signal.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.1   2006/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>

/*************************  VARIABLES  *************************/

/* The initial domain. */
extern struct domain_info KERNEL_DOMAIN;

extern struct semaphore domain_acl_lock;

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditSignalLog(const int signal, const char *dest_pattern, const int is_granted);

/*************************  SIGNAL ACL HANDLER  *************************/

static int AddSignalEntry(const int sig, const char *dest_pattern, struct domain_info *source)
{
	struct acl_info *ptr;
	const char *saved_dest_pattern;
	const unsigned int type_hash = MAKE_ACL_TYPE(TYPE_SIGNAL_ACL) + MAKE_ACL_HASH(sig);
	int error = -ENOMEM;
	if (!source) return -EINVAL;
	if (!dest_pattern) {
		printk("%s: ERROR: dest_pattern == NULL\n", __FUNCTION__);
		return -EINVAL;
	}
	down(&domain_acl_lock);
	if ((ptr = source->first_acl_ptr) == NULL) goto first_entry;
	while (1) {
		SIGNAL_ACL_RECORD *new_ptr;
		if (ptr->type_hash == type_hash) {
			const int len = strlen(((SIGNAL_ACL_RECORD *) ptr)->domainname);
			if (strncmp(((SIGNAL_ACL_RECORD *) ptr)->domainname, dest_pattern, len) == 0 && (dest_pattern[len] == ' ' || dest_pattern[len] == '\0')) {
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
		if ((saved_dest_pattern = SaveName(dest_pattern)) == NULL) break;
		if ((new_ptr = (SIGNAL_ACL_RECORD *) alloc_element(sizeof(SIGNAL_ACL_RECORD))) == NULL) break;
		new_ptr->next = NULL;
		new_ptr->type_hash = type_hash;
		new_ptr->domainname = saved_dest_pattern;
		mb(); /* Instead of using spinlock. */
		if (!ptr) source->first_acl_ptr = (struct acl_info *) new_ptr;
		else ptr->next = (struct acl_info *) new_ptr;
		error = 0;
		break;
	}
	up(&domain_acl_lock);
	return error;
}

int CheckSignalACL(const int sig, const int pid)
{
	struct domain_info *source = GetCurrentDomain();
	struct domain_info *dest = NULL;
	const char *dest_pattern;
	struct acl_info *ptr;
	const unsigned int type_hash = MAKE_ACL_TYPE(TYPE_SIGNAL_ACL) + MAKE_ACL_HASH(sig);
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_SIGNAL);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_SIGNAL)) return 0;
	if (!sig) return 0;                               /* No check for NULL signal. */
	if (current->pid == pid) {
		AuditSignalLog(sig, source->domainname, 1);
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
	if (source == dest || (source->attribute & DOMAIN_ATTRIBUTE_TRUSTED) == DOMAIN_ATTRIBUTE_TRUSTED) {
		AuditSignalLog(sig, dest->domainname, 1);
		return 0;
	}
	dest_pattern = dest->domainname;
	for (ptr = source->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type_hash == type_hash) {
			const int len = strlen(((SIGNAL_ACL_RECORD *) ptr)->domainname);
			if (strncmp(((SIGNAL_ACL_RECORD *) ptr)->domainname, dest_pattern, len) == 0 && (dest_pattern[len] == ' ' || dest_pattern[len] == '\0')) break;
		}
	}
	if (ptr) {
		AuditSignalLog(sig, dest_pattern, 1);
		return 0;
	}
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: Signal %d to %s denied for %s\n", GetMSG(is_enforce), sig, GetLastName(dest), GetLastName(source));
	}
	AuditSignalLog(sig, dest_pattern, 0);
	if (is_enforce) return -EPERM;
	if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_SIGNAL)) AddSignalEntry(sig, dest_pattern, source);
	return 0;
}


int AddSignalPolicy(char *data, void **domain)
{
	int sig;
	char *cp;
	if (!isRoot()) return -EPERM;
	if (sscanf(data, "%d", &sig) == 1 && (cp = strchr(data, ' ')) != NULL) {
		if (IsDomainDef(cp + 1)) return AddSignalEntry(sig, cp + 1, (struct domain_info *) *domain);
	}
	return -EINVAL;
}

EXPORT_SYMBOL(CheckSignalACL);

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditSignalLog(const int signal, const char *dest_pattern, const int is_granted)
{
	char *buf;
	int len;
	struct timeval tv;
	struct task_struct *task = current;
	const char *domainname = task->domain_info->domainname;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	do_gettimeofday(&tv);
	len = strlen(domainname) + strlen(dest_pattern) + 256;
	if ((buf = kmalloc(len, GFP_KERNEL)) == NULL) return -ENOMEM;
	memset(buf, 0, len);
	snprintf(buf, len - 1, "#timestamp=%lu pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d\n%s\n" KEYWORD_ALLOW_SIGNAL "%d %s\n", tv.tv_sec, task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, domainname, signal, dest_pattern);
	return WriteAuditLog(buf, is_granted);
}

/***** TOMOYO Linux end. *****/
