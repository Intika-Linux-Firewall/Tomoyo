/*
 * fs/tomoyo_signal.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.0.2 2006/01/24
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>

/***** The structure for signal controls. *****/

typedef struct signal_entry {
	struct signal_entry *next; /* Pointer to next record. NULL if none.                            */
	const DOMAIN_INFO *source; /* Pointer to domain record that this entry applies to. Never NULL. */
	int sig;                   /* Signal number.                                                   */
	const char *dest_pattern;  /* Pointer to destination pattern. Never NULL.                      */
} SIGNAL_ENTRY;

/*************************  VARIABLES  *************************/

/* The initial domain. */
extern struct domain_info KERNEL_DOMAIN;

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditSignalLog(const int signal, const char *dest_pattern, const int is_granted);

/*************************  SIGNAL ACL HANDLER  *************************/

static SIGNAL_ENTRY signal_list = { NULL, NULL, 0, NULL };

static int AddSignalEntry(const int sig, const char *dest_pattern, const struct domain_info *source)
{
	SIGNAL_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	const char *saved_dest_pattern;
	if (!source) {
		printk("%s: ERROR: source == NULL\n", __FUNCTION__);
		return -EINVAL;
	}
	if (!dest_pattern) {
		printk("%s: ERROR: dest_pattern == NULL\n", __FUNCTION__);
		return -EINVAL;
	}
	/* I don't want to add if it was already added. */
	for (ptr = signal_list.next; ptr; ptr = ptr->next) {
		const int len = strlen(ptr->dest_pattern);
		if (ptr->source == source && ptr->sig == sig && strncmp(ptr->dest_pattern, dest_pattern, len) == 0 && (dest_pattern[len] == ' ' || dest_pattern[len] == '\0')) return 0;
	}
	if ((saved_dest_pattern = SaveName(dest_pattern)) == NULL) return -ENOMEM;
	if ((new_entry = (SIGNAL_ENTRY *) alloc_element(sizeof(SIGNAL_ENTRY))) == NULL) return -ENOMEM;
	memset(new_entry, 0, sizeof(SIGNAL_ENTRY));
	new_entry->next = NULL;
	new_entry->source = source;
	new_entry->sig = sig;
	new_entry->dest_pattern = saved_dest_pattern;
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	for (ptr = &signal_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

int CheckSignalACL(const int sig, const int pid)
{
	const struct domain_info *source = GetCurrentDomain();
	struct domain_info *dest = NULL;
	const char *dest_pattern;
	SIGNAL_ENTRY *ptr;
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
	for (ptr = signal_list.next; ptr; ptr = ptr->next) {
		const int len = strlen(ptr->dest_pattern);
		if (ptr->source == source && ptr->sig == sig && strncmp(ptr->dest_pattern, dest_pattern, len) == 0 && (dest_pattern[len] == ' ' || dest_pattern[len] == '\0')) break;
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

int ReadSignalPolicy(IO_BUFFER *head)
{
	struct domain_info *domain = (struct domain_info *) head->read_var1;
	SIGNAL_ENTRY *ptr = (SIGNAL_ENTRY *) head->read_var2;
	if (!ptr) ptr = signal_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (domain == ptr->source) {
			if (io_printf(head, KEYWORD_ALLOW_SIGNAL "%u %s\n", ptr->sig, ptr->dest_pattern)) break;
		}
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

EXPORT_SYMBOL(CheckSignalACL);

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditSignalLog(const int signal, const char *dest_pattern, const int is_granted)
{
	char *buf;
	const struct domain_info *domain = current->domain_info;
	int len;
	struct timeval tv;
	struct task_struct *task = current;
	if (!domain) {
		printk("%s: ERROR: domain == NULL\n", __FUNCTION__);
		return -EINVAL;
	}
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	do_gettimeofday(&tv);
	len = strlen(domain->domainname) + strlen(dest_pattern) + 256;
	if ((buf = kmalloc(len, GFP_KERNEL)) == NULL) return -ENOMEM;
	memset(buf, 0, len);
	snprintf(buf, len - 1, "#timestamp=%lu pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d\n%s\n" KEYWORD_ALLOW_SIGNAL "%d %s\n", tv.tv_sec, task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, domain->domainname, signal, dest_pattern);
	return WriteAuditLog(buf, is_granted);
}

/***** TOMOYO Linux end. *****/
