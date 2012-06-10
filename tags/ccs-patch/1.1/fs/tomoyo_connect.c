/*
 * fs/tomoyo_connect.c
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

extern struct semaphore domain_acl_lock;

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditPortLog(const int is_stream, const unsigned short int port, const int is_granted);

/*************************  NETWORK CONNECT ACL HANDLER  *************************/

static int AddConnectEntry(const int is_stream, const unsigned short int min_port, const unsigned short int max_port, struct domain_info *domain)
{
	struct acl_info *ptr;
	int error = -ENOMEM;
	const unsigned int type_hash = MAKE_ACL_TYPE(TYPE_CONNECT_ACL) + MAKE_ACL_HASH(is_stream ? 1 : 0);
	if (!domain) return -EINVAL;
	down(&domain_acl_lock);
	if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
	while (1) {
		NETWORK_ACL_RECORD *new_ptr;
		if (ptr->type_hash == type_hash) {
			if (((NETWORK_ACL_RECORD *) ptr)->min_port <= min_port && max_port <= ((NETWORK_ACL_RECORD *) ptr)->max_port) {
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
		if ((new_ptr = (NETWORK_ACL_RECORD *) alloc_element(sizeof(NETWORK_ACL_RECORD))) == NULL) break;
		new_ptr->next = NULL;
		new_ptr->type_hash = type_hash;
		new_ptr->min_port = min_port;
		new_ptr->max_port = max_port;
		mb(); /* Instead of using spinlock. */
		if (!ptr) domain->first_acl_ptr = (struct acl_info *) new_ptr;
		else ptr->next = (struct acl_info *) new_ptr;
		error = 0;
		break;
	}
	up(&domain_acl_lock);
	return error;
}

int CheckConnectEntry(const int is_stream, const unsigned short int port)
{
	struct domain_info * const domain = GetCurrentDomain();
	struct acl_info *ptr;
	const unsigned int type_hash = MAKE_ACL_TYPE(TYPE_CONNECT_ACL) + MAKE_ACL_HASH(is_stream ? 1 : 0);
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_CONNECTPORT);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_CONNECTPORT)) return 0;
	if (domain->attribute & DOMAIN_ATTRIBUTE_TRUSTED) {
		AuditPortLog(is_stream, port, 1);
		return 0;
	}
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type_hash == type_hash && ((NETWORK_ACL_RECORD *) ptr)->min_port <= port && port <= ((NETWORK_ACL_RECORD *) ptr)->max_port) break;
	}
	if (ptr) {
		AuditPortLog(is_stream, port, 1);
		return 0;
	}
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: Connect to %s port %d denied for %s\n", GetMSG(is_enforce), is_stream ? "TCP" : "UDP", port, GetLastName(domain));
	}
	AuditPortLog(is_stream, port, 0);
	if (is_enforce) return -EPERM;
	if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_CONNECTPORT)) AddConnectEntry(is_stream, port, port, domain);
	return 0;
}

int AddConnectPolicy(char *data, void **domain)
{
	unsigned int from, to;
	if (!isRoot()) return -EPERM;
	if (sscanf(data, "TCP/%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536) return AddConnectEntry(1, from, to, (struct domain_info *) *domain);
	} else if (sscanf(data, "TCP/%u", &from) == 1) {
		if (from < 65536) return AddConnectEntry(1, from, from, (struct domain_info *) *domain);
	} else if (sscanf(data, "UDP/%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536) return AddConnectEntry(0, from, to, (struct domain_info *) *domain);
	} else if (sscanf(data, "UDP/%u", &from) == 1) {
		if (from < 65536) return AddConnectEntry(0, from, from, (struct domain_info *) *domain);
	}
	printk("%s: ERROR: Invalid port range '%s'\n", __FUNCTION__, data);
	return -EINVAL;
}

EXPORT_SYMBOL(CheckConnectEntry);

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditPortLog(const int is_stream, const unsigned short int port, const int is_granted)
{
	char *buf;
	int len;
	struct timeval tv;
	struct task_struct *task = current;
	const char *domainname = current->domain_info->domainname;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	do_gettimeofday(&tv);
	len = strlen(domainname) + 256;
	if ((buf = kmalloc(len, GFP_KERNEL)) == NULL) return -ENOMEM;
	memset(buf, 0, len);
	snprintf(buf, len - 1, "#timestamp=%lu pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d\n%s\n" KEYWORD_ALLOW_CONNECT "%s-%u\n", tv.tv_sec, task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, domainname, is_stream ? "TCP" : "UDP", port);
	return WriteAuditLog(buf, is_granted);
}

/***** TOMOYO Linux end. *****/
