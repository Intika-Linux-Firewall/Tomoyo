/*
 * fs/tomoyo_port.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.2   2006/09/03
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

#ifdef CONFIG_TOMOYO_AUDIT
static int AuditPortLog(const int is_connect, const int is_stream, const u16 port, const int is_granted)
{
	char *buf;
	int len = 64;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, "%s%s/%u\n", is_connect ? KEYWORD_ALLOW_CONNECT : KEYWORD_ALLOW_BIND, is_stream ? "TCP" : "UDP", port);
	return WriteAuditLog(buf, is_granted);
}
#else
static inline void AuditPortLog(const int is_connect, const int is_stream, const u16 port, const int is_granted) {}
#endif

/*************************  NETWORK PORT ACL HANDLER  *************************/

static int AddPortEntry(const int is_connect, const int is_stream, const u16 min_port, const u16 max_port, struct domain_info *domain, const int is_delete, const struct condition_list *condition)
{
	struct acl_info *ptr;
	int error = -ENOMEM;
	const unsigned int type_hash = MAKE_ACL_TYPE(is_connect ? TYPE_CONNECT_ACL : TYPE_BIND_ACL) + MAKE_ACL_HASH(is_stream ? 1 : 0);
	if (!domain) return -EINVAL;
	down(&domain_acl_lock);
	if (!is_delete) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			NETWORK_ACL_RECORD *new_ptr;
			if (ptr->type_hash == type_hash && ptr->cond == condition) {
				if (((NETWORK_ACL_RECORD *) ptr)->min_port == min_port && max_port == ((NETWORK_ACL_RECORD *) ptr)->max_port) {
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
			new_ptr->head.type_hash = type_hash;
			new_ptr->head.cond = condition;
			new_ptr->min_port = min_port;
			new_ptr->max_port = max_port;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		struct acl_info *prev = NULL;
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; prev = ptr, ptr = ptr->next) {
			if (ptr->type_hash != type_hash || ptr->cond != condition) continue;
			if (((NETWORK_ACL_RECORD *) ptr)->min_port != min_port || ((NETWORK_ACL_RECORD *) ptr)->max_port != max_port) continue;
			error = DelDomainACL(prev, domain, ptr);
			break;
		}
	}
	up(&domain_acl_lock);
	return error;
}

static int CheckPortEntry(const int is_connect, const int is_stream, const u16 port)
{
	struct domain_info * const domain = current->domain_info;
	struct acl_info *ptr;
	const unsigned int type_hash = MAKE_ACL_TYPE(is_connect ? TYPE_CONNECT_ACL : TYPE_BIND_ACL) + MAKE_ACL_HASH(is_stream ? 1 : 0);
	const int is_enforce = CheckCCSEnforce(is_connect ? CCS_TOMOYO_MAC_FOR_CONNECTPORT : CCS_TOMOYO_MAC_FOR_BINDPORT);
	if (!CheckCCSFlags(is_connect ? CCS_TOMOYO_MAC_FOR_CONNECTPORT : CCS_TOMOYO_MAC_FOR_BINDPORT)) return 0;
	if (GetDomainAttribute(domain) & DOMAIN_ATTRIBUTE_TRUSTED) {
		AuditPortLog(is_connect, is_stream, port, 1);
		return 0;
	}
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type_hash == type_hash && ((NETWORK_ACL_RECORD *) ptr)->min_port <= port && port <= ((NETWORK_ACL_RECORD *) ptr)->max_port && CheckCondition(ptr->cond, NULL) == 0) break;
	}
	if (ptr) {
		AuditPortLog(is_connect, is_stream, port, 1);
		return 0;
	}
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: %s to %s port %d denied for %s\n", GetMSG(is_enforce), is_connect ?  "Connect" : "Bind", is_stream ? "TCP" : "UDP", port, GetLastName(domain));
	}
	AuditPortLog(is_connect, is_stream, port, 0);
	if (is_enforce) return CheckSupervisor("%s\n%s%s/%u\n", domain->domainname, is_connect ? KEYWORD_ALLOW_CONNECT : KEYWORD_ALLOW_BIND, is_stream ? "TCP" : "UDP", port);
	if (CheckCCSAccept(is_connect ? CCS_TOMOYO_MAC_FOR_CONNECTPORT : CCS_TOMOYO_MAC_FOR_BINDPORT)) AddPortEntry(is_connect, is_stream, port, port, domain, 0, NULL);
	return 0;
}

int AddPortPolicy(char *data, struct domain_info *domain, const int is_delete)
{
	unsigned int from, to;
	int is_connect = 0;
	const struct condition_list *condition = NULL;
	char *cp;
	if (strncmp(data, KEYWORD_ALLOW_BIND, KEYWORD_ALLOW_BIND_LEN) == 0) {
		data += KEYWORD_ALLOW_BIND_LEN;
	} else if (strncmp(data, KEYWORD_ALLOW_CONNECT, KEYWORD_ALLOW_CONNECT_LEN) == 0) {
		data += KEYWORD_ALLOW_CONNECT_LEN;
		is_connect = 1;
	} else {
		goto out;
	}
	cp = FindConditionPart(data);
	if (cp && (condition = FindOrAssignNewCondition(cp)) == NULL) goto out;
	if (sscanf(data, "TCP/%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536) return AddPortEntry(is_connect, 1, from, to, domain, is_delete, condition);
	} else if (sscanf(data, "TCP/%u", &from) == 1) {
		if (from < 65536) return AddPortEntry(is_connect, 1, from, from, domain, is_delete, condition);
	} else if (sscanf(data, "UDP/%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536) return AddPortEntry(is_connect, 0, from, to, domain, is_delete, condition);
	} else if (sscanf(data, "UDP/%u", &from) == 1) {
		if (from < 65536) return AddPortEntry(is_connect, 0, from, from, domain, is_delete, condition);
	}
 out: ;
	return -EINVAL;
}

int CheckConnectEntry(const int is_stream, const u16 port)
{
	return CheckPortEntry(1, is_stream, port);
}

int CheckBindEntry(const int is_stream, const u16 port)
{
	return CheckPortEntry(0, is_stream, port);
}

EXPORT_SYMBOL(CheckConnectEntry);
EXPORT_SYMBOL(CheckBindEntry);

/***** TOMOYO Linux end. *****/
