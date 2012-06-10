/*
 * fs/tomoyo_exec.c
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
static int AuditArgv0Log(const char *filename, const char *argv0, const int is_granted)
{
	char *buf;
	int len;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	len = strlen(filename) + 8;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_ARGV0 "%s %s\n", filename, argv0);
	return WriteAuditLog(buf, is_granted);
}

#else
static inline void AuditArgv0Log(const char *filename, const char *argv0, const int is_granted) {}
#endif

/*************************  ARGV0 MISMATCH HANDLER  *************************/

static int AddArgv0Entry(const char *filename, const char *argv0, struct domain_info *domain, const int is_delete, const struct condition_list *condition)
{
	struct acl_info *ptr;
	const char *saved_filename;
	const char *saved_argv0;
	int error = -ENOMEM;
	const unsigned int type_hash = MAKE_ACL_TYPE(TYPE_ARGV0_ACL) + MAKE_ACL_HASH(PathDepth(filename));
	down(&domain_acl_lock);
	if (!is_delete) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			ARGV0_ACL_RECORD *new_ptr;
			if (ptr->type_hash == type_hash && ptr->cond == condition) {
				if (strcmp(((ARGV0_ACL_RECORD *) ptr)->filename, filename) == 0 && strcmp(((ARGV0_ACL_RECORD *) ptr)->argv0, argv0) == 0) {
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
			if ((saved_filename = SaveName(filename)) == NULL) break;
			if ((saved_argv0 = SaveName(argv0)) == NULL) break;
			if ((new_ptr = (ARGV0_ACL_RECORD *) alloc_element(sizeof(ARGV0_ACL_RECORD))) == NULL) break;
			new_ptr->head.type_hash = type_hash;
			new_ptr->head.cond = condition;
			new_ptr->filename = saved_filename;
			new_ptr->argv0 = saved_argv0;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		struct acl_info *prev = NULL;
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; prev = ptr, ptr = ptr->next) {
			if (type_hash != ptr->type_hash || ptr->cond != condition) continue;
			if (strcmp(((ARGV0_ACL_RECORD *) ptr)->filename, filename) || strcmp(((ARGV0_ACL_RECORD *) ptr)->argv0, argv0)) continue;
			error = DelDomainACL(prev, domain, ptr);
			break;
		}
	}
	up(&domain_acl_lock);
	return error;
}

static int CheckArgv0ACL(const char *filename, const char *argv0)
{
	const struct domain_info *domain = current->domain_info;
	int error = -EPERM;
	unsigned int type_hash;
	struct acl_info *ptr;
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_ARGV0)) return 0;
	if (GetDomainAttribute(domain) & DOMAIN_ATTRIBUTE_TRUSTED) return 0;
	type_hash = MAKE_ACL_TYPE(TYPE_ARGV0_ACL) + MAKE_ACL_HASH(PathDepth(filename));
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type_hash == type_hash && CheckCondition(ptr->cond, NULL) == 0 &&
			PathMatchesToPattern(filename, ((ARGV0_ACL_RECORD *) ptr)->filename) &&
			PathMatchesToPattern(argv0, ((ARGV0_ACL_RECORD *) ptr)->argv0)) {
			error = 0;
			break;
		}
	}
	return error;
}

int CheckArgv0Perm(const char *filename, const char *argv0)
{
	int error = 0;
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_ARGV0)) return 0;
	if (!filename || !argv0) return 0;
	error = CheckArgv0ACL(filename, argv0);
	AuditArgv0Log(filename, argv0, !error);
	if (error) {
		struct domain_info * const domain = current->domain_info;
		const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_ARGV0);
		if (TomoyoVerboseMode()) {
			printk("TOMOYO-%s: Run %s as %s denied for %s\n", GetMSG(is_enforce), filename, argv0, GetLastName(domain));
		}
		if (is_enforce) error = CheckSupervisor("%s\n" KEYWORD_ALLOW_ARGV0 "%s %s\n", domain->domainname, filename, argv0);
		else if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_ARGV0)) AddArgv0Entry(filename, argv0, domain, 0, NULL);
		if (!is_enforce) error = 0;
	}
	return error;
}

int AddArgv0Policy(char *data, struct domain_info *domain, const int is_delete)
{
	char *argv0 = strchr(data, ' ');
	char *cp;
	const struct condition_list *condition = NULL;
	if (!argv0) return -EINVAL;
	*argv0++ = '\0';
	cp = FindConditionPart(argv0);
	if (cp && (condition = FindOrAssignNewCondition(cp)) == NULL) return -EINVAL;
	return AddArgv0Entry(data, argv0, domain, is_delete, condition);
}

EXPORT_SYMBOL(CheckArgv0Perm);

/***** TOMOYO Linux end. *****/
