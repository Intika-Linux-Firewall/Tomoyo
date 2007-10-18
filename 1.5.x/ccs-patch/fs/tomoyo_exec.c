/*
 * fs/tomoyo_exec.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.5.2-pre   2007/10/19
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

static int AuditArgv0Log(const struct path_info *filename, const char *argv0, const u8 is_granted)
{
	char *buf;
	int len;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	len = filename->total_len + strlen(argv0) + 8;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_ARGV0 "%s %s\n", filename->name, argv0);
	return WriteAuditLog(buf, is_granted);
}

/*************************  ARGV0 MISMATCH HANDLER  *************************/

static int AddArgv0Entry(const char *filename, const char *argv0, struct domain_info *domain, const struct condition_list *condition, const u8 is_delete)
{
	struct acl_info *ptr;
	const struct path_info *saved_filename, *saved_argv0;
	int error = -ENOMEM;
	if (!IsCorrectPath(filename, 1, 0, -1, __FUNCTION__) || !IsCorrectPath(argv0, -1, 0, -1, __FUNCTION__) || strchr(argv0, '/')) return -EINVAL;
	if ((saved_filename = SaveName(filename)) == NULL || (saved_argv0 = SaveName(argv0)) == NULL) return -ENOMEM;
	down(&domain_acl_lock);
	if (!is_delete) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			struct argv0_acl_record *new_ptr;
			if (ptr->type == TYPE_ARGV0_ACL && ptr->cond == condition) {
				if (((struct argv0_acl_record *) ptr)->filename == saved_filename && ((struct argv0_acl_record *) ptr)->argv0 == saved_argv0) {
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
			new_ptr->head.type = TYPE_ARGV0_ACL;
			new_ptr->head.cond = condition;
			new_ptr->filename = saved_filename;
			new_ptr->argv0 = saved_argv0;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
			if (ptr->type != TYPE_ARGV0_ACL || ptr->is_deleted || ptr->cond != condition) continue;
			if (((struct argv0_acl_record *) ptr)->filename != saved_filename || ((struct argv0_acl_record *) ptr)->argv0 != saved_argv0) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
	up(&domain_acl_lock);
	return error;
}

static int CheckArgv0ACL(const struct path_info *filename, const char *argv0_)
{
	const struct domain_info *domain = current->domain_info;
	int error = -EPERM;
	struct acl_info *ptr;
	struct path_info argv0;
	argv0.name = argv0_;
	fill_path_info(&argv0);
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type == TYPE_ARGV0_ACL && ptr->is_deleted == 0 && CheckCondition(ptr->cond, NULL) == 0 &&
			PathMatchesToPattern(filename, ((struct argv0_acl_record *) ptr)->filename) &&
			PathMatchesToPattern(&argv0, ((struct argv0_acl_record *) ptr)->argv0)) {
			error = 0;
			break;
		}
	}
	return error;
}

int CheckArgv0Perm(const struct path_info *filename, const char *argv0)
{
	int error = 0;
	if (!filename || !argv0 || !*argv0) return 0;
	error = CheckArgv0ACL(filename, argv0);
	AuditArgv0Log(filename, argv0, !error);
	if (error) {
		struct domain_info * const domain = current->domain_info;
		const u8 is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_ARGV0);
		if (TomoyoVerboseMode()) {
			printk("TOMOYO-%s: Run %s as %s denied for %s\n", GetMSG(is_enforce), filename->name, argv0, GetLastName(domain));
		}
		if (is_enforce) error = CheckSupervisor("%s\n" KEYWORD_ALLOW_ARGV0 "%s %s\n", domain->domainname->name, filename->name, argv0);
		else if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_ARGV0, domain)) AddArgv0Entry(filename->name, argv0, domain, NULL, 0);
		if (!is_enforce) error = 0;
	}
	return error;
}
EXPORT_SYMBOL(CheckArgv0Perm);

int AddArgv0Policy(char *data, struct domain_info *domain, const struct condition_list *condition, const u8 is_delete)
{
	char *argv0 = strchr(data, ' ');
	if (!argv0) return -EINVAL;
	*argv0++ = '\0';
	return AddArgv0Entry(data, argv0, domain, condition, is_delete);
}

/***** TOMOYO Linux end. *****/
