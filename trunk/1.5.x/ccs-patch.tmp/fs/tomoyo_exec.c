/*
 * fs/tomoyo_exec.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.5.2-pre   2007/11/27
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

extern struct mutex domain_acl_lock;

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditArgv0Log(const struct path_info *filename, const char *argv0, const bool is_granted)
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

static int AddArgv0Entry(const char *filename, const char *argv0, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	struct acl_info *ptr;
	struct argv0_acl_record *acl;
	const struct path_info *saved_filename, *saved_argv0;
	int error = -ENOMEM;
	if (!IsCorrectPath(filename, 1, 0, -1, __FUNCTION__) || !IsCorrectPath(argv0, -1, 0, -1, __FUNCTION__) || strchr(argv0, '/')) return -EINVAL;
	if ((saved_filename = SaveName(filename)) == NULL || (saved_argv0 = SaveName(argv0)) == NULL) return -ENOMEM;
	mutex_lock(&domain_acl_lock);
	if (!is_delete) {
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = container_of(ptr, struct argv0_acl_record, head);
			if (ptr->type == TYPE_ARGV0_ACL && ptr->cond == condition) {
				if (acl->filename == saved_filename && acl->argv0 == saved_argv0) {
					ptr->is_deleted = 0;
					/* Found. Nothing to do. */
					error = 0;
					goto out;
				}
			}
		}
		/* Not found. Append it to the tail. */
		if ((acl = alloc_element(sizeof(*acl))) == NULL) goto out;
		acl->head.type = TYPE_ARGV0_ACL;
		acl->head.cond = condition;
		acl->filename = saved_filename;
		acl->argv0 = saved_argv0;
		error = AddDomainACL(domain, &acl->head);
	} else {
		error = -ENOENT;
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = container_of(ptr, struct argv0_acl_record, head);
			if (ptr->type != TYPE_ARGV0_ACL || ptr->is_deleted || ptr->cond != condition) continue;
			if (acl->filename != saved_filename || acl->argv0 != saved_argv0) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
 out: ;
	mutex_unlock(&domain_acl_lock);
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
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct argv0_acl_record *acl;
		acl = container_of(ptr, struct argv0_acl_record, head);
		if (ptr->type == TYPE_ARGV0_ACL && ptr->is_deleted == 0 && CheckCondition(ptr->cond, NULL) == 0 &&
			PathMatchesToPattern(filename, acl->filename) &&
			PathMatchesToPattern(&argv0, acl->argv0)) {
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
		const bool is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_ARGV0);
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

int AddArgv0Policy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	char *argv0 = strchr(data, ' ');
	if (!argv0) return -EINVAL;
	*argv0++ = '\0';
	return AddArgv0Entry(data, argv0, domain, condition, is_delete);
}

/***** TOMOYO Linux end. *****/
