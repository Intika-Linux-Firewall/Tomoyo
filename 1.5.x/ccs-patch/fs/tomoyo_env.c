/*
 * fs/tomoyo_env.c
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

static int AuditEnvLog(const char *env, const bool is_granted)
{
	char *buf;
	int len;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	len = strlen(env) + 8;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_ENV "%s\n", env);
	return WriteAuditLog(buf, is_granted);
}

/***** The structure for globally usable environments. *****/

struct globally_usable_env_entry {
	struct list1_head list;
	const struct path_info *env;
	bool is_deleted;
};

/*************************  GLOBALLY USABLE ENVIRONMENT HANDLER  *************************/

static LIST1_HEAD(globally_usable_env_list);

static int AddGloballyUsableEnvEntry(const char *env, const bool is_delete)
{
	struct globally_usable_env_entry *new_entry, *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_env;
	int error = -ENOMEM;
	if (!IsCorrectPath(env, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if ((saved_env = SaveName(env)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &globally_usable_env_list, list) {
		if (ptr->env == saved_env) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT; goto out;
	}
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->env = saved_env;
	list1_add_tail_mb(&new_entry->list, &globally_usable_env_list);
	error = 0;
 out: ;
	mutex_unlock(&lock);
	return error;
}

static int IsGloballyUsableEnv(const struct path_info *env)
{
	struct globally_usable_env_entry *ptr;
	list1_for_each_entry(ptr, &globally_usable_env_list, list) {
		if (!ptr->is_deleted && PathMatchesToPattern(env, ptr->env)) return 1;
	}
	return 0;
}

int AddGloballyUsableEnvPolicy(char *env, const bool is_delete)
{
	return AddGloballyUsableEnvEntry(env, is_delete);
}

int ReadGloballyUsableEnvPolicy(struct io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &globally_usable_env_list) {
		struct globally_usable_env_entry *ptr;
		ptr = list1_entry(pos, struct globally_usable_env_entry, list);
		if (ptr->is_deleted) continue;
		if (io_printf(head, KEYWORD_ALLOW_ENV "%s\n", ptr->env->name)) return -ENOMEM;
	}
	return 0;
}

/*************************  ENVIRONMENT VARIABLE CHECKING HANDLER  *************************/

static int AddEnvEntry(const char *env, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	struct acl_info *ptr;
	struct env_acl_record *acl;
	const struct path_info *saved_env;
	int error = -ENOMEM;
	if (!IsCorrectPath(env, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if ((saved_env = SaveName(env)) == NULL) return -ENOMEM;
	if (!is_delete && IsGloballyUsableEnv(saved_env)) return 0;
	
	mutex_lock(&domain_acl_lock);
	if (!is_delete) {
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = container_of(ptr, struct env_acl_record, head);
			if (ptr->type == TYPE_ENV_ACL && ptr->cond == condition) {
				if (acl->env == saved_env) {
					ptr->is_deleted = 0;
					/* Found. Nothing to do. */
					error = 0;
					goto out;
				}
			}
		}
		/* Not found. Append it to the tail. */
		if ((acl = alloc_element(sizeof(*acl))) == NULL) goto out;
		acl->head.type = TYPE_ENV_ACL;
		acl->head.cond = condition;
		acl->env = saved_env;
		error = AddDomainACL(domain, &acl->head);
	} else {
		error = -ENOENT;
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = container_of(ptr, struct env_acl_record, head);
			if (ptr->type != TYPE_ENV_ACL || ptr->is_deleted || ptr->cond != condition) continue;
			if (acl->env != saved_env) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
 out: ;
	mutex_unlock(&domain_acl_lock);
	return error;
}

static int CheckEnvACL(const char *env_)
{
	const struct domain_info *domain = current->domain_info;
	int error = -EPERM;
	struct acl_info *ptr;
	struct path_info env;
	env.name = env_;
	fill_path_info(&env);
	if (IsGloballyUsableEnv(&env)) return 0;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct env_acl_record *acl;
		acl = container_of(ptr, struct env_acl_record, head);
		if (ptr->type == TYPE_ENV_ACL && ptr->is_deleted == 0 && CheckCondition(ptr->cond, NULL) == 0 &&
		    PathMatchesToPattern(&env, acl->env)) {
			error = 0;
			break;
		}
	}
	return error;
}

int CheckEnvPerm(const char *env)
{
	int error = 0;
	if (!env || !*env) return 0;
	error = CheckEnvACL(env);
	AuditEnvLog(env, !error);
	if (error) {
		struct domain_info * const domain = current->domain_info;
		const bool is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_ENV);
		if (TomoyoVerboseMode()) {
			printk("TOMOYO-%s: Environ %s denied for %s\n", GetMSG(is_enforce), env, GetLastName(domain));
		}
		if (is_enforce) error = CheckSupervisor("%s\n" KEYWORD_ALLOW_ENV "%s\n", domain->domainname->name, env);
		else if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_ENV, domain)) AddEnvEntry(env, domain, NULL, 0);
		if (!is_enforce) error = 0;
	}
	return error;
}
EXPORT_SYMBOL(CheckEnvPerm);

int AddEnvPolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	return AddEnvEntry(data, domain, condition, is_delete);
}

/***** TOMOYO Linux end. *****/
