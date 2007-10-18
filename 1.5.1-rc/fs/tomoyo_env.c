/*
 * fs/tomoyo_env.c
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

static int AuditEnvLog(const char *env, const u8 is_granted)
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
	struct globally_usable_env_entry *next;
	const struct path_info *env;
	u8 is_deleted;
};

/*************************  GLOBALLY USABLE ENVIRONMENT HANDLER  *************************/

static struct globally_usable_env_entry *globally_usable_env_list = NULL;

static int AddGloballyUsableEnvEntry(const char *env, const u8 is_delete)
{
	struct globally_usable_env_entry *new_entry, *ptr;
	static DECLARE_MUTEX(lock);
	const struct path_info *saved_env;
	int error = -ENOMEM;
	if (!IsCorrectPath(env, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if ((saved_env = SaveName(env)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = globally_usable_env_list; ptr; ptr = ptr->next) {
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
	mb(); /* Instead of using spinlock. */
	if ((ptr = globally_usable_env_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		globally_usable_env_list = new_entry;
	}
	error = 0;
 out: ;
	up(&lock);
	return error;
}

static int IsGloballyUsableEnv(const struct path_info *env)
{
	struct globally_usable_env_entry *ptr;
	for (ptr = globally_usable_env_list; ptr; ptr = ptr->next) {
		if (!ptr->is_deleted && PathMatchesToPattern(env, ptr->env)) return 1;
	}
	return 0;
}

int AddGloballyUsableEnvPolicy(char *env, const u8 is_delete)
{
	return AddGloballyUsableEnvEntry(env, is_delete);
}

int ReadGloballyUsableEnvPolicy(struct io_buffer *head)
{
	struct globally_usable_env_entry *ptr = head->read_var2;
	if (!ptr) ptr = globally_usable_env_list;
	while (ptr) {
		head->read_var2 = ptr;
		if (!ptr->is_deleted && io_printf(head, KEYWORD_ALLOW_ENV "%s\n", ptr->env->name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

/*************************  ENVIRONMENT VARIABLE CHECKING HANDLER  *************************/

static int AddEnvEntry(const char *env, struct domain_info *domain, const struct condition_list *condition, const u8 is_delete)
{
	struct acl_info *ptr;
	const struct path_info *saved_env;
	int error = -ENOMEM;
	if (!IsCorrectPath(env, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if ((saved_env = SaveName(env)) == NULL) return -ENOMEM;
	if (!is_delete && IsGloballyUsableEnv(saved_env)) return 0;
	
	down(&domain_acl_lock);
	if (!is_delete) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			struct env_acl_record *new_ptr;
			if (ptr->type == TYPE_ENV_ACL && ptr->cond == condition) {
				if (((struct env_acl_record *) ptr)->env == saved_env) {
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
			new_ptr->head.type = TYPE_ENV_ACL;
			new_ptr->head.cond = condition;
			new_ptr->env = saved_env;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
			if (ptr->type != TYPE_ENV_ACL || ptr->is_deleted || ptr->cond != condition) continue;
			if (((struct env_acl_record *) ptr)->env != saved_env) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
	up(&domain_acl_lock);
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
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type == TYPE_ENV_ACL && ptr->is_deleted == 0 && CheckCondition(ptr->cond, NULL) == 0 &&
			PathMatchesToPattern(&env, ((struct env_acl_record *) ptr)->env)) {
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
		const u8 is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_ENV);
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

int AddEnvPolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const u8 is_delete)
{
	return AddEnvEntry(data, domain, condition, is_delete);
}

/***** TOMOYO Linux end. *****/
