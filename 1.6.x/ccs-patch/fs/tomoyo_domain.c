/*
 * fs/tomoyo_domain.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.0-pre   2008/02/25
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#include <linux/highmem.h>
#include <linux/binfmts.h>

#ifndef for_each_process
#define for_each_process for_each_task
#endif

/*************************  VARIABLES  *************************/

/* The initial domain. */
struct domain_info KERNEL_DOMAIN;

/* List of domains. */
LIST1_HEAD(domain_list);

/* /sbin/init started? */
extern bool sbin_init_started;

#ifdef CONFIG_TOMOYO

/* Lock for appending domain's ACL. */
DEFINE_MUTEX(domain_acl_lock);

/*************************  UTILITY FUNCTIONS  *************************/

/***** The structure for program files to force domain reconstruction. *****/

struct domain_initializer_entry {
	struct list1_head list;
	const struct path_info *domainname;    /* This may be NULL */
	const struct path_info *program;
	bool is_deleted;
	bool is_not;
	bool is_last_name;
};

/***** The structure for domains to not to transit domains. *****/

struct domain_keeper_entry {
	struct list1_head list;
	const struct path_info *domainname;
	const struct path_info *program;       /* This may be NULL */
	bool is_deleted;
	bool is_not;
	bool is_last_name;
};

/***** The structure for program files that should be aggregated. *****/

struct aggregator_entry {
	struct list1_head list;
	const struct path_info *original_name;
	const struct path_info *aggregated_name;
	bool is_deleted;
};

/***** The structure for program files that should be aliased. *****/

struct alias_entry {
	struct list1_head list;
	const struct path_info *original_name;
	const struct path_info *aliased_name;
	bool is_deleted;
};

/*************************  VARIABLES  *************************/

/* Domain creation lock. */
static DEFINE_MUTEX(new_domain_assign_lock);

/*************************  UTILITY FUNCTIONS  *************************/

const char *GetLastName(const struct domain_info *domain)
{
	const char *cp0 = domain->domainname->name, *cp1;
	if ((cp1 = strrchr(cp0, ' ')) != NULL) return cp1 + 1;
	return cp0;
}

int AddDomainACL(struct domain_info *domain, struct acl_info *acl)
{
	if (domain) list1_add_tail_mb(&acl->list, &domain->acl_info_list);
	else acl->type &= ~ACL_DELETED;
	UpdateCounter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

int DelDomainACL(struct acl_info *acl)
{
	if (acl) acl->type |= ACL_DELETED;
	UpdateCounter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

/*************************  DOMAIN INITIALIZER HANDLER  *************************/

static LIST1_HEAD(domain_initializer_list);

static int AddDomainInitializerEntry(const char *domainname, const char *program, const bool is_not, const bool is_delete)
{
	struct domain_initializer_entry *new_entry, *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_program, *saved_domainname = NULL;
	int error = -ENOMEM;
	bool is_last_name = 0;
	if (!IsCorrectPath(program, 1, -1, -1, __FUNCTION__)) return -EINVAL; /* No patterns allowed. */
	if (domainname) {
		if (!IsDomainDef(domainname) && IsCorrectPath(domainname, 1, -1, -1, __FUNCTION__)) {
			is_last_name = 1;
		} else if (!IsCorrectDomain(domainname, __FUNCTION__)) {
			return -EINVAL;
		}
		if ((saved_domainname = SaveName(domainname)) == NULL) return -ENOMEM;
	}
	if ((saved_program = SaveName(program)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &domain_initializer_list, list) {
		if (ptr->is_not == is_not && ptr->domainname == saved_domainname && ptr->program == saved_program) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->domainname = saved_domainname;
	new_entry->program = saved_program;
	new_entry->is_not = is_not;
	new_entry->is_last_name = is_last_name;
	list1_add_tail_mb(&new_entry->list, &domain_initializer_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	return error;
}

int ReadDomainInitializerPolicy(struct io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &domain_initializer_list) {
		struct domain_initializer_entry *ptr;
		ptr = list1_entry(pos, struct domain_initializer_entry, list);
		if (ptr->is_deleted) continue;
		if (ptr->domainname) {
			if (io_printf(head, "%s" KEYWORD_INITIALIZE_DOMAIN "%s from %s\n", ptr->is_not ? "no_" : "", ptr->program->name, ptr->domainname->name)) return -ENOMEM;
		} else {
			if (io_printf(head, "%s" KEYWORD_INITIALIZE_DOMAIN "%s\n", ptr->is_not ? "no_" : "", ptr->program->name)) return -ENOMEM;
		}
	}
	return 0;
}

int AddDomainInitializerPolicy(char *data, const bool is_not, const bool is_delete)
{
	char *cp = strstr(data, " from ");
	if (cp) {
		*cp = '\0';
		return AddDomainInitializerEntry(cp + 6, data, is_not, is_delete);
	} else {
		return AddDomainInitializerEntry(NULL, data, is_not, is_delete);
	}
}

static bool IsDomainInitializer(const struct path_info *domainname, const struct path_info *program, const struct path_info *last_name)
{
	struct domain_initializer_entry *ptr;
	bool flag = 0;
	list1_for_each_entry(ptr,  &domain_initializer_list, list) {
		if (ptr->is_deleted) continue;
		if (ptr->domainname) {
			if (!ptr->is_last_name) {
				if (ptr->domainname != domainname) continue;
			} else {
				if (pathcmp(ptr->domainname, last_name)) continue;
			}
		}
		if (pathcmp(ptr->program, program)) continue;
		if (ptr->is_not) return 0;
		flag = 1;
	}
	return flag;
}

/*************************  DOMAIN KEEPER HANDLER  *************************/

static LIST1_HEAD(domain_keeper_list);

static int AddDomainKeeperEntry(const char *domainname, const char *program, const bool is_not, const bool is_delete)
{
	struct domain_keeper_entry *new_entry, *ptr;
	const struct path_info *saved_domainname, *saved_program = NULL;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	bool is_last_name = 0;
	if (!IsDomainDef(domainname) && IsCorrectPath(domainname, 1, -1, -1, __FUNCTION__)) {
		is_last_name = 1;
	} else if (!IsCorrectDomain(domainname, __FUNCTION__)) {
		return -EINVAL;
	}
	if (program) {
		if (!IsCorrectPath(program, 1, -1, -1, __FUNCTION__)) return -EINVAL;
		if ((saved_program = SaveName(program)) == NULL) return -ENOMEM;
	}
	if ((saved_domainname = SaveName(domainname)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &domain_keeper_list, list) {
		if (ptr->is_not == is_not && ptr->domainname == saved_domainname && ptr->program == saved_program) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->domainname = saved_domainname;
	new_entry->program = saved_program;
	new_entry->is_not = is_not;
	new_entry->is_last_name = is_last_name;
	list1_add_tail_mb(&new_entry->list, &domain_keeper_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	return error;
}

int AddDomainKeeperPolicy(char *data, const bool is_not, const bool is_delete)
{
	char *cp = strstr(data, " from ");
	if (cp) {
		*cp = '\0';
		return AddDomainKeeperEntry(cp + 6, data, is_not, is_delete);
	} else {
		return AddDomainKeeperEntry(data, NULL, is_not, is_delete);
	}
}

int ReadDomainKeeperPolicy(struct io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &domain_keeper_list) {
		struct domain_keeper_entry *ptr;
		ptr = list1_entry(pos, struct domain_keeper_entry, list);
		if (ptr->is_deleted) continue;
		if (ptr->program) {
			if (io_printf(head, "%s" KEYWORD_KEEP_DOMAIN "%s from %s\n", ptr->is_not ? "no_" : "", ptr->program->name, ptr->domainname->name)) return -ENOMEM;
		} else {
			if (io_printf(head, "%s" KEYWORD_KEEP_DOMAIN "%s\n", ptr->is_not ? "no_" : "", ptr->domainname->name)) return -ENOMEM;
		}
	}
	return 0;
}

static bool IsDomainKeeper(const struct path_info *domainname, const struct path_info *program, const struct path_info *last_name)
{
	struct domain_keeper_entry *ptr;
	bool flag = 0;
	list1_for_each_entry(ptr, &domain_keeper_list, list) {
		if (ptr->is_deleted) continue;
		if (!ptr->is_last_name) {
			if (ptr->domainname != domainname) continue;
		} else {
			if (pathcmp(ptr->domainname, last_name)) continue;
		}
		if (ptr->program && pathcmp(ptr->program, program)) continue;
		if (ptr->is_not) return 0;
		flag = 1;
	}
	return flag;
}

/*************************  SYMBOLIC LINKED PROGRAM HANDLER  *************************/

static LIST1_HEAD(alias_list);

static int AddAliasEntry(const char *original_name, const char *aliased_name, const bool is_delete)
{
	struct alias_entry *new_entry, *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_original_name, *saved_aliased_name;
	int error = -ENOMEM;
	if (!IsCorrectPath(original_name, 1, -1, -1, __FUNCTION__) || !IsCorrectPath(aliased_name, 1, -1, -1, __FUNCTION__)) return -EINVAL; /* No patterns allowed. */
	if ((saved_original_name = SaveName(original_name)) == NULL || (saved_aliased_name = SaveName(aliased_name)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &alias_list, list) {
		if (ptr->original_name == saved_original_name && ptr->aliased_name == saved_aliased_name) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->original_name = saved_original_name;
	new_entry->aliased_name = saved_aliased_name;
	list1_add_tail_mb(&new_entry->list, &alias_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	return error;
}

int ReadAliasPolicy(struct io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &alias_list) {
		struct alias_entry *ptr;
		ptr = list1_entry(pos, struct alias_entry, list);
		if (ptr->is_deleted) continue;
		if (io_printf(head, KEYWORD_ALIAS "%s %s\n", ptr->original_name->name, ptr->aliased_name->name)) return -ENOMEM;
	}
	return 0;
}

int AddAliasPolicy(char *data, const bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp++ = '\0';
	return AddAliasEntry(data, cp, is_delete);
}

/*************************  DOMAIN AGGREGATOR HANDLER  *************************/

static LIST1_HEAD(aggregator_list);

static int AddAggregatorEntry(const char *original_name, const char *aggregated_name, const bool is_delete)
{
	struct aggregator_entry *new_entry, *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_original_name, *saved_aggregated_name;
	int error = -ENOMEM;
	if (!IsCorrectPath(original_name, 1, 0, -1, __FUNCTION__) || !IsCorrectPath(aggregated_name, 1, -1, -1, __FUNCTION__)) return -EINVAL;
	if ((saved_original_name = SaveName(original_name)) == NULL || (saved_aggregated_name = SaveName(aggregated_name)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &aggregator_list, list) {
		if (ptr->original_name == saved_original_name && ptr->aggregated_name == saved_aggregated_name) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->original_name = saved_original_name;
	new_entry->aggregated_name = saved_aggregated_name;
	list1_add_tail_mb(&new_entry->list, &aggregator_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	return error;
}

int ReadAggregatorPolicy(struct io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &aggregator_list) {
		struct aggregator_entry *ptr;
		ptr = list1_entry(pos, struct aggregator_entry, list);
		if (ptr->is_deleted) continue;
		if (io_printf(head, KEYWORD_AGGREGATOR "%s %s\n", ptr->original_name->name, ptr->aggregated_name->name)) return -ENOMEM;
	}
	return 0;
}

int AddAggregatorPolicy(char *data, const bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp++ = '\0';
	return AddAggregatorEntry(data, cp, is_delete);
}

/*************************  DOMAIN DELETION HANDLER  *************************/

/* #define DEBUG_DOMAIN_UNDELETE */

int DeleteDomain(char *domainname0)
{
	struct domain_info *domain;
	struct path_info domainname;
	domainname.name = domainname0;
	fill_path_info(&domainname);
	mutex_lock(&new_domain_assign_lock);
#ifdef DEBUG_DOMAIN_UNDELETE
	printk("DeleteDomain %s\n", domainname0);
	list1_for_each_entry(domain, &domain_list, list) {
		if (pathcmp(domain->domainname, &domainname)) continue;
		printk("List: %p %u\n", domain, domain->is_deleted);
	}
#endif
	/* Is there an active domain? */
	list1_for_each_entry(domain, &domain_list, list) {
		struct domain_info *domain2;
		/* Never delete KERNEL_DOMAIN */
		if (domain == &KERNEL_DOMAIN || domain->is_deleted || pathcmp(domain->domainname, &domainname)) continue;
		/* Mark already deleted domains as non undeletable. */
		list1_for_each_entry(domain2, &domain_list, list) {
			if (!domain2->is_deleted || pathcmp(domain2->domainname, &domainname)) continue;
#ifdef DEBUG_DOMAIN_UNDELETE
			if (domain2->is_deleted != 255) printk("Marked %p as non undeletable\n", domain2);
#endif
			domain2->is_deleted = 255;
		}
		/* Delete and mark active domain as undeletable. */
		domain->is_deleted = 1;
#ifdef DEBUG_DOMAIN_UNDELETE
		printk("Marked %p as undeletable\n", domain);
#endif
		break;
	}
	mutex_unlock(&new_domain_assign_lock);
	return 0;
}

struct domain_info *UndeleteDomain(const char *domainname0)
{
	struct domain_info *domain, *candidate_domain = NULL;
	struct path_info domainname;
	domainname.name = domainname0;
	fill_path_info(&domainname);
	mutex_lock(&new_domain_assign_lock);
#ifdef DEBUG_DOMAIN_UNDELETE
	printk("UndeleteDomain %s\n", domainname0);
	list1_for_each_entry(domain, &domain_list, list) {
		if (pathcmp(domain->domainname, &domainname)) continue;
		printk("List: %p %u\n", domain, domain->is_deleted);
	}
#endif
	list1_for_each_entry(domain, &domain_list, list) {
		if (pathcmp(&domainname, domain->domainname)) continue;
		if (!domain->is_deleted) {
			/* This domain is active. I can't undelete. */
			candidate_domain = NULL;
#ifdef DEBUG_DOMAIN_UNDELETE
			printk("%p is active. I can't undelete.\n", domain);
#endif
			break;
		}
		/* Is this domain undeletable? */
		if (domain->is_deleted == 1) candidate_domain = domain;
	}
	if (candidate_domain) {
		candidate_domain->is_deleted = 0;
#ifdef DEBUG_DOMAIN_UNDELETE
		printk("%p was undeleted.\n", candidate_domain);
#endif
	}
	mutex_unlock(&new_domain_assign_lock);
	return candidate_domain;
}

/*************************  DOMAIN TRANSITION HANDLER  *************************/

struct domain_info *FindOrAssignNewDomain(const char *domainname, const u8 profile)
{
	struct domain_info *domain = NULL;
	const struct path_info *saved_domainname;
	mutex_lock(&new_domain_assign_lock);
	if ((domain = FindDomain(domainname)) != NULL) goto out;
	if (!IsCorrectDomain(domainname, __FUNCTION__)) goto out;
	if ((saved_domainname = SaveName(domainname)) == NULL) goto out;
	/* Can I reuse memory of deleted domain? */
	list1_for_each_entry(domain, &domain_list, list) {
		struct task_struct *p;
		struct acl_info *ptr;
		bool flag;
		if (!domain->is_deleted || domain->domainname != saved_domainname) continue;
		flag = 0;
		/***** CRITICAL SECTION START *****/
		read_lock(&tasklist_lock);
		for_each_process(p) {
			if (p->domain_info == domain) { flag = 1; break; }
		}
		read_unlock(&tasklist_lock);
		/***** CRITICAL SECTION END *****/
		if (flag) continue;
#ifdef DEBUG_DOMAIN_UNDELETE
		printk("Reusing %p %s\n", domain, domain->domainname->name);
#endif
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			ptr->type |= ACL_DELETED;
		}
		domain->profile = profile;
		domain->quota_warned = 0;
		mb(); /* Avoid out-of-order execution. */
		domain->is_deleted = 0;
		goto out;
	}
	/* No memory reusable. Create using new memory. */
	if ((domain = alloc_element(sizeof(*domain))) != NULL) {
		INIT_LIST1_HEAD(&domain->acl_info_list);
		domain->domainname = saved_domainname;
		domain->profile = profile;
		list1_add_tail_mb(&domain->list, &domain_list);
	}
 out: ;
	mutex_unlock(&new_domain_assign_lock);
	return domain;
}

static int Escape(char *dest, const char *src, int dest_len)
{
	while (*src) {
		const unsigned char c = * (const unsigned char *) src;
		if (c == '\\') {
			dest_len -= 2;
			if (dest_len <= 0) goto out;
			*dest++ = '\\';
			*dest++ = '\\';
		} else if (c > ' ' && c < 127) {
			if (--dest_len <= 0) goto out;
			*dest++ = c;
		} else {
			dest_len -= 4;
			if (dest_len <= 0) goto out;
			*dest++ = '\\';
			*dest++ = (c >> 6) + '0';
			*dest++ = ((c >> 3) & 7) + '0';
			*dest++ = (c & 7) + '0';
		}
		src++;
	}
	if (--dest_len <= 0) goto out;
	*dest = '\0';
	return 0;
 out:
	return -ENOMEM;
}

static char *get_argv0(struct linux_binprm *bprm)
{
	char *arg_ptr = ccs_alloc(PAGE_SIZE); /* Initial buffer. */
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int i = pos / PAGE_SIZE, offset = pos % PAGE_SIZE;
	if (!bprm->argc || !arg_ptr) goto out;
	while (1) {
		struct page *page;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
		if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page, NULL) <= 0) goto out;
#else
		page = bprm->page[i];
#endif
		{ /* Map and copy to kernel buffer and unmap. */
			const char *kaddr = kmap(page);
			if (!kaddr) { /* Mapping failed. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
				put_page(page);
#endif
				goto out;
			}
			memmove(arg_ptr + arg_len, kaddr + offset, PAGE_SIZE - offset);
			kunmap(page);
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
		put_page(page);
		pos += PAGE_SIZE - offset;
#endif
		arg_len += PAGE_SIZE - offset;
		if (memchr(arg_ptr, '\0', arg_len)) break;
		{ /* Initial buffer was too small for argv[0]. Retry after expanding buffer. */
			char *tmp_arg_ptr = ccs_alloc(arg_len + PAGE_SIZE);
			if (!tmp_arg_ptr) goto out;
			memmove(tmp_arg_ptr, arg_ptr, arg_len);
			ccs_free(arg_ptr);
			arg_ptr = tmp_arg_ptr;
		}
		i++;
		offset = 0;
	}
	return arg_ptr;
 out: /* Release initial buffer. */
	ccs_free(arg_ptr);
	return NULL;
}

static int FindNextDomain(struct linux_binprm *bprm, struct domain_info **next_domain, const u8 do_perm_check)
{
	/* This function assumes that the size of buffer returned by realpath() = CCS_MAX_PATHNAME_LEN. */
	struct domain_info *old_domain = current->domain_info, *domain = NULL;
	const char *old_domain_name = old_domain->domainname->name;
	const char *original_name = bprm->filename;
	char *new_domain_name = NULL;
	char *real_program_name = NULL, *symlink_program_name = NULL;
	const bool is_enforce = (CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE) == 3);
	int retval;
	struct path_info r, s, l;

	{
		/*
		 * Built-in initializers. This is needed because policies are not loaded until starting /sbin/init .
		 */
		static bool first = 1;
		if (first) {
			AddDomainInitializerEntry(NULL, "/sbin/hotplug", 0, 0);
			AddDomainInitializerEntry(NULL, "/sbin/modprobe", 0, 0);
			first = 0;
		}
	}

	/* Get realpath of program. */
	retval = -ENOENT; /* I hope realpath() won't fail with -ENOMEM. */
	if ((real_program_name = realpath(original_name)) == NULL) goto out;
	/* Get realpath of symbolic link. */
	if ((symlink_program_name = realpath_nofollow(original_name)) == NULL) goto out;

	r.name = real_program_name;
	fill_path_info(&r);
	s.name = symlink_program_name;
	fill_path_info(&s);
	if ((l.name = strrchr(old_domain_name, ' ')) != NULL) l.name++;
	else l.name = old_domain_name;
	fill_path_info(&l);

	if (!do_perm_check) goto ok;

	/* Check 'alias' directive. */
	if (pathcmp(&r, &s)) {
		struct alias_entry *ptr;
		/* Is this program allowed to be called via symbolic links? */
		list1_for_each_entry(ptr, &alias_list, list) {
			if (ptr->is_deleted || pathcmp(&r, ptr->original_name) || pathcmp(&s, ptr->aliased_name)) continue;
			memset(real_program_name, 0, CCS_MAX_PATHNAME_LEN);
			strncpy(real_program_name, ptr->aliased_name->name, CCS_MAX_PATHNAME_LEN - 1);
			fill_path_info(&r);
			break;
		}
	}
	
	/* Compare basename of real_program_name and argv[0] */
	if (bprm->argc > 0 && CheckCCSFlags(CCS_TOMOYO_MAC_FOR_ARGV0)) {
		char *org_argv0 = get_argv0(bprm);
		retval = -ENOMEM;
		if (org_argv0) {
			const int len = strlen(org_argv0);
			char *printable_argv0 = ccs_alloc(len * 4 + 8);
			if (printable_argv0 && Escape(printable_argv0, org_argv0, len * 4 + 8) == 0) {
				const char *base_argv0, *base_filename;
				if ((base_argv0 = strrchr(printable_argv0, '/')) == NULL) base_argv0 = printable_argv0; else base_argv0++;
				if ((base_filename = strrchr(real_program_name, '/')) == NULL) base_filename = real_program_name; else base_filename++;
				if (strcmp(base_argv0, base_filename)) retval = CheckArgv0Perm(&r, base_argv0);
				else retval = 0;
			}
			ccs_free(printable_argv0);
			ccs_free(org_argv0);
		}
		if (retval) goto out;
	}
	
	/* Check 'aggregator' directive. */
	{
		struct aggregator_entry *ptr;
		/* Is this program allowed to be aggregated? */
		list1_for_each_entry(ptr, &aggregator_list, list) {
			if (ptr->is_deleted || !PathMatchesToPattern(&r, ptr->original_name)) continue;
			memset(real_program_name, 0, CCS_MAX_PATHNAME_LEN);
			strncpy(real_program_name, ptr->aggregated_name->name, CCS_MAX_PATHNAME_LEN - 1);
			fill_path_info(&r);
			break;
		}
	}

	/* Check execute permission. */
	if ((retval = CheckExecPerm(&r, bprm)) < 0) goto out;

 ok: ;
	/* Allocate memory for calcurating domain name. */
	retval = -ENOMEM;
	if ((new_domain_name = ccs_alloc(CCS_MAX_PATHNAME_LEN + 16)) == NULL) goto out;
	
	if (IsDomainInitializer(old_domain->domainname, &r, &l)) {
		/* Transit to the child of KERNEL_DOMAIN domain. */
		snprintf(new_domain_name, CCS_MAX_PATHNAME_LEN + 1, ROOT_NAME " " "%s", real_program_name);
	} else if (old_domain == &KERNEL_DOMAIN && !sbin_init_started) {
		/*
		 * Needn't to transit from kernel domain before starting /sbin/init .
		 * But transit from kernel domain if executing initializers, for they might start before /sbin/init .
		 */
		domain = old_domain;
	} else if (IsDomainKeeper(old_domain->domainname, &r, &l)) {
		/* Keep current domain. */
		domain = old_domain;
	} else {
		/* Normal domain transition. */
		snprintf(new_domain_name, CCS_MAX_PATHNAME_LEN + 1, "%s %s", old_domain_name, real_program_name);
	}
	if (!domain && strlen(new_domain_name) < CCS_MAX_PATHNAME_LEN) {
		if (is_enforce) {
			domain = FindDomain(new_domain_name);
			if (!domain) if (CheckSupervisor("#Need to create domain\n%s\n", new_domain_name) == 0) domain = FindOrAssignNewDomain(new_domain_name, current->domain_info->profile);
		} else {
			domain = FindOrAssignNewDomain(new_domain_name, current->domain_info->profile);
		}
	}
	if (!domain) {
		printk("TOMOYO-ERROR: Domain '%s' not defined.\n", new_domain_name);
		if (is_enforce) retval = -EPERM;
	} else {
		retval = 0;
	}
 out: ;
	ccs_free(new_domain_name);
	ccs_free(real_program_name);
	ccs_free(symlink_program_name);
	*next_domain = domain ? domain : old_domain;
	return retval;
}

static int CheckEnviron(struct linux_binprm *bprm)
{
	const u8 profile = current->domain_info->profile;
	const u8 mode = CheckCCSFlags(CCS_TOMOYO_MAC_FOR_ENV);
	char *arg_ptr;
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int i = pos / PAGE_SIZE, offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	//printk("start %d %d\n", argv_count, envp_count);
	int error = -ENOMEM;
	if (!mode || !envp_count) return 0;
	arg_ptr = ccs_alloc(CCS_MAX_PATHNAME_LEN);
	if (!arg_ptr) goto out;
	while (error == -ENOMEM) {
		struct page *page;
		const char *kaddr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
		if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page, NULL) <= 0) goto out;
		pos += PAGE_SIZE - offset;
#else
		page = bprm->page[i];
#endif
		/* Map */
		kaddr = kmap(page);
		if (!kaddr) { /* Mapping failed. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
			put_page(page);
#endif
			goto out;
		}
		/* Read. */
		while (argv_count && offset < PAGE_SIZE) {
			if (!kaddr[offset++]) argv_count--;
		}
		if (argv_count) goto unmap_page;
		while (offset < PAGE_SIZE) {
			const unsigned char c = kaddr[offset++];
			if (c && arg_len < CCS_MAX_PATHNAME_LEN - 10) {
				if (c == '=') {
					arg_ptr[arg_len++] = '\0';
				} else if (c == '\\') {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = '\\';
				} else if (c > ' ' && c < 127) {
					arg_ptr[arg_len++] = c;
				} else {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = (c >> 6) + '0';
					arg_ptr[arg_len++] = ((c >> 3) & 7) + '0';
					arg_ptr[arg_len++] = (c & 7) + '0';
				}
			} else {
				arg_ptr[arg_len] = '\0';
			}
			if (c) continue;
			if (CheckEnvPerm(arg_ptr, profile, mode)) {
				error = -EPERM;
				break;
			}
			if (!--envp_count) {
				error = 0;
				break;
			}
			arg_len = 0;
		}
	unmap_page:
		/* Unmap. */
		kunmap(page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23) && defined(CONFIG_MMU)
		put_page(page);
#endif
		i++;
		offset = 0;
	}
 out:
	ccs_free(arg_ptr);
	if (error && mode != 3) error = 0;
	return error;
}

static void UnEscape(unsigned char *dest)
{
	unsigned char *src = dest;
	unsigned char c, d, e;
	while ((c = *src++) != '\0') {
		if (c != '\\') {
			*dest++ = c;
			continue;
		}
		c = *src++;
		if (c == '\\') {
			*dest++ = c;
		} else if (c >= '0' && c <= '3' &&
			   (d = *src++) >= '0' && d <= '7' &&
			   (e = *src++) >= '0' && e <= '7') {
			*dest++ = ((c - '0') << 6) | ((d - '0') << 3) | (e - '0');
		} else {
			break;
		}
	}
	*dest = '\0';
}

static int try_alt_exec(struct linux_binprm *bprm, char **work)
{
	/*
	 * Contents of modified bprm.
	 * The envp[] in original bprm is moved to argv[] so that
	 * the alternatively executed program won't be affected by
	 * some dangerous environment variables like LD_PRELOAD .
	 *
	 * modified bprm->argc
	 *    = original bprm->argc + original bprm->envc + 7
	 * modified bprm->envc
	 *    = 0
	 *
	 * modified bprm->argv[0]
	 *    = the program's name specified by alt_exec
	 * modified bprm->argv[1]
	 *    = current->domain_info->domainname->name
	 * modified bprm->argv[2]
	 *    = the current process's name
	 * modified bprm->argv[3]
	 *    = the current process's information (e.g. uid/gid).
	 * modified bprm->argv[4]
	 *    = original bprm->filename
	 * modified bprm->argv[5]
	 *    = original bprm->argc in string expression
	 * modified bprm->argv[6]
	 *    = original bprm->envc in string expression
	 * modified bprm->argv[7]
	 *    = original bprm->argv[0]
	 *  ...
	 * modified bprm->argv[bprm->argc + 6]
	 *     = original bprm->argv[bprm->argc - 1]
	 * modified bprm->argv[bprm->argc + 7]
	 *     = original bprm->envp[0]
	 *  ...
	 * modified bprm->argv[bprm->envc + bprm->argc + 6]
	 *     = original bprm->envp[bprm->envc - 1]
	 */
	struct file *filp;
	int retval;
	const int original_argc = bprm->argc;
	const int original_envc = bprm->envc;
	struct task_struct *task = current;
	static const int buffer_len = PAGE_SIZE;
	char *buffer = NULL;
	char *alt_exec;
	const char *alt_exec1 = GetAltExec();
	if (!alt_exec1 || *alt_exec1 != '/') return -EINVAL;
	retval = strlen(alt_exec1) + 1;
	alt_exec = ccs_alloc(retval);
	if (!alt_exec) return -ENOMEM;
	*work = alt_exec;
	memmove(alt_exec, alt_exec1, retval);
	UnEscape(alt_exec);

	/* Close the rejected program's dentry. */
	allow_write_access(bprm->file);
	fput(bprm->file);
	bprm->file = NULL;

	/* Allocate buffer. */
	buffer = ccs_alloc(buffer_len);
	if (!buffer) return -ENOMEM;

	/* Move envp[] to argv[] */
	bprm->argc += bprm->envc;
	bprm->envc = 0;

	/* Set argv[6] */
	{
		snprintf(buffer, buffer_len - 1, "%d", original_envc);
		retval = copy_strings_kernel(1, &buffer, bprm);
		if (retval < 0) goto out;
		bprm->argc++;
	}

	/* Set argv[5] */
	{
		snprintf(buffer, buffer_len - 1, "%d", original_argc);
		retval = copy_strings_kernel(1, &buffer, bprm);
		if (retval < 0) goto out;
		bprm->argc++;
	}

	/* Set argv[4] */
	{
		retval = copy_strings_kernel(1, &bprm->filename, bprm);
		if (retval < 0) goto out;
		bprm->argc++;
	}

	/* Set argv[3] */
	{
		const u32 tomoyo_flags = task->tomoyo_flags;
		snprintf(buffer, buffer_len - 1, "pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d state[0]=%u state[1]=%u state[2]=%u", task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, (u8) (tomoyo_flags >> 24), (u8) (tomoyo_flags >> 16), (u8) (tomoyo_flags >> 8));
		retval = copy_strings_kernel(1, &buffer, bprm);
		if (retval < 0) goto out;
		bprm->argc++;
	}

	/* Set argv[2] */
	{
		char *exe = (char *) GetEXE();
		if (exe) {
			retval = copy_strings_kernel(1, &exe, bprm);
			ccs_free(exe);
		} else {
			snprintf(buffer, buffer_len - 1, "<unknown>");
			retval = copy_strings_kernel(1, &buffer, bprm);
		}
		if (retval < 0) goto out;
		bprm->argc++;
	}

	/* Set argv[1] */
	{
		strncpy(buffer, task->domain_info->domainname->name, buffer_len - 1);
		retval = copy_strings_kernel(1, &buffer, bprm);
		if (retval < 0) goto out;
		bprm->argc++;
	}

	/* Set argv[0] */
	{
		retval = copy_strings_kernel(1, &alt_exec, bprm);
		if (retval < 0) goto out;
		bprm->argc++;
	}

	/* OK, now restart the process with the alternative program's dentry. */
	filp = open_exec(alt_exec);
	if (IS_ERR(filp)) {
		retval = PTR_ERR(filp);
		goto out;
	}
	bprm->file= filp;
	bprm->filename = alt_exec;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
	bprm->interp = alt_exec;
#endif
	retval = 0;
 out:
	/* Free buffer. */
	ccs_free(buffer);
	return retval;
}

#endif

int search_binary_handler_with_transition(struct linux_binprm *bprm, struct pt_regs *regs)
{
	struct domain_info *next_domain = NULL, *prev_domain = current->domain_info;
 	int retval;
	char *work = NULL; /* Keep valid until search_binary_handler() finishes. */
#if defined(CONFIG_SAKURA) || defined(CONFIG_TOMOYO)
	extern void CCS_LoadPolicy(const char *filename);
	CCS_LoadPolicy(bprm->filename);
#endif
#if defined(CONFIG_TOMOYO)
	retval = FindNextDomain(bprm, &next_domain, 1);
	if (retval == -EPERM && try_alt_exec(bprm, &work) == 0 && prepare_binprm(bprm) >= 0) {
		current->tomoyo_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
		retval = FindNextDomain(bprm, &next_domain, 0);
		current->tomoyo_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	}
	if (retval == 0) {
		current->domain_info = next_domain;
		retval = CheckEnviron(bprm);
		current->tomoyo_flags |= TOMOYO_CHECK_READ_FOR_OPEN_EXEC;
		if (!retval) retval = search_binary_handler(bprm, regs);
		current->tomoyo_flags &= ~TOMOYO_CHECK_READ_FOR_OPEN_EXEC;
		if (retval < 0) current->domain_info = prev_domain;
	}
	ccs_free(work);
	return retval;
#else
	return search_binary_handler(bprm, regs);
#endif
}

/***** TOMOYO Linux end. *****/
