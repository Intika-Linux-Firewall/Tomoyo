/*
 * fs/tomoyo_domain.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.3.2   2007/02/14
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#ifndef for_each_process
#define for_each_process for_each_task
#endif

/*************************  VARIABLES  *************************/

/* The initial domain. */
struct domain_info KERNEL_DOMAIN = { NULL, NULL, NULL, 0, 0, 0 };

/* /sbin/init started? */
extern int sbin_init_started;

#ifdef CONFIG_TOMOYO

/* Lock for appending domain's ACL. */
DECLARE_MUTEX(domain_acl_lock);

/*************************  UTILITY FUNCTIONS  *************************/

/***** The structure for program files to force domain reconstruction. *****/

typedef struct domain_initializer_entry {
	struct domain_initializer_entry *next;
	const struct path_info *domainname;    /* This may be NULL */
	const struct path_info *program;
	u8 is_deleted;
	u8 is_not;
	u8 is_last_name;
	u8 is_oldstyle;
} DOMAIN_INITIALIZER_ENTRY;

/***** The structure for domains to not to transit domains. *****/

typedef struct domain_keeper_entry {
	struct domain_keeper_entry *next;
	const struct path_info *domainname;
	const struct path_info *program;       /* This may be NULL */
	u8 is_deleted;
	u8 is_not;
	u8 is_last_name;
} DOMAIN_KEEPER_ENTRY;

/***** The structure for program files that should be aggregated. *****/

typedef struct aggregator_entry {
	struct aggregator_entry *next;
	const struct path_info *original_name;
	const struct path_info *aggregated_name;
	int is_deleted;
} AGGREGATOR_ENTRY;

/***** The structure for program files that should be aliased. *****/

typedef struct alias_entry {
	struct alias_entry *next;
	const struct path_info *original_name;
	const struct path_info *aliased_name;
	int is_deleted;
} ALIAS_ENTRY;

/*************************  VARIABLES  *************************/

/* Domain creation lock. */
static DECLARE_MUTEX(new_domain_assign_lock);

/*************************  UTILITY FUNCTIONS  *************************/

int IsDomainDef(const unsigned char *buffer)
{
	/* while (*buffer && (*buffer <= ' ' || *buffer >= 127)) buffer++; */
	return strncmp(buffer, ROOT_NAME, ROOT_NAME_LEN) == 0;
}

const char *GetLastName(const struct domain_info *domain)
{
	const char *cp0 = domain->domainname->name, *cp1;
	if ((cp1 = strrchr(cp0, ' ')) != NULL) return cp1 + 1;
	return cp0;
}

int ReadSelfDomain(IO_BUFFER *head)
{
	if (!head->read_eof) {
		io_printf(head, "%s", current->domain_info->domainname->name);
		head->read_eof = 1;
	}
	return 0;
}

int AddDomainACL(struct acl_info *ptr, struct domain_info *domain, struct acl_info *new_ptr)
{
	mb(); /* Instead of using spinlock. */
	if (!ptr) domain->first_acl_ptr = (struct acl_info *) new_ptr;
	else ptr->next = (struct acl_info *) new_ptr;
	UpdateCounter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

int DelDomainACL(struct acl_info *ptr)
{
	ptr->is_deleted = 1;
	UpdateCounter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

/*************************  DOMAIN INITIALIZER HANDLER  *************************/

static DOMAIN_INITIALIZER_ENTRY *domain_initializer_list = NULL;

static int AddDomainInitializerEntry(const char *domainname, const char *program, const int is_not, const int is_delete, const int is_oldstyle)
{
	DOMAIN_INITIALIZER_ENTRY *new_entry, *ptr;
	static DECLARE_MUTEX(lock);
	const struct path_info *saved_program, *saved_domainname = NULL;
	int error = -ENOMEM;
	int is_last_name = 0;
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
	down(&lock);
	for (ptr = domain_initializer_list; ptr; ptr = ptr->next) {
		if (ptr->is_not == is_not && ptr->is_oldstyle == is_oldstyle && ptr->domainname == saved_domainname && ptr->program == saved_program) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = (DOMAIN_INITIALIZER_ENTRY *) alloc_element(sizeof(DOMAIN_INITIALIZER_ENTRY))) == NULL) goto out;
	new_entry->domainname = saved_domainname;
	new_entry->program = saved_program;
	new_entry->is_not = is_not;
	new_entry->is_last_name = is_last_name;
	new_entry->is_oldstyle = is_oldstyle;
	mb(); /* Instead of using spinlock. */
	if ((ptr = domain_initializer_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		domain_initializer_list = new_entry;
	}
	error = 0;
 out:
	up(&lock);
	return error;
}

int ReadDomainInitializerPolicy(IO_BUFFER *head)
{
	DOMAIN_INITIALIZER_ENTRY *ptr = (DOMAIN_INITIALIZER_ENTRY *) head->read_var2;
	if (!ptr) ptr = domain_initializer_list;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (!ptr->is_deleted) {
			if (ptr->domainname) {
				if (io_printf(head, "%s%s%s from %s\n", ptr->is_not ? "no_" : "", ptr->is_oldstyle ? KEYWORD_INITIALIZER : KEYWORD_INITIALIZE_DOMAIN, ptr->program->name, ptr->domainname->name)) break;
			} else {
				if (io_printf(head, "%s%s%s\n", ptr->is_not ? "no_" : "", ptr->is_oldstyle ? KEYWORD_INITIALIZER : KEYWORD_INITIALIZE_DOMAIN, ptr->program->name)) break;
			}
		}
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

int AddDomainInitializerPolicy(char *data, const int is_not, const int is_delete, const int is_oldstyle)
{
	char *cp = strstr(data, " from ");
	if (cp) {
		*cp = '\0';
		return AddDomainInitializerEntry(cp + 6, data, is_not, is_delete, is_oldstyle);
	} else {
		return AddDomainInitializerEntry(NULL, data, is_not, is_delete, is_oldstyle);
	}
}

static int IsDomainInitializer(const struct path_info *domainname, const struct path_info *program, const struct path_info *last_name)
{
	DOMAIN_INITIALIZER_ENTRY *ptr;
	int flag = 0;
	for (ptr = domain_initializer_list; ptr; ptr = ptr->next) {
		if (ptr->is_deleted ) continue;
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

static DOMAIN_KEEPER_ENTRY *domain_keeper_list = NULL;

static int AddDomainKeeperEntry(const char *domainname, const char *program, const int is_not, const int is_delete)
{
	DOMAIN_KEEPER_ENTRY *new_entry, *ptr;
	const struct path_info *saved_domainname, *saved_program = NULL;
	static DECLARE_MUTEX(lock);
	int error = -ENOMEM;
	int is_last_name = 0;
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
	down(&lock);
	for (ptr = domain_keeper_list; ptr; ptr = ptr->next) {
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
	if ((new_entry = (DOMAIN_KEEPER_ENTRY *) alloc_element(sizeof(DOMAIN_KEEPER_ENTRY))) == NULL) goto out;
	new_entry->domainname = saved_domainname;
	new_entry->program = saved_program;
	new_entry->is_not = is_not;
	new_entry->is_last_name = is_last_name;
	mb(); /* Instead of using spinlock. */
	if ((ptr = domain_keeper_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		domain_keeper_list = new_entry;
	}
	error = 0;
 out:
	up(&lock);
	return error;
}

int AddDomainKeeperPolicy(char *data, const int is_not, const int is_delete)
{
	char *cp = strstr(data, " from ");
	if (cp) {
		*cp = '\0';
		return AddDomainKeeperEntry(cp + 6, data, is_not, is_delete);
	} else {
		return AddDomainKeeperEntry(data, NULL, is_not, is_delete);
	}
}

int ReadDomainKeeperPolicy(IO_BUFFER *head)
{
	DOMAIN_KEEPER_ENTRY *ptr = (DOMAIN_KEEPER_ENTRY *) head->read_var2;
	if (!ptr) ptr = domain_keeper_list;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (!ptr->is_deleted) {
			if (ptr->program) {
				if (io_printf(head, "%s" KEYWORD_KEEP_DOMAIN "%s from %s\n", ptr->is_not ? "no_" : "", ptr->program->name, ptr->domainname->name)) break;
			} else {
				if (io_printf(head, "%s" KEYWORD_KEEP_DOMAIN "%s\n", ptr->is_not ? "no_" : "", ptr->domainname->name)) break;
			}
		}
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

static int IsDomainKeeper(const struct path_info *domainname, const struct path_info *program, const struct path_info *last_name)
{
	DOMAIN_KEEPER_ENTRY *ptr;
	int flag = 0;
	for (ptr = domain_keeper_list; ptr; ptr = ptr->next) {
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

static ALIAS_ENTRY *alias_list = NULL;

static int AddAliasEntry(const char *original_name, const char *aliased_name, const int is_delete)
{
	ALIAS_ENTRY *new_entry, *ptr;
	static DECLARE_MUTEX(lock);
	const struct path_info *saved_original_name, *saved_aliased_name;
	int error = -ENOMEM;
	if (!IsCorrectPath(original_name, 1, -1, -1, __FUNCTION__) || !IsCorrectPath(aliased_name, 1, -1, -1, __FUNCTION__)) return -EINVAL; /* No patterns allowed. */
	if ((saved_original_name = SaveName(original_name)) == NULL || (saved_aliased_name = SaveName(aliased_name)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = alias_list; ptr; ptr = ptr->next) {
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
	if ((new_entry = (ALIAS_ENTRY *) alloc_element(sizeof(ALIAS_ENTRY))) == NULL) goto out;
	new_entry->original_name = saved_original_name;
	new_entry->aliased_name = saved_aliased_name;
	mb(); /* Instead of using spinlock. */
	if ((ptr = alias_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		alias_list = new_entry;
	}
	error = 0;
 out:
	up(&lock);
	return error;
}

int ReadAliasPolicy(IO_BUFFER *head)
{
	ALIAS_ENTRY *ptr = (ALIAS_ENTRY *) head->read_var2;
	if (!ptr) ptr = alias_list;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (!ptr->is_deleted && io_printf(head, KEYWORD_ALIAS "%s %s\n", ptr->original_name->name, ptr->aliased_name->name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

int AddAliasPolicy(char *data, const int is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp++ = '\0';
	return AddAliasEntry(data, cp, is_delete);
}

/*************************  DOMAIN AGGREGATOR HANDLER  *************************/

static AGGREGATOR_ENTRY *aggregator_list = NULL;

static int AddAggregatorEntry(const char *original_name, const char *aggregated_name, const int is_delete)
{
	AGGREGATOR_ENTRY *new_entry, *ptr;
	static DECLARE_MUTEX(lock);
	const struct path_info *saved_original_name, *saved_aggregated_name;
	int error = -ENOMEM;
	if (!IsCorrectPath(original_name, 1, 0, -1, __FUNCTION__) || !IsCorrectPath(aggregated_name, 1, -1, -1, __FUNCTION__)) return -EINVAL;
	if ((saved_original_name = SaveName(original_name)) == NULL || (saved_aggregated_name = SaveName(aggregated_name)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = aggregator_list; ptr; ptr = ptr->next) {
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
	if ((new_entry = (AGGREGATOR_ENTRY *) alloc_element(sizeof(AGGREGATOR_ENTRY))) == NULL) goto out;
	new_entry->original_name = saved_original_name;
	new_entry->aggregated_name = saved_aggregated_name;
	mb(); /* Instead of using spinlock. */
	if ((ptr = aggregator_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		aggregator_list = new_entry;
	}
	error = 0;
 out:
	up(&lock);
	return error;
}

int ReadAggregatorPolicy(IO_BUFFER *head)
{
	AGGREGATOR_ENTRY *ptr = (AGGREGATOR_ENTRY *) head->read_var2;
	if (!ptr) ptr = aggregator_list;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (!ptr->is_deleted && io_printf(head, KEYWORD_AGGREGATOR "%s %s\n", ptr->original_name->name, ptr->aggregated_name->name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

int AddAggregatorPolicy(char *data, const int is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp++ = '\0';
	return AddAggregatorEntry(data, cp, is_delete);
}

/*************************  DOMAIN DELETION HANDLER  *************************/

// #define DEBUG_DOMAIN_UNDELETE

int DeleteDomain(char *domainname0)
{
	struct domain_info *domain;
	struct path_info domainname;
	domainname.name = domainname0;
	fill_path_info(&domainname);
	down(&new_domain_assign_lock);
#ifdef DEBUG_DOMAIN_UNDELETE
	printk("DeleteDomain %s\n", domainname0);
	for (domain = KERNEL_DOMAIN.next; domain; domain = domain->next) {
		if (pathcmp(domain->domainname, &domainname)) continue;
		printk("List: %p %u\n", domain, domain->is_deleted);
	}
#endif
	/* Is there an active domain? */
	for (domain = KERNEL_DOMAIN.next; domain; domain = domain->next) { /* Never delete KERNEL_DOMAIN */
		if (domain->is_deleted || pathcmp(domain->domainname, &domainname)) continue;
		break;
	}
	if (domain) {
		struct domain_info *domain2;
		/* Mark already deleted domains as non undeletable. */
		for (domain2 = KERNEL_DOMAIN.next; domain2; domain2 = domain2->next) {
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
	}
	up(&new_domain_assign_lock);
	return 0;
}

struct domain_info *UndeleteDomain(const char *domainname0)
{
	struct domain_info *domain, *candidate_domain = NULL;
	struct path_info domainname;
	domainname.name = domainname0;
	fill_path_info(&domainname);
	down(&new_domain_assign_lock);
#ifdef DEBUG_DOMAIN_UNDELETE
	printk("UndeleteDomain %s\n", domainname0);
	for (domain = KERNEL_DOMAIN.next; domain; domain = domain->next) {
		if (pathcmp(domain->domainname, &domainname)) continue;
		printk("List: %p %u\n", domain, domain->is_deleted);
	}
#endif
	for (domain = KERNEL_DOMAIN.next; domain; domain = domain->next) {
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
	up(&new_domain_assign_lock);
	return candidate_domain;
}

/*************************  DOMAIN TRANSITION HANDLER  *************************/

struct domain_info *FindDomain(const char *domainname0)
{
	struct domain_info *domain;
	static int first = 1;
	struct path_info domainname;
	domainname.name = domainname0;
	fill_path_info(&domainname);
	if (first) {
		KERNEL_DOMAIN.domainname = SaveName(ROOT_NAME);
		first = 0;
	}
	for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
		if (!domain->is_deleted && !pathcmp(&domainname, domain->domainname)) return domain;
	}
	return NULL;
}

struct domain_info *FindOrAssignNewDomain(const char *domainname, const u8 profile)
{
	struct domain_info *domain = NULL;
	const struct path_info *saved_domainname;
	down(&new_domain_assign_lock);
	if ((domain = FindDomain(domainname)) != NULL) goto out;
	if (!IsCorrectDomain(domainname, __FUNCTION__)) goto out;
	if ((saved_domainname = SaveName(domainname)) == NULL) goto out;
	/* Can I reuse memory of deleted domain? */
	for (domain = KERNEL_DOMAIN.next; domain; domain = domain->next) {
		struct task_struct *p;
		struct acl_info *ptr;
		int flag;
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
		for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) ptr->is_deleted = 1;
		domain->profile = profile;
		domain->quota_warned = 0;
		mb(); /* Instead of using spinlock. */
		domain->is_deleted = 0;
		goto out;
	}
	/* No memory reusable. Create using new memory. */
	if ((domain = (struct domain_info *) alloc_element(sizeof(struct domain_info))) != NULL) {
		struct domain_info *ptr = &KERNEL_DOMAIN;
		domain->domainname = saved_domainname;
		domain->profile = profile;
		mb(); /* Instead of using spinlock. */
		while (ptr->next) ptr = ptr->next; ptr->next = domain;
	}
 out: ;
	up(&new_domain_assign_lock);
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

int FindNextDomain(const char *original_name, struct file *filp, struct domain_info **next_domain, char __user * __user *argv)
{
	/* This function assumes that the size of buffer returned by realpath() = CCS_MAX_PATHNAME_LEN. */
	struct domain_info *old_domain = current->domain_info, *domain = NULL;
	const char *old_domain_name = old_domain->domainname->name;
	char *new_domain_name = NULL;
	char *real_program_name = NULL, *symlink_program_name = NULL;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	int retval;
	struct path_info r, s, l;

	{
		/*
		 * Built-in initializers. This is needed because policies are not loaded until starting /sbin/init .
		 */
		static int first = 1;
		if (first) {
			AddDomainInitializerEntry(NULL, "/sbin/hotplug", 0, 0, 0);
			AddDomainInitializerEntry(NULL, "/sbin/modprobe", 0, 0, 0);
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

	/* Check 'alias' directive. */
	if (pathcmp(&r, &s)) {
		ALIAS_ENTRY *ptr;
		/* Is this program allowed to be called via symbolic links? */
		for (ptr = alias_list; ptr; ptr = ptr->next) {
			if (ptr->is_deleted || pathcmp(&r, ptr->original_name) || pathcmp(&s, ptr->aliased_name)) continue;
			memset(real_program_name, 0, CCS_MAX_PATHNAME_LEN);
			strncpy(real_program_name, ptr->aliased_name->name, CCS_MAX_PATHNAME_LEN - 1);
			fill_path_info(&r);
			break;
		}
	}
	
	/* Check 'aggregator' directive. */
	{
		AGGREGATOR_ENTRY *ptr;
		/* Is this program allowed to be aggregated? */
		for (ptr = aggregator_list; ptr; ptr = ptr->next) {
			if (ptr->is_deleted || !PathMatchesToPattern(&r, ptr->original_name)) continue;
			memset(real_program_name, 0, CCS_MAX_PATHNAME_LEN);
			strncpy(real_program_name, ptr->aggregated_name->name, CCS_MAX_PATHNAME_LEN - 1);
			fill_path_info(&r);
			break;
		}
	}

	/* Compare basename of symlink_program_name and argv[0] */
	if (argv && CheckCCSFlags(CCS_TOMOYO_MAC_FOR_ARGV0)) {
		char __user *p;
		retval = 0;
		if (get_user(p, argv) == 0 && p) {
			const int len = strlen_user(p);
			char *org_argv0 = ccs_alloc(len + 1), *printable_argv0 = NULL;
			if (!org_argv0) {
				retval = -ENOMEM;
			} else if (copy_from_user(org_argv0, p, len)) {
				retval = -EFAULT;
			} else if ((printable_argv0 = ccs_alloc(len * 4 + 8)) == NULL || Escape(printable_argv0, org_argv0, len * 4 + 8)) {
				retval = -ENOMEM;
			} else {
				const char *base_argv0, *base_filename;
				if ((base_argv0 = strrchr(printable_argv0, '/')) == NULL) base_argv0 = printable_argv0; else base_argv0++;
				if ((base_filename = strrchr(symlink_program_name, '/')) == NULL) base_filename = symlink_program_name; else base_filename++;
				if (strcmp(base_argv0, base_filename)) retval = CheckArgv0Perm(&s, base_argv0);
			}
			ccs_free(printable_argv0);
			ccs_free(org_argv0);
		}
		if (retval) goto out;
	}
	
	/* Check execute permission. */
	if ((retval = CheckExecPerm(&r, filp)) < 0) goto out;

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

#endif

/***** TOMOYO Linux end. *****/
