/*
 * fs/tomoyo_domain.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.3.1   2006/12/08
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

#define ROOT_NAME "<kernel>"             /* A domain definition starts with <kernel> . */

/* The initial domain. */
struct domain_info KERNEL_DOMAIN = { NULL, NULL, ROOT_NAME, 0, 0, 0 /* full_name_hash(ROOT_NAME) */ };

/* /sbin/init started? */
extern int sbin_init_started;

#ifdef CONFIG_TOMOYO

/* Lock for appending domain's ACL. */
DECLARE_MUTEX(domain_acl_lock);

/*************************  UTILITY FUNCTIONS  *************************/

/***** The structure for program files to force domain reconstruction. *****/

typedef struct initializer_entry {
	struct initializer_entry *next; /* Pointer to next record. NULL if none.                   */
	u32 hash_and_flag;              /* (full_name_hash(initializer) << 1). LSB is delete flag. */
	const char *initializer;        /* Absolute pathname. Never NULL.                          */
} INITIALIZER_ENTRY;

/***** The structure for program files that should be aggregated. *****/

typedef struct aggregator_entry {
	struct aggregator_entry *next; /* Pointer to next record. NULL if none.                */
	u32 depth_and_flag;            /* (PathDepth(original_name) << 1). LSB is delete flag. */
	const char *original_name;     /* Absolute pathname. Never NULL.                       */
	const char *aggregated_name;   /* Absolute pathname. Never NULL.                       */
} AGGREGATOR_ENTRY;

/***** The structure for program files that should be aliased. *****/

typedef struct alias_entry {
	struct alias_entry *next;  /* Pointer to next record. NULL if none.                     */
	u32 hash_and_flag;         /* (full_name_hash(original_name) << 1). LSB is delete flag. */
	const char *original_name; /* Absolute pathname. Never NULL.                            */
	const char *aliased_name;  /* Absolute pathname. Never NULL.                            */
} ALIAS_ENTRY;

/***** The structure for domains to not to transit domains. *****/

typedef struct domain_keeper_entry {
	struct domain_keeper_entry *next; /* Pointer to next record. NULL if none.                     */
	u32 hash_and_flag;                /* (full_name_hash(domain_keeper) << 1). LSB is delete flag. */
	const char *domain_keeper;        /* Pattern of domain name. Never NULL.                       */
} DOMAIN_KEEPER_ENTRY;

/*************************  PROTOTYPES  *************************/

static int IsInitializer(const char *filename);
static int IsDomainKeeper(const char *domainname);
static int AddInitializerEntry(const char *initializer);

/*************************  VARIABLES  *************************/

/* Domain creation lock. */
static DECLARE_MUTEX(new_domain_assign_lock);

/*************************  UTILITY FUNCTIONS  *************************/

int IsDomainDef(const unsigned char *buffer)
{
	/* while (*buffer && (*buffer <= ' ' || *buffer >= 127)) buffer++; */
	return strncmp(buffer, ROOT_NAME, strlen(ROOT_NAME)) == 0;
}

const char *GetLastName(const struct domain_info *domain)
{
	const char *cp0 = domain->domainname, *cp1;
	if ((cp1 = strrchr(cp0, ' ')) != NULL) return cp1 + 1;
	return cp0;
}

/*
 *  Check whether the given domainname follows the naming rules.
 *  Returns nonzero if follows, zero otherwise.
 */
int IsCorrectDomain(const unsigned char *domainname)
{
	unsigned char c, d, e;
	if (!domainname || strncmp(domainname, ROOT_NAME, strlen(ROOT_NAME))) goto out;
	domainname += strlen(ROOT_NAME);
	if (!*domainname) return 1;
	do {
		if (*domainname++ != ' ') goto out;
		if (*domainname++ != '/') goto out;
		while ((c = *domainname) != '\0' && c != ' ') {
			domainname++;
			if (c == '\\') {
				switch ((c = *domainname++)) {
				case '\\':  /* "\\" */
					continue;
				case '0':   /* "\ooo" */
				case '1':
				case '2':
				case '3':
					if ((d = *domainname++) >= '0' && d <= '7' && (e = *domainname++) >= '0' && e <= '7') {
						const unsigned char f =
							(((unsigned char) (c - '0')) << 6) +
							(((unsigned char) (d - '0')) << 3) +
							(((unsigned char) (e - '0')));
						if (f && (f <= ' ' || f >= 127)) continue; /* pattern is not \000 */
					}
				}
				goto out;
			} else if (c < ' ' || c >= 127) {
				goto out;
			}
		}
	} while (*domainname);
	return 1;
 out:
	return 0;
}

/* Update domain attribute. */
void SetDomainAttribute(struct domain_info *domain, const u16 attribute)
{
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	spin_lock(&lock);
	if (attribute == DOMAIN_ATTRIBUTE_CLEAR_DOMAIN_KEEPER) domain->attributes &= ~DOMAIN_ATTRIBUTE_DOMAIN_KEEPER;
	else domain->attributes |= attribute;
	spin_unlock(&lock);
}

u16 GetDomainAttribute(const struct domain_info *domain)
{
	return domain->attributes;
}

int ReadSelfDomain(IO_BUFFER *head)
{
	if (!head->read_eof) {
		io_printf(head, "%s", current->domain_info->domainname);
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

int DelDomainACL(struct acl_info *prev, struct domain_info *domain, struct acl_info *ptr)
{
	if (prev) prev->next = ptr->next;
	else domain->first_acl_ptr = ptr->next;
	UpdateCounter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

/*************************  DOMAIN INITIALIZER HANDLER  *************************/

static INITIALIZER_ENTRY initializer_list = { NULL, 0, "" };

static int AddInitializerEntry(const char *initializer)
{
	INITIALIZER_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	const char *saved_initializer;
	u32 hash_and_flag;
	if (!IsCorrectPath(initializer, 1, -1, -1, __FUNCTION__)) return -EINVAL; /* No patterns allowed. */
	hash_and_flag = full_name_hash(initializer, strlen(initializer)) << 1;
	/* I don't want to add if it was already added. */
	for (ptr = initializer_list.next; ptr; ptr = ptr->next) if ((ptr->hash_and_flag & ~1) == hash_and_flag && strcmp(ptr->initializer, initializer) == 0) { ptr->hash_and_flag &= ~1; return 0; }
	if ((saved_initializer = SaveName(initializer)) == NULL || (new_entry = (INITIALIZER_ENTRY *) alloc_element(sizeof(INITIALIZER_ENTRY))) == NULL) return -ENOMEM;
	new_entry->hash_and_flag = hash_and_flag;
	new_entry->initializer = saved_initializer;
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	for (ptr = &initializer_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

int ReadInitializerPolicy(IO_BUFFER *head)
{
	INITIALIZER_ENTRY *ptr = (INITIALIZER_ENTRY *) head->read_var2;
	if (!ptr) ptr = initializer_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if ((ptr->hash_and_flag & 1) == 0 && io_printf(head, KEYWORD_INITIALIZER "%s\n", ptr->initializer)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

int AddInitializerPolicy(char *initializer, const int is_delete)
{
	INITIALIZER_ENTRY *ptr;
	if (!is_delete) return AddInitializerEntry(initializer);
	for (ptr = initializer_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->initializer, initializer) == 0) ptr->hash_and_flag |= 1;
	return 0;
}

static int IsInitializer(const char *filename)
{
	if (filename) {
		INITIALIZER_ENTRY *ptr;
		const u32 hash_and_flag = full_name_hash(filename, strlen(filename)) << 1;
		for (ptr = initializer_list.next; ptr; ptr = ptr->next) {
			if (hash_and_flag == ptr->hash_and_flag && strcmp(filename, ptr->initializer) == 0) return 1;
		}
	}
	return 0;
}

/*************************  SYMBOLIC LINKED PROGRAM HANDLER  *************************/

static ALIAS_ENTRY alias_list = { NULL, 0, "", "" };

static int AddAliasEntry(const char *original_name, const char *aliased_name)
{
	ALIAS_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	const char *saved_original_name, *saved_aliased_name;
	u32 hash_and_flag;
	if (!IsCorrectPath(original_name, 1, -1, -1, __FUNCTION__) || !IsCorrectPath(aliased_name, 1, -1, -1, __FUNCTION__)) return -EINVAL; /* No patterns allowed. */
	hash_and_flag = full_name_hash(original_name, strlen(original_name)) << 1;
	/* I don't want to add if it was already added. */
	for (ptr = alias_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->original_name, original_name) == 0 && strcmp(ptr->aliased_name, aliased_name) == 0) { ptr->hash_and_flag &= ~1; return 0; }
	if ((saved_original_name = SaveName(original_name)) == NULL || (saved_aliased_name = SaveName(aliased_name)) == NULL || (new_entry = (ALIAS_ENTRY *) alloc_element(sizeof(ALIAS_ENTRY))) == NULL) return -ENOMEM;
	new_entry->hash_and_flag = hash_and_flag;
	new_entry->original_name = saved_original_name;
	new_entry->aliased_name = saved_aliased_name;
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	for (ptr = &alias_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

int ReadAliasPolicy(IO_BUFFER *head)
{
	ALIAS_ENTRY *ptr = (ALIAS_ENTRY *) head->read_var2;
	if (!ptr) ptr = alias_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if ((ptr->hash_and_flag & 1) == 0 && io_printf(head, KEYWORD_ALIAS "%s %s\n", ptr->original_name, ptr->aliased_name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

int AddAliasPolicy(char *data, const int is_delete)
{
	ALIAS_ENTRY *ptr;
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp = '\0';
	if (!is_delete) return AddAliasEntry(data, cp + 1);
	for (ptr = alias_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->original_name, data) == 0 && strcmp(ptr->aliased_name, cp + 1) == 0) ptr->hash_and_flag |= 1;
	return 0;
}

/*************************  DOMAIN AGGREGATOR HANDLER  *************************/

static AGGREGATOR_ENTRY aggregator_list = { NULL, 0, "", "" };

static int AddAggregatorEntry(const char *original_name, const char *aggregated_name)
{
	AGGREGATOR_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	const char *saved_original_name, *saved_aggregated_name;
	u32 depth_and_flag;
	if (!IsCorrectPath(original_name, 1, 0, -1, __FUNCTION__) || !IsCorrectPath(aggregated_name, 1, -1, -1, __FUNCTION__)) return -EINVAL;
	depth_and_flag = PathDepth(original_name) << 1;
	/* I don't want to add if it was already added. */
	for (ptr = aggregator_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->original_name, original_name) == 0 && strcmp(ptr->aggregated_name, aggregated_name) == 0) { ptr->depth_and_flag &= ~1; return 0; }
	if ((saved_original_name = SaveName(original_name)) == NULL || (saved_aggregated_name = SaveName(aggregated_name)) == NULL || (new_entry = (AGGREGATOR_ENTRY *) alloc_element(sizeof(AGGREGATOR_ENTRY))) == NULL) return -ENOMEM;
	new_entry->depth_and_flag = depth_and_flag;
	new_entry->original_name = saved_original_name;
	new_entry->aggregated_name = saved_aggregated_name;
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	for (ptr = &aggregator_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

int ReadAggregatorPolicy(IO_BUFFER *head)
{
	AGGREGATOR_ENTRY *ptr = (AGGREGATOR_ENTRY *) head->read_var2;
	if (!ptr) ptr = aggregator_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if ((ptr->depth_and_flag & 1) == 0 && io_printf(head, KEYWORD_AGGREGATOR "%s %s\n", ptr->original_name, ptr->aggregated_name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

int AddAggregatorPolicy(char *data, const int is_delete)
{
	AGGREGATOR_ENTRY *ptr;
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp = '\0';
	if (!is_delete) return AddAggregatorEntry(data, cp + 1);
	for (ptr = aggregator_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->original_name, data) == 0 && strcmp(ptr->aggregated_name, cp + 1) == 0) ptr->depth_and_flag |= 1;
	return 0;
}

/*************************  DOMAIN KEEPER HANDLER  *************************/

static DOMAIN_KEEPER_ENTRY domain_keeper_list = { NULL, 0, "" };

static int AddDomainKeeperEntry(const char *domain_keeper)
{
	DOMAIN_KEEPER_ENTRY *new_entry, *ptr;
	u32 hash_and_flag;
	if (!IsCorrectDomain(domain_keeper)) {
		printk(KERN_DEBUG "%s: Invalid domainname '%s'\n", __FUNCTION__, domain_keeper);
		return -EINVAL;
	}
	hash_and_flag = full_name_hash(domain_keeper, strlen(domain_keeper)) << 1;
	/* I don't want to add if it was already added. */
	for (ptr = domain_keeper_list.next; ptr; ptr = ptr->next) {
		if ((ptr->hash_and_flag & ~1) == hash_and_flag && strcmp(ptr->domain_keeper, domain_keeper) == 0) {
			ptr->hash_and_flag &= ~1; break;
		}
	}
	if (!ptr) {
		static spinlock_t lock = SPIN_LOCK_UNLOCKED;
		const char *saved_domain_keeper;
		if ((saved_domain_keeper = SaveName(domain_keeper)) == NULL || (new_entry = (DOMAIN_KEEPER_ENTRY *) alloc_element(sizeof(DOMAIN_KEEPER_ENTRY))) == NULL) return -ENOMEM;
		new_entry->hash_and_flag = hash_and_flag;
		new_entry->domain_keeper = saved_domain_keeper;
		/***** CRITICAL SECTION START *****/
		spin_lock(&lock);
		for (ptr = &domain_keeper_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
		spin_unlock(&lock);
		/***** CRITICAL SECTION END *****/
	}
	/***** CRITICAL SECTION START *****/
	{   /* Update domain_keeper flag for existing domains. */
		struct domain_info *domain;
		down(&new_domain_assign_lock);
		for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
			if (GetDomainAttribute(domain) & DOMAIN_ATTRIBUTE_DOMAIN_KEEPER) continue;
			if (strcmp(domain->domainname, domain_keeper)) continue;
			SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_DOMAIN_KEEPER);
		}
		up(&new_domain_assign_lock);
	}
	/***** CRITICAL SECTION END *****/
	return 0;
}

int AddDomainKeeperPolicy(char *domain_keeper, const int is_delete)
{
	DOMAIN_KEEPER_ENTRY *ptr;
	if (!is_delete) return AddDomainKeeperEntry(domain_keeper);
	for (ptr = domain_keeper_list.next; ptr; ptr = ptr->next) {
		if (strcmp(ptr->domain_keeper, domain_keeper)) continue;
		ptr->hash_and_flag |= 1;
		/***** CRITICAL SECTION START *****/
		{   /* Update domain_keeper flag for existing domains. */
			struct domain_info *domain;
			down(&new_domain_assign_lock);
			for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
				if ((GetDomainAttribute(domain) & DOMAIN_ATTRIBUTE_DOMAIN_KEEPER) == 0) continue;
				if (IsDomainKeeper(domain->domainname) == 0) SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_CLEAR_DOMAIN_KEEPER);
			}
			up(&new_domain_assign_lock);
		}
		/***** CRITICAL SECTION END *****/
	}
	return 0;
}

int ReadDomainKeeperPolicy(IO_BUFFER *head)
{
	DOMAIN_KEEPER_ENTRY *ptr = (DOMAIN_KEEPER_ENTRY *) head->read_var2;
	if (!ptr) ptr = domain_keeper_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if ((ptr->hash_and_flag & 1) == 0 && io_printf(head, KEYWORD_DOMAIN_KEEPER "%s\n", ptr->domain_keeper)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

static int IsDomainKeeper(const char *domainname)
{
	if (domainname) {
		DOMAIN_KEEPER_ENTRY *ptr;
		for (ptr = domain_keeper_list.next; ptr; ptr = ptr->next) {
			if ((ptr->hash_and_flag & 1) || strcmp(domainname, ptr->domain_keeper)) continue;
			return 1;
		}
	}
	return 0;
}

/*************************  DOMAIN DELETION HANDLER  *************************/

static int SetDeleteMark(const char *domainname)
{
	struct domain_info *domain;
	/* Never delete KERNEL_DOMAIN */
	for (domain = KERNEL_DOMAIN.next; domain; domain = domain->next) {
		if (GetDomainAttribute(domain) & DOMAIN_ATTRIBUTE_DELETED) continue;
		if (strcmp(domain->domainname, domainname)) continue;
		SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_DELETED);
	}
	return 0;
}

int DeleteDomain(char *data)
{
	return SetDeleteMark(data);
}

/*************************  DOMAIN TRANSITION HANDLER  *************************/

struct domain_info *FindDomain(const char *domainname)
{
	struct domain_info *domain;
	static int first = 1;
	const u16 hash = full_name_hash(domainname, strlen(domainname));
	if (first) {
		KERNEL_DOMAIN.hash = full_name_hash(ROOT_NAME, strlen(ROOT_NAME));
		first = 0;
	}
	for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
		if ((GetDomainAttribute(domain) & DOMAIN_ATTRIBUTE_DELETED) == 0 && hash == domain->hash && strcmp(domainname, domain->domainname) == 0) return domain;
	}
	return NULL;
}

struct domain_info *FindOrAssignNewDomain(const char *domainname, const u8 profile)
{
	struct domain_info *domain = NULL;
	const char *saved_domainname;
	down(&new_domain_assign_lock);
	if ((domain = FindDomain(domainname)) == NULL) {
		if (IsCorrectDomain(domainname)) {
			if ((saved_domainname = SaveName(domainname)) != NULL && (domain = (struct domain_info *) alloc_element(sizeof(struct domain_info))) != NULL) {
				struct domain_info *ptr = &KERNEL_DOMAIN;
				domain->domainname = saved_domainname;
				domain->hash = full_name_hash(saved_domainname, strlen(saved_domainname));
				domain->profile = profile;
				if (IsDomainKeeper(saved_domainname)) SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_DOMAIN_KEEPER);
				mb(); /* Instead of using spinlock. */
				while (ptr->next) ptr = ptr->next; ptr->next = domain;
			}
		} else {
			printk(KERN_DEBUG "%s: Invalid domainname '%s'\n", __FUNCTION__, domainname);
		}
	}
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
	/* This function assumes that the size of buffer returned by realpath() = PAGE_SIZE. */
	struct domain_info *old_domain = current->domain_info, *domain = NULL;
	char *new_domain_name = NULL, *real_program_name = NULL, *symlink_program_name = NULL;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	int retval;

	{
		/*
		 * Built-in initializers. This is needed because policies are not loaded until starting /sbin/init .
		 */
		static int first = 1;
		if (first) {
			AddInitializerEntry("/sbin/hotplug");
			AddInitializerEntry("/sbin/modprobe");
			first = 0;
		}
	}

	/* Get realpath of program. */
	retval = -ENOENT; /* I hope realpath() won't fail with -ENOMEM. */
	if ((real_program_name = (char *) realpath(original_name)) == NULL) goto out;
	/* Get realpath of symbolic link. */
	if ((symlink_program_name = (char *) realpath_nofollow(original_name)) == NULL) goto out;
	
	/* Check 'alias' directive. */
	if (strcmp(real_program_name, symlink_program_name)) {
		ALIAS_ENTRY *ptr;
		const u32 hash_and_flag = full_name_hash(real_program_name, strlen(real_program_name)) << 1;
		/* Is this program allowed to be called via symbolic links? */
		for (ptr = alias_list.next; ptr; ptr = ptr->next) {
			if (hash_and_flag != ptr->hash_and_flag || strcmp(real_program_name, ptr->original_name) || strcmp(symlink_program_name, ptr->aliased_name)) continue;
			memset(real_program_name, 0, PAGE_SIZE);
			strncpy(real_program_name, ptr->aliased_name, PAGE_SIZE - 1);
			break;
		}
	}
	
	/* Check 'aggregator' directive. */
	{
		AGGREGATOR_ENTRY *ptr;
		const u32 depth_and_flag = PathDepth(real_program_name) << 1;
		/* Is this program allowed to be aggregated? */
		for (ptr = aggregator_list.next; ptr; ptr = ptr->next) {
			if (depth_and_flag != ptr->depth_and_flag || !PathMatchesToPattern(real_program_name, ptr->original_name)) continue;
			memset(real_program_name, 0, PAGE_SIZE);
			strncpy(real_program_name, ptr->aggregated_name, PAGE_SIZE - 1);
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
				if (strcmp(base_argv0, base_filename)) retval = CheckArgv0Perm(symlink_program_name, base_argv0);
			}
			ccs_free(printable_argv0);
			ccs_free(org_argv0);
		}
		if (retval) goto out;
	}
	
	/* Check execute permission. */
	if ((retval = CheckExecPerm(real_program_name, filp)) < 0) goto out;

	/* Allocate memory for calcurating domain name. */
	retval = -ENOMEM;
	if ((new_domain_name = ccs_alloc(PAGE_SIZE)) == NULL) goto out;

	/* Check 'initializer' directtive. */
	if (IsInitializer(real_program_name)) {
		snprintf(new_domain_name, PAGE_SIZE - 1, ROOT_NAME " " "%s", real_program_name);
		if (strlen(new_domain_name) < PAGE_SIZE - 10) {
			if (is_enforce) domain = FindDomain(new_domain_name);
			else domain = FindOrAssignNewDomain(new_domain_name, current->domain_info->profile);
		}
	} else if (old_domain == &KERNEL_DOMAIN && !sbin_init_started) {
		/*
		 * Needn't to transit from kernel domain before starting /sbin/init .
		 * But transit from kernel domain if executing initializers, for they might start before /sbin/init .
		 */
		domain = old_domain;
	} else if ((GetDomainAttribute(old_domain) & DOMAIN_ATTRIBUTE_DOMAIN_KEEPER) == 0) {
		/* Normal domain transition. */
		snprintf(new_domain_name, PAGE_SIZE - 1, "%s %s", old_domain->domainname, real_program_name);
		if (strlen(new_domain_name) < PAGE_SIZE - 10) {
			if (is_enforce) domain = FindDomain(new_domain_name);
			else domain = FindOrAssignNewDomain(new_domain_name, current->domain_info->profile);
		}
	} else {
		domain = old_domain;
	}
	if (!domain && is_enforce && strlen(new_domain_name) < PAGE_SIZE - 10) {
		if (CheckSupervisor("#Need to create domain\n%s\n", new_domain_name) == 0) domain = FindOrAssignNewDomain(new_domain_name, current->domain_info->profile);
	}
	if (!domain) {
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
