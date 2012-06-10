/*
 * fs/tomoyo_domain.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005  NTT DATA CORPORATION
 *
 * Version: 1.0 2005/11/11
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
struct domain_info KERNEL_DOMAIN = { NULL, NULL, ROOT_NAME, 0 };

/* /sbin/init started? */
int sbin_init_started = 0;

#ifdef CONFIG_TOMOYO

/*************************  UTILITY FUNCTIONS  *************************/

/***** The structure for program files to force domain reconstruction. *****/

typedef struct initializer_entry {
	struct initializer_entry *next; /* Pointer to next record. NULL if none. */
	int is_deleted;                 /* Delete flag.                          */
	const char *initializer;        /* Absolute pathname. Never NULL.        */
} INITIALIZER_ENTRY;

/***** The structure for domain definitions to treat as trusted. *****/

typedef struct trusted_pattern_entry {
	struct trusted_pattern_entry *next; /* Pointer to next record. NULL if none. */
	int is_deleted;                     /* Delete flag.                          */
	const char *trusted_pattern;        /* Pattern of domain name. Never NULL.   */
} TRUSTED_PATTERN_ENTRY;

/*************************  PROTOTYPES  *************************/

static int IsInitializer(const char *filename);
static int IsTrustedDomain(const char *domainname);
static int IsCorrectDomain(const unsigned char *domainname);
static int AddInitializerEntry(const char *initializer);
static void ReadPIDStatus(IO_BUFFER *head, const unsigned int attribute);

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
static int IsCorrectDomain(const unsigned char *domainname)
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
void SetDomainAttribute(struct domain_info *domain, const unsigned int attribute) {
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	spin_lock(&lock);
	if (attribute == DOMAIN_ATTRIBUTE_UNTRUSTED) domain->attribute &= ~DOMAIN_ATTRIBUTE_TRUSTED;
	else domain->attribute |= attribute;
	spin_unlock(&lock);
}

/*************************  DOMAIN TRANSITION HANDLER  *************************/

static struct domain_info *FindDomain(const char *domainname)
{
	struct domain_info *domain;
	for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
		if ((domain->attribute & DOMAIN_ATTRIBUTE_DELETED) == 0 && strcmp(domainname, domain->domainname) == 0) return domain;
	}
	return NULL;
}

struct domain_info *FindOrAssignNewDomain(const char *domainname)
{
	struct domain_info *domain = NULL;
	const char *saved_domainname;
	down(&new_domain_assign_lock);
	if ((domain = FindDomain(domainname)) == NULL) {
		if (IsCorrectDomain(domainname)) {
			if ((saved_domainname = SaveName(domainname)) != NULL && (domain = (struct domain_info *) alloc_element(sizeof(struct domain_info))) != NULL) {
				struct domain_info *ptr = &KERNEL_DOMAIN;
				memset(domain, 0, sizeof(struct domain_info));
				domain->next = NULL;
				domain->domainname = saved_domainname;
				/* Check is_trusted flag for this domain. */
				if (IsTrustedDomain(saved_domainname)) {
					SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_TRUSTED);
					/* printk("TOMOYO: Created a trusted domain '%s'.\n", saved_domainname); */
				}
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

struct domain_info *GetNextDomain(const char *filename, int *errno)
{
	struct domain_info *old_domain = GetCurrentDomain(), *domain = NULL;
	char *new_domain_name;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	*errno = -ENOMEM;
	if ((new_domain_name = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL) return NULL;
	memset(new_domain_name, 0, PAGE_SIZE);
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
	if (IsInitializer(filename)) {
		snprintf(new_domain_name, PAGE_SIZE - 1, ROOT_NAME " " "%s", filename);
		if (strlen(new_domain_name) < PAGE_SIZE - 10) {
			if (is_enforce) domain = FindDomain(new_domain_name);
			else domain = FindOrAssignNewDomain(new_domain_name);
		}
	} else if (old_domain == &KERNEL_DOMAIN && !sbin_init_started) {
		/*
		 * Needn't to transit from kernel domain before starting /sbin/init .
		 * But transit from kernel domain if executing initializers, for they might start before /sbin/init .
		 */
		domain = old_domain;
	} else if ((old_domain->attribute & DOMAIN_ATTRIBUTE_TRUSTED) == 0) {
		snprintf(new_domain_name, PAGE_SIZE - 1, "%s %s", old_domain->domainname, filename);
		if (strlen(new_domain_name) < PAGE_SIZE - 10) {
			if (is_enforce) domain = FindDomain(new_domain_name);
			else domain = FindOrAssignNewDomain(new_domain_name);
		}
	} else {
		domain = old_domain;
	}
	if (!domain) {
		if (is_enforce) *errno = -EPERM;
	} else {
		*errno = 0;
	}
	kfree(new_domain_name);
	return domain;
}

/*************************  DOMAIN INITIALIZER HANDLER  *************************/

static INITIALIZER_ENTRY initializer_list = { NULL, 0, "" };

static int AddInitializerEntry(const char *initializer)
{
	INITIALIZER_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	const char *saved_initializer;
	if (!IsCorrectPath(initializer, 0) || strendswith(initializer, "/")) {
		printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", __FUNCTION__, initializer);
		return -EINVAL; /* No patterns alloed. */
	}
	/* I don't want to add if it was already added. */
	for (ptr = initializer_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->initializer, initializer) == 0) { ptr->is_deleted = 0; return 0; }
	if ((saved_initializer = SaveName(initializer)) == NULL || (new_entry = (INITIALIZER_ENTRY *) alloc_element(sizeof(INITIALIZER_ENTRY))) == NULL) return -ENOMEM;
	memset(new_entry, 0, sizeof(INITIALIZER_ENTRY));
	new_entry->next = NULL;
	new_entry->is_deleted = 0;
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
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_INITIALIZER "%s\n", ptr->initializer)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

int AddInitializerPolicy(char *data)
{
	if (!isRoot()) return -EPERM;
	return AddInitializerEntry(data);
}

int DelInitializerPolicy(const char *initializer)
{
	INITIALIZER_ENTRY *ptr;
	for (ptr = initializer_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->initializer, initializer) == 0) ptr->is_deleted = 1;
	return 0;
}

static int IsInitializer(const char *filename)
{
	if (filename) {
		INITIALIZER_ENTRY *ptr;
		for (ptr = initializer_list.next; ptr; ptr = ptr->next) {
			if (ptr->is_deleted) continue;
			if (strcmp(filename, ptr->initializer) == 0) return 1;
		}
	}
	return 0;
}

/*************************  TRUSTED DOMAIN HANDLER  *************************/

static TRUSTED_PATTERN_ENTRY trusted_pattern_list = { NULL, 0, "" };

static int AddTrustedPatternEntry(const char *trusted_pattern)
{
	TRUSTED_PATTERN_ENTRY *new_entry, *ptr;
	if (!IsCorrectDomain(trusted_pattern)) {
		printk(KERN_DEBUG "%s: Invalid domainname pattern '%s'\n", __FUNCTION__, trusted_pattern);
		return -EINVAL;
	}
	/* I don't want to add if it was already added. */
	for (ptr = trusted_pattern_list.next; ptr; ptr = ptr->next) {
		if (strcmp(ptr->trusted_pattern, trusted_pattern) == 0) {
			ptr->is_deleted = 0; break;
		}
	}
	if (!ptr) {
		static spinlock_t lock = SPIN_LOCK_UNLOCKED;
		const char *saved_trusted_pattern;
		if ((saved_trusted_pattern = SaveName(trusted_pattern)) == NULL || (new_entry = (TRUSTED_PATTERN_ENTRY *) alloc_element(sizeof(TRUSTED_PATTERN_ENTRY))) == NULL) return -ENOMEM;
		memset(new_entry, 0, sizeof(TRUSTED_PATTERN_ENTRY));
		new_entry->next = NULL;
		new_entry->is_deleted = 0;
		new_entry->trusted_pattern = saved_trusted_pattern;
		/***** CRITICAL SECTION START *****/
		spin_lock(&lock);
		for (ptr = &trusted_pattern_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
		spin_unlock(&lock);
		/***** CRITICAL SECTION END *****/
	}
	/***** CRITICAL SECTION START *****/
	{   /* Update trusted flag for existing domains. */
		struct domain_info *domain;
		const int len = strlen(trusted_pattern);
		down(&new_domain_assign_lock);
		for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
			if (domain->attribute & DOMAIN_ATTRIBUTE_TRUSTED) continue;
			if (strncmp(domain->domainname, trusted_pattern, len)) continue;
			if (domain->domainname[len] == '\0' || domain->domainname[len] == ' ') {
				SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_TRUSTED);
				printk("TOMOYO: Domain '%s' is now trusted.\n", domain->domainname);
			}
		}
		up(&new_domain_assign_lock);
	}
	/***** CRITICAL SECTION END *****/
	return 0;
}

int AddTrustedPatternPolicy(char *data)
{
	if (!isRoot()) return -EPERM;
	return AddTrustedPatternEntry(data);
}

int DelTrustedPatternPolicy(const char *trusted_pattern)
{
	TRUSTED_PATTERN_ENTRY *ptr;
	for (ptr = trusted_pattern_list.next; ptr; ptr = ptr->next) {
		if (strcmp(ptr->trusted_pattern, trusted_pattern)) continue;
		ptr->is_deleted = 1;
		/***** CRITICAL SECTION START *****/
		{   /* Update trusted flag for existing domains. */
			struct domain_info *domain;
			down(&new_domain_assign_lock);
			for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
				if ((domain->attribute & DOMAIN_ATTRIBUTE_TRUSTED) == 0) continue;
				if (IsTrustedDomain(domain->domainname) == 0) {
					SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_UNTRUSTED);
					printk("TOMOYO: Domain '%s' is now untrusted.\n", domain->domainname);
				}
			}
			up(&new_domain_assign_lock);
		}
		/***** CRITICAL SECTION END *****/
	}
	return 0;
}

int ReadTrustedPatternPolicy(IO_BUFFER *head)
{
	TRUSTED_PATTERN_ENTRY *ptr = (TRUSTED_PATTERN_ENTRY *) head->read_var2;
	if (!ptr) ptr = trusted_pattern_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_TRUST_DOMAIN "%s\n", ptr->trusted_pattern)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

static int IsTrustedDomain(const char *domainname)
{
	if (domainname) {
		TRUSTED_PATTERN_ENTRY *ptr;
		for (ptr = trusted_pattern_list.next; ptr; ptr = ptr->next) {
			const int len = strlen(ptr->trusted_pattern);
			if (ptr->is_deleted) continue;
			if (strncmp(domainname, ptr->trusted_pattern, len)) continue;
			if (domainname[len] == ' ' || domainname[len] == '\0') return 1;
		}
	}
	return 0;
}

int ReadTrustedPIDs(IO_BUFFER *head)
{
	if (!head->read_eof) {
		ReadPIDStatus(head, DOMAIN_ATTRIBUTE_TRUSTED);
		head->read_eof = 1;
	}
	return 0;
}

/*************************  DOMAIN DELETION HANDLER  *************************/

static int SetDeleteMark(const char *domainname)
{
	struct domain_info *domain;
	int found = 0;
	for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
		if (domain->attribute & DOMAIN_ATTRIBUTE_DELETED) continue;
		if (strcmp(domain->domainname, domainname)) continue;
		SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_DELETED);
		printk("TOMOYO: Domain '%s' is marked as deleted.\n", domainname);
		found = 1;
	}
	if (!found) printk("%s: Domain '%s' not deleted.\n", __FUNCTION__, domainname);
	return 0;
}

int DeleteDomain(char *data, void **dummy)
{
	if (!isRoot()) return -EPERM;
	return SetDeleteMark(data);
}

int ReadDeletedPIDs(IO_BUFFER *head)
{
	if (!head->read_eof) {
		ReadPIDStatus(head, DOMAIN_ATTRIBUTE_DELETED);
		head->read_eof = 1;
	}
	return 0;
}

/*************************  DOMAIN UPDATE HANDLER  *************************/

static int SetUpdateMark(const char *domainname)
{
	struct domain_info *domain, *new_domain;
	int found = 0;
	for (domain = &KERNEL_DOMAIN; domain; domain = domain->next) {
		if (domain->attribute & DOMAIN_ATTRIBUTE_UPDATED) continue;
		if (strcmp(domain->domainname, domainname)) continue;
		for (new_domain = domain->next; new_domain; new_domain = new_domain->next) {
			if (strcmp(new_domain->domainname, domainname) == 0) break;
		}
		if (!new_domain) continue;
		SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_UPDATED);
		printk("TOMOYO: Domain '%s' is marked as updated.\n", domainname);
		found = 1;
	}
	if (!found) printk("%s: Domain '%s' not updated.\n", __FUNCTION__, domainname);
	return 0;
}

int UpdateDomain(char *data, void **dummy)
{
	if (!isRoot()) return -EPERM;
	return SetUpdateMark(data);
}

struct domain_info *GetCurrentDomain(void)
{
	struct domain_info *domain = current->domain_info;
	while (domain->attribute & DOMAIN_ATTRIBUTE_UPDATED) {
		struct domain_info *new_domain;
		const char *domainname = domain->domainname;
		for (new_domain = domain->next; new_domain; new_domain = new_domain->next) {
			if (strcmp(new_domain->domainname, domainname)) continue;
			break;
		}
		if (new_domain) {
			current->domain_info = domain = new_domain;
			printk("TOMOYO: PID %d is now updated.\n", current->pid);
		} else { /* This mustn't happen. */
			if ((domain->attribute & DOMAIN_ATTRIBUTE_BUG_WARNED) == 0) {
				SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_BUG_WARNED);
				printk(KERN_ERR "TOMOYO-BUG: Domain '%s' is marked as updated, but new domain was not found.\n", domainname);
			}
			break;
		}
	}
	return domain;
}

static void ReadPIDStatus(IO_BUFFER *head, const unsigned int attribute)
{
	struct task_struct *p;
	/***** CRITICAL SECTION START *****/
	read_lock(&tasklist_lock);
	for_each_process(p) {
		struct domain_info *domain = p->domain_info;
		/* Use the latest domain information */
		while (domain->attribute & DOMAIN_ATTRIBUTE_UPDATED) {
			struct domain_info *new_domain;
			const char *domainname = domain->domainname;
			for (new_domain = domain->next; new_domain; new_domain = new_domain->next) {
				if (strcmp(new_domain->domainname, domainname)) continue;
				break;
			}
			if (!new_domain) break; /* This mustn't happen. */
			domain = new_domain; /* p->domain_info MUST be updated at GetCurrentDomain(). */
		}
		if (domain->attribute & attribute) {
			/* If there are too many process to list up, I can't sleep to reallocate, so I ignore them. */
			if (io_printf(head, " %d", p->pid)) break;
		}
	}
	read_unlock(&tasklist_lock);
	/***** CRITICAL SECTION END *****/
}

#endif

/***** TOMOYO Linux end. *****/
