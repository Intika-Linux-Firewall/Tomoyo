/*
 * fs/tomoyo_file.c
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

/***** The structure for globally readable files. *****/

typedef struct globally_readable_file_entry {
	struct globally_readable_file_entry *next; /* Pointer to next record. NULL if none. */
	int is_deleted;                            /* Delete flag.                          */
	const char *filename;                      /* Absolute pathname. Never NULL.        */
} GLOBALLY_READABLE_FILE_ENTRY;

/***** The structure for filename patterns. *****/

typedef struct pattern_entry {
	struct pattern_entry *next; /* Pointer to next record. NULL if none. */
	int is_deleted;             /* Delete flag.                          */
	const char *pattern;        /* Patterned filename. Never NULL.       */
} PATTERN_ENTRY;

/*************************  UTILITY FUNCTIONS  *************************/

/*
 *  Check whether the given filename is patterened.
 *  Returns nonzero if patterned, zero otherwise.
 */
static int PathContainsPattern(const char *filename)
{
	if (filename) {
		char c, d, e;
		while ((c = *filename++) != '\0') {
			if (c != '\\') continue;
			switch (c = *filename++) {
			case '\\':  /* "\\" */
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				if ((d = *filename++) >= '0' && d <= '7' && (e = *filename++) >= '0' && e <= '7'
					&& (c != '0' || d != '0' || e != '0')) continue; /* pattern is not \000 */
			}
			return 1;
		}
	}
	return 0;
}

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditFileLog(const char *filename, const unsigned short int perm, const int is_granted);

/*************************  GLOBALLY READABLE FILE HANDLER  *************************/

static GLOBALLY_READABLE_FILE_ENTRY globally_readable_list = { NULL, 0, "" };

static int AddGloballyReadableEntry(const char *filename)
{
	GLOBALLY_READABLE_FILE_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	const char *saved_filename;
	if (!IsCorrectPath(filename, 0) || strendswith(filename, "/")) {
		printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", __FUNCTION__, filename);
		return -EINVAL; /* No patterns allowed. */
	}
	/* I don't want to add if it was already added. */
	for (ptr = globally_readable_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->filename, filename) == 0) { ptr->is_deleted = 0; return 0; }
	if ((saved_filename = SaveName(filename)) == NULL || (new_entry = (GLOBALLY_READABLE_FILE_ENTRY *) alloc_element(sizeof(GLOBALLY_READABLE_FILE_ENTRY))) == NULL) return -ENOMEM;
	memset(new_entry, 0, sizeof(GLOBALLY_READABLE_FILE_ENTRY));
	new_entry->next = NULL;
	new_entry->is_deleted = 0;
	new_entry->filename = saved_filename;
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	for (ptr = &globally_readable_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

static int IsGloballyReadableFile(const char *filename)
{
	if (filename) {
		GLOBALLY_READABLE_FILE_ENTRY *ptr;
		for (ptr = globally_readable_list.next; ptr; ptr = ptr->next) {
			if (ptr->is_deleted) continue;
			if (strcmp(filename, ptr->filename) == 0) return 1;
		}
	}
	return 0;
}

int AddGloballyReadablePolicy(char *data)
{
	if (!isRoot()) return -EPERM;
	return AddGloballyReadableEntry(data);
}

int DelGloballyReadablePolicy(const char *filename)
{
	GLOBALLY_READABLE_FILE_ENTRY *ptr;
	for (ptr = globally_readable_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->filename, filename) == 0) ptr->is_deleted = 1;
	return 0;
}

int ReadGloballyReadablePolicy(IO_BUFFER *head)
{
	GLOBALLY_READABLE_FILE_ENTRY *ptr = (GLOBALLY_READABLE_FILE_ENTRY *) head->read_var2;
	if (!ptr) ptr = globally_readable_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_ALLOW_READ "%s\n", ptr->filename)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

/*************************  FILE PATTERN HANDLER  *************************/

static PATTERN_ENTRY pattern_list = { NULL, 0, "" };

static int AddPatternEntry(const char *pattern)
{
	PATTERN_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	const char *saved_pattern;
	if (!IsCorrectPath(pattern, 1)) {
		printk(KERN_DEBUG "%s: Invalid pattern '%s'\n", __FUNCTION__, pattern);
		return -EINVAL;
	} else if (IsCorrectPath(pattern, 0)) {
		printk(KERN_DEBUG "%s: Is not a pattern '%s'\n", __FUNCTION__, pattern);
		return -EINVAL;
	}
	/* I don't want to add if it was already added. */
	for (ptr = pattern_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->pattern, pattern) == 0) { ptr->is_deleted = 0; return 0; }
	if ((saved_pattern = SaveName(pattern)) == NULL || (new_entry = (PATTERN_ENTRY *) alloc_element(sizeof(PATTERN_ENTRY))) == NULL) return -ENOMEM;
	memset(new_entry, 0, sizeof(PATTERN_ENTRY));
	new_entry->next = NULL;
	new_entry->is_deleted = 0;
	new_entry->pattern = saved_pattern;
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	for (ptr = &pattern_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

static const char *GetPattern(const char *filename)
{
	if (filename) {
		PATTERN_ENTRY *ptr;
		for (ptr = pattern_list.next; ptr; ptr = ptr->next) {
			if (ptr->is_deleted) continue;
			if (PathMatchesToPattern(filename, ptr->pattern)) return ptr->pattern;
		}
	}
	return filename;
}

int AddPatternPolicy(char *data)
{
	if (!isRoot()) return -EPERM;
	return AddPatternEntry(data);
}

int DelPatternPolicy(const char *pattern)
{
	PATTERN_ENTRY *ptr;
	for (ptr = pattern_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->pattern, pattern) == 0) ptr->is_deleted = 1;
	return 0;
}

int ReadPatternPolicy(IO_BUFFER *head)
{
	PATTERN_ENTRY *ptr = (PATTERN_ENTRY *) head->read_var2;
	if (!ptr) ptr = pattern_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_FILE_PATTERN "%s\n", ptr->pattern)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

/*************************  FILE ACL HANDLER  *************************/

static int AddFileACL(const char *filename, unsigned short int perm, struct domain_info * const domain, const int force)
{
	static DECLARE_MUTEX(lock);
	FILE_ACL_RECORD *ptr, *new_ptr;
	const char *saved_filename;
	int error = -ENOMEM;
	if (!domain) {
		printk("%s: ERROR: domain == NULL\n", __FUNCTION__);
		return -EINVAL;
	}
	if (!IsCorrectPath(filename, 1)) {
		printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", __FUNCTION__, filename);
		return -EINVAL;
	}
	if (perm > 7 || !perm) { /* Should I allow perm == 0, for somebody may wish to give '4 /etc/\*' and '0 /etc/shadow' ? */
		printk(KERN_DEBUG "%s: Invalid permission '%d %s'\n", __FUNCTION__, perm, filename);
		return -EINVAL;
	}
	if (strendswith(filename, "/")) {
		perm |= 5;  /* Always allow read and execute for dir. */
	} else if ((perm & 1) == 1 && PathContainsPattern(filename)) {
		perm ^= 1;  /* Never allow execute permission with patterns. */
		printk("%s: Dropping execute permission for '%s'\n", __FUNCTION__, filename);
	} else if (perm == 4 && IsGloballyReadableFile(filename)) {
		return 0;   /* Don't add if the file is globally readable files. */
	}
	down(&lock);
	if ((ptr = domain->first_acl_ptr) == NULL) { /* if first, no check needed. */
		if ((saved_filename = SaveName(filename)) != NULL && (new_ptr = (FILE_ACL_RECORD *) alloc_element(sizeof(FILE_ACL_RECORD))) != NULL) {
			memset(new_ptr, 0, sizeof(FILE_ACL_RECORD));
			new_ptr->next = NULL;
			new_ptr->filename = saved_filename;
			new_ptr->perm = perm;
			domain->first_acl_ptr = new_ptr;
			error = 0;
		}
	} else { /* Not first, so I need to check. */
		unsigned int count = 0;
		while (1) {
			count++;
			if (strcmp(ptr->filename, filename) == 0) {
				/* Found. Just 'OR' the permission bits. */
				ptr->perm |= perm;
				error = 0;
				break;
			}
			if (ptr->next) {
				ptr = ptr->next;
				continue;
			}
			/* If there are so many entries, don't append if accept mode. */
			if (!force && count >= GetMaxAutoAppendFiles()) {
				if (domain->attribute & DOMAIN_ATTRIBUTE_QUOTA_WARNED) break;
				printk("TOMOYO-WARNING: Domain '%s' has so many ACLs to hold. Stopped auto-append mode.\n", domain->domainname);
				SetDomainAttribute(domain, DOMAIN_ATTRIBUTE_QUOTA_WARNED);
				break;
			}
			/* Not found. Append it to the tail. */
			if ((saved_filename = SaveName(filename)) == NULL || (new_ptr = (FILE_ACL_RECORD *) alloc_element(sizeof(FILE_ACL_RECORD))) == NULL) break;
			error = 0;
			memset(new_ptr, 0, sizeof(FILE_ACL_RECORD));
			new_ptr->next = NULL;
			new_ptr->filename = saved_filename;
			new_ptr->perm = perm;
			mb(); /* Instead of using spinlock. */
			ptr->next = new_ptr;
			break;
		}
	}
	up(&lock);
	return error;
}

static int CheckFileACL(const char *filename, unsigned short int perm)
{
	const struct domain_info *domain = GetCurrentDomain();
	int error = -EPERM;
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (!domain) {
		printk("%s: ERROR: domain == NULL\n", __FUNCTION__);
		return -EINVAL;
	}
	if (domain->attribute & DOMAIN_ATTRIBUTE_TRUSTED) return 0;
	if (perm == 4 && IsGloballyReadableFile(filename)) return 0;
	if ((perm & 1) == 0) { /* Read/Write permission check allows patterns. */
		FILE_ACL_RECORD *ptr = domain->first_acl_ptr;
		FILE_ACL_RECORD *target_acl_ptr = NULL;
		/*
		 * Exact matching is very difficult if patterns are allowed.
		 * For example, let's consider the following case.
		 *  (A) 2 /tmp/file-\$.txt
		 *  (B) 4 /tmp/fil\?-0.txt
		 *  (C) 6 /tmp/\*
		 * If the given filename is '/tmp/file-0.txt', then (A) (B) (C) matches.
		 * Since this is in the kernel operation, I don't want to spend much time expanding patterns.
		 * So I just don't use (C) if (A) or (B) is available, and I don't care which one is the better.
		 */
		while (ptr) {
			const char *cp = ptr->filename;
			if (PathMatchesToPattern(filename, cp)) {
				target_acl_ptr = ptr;
				if (strendswith(cp, "/\\*") || strendswith(cp, "/\\*/")) {
					/* Do nothing. Try to find the better match. */
				} else {
					/* This would be the better match. Use this. */
					break;
				}
			}
			ptr = ptr->next;
		}
		if (target_acl_ptr) {
			const unsigned short int perm0 = target_acl_ptr->perm;
			if ((perm0 & perm) == perm) error = 0;
		}
	} else { /* Execute permission check doesn't allow patterns. */
		FILE_ACL_RECORD *ptr = domain->first_acl_ptr;
		while (ptr) {
			const char *cp = ptr->filename;
			/* Even if strcmp() says they are equals, they are not equals if it contains patterns. */
			if ((ptr->perm & 1) == 1 && strcmp(filename, cp) == 0 && !PathContainsPattern(cp)) {
				error = 0;
				break;
			}
			ptr = ptr->next;
		}
	}
	return error;
}

int CheckFilePerm(const char *filename, const unsigned short int perm, const int is_realpath, const char *operation)
{
	int error = 0;
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (!filename) return 0;
	if (!is_realpath) {
		const char *realname = realpath(filename);
		if (realname) {
			error = CheckFilePerm(realname, perm, 1, operation);
			kfree(realname);
		} else {
			error = -ENOENT;
		}
		return error;
	}
	if ((perm & 2) == 0 && strendswith(filename, "/")) {
		/* Don't check directories for non-writing. */
	} else if (CheckFileACL(filename, perm)) {
		struct domain_info * const domain = current->domain_info;
		const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
		/* Don't use patterns if execution bit is on. */
		const char *patterned_file = ((perm & 1) == 0) ? GetPattern(filename) : filename;
		AuditFileLog(patterned_file, perm, 0);
		if (TomoyoVerboseMode()) {
			printk("TOMOYO-%s: Access %d(%s) to %s denied for %s\n", GetMSG(is_enforce), perm, operation, filename, GetLastName(domain));
		}
		if (is_enforce) error = -EPERM;
		else if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_FILE)) AddFileACL(patterned_file, perm, domain, 0);
	} else {
		AuditFileLog(filename, perm, 1);
	}
	return error;
}

int CheckWritePermission(struct dentry *dentry, struct vfsmount *mnt, const int is_dir, const char *operation)
{
	int error = 0;
	char *buf;
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL) return -ENOMEM;
	memset(buf, 0, PAGE_SIZE);
	if ((error = realpath_from_dentry(dentry, mnt, buf, PAGE_SIZE - 1)) == 0) {
		int len = strlen(buf);
		if (len > 0 && len <= PAGE_SIZE - 4) {
			if (is_dir) {
				if (buf[len - 1] != '/') {
					buf[len++] = '/'; buf[len++] = '\0';
				}
			}
			error = CheckFilePerm(buf, 2, 1, operation);
		} else {
			error = -ERANGE;
		}
	} else {
		printk("DEBUG: realpath_from_dentry = %d\n", error);
	}
	kfree(buf);
	if (!CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE)) error = 0;
	return error;
}

int AddFilePolicy(char *data, void **domain)
{
	char *cp;
	unsigned int perm;
	if (!isRoot()) return -EPERM;
	if ((cp = strchr(data, ' ')) == NULL || sscanf(data, "%u", &perm) != 1) return -EINVAL;
	return AddFileACL(cp + 1, (unsigned short int) perm, (struct domain_info *) *domain, 1);
}

int ReadFilePolicy(IO_BUFFER *head)
{
	struct domain_info *domain = (struct domain_info *) head->read_var1;
	FILE_ACL_RECORD *ptr = (FILE_ACL_RECORD *) head->read_var2;
	if (!ptr) ptr = domain->first_acl_ptr;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (io_printf(head, "%d %s \n", ptr->perm, ptr->filename)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

EXPORT_SYMBOL(CheckFilePerm);
EXPORT_SYMBOL(CheckWritePermission);

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditFileLog(const char *filename, const unsigned short int perm, const int is_granted)
{
	char *buf;
	const struct domain_info *domain = current->domain_info;
	int len;
	struct timeval tv;
	struct task_struct *task = current;
	if (!domain) {
		printk("%s: ERROR: domain == NULL\n", __FUNCTION__);
		return -EINVAL;
	}
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	do_gettimeofday(&tv);
	len = strlen(domain->domainname) + strlen(filename) + 256;
	if ((buf = kmalloc(len, GFP_KERNEL)) == NULL) return -ENOMEM;
	memset(buf, 0, len);
	snprintf(buf, len - 1, "#timestamp=%lu pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d\n%s\n%d %s\n", tv.tv_sec, task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, domain->domainname, perm, filename);
	return WriteAuditLog(buf, is_granted);
}

/***** TOMOYO Linux end. *****/
