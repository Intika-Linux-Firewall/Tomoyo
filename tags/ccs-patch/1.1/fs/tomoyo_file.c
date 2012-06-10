/*
 * fs/tomoyo_file.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.1   2006/04/01
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

/***** The structure for globally readable files. *****/

typedef struct globally_readable_file_entry {
	struct globally_readable_file_entry *next; /* Pointer to next record. NULL if none. */
	int is_deleted;                            /* Delete flag.                          */
	unsigned int hash;                         /* full_name_hash(filename)              */
	const char *filename;                      /* Absolute pathname. Never NULL.        */
} GLOBALLY_READABLE_FILE_ENTRY;

/***** The structure for filename patterns. *****/

typedef struct pattern_entry {
	struct pattern_entry *next; /* Pointer to next record. NULL if none. */
	int is_deleted;             /* Delete flag.                          */
	const char *pattern;        /* Patterned filename. Never NULL.       */
} PATTERN_ENTRY;

/***** The structure for detailed write operations. *****/ 

static struct {
	const char *keyword;
	const int paths;
	int check_type;
} acl_type_array[] = { /* mapping.txt */
	{ "create",   1, 1 }, // TYPE_CREATE_ACL
	{ "unlink",   1, 1 }, // TYPE_UNLINK_ACL
	{ "mkdir",    1, 1 }, // TYPE_MKDIR_ACL
	{ "rmdir",    1, 1 }, // TYPE_RMDIR_ACL
	{ "mkfifo",   1, 1 }, // TYPE_MKFIFO_ACL
	{ "mksock",   1, 1 }, // TYPE_MKSOCK_ACL
	{ "mkblock",  1, 1 }, // TYPE_MKBLOCK_ACL
	{ "mkchar",   1, 1 }, // TYPE_MKCHAR_ACL
	{ "truncate", 1, 1 }, // TYPE_TRUNCATE_ACL
	{ "symlink",  1, 1 }, // TYPE_SYMLINK_ACL
	{ "link",     2, 1 }, // TYPE_LINK_ACL
	{ "rename",   2, 1 }, // TYPE_RENAME_ACL
	{ NULL, 0, 0 }
};

/*************************  UTILITY FUNCTIONS  *************************/

const char *acltype2keyword(const unsigned int acl_type)
{
	return (acl_type < sizeof(acl_type_array) / sizeof(acl_type_array[0]))
		? acl_type_array[acl_type].keyword : NULL;
}

int acltype2paths(const unsigned int acl_type)
{
	return (acl_type < sizeof(acl_type_array) / sizeof(acl_type_array[0]))
		? acl_type_array[acl_type].paths : 0;
}

static unsigned int CheckACLFlags(const unsigned int index)
{
	if (index < (sizeof(acl_type_array) / sizeof(acl_type_array[0])) - 1)
		return acl_type_array[index].check_type;
	printk("%s: Index %u is out of range. Fix the kernel source.\n", __FUNCTION__, index);
	return 0;
}

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


/*************************  PROTOTYPES  *************************/

static int AddSingleWriteACL(const unsigned int type, const unsigned int hash, const char *filename, struct domain_info * const domain);
static int AddDoubleWriteACL(const unsigned int type, const unsigned int hash, const char *filename1, const char *filename2, struct domain_info * const domain);

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditFileLog(const char *filename, const unsigned short int perm, const int is_granted);
static int AuditWriteLog(const char *operation, const char *filename1, const char *filename2, const int is_granted);

/*************************  GLOBALLY READABLE FILE HANDLER  *************************/

static GLOBALLY_READABLE_FILE_ENTRY globally_readable_list = { NULL, 0, 0, "" };

static int AddGloballyReadableEntry(const char *filename)
{
	GLOBALLY_READABLE_FILE_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	const char *saved_filename;
	unsigned int hash;
	if (!IsCorrectPath(filename, 0) || strendswith(filename, "/")) {
		printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", __FUNCTION__, filename);
		return -EINVAL; /* No patterns allowed. */
	}
	hash = full_name_hash(filename, strlen(filename));
	/* I don't want to add if it was already added. */
	for (ptr = globally_readable_list.next; ptr; ptr = ptr->next) if (ptr->hash == hash && strcmp(ptr->filename, filename) == 0) { ptr->is_deleted = 0; return 0; }
	if ((saved_filename = SaveName(filename)) == NULL || (new_entry = (GLOBALLY_READABLE_FILE_ENTRY *) alloc_element(sizeof(GLOBALLY_READABLE_FILE_ENTRY))) == NULL) return -ENOMEM;
	memset(new_entry, 0, sizeof(GLOBALLY_READABLE_FILE_ENTRY));
	new_entry->next = NULL;
	new_entry->is_deleted = 0;
	new_entry->hash = hash;
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
		const unsigned int hash = full_name_hash(filename, strlen(filename));
		for (ptr = globally_readable_list.next; ptr; ptr = ptr->next) {
			if (ptr->is_deleted) continue;
			if (hash == ptr->hash && strcmp(filename, ptr->filename) == 0) return 1;
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
	const unsigned int hash = full_name_hash(filename, strlen(filename));
	for (ptr = globally_readable_list.next; ptr; ptr = ptr->next) if (hash == ptr->hash && strcmp(ptr->filename, filename) == 0) ptr->is_deleted = 1;
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


static unsigned short int NumSlashes(const char *filename)
{
	unsigned short int i = 0;
	if (filename) {
		while (*filename) {
			if (*filename++ == '/') i++;
		}
	}
	return i;
}

static int AddFileACL(const char *filename, unsigned short int perm, struct domain_info * const domain, const int force)
{
	const char *saved_filename;
	struct acl_info *ptr;
	unsigned int count = 0;
	const int is_dir = strendswith(filename, "/");
	const unsigned int type_hash = MAKE_ACL_TYPE(is_dir ? TYPE_DIR_ACL : TYPE_FILE_ACL) + MAKE_ACL_HASH(NumSlashes(filename));
	int error = -ENOMEM;
	if (!domain) return -EINVAL;
	if (!IsCorrectPath(filename, 1)) {
		printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", __FUNCTION__, filename);
		return -EINVAL;
	}
	if (perm > 7 || !perm) { /* Should I allow perm == 0, for somebody may wish to give '4 /etc/\*' and '0 /etc/shadow' ? */
		printk(KERN_DEBUG "%s: Invalid permission '%d %s'\n", __FUNCTION__, perm, filename);
		return -EINVAL;
	}
	if (!is_dir) {
		if ((perm & 1) == 1 && PathContainsPattern(filename)) {
			perm ^= 1;  /* Never allow execute permission with patterns. */
			printk("%s: Dropping execute permission for '%s'\n", __FUNCTION__, filename);
		} else if (perm == 4 && IsGloballyReadableFile(filename)) {
			return 0;   /* Don't add if the file is globally readable files. */
		}
	} else if ((perm & 2) == 0) {
		return 0; /* Don't add if the directory doesn't have write permission. */
	}
	down(&domain_acl_lock);
	if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
	while (1) {
		count++;
		if (is_dir) {
			if (ptr->type_hash == type_hash && strcmp(((DIR_ACL_RECORD *) ptr)->filename, filename) == 0) {
				/* Found. Nothing to do. */
				error = 0;
				break;
			}
		} else {
			if (ptr->type_hash == type_hash && strcmp(((FILE_ACL_RECORD *) ptr)->filename, filename) == 0) {
				/* Found. Just 'OR' the permission bits. */
				((FILE_ACL_RECORD *) ptr)->perm |= perm;
				error = 0;
				break;
			}
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
	first_entry: ;
		/* Not found. Append it to the tail. */
		if ((saved_filename = SaveName(filename)) == NULL) break;
		if (is_dir) {
			DIR_ACL_RECORD *new_ptr = (DIR_ACL_RECORD *) alloc_element(sizeof(DIR_ACL_RECORD));
			if (!new_ptr) break;
			new_ptr->next = NULL;
			new_ptr->type_hash = type_hash;
			new_ptr->filename = saved_filename;
			mb(); /* Instead of using spinlock. */
			if (!ptr) domain->first_acl_ptr = (struct acl_info *) new_ptr;
			else ptr->next = (struct acl_info *) new_ptr;
		} else {
			FILE_ACL_RECORD *new_ptr = (FILE_ACL_RECORD *) alloc_element(sizeof(FILE_ACL_RECORD));
			if (!new_ptr) break;
			new_ptr->next = NULL;
			new_ptr->type_hash = type_hash;
			new_ptr->filename = saved_filename;
			new_ptr->perm = perm;
			mb(); /* Instead of using spinlock. */
			if (!ptr) domain->first_acl_ptr = (struct acl_info *) new_ptr;
			else ptr->next = (struct acl_info *) new_ptr;
		}
		error = 0;
		break;
	}
	up(&domain_acl_lock);
	return error;
}

static int CheckFileACL(const char *filename, unsigned short int perm)
{
	const struct domain_info *domain = GetCurrentDomain();
	int error = -EPERM;
	unsigned int type_hash;
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (domain->attribute & DOMAIN_ATTRIBUTE_TRUSTED) return 0;
	if (strendswith(filename, "/")) {
		struct acl_info *ptr = domain->first_acl_ptr;
		type_hash = MAKE_ACL_TYPE(TYPE_DIR_ACL) + MAKE_ACL_HASH(NumSlashes(filename));
		while (ptr) {
			if (ptr->type_hash == type_hash && PathMatchesToPattern(filename, ((DIR_ACL_RECORD *) ptr)->filename)) return 0;
			ptr = ptr->next;
		}
		return -EPERM;
	}
	if (perm == 4 && IsGloballyReadableFile(filename)) return 0;
	type_hash = MAKE_ACL_TYPE(TYPE_FILE_ACL) + MAKE_ACL_HASH(NumSlashes(filename));
	if ((perm & 1) == 0) { /* Read/Write permission check allows patterns. */
		struct acl_info *ptr = domain->first_acl_ptr;
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
			const char *cp = ((FILE_ACL_RECORD *) ptr)->filename;
			if (ptr->type_hash == type_hash && PathMatchesToPattern(filename, cp)) {
				target_acl_ptr = (FILE_ACL_RECORD *) ptr;
				if (strendswith(cp, "/\\*")) {
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
		struct acl_info *ptr = domain->first_acl_ptr;
		while (ptr) {
			const char *cp = ((FILE_ACL_RECORD *) ptr)->filename;
			/* Even if strcmp() says they are equals, they are not equals if it contains patterns. */
			if (ptr->type_hash == type_hash && (((FILE_ACL_RECORD *) ptr)->perm & 1) == 1 && strcmp(filename, cp) == 0 && !PathContainsPattern(cp)) {
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

int AddFilePolicy(char *data, void **domain)
{
	char *cp;
	unsigned int perm;
	int i;
	if (!isRoot()) return -EPERM;
	if ((cp = strchr(data, ' ')) == NULL) return -EINVAL;
	*cp = '\0';
	if (sscanf(data, "%u", &perm) == 1) return AddFileACL(cp + 1, (unsigned short int) perm, (struct domain_info *) *domain, 1);
	if (strncmp(data, "allow_", 6)) return -EINVAL;
	data += 6;
	for (i = 0; acl_type_array[i].keyword; i++) {
		if (strcmp(data, acl_type_array[i].keyword)) continue;
		if (acl_type_array[i].paths == 2) {
			char *cp2 = strchr(cp + 1, ' ');
			if (!cp2) break;
			*cp2 = '\0';
			return AddDoubleWriteACL(i, NumSlashes(cp + 1), cp + 1, cp2 + 1, (struct domain_info *) *domain);
		} else {
			return AddSingleWriteACL(i, NumSlashes(cp + 1), cp + 1, (struct domain_info *) *domain);
		}
		break;
	}
	return -EINVAL;
}

/*************************  DETAILED FILE ACL HANDLER  *************************/

static int AddSingleWriteACL(const unsigned int type, const unsigned int hash, const char *filename, struct domain_info * const domain)
{
	const char *saved_filename;
	struct acl_info *ptr;
	const unsigned int type_hash = MAKE_ACL_TYPE(type) + MAKE_ACL_HASH(hash);
	int error = -ENOMEM;
	if (!domain) return -EINVAL;
	if (!IsCorrectPath(filename, 1)) {
		printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", __FUNCTION__, filename);
		return -EINVAL;
	}
	down(&domain_acl_lock);
	if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
	while (1) {
		SINGLE_ACL_RECORD *new_ptr;
		if (ptr->type_hash == type_hash && strcmp(((SINGLE_ACL_RECORD *) ptr)->filename, filename) == 0) {
			/* Found. Nothing to do. */
			error = 0;
			break;
		}
		if (ptr->next) {
			ptr = ptr->next;
			continue;
		}
	first_entry: ;
		/* Not found. Append it to the tail. */
		if ((saved_filename = SaveName(filename)) == NULL) break;
		if ((new_ptr = (SINGLE_ACL_RECORD *) alloc_element(sizeof(SINGLE_ACL_RECORD))) == NULL) break;
		new_ptr->next = NULL;
		new_ptr->type_hash = type_hash;
		new_ptr->filename = saved_filename;
		mb(); /* Instead of using spinlock. */
		if (!ptr) domain->first_acl_ptr = (struct acl_info *) new_ptr;
		else ptr->next = (struct acl_info *) new_ptr;
		error = 0;
		break;
	}
	up(&domain_acl_lock);
	return error;
} 

static int AddDoubleWriteACL(const unsigned int type, const unsigned int hash, const char *filename1, const char *filename2, struct domain_info * const domain)
{
	const char *saved_filename1, *saved_filename2;
	struct acl_info *ptr;
	const unsigned int type_hash = MAKE_ACL_TYPE(type) + MAKE_ACL_HASH(hash);
	int error = -ENOMEM;
	if (!domain) return -EINVAL;
	if (!IsCorrectPath(filename1, 1)) {
		printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", __FUNCTION__, filename1);
		return -EINVAL;
	}
	if (!IsCorrectPath(filename2, 1)) {
		printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", __FUNCTION__, filename2);
		return -EINVAL;
	}
	down(&domain_acl_lock);
	if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
	while (1) {
		DOUBLE_ACL_RECORD *new_ptr;
		if (ptr->type_hash == type_hash && strcmp(((DOUBLE_ACL_RECORD *) ptr)->filename1, filename1) == 0 && strcmp(((DOUBLE_ACL_RECORD *) ptr)->filename2, filename2) == 0) {
			/* Found. Nothing to do. */
			error = 0;
			break;
		}
		if (ptr->next) {
			ptr = ptr->next;
			continue;
		}
	first_entry: ;
		/* Not found. Append it to the tail. */
		if ((saved_filename1 = SaveName(filename1)) == NULL) break;
		if ((saved_filename2 = SaveName(filename2)) == NULL) break;
		if ((new_ptr = (DOUBLE_ACL_RECORD *) alloc_element(sizeof(DOUBLE_ACL_RECORD))) == NULL) break;
		new_ptr->next = NULL;
		new_ptr->type_hash = type_hash;
		new_ptr->filename1 = saved_filename1;
		new_ptr->filename2 = saved_filename2;
		mb(); /* Instead of using spinlock. */
		if (!ptr) domain->first_acl_ptr = (struct acl_info *) new_ptr;
		else ptr->next = (struct acl_info *) new_ptr;
		error = 0;
		break;
	}
	up(&domain_acl_lock);
	return error;
}

static int CheckSingleWriteACL(const unsigned int type, const unsigned int hash, const char *filename)
{
	const struct domain_info *domain = GetCurrentDomain();
	const unsigned int type_hash = MAKE_ACL_TYPE(type) + MAKE_ACL_HASH(hash);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (domain->attribute & DOMAIN_ATTRIBUTE_TRUSTED) return 0;
	{
		struct acl_info *ptr = domain->first_acl_ptr;
		while (ptr) {
			if (ptr->type_hash == type_hash && PathMatchesToPattern(filename, ((SINGLE_ACL_RECORD *) ptr)->filename)) return 0;
			ptr = ptr->next;
		}
	}
	return -EPERM;
} 

static int CheckDoubleWriteACL(const unsigned int type, const unsigned int hash, const char *filename1, const char *filename2)
{
	const struct domain_info *domain = GetCurrentDomain();
	const unsigned int type_hash = MAKE_ACL_TYPE(type) + MAKE_ACL_HASH(hash);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (domain->attribute & DOMAIN_ATTRIBUTE_TRUSTED) return 0;
	{
		struct acl_info *ptr = domain->first_acl_ptr;
		while (ptr) {
			if (ptr->type_hash == type_hash && PathMatchesToPattern(filename1, ((DOUBLE_ACL_RECORD *) ptr)->filename1) && PathMatchesToPattern(filename2, ((DOUBLE_ACL_RECORD *) ptr)->filename2)) return 0;
			ptr = ptr->next;
		}
	}
	return -EPERM;
}

int CheckSingleWritePermission(const unsigned int operation, struct dentry *dentry, struct vfsmount *mnt)
{
	int error;
	char *buf;
	struct domain_info * const domain = current->domain_info;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (CheckACLFlags(operation) < 0) return 0;	
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL) return -ENOMEM;
	memset(buf, 0, PAGE_SIZE);
	if ((error = realpath_from_dentry(dentry, mnt, buf, PAGE_SIZE - 4)) == 0) {
		int len = strlen(buf);
		switch (operation) {
		case TYPE_MKDIR_ACL:
		case TYPE_RMDIR_ACL:
			if (buf[len - 1] != '/') {
				buf[len++] = '/'; buf[len++] = '\0';
			}
		}
		if (CheckACLFlags(operation) > 0) {
			error = CheckSingleWriteACL(operation, NumSlashes(buf), buf);
			if (error) {
				if (TomoyoVerboseMode()) {
					printk("TOMOYO-%s: Access '%s %s' denied for %s\n", GetMSG(is_enforce), acltype2keyword(operation), buf, GetLastName(domain));
				}
				if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_FILE)) {
					const char *patterned_file = GetPattern(buf);
					AddSingleWriteACL(operation, NumSlashes(buf), patterned_file, domain);
				}
			}
			AuditWriteLog(acltype2keyword(operation), buf, "", error ? 0 : 1);
		} else {
			error = CheckFilePerm(buf, 2, 1, acltype2keyword(operation));
		}
	} else {
		printk("DEBUG: realpath_from_dentry = %d\n", error);
	}
	kfree(buf);
	if (!is_enforce) error = 0;
	return error;
}

int CheckDoubleWritePermission(const unsigned int operation, struct dentry *dentry1, struct vfsmount *mnt1, struct dentry *dentry2, struct vfsmount *mnt2)
{
	int error;
	char *buf1, *buf2;
	struct domain_info * const domain = current->domain_info;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (CheckACLFlags(operation) < 0) return 0;		
	buf1 = kmalloc(PAGE_SIZE, GFP_KERNEL);
	buf2 = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf1 || !buf2) {
		kfree(buf1); kfree(buf2);
		return -ENOMEM;
	}
	memset(buf1, 0, PAGE_SIZE);
	memset(buf2, 0, PAGE_SIZE);
	if ((error = realpath_from_dentry(dentry1, mnt1, buf1, PAGE_SIZE - 4)) == 0) {
		if ((error = realpath_from_dentry(dentry2, mnt2, buf2, PAGE_SIZE - 4)) == 0) {
			if (operation == TYPE_RENAME_ACL) {
				if (dentry1->d_inode && S_ISDIR(dentry1->d_inode->i_mode)) {
					int len = strlen(buf1);
					if (buf1[len - 1] != '/') {
						buf1[len++] = '/'; buf1[len++] = '\0';
					}
					len = strlen(buf2);
					if (buf2[len - 1] != '/') {
						buf2[len++] = '/'; buf2[len++] = '\0';
					}
				}
			}
			if (CheckACLFlags(operation) > 0) {
				error = CheckDoubleWriteACL(operation, NumSlashes(buf1), buf1, buf2);
				if (error) {
					if (TomoyoVerboseMode()) {
						printk("TOMOYO-%s: Access '%s %s %s' denied for %s\n", GetMSG(is_enforce), acltype2keyword(operation), buf1, buf2, GetLastName(domain));
					}
					if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_FILE)) {
						const char *patterned_file1 = GetPattern(buf1);
						const char *patterned_file2 = GetPattern(buf2);
						AddDoubleWriteACL(operation, NumSlashes(buf1), patterned_file1, patterned_file2, domain);
					}
				}
				AuditWriteLog(acltype2keyword(operation), buf1, buf2, error ? 0 : 1);
			} else {
				error = CheckFilePerm(buf1, 2, 1, acltype2keyword(operation));
				if (!error) error = CheckFilePerm(buf2, 2, 1, acltype2keyword(operation));
			}
		} else {
			printk("DEBUG: realpath_from_dentry = %d\n", error);
		}
	} else {
		printk("DEBUG: realpath_from_dentry = %d\n", error);
	}
	kfree(buf1);
	kfree(buf2);
	if (!is_enforce) error = 0;
	return error;
}

int SetPermissionMapping(char *data, void **dummy)
{
	int i;
	char *cp = NULL;
	if (!isRoot()) return -EPERM;
	if (!data || (cp = strchr(data, '=')) == NULL) {
	out: ;
		printk("ERROR: Invalid line '%s=%s'\n", data, cp);
		printk("This line must be one of the following. The first is the default.\n");
		printk("%s=%s if you want to check this permission using this permission.\n", data, data);
		printk("%s=generic-write if you want to check this permission using generic-write permission.\n", data);
		printk("%s=no-check if you don't want to check this permission.\n", data);
		return -EINVAL;
	}
	*cp++ = '\0';
	for (i = 0; acl_type_array[i].keyword; i++) {
		if (strcmp(acl_type_array[i].keyword, data)) continue;
		if (strcmp(cp, acl_type_array[i].keyword) == 0) acl_type_array[i].check_type = 1;
		else if (strcmp(cp, "generic-write") == 0) acl_type_array[i].check_type = 0;
		else if (strcmp(cp, "no-check") == 0) acl_type_array[i].check_type = -1;
		else goto out;
		return 0;
	}
	printk("WARNING: Unprocessed line '%s=%s'\n", data, cp);
	return -EINVAL;
}

int ReadPermissionMapping(IO_BUFFER *head)
{
	if (!head->read_eof) {
		int i;
		for (i = 0; acl_type_array[i].keyword; i++) { /* Ignore reserved entries. */
			io_printf(head, "%s=%s\n", acl_type_array[i].keyword, acl_type_array[i].check_type > 0 ? acl_type_array[i].keyword : acl_type_array[i].check_type == 0 ? "generic-write" : "no-check");
		}
		head->read_eof = 1;
	}
	return 0;
}


EXPORT_SYMBOL(CheckFilePerm);
EXPORT_SYMBOL(CheckSingleWritePermission);
EXPORT_SYMBOL(CheckDoubleWritePermission);

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditFileLog(const char *filename, const unsigned short int perm, const int is_granted)
{
	char *buf;
	const char *domainname = current->domain_info->domainname;
	int len;
	struct timeval tv;
	struct task_struct *task = current;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	do_gettimeofday(&tv);
	len = strlen(domainname) + strlen(filename) + 256;
	if ((buf = kmalloc(len, GFP_KERNEL)) == NULL) return -ENOMEM;
	memset(buf, 0, len);
	snprintf(buf, len - 1, "#timestamp=%lu pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d\n%s\n%d %s\n", tv.tv_sec, task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, domainname, perm, filename);
	return WriteAuditLog(buf, is_granted);
}

static int AuditWriteLog(const char *operation, const char *filename1, const char *filename2, const int is_granted)
{
	char *buf;
	int len;
	struct timeval tv;
	struct task_struct *task = current;
	const char *domainname = task->domain_info->domainname;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	do_gettimeofday(&tv);
	len = strlen(domainname) + strlen(operation) + strlen(filename1) + strlen(filename2) + 256;
	if ((buf = kmalloc(len, GFP_KERNEL)) == NULL) return -ENOMEM;
	memset(buf, 0, len);
	snprintf(buf, len - 1, "#timestamp=%lu pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d\n%s\nallow_%s %s %s\n", tv.tv_sec, task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, domainname, operation, filename1, filename2);
	return WriteAuditLog(buf, is_granted);
}

/***** TOMOYO Linux end. *****/
