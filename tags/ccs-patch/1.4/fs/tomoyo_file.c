/*
 * fs/tomoyo_file.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.4   2007/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])

/*************************  VARIABLES  *************************/

extern struct semaphore domain_acl_lock;

/***** The structure for globally readable files. *****/

typedef struct globally_readable_file_entry {
	struct globally_readable_file_entry *next;
	const struct path_info *filename;
	int is_deleted;
} GLOBALLY_READABLE_FILE_ENTRY;

/***** The structure for filename patterns. *****/

typedef struct pattern_entry {
	struct pattern_entry *next;
	const struct path_info *pattern;
	int is_deleted;
} PATTERN_ENTRY;

/***** The structure for non-rewritable-by-default file patterns. *****/

typedef struct no_rewrite_entry {
	struct no_rewrite_entry *next;
	const struct path_info *pattern;
	int is_deleted;
} NO_REWRITE_ENTRY;

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
	{ "rewrite",  1, 1 }, // TYPE_REWRITE_ACL
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

static int strendswith(const char *name, const char *tail)
{
	int len;
	if (!name || !tail) return 0;
	len = strlen(name) - strlen(tail);
	return len >= 0 && strcmp(name + len, tail) == 0;
}

static struct path_info *GetPath(struct dentry *dentry, struct vfsmount *mnt)
{
	struct path_info_with_data { /* sizeof(struct path_info_with_data) <= PAGE_SIZE */
		struct path_info head; /* Keep this first, for this pointer is passed to ccs_free(). */
		char bariier1[16];
		char body[CCS_MAX_PATHNAME_LEN];
		char barrier2[16];
	} *buf = (struct path_info_with_data *) ccs_alloc(sizeof(struct path_info_with_data));
	if (buf) {
		int error;
		if ((error = realpath_from_dentry2(dentry, mnt, buf->body, sizeof(buf->body) - 1)) == 0) {
			buf->head.name = buf->body;
			fill_path_info(&buf->head);
			return &buf->head;
		}
		ccs_free(buf); buf = NULL;
		printk("realpath_from_dentry = %d\n", error);
	}
	return NULL;
}

/*************************  PROTOTYPES  *************************/

static int AddDoubleWriteACL(const u8 type, const char *filename1, const char *filename2, struct domain_info * const domain, const u8 is_add, const struct condition_list *condition);
static int AddSingleWriteACL(const u8 type, const char *filename, struct domain_info * const domain, const u8 is_add, const struct condition_list *condition);

/*************************  AUDIT FUNCTIONS  *************************/

#ifdef CONFIG_TOMOYO_AUDIT
static int AuditFileLog(const struct path_info *filename, const u8 perm, const int is_granted)
{
	char *buf;
	int len;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	len = filename->total_len + 8;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, "%d %s\n", perm, filename->name);
	return WriteAuditLog(buf, is_granted);
}

static int AuditWriteLog(const char *operation, const struct path_info *filename1, const struct path_info *filename2, const int is_granted)
{
	char *buf;
	int len;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	len = strlen(operation) + filename1->total_len + (filename2 ? filename2->total_len : 0) + 16;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, "allow_%s %s %s\n", operation, filename1->name, filename2 ? filename2->name : "");
	return WriteAuditLog(buf, is_granted);
}
#else
static inline void AuditFileLog(const struct path_info *filename, const u8 perm, const int is_granted) {}
static inline void AuditWriteLog(const char *operation, const struct path_info *filename1, const struct path_info *filename2, const int is_granted) {}
#endif

/*************************  PERMISSION MAP HANDLER  *************************/

int SetPermissionMapping(IO_BUFFER *head)
{
	int i;
	char *data = head->write_buf;
	char *cp = NULL;
	if ((cp = strchr(data, '=')) == NULL) {
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
		for (i = 0; acl_type_array[i].keyword; i++) {
			io_printf(head, "%s=%s\n", acl_type_array[i].keyword, acl_type_array[i].check_type > 0 ? acl_type_array[i].keyword : acl_type_array[i].check_type == 0 ? "generic-write" : "no-check");
		}
		head->read_eof = 1;
	}
	return 0;
}

/*************************  GLOBALLY READABLE FILE HANDLER  *************************/

static GLOBALLY_READABLE_FILE_ENTRY *globally_readable_list = NULL;

static int AddGloballyReadableEntry(const char *filename, const int is_delete)
{
	GLOBALLY_READABLE_FILE_ENTRY *new_entry, *ptr;
	static DECLARE_MUTEX(lock);
	const struct path_info *saved_filename;
	int error = -ENOMEM;
	if (!IsCorrectPath(filename, 1, -1, -1, __FUNCTION__)) return -EINVAL; /* No patterns allowed. */
	if ((saved_filename = SaveName(filename)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = globally_readable_list; ptr; ptr = ptr->next) {
		if (ptr->filename == saved_filename) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT; goto out;
	}
	if ((new_entry = (GLOBALLY_READABLE_FILE_ENTRY *) alloc_element(sizeof(GLOBALLY_READABLE_FILE_ENTRY))) == NULL) goto out;
	new_entry->filename = saved_filename;
	mb(); /* Instead of using spinlock. */
	if ((ptr = globally_readable_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		globally_readable_list = new_entry;
	}
	error = 0;
 out: ;
	up(&lock);
	return error;
}

static int IsGloballyReadableFile(const struct path_info *filename)
{
	GLOBALLY_READABLE_FILE_ENTRY *ptr;
	for (ptr = globally_readable_list; ptr; ptr = ptr->next) {
		if (!ptr->is_deleted && !pathcmp(filename, ptr->filename)) return 1;
	}
	return 0;
}

int AddGloballyReadablePolicy(char *filename, const int is_delete)
{
	return AddGloballyReadableEntry(filename, is_delete);
}

int ReadGloballyReadablePolicy(IO_BUFFER *head)
{
	GLOBALLY_READABLE_FILE_ENTRY *ptr = (GLOBALLY_READABLE_FILE_ENTRY *) head->read_var2;
	if (!ptr) ptr = globally_readable_list;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (!ptr->is_deleted && io_printf(head, KEYWORD_ALLOW_READ "%s\n", ptr->filename->name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

/*************************  FILE GROUP HANDLER  *************************/

static GROUP_ENTRY *group_list = NULL;

static int AddGroupEntry(const char *group_name, const char *member_name, const int is_delete)
{
	static DECLARE_MUTEX(lock);
	GROUP_ENTRY *new_group, *group;
	GROUP_MEMBER *new_member, *member;
	const struct path_info *saved_group_name, *saved_member_name;
	int error = -ENOMEM;
	if (!IsCorrectPath(group_name, 0, 0, 0, __FUNCTION__) || !group_name[0] ||
		!IsCorrectPath(member_name, 0, 0, 0, __FUNCTION__) || !member_name[0]) return -EINVAL;
	if ((saved_group_name = SaveName(group_name)) == NULL ||
		(saved_member_name = SaveName(member_name)) == NULL) return -ENOMEM;
	down(&lock);
	for (group = group_list; group; group = group->next) {
		if (saved_group_name != group->group_name) continue;
		for (member = group->first_member; member; member = member->next) {
			if (member->member_name == saved_member_name) {
				member->is_deleted = is_delete;
				error = 0;
				goto out;
			}
		}
		break;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if (!group) {
		if ((new_group = (GROUP_ENTRY *) alloc_element(sizeof(GROUP_ENTRY))) == NULL) goto out;
		new_group->group_name = saved_group_name;
		mb(); /* Instead of using spinlock. */
		if ((group = group_list) != NULL) {
			while (group->next) group = group->next; group->next = new_group;
		} else {
			group_list= new_group;
		}
		group = new_group;
	}
	if ((new_member = (GROUP_MEMBER *) alloc_element(sizeof(GROUP_MEMBER))) == NULL) goto out;
	new_member->member_name = saved_member_name;
	mb(); /* Instead of using spinlock. */
	if ((member = group->first_member) != NULL) {
		while (member->next) member = member->next; member->next = new_member;
	} else {
		group->first_member = new_member;
	}
	error = 0;
 out:
	up(&lock);
	return error;
}

int AddGroupPolicy(char *data, const int is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp++ = '\0';
	return AddGroupEntry(data, cp, is_delete);
}

static GROUP_ENTRY *FindOrAssignNewGroup(const char *group_name)
{
	int i;
	GROUP_ENTRY *group;
	for (i = 0; i <= 1; i++) {
		for (group = group_list; group; group = group->next) {
			if (strcmp(group_name, group->group_name->name) == 0) return group;
		}
		if (i == 0) {
			AddGroupEntry(group_name, "/", 0);
			AddGroupEntry(group_name, "/", 1);
		}
	}
	return NULL;
}

static int PathMatchesToGroup(const struct path_info *pathname, const GROUP_ENTRY *group, const int may_use_pattern)
{
	GROUP_MEMBER *member;
	for (member = group->first_member; member; member = member->next) {
		if (member->is_deleted) continue;
		if (!member->member_name->is_patterned) {
			if (!pathcmp(pathname, member->member_name)) return 1;
		} else if (may_use_pattern) {
			if (PathMatchesToPattern(pathname, member->member_name)) return 1;
		}
	}
	return 0;
}

int ReadGroupPolicy(IO_BUFFER *head)
{
	GROUP_ENTRY *group = (GROUP_ENTRY *) head->read_var1;
	GROUP_MEMBER *member = (GROUP_MEMBER *) head->read_var2;
	if (!group) group = group_list;
	while (group) {
		head->read_var1 = (struct domain_info *) group;
		if (!member) member = group->first_member;
		while (member) {
			head->read_var2 = (void *) member;
			if (!member->is_deleted && io_printf(head, KEYWORD_PATH_GROUP "%s %s\n", group->group_name->name, member->member_name->name)) break;
			member = member->next;
		}
		if (member) break;
		head->read_var2 = NULL;
		group = group->next;
	}
	return group ? -ENOMEM : 0;
}

/*************************  FILE PATTERN HANDLER  *************************/

static PATTERN_ENTRY *pattern_list = NULL;

static int AddPatternEntry(const char *pattern, const int is_delete)
{
	PATTERN_ENTRY *new_entry, *ptr;
	static DECLARE_MUTEX(lock);
	const struct path_info *saved_pattern;
	int error = -ENOMEM;
	if (!IsCorrectPath(pattern, 0, 1, 0, __FUNCTION__)) return -EINVAL;
	if ((saved_pattern = SaveName(pattern)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = pattern_list; ptr; ptr = ptr->next) {
		if (saved_pattern == ptr->pattern) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = (PATTERN_ENTRY *) alloc_element(sizeof(PATTERN_ENTRY))) == NULL) goto out;
	new_entry->pattern = saved_pattern;
	mb(); /* Instead of using spinlock. */
	if ((ptr = pattern_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		pattern_list = new_entry;
	}
	error = 0;
 out:
	up(&lock);
	return error;
}

static const struct path_info *GetPattern(const struct path_info *filename)
{
	PATTERN_ENTRY *ptr;
	const struct path_info *pattern = NULL;
	for (ptr = pattern_list; ptr; ptr = ptr->next) {
		if (ptr->is_deleted) continue;
		if (!PathMatchesToPattern(filename, ptr->pattern)) continue;
		pattern = ptr->pattern;
		if (strendswith(pattern->name, "/\\*")) {
			/* Do nothing. Try to find the better match. */
		} else {
			/* This would be the better match. Use this. */
			break;
		}
	}
	if (pattern) filename = pattern;
	return filename;
}

int AddPatternPolicy(char *pattern, const int is_delete)
{
	return AddPatternEntry(pattern, is_delete);
}

int ReadPatternPolicy(IO_BUFFER *head)
{
	PATTERN_ENTRY *ptr = (PATTERN_ENTRY *) head->read_var2;
	if (!ptr) ptr = pattern_list;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (!ptr->is_deleted && io_printf(head, KEYWORD_FILE_PATTERN "%s\n", ptr->pattern->name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

/*************************  NON REWRITABLE FILE HANDLER  *************************/

static NO_REWRITE_ENTRY *no_rewrite_list = NULL;

static int AddNoRewriteEntry(const char *pattern, const int is_delete)
{
	NO_REWRITE_ENTRY *new_entry, *ptr;
	static DECLARE_MUTEX(lock);
	const struct path_info *saved_pattern;
	int error = -ENOMEM;
	if (!IsCorrectPath(pattern, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if ((saved_pattern = SaveName(pattern)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = no_rewrite_list; ptr; ptr = ptr->next) {
		if (ptr->pattern == saved_pattern) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = (NO_REWRITE_ENTRY *) alloc_element(sizeof(NO_REWRITE_ENTRY))) == NULL) goto out;
	new_entry->pattern = saved_pattern;
	mb(); /* Instead of using spinlock. */
	if ((ptr = no_rewrite_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		no_rewrite_list = new_entry;
	}
	error = 0;
 out:
	up(&lock);
	return error;
}

static int IsNoRewriteFile(const struct path_info *filename)
{
	NO_REWRITE_ENTRY *ptr;
	for (ptr = no_rewrite_list; ptr; ptr = ptr->next) {
		if (ptr->is_deleted) continue;
		if (!PathMatchesToPattern(filename, ptr->pattern)) continue;
		return 1;
	}
	return 0;
}

int AddNoRewritePolicy(char *pattern, const int is_delete)
{
	return AddNoRewriteEntry(pattern, is_delete);
}

int ReadNoRewritePolicy(IO_BUFFER *head)
{
	NO_REWRITE_ENTRY *ptr = (NO_REWRITE_ENTRY *) head->read_var2;
	if (!ptr) ptr = no_rewrite_list;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (!ptr->is_deleted && io_printf(head, KEYWORD_DENY_REWRITE "%s\n", ptr->pattern->name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

/*************************  FILE ACL HANDLER  *************************/

static int AddFileACL(const char *filename, u8 perm, struct domain_info * const domain, const u8 is_add, const struct condition_list *condition)
{
	const struct path_info *saved_filename;
	struct acl_info *ptr;
	int error = -ENOMEM;
	u8 is_group = 0;
	if (!domain) return -EINVAL;
	if (perm > 7 || !perm) {
		printk(KERN_DEBUG "%s: Invalid permission '%d %s'\n", __FUNCTION__, perm, filename);
		return -EINVAL;
	}
	if (!IsCorrectPath(filename, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if (filename[0] == '@') {
		/* This cast is OK because I don't dereference in this function. */
		if ((saved_filename = (struct path_info *) FindOrAssignNewGroup(filename + 1)) == NULL) return -ENOMEM;
		is_group = 1;
	} else {
		if ((saved_filename = SaveName(filename)) == NULL) return -ENOMEM;
		if (!saved_filename->is_dir) {
			if (perm == 4 && IsGloballyReadableFile(saved_filename) && is_add) {
				return 0;   /* Don't add if the file is globally readable files. */
			}
		} else {
			if ((perm & 2) == 0) return 0; /* Don't add if the directory doesn't have write permission. */
		}
	}
	down(&domain_acl_lock);
	if (is_add) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			FILE_ACL_RECORD *new_ptr;
			if (ptr->type == TYPE_FILE_ACL && ptr->cond == condition) {
				if (((FILE_ACL_RECORD *) ptr)->u.filename == saved_filename) {
					if (ptr->is_deleted) {
						ptr->u.b[0] = 0;
						mb();
						ptr->is_deleted = 0;
					}
					/* Found. Just 'OR' the permission bits. */
					ptr->u.b[0] |= perm;
					error = 0;
					UpdateCounter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
					break;
				}
			}
			if (ptr->next) {
				ptr = ptr->next;
				continue;
			}
	first_entry: ;
			if (is_add == 1 && TooManyDomainACL(domain)) break;
			/* Not found. Append it to the tail. */
			if ((new_ptr = (FILE_ACL_RECORD *) alloc_element(sizeof(FILE_ACL_RECORD))) == NULL) break;
			new_ptr->head.type = TYPE_FILE_ACL;
			new_ptr->head.u.b[0] = perm;
			new_ptr->head.u.b[1] = is_group;
			new_ptr->head.cond = condition;
			new_ptr->u.filename = saved_filename;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
			if (ptr->type != TYPE_FILE_ACL || ptr->is_deleted || ptr->cond != condition || ptr->u.b[0] != perm) continue;
			if (((FILE_ACL_RECORD *) ptr)->u.filename != saved_filename) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
	up(&domain_acl_lock);
	return error;
}

static int CheckFileACL(const struct path_info *filename, const u8 perm, struct obj_info *obj)
{
	const struct domain_info *domain = current->domain_info;
	struct acl_info *ptr;
	const int may_use_pattern = ((perm & 1) == 0);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (!filename->is_dir) {
		if (perm == 4 && IsGloballyReadableFile(filename)) return 0;
	}
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type != TYPE_FILE_ACL || ptr->is_deleted || (ptr->u.b[0] & perm) != perm || CheckCondition(ptr->cond, obj)) continue;
		if (ptr->u.b[1]) {
			if (PathMatchesToGroup(filename, ((FILE_ACL_RECORD *) ptr)->u.group, may_use_pattern)) return 0;
		} else if (may_use_pattern || !((FILE_ACL_RECORD *) ptr)->u.filename->is_patterned) {
			if (PathMatchesToPattern(filename, ((FILE_ACL_RECORD *) ptr)->u.filename)) return 0;
		}
	}
	return -EPERM;
}

static int CheckFilePerm2(const struct path_info *filename, const u8 perm, const char *operation, struct obj_info *obj)
{
	int error = 0;
	if (!filename) return 0;
	error = CheckFileACL(filename, perm, obj);
	AuditFileLog(filename, perm, !error);
	if (error) {
		struct domain_info * const domain = current->domain_info;
		const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
		if (TomoyoVerboseMode()) {
			printk("TOMOYO-%s: Access %d(%s) to %s denied for %s\n", GetMSG(is_enforce), perm, operation, filename->name, GetLastName(domain));
		}
		if (is_enforce) error = CheckSupervisor("%s\n%d %s\n", domain->domainname->name, perm, filename->name);
		else if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_FILE)) {
			/* Don't use patterns if execution bit is on. */
			const struct path_info *patterned_file = ((perm & 1) == 0) ? GetPattern(filename) : filename;
			AddFileACL(patterned_file->name, perm, domain, 1, NULL);
		}
		if (!is_enforce) error = 0;
	}
	return error;
}

int AddFilePolicy(char *data, struct domain_info *domain, const int is_delete)
{
	char *filename = strchr(data, ' ');
	char *cp;
	const struct condition_list *condition = NULL;
	unsigned int perm;
	u8 type;
	if (!filename) return -EINVAL;
	*filename++ = '\0';
	if (sscanf(data, "%u", &perm) == 1) {
		cp = FindConditionPart(filename);
		if (cp && (condition = FindOrAssignNewCondition(cp)) == NULL) goto out;
		return AddFileACL(filename, (u8) perm, domain, is_delete ? 0 : -1, condition);
	}
	if (strncmp(data, "allow_", 6)) goto out;
	data += 6;
	for (type = 0; acl_type_array[type].keyword; type++) {
		if (strcmp(data, acl_type_array[type].keyword)) continue;
		if (acl_type_array[type].paths == 2) {
			char *filename2 = strchr(filename, ' ');
			if (!filename2) break;
			*filename2++ = '\0';
			cp = FindConditionPart(filename2);
			if (cp && (condition = FindOrAssignNewCondition(cp)) == NULL) goto out;
			return AddDoubleWriteACL(type, filename, filename2, domain, is_delete ? 0 : -1, condition);
		} else {
			cp = FindConditionPart(filename);
			if (cp && (condition = FindOrAssignNewCondition(cp)) == NULL) goto out;
			return AddSingleWriteACL(type, filename, domain, is_delete ? 0 : -1, condition);
		}
		break;
	}
 out:
	return -EINVAL;
}

static int AddSingleWriteACL(const u8 type, const char *filename, struct domain_info * const domain, const u8 is_add, const struct condition_list *condition)
{
	const struct path_info *saved_filename;
	struct acl_info *ptr;
	int error = -ENOMEM;
	u8 is_group = 0;
	if (!domain) return -EINVAL;
	if (!IsCorrectPath(filename, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if (filename[0] == '@') {
		/* This cast is OK because I don't dereference in this function. */
		if ((saved_filename = (struct path_info *) FindOrAssignNewGroup(filename + 1)) == NULL) return -ENOMEM;
		is_group = 1;
	} else {
		if ((saved_filename = SaveName(filename)) == NULL) return -ENOMEM;
	}
	down(&domain_acl_lock);
	if (is_add) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			SINGLE_ACL_RECORD *new_ptr;
			if (ptr->type == type && ptr->cond == condition) {
				if (((SINGLE_ACL_RECORD *) ptr)->u.filename == saved_filename) {
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
			if (is_add == 1 && TooManyDomainACL(domain)) break;
			/* Not found. Append it to the tail. */
			if ((new_ptr = (SINGLE_ACL_RECORD *) alloc_element(sizeof(SINGLE_ACL_RECORD))) == NULL) break;
			new_ptr->head.type = type;
			new_ptr->head.cond = condition;
			new_ptr->head.u.w = is_group;
			new_ptr->u.filename = saved_filename;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
			if (ptr->type != type || ptr->is_deleted || ptr->cond != condition) continue;
			if (((SINGLE_ACL_RECORD *) ptr)->u.filename != saved_filename) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
	up(&domain_acl_lock);
	return error;
}

static int AddDoubleWriteACL(const u8 type, const char *filename1, const char *filename2, struct domain_info * const domain, const u8 is_add, const struct condition_list *condition)
{
	const struct path_info *saved_filename1, *saved_filename2;
	struct acl_info *ptr;
	int error = -ENOMEM;
	u8 is_group1 = 0, is_group2 = 0;
	if (!domain) return -EINVAL;
	if (!IsCorrectPath(filename1, 0, 0, 0, __FUNCTION__) || !IsCorrectPath(filename2, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if (filename1[0] == '@') {
		/* This cast is OK because I don't dereference in this function. */
		if ((saved_filename1 = (struct path_info *) FindOrAssignNewGroup(filename1 + 1)) == NULL) return -ENOMEM;
		is_group1 = 1;
	} else {
		if ((saved_filename1 = SaveName(filename1)) == NULL) return -ENOMEM;
	}
	if (filename2[0] == '@') {
		/* This cast is OK because I don't dereference in this function. */
		if ((saved_filename2 = (struct path_info *) FindOrAssignNewGroup(filename2 + 1)) == NULL) return -ENOMEM;
		is_group2 = 1;
	} else {
		if ((saved_filename2 = SaveName(filename2)) == NULL) return -ENOMEM;
	}
	down(&domain_acl_lock);
	if (is_add) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			DOUBLE_ACL_RECORD *new_ptr;
			if (ptr->type == type && ptr->cond == condition) {
				if (((DOUBLE_ACL_RECORD *) ptr)->u1.filename1 == saved_filename1 && ((DOUBLE_ACL_RECORD *) ptr)->u2.filename2 == saved_filename2) {
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
			if (is_add == 1 && TooManyDomainACL(domain)) break;
			/* Not found. Append it to the tail. */
			if ((new_ptr = (DOUBLE_ACL_RECORD *) alloc_element(sizeof(DOUBLE_ACL_RECORD))) == NULL) break;
			new_ptr->head.type = type;
			new_ptr->head.cond = condition;
			new_ptr->head.u.b[0] = is_group1;
			new_ptr->head.u.b[1] = is_group2;
			new_ptr->u1.filename1 = saved_filename1;
			new_ptr->u2.filename2 = saved_filename2;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
			if (ptr->type != type || ptr->is_deleted || ptr->cond != condition) continue;
			if (((DOUBLE_ACL_RECORD *) ptr)->u1.filename1 != saved_filename1 ||
				((DOUBLE_ACL_RECORD *) ptr)->u2.filename2 != saved_filename2) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
	up(&domain_acl_lock);
	return error;
}

static int CheckSingleWriteACL(const u8 type, const struct path_info *filename, struct obj_info *obj)
{
	const struct domain_info *domain = current->domain_info;
	struct acl_info *ptr;
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type != type || ptr->is_deleted || CheckCondition(ptr->cond, obj)) continue;
		if (ptr->u.w) {
			if (!PathMatchesToGroup(filename, ((SINGLE_ACL_RECORD *) ptr)->u.group, 1)) continue;
		} else {
			if (!PathMatchesToPattern(filename, ((SINGLE_ACL_RECORD *) ptr)->u.filename)) continue;
		}
		return 0;
	}
	return -EPERM;
}

static int CheckDoubleWriteACL(const u8 type, const struct path_info *filename1, const struct path_info *filename2, struct obj_info *obj)
{
	const struct domain_info *domain = current->domain_info;
	struct acl_info *ptr;
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type != type || ptr->is_deleted || CheckCondition(ptr->cond, obj)) continue;
		if (ptr->u.b[0]) {
			if (!PathMatchesToGroup(filename1, ((DOUBLE_ACL_RECORD *) ptr)->u1.group1, 1)) continue;
		} else {
			if (!PathMatchesToPattern(filename1, ((DOUBLE_ACL_RECORD *) ptr)->u1.filename1)) continue;
		}
		if (ptr->u.b[1]) {
			if (!PathMatchesToGroup(filename2, ((DOUBLE_ACL_RECORD *) ptr)->u2.group2, 1)) continue;
		} else {
			if (!PathMatchesToPattern(filename2, ((DOUBLE_ACL_RECORD *) ptr)->u2.filename2)) continue;
		}
		return 0;
	}
	return -EPERM;
}

static int CheckSingleWritePermission2(const unsigned int operation, const struct path_info *filename, struct obj_info *obj)
{
	int error;
	struct domain_info * const domain = current->domain_info;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (CheckACLFlags(operation) < 0) return 0;
	if (CheckACLFlags(operation) > 0) {
		error = CheckSingleWriteACL(operation, filename, obj);
		AuditWriteLog(acltype2keyword(operation), filename, NULL, !error);
		if (error) {
			if (TomoyoVerboseMode()) {
				printk("TOMOYO-%s: Access '%s %s' denied for %s\n", GetMSG(is_enforce), acltype2keyword(operation), filename->name, GetLastName(domain));
			}
			if (is_enforce) error = CheckSupervisor("%s\nallow_%s %s\n", domain->domainname->name, acltype2keyword(operation), filename->name);
			else if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_FILE)) AddSingleWriteACL(operation, GetPattern(filename)->name, domain, 1, NULL);
			if (!is_enforce) error = 0;
		}
	} else {
		error = CheckFilePerm2(filename, 2, acltype2keyword(operation), obj);
	}
	if (!error && operation == TYPE_TRUNCATE_ACL && IsNoRewriteFile(filename)) {
		error = CheckSingleWritePermission2(TYPE_REWRITE_ACL, filename, obj);
	}
	return error;
}

int CheckFilePerm(const char *filename0, const u8 perm, const char *operation)
{
	struct path_info filename;
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	filename.name = filename0;
	fill_path_info(&filename);
	return CheckFilePerm2(&filename, perm, operation, NULL);
}

int CheckExecPerm(const struct path_info *filename, struct file *filp)
{
	struct obj_info obj;
	memset(&obj, 0, sizeof(obj));
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	obj.path1_dentry = filp->f_dentry;
	obj.path1_vfsmnt = filp->f_vfsmnt;
	return CheckFilePerm2(filename, 1, "do_execve", &obj);
}

int CheckOpenPermission(struct dentry *dentry, struct vfsmount *mnt, const int flag)
{
	const int acc_mode = ACC_MODE(flag);
	int error = -ENOMEM;
	struct path_info *buf;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (acc_mode == 0) return 0;
	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)) {
		/* I don't check directories here because mkdir() and rmdir() don't call me. */
		return 0;
	}
	buf = GetPath(dentry, mnt);
	if (buf) {
		struct obj_info obj;
		memset(&obj, 0, sizeof(obj));
		obj.path1_dentry = dentry;
		obj.path1_vfsmnt = mnt;
		error = 0;
		if ((acc_mode & MAY_WRITE)) {
			if ((flag & O_TRUNC) || !(flag & O_APPEND)) {
				if (IsNoRewriteFile(buf)) {
					error = CheckSingleWritePermission2(TYPE_REWRITE_ACL, buf, &obj);
				}
			}
		}
		if (error == 0) error = CheckFilePerm2(buf, acc_mode, "open", &obj);
		if (error == 0 && (flag & O_TRUNC)) error = CheckSingleWritePermission2(TYPE_TRUNCATE_ACL, buf, &obj);
		ccs_free(buf);
	}
	if (!is_enforce) error = 0;
	return error;
}

int CheckSingleWritePermission(const unsigned int operation, struct dentry *dentry, struct vfsmount *mnt)
{
	int error = -ENOMEM;
	struct path_info *buf;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	buf = GetPath(dentry, mnt);
	if (buf) {
		struct obj_info obj;
		switch (operation) {
		case TYPE_MKDIR_ACL:
		case TYPE_RMDIR_ACL:
			if (!buf->is_dir) {
				strcat((char *) buf->name, "/");
				fill_path_info(buf);
			}
		}
		memset(&obj, 0, sizeof(obj));
		obj.path1_dentry = dentry;
		obj.path1_vfsmnt = mnt;
		error = CheckSingleWritePermission2(operation, buf, &obj);
		ccs_free(buf);
	}
	if (!is_enforce) error = 0;
	return error;
}

int CheckReWritePermission(struct file *filp)
{
	int error = -ENOMEM;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	struct path_info *buf = GetPath(filp->f_dentry, filp->f_vfsmnt);
	if (buf) {
		if (IsNoRewriteFile(buf)) {
			struct obj_info obj;
			memset(&obj, 0, sizeof(obj));
			obj.path1_dentry = filp->f_dentry;
			obj.path1_vfsmnt = filp->f_vfsmnt;
			error = CheckSingleWritePermission2(TYPE_REWRITE_ACL, buf, &obj);
		} else {
			error = 0;
		}
		ccs_free(buf);
	}
	if (!is_enforce) error = 0;
	return error;
}

int CheckDoubleWritePermission(const unsigned int operation, struct dentry *dentry1, struct vfsmount *mnt1, struct dentry *dentry2, struct vfsmount *mnt2)
{
	int error = -ENOMEM;
	struct path_info *buf1, *buf2;
	struct domain_info * const domain = current->domain_info;
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (CheckACLFlags(operation) < 0) return 0;		
	buf1 = GetPath(dentry1, mnt1);
	buf2 = GetPath(dentry2, mnt2);
	if (buf1 && buf2) {
		struct obj_info obj;
		if (operation == TYPE_RENAME_ACL) { /* TYPE_LINK_ACL can't reach here for directory. */
			if (dentry1->d_inode && S_ISDIR(dentry1->d_inode->i_mode)) {
				if (!buf1->is_dir) {
					strcat((char *) buf1->name, "/");
					fill_path_info(buf1);
				}
				if (!buf2->is_dir) {
					strcat((char *) buf2->name, "/");
					fill_path_info(buf2);
				}
			}
		}
		memset(&obj, 0, sizeof(obj));
		obj.path1_dentry = dentry1;
		obj.path1_vfsmnt = mnt1;
		obj.path2_dentry = dentry2;
		obj.path2_vfsmnt = mnt2;
		if (CheckACLFlags(operation) > 0) {
			error = CheckDoubleWriteACL(operation, buf1, buf2, &obj);
			AuditWriteLog(acltype2keyword(operation), buf1, buf2, !error);
			if (error) {
				if (TomoyoVerboseMode()) {
					printk("TOMOYO-%s: Access '%s %s %s' denied for %s\n", GetMSG(is_enforce), acltype2keyword(operation), buf1->name, buf2->name, GetLastName(domain));
				}
				if (is_enforce) error = CheckSupervisor("%s\nallow_%s %s %s\n", domain->domainname->name, acltype2keyword(operation), buf1->name, buf2->name);
				else if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_FILE)) AddDoubleWriteACL(operation, GetPattern(buf1)->name, GetPattern(buf2)->name, domain, 1, NULL);
			}
		} else {
			error = CheckFilePerm2(buf1, 2, acltype2keyword(operation), &obj);
			if (!error) error = CheckFilePerm2(buf2, 2, acltype2keyword(operation), &obj);
		}
	}
	ccs_free(buf1);
	ccs_free(buf2);
	if (!is_enforce) error = 0;
	return error;
}

EXPORT_SYMBOL(CheckFilePerm);
EXPORT_SYMBOL(CheckExecPerm);
EXPORT_SYMBOL(CheckOpenPermission);
EXPORT_SYMBOL(CheckReWritePermission);
EXPORT_SYMBOL(CheckSingleWritePermission);
EXPORT_SYMBOL(CheckDoubleWritePermission);

/***** TOMOYO Linux end. *****/
