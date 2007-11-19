/*
 * fs/tomoyo_file.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.5.2-pre   2007/11/19
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

extern struct mutex domain_acl_lock;

/***** The structure for globally readable files. *****/

struct globally_readable_file_entry {
	struct list_head list;
	const struct path_info *filename;
	bool is_deleted;
};

/***** The structure for filename patterns. *****/

struct pattern_entry {
	struct list_head list;
	const struct path_info *pattern;
	bool is_deleted;
};

/***** The structure for non-rewritable-by-default file patterns. *****/

struct no_rewrite_entry {
	struct list_head list;
	const struct path_info *pattern;
	bool is_deleted;
};

/***** The structure for detailed write operations. *****/

static struct {
	const char *keyword;
	const int paths;
} acl_type_array[] = { /* mapping.txt */
	{ "create",   1 }, /* TYPE_CREATE_ACL   */
	{ "unlink",   1 }, /* TYPE_UNLINK_ACL   */
	{ "mkdir",    1 }, /* TYPE_MKDIR_ACL    */
	{ "rmdir",    1 }, /* TYPE_RMDIR_ACL    */
	{ "mkfifo",   1 }, /* TYPE_MKFIFO_ACL   */
	{ "mksock",   1 }, /* TYPE_MKSOCK_ACL   */
	{ "mkblock",  1 }, /* TYPE_MKBLOCK_ACL  */
	{ "mkchar",   1 }, /* TYPE_MKCHAR_ACL   */
	{ "truncate", 1 }, /* TYPE_TRUNCATE_ACL */
	{ "symlink",  1 }, /* TYPE_SYMLINK_ACL  */
	{ "link",     2 }, /* TYPE_LINK_ACL     */
	{ "rename",   2 }, /* TYPE_RENAME_ACL   */
	{ "rewrite",  1 }, /* TYPE_REWRITE_ACL  */
	{ NULL, 0 }
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

static int strendswith(const char *name, const char *tail)
{
	int len;
	if (!name || !tail) return 0;
	len = strlen(name) - strlen(tail);
	return len >= 0 && strcmp(name + len, tail) == 0;
}

static struct path_info *GetPath(struct dentry *dentry, struct vfsmount *mnt)
{
	struct path_info_with_data { /* Keep sizeof(struct path_info_with_data) <= PAGE_SIZE for speed. */
		struct path_info head; /* Keep this first, for this pointer is passed to ccs_free(). */
		char bariier1[16];
		char body[CCS_MAX_PATHNAME_LEN];
		char barrier2[16];
	} *buf = ccs_alloc(sizeof(*buf));
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

static int AddDoubleWriteACL(const u8 type, const char *filename1, const char *filename2, struct domain_info * const domain, const struct condition_list *condition, const bool is_delete);
static int AddSingleWriteACL(const u8 type, const char *filename, struct domain_info * const domain, const struct condition_list *condition, const bool is_delete);

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditFileLog(const struct path_info *filename, const u8 perm, const bool is_granted)
{
	char *buf;
	int len;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	len = filename->total_len + 8;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, "%d %s\n", perm, filename->name);
	return WriteAuditLog(buf, is_granted);
}

static int AuditWriteLog(const char *operation, const struct path_info *filename1, const struct path_info *filename2, const bool is_granted)
{
	char *buf;
	int len;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	len = strlen(operation) + filename1->total_len + (filename2 ? filename2->total_len : 0) + 16;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, "allow_%s %s %s\n", operation, filename1->name, filename2 ? filename2->name : "");
	return WriteAuditLog(buf, is_granted);
}

/*************************  GLOBALLY READABLE FILE HANDLER  *************************/

static LIST_HEAD(globally_readable_list);

static int AddGloballyReadableEntry(const char *filename, const bool is_delete)
{
	struct globally_readable_file_entry *new_entry, *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_filename;
	int error = -ENOMEM;
	if (!IsCorrectPath(filename, 1, -1, -1, __FUNCTION__)) return -EINVAL; /* No patterns allowed. */
	if ((saved_filename = SaveName(filename)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list_for_each_entry(ptr, &globally_readable_list, list) {
		if (ptr->filename == saved_filename) {
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT; goto out;
	}
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->filename = saved_filename;
	list_add_tail_mb(&new_entry->list, &globally_readable_list);
	error = 0;
 out: ;
	mutex_unlock(&lock);
	return error;
}

static int IsGloballyReadableFile(const struct path_info *filename)
{
	struct globally_readable_file_entry *ptr;
	list_for_each_entry(ptr, &globally_readable_list, list) {
		if (!ptr->is_deleted && !pathcmp(filename, ptr->filename)) return 1;
	}
	return 0;
}

int AddGloballyReadablePolicy(char *filename, const bool is_delete)
{
	return AddGloballyReadableEntry(filename, is_delete);
}

int ReadGloballyReadablePolicy(struct io_buffer *head)
{
	struct list_head *pos;
	list_for_each_cookie(pos, head->read_var2, &globally_readable_list) {
		struct globally_readable_file_entry *ptr;
		ptr = list_entry(pos, struct globally_readable_file_entry, list);
		if (ptr->is_deleted) continue;
		if (io_printf(head, KEYWORD_ALLOW_READ "%s\n", ptr->filename->name)) return -ENOMEM;
	}
	return 0;
}

/*************************  FILE GROUP HANDLER  *************************/

static LIST_HEAD(path_group_list);

static int AddPathGroupEntry(const char *group_name, const char *member_name, const bool is_delete)
{
	static DEFINE_MUTEX(lock);
	struct path_group_entry *new_group, *group;
	struct path_group_member *new_member, *member;
	const struct path_info *saved_group_name, *saved_member_name;
	int error = -ENOMEM;
	bool found = 0;
	if (!IsCorrectPath(group_name, 0, 0, 0, __FUNCTION__) || !group_name[0] ||
		!IsCorrectPath(member_name, 0, 0, 0, __FUNCTION__) || !member_name[0]) return -EINVAL;
	if ((saved_group_name = SaveName(group_name)) == NULL ||
		(saved_member_name = SaveName(member_name)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list_for_each_entry(group, &path_group_list, list) {
		if (saved_group_name != group->group_name) continue;
		list_for_each_entry(member, &group->path_group_member_list, list) {
			if (member->member_name == saved_member_name) {
				member->is_deleted = is_delete;
				error = 0;
				goto out;
			}
		}
		found = 1;
		break;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if (!found) {
		if ((new_group = alloc_element(sizeof(*new_group))) == NULL) goto out;
		INIT_LIST_HEAD(&new_group->path_group_member_list);
		new_group->group_name = saved_group_name;
		list_add_tail_mb(&new_group->list, &path_group_list);
		group = new_group;
	}
	if ((new_member = alloc_element(sizeof(*new_member))) == NULL) goto out;
	new_member->member_name = saved_member_name;
	list_add_tail_mb(&new_member->list, &group->path_group_member_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	return error;
}

int AddPathGroupPolicy(char *data, const bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp++ = '\0';
	return AddPathGroupEntry(data, cp, is_delete);
}

static struct path_group_entry *FindOrAssignNewPathGroup(const char *group_name)
{
	int i;
	struct path_group_entry *group;
	for (i = 0; i <= 1; i++) {
		list_for_each_entry(group, &path_group_list, list) {
			if (strcmp(group_name, group->group_name->name) == 0) return group;
		}
		if (i == 0) {
			AddPathGroupEntry(group_name, "/", 0);
			AddPathGroupEntry(group_name, "/", 1);
		}
	}
	return NULL;
}

static int PathMatchesToGroup(const struct path_info *pathname, const struct path_group_entry *group, const bool may_use_pattern)
{
	struct path_group_member *member;
	list_for_each_entry(member, &group->path_group_member_list, list) {
		if (member->is_deleted) continue;
		if (!member->member_name->is_patterned) {
			if (!pathcmp(pathname, member->member_name)) return 1;
		} else if (may_use_pattern) {
			if (PathMatchesToPattern(pathname, member->member_name)) return 1;
		}
	}
	return 0;
}

int ReadPathGroupPolicy(struct io_buffer *head)
{
	struct list_head *gpos;
	struct list_head *mpos;
	list_for_each_cookie(gpos, head->read_var1, &path_group_list) {
		struct path_group_entry *group;
		group = list_entry(gpos, struct path_group_entry, list);
		list_for_each_cookie(mpos, head->read_var2, &group->path_group_member_list) {
			struct path_group_member *member;
			member = list_entry(mpos, struct path_group_member, list);
			if (member->is_deleted) continue;
			if (io_printf(head, KEYWORD_PATH_GROUP "%s %s\n", group->group_name->name, member->member_name->name)) return -ENOMEM;
		}
	}
	return 0;
}

/*************************  FILE PATTERN HANDLER  *************************/

static LIST_HEAD(pattern_list);

static int AddPatternEntry(const char *pattern, const bool is_delete)
{
	struct pattern_entry *new_entry, *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_pattern;
	int error = -ENOMEM;
	if (!IsCorrectPath(pattern, 0, 1, 0, __FUNCTION__)) return -EINVAL;
	if ((saved_pattern = SaveName(pattern)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list_for_each_entry(ptr, &pattern_list, list) {
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
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->pattern = saved_pattern;
	list_add_tail_mb(&new_entry->list, &pattern_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	return error;
}

static const struct path_info *GetPattern(const struct path_info *filename)
{
	struct pattern_entry *ptr;
	const struct path_info *pattern = NULL;
	list_for_each_entry(ptr, &pattern_list, list) {
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

int AddPatternPolicy(char *pattern, const bool is_delete)
{
	return AddPatternEntry(pattern, is_delete);
}

int ReadPatternPolicy(struct io_buffer *head)
{
	struct list_head *pos;
	list_for_each_cookie(pos, head->read_var2, &pattern_list) {
		struct pattern_entry *ptr;
		ptr = list_entry(pos, struct pattern_entry, list);
		if (ptr->is_deleted) continue;
		if (io_printf(head, KEYWORD_FILE_PATTERN "%s\n", ptr->pattern->name)) return -ENOMEM;
	}
	return 0;
}

/*************************  NON REWRITABLE FILE HANDLER  *************************/

static LIST_HEAD(no_rewrite_list);

static int AddNoRewriteEntry(const char *pattern, const bool is_delete)
{
	struct no_rewrite_entry *new_entry, *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_pattern;
	int error = -ENOMEM;
	if (!IsCorrectPath(pattern, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if ((saved_pattern = SaveName(pattern)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list_for_each_entry(ptr, &no_rewrite_list, list) {
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
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->pattern = saved_pattern;
	list_add_tail_mb(&new_entry->list, &no_rewrite_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	return error;
}

static int IsNoRewriteFile(const struct path_info *filename)
{
	struct no_rewrite_entry *ptr;
	list_for_each_entry(ptr, &no_rewrite_list, list) {
		if (ptr->is_deleted) continue;
		if (!PathMatchesToPattern(filename, ptr->pattern)) continue;
		return 1;
	}
	return 0;
}

int AddNoRewritePolicy(char *pattern, const bool is_delete)
{
	return AddNoRewriteEntry(pattern, is_delete);
}

int ReadNoRewritePolicy(struct io_buffer *head)
{
	struct list_head *pos;
	list_for_each_cookie(pos, head->read_var2, &no_rewrite_list) {
		struct no_rewrite_entry *ptr;
		ptr = list_entry(pos, struct no_rewrite_entry, list);
		if (ptr->is_deleted) continue;
		if (io_printf(head, KEYWORD_DENY_REWRITE "%s\n", ptr->pattern->name)) return -ENOMEM;
	}
	return 0;
}

/*************************  FILE ACL HANDLER  *************************/

static int AddFileACL(const char *filename, u8 perm, struct domain_info * const domain, const struct condition_list *condition, const bool is_delete)
{
	const struct path_info *saved_filename;
	struct acl_info *ptr;
	struct file_acl_record *acl;
	int error = -ENOMEM;
	bool is_group = 0;
	if (!domain) return -EINVAL;
	if (perm > 7 || !perm) {
		printk(KERN_DEBUG "%s: Invalid permission '%d %s'\n", __FUNCTION__, perm, filename);
		return -EINVAL;
	}
	if (!IsCorrectPath(filename, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if (filename[0] == '@') {
		/* This cast is OK because I don't dereference in this function. */
		if ((saved_filename = (struct path_info *) FindOrAssignNewPathGroup(filename + 1)) == NULL) return -ENOMEM;
		is_group = 1;
	} else {
		if (strendswith(filename, "/")) {
			return 0; /* Valid permissions for directory are only 'allow_mkdir' and 'allow_rmdir'. */
		}
		if ((saved_filename = SaveName(filename)) == NULL) return -ENOMEM;
		if (!is_delete && perm == 4 && IsGloballyReadableFile(saved_filename)) {
			return 0;   /* Don't add if the file is globally readable files. */
		}
	}
	mutex_lock(&domain_acl_lock);
	if (!is_delete) {
		list_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = list_entry(ptr, struct file_acl_record, head);
			if (ptr->type == TYPE_FILE_ACL && ptr->cond == condition) {
				if (acl->u.filename == saved_filename) {
					if (ptr->is_deleted) {
						acl->perm = 0;
						mb(); /* Avoid out-of-order execution. */
						ptr->is_deleted = 0;
					}
					/* Found. Just 'OR' the permission bits. */
					acl->perm |= perm;
					error = 0;
					UpdateCounter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
					goto out;
				}
			}
		}
		/* Not found. Append it to the tail. */
		if ((acl = alloc_element(sizeof(*acl))) == NULL) goto out;
		acl->head.type = TYPE_FILE_ACL;
		acl->perm = perm;
		acl->u_is_group = is_group;
		acl->head.cond = condition;
		acl->u.filename = saved_filename;
		error = AddDomainACL(domain, &acl->head);
	} else {
		list_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = list_entry(ptr, struct file_acl_record, head);
			if (ptr->type != TYPE_FILE_ACL || ptr->is_deleted || ptr->cond != condition || acl->perm != perm) continue;
			if (acl->u.filename != saved_filename) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
 out: ;
	mutex_unlock(&domain_acl_lock);
	return error;
}

static int CheckFileACL(const struct path_info *filename, const u8 perm, struct obj_info *obj)
{
	const struct domain_info *domain = current->domain_info;
	struct acl_info *ptr;
	const bool may_use_pattern = ((perm & 1) == 0);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	if (!filename->is_dir) {
		if (perm == 4 && IsGloballyReadableFile(filename)) return 0;
	}
	list_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct file_acl_record *acl;
		acl = list_entry(ptr, struct file_acl_record, head);
		if (ptr->type != TYPE_FILE_ACL || ptr->is_deleted || (acl->perm & perm) != perm || CheckCondition(ptr->cond, obj)) continue;
		if (acl->u_is_group) {
			if (PathMatchesToGroup(filename, acl->u.group, may_use_pattern)) return 0;
		} else if (may_use_pattern || !acl->u.filename->is_patterned) {
			if (PathMatchesToPattern(filename, acl->u.filename)) return 0;
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
		const bool is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
		if (TomoyoVerboseMode()) {
			printk("TOMOYO-%s: Access %d(%s) to %s denied for %s\n", GetMSG(is_enforce), perm, operation, filename->name, GetLastName(domain));
		}
		if (is_enforce) error = CheckSupervisor("%s\n%d %s\n", domain->domainname->name, perm, filename->name);
		else if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_FILE, domain)) {
			/* Don't use patterns if execution bit is on. */
			const struct path_info *patterned_file = ((perm & 1) == 0) ? GetPattern(filename) : filename;
			AddFileACL(patterned_file->name, perm, domain, NULL, 0);
		}
		if (!is_enforce) error = 0;
	}
	return error;
}

int AddFilePolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	char *filename = strchr(data, ' ');
	unsigned int perm;
	u8 type;
	if (!filename) return -EINVAL;
	*filename++ = '\0';
	if (sscanf(data, "%u", &perm) == 1) {
		return AddFileACL(filename, (u8) perm, domain, condition, is_delete);
	}
	if (strncmp(data, "allow_", 6)) goto out;
	data += 6;
	for (type = 0; acl_type_array[type].keyword; type++) {
		if (strcmp(data, acl_type_array[type].keyword)) continue;
		if (acl_type_array[type].paths == 2) {
			char *filename2 = strchr(filename, ' ');
			if (!filename2) break;
			*filename2++ = '\0';
			return AddDoubleWriteACL(type, filename, filename2, domain, condition, is_delete);
		} else {
			return AddSingleWriteACL(type, filename, domain, condition, is_delete);
		}
		break;
	}
 out:
	return -EINVAL;
}

static int AddSingleWriteACL(const u8 type, const char *filename, struct domain_info * const domain, const struct condition_list *condition, const bool is_delete)
{
	const struct path_info *saved_filename;
	struct acl_info *ptr;
	struct single_acl_record *acl;
	int error = -ENOMEM;
	bool is_group = 0;
	if (!domain) return -EINVAL;
	if (!IsCorrectPath(filename, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if (filename[0] == '@') {
		/* This cast is OK because I don't dereference in this function. */
		if ((saved_filename = (struct path_info *) FindOrAssignNewPathGroup(filename + 1)) == NULL) return -ENOMEM;
		is_group = 1;
	} else {
		if ((saved_filename = SaveName(filename)) == NULL) return -ENOMEM;
	}
	mutex_lock(&domain_acl_lock);
	if (!is_delete) {
		list_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = list_entry(ptr, struct single_acl_record, head);
			if (ptr->type == type && ptr->cond == condition) {
				if (acl->u.filename == saved_filename) {
					ptr->is_deleted = 0;
					/* Found. Nothing to do. */
					error = 0;
					goto out;
				}
			}
		}
		/* Not found. Append it to the tail. */
		if ((acl = alloc_element(sizeof(*acl))) == NULL) goto out;
		acl->head.type = type;
		acl->head.cond = condition;
		acl->u_is_group = is_group;
		acl->u.filename = saved_filename;
		error = AddDomainACL(domain, &acl->head);
	} else {
		error = -ENOENT;
		list_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = list_entry(ptr, struct single_acl_record, head);
			if (ptr->type != type || ptr->is_deleted || ptr->cond != condition) continue;
			if (acl->u.filename != saved_filename) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
 out: ;
	mutex_unlock(&domain_acl_lock);
	return error;
}

static int AddDoubleWriteACL(const u8 type, const char *filename1, const char *filename2, struct domain_info * const domain, const struct condition_list *condition, const bool is_delete)
{
	const struct path_info *saved_filename1, *saved_filename2;
	struct acl_info *ptr;
	struct double_acl_record *acl;
	int error = -ENOMEM;
	bool is_group1 = 0, is_group2 = 0;
	if (!domain) return -EINVAL;
	if (!IsCorrectPath(filename1, 0, 0, 0, __FUNCTION__) || !IsCorrectPath(filename2, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if (filename1[0] == '@') {
		/* This cast is OK because I don't dereference in this function. */
		if ((saved_filename1 = (struct path_info *) FindOrAssignNewPathGroup(filename1 + 1)) == NULL) return -ENOMEM;
		is_group1 = 1;
	} else {
		if ((saved_filename1 = SaveName(filename1)) == NULL) return -ENOMEM;
	}
	if (filename2[0] == '@') {
		/* This cast is OK because I don't dereference in this function. */
		if ((saved_filename2 = (struct path_info *) FindOrAssignNewPathGroup(filename2 + 1)) == NULL) return -ENOMEM;
		is_group2 = 1;
	} else {
		if ((saved_filename2 = SaveName(filename2)) == NULL) return -ENOMEM;
	}
	mutex_lock(&domain_acl_lock);
	if (!is_delete) {
		list_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = list_entry(ptr, struct double_acl_record, head);
			if (ptr->type == type && ptr->cond == condition) {
				if (acl->u1.filename1 == saved_filename1 && acl->u2.filename2 == saved_filename2) {
					ptr->is_deleted = 0;
					/* Found. Nothing to do. */
					error = 0;
					goto out;
				}
			}
		}
		/* Not found. Append it to the tail. */
		if ((acl = alloc_element(sizeof(*acl))) == NULL) goto out;
		acl->head.type = type;
		acl->head.cond = condition;
		acl->u1_is_group = is_group1;
		acl->u2_is_group = is_group2;
		acl->u1.filename1 = saved_filename1;
		acl->u2.filename2 = saved_filename2;
		error = AddDomainACL(domain, &acl->head);
	} else {
		error = -ENOENT;
		list_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = list_entry(ptr, struct double_acl_record, head);
			if (ptr->type != type || ptr->is_deleted || ptr->cond != condition) continue;
			if (acl->u1.filename1 != saved_filename1 || acl->u2.filename2 != saved_filename2) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
 out: ;
	mutex_unlock(&domain_acl_lock);
	return error;
}

static int CheckSingleWriteACL(const u8 type, const struct path_info *filename, struct obj_info *obj)
{
	const struct domain_info *domain = current->domain_info;
	struct acl_info *ptr;
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	list_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct single_acl_record *acl;
		acl = list_entry(ptr, struct single_acl_record, head);
		if (ptr->type != type || ptr->is_deleted || CheckCondition(ptr->cond, obj)) continue;
		if (acl->u_is_group) {
			if (!PathMatchesToGroup(filename, acl->u.group, 1)) continue;
		} else {
			if (!PathMatchesToPattern(filename, acl->u.filename)) continue;
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
	list_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct double_acl_record *acl;
		acl = list_entry(ptr, struct double_acl_record, head);
		if (ptr->type != type || ptr->is_deleted || CheckCondition(ptr->cond, obj)) continue;
		if (acl->u1_is_group) {
			if (!PathMatchesToGroup(filename1, acl->u1.group1, 1)) continue;
		} else {
			if (!PathMatchesToPattern(filename1, acl->u1.filename1)) continue;
		}
		if (acl->u2_is_group) {
			if (!PathMatchesToGroup(filename2, acl->u2.group2, 1)) continue;
		} else {
			if (!PathMatchesToPattern(filename2, acl->u2.filename2)) continue;
		}
		return 0;
	}
	return -EPERM;
}

static int CheckSingleWritePermission2(const unsigned int operation, const struct path_info *filename, struct obj_info *obj)
{
	int error;
	struct domain_info * const domain = current->domain_info;
	const bool is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	error = CheckSingleWriteACL(operation, filename, obj);
	AuditWriteLog(acltype2keyword(operation), filename, NULL, !error);
	if (error) {
		if (TomoyoVerboseMode()) {
			printk("TOMOYO-%s: Access '%s %s' denied for %s\n", GetMSG(is_enforce), acltype2keyword(operation), filename->name, GetLastName(domain));
		}
		if (is_enforce) error = CheckSupervisor("%s\nallow_%s %s\n", domain->domainname->name, acltype2keyword(operation), filename->name);
		else if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_FILE, domain)) AddSingleWriteACL(operation, GetPattern(filename)->name, domain, NULL, 0);
		if (!is_enforce) error = 0;
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
EXPORT_SYMBOL(CheckFilePerm);

int CheckExecPerm(const struct path_info *filename, struct file *filp)
{
	struct obj_info obj;
	memset(&obj, 0, sizeof(obj));
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
	obj.path1_dentry = filp->f_dentry;
	obj.path1_vfsmnt = filp->f_vfsmnt;
	return CheckFilePerm2(filename, 1, "do_execve", &obj);
}
EXPORT_SYMBOL(CheckExecPerm);

int CheckOpenPermission(struct dentry *dentry, struct vfsmount *mnt, const int flag)
{
	const int acc_mode = ACC_MODE(flag);
	int error = -ENOMEM;
	struct path_info *buf;
	const bool is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
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
EXPORT_SYMBOL(CheckOpenPermission);

int CheckSingleWritePermission(const unsigned int operation, struct dentry *dentry, struct vfsmount *mnt)
{
	int error = -ENOMEM;
	struct path_info *buf;
	const bool is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
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
EXPORT_SYMBOL(CheckSingleWritePermission);

int CheckReWritePermission(struct file *filp)
{
	int error = -ENOMEM;
	const bool is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
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
EXPORT_SYMBOL(CheckReWritePermission);

int CheckDoubleWritePermission(const unsigned int operation, struct dentry *dentry1, struct vfsmount *mnt1, struct dentry *dentry2, struct vfsmount *mnt2)
{
	int error = -ENOMEM;
	struct path_info *buf1, *buf2;
	struct domain_info * const domain = current->domain_info;
	const bool is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_FILE);
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_FILE)) return 0;
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
		error = CheckDoubleWriteACL(operation, buf1, buf2, &obj);
		AuditWriteLog(acltype2keyword(operation), buf1, buf2, !error);
		if (error) {
			if (TomoyoVerboseMode()) {
				printk("TOMOYO-%s: Access '%s %s %s' denied for %s\n", GetMSG(is_enforce), acltype2keyword(operation), buf1->name, buf2->name, GetLastName(domain));
			}
			if (is_enforce) error = CheckSupervisor("%s\nallow_%s %s %s\n", domain->domainname->name, acltype2keyword(operation), buf1->name, buf2->name);
			else if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_FILE, domain)) AddDoubleWriteACL(operation, GetPattern(buf1)->name, GetPattern(buf2)->name, domain, NULL, 0);
		}
	}
	ccs_free(buf1);
	ccs_free(buf2);
	if (!is_enforce) error = 0;
	return error;
}
EXPORT_SYMBOL(CheckDoubleWritePermission);

/***** TOMOYO Linux end. *****/
