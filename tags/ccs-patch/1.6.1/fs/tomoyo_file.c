/*
 * fs/tomoyo_file.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.1   2008/05/10
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#include <linux/binfmts.h>
#define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])

/* Structure for "allow_read" keyword. */
struct globally_readable_file_entry {
	struct list1_head list;
	const struct path_info *filename;
	bool is_deleted;
};

/* Structure for "file_pattern" keyword. */
struct pattern_entry {
	struct list1_head list;
	const struct path_info *pattern;
	bool is_deleted;
};

/* Structure for "deny_rewrite" keyword. */
struct no_rewrite_entry {
	struct list1_head list;
	const struct path_info *pattern;
	bool is_deleted;
};

/* Keyword array for single path operations. */
static const char *sp_keyword[MAX_SINGLE_PATH_OPERATION] = {
	[TYPE_READ_WRITE_ACL] = "read/write",
	[TYPE_EXECUTE_ACL]    = "execute",
	[TYPE_READ_ACL]       = "read",
	[TYPE_WRITE_ACL]      = "write",
	[TYPE_CREATE_ACL]     = "create",
	[TYPE_UNLINK_ACL]     = "unlink",
	[TYPE_MKDIR_ACL]      = "mkdir",
	[TYPE_RMDIR_ACL]      = "rmdir",
	[TYPE_MKFIFO_ACL]     = "mkfifo",
	[TYPE_MKSOCK_ACL]     = "mksock",
	[TYPE_MKBLOCK_ACL]    = "mkblock",
	[TYPE_MKCHAR_ACL]     = "mkchar",
	[TYPE_TRUNCATE_ACL]   = "truncate",
	[TYPE_SYMLINK_ACL]    = "symlink",
	[TYPE_REWRITE_ACL]    = "rewrite",
};

/* Keyword array for double path operations. */
static const char *dp_keyword[MAX_DOUBLE_PATH_OPERATION] = {
	[TYPE_LINK_ACL]    = "link",
	[TYPE_RENAME_ACL]  = "rename",
};

/**
 * ccs_sp2keyword - Get the name of single path operation.
 *
 * @operation: Type of operation.
 *
 * Returns the name of single path operation.
 */
const char *ccs_sp2keyword(const u8 operation)
{
	return (operation < MAX_SINGLE_PATH_OPERATION)
		? sp_keyword[operation] : NULL;
}

/**
 * ccs_dp2keyword - Get the name of double path operation.
 *
 * @operation: Type of operation.
 *
 * Returns the name of double path operation.
 */
const char *ccs_dp2keyword(const u8 operation)
{
	return (operation < MAX_DOUBLE_PATH_OPERATION)
		? dp_keyword[operation] : NULL;
}

/**
 * strendswith - Check whether the token ends with the given token.
 *
 * @name: The token to check.
 * @tail: The token to find.
 *
 * Returns true if @name ends with @tail, false otherwise.
 */
static bool strendswith(const char *name, const char *tail)
{
	int len;
	if (!name || !tail)
		return false;
	len = strlen(name) - strlen(tail);
	return len >= 0 && !strcmp(name + len, tail);
}

/**
 * ccs_get_path - Get realpath.
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount".
 *
 * Returns pointer to "struct path_info" on success, NULL otherwise.
 */
static struct path_info *ccs_get_path(struct dentry *dentry,
				      struct vfsmount *mnt)
{
	int error;
	struct path_info_with_data *buf = ccs_alloc(sizeof(*buf));
	if (!buf)
		return NULL;
	/* Preserve one byte for appending "/". */
	error = ccs_realpath_from_dentry2(dentry, mnt, buf->body,
					  sizeof(buf->body) - 2);
	if (!error) {
		buf->head.name = buf->body;
		ccs_fill_path_info(&buf->head);
		return &buf->head;
	}
	ccs_free(buf);
	return NULL;
}

static int update_double_path_acl(const u8 type, const char *filename1,
				  const char *filename2,
				  struct domain_info * const domain,
				  const struct condition_list *condition,
				  const bool is_delete);
static int update_single_path_acl(const u8 type, const char *filename,
				  struct domain_info * const domain,
				  const struct condition_list *condition,
				  const bool is_delete);

/**
 * audit_file_log - Audit file related request log.
 *
 * @operation:  The name of operation.
 * @filename1:  First pathname.
 * @filename2:  Second pathname. May be NULL.
 * @is_granted: True if this is a granted log.
 * @profile:    Profile number used.
 * @mode:       Access control mode used.
 * @bprm:       Pointer to "struct linux_binprm". May be NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int audit_file_log(const char *operation,
			  const struct path_info *filename1,
			  const struct path_info *filename2,
			  const bool is_granted, const u8 profile,
			  const u8 mode, struct linux_binprm *bprm)
{
	char *buf;
	int len;
	int len2;
	if (ccs_can_save_audit_log(is_granted) < 0)
		return -ENOMEM;
	len = strlen(operation) + filename1->total_len + 16;
	if (filename2)
		len += filename2->total_len;
	buf = ccs_init_audit_log(&len, profile, mode, bprm);
	if (!buf)
		return -ENOMEM;
	len2 = strlen(buf);
	snprintf(buf + len2, len - len2 - 1, "allow_%s %s %s\n",
		 operation, filename1->name, filename2 ? filename2->name : "");
	return ccs_write_audit_log(buf, is_granted);
}

/* The list for "struct globally_readable_file_entry". */
static LIST1_HEAD(globally_readable_list);

/**
 * update_globally_readable_entry - Update "struct globally_readable_file_entry" list.
 *
 * @filename:  Filename unconditionally permitted to open() for reading.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_globally_readable_entry(const char *filename,
					  const bool is_delete)
{
	struct globally_readable_file_entry *new_entry;
	struct globally_readable_file_entry *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_filename;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(filename, 1, -1, -1, __func__))
		return -EINVAL; /* No patterns allowed. */
	saved_filename = ccs_save_name(filename);
	if (!saved_filename)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &globally_readable_list, list) {
		if (ptr->filename != saved_filename)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		goto out;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	new_entry = ccs_alloc_element(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	new_entry->filename = saved_filename;
	list1_add_tail_mb(&new_entry->list, &globally_readable_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * is_globally_readable_file - Check if the file is unconditionnaly permitted to be open()ed for reading.
 *
 * @filename: The filename to check.
 *
 * Returns true if any domain can open @filename for reading, false otherwise.
 */
static bool is_globally_readable_file(const struct path_info *filename)
{
	struct globally_readable_file_entry *ptr;
	list1_for_each_entry(ptr, &globally_readable_list, list) {
		if (!ptr->is_deleted && !ccs_pathcmp(filename, ptr->filename))
			return true;
	}
	return false;
}

/**
 * ccs_write_globally_readable_policy - Write "struct globally_readable_file_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_globally_readable_policy(char *data, const bool is_delete)
{
	return update_globally_readable_entry(data, is_delete);
}

/**
 * ccs_read_globally_readable_policy - Read "struct globally_readable_file_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_globally_readable_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &globally_readable_list) {
		struct globally_readable_file_entry *ptr;
		ptr = list1_entry(pos, struct globally_readable_file_entry,
				  list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_ALLOW_READ "%s\n",
				   ptr->filename->name))
			goto out;
	}
	return true;
 out:
	return false;
}

/* The list for "struct path_group_entry". */
static LIST1_HEAD(path_group_list);

/**
 * update_path_group_entry - Update "struct path_group_entry" list.
 *
 * @group_name:  The name of pathname group.
 * @member_name: The name of group's member.
 * @is_delete:   True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_path_group_entry(const char *group_name,
				   const char *member_name,
				   const bool is_delete)
{
	static DEFINE_MUTEX(lock);
	struct path_group_entry *new_group;
	struct path_group_entry *group;
	struct path_group_member *new_member;
	struct path_group_member *member;
	const struct path_info *saved_group_name;
	const struct path_info *saved_member_name;
	int error = -ENOMEM;
	bool found = false;
	if (!ccs_is_correct_path(group_name, 0, 0, 0, __func__) ||
	    !group_name[0] ||
	    !ccs_is_correct_path(member_name, 0, 0, 0, __func__) ||
	    !member_name[0])
		return -EINVAL;
	saved_group_name = ccs_save_name(group_name);
	saved_member_name = ccs_save_name(member_name);
	if (!saved_group_name || !saved_member_name)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(group, &path_group_list, list) {
		if (saved_group_name != group->group_name)
			continue;
		list1_for_each_entry(member, &group->path_group_member_list,
				     list) {
			if (member->member_name != saved_member_name)
				continue;
			member->is_deleted = is_delete;
			error = 0;
			goto out;
		}
		found = true;
		break;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if (!found) {
		new_group = ccs_alloc_element(sizeof(*new_group));
		if (!new_group)
			goto out;
		INIT_LIST1_HEAD(&new_group->path_group_member_list);
		new_group->group_name = saved_group_name;
		list1_add_tail_mb(&new_group->list, &path_group_list);
		group = new_group;
	}
	new_member = ccs_alloc_element(sizeof(*new_member));
	if (!new_member)
		goto out;
	new_member->member_name = saved_member_name;
	list1_add_tail_mb(&new_member->list, &group->path_group_member_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * ccs_write_path_group_policy - Write "struct path_group_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, nagative value otherwise.
 */
int ccs_write_path_group_policy(char *data, const bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return update_path_group_entry(data, cp, is_delete);
}

/**
 * find_or_assign_new_path_group - Create pathname group.
 *
 * @group_name: The name of pathname group.
 *
 * Returns pointer to "struct path_group_entry" if found, NULL otherwise.
 */
static struct path_group_entry *
find_or_assign_new_path_group(const char *group_name)
{
	u8 i;
	struct path_group_entry *group;
	for (i = 0; i <= 1; i++) {
		list1_for_each_entry(group, &path_group_list, list) {
			if (!strcmp(group_name, group->group_name->name))
				return group;
		}
		if (!i) {
			update_path_group_entry(group_name, "/", false);
			update_path_group_entry(group_name, "/", true);
		}
	}
	return NULL;
}

/**
 * path_matches_group - Check whether the given pathname matches members of the given pathname group.
 *
 * @pathname:        The name of pathname.
 * @group:           Pointer to "struct path_group_entry".
 * @may_use_pattern: True if wild card is permitted.
 *
 * Returns true if @pathname matches pathnames in @group, false otherwise.
 */
static bool path_matches_group(const struct path_info *pathname,
			       const struct path_group_entry *group,
			       const bool may_use_pattern)
{
	struct path_group_member *member;
	list1_for_each_entry(member, &group->path_group_member_list, list) {
		if (member->is_deleted)
			continue;
		if (!member->member_name->is_patterned) {
			if (!ccs_pathcmp(pathname, member->member_name))
				return true;
		} else if (may_use_pattern) {
			if (ccs_path_matches_pattern(pathname,
						     member->member_name))
				return true;
		}
	}
	return false;
}

/**
 * ccs_read_path_group_policy - Read "struct path_group_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_path_group_policy(struct ccs_io_buffer *head)
{
	struct list1_head *gpos;
	struct list1_head *mpos;
	list1_for_each_cookie(gpos, head->read_var1, &path_group_list) {
		struct path_group_entry *group;
		group = list1_entry(gpos, struct path_group_entry, list);
		list1_for_each_cookie(mpos, head->read_var2,
				      &group->path_group_member_list) {
			struct path_group_member *member;
			member = list1_entry(mpos, struct path_group_member,
					     list);
			if (member->is_deleted)
				continue;
			if (!ccs_io_printf(head, KEYWORD_PATH_GROUP "%s %s\n",
					   group->group_name->name,
					   member->member_name->name))
				goto out;
		}
	}
	return true;
 out:
	return false;
}

/* The list for "struct pattern_entry". */
static LIST1_HEAD(pattern_list);

/**
 * update_file_pattern_entry - Update "struct pattern_entry" list.
 *
 * @pattern:   Pathname pattern.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_file_pattern_entry(const char *pattern, const bool is_delete)
{
	struct pattern_entry *new_entry;
	struct pattern_entry *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_pattern;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(pattern, 0, 1, 0, __func__))
		return -EINVAL;
	saved_pattern = ccs_save_name(pattern);
	if (!saved_pattern)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &pattern_list, list) {
		if (saved_pattern != ptr->pattern)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		goto out;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	new_entry = ccs_alloc_element(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	new_entry->pattern = saved_pattern;
	list1_add_tail_mb(&new_entry->list, &pattern_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * get_file_pattern - Get patterned pathname.
 *
 * @filename: The filename to find patterned pathname.
 *
 * Returns pointer to pathname pattern if matched, @filename otherwise.
 */
static const struct path_info *
get_file_pattern(const struct path_info *filename)
{
	struct pattern_entry *ptr;
	const struct path_info *pattern = NULL;
	list1_for_each_entry(ptr, &pattern_list, list) {
		if (ptr->is_deleted)
			continue;
		if (!ccs_path_matches_pattern(filename, ptr->pattern))
			continue;
		pattern = ptr->pattern;
		if (strendswith(pattern->name, "/\\*")) {
			/* Do nothing. Try to find the better match. */
		} else {
			/* This would be the better match. Use this. */
			break;
		}
	}
	if (pattern)
		filename = pattern;
	return filename;
}

/**
 * ccs_write_pattern_policy - Write "struct pattern_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_pattern_policy(char *data, const bool is_delete)
{
	return update_file_pattern_entry(data, is_delete);
}

/**
 * ccs_read_file_pattern - Read "struct pattern_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_file_pattern(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &pattern_list) {
		struct pattern_entry *ptr;
		ptr = list1_entry(pos, struct pattern_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_FILE_PATTERN "%s\n",
				   ptr->pattern->name))
			goto out;
	}
	return true;
 out:
	return false;
}

/* The list for "struct no_rewrite_entry". */
static LIST1_HEAD(no_rewrite_list);

/**
 * update_no_rewrite_entry - Update "struct no_rewrite_entry" list.
 *
 * @pattern:   Pathname pattern that are not rewritable by default.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_no_rewrite_entry(const char *pattern, const bool is_delete)
{
	struct no_rewrite_entry *new_entry, *ptr;
	static DEFINE_MUTEX(lock);
	const struct path_info *saved_pattern;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(pattern, 0, 0, 0, __func__))
		return -EINVAL;
	saved_pattern = ccs_save_name(pattern);
	if (!saved_pattern)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &no_rewrite_list, list) {
		if (ptr->pattern != saved_pattern)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		goto out;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	new_entry = ccs_alloc_element(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	new_entry->pattern = saved_pattern;
	list1_add_tail_mb(&new_entry->list, &no_rewrite_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * is_no_rewrite_file - Check if the given pathname is not permitted to be rewrited.
 *
 * @filename: Filename to check.
 *
 * Returns true if @filename is specified by "deny_rewrite" directive,
 * false otherwise.
 */
static bool is_no_rewrite_file(const struct path_info *filename)
{
	struct no_rewrite_entry *ptr;
	list1_for_each_entry(ptr, &no_rewrite_list, list) {
		if (ptr->is_deleted)
			continue;
		if (!ccs_path_matches_pattern(filename, ptr->pattern))
			continue;
		return true;
	}
	return false;
}

/**
 * ccs_write_no_rewrite_policy - Write "struct no_rewrite_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_no_rewrite_policy(char *data, const bool is_delete)
{
	return update_no_rewrite_entry(data, is_delete);
}

/**
 * ccs_read_no_rewrite_policy - Read "struct no_rewrite_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_no_rewrite_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &no_rewrite_list) {
		struct no_rewrite_entry *ptr;
		ptr = list1_entry(pos, struct no_rewrite_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_DENY_REWRITE "%s\n",
				   ptr->pattern->name))
			goto out;
	}
	return true;
 out:
	return false;
}

/**
 * update_file_acl - Update file's read/write/execute ACL.
 *
 * @filename:  Filename.
 * @perm:      Permission (between 1 to 7).
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * This is legacy support interface for older policy syntax.
 * Current policy syntax uses "allow_read/write" instead of "6",
 * "allow_read" instead of "4", "allow_write" instead of "2",
 * "allow_execute" instead of "1".
 */
static int update_file_acl(const char *filename, u8 perm,
			   struct domain_info * const domain,
			   const struct condition_list *condition,
			   const bool is_delete)
{
	if (perm > 7 || !perm) {
		printk(KERN_DEBUG "%s: Invalid permission '%d %s'\n",
		       __func__, perm, filename);
		return -EINVAL;
	}
	if (filename[0] != '@' && strendswith(filename, "/"))
		/*
		 * Only 'allow_mkdir' and 'allow_rmdir' are valid for
		 * directory permissions.
		 */
		return 0;
	if (perm & 4)
		update_single_path_acl(TYPE_READ_ACL, filename, domain,
				       condition, is_delete);
	if (perm & 2)
		update_single_path_acl(TYPE_WRITE_ACL, filename, domain,
				       condition, is_delete);
	if (perm & 1)
		update_single_path_acl(TYPE_EXECUTE_ACL, filename, domain,
				       condition, is_delete);
	return 0;
}

/**
 * check_single_path_acl2 - Check permission for single path operation.
 *
 * @filename:        Filename to check.
 * @perm:            Permission.
 * @obj:             Pointer to "struct obj_info".
 * @may_use_pattern: True if patterned ACL is permitted.
 *
 * Returns 0 on success, -EPERM otherwise.
 */
static int check_single_path_acl2(const struct path_info *filename,
				  const u16 perm, struct obj_info *obj,
				  const bool may_use_pattern)
{
	const struct domain_info *domain = current->domain_info;
	struct acl_info *ptr;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct single_path_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_SINGLE_PATH_ACL)
			continue;
		acl = container_of(ptr, struct single_path_acl_record, head);
		if (!(acl->perm & perm) || !ccs_check_condition(ptr, obj))
			continue;
		if (acl->u_is_group) {
			if (!path_matches_group(filename, acl->u.group,
						may_use_pattern))
				continue;
		} else if (may_use_pattern || !acl->u.filename->is_patterned) {
			if (!ccs_path_matches_pattern(filename,
						      acl->u.filename))
				continue;
		} else {
			continue;
		}
		ccs_update_condition(ptr);
		return 0;
	}
	return -EPERM;
}

/**
 * check_file_acl - Check permission for opening files.
 *
 * @filename:  Filename to check.
 * @operation: Mode ("read" or "write" or "read/write" or "execute").
 * @obj:       Pointer to "struct obj_info".
 *
 * Returns 0 on success, -EPERM otherwise.
 */
static int check_file_acl(const struct path_info *filename, const u8 operation,
			  struct obj_info *obj)
{
	u16 perm = 0;
	if (!ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE))
		return 0;
	if (operation == 6)
		perm = 1 << TYPE_READ_WRITE_ACL;
	else if (operation == 4)
		perm = 1 << TYPE_READ_ACL;
	else if (operation == 2)
		perm = 1 << TYPE_WRITE_ACL;
	else if (operation == 1)
		perm = 1 << TYPE_EXECUTE_ACL;
	else
		BUG();
	return check_single_path_acl2(filename, perm, obj, operation != 1);
}

/**
 * check_file_perm2 - Check permission for opening files.
 *
 * @filename:  Filename to check.
 * @perm:      Mode ("read" or "write" or "read/write" or "execute").
 * @operation: Operation name passed used for verbose mode.
 * @obj:       Pointer to "struct obj_info". May be NULL.
 * @profile:   Profile number passed to audit logs.
 * @mode:      Access control mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int check_file_perm2(const struct path_info *filename, const u8 perm,
			    const char *operation, struct obj_info *obj,
			    const u8 profile, const u8 mode)
{
	struct domain_info * const domain = current->domain_info;
	const bool is_enforce = (mode == 3);
	const char *msg = "<unknown>";
	int error = 0;
	if (!filename)
		return 0;
	error = check_file_acl(filename, perm, obj);
	if (error && perm == 4 &&
	    (domain->flags & DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_READ) == 0 &&
	    is_globally_readable_file(filename))
		error = 0;
	if (perm == 6)
		msg = ccs_sp2keyword(TYPE_READ_WRITE_ACL);
	else if (perm == 4)
		msg = ccs_sp2keyword(TYPE_READ_ACL);
	else if (perm == 2)
		msg = ccs_sp2keyword(TYPE_WRITE_ACL);
	else if (perm == 1)
		msg = ccs_sp2keyword(TYPE_EXECUTE_ACL);
	else
		BUG();
	audit_file_log(msg, filename, NULL, !error, profile, mode,
		       obj ? obj->bprm : NULL);
	if (!error)
		return 0;
	if (ccs_verbose_mode())
		printk(KERN_WARNING "TOMOYO-%s: Access '%s(%s) %s' denied "
		       "for %s\n", ccs_get_msg(is_enforce), msg, operation,
		       filename->name, ccs_get_last_name(domain));
	if (is_enforce)
		return ccs_check_supervisor("%s\nallow_%s %s\n",
					    domain->domainname->name,
					    msg, filename->name);
	if (mode == 1 && ccs_check_domain_quota(domain)) {
		/* Don't use patterns for execute permission. */
		const struct path_info *patterned_file = (perm != 1) ?
			get_file_pattern(filename) : filename;
		update_file_acl(patterned_file->name, perm,
				domain, NULL, false);
	}
	return 0;
}

/**
 * update_execute_handler - Update "struct execute_handler_record" list.
 *
 * @type:      Type of execute handler.
 * @filename:  Pathname to the execute handler.
 * @domain:    Pointer to "struct domain_info".
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_execute_handler(const u8 type, const char *filename,
				  struct domain_info * const domain,
				  const bool is_delete)
{
	const struct path_info *saved_filename;
	struct acl_info *ptr;
	struct execute_handler_record *acl;
	int error = -ENOMEM;
	if (!domain)
		return -EINVAL;
	if (!ccs_is_correct_path(filename, 1, -1, -1, __func__))
		return -EINVAL;
	saved_filename = ccs_save_name(filename);
	if (!saved_filename)
		return -ENOMEM;
	mutex_lock(&domain_acl_lock);
	if (is_delete)
		goto delete;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != type)
			continue;
		/* Condition not supported. */
		acl = container_of(ptr, struct execute_handler_record, head);
		if (acl->handler != saved_filename)
			continue;
		/* Only one entry can exist in a domain. */
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			if (ptr->type == type)
				ptr->type |= ACL_DELETED;
		}
		error = ccs_add_domain_acl(NULL, &acl->head);
		goto out;
	}
	/* Not found. Append it to the tail. */
	acl = ccs_alloc_acl_element(type, NULL);
	if (!acl)
		goto out;
	acl->handler = saved_filename;
	/* Only one entry can exist in a domain. */
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ptr->type == type)
			ptr->type |= ACL_DELETED;
	}
	error = ccs_add_domain_acl(domain, &acl->head);
	goto out;
 delete:
	error = -ENOENT;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type2(ptr) != type)
			continue;
		/* Condition not supported. */
		acl = container_of(ptr, struct execute_handler_record, head);
		if (acl->handler != saved_filename)
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
 out:
	mutex_unlock(&domain_acl_lock);
	return error;
}

/**
 * ccs_write_file_policy - Update file related list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_file_policy(char *data, struct domain_info *domain,
			  const struct condition_list *condition,
			  const bool is_delete)
{
	char *filename = strchr(data, ' ');
	char *filename2;
	unsigned int perm;
	u8 type;
	if (!filename)
		return -EINVAL;
	*filename++ = '\0';
	if (sscanf(data, "%u", &perm) == 1)
		return update_file_acl(filename, (u8) perm, domain, condition,
				       is_delete);
	if (strncmp(data, "allow_", 6)) {
		u8 type;
		if (!strcmp(data, KEYWORD_EXECUTE_HANDLER))
			type = TYPE_EXECUTE_HANDLER;
		else if (!strcmp(data, KEYWORD_DENIED_EXECUTE_HANDLER))
			type = TYPE_DENIED_EXECUTE_HANDLER;
		else
			goto out;
		return update_execute_handler(type, filename,
					      domain, is_delete);
	}
	data += 6;
	for (type = 0; type < MAX_SINGLE_PATH_OPERATION; type++) {
		if (strcmp(data, sp_keyword[type]))
			continue;
		return update_single_path_acl(type, filename, domain, condition,
					      is_delete);
	}
	filename2 = strchr(filename, ' ');
	if (!filename2)
		goto out;
	*filename2++ = '\0';
	for (type = 0; type < MAX_DOUBLE_PATH_OPERATION; type++) {
		if (strcmp(data, dp_keyword[type]))
			continue;
		return update_double_path_acl(type, filename, filename2, domain,
					      condition, is_delete);
	}
 out:
	return -EINVAL;
}

/**
 * update_single_path_acl - Update "struct single_path_acl_record" list.
 *
 * @type:      Type of operation.
 * @filename:  Filename.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_single_path_acl(const u8 type, const char *filename,
				  struct domain_info * const domain,
				  const struct condition_list *condition,
				  const bool is_delete)
{
	static const u16 rw_mask = (1 << TYPE_READ_ACL) | (1 << TYPE_WRITE_ACL);
	const struct path_info *saved_filename;
	struct acl_info *ptr;
	struct single_path_acl_record *acl;
	int error = -ENOMEM;
	bool is_group = false;
	const u16 perm = 1 << type;
	if (!domain)
		return -EINVAL;
	if (!ccs_is_correct_path(filename, 0, 0, 0, __func__))
		return -EINVAL;
	if (filename[0] == '@') {
		/*
		 * This cast is OK because I don't dereference
		 * in this function.
		 */
		saved_filename = (struct path_info *)
			find_or_assign_new_path_group(filename + 1);
		is_group = true;
	} else {
		saved_filename = ccs_save_name(filename);
	}
	if (!saved_filename)
		return -ENOMEM;
	mutex_lock(&domain_acl_lock);
	if (is_delete)
		goto delete;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != TYPE_SINGLE_PATH_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct single_path_acl_record, head);
		if (acl->u.filename != saved_filename)
			continue;
		/* Special case. Clear all bits if marked as deleted. */
		if (ptr->type & ACL_DELETED)
			acl->perm = 0;
		acl->perm |= perm;
		if ((acl->perm & rw_mask) == rw_mask)
			acl->perm |= 1 << TYPE_READ_WRITE_ACL;
		else if (acl->perm & (1 << TYPE_READ_WRITE_ACL))
			acl->perm |= rw_mask;
		error = ccs_add_domain_acl(NULL, ptr);
		goto out;
	}
	/* Not found. Append it to the tail. */
	acl = ccs_alloc_acl_element(TYPE_SINGLE_PATH_ACL, condition);
	if (!acl)
		goto out;
	acl->perm = perm;
	acl->u_is_group = is_group;
	acl->u.filename = saved_filename;
	error = ccs_add_domain_acl(domain, &acl->head);
	goto out;
 delete:
	error = -ENOENT;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type2(ptr) != TYPE_SINGLE_PATH_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct single_path_acl_record, head);
		if (acl->u.filename != saved_filename)
			continue;
		acl->perm &= ~perm;
		if ((acl->perm & rw_mask) != rw_mask)
			acl->perm &= ~(1 << TYPE_READ_WRITE_ACL);
		else if (!(acl->perm & (1 << TYPE_READ_WRITE_ACL)))
			acl->perm &= ~rw_mask;
		error = ccs_del_domain_acl(acl->perm ? NULL : ptr);
		break;
	}
 out:
	mutex_unlock(&domain_acl_lock);
	return error;
}

/**
 * update_double_path_acl - Update "struct double_path_acl_record" list.
 *
 * @type:      Type of operation.
 * @filename1: First filename.
 * @filename2: Second filename.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_double_path_acl(const u8 type, const char *filename1,
				  const char *filename2,
				  struct domain_info * const domain,
				  const struct condition_list *condition,
				  const bool is_delete)
{
	const struct path_info *saved_filename1;
	const struct path_info *saved_filename2;
	struct acl_info *ptr;
	struct double_path_acl_record *acl;
	int error = -ENOMEM;
	bool is_group1 = false;
	bool is_group2 = false;
	const u8 perm = 1 << type;
	if (!domain)
		return -EINVAL;
	if (!ccs_is_correct_path(filename1, 0, 0, 0, __func__) ||
	    !ccs_is_correct_path(filename2, 0, 0, 0, __func__))
		return -EINVAL;
	if (filename1[0] == '@') {
		/*
		 * This cast is OK because I don't dereference
		 * in this function.
		 */
		saved_filename1 = (struct path_info *)
			find_or_assign_new_path_group(filename1 + 1);
		is_group1 = true;
	} else {
		saved_filename1 = ccs_save_name(filename1);
	}
	if (filename2[0] == '@') {
		/*
		 * This cast is OK because I don't dereference
		 * in this function.
		 */
		saved_filename2 = (struct path_info *)
			find_or_assign_new_path_group(filename2 + 1);
		is_group2 = true;
	} else {
		saved_filename2 = ccs_save_name(filename2);
	}
	if (!saved_filename1 || !saved_filename2)
		return -ENOMEM;
	mutex_lock(&domain_acl_lock);
	if (is_delete)
		goto delete;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != TYPE_DOUBLE_PATH_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct double_path_acl_record, head);
		if (acl->u1.filename1 != saved_filename1 ||
		    acl->u2.filename2 != saved_filename2)
			continue;
		/* Special case. Clear all bits if marked as deleted. */
		if (ptr->type & ACL_DELETED)
			acl->perm = 0;
		acl->perm |= perm;
		error = ccs_add_domain_acl(NULL, ptr);
		goto out;
	}
	/* Not found. Append it to the tail. */
	acl = ccs_alloc_acl_element(TYPE_DOUBLE_PATH_ACL, condition);
	if (!acl)
		goto out;
	acl->perm = perm;
	acl->u1_is_group = is_group1;
	acl->u2_is_group = is_group2;
	acl->u1.filename1 = saved_filename1;
	acl->u2.filename2 = saved_filename2;
	error = ccs_add_domain_acl(domain, &acl->head);
	goto out;
 delete:
	error = -ENOENT;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type2(ptr) != TYPE_DOUBLE_PATH_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct double_path_acl_record, head);
		if (acl->u1.filename1 != saved_filename1 ||
		    acl->u2.filename2 != saved_filename2)
			continue;
		acl->perm &= ~perm;
		error = ccs_del_domain_acl(acl->perm ? NULL : ptr);
		break;
	}
 out:
	mutex_unlock(&domain_acl_lock);
	return error;
}

/**
 * check_single_path_acl - Check permission for single path operation.
 *
 * @type:     Type of operation.
 * @filename: Filename to check.
 * @obj:      Pointer to "struct obj_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int check_single_path_acl(const u8 type,
				 const struct path_info *filename,
				 struct obj_info *obj)
{
	if (!ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE))
		return 0;
	return check_single_path_acl2(filename, 1 << type, obj, 1);
}

/**
 * check_double_path_acl - Check permission for double path operation.
 *
 * @type:      Type of operation.
 * @filename1: First filename to check.
 * @filename2: Second filename to check.
 * @obj:       Pointer to "struct obj_info".
 *
 * Returns 0 on success, -EPERM otherwise.
 */
static int check_double_path_acl(const u8 type,
				 const struct path_info *filename1,
				 const struct path_info *filename2,
				 struct obj_info *obj)
{
	const struct domain_info *domain = current->domain_info;
	struct acl_info *ptr;
	const u8 perm = 1 << type;
	if (!ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE))
		return 0;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct double_path_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_DOUBLE_PATH_ACL)
			continue;
		acl = container_of(ptr, struct double_path_acl_record, head);
		if (!(acl->perm & perm) || !ccs_check_condition(ptr, obj))
			continue;
		if (acl->u1_is_group) {
			if (!path_matches_group(filename1, acl->u1.group1,
						true))
				continue;
		} else {
			if (!ccs_path_matches_pattern(filename1,
						      acl->u1.filename1))
				continue;
		}
		if (acl->u2_is_group) {
			if (!path_matches_group(filename2,
						acl->u2.group2, true))
				continue;
		} else {
			if (!ccs_path_matches_pattern(filename2,
						      acl->u2.filename2))
				continue;
		}
		ccs_update_condition(ptr);
		return 0;
	}
	return -EPERM;
}

/**
 * check_single_path_permission2 - Check permission for single path operation.
 *
 * @operation: Type of operation.
 * @filename:  Filename to check.
 * @obj:       Pointer to "struct obj_info".
 * @profile:   Profile number passed to audit logs.
 * @mode:      Access control mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int check_single_path_permission2(u8 operation,
					 const struct path_info *filename,
					 struct obj_info *obj,
					 const u8 profile, const u8 mode)
{
	const char *msg;
	int error;
	struct domain_info * const domain = current->domain_info;
	const bool is_enforce = (mode == 3);
	if (!mode)
		return 0;
 next:
	error = check_single_path_acl(operation, filename, obj);
	msg = ccs_sp2keyword(operation);
	audit_file_log(msg, filename, NULL, !error, profile, mode, NULL);
	if (!error)
		goto ok;
	if (ccs_verbose_mode())
		printk(KERN_WARNING "TOMOYO-%s: Access '%s %s' denied for %s\n",
		       ccs_get_msg(is_enforce), msg, filename->name,
		       ccs_get_last_name(domain));
	if (is_enforce)
		error = ccs_check_supervisor("%s\nallow_%s %s\n",
					     domain->domainname->name,
					     msg, filename->name);
	if (mode == 1 && ccs_check_domain_quota(domain))
		update_single_path_acl(operation,
				       get_file_pattern(filename)->name,
				       domain, NULL, false);
	if (!is_enforce)
		error = 0;
 ok:
	/*
	 * Since "allow_truncate" doesn't imply "allow_rewrite" permission,
	 * we need to check "allow_rewrite" permission if the filename is
	 * specified by "deny_rewrite" keyword.
	 */
	if (!error && operation == TYPE_TRUNCATE_ACL &&
	    is_no_rewrite_file(filename)) {
		operation = TYPE_REWRITE_ACL;
		goto next;
	}
	return error;
}

/**
 * ccs_check_file_perm - Check permission for sysctl()'s "read" and "write".
 *
 * @filename:  Filename to check.
 * @perm:      Mode ("read" or "write" or "read/write").
 * @operation: Always "sysctl".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_file_perm(const char *filename, const u8 perm,
			const char *operation)
{
	struct path_info name;
	const u8 profile = current->domain_info->profile;
	const u8 mode = ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE);
	if (!mode)
		return 0;
	name.name = filename;
	ccs_fill_path_info(&name);
	return check_file_perm2(&name, perm, operation, NULL, profile, mode);
}

/**
 * ccs_check_exec_perm - Check permission for "execute".
 *
 * @filename: Check permission for "execute".
 * @bprm:     Pointer to "struct linux_binprm".
 * @tmp:      Buffer for temporal use.
 *
 * Returns 0 on success, negativevalue otherwise.
 */
int ccs_check_exec_perm(const struct path_info *filename,
			struct linux_binprm *bprm, struct ccs_page_buffer *tmp)
{
	struct obj_info obj;
	const u8 profile = current->domain_info->profile;
	const u8 mode = ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE);
	if (!mode)
		return 0;
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = bprm->file->f_dentry;
	obj.path1_vfsmnt = bprm->file->f_vfsmnt;
	obj.bprm = bprm;
	obj.tmp = tmp;
	return check_file_perm2(filename, 1, "do_execve", &obj, profile, mode);
}

/**
 * ccs_check_open_permission - Check permission for "read" and "write".
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount".
 * @flag:   Flags for open().
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_open_permission(struct dentry *dentry, struct vfsmount *mnt,
			      const int flag)
{
	struct obj_info obj;
	const u8 acc_mode = ACC_MODE(flag);
	int error = -ENOMEM;
	struct path_info *buf;
	const u8 profile = current->domain_info->profile;
	const u8 mode = ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE);
	const bool is_enforce = (mode == 3);
	if (!mode)
		return 0;
	if (acc_mode == 0)
		return 0;
	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode))
		/*
		 * I don't check directories here because mkdir() and rmdir()
		 * don't call me.
		 */
		return 0;
	buf = ccs_get_path(dentry, mnt);
	if (!buf)
		goto out;
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = dentry;
	obj.path1_vfsmnt = mnt;
	error = 0;
	/*
	 * If the filename is specified by "deny_rewrite" keyword,
	 * we need to check "allow_rewrite" permission when the filename is not
	 * opened for append mode or the filename is truncated at open time.
	 */
	if ((acc_mode & MAY_WRITE) &&
	    ((flag & O_TRUNC) || !(flag & O_APPEND))) {
		if (is_no_rewrite_file(buf))
			error = check_single_path_permission2(TYPE_REWRITE_ACL,
							      buf, &obj,
							      profile, mode);
	}
	if (!error)
		error = check_file_perm2(buf, acc_mode, "open", &obj, profile,
					 mode);
	if (!error && (flag & O_TRUNC))
		error = check_single_path_permission2(TYPE_TRUNCATE_ACL, buf,
						      &obj, profile, mode);
 out:
	ccs_free(buf);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_check_1path_perm - Check permission for "create", "unlink", "mkdir", "rmdir", "mkfifo", "mksock", "mkblock", "mkchar", "truncate" and "symlink".
 *
 * @operation: Type of operation.
 * @dentry:    Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_1path_perm(const u8 operation, struct dentry *dentry,
			 struct vfsmount *mnt)
{
	struct obj_info obj;
	int error = -ENOMEM;
	struct path_info *buf;
	const u8 profile = current->domain_info->profile;
	const u8 mode = ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE);
	const bool is_enforce = (mode == 3);
	if (!mode)
		return 0;
	buf = ccs_get_path(dentry, mnt);
	if (!buf)
		goto out;
	switch (operation) {
	case TYPE_MKDIR_ACL:
	case TYPE_RMDIR_ACL:
		if (!buf->is_dir) {
			/* ccs_get_path() preserves space for appending "/." */
			strcat((char *) buf->name, "/");
			ccs_fill_path_info(buf);
		}
	}
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = dentry;
	obj.path1_vfsmnt = mnt;
	error = check_single_path_permission2(operation, buf, &obj, profile,
					      mode);
 out:
	ccs_free(buf);
	if (!is_enforce)
		error = 0;
	return error;
}
EXPORT_SYMBOL(ccs_check_1path_perm); /* for net/unix/af_unix.c  */

/**
 * ccs_check_rewrite_permission - Check permission for "rewrite".
 *
 * @filp: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_rewrite_permission(struct file *filp)
{
	struct obj_info obj;
	int error = -ENOMEM;
	const u8 profile = current->domain_info->profile;
	const u8 mode = ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE);
	const bool is_enforce = (mode == 3);
	struct path_info *buf = ccs_get_path(filp->f_dentry, filp->f_vfsmnt);
	if (!buf)
		goto out;
	if (!is_no_rewrite_file(buf)) {
		error = 0;
		goto out;
	}
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = filp->f_dentry;
	obj.path1_vfsmnt = filp->f_vfsmnt;
	error = check_single_path_permission2(TYPE_REWRITE_ACL, buf, &obj,
					      profile, mode);
 out:
	ccs_free(buf);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_check_2path_perm - Check permission for "rename" and "link".
 *
 * @operation: Type of operation.
 * @dentry1:   Pointer to "struct dentry".
 * @mnt1:      Pointer to "struct vfsmount".
 * @dentry2:   Pointer to "struct dentry".
 * @mnt2:      Pointer to "struct vfsmount".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_2path_perm(const u8 operation,
				     struct dentry *dentry1,
				     struct vfsmount *mnt1,
				     struct dentry *dentry2,
				     struct vfsmount *mnt2)
{
	int error = -ENOMEM;
	struct path_info *buf1, *buf2;
	struct domain_info * const domain = current->domain_info;
	const u8 profile = current->domain_info->profile;
	const u8 mode = ccs_check_flags(CCS_TOMOYO_MAC_FOR_FILE);
	const bool is_enforce = (mode == 3);
	const char *msg;
	struct obj_info obj;
	if (!mode)
		return 0;
	buf1 = ccs_get_path(dentry1, mnt1);
	buf2 = ccs_get_path(dentry2, mnt2);
	if (!buf1 || !buf2)
		goto out;
	if (operation == TYPE_RENAME_ACL) {
		/* TYPE_LINK_ACL can't reach here for directory. */
		if (dentry1->d_inode && S_ISDIR(dentry1->d_inode->i_mode)) {
			/* ccs_get_path() preserves space for appending "/." */
			if (!buf1->is_dir) {
				strcat((char *) buf1->name, "/");
				ccs_fill_path_info(buf1);
			}
			if (!buf2->is_dir) {
				strcat((char *) buf2->name, "/");
				ccs_fill_path_info(buf2);
			}
		}
	}
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = dentry1;
	obj.path1_vfsmnt = mnt1;
	obj.path2_dentry = dentry2;
	obj.path2_vfsmnt = mnt2;
	error = check_double_path_acl(operation, buf1, buf2, &obj);
	msg = ccs_dp2keyword(operation);
	audit_file_log(msg, buf1, buf2, !error, profile, mode, NULL);
	if (!error)
		goto out;
	if (ccs_verbose_mode())
		printk(KERN_WARNING "TOMOYO-%s: Access '%s %s %s' "
		       "denied for %s\n", ccs_get_msg(is_enforce),
		       msg, buf1->name, buf2->name, ccs_get_last_name(domain));
	if (is_enforce)
		error = ccs_check_supervisor("%s\nallow_%s %s %s\n",
					     domain->domainname->name,
					     msg, buf1->name, buf2->name);
	else if (mode == 1 && ccs_check_domain_quota(domain))
		update_double_path_acl(operation,
				       get_file_pattern(buf1)->name,
				       get_file_pattern(buf2)->name,
				       domain, NULL, false);
 out:
	ccs_free(buf1);
	ccs_free(buf2);
	if (!is_enforce)
		error = 0;
	return error;
}
