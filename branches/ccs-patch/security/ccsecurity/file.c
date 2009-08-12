/*
 * security/ccsecurity/file.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"
#define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])

/* Keyword array for single path operations. */
static const char *ccs_sp_keyword[CCS_MAX_SINGLE_PATH_OPERATION] = {
	[CCS_TYPE_READ_WRITE_ACL] = "read/write",
	[CCS_TYPE_EXECUTE_ACL]    = "execute",
	[CCS_TYPE_READ_ACL]       = "read",
	[CCS_TYPE_WRITE_ACL]      = "write",
	[CCS_TYPE_CREATE_ACL]     = "create",
	[CCS_TYPE_UNLINK_ACL]     = "unlink",
	[CCS_TYPE_MKDIR_ACL]      = "mkdir",
	[CCS_TYPE_RMDIR_ACL]      = "rmdir",
	[CCS_TYPE_MKFIFO_ACL]     = "mkfifo",
	[CCS_TYPE_MKSOCK_ACL]     = "mksock",
	[CCS_TYPE_TRUNCATE_ACL]   = "truncate",
	[CCS_TYPE_SYMLINK_ACL]    = "symlink",
	[CCS_TYPE_REWRITE_ACL]    = "rewrite",
};

/* Keyword array for mkdev operations. */
static const char *ccs_mkdev_keyword[CCS_MAX_MKDEV_OPERATION] = {
	[CCS_TYPE_MKBLOCK_ACL]    = "mkblock",
	[CCS_TYPE_MKCHAR_ACL]     = "mkchar",
};

/* Keyword array for double path operations. */
static const char *ccs_dp_keyword[CCS_MAX_DOUBLE_PATH_OPERATION] = {
	[CCS_TYPE_LINK_ACL]    = "link",
	[CCS_TYPE_RENAME_ACL]  = "rename",
};

static const char *ccs_path_number_keyword[CCS_MAX_PATH_NUMBER_OPERATION] = {
	[CCS_TYPE_IOCTL] = "ioctl",
	[CCS_TYPE_CHMOD] = "chmod",
	[CCS_TYPE_CHOWN] = "chown",
	[CCS_TYPE_CHGRP] = "chgrp",
};

/**
 * ccs_path_matches_group - Check whether the given pathname matches members of the given pathname group.
 *
 * @pathname:        The name of pathname.
 * @group:           Pointer to "struct ccs_path_group".
 * @may_use_pattern: True if wild card is permitted.
 *
 * Returns true if @pathname matches pathnames in @group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_path_matches_group(const struct ccs_path_info *pathname,
				   const struct ccs_path_group *group,
				   const bool may_use_pattern)
{
	struct ccs_path_group_member *member;
	bool matched = false;
	ccs_check_read_lock();
	list_for_each_entry_rcu(member, &group->path_group_member_list, list) {
		if (member->is_deleted)
			continue;
		if (!member->member_name->is_patterned) {
			if (ccs_pathcmp(pathname, member->member_name))
				continue;
		} else if (may_use_pattern) {
			if (!ccs_path_matches_pattern(pathname,
						      member->member_name))
				continue;
		} else
			continue;
		matched = true;
		break;
	}
	return matched;
}

void ccs_put_name_union(struct ccs_name_union *ptr)
{
	if (!ptr)
		return;
	if (ptr->is_group)
		ccs_put_path_group(ptr->group);
	else
		ccs_put_name(ptr->filename);
}

void ccs_put_number_union(struct ccs_number_union *ptr)
{
	if (ptr && ptr->is_group)
		ccs_put_number_group(ptr->group);
}

bool ccs_compare_number_union(const unsigned long value,
			      const struct ccs_number_union *ptr)
{
	if (ptr->is_group)
		return ccs_number_matches_group(value, value, ptr->group);
	return value >= ptr->values[0] && value <= ptr->values[1];
}

bool ccs_compare_name_union(const struct ccs_path_info *name,
			    const struct ccs_name_union *ptr)
{
	if (ptr->is_group)
		return ccs_path_matches_group(name, ptr->group, 1);
	return ccs_path_matches_pattern(name, ptr->filename);
}

static bool ccs_compare_name_union_pattern(const struct ccs_path_info *name,
					   const struct ccs_name_union *ptr,
					   const bool may_use_pattern)
{
	if (ptr->is_group)
		return ccs_path_matches_group(name, ptr->group,
					      may_use_pattern);
	if (may_use_pattern || !ptr->filename->is_patterned)
		return ccs_path_matches_pattern(name, ptr->filename);
	return false;
}

/**
 * ccs_sp2keyword - Get the name of single path operation.
 *
 * @operation: Type of operation.
 *
 * Returns the name of single path operation.
 */
const char *ccs_sp2keyword(const u8 operation)
{
	return (operation < CCS_MAX_SINGLE_PATH_OPERATION)
		? ccs_sp_keyword[operation] : NULL;
}

/**
 * ccs_mkdev2keyword - Get the name of mkdev operation.
 *
 * @operation: Type of operation.
 *
 * Returns the name of mkdev operation.
 */
const char *ccs_mkdev2keyword(const u8 operation)
{
	return (operation < CCS_MAX_MKDEV_OPERATION)
		? ccs_mkdev_keyword[operation] : NULL;
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
	return (operation < CCS_MAX_DOUBLE_PATH_OPERATION)
		? ccs_dp_keyword[operation] : NULL;
}

const char *ccs_path_number2keyword(const u8 operation)
{
	return (operation < CCS_MAX_PATH_NUMBER_OPERATION)
		? ccs_path_number_keyword[operation] : NULL;
}

/**
 * ccs_strendswith - Check whether the token ends with the given token.
 *
 * @name: The token to check.
 * @tail: The token to find.
 *
 * Returns true if @name ends with @tail, false otherwise.
 */
static bool ccs_strendswith(const char *name, const char *tail)
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
 * @buf:    Pointer to "struct ccs_path_info".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount".
 *
 * Returns true success, false otherwise.
 */
static bool ccs_get_path(struct ccs_path_info *buf, struct dentry *dentry,
			 struct vfsmount *mnt)
{
	buf->name = ccs_realpath_from_dentry(dentry, mnt);
	if (buf->name) {
		ccs_fill_path_info(buf);
		return true;
	}
	return false;
}

static int ccs_update_single_path_acl(const u8 type, const char *filename,
				      struct ccs_domain_info * const domain,
				      struct ccs_condition *condition,
				      const bool is_delete);

/**
 * ccs_audit_single_path_log - Audit single path request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @filename:   Pathname.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_single_path_log(struct ccs_request_info *r,
				     const char *operation,
				     const char *filename,
				     const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "TOMOYO-%s: Access '%s %s' denied "
		       "for %s\n", ccs_get_msg(r->mode == 3), operation,
		       filename, ccs_get_last_name(r->domain));
	return ccs_write_audit_log(is_granted, r, "allow_%s %s\n", operation,
				   filename);
}

/**
 * ccs_audit_double_path_log - Audit double path request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @filename1:  First pathname.
 * @filename2:  Second pathname.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_double_path_log(struct ccs_request_info *r,
				     const char *operation,
				     const char *filename1,
				     const char *filename2,
				     const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "TOMOYO-%s: Access '%s %s %s' "
		       "denied for %s\n", ccs_get_msg(r->mode == 3),
		       operation, filename1, filename2,
		       ccs_get_last_name(r->domain));
	return ccs_write_audit_log(is_granted, r, "allow_%s %s %s\n",
				   operation, filename1, filename2);
}

/**
 * ccs_audit_mkdev_log - Audit mkdev request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @filename:   First pathname.
 * @major:      Device major number.
 * @minor:      Device minor number.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_mkdev_log(struct ccs_request_info *r,
			       const char *operation, const char *filename,
			       const unsigned int major,
			       const unsigned int minor, const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "TOMOYO-%s: Access '%s %s %u %u' denied "
		       "for %s\n", ccs_get_msg(r->mode == 3), operation,
		       filename, major, minor, ccs_get_last_name(r->domain));
	return ccs_write_audit_log(is_granted, r, "allow_%s %s %u %u\n",
				   operation, filename, major, minor);
}

/**
 * ccs_audit_path_number_log - Audit ioctl/chmod/chown/chgrp related request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @type:       Type of operation.
 * @filename:   Pathname.
 * @value:      Value.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_path_number_log(struct ccs_request_info *r,
				     const char *operation,
				     const char *filename, const char *value,
				     const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "TOMOYO-%s: Access '%s %s %s' denied "
		       "for %s\n", ccs_get_msg(r->mode == 3), operation,
		       filename, value, ccs_get_last_name(r->domain));
	return ccs_write_audit_log(is_granted, r, "allow_%s %s %s\n",
				   operation, filename, value);
}

/* The list for "struct ccs_globally_readable_file_entry". */
LIST_HEAD(ccs_globally_readable_list);

/**
 * ccs_update_globally_readable_entry - Update "struct ccs_globally_readable_file_entry" list.
 *
 * @filename:  Filename unconditionally permitted to open() for reading.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_globally_readable_entry(const char *filename,
					      const bool is_delete)
{
	struct ccs_globally_readable_file_entry *entry = NULL;
	struct ccs_globally_readable_file_entry *ptr;
	const struct ccs_path_info *saved_filename;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(filename, 1, 0, -1))
		return -EINVAL;
	saved_filename = ccs_get_name(filename);
	if (!saved_filename)
		return -ENOMEM;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_globally_readable_list, list) {
		if (ptr->filename != saved_filename)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->filename = saved_filename;
		saved_filename = NULL;
		list_add_tail_rcu(&entry->list, &ccs_globally_readable_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(saved_filename);
	kfree(entry);
	return error;
}

/**
 * ccs_is_globally_readable_file - Check if the file is unconditionnaly permitted to be open()ed for reading.
 *
 * @filename: The filename to check.
 *
 * Returns true if any domain can open @filename for reading, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_is_globally_readable_file(const struct ccs_path_info *filename)
{
	struct ccs_globally_readable_file_entry *ptr;
	bool found = false;
	ccs_check_read_lock();
	list_for_each_entry_rcu(ptr, &ccs_globally_readable_list, list) {
		if (ptr->is_deleted ||
		    !ccs_path_matches_pattern(filename, ptr->filename))
			continue;
		found = true;
		break;
	}
	return found;
}

/**
 * ccs_write_globally_readable_policy - Write "struct ccs_globally_readable_file_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_globally_readable_policy(char *data, const bool is_delete)
{
	return ccs_update_globally_readable_entry(data, is_delete);
}

/**
 * ccs_read_globally_readable_policy - Read "struct ccs_globally_readable_file_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_globally_readable_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	ccs_check_read_lock();
	list_for_each_cookie(pos, head->read_var2,
			     &ccs_globally_readable_list) {
		struct ccs_globally_readable_file_entry *ptr;
		ptr = list_entry(pos, struct ccs_globally_readable_file_entry,
				 list);
		if (ptr->is_deleted)
			continue;
		done = ccs_io_printf(head, CCS_KEYWORD_ALLOW_READ "%s\n",
				     ptr->filename->name);
		if (!done)
			break;
	}
	return done;
}

/* The list for "struct ccs_path_group". */
LIST_HEAD(ccs_path_group_list);

/**
 * ccs_get_path_group - Allocate memory for "struct ccs_path_group".
 *
 * @group_name: The name of pathname group.
 *
 * Returns pointer to "struct ccs_path_group" on success, NULL otherwise.
 */
struct ccs_path_group *ccs_get_path_group(const char *group_name)
{
	struct ccs_path_group *entry = NULL;
	struct ccs_path_group *group;
	const struct ccs_path_info *saved_group_name;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(group_name, 0, 0, 0) ||
	    !group_name[0])
		return NULL;
	saved_group_name = ccs_get_name(group_name);
	if (!saved_group_name)
		return NULL;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(group, &ccs_path_group_list, list) {
		if (saved_group_name != group->group_name)
			continue;
		atomic_inc(&group->users);
		error = 0;
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		INIT_LIST_HEAD(&entry->path_group_member_list);
		entry->group_name = saved_group_name;
		saved_group_name = NULL;
		atomic_set(&entry->users, 1);
		list_add_tail_rcu(&entry->list, &ccs_path_group_list);
		group = entry;
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(saved_group_name);
	kfree(entry);
	return !error ? group : NULL;
}

/**
 * ccs_update_path_group - Update "struct ccs_path_group" list.
 *
 * @group_name:  The name of pathname group.
 * @member_name: The name of group's member.
 * @is_delete:   True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_path_group(const char *group_name,
				 const char *member_name, const bool is_delete)
{
	struct ccs_path_group *group;
	struct ccs_path_group_member *entry = NULL;
	struct ccs_path_group_member *member;
	const struct ccs_path_info *saved_member_name;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(member_name, 0, 0, 0) ||
	    !member_name[0])
		return -EINVAL;
	group = ccs_get_path_group(group_name);
	if (!group)
		return -ENOMEM;
	saved_member_name = ccs_get_name(member_name);
	if (!saved_member_name)
		goto out;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(member, &group->path_group_member_list, list) {
		if (member->member_name != saved_member_name)
			continue;
		member->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->member_name = saved_member_name;
		saved_member_name = NULL;
		list_add_tail_rcu(&entry->list, &group->path_group_member_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(saved_member_name);
	ccs_put_path_group(group);
	kfree(entry);
	return error;
}

/**
 * ccs_write_path_group_policy - Write "struct ccs_path_group" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, nagative value otherwise.
 */
int ccs_write_path_group_policy(char *data, const bool is_delete)
{
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	return ccs_update_path_group(w[0], w[1], is_delete);
}

/**
 * ccs_read_path_group_policy - Read "struct ccs_path_group" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_path_group_policy(struct ccs_io_buffer *head)
{
	struct list_head *gpos;
	struct list_head *mpos;
	bool done = true;
	ccs_check_read_lock();
	list_for_each_cookie(gpos, head->read_var1, &ccs_path_group_list) {
		struct ccs_path_group *group;
		group = list_entry(gpos, struct ccs_path_group, list);
		list_for_each_cookie(mpos, head->read_var2,
				     &group->path_group_member_list) {
			struct ccs_path_group_member *member;
			member = list_entry(mpos, struct ccs_path_group_member,
					     list);
			if (member->is_deleted)
				continue;
			done = ccs_io_printf(head, CCS_KEYWORD_PATH_GROUP
					     "%s %s\n",
					     group->group_name->name,
					     member->member_name->name);
			if (!done)
				break;
		}
	}
	return done;
}

/* The list for "struct ccs_pattern_entry". */
LIST_HEAD(ccs_pattern_list);

/**
 * ccs_update_file_pattern_entry - Update "struct ccs_pattern_entry" list.
 *
 * @pattern:   Pathname pattern.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_file_pattern_entry(const char *pattern,
					 const bool is_delete)
{
	struct ccs_pattern_entry *entry = NULL;
	struct ccs_pattern_entry *ptr;
	const struct ccs_path_info *saved_pattern;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(pattern, 0, 1, 0))
		return -EINVAL;
	saved_pattern = ccs_get_name(pattern);
	if (!saved_pattern)
		return -ENOMEM;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_pattern_list, list) {
		if (saved_pattern != ptr->pattern)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->pattern = saved_pattern;
		saved_pattern = NULL;
		list_add_tail_rcu(&entry->list, &ccs_pattern_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(saved_pattern);
	kfree(entry);
	return error;
}

/**
 * ccs_file_pattern - Get patterned pathname.
 *
 * @filename: Pointer to "struct ccs_path_info".
 *
 * Returns pointer to patterned pathname.
 *
 * Caller holds ccs_read_lock().
 */
const char *ccs_file_pattern(const struct ccs_path_info *filename)
{
	struct ccs_pattern_entry *ptr;
	const struct ccs_path_info *pattern = NULL;
	ccs_check_read_lock();
	list_for_each_entry_rcu(ptr, &ccs_pattern_list, list) {
		if (ptr->is_deleted)
			continue;
		if (!ccs_path_matches_pattern(filename, ptr->pattern))
			continue;
		pattern = ptr->pattern;
		if (ccs_strendswith(pattern->name, "/\\*")) {
			/* Do nothing. Try to find the better match. */
		} else {
			/* This would be the better match. Use this. */
			break;
		}
	}
	return pattern ? pattern->name : filename->name;
}

/**
 * ccs_write_pattern_policy - Write "struct ccs_pattern_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_pattern_policy(char *data, const bool is_delete)
{
	return ccs_update_file_pattern_entry(data, is_delete);
}

/**
 * ccs_read_file_pattern - Read "struct ccs_pattern_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_file_pattern(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	ccs_check_read_lock();
	list_for_each_cookie(pos, head->read_var2, &ccs_pattern_list) {
		struct ccs_pattern_entry *ptr;
		ptr = list_entry(pos, struct ccs_pattern_entry, list);
		if (ptr->is_deleted)
			continue;
		done = ccs_io_printf(head, CCS_KEYWORD_FILE_PATTERN "%s\n",
				     ptr->pattern->name);
		if (!done)
			break;
	}
	return done;
}

/* The list for "struct ccs_no_rewrite_entry". */
LIST_HEAD(ccs_no_rewrite_list);

/**
 * ccs_update_no_rewrite_entry - Update "struct ccs_no_rewrite_entry" list.
 *
 * @pattern:   Pathname pattern that are not rewritable by default.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_no_rewrite_entry(const char *pattern,
				       const bool is_delete)
{
	struct ccs_no_rewrite_entry *entry = NULL;
	struct ccs_no_rewrite_entry *ptr;
	const struct ccs_path_info *saved_pattern;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(pattern, 0, 0, 0))
		return -EINVAL;
	saved_pattern = ccs_get_name(pattern);
	if (!saved_pattern)
		return -ENOMEM;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_no_rewrite_list, list) {
		if (ptr->pattern != saved_pattern)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->pattern = saved_pattern;
		saved_pattern = NULL;
		list_add_tail_rcu(&entry->list, &ccs_no_rewrite_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(saved_pattern);
	kfree(entry);
	return error;
}

/**
 * ccs_is_no_rewrite_file - Check if the given pathname is not permitted to be rewrited.
 *
 * @filename: Filename to check.
 *
 * Returns true if @filename is specified by "deny_rewrite" directive,
 * false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_is_no_rewrite_file(const struct ccs_path_info *filename)
{
	struct ccs_no_rewrite_entry *ptr;
	bool matched = false;
	ccs_check_read_lock();
	list_for_each_entry_rcu(ptr, &ccs_no_rewrite_list, list) {
		if (ptr->is_deleted)
			continue;
		if (!ccs_path_matches_pattern(filename, ptr->pattern))
			continue;
		matched = true;
		break;
	}
	return matched;
}

/**
 * ccs_write_no_rewrite_policy - Write "struct ccs_no_rewrite_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_no_rewrite_policy(char *data, const bool is_delete)
{
	return ccs_update_no_rewrite_entry(data, is_delete);
}

/**
 * ccs_read_no_rewrite_policy - Read "struct ccs_no_rewrite_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_no_rewrite_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	bool done = true;
	ccs_check_read_lock();
	list_for_each_cookie(pos, head->read_var2,
			      &ccs_no_rewrite_list) {
		struct ccs_no_rewrite_entry *ptr;
		ptr = list_entry(pos, struct ccs_no_rewrite_entry, list);
		if (ptr->is_deleted)
			continue;
		done = ccs_io_printf(head, CCS_KEYWORD_DENY_REWRITE "%s\n",
				     ptr->pattern->name);
		if (!done)
			break;
	}
	return done;
}

/**
 * ccs_update_file_acl - Update file's read/write/execute ACL.
 *
 * @perm:      Permission (between 1 to 7).
 * @filename:  Filename.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * This is legacy support interface for older policy syntax.
 * Current policy syntax uses "allow_read/write" instead of "6",
 * "allow_read" instead of "4", "allow_write" instead of "2",
 * "allow_execute" instead of "1".
 */
static int ccs_update_file_acl(u8 perm, const char *filename,
			       struct ccs_domain_info * const domain,
			       struct ccs_condition *condition,
			       const bool is_delete)
{
	if (perm > 7 || !perm) {
		printk(KERN_DEBUG "Invalid permission '%d %s'\n",
		       perm, filename);
		return -EINVAL;
	}
	if (filename[0] != '@' && ccs_strendswith(filename, "/"))
		/*
		 * Only 'allow_mkdir' and 'allow_rmdir' are valid for
		 * directory permissions.
		 */
		return 0;
	if (perm & 4)
		ccs_update_single_path_acl(CCS_TYPE_READ_ACL, filename, domain,
					   condition, is_delete);
	if (perm & 2)
		ccs_update_single_path_acl(CCS_TYPE_WRITE_ACL, filename,
					   domain, condition, is_delete);
	if (perm & 1)
		ccs_update_single_path_acl(CCS_TYPE_EXECUTE_ACL, filename,
					   domain, condition, is_delete);
	return 0;
}

/**
 * ccs_check_single_path_acl - Check permission for single path operation.
 *
 * @r:               Pointer to "struct ccs_request_info".
 * @filename:        Filename to check.
 * @perm:            Permission.
 * @may_use_pattern: True if patterned ACL is permitted.
 *
 * Returns 0 on success, -EPERM otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_single_path_acl(struct ccs_request_info *r,
				     const struct ccs_path_info *filename,
				     const u16 perm,
				     const bool may_use_pattern)
{
	struct ccs_domain_info *domain = r->domain;
	struct ccs_acl_info *ptr;
	int error = -EPERM;
	ccs_check_read_lock();
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_single_path_acl_record *acl;
		if (ccs_acl_type2(ptr) != CCS_TYPE_SINGLE_PATH_ACL)
			continue;
		acl = container_of(ptr, struct ccs_single_path_acl_record,
				   head);
		if (!(acl->perm & perm) || !ccs_check_condition(r, ptr) ||
		    !ccs_compare_name_union_pattern(filename, &acl->name,
						    may_use_pattern))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	return error;
}

/**
 * ccs_check_mkdev_acl - Check permission for mkdev operation.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @filename: Filename to check.
 * @perm:     Permission.
 * @major:    Device major number.
 * @minor:    Device minor number.
 *
 * Returns 0 on success, -EPERM otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_mkdev_acl(struct ccs_request_info *r,
			       const struct ccs_path_info *filename,
			       const u16 perm, const unsigned int major,
			       const unsigned int minor)
{
	struct ccs_domain_info *domain = r->domain;
	struct ccs_acl_info *ptr;
	int error = -EPERM;
	ccs_check_read_lock();
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_mkdev_acl_record *acl;
		if (ccs_acl_type2(ptr) != CCS_TYPE_MKDEV_ACL)
			continue;
		acl = container_of(ptr, struct ccs_mkdev_acl_record, head);
		if (!ccs_compare_number_union(major, &acl->major))
				continue;
		if (!ccs_compare_number_union(minor, &acl->minor))
			continue;
		if (!(acl->perm & perm) || !ccs_check_condition(r, ptr))
			continue;
		if (!ccs_compare_name_union(filename, &acl->name))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	return error;
}

/**
 * ccs_check_file_perm - Check permission for opening files.
 *
 * @r:         Pointer to "strct ccs_request_info".
 * @filename:  Filename to check.
 * @mode:      Mode ("read" or "write" or "read/write" or "execute").
 *
 * Returns 0 on success, 1 on retry, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_file_perm(struct ccs_request_info *r,
			       const struct ccs_path_info *filename,
			       const u8 mode)
{
	const bool is_enforce = (r->mode == 3);
	const char *msg = "<unknown>";
	int error = 0;
	u16 perm = 0;
	ccs_check_read_lock();
	if (!filename)
		return 0;
	if (mode == 6) {
		msg = ccs_sp2keyword(CCS_TYPE_READ_WRITE_ACL);
		perm = 1 << CCS_TYPE_READ_WRITE_ACL;
	} else if (mode == 4) {
		msg = ccs_sp2keyword(CCS_TYPE_READ_ACL);
		perm = 1 << CCS_TYPE_READ_ACL;
	} else if (mode == 2) {
		msg = ccs_sp2keyword(CCS_TYPE_WRITE_ACL);
		perm = 1 << CCS_TYPE_WRITE_ACL;
	} else if (mode == 1) {
		msg = ccs_sp2keyword(CCS_TYPE_EXECUTE_ACL);
		perm = 1 << CCS_TYPE_EXECUTE_ACL;
	} else
		BUG();
 retry:
	error = ccs_check_single_path_acl(r, filename, perm, mode != 1);
	if (error && mode == 4 && !r->domain->ignore_global_allow_read
	    && ccs_is_globally_readable_file(filename))
		error = 0;
	ccs_audit_single_path_log(r, msg, filename->name, !error);
	if (error)
		error = ccs_check_supervisor(r, "allow_%s %s\n", msg,
					     mode == 1 ? filename->name :
					     ccs_file_pattern(filename));
	if (error == 1 && !r->ee)
		goto retry;
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_update_execute_handler - Update "struct ccs_execute_handler_record" list.
 *
 * @type:      Type of execute handler.
 * @filename:  Pathname to the execute handler.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_execute_handler(const u8 type, const char *filename,
				      struct ccs_domain_info * const domain,
				      const bool is_delete)
{
	const struct ccs_path_info *saved_filename;
	struct ccs_acl_info *ptr;
	struct ccs_execute_handler_record *entry = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!domain)
		return -EINVAL;
	if (!ccs_is_correct_path(filename, 1, -1, -1))
		return -EINVAL;
	saved_filename = ccs_get_name(filename);
	if (!saved_filename)
		return -ENOMEM;
	if (is_delete)
		goto delete;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_execute_handler_record *acl;
		if (ccs_acl_type1(ptr) != type)
			continue;
		/* Condition not supported. */
		acl = container_of(ptr, struct ccs_execute_handler_record,
				   head);
		if (acl->handler != saved_filename)
			continue;
		/* Only one entry can exist in a domain. */
		list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
			if (ptr->type == type)
				ptr->type |= CCS_ACL_DELETED;
		}
		error = ccs_add_domain_acl(NULL, &acl->head);
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->head.type = type;
		entry->handler = saved_filename;
		saved_filename = NULL;
		/* Only one entry can exist in a domain. */
		list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
			if (ptr->type == type)
				ptr->type |= CCS_ACL_DELETED;
		}
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	goto out;
 delete:
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_execute_handler_record *acl;
		if (ccs_acl_type2(ptr) != type)
			continue;
		/* Condition not supported. */
		acl = container_of(ptr, struct ccs_execute_handler_record,
				   head);
		if (acl->handler != saved_filename)
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(saved_filename);
	kfree(entry);
	return error;
}

/**
 * ccs_update_single_path_acl - Update "struct ccs_single_path_acl_record" list.
 *
 * @type:      Type of operation.
 * @filename:  Filename.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_single_path_acl(const u8 type, const char *filename,
				      struct ccs_domain_info * const domain,
				      struct ccs_condition *condition,
				      const bool is_delete)
{
	static const u16 ccs_rw_mask =
		(1 << CCS_TYPE_READ_ACL) | (1 << CCS_TYPE_WRITE_ACL);
	struct ccs_acl_info *ptr;
	struct ccs_single_path_acl_record e;
	struct ccs_single_path_acl_record *entry = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	const u16 perm = 1 << type;
	memset(&e, 0, sizeof(e));
	e.head.type = CCS_TYPE_SINGLE_PATH_ACL;
	e.head.cond = condition;
	if (!domain)
		return -EINVAL;
	if (!ccs_parse_name_union(filename, &e.name))
		return -EINVAL;
	if (is_delete)
		goto delete;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_single_path_acl_record *acl;
		if (ccs_acl_type1(ptr) != CCS_TYPE_SINGLE_PATH_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_single_path_acl_record,
				   head);
		if (memcmp(&acl->name, &e.name, sizeof(e.name)))
			continue;
		/* Special case. Clear all bits if marked as deleted. */
		if (ptr->type & CCS_ACL_DELETED)
			acl->perm = 0;
		acl->perm |= perm;
		if ((acl->perm & ccs_rw_mask) == ccs_rw_mask)
			acl->perm |= 1 << CCS_TYPE_READ_WRITE_ACL;
		else if (acl->perm & (1 << CCS_TYPE_READ_WRITE_ACL))
			acl->perm |= ccs_rw_mask;
		error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		memmove(entry, &e, sizeof(e));
		memset(&e, 0, sizeof(e));
		entry->perm = perm;
		if (perm == (1 << CCS_TYPE_READ_WRITE_ACL))
			entry->perm |= ccs_rw_mask;
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	goto out;
 delete:
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_single_path_acl_record *acl;
		if (ccs_acl_type2(ptr) != CCS_TYPE_SINGLE_PATH_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_single_path_acl_record,
				   head);
		if (memcmp(&acl->name, &e.name, sizeof(e.name)))
			continue;
		acl->perm &= ~perm;
		if ((acl->perm & ccs_rw_mask) != ccs_rw_mask)
			acl->perm &= ~(1 << CCS_TYPE_READ_WRITE_ACL);
		else if (!(acl->perm & (1 << CCS_TYPE_READ_WRITE_ACL)))
			acl->perm &= ~ccs_rw_mask;
		error = ccs_del_domain_acl(acl->perm ? NULL : ptr);
		break;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name);
	kfree(entry);
	return error;
}

/**
 * ccs_update_mkdev_acl - Update "struct ccs_mkdev_acl_record" list.
 *
 * @type:      Type of operation.
 * @filename:  Filename.
 * @major:     Device major number.
 * @minor:     Device minor number.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_mkdev_acl(const u8 type, const char *filename,
				char *major, char *minor,
				struct ccs_domain_info * const domain,
				struct ccs_condition *condition,
				const bool is_delete)
{
	static const u8 offset = offsetof(struct ccs_mkdev_acl_record,
					  name);
	struct ccs_acl_info *ptr;
	struct ccs_mkdev_acl_record e;
	struct ccs_mkdev_acl_record *entry = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	const u8 perm = 1 << type;
	if (!domain)
		return -EINVAL;
	memset(&e, 0, sizeof(e));
	e.head.type = CCS_TYPE_MKDEV_ACL;
	e.head.cond = condition;
	if (!ccs_parse_name_union(filename, &e.name))
		return -EINVAL;
	if (!ccs_parse_number_union(major, &e.major))
		goto out;
	if (!ccs_parse_number_union(minor, &e.minor))
		goto out;
	if (is_delete)
		goto delete;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_mkdev_acl_record *acl;
		if (ccs_acl_type1(ptr) != CCS_TYPE_MKDEV_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_mkdev_acl_record, head);
		if (memcmp(((char *) acl) + offset, ((char *) &e) + offset,
			   sizeof(e) - offset))
			continue;
		/* Special case. Clear all bits if marked as deleted. */
		if (ptr->type & CCS_ACL_DELETED)
			acl->perm = 0;
		acl->perm |= perm;
		error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		memmove(entry, &e, sizeof(e));
		memset(&e, 0, sizeof(e));
		entry->perm = perm;
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	goto out;
 delete:
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_mkdev_acl_record *acl;
		if (ccs_acl_type2(ptr) != CCS_TYPE_MKDEV_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_mkdev_acl_record, head);
		if (memcmp(((char *) acl) + offset, ((char *) &e) + offset,
			   sizeof(e) - offset))
			continue;
		acl->perm &= ~perm;
		error = ccs_del_domain_acl(acl->perm ? NULL : ptr);
		break;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name);
	ccs_put_number_union(&e.major);
	ccs_put_number_union(&e.minor);
	kfree(entry);
	return error;
}

/**
 * ccs_update_double_path_acl - Update "struct ccs_double_path_acl_record" list.
 *
 * @type:      Type of operation.
 * @filename1: First filename.
 * @filename2: Second filename.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_double_path_acl(const u8 type, const char *filename1,
				      const char *filename2,
				      struct ccs_domain_info * const domain,
				      struct ccs_condition *condition,
				      const bool is_delete)
{
	struct ccs_acl_info *ptr;
	struct ccs_double_path_acl_record e;
	struct ccs_double_path_acl_record *entry = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	const u8 perm = 1 << type;
	memset(&e, 0, sizeof(e));
	e.head.type = CCS_TYPE_DOUBLE_PATH_ACL;
	e.head.cond = condition;
	if (!domain)
		return -EINVAL;
	if (!ccs_parse_name_union(filename1, &e.name1) ||
	    !ccs_parse_name_union(filename2, &e.name2))
		return -EINVAL;
	if (is_delete)
		goto delete;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_double_path_acl_record *acl;
		if (ccs_acl_type1(ptr) != CCS_TYPE_DOUBLE_PATH_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_double_path_acl_record,
				   head);
		if (memcmp(&acl->name1, &e.name1, sizeof(e.name1)) ||
		    memcmp(&acl->name2, &e.name2, sizeof(e.name2)))
			continue;
		/* Special case. Clear all bits if marked as deleted. */
		if (ptr->type & CCS_ACL_DELETED)
			acl->perm = 0;
		acl->perm |= perm;
		error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		memmove(entry, &e, sizeof(e));
		memset(&e, 0, sizeof(e));
		entry->perm = perm;
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	goto out;
 delete:
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_double_path_acl_record *acl;
		if (ccs_acl_type2(ptr) != CCS_TYPE_DOUBLE_PATH_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_double_path_acl_record,
				   head);
		if (memcmp(&acl->name1, &e.name1, sizeof(e.name1)) ||
		    memcmp(&acl->name2, &e.name2, sizeof(e.name2)))
			continue;
		acl->perm &= ~perm;
		error = ccs_del_domain_acl(acl->perm ? NULL : ptr);
		break;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name1);
	ccs_put_name_union(&e.name2);
	kfree(entry);
	return error;
}

/**
 * ccs_check_double_path_acl - Check permission for double path operation.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @type:      Type of operation.
 * @filename1: First filename to check.
 * @filename2: Second filename to check.
 *
 * Returns 0 on success, -EPERM otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_double_path_acl(struct ccs_request_info *r, const u8 type,
				     const struct ccs_path_info *filename1,
				     const struct ccs_path_info *filename2)
{
	const struct ccs_domain_info *domain = r->domain;
	struct ccs_acl_info *ptr;
	const u8 perm = 1 << type;
	int error = -EPERM;
	ccs_check_read_lock();
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_double_path_acl_record *acl;
		if (ccs_acl_type2(ptr) != CCS_TYPE_DOUBLE_PATH_ACL)
			continue;
		acl = container_of(ptr, struct ccs_double_path_acl_record,
				   head);
		if (!(acl->perm & perm) || !ccs_check_condition(r, ptr) ||
		    !ccs_compare_name_union(filename1, &acl->name1) ||
		    !ccs_compare_name_union(filename2, &acl->name2))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	return error;
}

/**
 * ccs_check_single_path_permission - Check permission for single path operation.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @operation: Type of operation.
 * @filename:  Filename to check.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_single_path_permission(struct ccs_request_info *r,
					    u8 operation,
					    const struct ccs_path_info *
					    filename)
{
	const char *msg;
	int error;
	const bool is_enforce = (r->mode == 3);
	ccs_check_read_lock();
	if (!r->mode)
		return 0;
 retry:
	error = ccs_check_single_path_acl(r, filename, 1 << operation, 1);
	msg = ccs_sp2keyword(operation);
	ccs_audit_single_path_log(r, msg, filename->name, !error);
	if (error)
		error = ccs_check_supervisor(r, "allow_%s %s\n", msg,
					     ccs_file_pattern(filename));
	if (error == 1)
		goto retry;
	if (!is_enforce)
		error = 0;
	/*
	 * Since "allow_truncate" doesn't imply "allow_rewrite" permission,
	 * we need to check "allow_rewrite" permission if the filename is
	 * specified by "deny_rewrite" keyword.
	 */
	if (!error && operation == CCS_TYPE_TRUNCATE_ACL &&
	    ccs_is_no_rewrite_file(filename)) {
		operation = CCS_TYPE_REWRITE_ACL;
		goto retry;
	}
	return error;
}

/**
 * ccs_check_mkdev_permission - Check permission for mkdev operation.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @operation: Type of operation.
 * @filename:  Filename to check.
 * @dev:       Device number.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_mkdev_permission(struct ccs_request_info *r,
				      const u8 operation,
				      const struct ccs_path_info *filename,
				      const unsigned int dev)
{
	int error;
	const char *msg = ccs_sp2keyword(operation);
	const bool is_enforce = (r->mode == 3);
	const unsigned int major = MAJOR(dev);
	const unsigned int minor = MINOR(dev);
	ccs_check_read_lock();
	if (!r->mode)
		return 0;
 retry:
	error = ccs_check_mkdev_acl(r, filename, 1 << operation, major, minor);
	ccs_audit_mkdev_log(r, msg, filename->name, major, minor, !error);
	if (error)
		error = ccs_check_supervisor(r, "allow_%s %s %u %u\n", msg,
					     ccs_file_pattern(filename), major,
					     minor);
	if (error == 1)
		goto retry;
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_check_exec_perm - Check permission for "execute".
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @filename: Check permission for "execute".
 *
 * Returns 0 on success, 1 on retry, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_check_exec_perm(struct ccs_request_info *r,
			const struct ccs_path_info *filename)
{
	ccs_check_read_lock();
	if (!ccs_can_sleep())
		return 0;
	if (!r->mode)
		return 0;
	return ccs_check_file_perm(r, filename, 1);
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
	struct ccs_request_info r;
	struct ccs_obj_info obj;
	const u8 acc_mode = ACC_MODE(flag);
	int error = -ENOMEM;
	struct ccs_path_info buf;
	int idx;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	if (current->in_execve &&
	    !(current->ccs_flags & CCS_CHECK_READ_FOR_OPEN_EXEC))
		return 0;
#endif
	if (!ccs_can_sleep())
		return 0;
	buf.name = NULL;
	idx = ccs_read_lock();
	ccs_init_request_info(&r, current->ccs_flags &
			      CCS_CHECK_READ_FOR_OPEN_EXEC ?
			      ccs_fetch_next_domain() : ccs_current_domain(),
			      CCS_MAC_FOR_FILE);
	if (!r.mode || !mnt) {
		error = 0;
		goto out;
	}
	if (acc_mode == 0) {
		error = 0;
		goto out;
	}
	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)) {
		/*
		 * I don't check directories here because mkdir() and rmdir()
		 * don't call me.
		 */
		error = 0;
		goto out;
	}
	if (!ccs_get_path(&buf, dentry, mnt))
		goto out;
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = dentry;
	obj.path1_vfsmnt = mnt;
	r.obj = &obj;
	error = 0;
	/*
	 * If the filename is specified by "deny_rewrite" keyword,
	 * we need to check "allow_rewrite" permission when the filename is not
	 * opened for append mode or the filename is truncated at open time.
	 */
	if ((acc_mode & MAY_WRITE) && ((flag & O_TRUNC) || !(flag & O_APPEND))
	    && ccs_is_no_rewrite_file(&buf))
		error = ccs_check_single_path_permission(&r,
							 CCS_TYPE_REWRITE_ACL,
							 &buf);
	if (!error)
		error = ccs_check_file_perm(&r, &buf, acc_mode);
	if (!error && (flag & O_TRUNC))
		error = ccs_check_single_path_permission(&r,
							 CCS_TYPE_TRUNCATE_ACL,
							 &buf);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (r.mode != 3)
		error = 0;
	return error;
}

/**
 * ccs_check_1path_perm - Check permission for "create", "unlink", "mkdir", "rmdir", "mkfifo", "mksock", "truncate" and "symlink".
 *
 * @operation: Type of operation.
 * @dentry:    Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount".
 * @target:    Symlink's target if @operation is CCS_TYPE_SYMLINK_ACL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_1path_perm(const u8 operation, struct dentry *dentry,
				struct vfsmount *mnt, const char *target)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj;
	int error = -ENOMEM;
	struct ccs_path_info buf;
	bool is_enforce;
	struct ccs_path_info symlink_target;
	int idx;
	if (!ccs_can_sleep())
		return 0;
	buf.name = NULL;
	symlink_target.name = NULL;
	idx = ccs_read_lock();
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_FILE);
	is_enforce = (r.mode == 3);
	if (!r.mode || !mnt) {
		error = 0;
		goto out;
	}
	if (!ccs_get_path(&buf, dentry, mnt))
		goto out;
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = dentry;
	obj.path1_vfsmnt = mnt;
	r.obj = &obj;
	switch (operation) {
	case CCS_TYPE_MKDIR_ACL:
	case CCS_TYPE_RMDIR_ACL:
		if (!buf.is_dir) {
			/* ccs_get_path() reserves space for appending "/". */
			strcat((char *) buf.name, "/");
			ccs_fill_path_info(&buf);
		}
		break;
	case CCS_TYPE_SYMLINK_ACL:
		symlink_target.name = ccs_encode(target);
		if (!symlink_target.name)
			goto out;
		ccs_fill_path_info(&symlink_target);
		obj.symlink_target = &symlink_target;
		break;
	}
	error = ccs_check_single_path_permission(&r, operation, &buf);
	if (operation == CCS_TYPE_SYMLINK_ACL)
		kfree(symlink_target.name);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_check_mkdev_perm - Check permission for "mkblock" and "mkchar".
 *
 * @operation: Type of operation. (CCS_TYPE_MKCHAR_ACL or CCS_TYPE_MKBLOCK_ACL)
 * @dentry:    Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount".
 * @dev:       Device number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_mkdev_perm(const u8 operation, struct dentry *dentry,
				struct vfsmount *mnt, unsigned int dev)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj;
	int error = -ENOMEM;
	struct ccs_path_info buf;
	bool is_enforce;
	int idx;
	if (!ccs_can_sleep())
		return 0;
	buf.name = NULL;
	idx = ccs_read_lock();
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_FILE);
	is_enforce = (r.mode == 3);
	if (!r.mode || !mnt) {
		error = 0;
		goto out;
	}
	if (!ccs_get_path(&buf, dentry, mnt))
		goto out;
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = dentry;
	obj.path1_vfsmnt = mnt;
	obj.dev = dev;
	r.obj = &obj;
	error = ccs_check_mkdev_permission(&r, operation, &buf, dev);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_check_rewrite_permission - Check permission for "rewrite".
 *
 * @filp: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_rewrite_permission(struct file *filp)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj;
	int error = -ENOMEM;
	bool is_enforce;
	struct ccs_path_info buf;
	int idx;
	if (!ccs_can_sleep())
		return 0;
	buf.name = NULL;
	idx = ccs_read_lock();
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_FILE);
	is_enforce = (r.mode == 3);
	if (!r.mode || !filp->f_vfsmnt) {
		error = 0;
		goto out;
	}
	if (!ccs_get_path(&buf, filp->f_dentry, filp->f_vfsmnt))
		goto out;
	if (!ccs_is_no_rewrite_file(&buf)) {
		error = 0;
		goto out;
	}
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = filp->f_dentry;
	obj.path1_vfsmnt = filp->f_vfsmnt;
	r.obj = &obj;
	error = ccs_check_single_path_permission(&r, CCS_TYPE_REWRITE_ACL,
						 &buf);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_check_2path_perm - Check permission for "rename" and "link".
 *
 * @operation: Type of operation.
 * @dentry1:   Pointer to "struct dentry".
 * @dentry2:   Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_2path_perm(const u8 operation, struct dentry *dentry1,
				struct dentry *dentry2, struct vfsmount *mnt)
{
	struct ccs_request_info r;
	int error = -ENOMEM;
	const char *msg = ccs_dp2keyword(operation);
	struct ccs_path_info buf1;
	struct ccs_path_info buf2;
	bool is_enforce;
	struct ccs_obj_info obj;
	int idx;
	if (!ccs_can_sleep())
		return 0;
	buf1.name = NULL;
	buf2.name = NULL;
	idx = ccs_read_lock();
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_FILE);
	is_enforce = (r.mode == 3);
	if (!r.mode || !mnt) {
		error = 0;
		goto out;
	}
	if (!ccs_get_path(&buf1, dentry1, mnt) ||
	    !ccs_get_path(&buf2, dentry2, mnt))
		goto out;
	if (operation == CCS_TYPE_RENAME_ACL) {
		/* CCS_TYPE_LINK_ACL can't reach here for directory. */
		if (dentry1->d_inode && S_ISDIR(dentry1->d_inode->i_mode)) {
			/* ccs_get_path() reserves space for appending "/". */
			if (!buf1.is_dir) {
				strcat((char *) buf1.name, "/");
				ccs_fill_path_info(&buf1);
			}
			if (!buf2.is_dir) {
				strcat((char *) buf2.name, "/");
				ccs_fill_path_info(&buf2);
			}
		}
	}
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = dentry1;
	obj.path1_vfsmnt = mnt;
	obj.path2_dentry = dentry2;
	obj.path2_vfsmnt = mnt;
	r.obj = &obj;
 retry:
	error = ccs_check_double_path_acl(&r, operation, &buf1, &buf2);
	ccs_audit_double_path_log(&r, msg, buf1.name, buf2.name, !error);
	if (error)
		error = ccs_check_supervisor(&r, "allow_%s %s %s\n", msg,
					     ccs_file_pattern(&buf1),
					     ccs_file_pattern(&buf2));
	if (error == 1)
		goto retry;
 out:
	kfree(buf1.name);
	kfree(buf2.name);
	ccs_read_unlock(idx);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_update_path_number_acl - Update ioctl/chmod/chown/chgrp ACL.
 *
 * @type:      Type of operation.
 * @filename:  Filename.
 * @number:    Number.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_path_number_acl(const u8 type, const char *filename,
				      char *number,
				      struct ccs_domain_info * const domain,
				      struct ccs_condition *condition,
				      const bool is_delete)
{
	static const u8 offset = offsetof(struct ccs_path_number_acl_record,
					  name);
	const u8 perm = 1 << type;
	struct ccs_acl_info *ptr;
	struct ccs_path_number_acl_record e;
	struct ccs_path_number_acl_record *entry = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	memset(&e, 0, sizeof(e));
	e.head.type = CCS_TYPE_PATH_NUMBER_ACL;
	e.head.cond = condition;
	e.perm = perm;
	if (!domain)
		return -EINVAL;
	if (!ccs_parse_name_union(filename, &e.name))
		return -EINVAL;
	if (!ccs_parse_number_union(number, &e.number))
		goto out;
	if (is_delete)
		goto delete;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number_acl_record *acl;
		if (ccs_acl_type1(ptr) != CCS_TYPE_PATH_NUMBER_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_path_number_acl_record,
				   head);
		if (memcmp(((char *) acl) + offset, ((char *) &e) + offset,
			   sizeof(e) - offset))
			continue;
		/* Special case. Clear all bits if marked as deleted. */
		if (ptr->type & CCS_ACL_DELETED)
			acl->perm = 0;
		acl->perm |= perm;
		error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		memmove(entry, &e, sizeof(e));
		memset(&e, 0, sizeof(e));
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	goto out;
 delete:
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number_acl_record *acl;
		if (ccs_acl_type2(ptr) != CCS_TYPE_PATH_NUMBER_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_path_number_acl_record,
				   head);
		if (memcmp(((char *) acl) + offset, ((char *) &e) + offset,
			   sizeof(e) - offset))
			continue;
		acl->perm &= ~perm;
		error = ccs_del_domain_acl(acl->perm ? NULL : ptr);
		break;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name);
	ccs_put_number_union(&e.number);
	kfree(entry);
	return error;
}

/**
 * ccs_check_path_number_acl - Check permission for ioctl/chmod/chown/chgrp operation.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @type:     Operation.
 * @filename: Filename to check.
 * @number:   Number.
 *
 * Returns 0 on success, -EPERM otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_path_number_acl(struct ccs_request_info *r, const u8 type,
				     const struct ccs_path_info *filename,
				     const unsigned long number)
{
	struct ccs_domain_info *domain = r->domain;
	struct ccs_acl_info *ptr;
	const u8 perm = 1 << type;
	int error = -EPERM;
	ccs_check_read_lock();
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number_acl_record *acl;
		if (ccs_acl_type2(ptr) != CCS_TYPE_PATH_NUMBER_ACL)
			continue;
		acl = container_of(ptr, struct ccs_path_number_acl_record,
				   head);
		if (!(acl->perm & perm) || !ccs_check_condition(r, ptr) ||
		    !ccs_compare_number_union(number, &acl->number) ||
		    !ccs_compare_name_union(filename, &acl->name))
			continue;
		r->cond = ptr->cond;
		error = 0;
		break;
	}
	return error;
}

/**
 * ccs_check_path_number_perm - Check permission for ioctl/chmod/chown/chgrp.
 *
 * @r:        Pointer to "strct ccs_request_info".
 * @filename: Filename to check.
 * @numr:     Number.
 *
 * Returns 0 on success, 1 on retry, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_path_number_perm(struct ccs_request_info *r,
				      const u8 type,
				      const struct ccs_path_info *filename,
				      const unsigned long number)
{
	const bool is_enforce = (r->mode == 3);
	char buffer[64];
	int error;
	const char *msg = ccs_path_number2keyword(type);
	ccs_check_read_lock();
	if (!filename)
		return 0;
	ccs_print_ulong(buffer, sizeof(buffer), number,
			type == CCS_TYPE_CHMOD ? CCS_VALUE_TYPE_OCTAL :
			(type == CCS_TYPE_IOCTL ? CCS_VALUE_TYPE_HEXADECIMAL :
			 CCS_VALUE_TYPE_DECIMAL));
 retry:
	error = ccs_check_path_number_acl(r, type, filename, number);
	ccs_audit_path_number_log(r, msg, filename->name, buffer, !error);
	if (!error)
		return 0;
	error = ccs_check_supervisor(r, "allow_%s %s %s\n", msg,
				     ccs_file_pattern(filename), buffer);
	if (error == 1)
		goto retry;
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_check_path_number_permission - Check permission for "ioctl/chmod/chown/chgrp".
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 * @number: Number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_path_number_permission(const u8 type,
					    struct dentry *dentry,
					    struct vfsmount *vfsmnt,
					    unsigned long number)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj;
	int error = -ENOMEM;
	struct ccs_path_info buf;
	int idx;
	if (!ccs_can_sleep() || !vfsmnt || !dentry)
		return 0;
	buf.name = NULL;
	idx = ccs_read_lock();
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_IOCTL); /* */
	if (!r.mode) {
		error = 0;
		goto out;
	}
	if (!ccs_get_path(&buf, dentry, vfsmnt))
		goto out;
	memset(&obj, 0, sizeof(obj));
	obj.path1_dentry = dentry;
	obj.path1_vfsmnt = vfsmnt;
	r.obj = &obj;
	error = ccs_check_path_number_perm(&r, type, &buf, number);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (r.mode != 3)
		error = 0;
	return error;
}

/**
 * ccs_check_ioctl_permission - Check permission for "ioctl".
 *
 * @file: Pointer to "struct file".
 * @cmd:  Ioctl command number.
 * @arg:  Param for @cmd .
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_ioctl_permission(struct file *filp, unsigned int cmd,
			       unsigned long arg)
{
	return ccs_check_path_number_permission(CCS_TYPE_IOCTL,
						filp->f_dentry, filp->f_vfsmnt,
						cmd);
}

/**
 * ccs_chmod_permission - Check permission for "chmod".
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 * @mode:   Mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_chmod_permission(struct dentry *dentry, struct vfsmount *vfsmnt,
			 mode_t mode)
{
	if (mode == (mode_t) -1)
		return 0;
	return ccs_check_path_number_permission(CCS_TYPE_CHMOD, dentry, vfsmnt,
						mode);
}

/**
 * ccs_chown_permission - Check permission for "chown/chgrp".
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 * @user:   User ID.
 * @group:  Group ID.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_chown_permission(struct dentry *dentry, struct vfsmount *vfsmnt,
			 uid_t user, gid_t group)
{
	int error = 0;
	if (user != (uid_t) -1)
		error = ccs_check_path_number_permission(CCS_TYPE_CHOWN, dentry,
							 vfsmnt, user);
	if (!error && group != (gid_t) -1)
		error = ccs_check_path_number_permission(CCS_TYPE_CHGRP, dentry,
							 vfsmnt, group);
	return error;
}

/**
 * ccs_write_file_policy - Update file related list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_file_policy(char *data, struct ccs_domain_info *domain,
			  struct ccs_condition *condition,
			  const bool is_delete)
{
	char *w[4];
	unsigned int perm;
	u8 type;
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	if (strncmp(w[0], "allow_", 6)) {
		if (sscanf(w[0], "%u", &perm) == 1)
			return ccs_update_file_acl((u8) perm, w[1], domain,
						   condition, is_delete);
		if (!strcmp(w[0], CCS_KEYWORD_EXECUTE_HANDLER))
			type = CCS_TYPE_EXECUTE_HANDLER;
		else if (!strcmp(w[0], CCS_KEYWORD_DENIED_EXECUTE_HANDLER))
			type = CCS_TYPE_DENIED_EXECUTE_HANDLER;
		else
			goto out;
		return ccs_update_execute_handler(type, w[1], domain,
						  is_delete);
	}
	w[0] += 6;
	for (type = 0; type < CCS_MAX_SINGLE_PATH_OPERATION; type++) {
		if (strcmp(w[0], ccs_sp_keyword[type]))
			continue;
		return ccs_update_single_path_acl(type, w[1], domain,
						  condition, is_delete);
	}
	if (!w[2][0])
		goto out;
	for (type = 0; type < CCS_MAX_DOUBLE_PATH_OPERATION; type++) {
		if (strcmp(w[0], ccs_dp_keyword[type]))
			continue;
		return ccs_update_double_path_acl(type, w[1], w[2], domain,
						  condition, is_delete);
	}
	for (type = 0; type < CCS_MAX_PATH_NUMBER_OPERATION; type++) {
		if (strcmp(w[0], ccs_path_number_keyword[type]))
			continue;
		return ccs_update_path_number_acl(type, w[1], w[2], domain,
						  condition, is_delete);
	}
	if (!w[3][0])
		goto out;
	for (type = 0; type < CCS_MAX_MKDEV_OPERATION; type++) {
		if (strcmp(w[0], ccs_mkdev_keyword[type]))
			continue;
		return ccs_update_mkdev_acl(type, w[1], w[2], w[3], domain,
					    condition, is_delete);
	}
 out:
	return -EINVAL;
}

/*
 * Below part contains copy of some of VFS helper functions.
 *
 * Since TOMOYO Linux requires "struct vfsmount" parameter to calculate
 * an absolute pathname of the requested "struct dentry" parameter
 * but the VFS helper functions don't receive "struct vfsmount" parameter,
 * TOMOYO Linux checks permission outside VFS helper functions.
 * To keep the DAC's permission checks are performed before the
 * TOMOYO Linux's permission checks are performed, I'm manually copying
 * these functions that performs the DAC's permission checks from fs/namei.c.
 *
 * The approach to obtain "struct vfsmount" parameter from
 * the "struct task_struct" doesn't work because it triggers deadlock.
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

/* Permission checks from vfs_create(). */
static int ccs_pre_vfs_create(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = ccs_may_create(dir, dentry);
	if (!error && (!dir->i_op || !dir->i_op->create))
		error = -EACCES;
	up(&dir->i_zombie);
	return error;
}

/* Permission checks from vfs_mknod(). */
static int ccs_pre_vfs_mknod(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = ccs_may_create(dir, dentry);
	if (!error && (!dir->i_op || !dir->i_op->mknod))
		error = -EPERM;
	up(&dir->i_zombie);
	return error;
}

/* Permission checks from vfs_mkdir(). */
static int ccs_pre_vfs_mkdir(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = ccs_may_create(dir, dentry);
	if (!error && (!dir->i_op || !dir->i_op->mkdir))
		error = -EPERM;
	up(&dir->i_zombie);
	return error;
}

/* Permission checks from vfs_rmdir(). */
static int ccs_pre_vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = ccs_may_delete(dir, dentry, 1);
	if (!error && (!dir->i_op || !dir->i_op->rmdir))
		error = -EPERM;
	return error;
}

/* Permission checks from vfs_unlink(). */
static int ccs_pre_vfs_unlink(struct inode *dir, struct dentry *dentry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 33)
	int error;
	down(&dir->i_zombie);
	error = ccs_may_delete(dir, dentry, 0);
	if (!error && (!dir->i_op || !dir->i_op->unlink))
		error = -EPERM;
	up(&dir->i_zombie);
	return error;
#else
	int error;
	struct inode *inode;
	error = ccs_may_delete(dir, dentry, 0);
	if (error)
		return error;
	inode = dentry->d_inode;
	atomic_inc(&inode->i_count);
	double_down(&dir->i_zombie, &inode->i_zombie);
	error = -EPERM;
	if (dir->i_op && dir->i_op->unlink)
		error = 0;
	double_up(&dir->i_zombie, &inode->i_zombie);
	iput(inode);
	return error;
#endif
}

/* Permission checks from vfs_symlink(). */
static int ccs_pre_vfs_symlink(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = ccs_may_create(dir, dentry);
	if (error)
		goto exit_lock;
	if (!dir->i_op || !dir->i_op->symlink)
		error = -EPERM;
 exit_lock:
	up(&dir->i_zombie);
	return error;
}

/* Permission checks from vfs_link(). */
static int ccs_pre_vfs_link(struct dentry *old_dentry, struct inode *dir,
			    struct dentry *new_dentry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 33)
	struct inode *inode;
	int error;
	down(&dir->i_zombie);
	error = -ENOENT;
	inode = old_dentry->d_inode;
	if (!inode)
		goto exit_lock;
	error = ccs_may_create(dir, new_dentry);
	if (error)
		goto exit_lock;
	error = -EXDEV;
	if (dir->i_dev != inode->i_dev)
		goto exit_lock;
	error = -EPERM;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		goto exit_lock;
	if (!dir->i_op || !dir->i_op->link)
		goto exit_lock;
	error = 0;
 exit_lock:
	up(&dir->i_zombie);
	return error;
#else
	struct inode *inode;
	int error;
	error = -ENOENT;
	inode = old_dentry->d_inode;
	if (!inode)
		goto exit;
	error = -EXDEV;
	if (dir->i_dev != inode->i_dev)
		goto exit;
	double_down(&dir->i_zombie, &old_dentry->d_inode->i_zombie);
	error = ccs_may_create(dir, new_dentry);
	if (error)
		goto exit_lock;
	error = -EPERM;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		goto exit_lock;
	if (!dir->i_op || !dir->i_op->link)
		goto exit_lock;
	error = 0;
 exit_lock:
	double_up(&dir->i_zombie, &old_dentry->d_inode->i_zombie);
 exit:
	return error;
#endif
}

/* Permission checks from vfs_rename_dir(). */
static inline int ccs_pre_vfs_rename_dir(struct inode *old_dir,
					 struct dentry *old_dentry,
					 struct inode *new_dir,
					 struct dentry *new_dentry)
{
	int error;
	if (old_dentry->d_inode == new_dentry->d_inode)
		return 0;
	error = ccs_may_delete(old_dir, old_dentry, 1);
	if (error)
		return error;
	if (new_dir->i_dev != old_dir->i_dev)
		return -EXDEV;
	if (!new_dentry->d_inode)
		error = ccs_may_create(new_dir, new_dentry);
	else
		error = ccs_may_delete(new_dir, new_dentry, 1);
	if (error)
		return error;
	if (!old_dir->i_op || !old_dir->i_op->rename)
		return -EPERM;
	if (new_dir != old_dir)
		error = permission(old_dentry->d_inode, MAY_WRITE);
	return error;
}

/* Permission checks from vfs_rename_other(). */
static inline int ccs_pre_vfs_rename_other(struct inode *old_dir,
					   struct dentry *old_dentry,
					   struct inode *new_dir,
					   struct dentry *new_dentry)
{
	int error;
	if (old_dentry->d_inode == new_dentry->d_inode)
		return 0;
	error = ccs_may_delete(old_dir, old_dentry, 0);
	if (error)
		return error;
	if (new_dir->i_dev != old_dir->i_dev)
		return -EXDEV;
	if (!new_dentry->d_inode)
		error = ccs_may_create(new_dir, new_dentry);
	else
		error = ccs_may_delete(new_dir, new_dentry, 0);
	if (error)
		return error;
	if (!old_dir->i_op || !old_dir->i_op->rename)
		return -EPERM;
	return 0;
}

/* Permission checks from vfs_rename(). */
static int ccs_pre_vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			      struct inode *new_dir, struct dentry *new_dentry)
{
	int error;
	lock_kernel(); /* From do_rename(). */
	if (S_ISDIR(old_dentry->d_inode->i_mode))
		error = ccs_pre_vfs_rename_dir(old_dir, old_dentry,
					       new_dir, new_dentry);
	else
		error = ccs_pre_vfs_rename_other(old_dir, old_dentry,
						 new_dir, new_dentry);
	unlock_kernel(); /* From do_rename(). */
	return error;
}

#else

/* SUSE 11.0 adds is_dir for may_create(). */
#ifdef MS_WITHAPPEND
#define HAVE_IS_DIR_FOR_MAY_CREATE
#endif

/* Permission checks from vfs_create(). */
static int ccs_pre_vfs_create(struct inode *dir, struct dentry *dentry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = ccs_may_create(dir, dentry, NULL, 0);
#else
	int error = ccs_may_create(dir, dentry, NULL);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = ccs_may_create(dir, dentry, 0);
#else
	int error = ccs_may_create(dir, dentry);
#endif
#endif
	if (error)
		return error;
	if (!dir->i_op || !dir->i_op->create)
		return -EACCES; /* shouldn't it be ENOSYS? */
	return 0;
}

/* Permission checks from vfs_mknod(). */
static int ccs_pre_vfs_mknod(struct inode *dir, struct dentry *dentry,
			     int mode)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = ccs_may_create(dir, dentry, NULL, 0);
#else
	int error = ccs_may_create(dir, dentry, NULL);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = ccs_may_create(dir, dentry, 0);
#else
	int error = ccs_may_create(dir, dentry);
#endif
#endif
	if (error)
		return error;
	if ((S_ISCHR(mode) || S_ISBLK(mode)) && !capable(CAP_MKNOD))
		return -EPERM;
	if (!dir->i_op || !dir->i_op->mknod)
		return -EPERM;
	return 0;
}

/* Permission checks from vfs_mkdir(). */
static int ccs_pre_vfs_mkdir(struct inode *dir, struct dentry *dentry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = ccs_may_create(dir, dentry, NULL, 1);
#else
	int error = ccs_may_create(dir, dentry, NULL);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = ccs_may_create(dir, dentry, 1);
#else
	int error = ccs_may_create(dir, dentry);
#endif
#endif
	if (error)
		return error;
	if (!dir->i_op || !dir->i_op->mkdir)
		return -EPERM;
	return 0;
}

/* Permission checks from vfs_rmdir(). */
static int ccs_pre_vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = ccs_may_delete(dir, dentry, 1);
	if (error)
		return error;
	if (!dir->i_op || !dir->i_op->rmdir)
		return -EPERM;
	return 0;
}

/* Permission checks from vfs_unlink(). */
static int ccs_pre_vfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int error = ccs_may_delete(dir, dentry, 0);
	if (error)
		return error;
	if (!dir->i_op || !dir->i_op->unlink)
		return -EPERM;
	return 0;
}

/* Permission checks from vfs_link(). */
static int ccs_pre_vfs_link(struct dentry *old_dentry, struct inode *dir,
			    struct dentry *new_dentry)
{
	struct inode *inode = old_dentry->d_inode;
	int error;
	if (!inode)
		return -ENOENT;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	error = ccs_may_create(dir, new_dentry, NULL, 0);
#else
	error = ccs_may_create(dir, new_dentry, NULL);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	error = ccs_may_create(dir, new_dentry, 0);
#else
	error = ccs_may_create(dir, new_dentry);
#endif
#endif
	if (error)
		return error;
	if (dir->i_sb != inode->i_sb)
		return -EXDEV;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;
	if (!dir->i_op || !dir->i_op->link)
		return -EPERM;
	if (S_ISDIR(old_dentry->d_inode->i_mode))
		return -EPERM;
	return 0;
}

/* Permission checks from vfs_symlink(). */
static int ccs_pre_vfs_symlink(struct inode *dir, struct dentry *dentry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = ccs_may_create(dir, dentry, NULL, 0);
#else
	int error = ccs_may_create(dir, dentry, NULL);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = ccs_may_create(dir, dentry, 0);
#else
	int error = ccs_may_create(dir, dentry);
#endif
#endif
	if (error)
		return error;
	if (!dir->i_op || !dir->i_op->symlink)
		return -EPERM;
	return 0;
}

/* Permission checks from vfs_rename(). */
static int ccs_pre_vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			      struct inode *new_dir, struct dentry *new_dentry)
{
	int error;
	const int is_dir = S_ISDIR(old_dentry->d_inode->i_mode);
	if (old_dentry->d_inode == new_dentry->d_inode)
		return 0;
	error = ccs_may_delete(old_dir, old_dentry, is_dir);
	if (error)
		return error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	if (!new_dentry->d_inode)
		error = ccs_may_create(new_dir, new_dentry, NULL, is_dir);
	else
		error = ccs_may_delete(new_dir, new_dentry, is_dir);
#else
	if (!new_dentry->d_inode)
		error = ccs_may_create(new_dir, new_dentry, NULL);
	else
		error = ccs_may_delete(new_dir, new_dentry, is_dir);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	if (!new_dentry->d_inode)
		error = ccs_may_create(new_dir, new_dentry, is_dir);
	else
		error = ccs_may_delete(new_dir, new_dentry, is_dir);
#else
	if (!new_dentry->d_inode)
		error = ccs_may_create(new_dir, new_dentry);
	else
		error = ccs_may_delete(new_dir, new_dentry, is_dir);
#endif
#endif
	if (error)
		return error;
	if (!old_dir->i_op || !old_dir->i_op->rename)
		return -EPERM;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
	if (is_dir && new_dir != old_dir)
		error = permission(old_dentry->d_inode, MAY_WRITE, NULL);
#else
	if (is_dir && new_dir != old_dir)
		error = inode_permission(old_dentry->d_inode, MAY_WRITE);
#endif
	return error;
}

#endif

/*
 * Permission checks from vfs_mknod().
 *
 * This function is exported because
 * vfs_mknod() is called from net/unix/af_unix.c.
 */
int ccs_check_mknod_permission(struct inode *dir, struct dentry *dentry,
			       struct vfsmount *mnt, int mode, unsigned dev)
{
	int error;
	if (S_ISCHR(mode) && !ccs_capable(CCS_CREATE_CHAR_DEV))
		return -EPERM;
	if (S_ISBLK(mode) && !ccs_capable(CCS_CREATE_BLOCK_DEV))
		return -EPERM;
	if (S_ISFIFO(mode) && !ccs_capable(CCS_CREATE_FIFO))
		return -EPERM;
	if (S_ISSOCK(mode) && !ccs_capable(CCS_CREATE_UNIX_SOCKET))
		return -EPERM;
	switch (mode & S_IFMT) {
	case 0:
	case S_IFREG:
		error = ccs_pre_vfs_create(dir, dentry);
		if (!error)
			error = ccs_check_1path_perm(CCS_TYPE_CREATE_ACL,
						     dentry, mnt, NULL);
		return error;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
	error = ccs_pre_vfs_mknod(dir, dentry);
#else
	error = ccs_pre_vfs_mknod(dir, dentry, mode);
#endif
	if (error)
		return error;
	switch (mode & S_IFMT) {
	case S_IFCHR:
		error = ccs_check_mkdev_perm(CCS_TYPE_MKCHAR_ACL, dentry, mnt,
					     dev);
		break;
	case S_IFBLK:
		error = ccs_check_mkdev_perm(CCS_TYPE_MKBLOCK_ACL, dentry, mnt,
					     dev);
		break;
	case S_IFIFO:
		error = ccs_check_1path_perm(CCS_TYPE_MKFIFO_ACL, dentry, mnt,
					     NULL);
		break;
	case S_IFSOCK:
		error = ccs_check_1path_perm(CCS_TYPE_MKSOCK_ACL, dentry, mnt,
					     NULL);
		break;
	}
	return error;
}
EXPORT_SYMBOL(ccs_check_mknod_permission);

/* Permission checks for vfs_mkdir(). */
int ccs_check_mkdir_permission(struct inode *dir, struct dentry *dentry,
			       struct vfsmount *mnt, int mode)
{
	int error = ccs_pre_vfs_mkdir(dir, dentry);
	if (!error)
		error = ccs_check_1path_perm(CCS_TYPE_MKDIR_ACL, dentry, mnt,
					     NULL);
	return error;
}

/* Permission checks for vfs_rmdir(). */
int ccs_check_rmdir_permission(struct inode *dir, struct dentry *dentry,
			       struct vfsmount *mnt)
{
	int error = ccs_pre_vfs_rmdir(dir, dentry);
	if (!error)
		error = ccs_check_1path_perm(CCS_TYPE_RMDIR_ACL, dentry, mnt,
					     NULL);
	return error;
}

/* Permission checks for vfs_unlink(). */
int ccs_check_unlink_permission(struct inode *dir, struct dentry *dentry,
				struct vfsmount *mnt)
{
	int error;
	if (!ccs_capable(CCS_SYS_UNLINK))
		return -EPERM;
	error = ccs_pre_vfs_unlink(dir, dentry);
	if (!error)
		error = ccs_check_1path_perm(CCS_TYPE_UNLINK_ACL, dentry, mnt,
					     NULL);
	return error;
}

/* Permission checks for vfs_symlink(). */
int ccs_check_symlink_permission(struct inode *dir, struct dentry *dentry,
				 struct vfsmount *mnt, char *from)
{
	int error;
	if (!ccs_capable(CCS_SYS_SYMLINK))
		return -EPERM;
	error = ccs_pre_vfs_symlink(dir, dentry);
	if (!error)
		error = ccs_check_1path_perm(CCS_TYPE_SYMLINK_ACL, dentry, mnt,
					     from);
	return error;
}

/* Permission checks for notify_change(). */
int ccs_check_truncate_permission(struct dentry *dentry, struct vfsmount *mnt,
				  loff_t length, unsigned int time_attrs)
{
	return ccs_check_1path_perm(CCS_TYPE_TRUNCATE_ACL, dentry, mnt, NULL);
}

/* Permission checks for vfs_rename(). */
int ccs_check_rename_permission(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry,
				struct vfsmount *mnt)
{
	int error;
	if (!ccs_capable(CCS_SYS_RENAME))
		return -EPERM;
	error = ccs_pre_vfs_rename(old_dir, old_dentry, new_dir, new_dentry);
	if (!error)
		error = ccs_check_2path_perm(CCS_TYPE_RENAME_ACL, old_dentry,
					     new_dentry, mnt);
	return error;
}

/* Permission checks for vfs_link(). */
int ccs_check_link_permission(struct dentry *old_dentry, struct inode *new_dir,
			      struct dentry *new_dentry, struct vfsmount *mnt)
{
	int error;
	if (!ccs_capable(CCS_SYS_LINK))
		return -EPERM;
	error = ccs_pre_vfs_link(old_dentry, new_dir, new_dentry);
	if (!error)
		error = ccs_check_2path_perm(CCS_TYPE_LINK_ACL, old_dentry,
					     new_dentry, mnt);
	return error;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
/* Permission checks for open_exec(). */
int ccs_check_open_exec_permission(struct dentry *dentry, struct vfsmount *mnt)
{
	return (current->ccs_flags & CCS_CHECK_READ_FOR_OPEN_EXEC) ?
		/* 01 means "read". */
		ccs_check_open_permission(dentry, mnt, 01) : 0;
}

/* Permission checks for sys_uselib(). */
int ccs_check_uselib_permission(struct dentry *dentry, struct vfsmount *mnt)
{
	/* 01 means "read". */
	return ccs_check_open_permission(dentry, mnt, 01);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18) || defined(CONFIG_SYSCTL_SYSCALL)

#include <linux/sysctl.h>

/* Permission checks for parse_table(). */
int ccs_parse_table(int __user *name, int nlen, void __user *oldval,
		    void __user *newval, struct ctl_table *table)
{
	int n;
	int error = -ENOMEM;
	int op = 0;
	struct ccs_path_info buf;
	struct ccs_request_info r;
	int idx;
	if (oldval)
		op |= 004;
	if (newval)
		op |= 002;
	if (!op) /* Neither read nor write */
		return 0;
	if (!ccs_can_sleep())
		return 0;
	buf.name = NULL;
	idx = ccs_read_lock();
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_FILE);
	if (!r.mode) {
		error = 0;
		goto out;
	}
	buf.name = kzalloc(CCS_MAX_PATHNAME_LEN, GFP_KERNEL);
	if (!buf.name)
		goto out;
	snprintf((char *) buf.name, CCS_MAX_PATHNAME_LEN - 1, "/proc/sys");
 repeat:
	if (!nlen) {
		error = -ENOTDIR;
		goto out;
	}
	if (get_user(n, name)) {
		error = -EFAULT;
		goto out;
	}
	for ( ; table->ctl_name
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21)
		      || table->procname
#endif
		      ; table++) {
		int pos;
		const char *cp;
		char *buffer = (char *) buf.name;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
		if (n != table->ctl_name && table->ctl_name != CTL_ANY)
			continue;
#else
		if (!n || n != table->ctl_name)
			continue;
#endif
		pos = strlen(buffer);
		cp = table->procname;
		error = -ENOMEM;
		if (cp) {
			if (pos + 1 >= CCS_MAX_PATHNAME_LEN - 1)
				goto out;
			buffer[pos++] = '/';
			while (*cp) {
				const unsigned char c
					= *(const unsigned char *) cp;
				if (c == '\\') {
					if (pos + 2 >= CCS_MAX_PATHNAME_LEN - 1)
						goto out;
					buffer[pos++] = '\\';
					buffer[pos++] = '\\';
				} else if (c > ' ' && c < 127) {
					if (pos + 1 >= CCS_MAX_PATHNAME_LEN - 1)
						goto out;
					buffer[pos++] = c;
				} else {
					if (pos + 4 >= CCS_MAX_PATHNAME_LEN - 1)
						goto out;
					buffer[pos++] = '\\';
					buffer[pos++] = (c >> 6) + '0';
					buffer[pos++] = ((c >> 3) & 7) + '0';
					buffer[pos++] = (c & 7) + '0';
				}
				cp++;
			}
		} else {
			/* Assume nobody assigns "=\$=" for procname. */
			snprintf(buffer + pos, CCS_MAX_PATHNAME_LEN - pos - 1,
				 "/=%d=", table->ctl_name);
			if (!memchr(buffer, '\0', CCS_MAX_PATHNAME_LEN - 2))
				goto out;
		}
		if (table->child) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
			if (table->strategy) {
				/* printk("sysctl='%s'\n", buffer); */
				ccs_fill_path_info(&buf);
				if (ccs_check_file_perm(&r, &buf, op)) {
					error = -EPERM;
					goto out;
				}
			}
#endif
			name++;
			nlen--;
			table = table->child;
			goto repeat;
		}
		/* printk("sysctl='%s'\n", buffer); */
		ccs_fill_path_info(&buf);
		error = ccs_check_file_perm(&r, &buf, op);
		goto out;
	}
	error = -ENOTDIR;
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	return error;
}
#endif
