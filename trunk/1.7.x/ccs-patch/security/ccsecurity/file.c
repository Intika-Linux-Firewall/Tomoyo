/*
 * security/ccsecurity/file.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0   2009/09/11
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"
#define ACC_MODE(x) ("\000\004\002\006"[(x)&O_ACCMODE])

static const char *ccs_path_keyword[CCS_MAX_PATH_OPERATION] = {
	[CCS_TYPE_READ_WRITE] = "read/write",
	[CCS_TYPE_EXECUTE]    = "execute",
	[CCS_TYPE_READ]       = "read",
	[CCS_TYPE_WRITE]      = "write",
	[CCS_TYPE_UNLINK]     = "unlink",
	[CCS_TYPE_RMDIR]      = "rmdir",
	[CCS_TYPE_TRUNCATE]   = "truncate",
	[CCS_TYPE_SYMLINK]    = "symlink",
	[CCS_TYPE_REWRITE]    = "rewrite",
};

static const char *ccs_path_number3_keyword[CCS_MAX_PATH_NUMBER3_OPERATION] = {
	[CCS_TYPE_MKBLOCK]    = "mkblock",
	[CCS_TYPE_MKCHAR]     = "mkchar",
};

static const char *ccs_path2_keyword[CCS_MAX_PATH2_OPERATION] = {
	[CCS_TYPE_LINK]    = "link",
	[CCS_TYPE_RENAME]  = "rename",
};

static const char *ccs_path_number_keyword[CCS_MAX_PATH_NUMBER_OPERATION] = {
	[CCS_TYPE_CREATE] = "create",
	[CCS_TYPE_MKDIR]  = "mkdir",
	[CCS_TYPE_MKFIFO] = "mkfifo",
	[CCS_TYPE_MKSOCK] = "mksock",
	[CCS_TYPE_IOCTL]  = "ioctl",
	[CCS_TYPE_CHMOD]  = "chmod",
	[CCS_TYPE_CHOWN]  = "chown",
	[CCS_TYPE_CHGRP]  = "chgrp",
};

static const u8 ccs_p2mac[CCS_MAX_PATH_OPERATION] = {
	[CCS_TYPE_READ_WRITE] = CCS_MAC_FILE_OPEN,
	[CCS_TYPE_EXECUTE]    = CCS_MAC_FILE_EXECUTE,
	[CCS_TYPE_READ]       = CCS_MAC_FILE_OPEN,
	[CCS_TYPE_WRITE]      = CCS_MAC_FILE_OPEN,
	[CCS_TYPE_UNLINK]     = CCS_MAC_FILE_UNLINK,
	[CCS_TYPE_RMDIR]      = CCS_MAC_FILE_RMDIR,
	[CCS_TYPE_TRUNCATE]   = CCS_MAC_FILE_TRUNCATE,
	[CCS_TYPE_SYMLINK]    = CCS_MAC_FILE_SYMLINK,
	[CCS_TYPE_REWRITE]    = CCS_MAC_FILE_REWRITE,
};

static const u8 ccs_pnnn2mac[CCS_MAX_PATH_NUMBER3_OPERATION] = {
	[CCS_TYPE_MKBLOCK] = CCS_MAC_FILE_MKBLOCK,
	[CCS_TYPE_MKCHAR]  = CCS_MAC_FILE_MKCHAR,
};

static const u8 ccs_pp2mac[CCS_MAX_PATH2_OPERATION] = {
	[CCS_TYPE_LINK]   = CCS_MAC_FILE_LINK,
	[CCS_TYPE_RENAME] = CCS_MAC_FILE_RENAME,
};

static const u8 ccs_pn2mac[CCS_MAX_PATH_NUMBER_OPERATION] = {
	[CCS_TYPE_CREATE] = CCS_MAC_FILE_CREATE,
	[CCS_TYPE_MKDIR]  = CCS_MAC_FILE_MKDIR,
	[CCS_TYPE_MKFIFO] = CCS_MAC_FILE_MKFIFO,
	[CCS_TYPE_MKSOCK] = CCS_MAC_FILE_MKSOCK,
	[CCS_TYPE_IOCTL]  = CCS_MAC_FILE_IOCTL,
	[CCS_TYPE_CHMOD]  = CCS_MAC_FILE_CHMOD,
	[CCS_TYPE_CHOWN]  = CCS_MAC_FILE_CHOWN,
	[CCS_TYPE_CHGRP]  = CCS_MAC_FILE_CHGRP,
};


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
 * ccs_path2keyword - Get the name of single path operation.
 *
 * @operation: Type of operation.
 *
 * Returns the name of single path operation.
 */
const char *ccs_path2keyword(const u8 operation)
{
	return (operation < CCS_MAX_PATH_OPERATION)
		? ccs_path_keyword[operation] : NULL;
}

/**
 * ccs_path_number32keyword - Get the name of mkdev operation.
 *
 * @operation: Type of operation.
 *
 * Returns the name of mkdev operation.
 */
const char *ccs_path_number32keyword(const u8 operation)
{
	return (operation < CCS_MAX_PATH_NUMBER3_OPERATION)
		? ccs_path_number3_keyword[operation] : NULL;
}

/**
 * ccs_path22keyword - Get the name of double path operation.
 *
 * @operation: Type of operation.
 *
 * Returns the name of double path operation.
 */
const char *ccs_path22keyword(const u8 operation)
{
	return (operation < CCS_MAX_PATH2_OPERATION)
		? ccs_path2_keyword[operation] : NULL;
}

const char *ccs_path_number2keyword(const u8 operation)
{
	return (operation < CCS_MAX_PATH_NUMBER_OPERATION)
		? ccs_path_number_keyword[operation] : NULL;
}

static void ccs_add_slash(struct ccs_path_info *buf)
{
	if (buf->is_dir)
		return;
	/* This is OK because ccs_encode() reserves space for appending "/". */
	strcat((char *) buf->name, "/");
	ccs_fill_path_info(buf);
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
 * ccs_get_realpath - Get realpath.
 *
 * @buf:    Pointer to "struct ccs_path_info".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount".
 *
 * Returns true success, false otherwise.
 */
static bool ccs_get_realpath(struct ccs_path_info *buf, struct dentry *dentry,
			     struct vfsmount *mnt)
{
	struct path path = { mnt, dentry };
	buf->name = ccs_realpath_from_path(&path);
	if (buf->name) {
		ccs_fill_path_info(buf);
		return true;
	}
	return false;
}

static int ccs_update_path_acl(const u8 type, const char *filename,
			       struct ccs_domain_info * const domain,
			       struct ccs_condition *condition,
			       const bool is_delete);

/**
 * ccs_audit_path_log - Audit single path request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @filename:   Pathname.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_path_log(struct ccs_request_info *r,
			      const char *operation, const char *filename,
			      const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "%s %s", operation, filename);
	return ccs_write_audit_log(is_granted, r, "allow_%s %s\n", operation,
				   filename);
}

/**
 * ccs_audit_path2_log - Audit double path request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @filename1:  First pathname.
 * @filename2:  Second pathname.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_path2_log(struct ccs_request_info *r,
			       const char *operation, const char *filename1,
			       const char *filename2, const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "%s %s %s", operation, filename1, filename2);
	return ccs_write_audit_log(is_granted, r, "allow_%s %s %s\n",
				   operation, filename1, filename2);
}

/**
 * ccs_audit_path_number3_log - Audit mkdev request log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @filename:   First pathname.
 * @mode:       Create mode.
 * @major:      Device major number.
 * @minor:      Device minor number.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_path_number3_log(struct ccs_request_info *r,
				      const char *operation,
				      const char *filename,
				      const unsigned int mode,
				      const unsigned int major,
				      const unsigned int minor,
				      const bool is_granted)
{
	if (!is_granted)
		ccs_warn_log(r, "%s %s 0%o %u %u", operation, filename, mode,
			     major, minor);
	return ccs_write_audit_log(is_granted, r, "allow_%s %s 0%o %u %u\n",
				   operation, filename, mode, major, minor);
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
	if (!is_granted)
		ccs_warn_log(r, "%s %s %s", operation, filename, value);
	return ccs_write_audit_log(is_granted, r, "allow_%s %s %s\n",
				   operation, filename, value);
}

/* The list for "struct ccs_globally_readable_file_entry". */
LIST_HEAD(ccs_globally_readable_list);

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
	struct ccs_globally_readable_file_entry *entry = NULL;
	struct ccs_globally_readable_file_entry *ptr;
	struct ccs_globally_readable_file_entry e = { };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(data, 1, 0, -1))
		return -EINVAL;
	e.filename = ccs_get_name(data);
	if (!e.filename)
		return -ENOMEM;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_globally_readable_list, list) {
		if (ptr->filename != e.filename)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		list_add_tail_rcu(&entry->list, &ccs_globally_readable_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(e.filename);
	kfree(entry);
	return error;
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

/* The list for "struct ccs_pattern_entry". */
LIST_HEAD(ccs_pattern_list);

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
	struct ccs_pattern_entry *entry = NULL;
	struct ccs_pattern_entry *ptr;
	struct ccs_pattern_entry e = { .pattern = ccs_get_name(data) };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!e.pattern)
		return error;
	if (!e.pattern->is_patterned)
		goto out;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_pattern_list, list) {
		if (e.pattern != ptr->pattern)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		list_add_tail_rcu(&entry->list, &ccs_pattern_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(e.pattern);
	kfree(entry);
	return error;
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
	struct ccs_no_rewrite_entry *entry = NULL;
	struct ccs_no_rewrite_entry *ptr;
	struct ccs_no_rewrite_entry e = { };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(data, 0, 0, 0))
		return -EINVAL;
	e.pattern = ccs_get_name(data);
	if (!e.pattern)
		return error;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_no_rewrite_list, list) {
		if (ptr->pattern != e.pattern)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		list_add_tail_rcu(&entry->list, &ccs_no_rewrite_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(e.pattern);
	kfree(entry);
	return error;
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
static inline int ccs_update_file_acl(u8 perm, const char *filename,
				      struct ccs_domain_info * const domain,
				      struct ccs_condition *condition,
				      const bool is_delete)
{
	if (perm > 7 || !perm)
		return -EINVAL;
	if (filename[0] != '@' && ccs_strendswith(filename, "/"))
		/*
		 * Only 'allow_mkdir' and 'allow_rmdir' are valid for
		 * directory permissions.
		 */
		return 0;
	if (perm & 4)
		ccs_update_path_acl(CCS_TYPE_READ, filename, domain,
				    condition, is_delete);
	if (perm & 2)
		ccs_update_path_acl(CCS_TYPE_WRITE, filename,
				    domain, condition, is_delete);
	if (perm & 1)
		ccs_update_path_acl(CCS_TYPE_EXECUTE, filename,
				    domain, condition, is_delete);
	return 0;
}

/**
 * ccs_path_acl - Check permission for single path operation.
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
static int ccs_path_acl(struct ccs_request_info *r,
			const struct ccs_path_info *filename,
			const u16 perm,
			const bool may_use_pattern)
{
	struct ccs_domain_info *domain = r->domain;
	struct ccs_acl_info *ptr;
	int error = -EPERM;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_PATH_ACL)
			continue;
		acl = container_of(ptr, struct ccs_path_acl,
				   head);
		if (!(acl->perm & perm) || !ccs_condition(r, ptr) ||
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
 * ccs_path_number3_acl - Check permission for mkdev operation.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @filename: Filename to check.
 * @perm:     Permission.
 * @mode:     Create mode.
 * @major:    Device major number.
 * @minor:    Device minor number.
 *
 * Returns 0 on success, -EPERM otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_path_number3_acl(struct ccs_request_info *r,
				const struct ccs_path_info *filename,
				const u16 perm, const unsigned int mode,
				const unsigned int major,
				const unsigned int minor)
{
	struct ccs_domain_info *domain = r->domain;
	struct ccs_acl_info *ptr;
	int error = -EPERM;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number3_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_PATH_NUMBER3_ACL)
			continue;
		acl = container_of(ptr, struct ccs_path_number3_acl, head);
		if (!ccs_compare_number_union(mode, &acl->mode))
			continue;
		if (!ccs_compare_number_union(major, &acl->major))
			continue;
		if (!ccs_compare_number_union(minor, &acl->minor))
			continue;
		if (!(acl->perm & perm) || !ccs_condition(r, ptr))
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
 * ccs_file_perm - Check permission for opening files.
 *
 * @r:         Pointer to "strct ccs_request_info".
 * @filename:  Filename to check.
 * @mode:      Mode ("read" or "write" or "read/write" or "execute").
 *
 * Returns 0 on success, 1 on retry, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_file_perm(struct ccs_request_info *r,
			 const struct ccs_path_info *filename, const u8 mode)
{
	const char *msg = "<unknown>";
	int error = 0;
	u16 perm = 0;
	if (!filename)
		return 0;
	if (mode == 6) {
		msg = ccs_path2keyword(CCS_TYPE_READ_WRITE);
		perm = 1 << CCS_TYPE_READ_WRITE;
	} else if (mode == 4) {
		msg = ccs_path2keyword(CCS_TYPE_READ);
		perm = 1 << CCS_TYPE_READ;
	} else if (mode == 2) {
		msg = ccs_path2keyword(CCS_TYPE_WRITE);
		perm = 1 << CCS_TYPE_WRITE;
	} else if (mode == 1) {
		msg = ccs_path2keyword(CCS_TYPE_EXECUTE);
		perm = 1 << CCS_TYPE_EXECUTE;
	} else
		BUG();
	do {
		error = ccs_path_acl(r, filename, perm, mode != 1);
		if (error && mode == 4 && !r->domain->ignore_global_allow_read
		    && ccs_is_globally_readable_file(filename))
			error = 0;
		ccs_audit_path_log(r, msg, filename->name, !error);
		if (!error)
			break;
		error = ccs_supervisor(r, "allow_%s %s\n", msg,
				       mode == 1 ? filename->name :
				       ccs_file_pattern(filename));
		/*
		 * Do not retry for execute request, for aggregator may have
		 * changed.
		 */
	} while (error == 1 && !r->ee);
	if (r->mode != CCS_CONFIG_ENFORCING)
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
static inline int ccs_update_execute_handler(const u8 type,
					     const char *filename,
					     struct ccs_domain_info * const
					     domain, const bool is_delete)
{
	struct ccs_acl_info *ptr;
	struct ccs_execute_handler_record e = { .head.type = type };
	struct ccs_execute_handler_record *entry = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!domain)
		return -EINVAL;
	if (!ccs_is_correct_path(filename, 1, -1, -1))
		return -EINVAL;
	e.handler = ccs_get_name(filename);
	if (!e.handler)
		return -ENOMEM;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_execute_handler_record *acl;
		if (ptr->type != type)
			continue;
		/* Condition not supported. */
		acl = container_of(ptr, struct ccs_execute_handler_record,
				   head);
		if (acl->handler != e.handler)
			continue;
		if (!is_delete) {
			/* Only one entry can exist in a domain. */
			struct ccs_acl_info *ptr2;
			list_for_each_entry_rcu(ptr2, &domain->acl_info_list,
						list) {
				if (ptr2->type == type)
					ptr2->is_deleted = true;
			}
		}
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		/* Only one entry can exist in a domain. */
		list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
			if (ptr->type == type)
				ptr->is_deleted = true;
		}
		ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(e.handler);
	kfree(entry);
	return error;
}

/**
 * ccs_update_path_acl - Update "struct ccs_path_acl" list.
 *
 * @type:      Type of operation.
 * @filename:  Filename.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_path_acl(const u8 type, const char *filename,
			       struct ccs_domain_info * const domain,
			       struct ccs_condition *condition,
			       const bool is_delete)
{
	static const u16 ccs_rw_mask =
		(1 << CCS_TYPE_READ) | (1 << CCS_TYPE_WRITE);
	const u16 perm = 1 << type;
	struct ccs_acl_info *ptr;
	struct ccs_path_acl e = {
		.head.type = CCS_TYPE_PATH_ACL,
		.head.cond = condition,
		.perm = perm
	};
	struct ccs_path_acl *entry = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (type == CCS_TYPE_READ_WRITE)
		e.perm |= ccs_rw_mask;
	if (!ccs_parse_name_union(filename, &e.name))
		return -EINVAL;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_acl *acl =
			container_of(ptr, struct ccs_path_acl,
				     head);
		if (ptr->type != CCS_TYPE_PATH_ACL ||
		    ptr->cond != condition ||
		    ccs_memcmp(acl, &e, offsetof(typeof(e), name), sizeof(e)))
			continue;
		if (is_delete) {
			acl->perm &= ~perm;
			if ((acl->perm & ccs_rw_mask) != ccs_rw_mask)
				acl->perm &= ~(1 << CCS_TYPE_READ_WRITE);
			else if (!(acl->perm & (1 << CCS_TYPE_READ_WRITE)))
				acl->perm &= ~ccs_rw_mask;
			if (!acl->perm)
				ptr->is_deleted = true;
		} else {
			if (ptr->is_deleted)
				acl->perm = 0;
			acl->perm |= perm;
			if ((acl->perm & ccs_rw_mask) == ccs_rw_mask)
				acl->perm |= 1 << CCS_TYPE_READ_WRITE;
			else if (acl->perm & (1 << CCS_TYPE_READ_WRITE))
				acl->perm |= ccs_rw_mask;
			ptr->is_deleted = false;
		}
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name_union(&e.name);
	kfree(entry);
	return error;
}

/**
 * ccs_update_path_number3_acl - Update "struct ccs_path_number3_acl" list.
 *
 * @type:      Type of operation.
 * @filename:  Filename.
 * @mode:      Create mode.
 * @major:     Device major number.
 * @minor:     Device minor number.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_update_path_number3_acl(const u8 type,
					      const char *filename, char *mode,
					      char *major, char *minor,
					      struct ccs_domain_info * const
					      domain,
					      struct ccs_condition *condition,
					      const bool is_delete)
{
	const u8 perm = 1 << type;
	struct ccs_acl_info *ptr;
	struct ccs_path_number3_acl e = {
		.head.type = CCS_TYPE_PATH_NUMBER3_ACL,
		.head.cond = condition,
		.perm = perm
	};
	struct ccs_path_number3_acl *entry = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_parse_name_union(filename, &e.name) ||
	    !ccs_parse_number_union(mode, &e.mode) ||
	    !ccs_parse_number_union(major, &e.major) ||
	    !ccs_parse_number_union(minor, &e.minor))
		goto out;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number3_acl *acl =
			container_of(ptr, struct ccs_path_number3_acl, head);
		if (ptr->type != CCS_TYPE_PATH_NUMBER3_ACL ||
		    ptr->cond != condition ||
		    ccs_memcmp(acl, &e, offsetof(typeof(e), name), sizeof(e)))
			continue;
		if (is_delete) {
			acl->perm &= ~perm;
			if (!acl->perm)
				ptr->is_deleted = true;
		} else {
			if (ptr->is_deleted)
				acl->perm = 0;
			acl->perm |= perm;
			ptr->is_deleted = false;
		}
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name);
	ccs_put_number_union(&e.mode);
	ccs_put_number_union(&e.major);
	ccs_put_number_union(&e.minor);
	kfree(entry);
	return error;
}

/**
 * ccs_update_path2_acl - Update "struct ccs_path2_acl" list.
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
static inline int ccs_update_path2_acl(const u8 type,
				       const char *filename1,
				       const char *filename2,
				       struct ccs_domain_info * const
				       domain,
				       struct ccs_condition *condition,
				       const bool is_delete)
{
	const u8 perm = 1 << type;
	struct ccs_acl_info *ptr;
	struct ccs_path2_acl e = {
		.head.type = CCS_TYPE_PATH2_ACL,
		.head.cond = condition,
		.perm = perm
	};
	struct ccs_path2_acl *entry = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_parse_name_union(filename1, &e.name1) ||
	    !ccs_parse_name_union(filename2, &e.name2))
		goto out;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path2_acl *acl =
			container_of(ptr, struct ccs_path2_acl,
				     head);
		if (ptr->type != CCS_TYPE_PATH2_ACL ||
		    ptr->cond != condition ||
		    ccs_memcmp(acl, &e, offsetof(typeof(e), name1), sizeof(e)))
			continue;
		if (is_delete) {
			acl->perm &= ~perm;
			if (!acl->perm)
				ptr->is_deleted = true;
		} else {
			if (ptr->is_deleted)
				acl->perm = 0;
			acl->perm |= perm;
			ptr->is_deleted = false;
		}
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name1);
	ccs_put_name_union(&e.name2);
	kfree(entry);
	return error;
}

/**
 * ccs_path2_acl - Check permission for double path operation.
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
static int ccs_path2_acl(struct ccs_request_info *r, const u8 type,
			 const struct ccs_path_info *filename1,
			 const struct ccs_path_info *filename2)
{
	const struct ccs_domain_info *domain = r->domain;
	struct ccs_acl_info *ptr;
	const u8 perm = 1 << type;
	int error = -EPERM;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path2_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_PATH2_ACL)
			continue;
		acl = container_of(ptr, struct ccs_path2_acl,
				   head);
		if (!(acl->perm & perm) || !ccs_condition(r, ptr) ||
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
 * ccs_path_permission - Check permission for single path operation.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @operation: Type of operation.
 * @filename:  Filename to check.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_path_permission(struct ccs_request_info *r,
			       u8 operation,
			       const struct ccs_path_info *
			       filename)
{
	const char *msg;
	int error;
 repeat:
	r->mode = ccs_get_mode(r->profile, ccs_p2mac[operation]);
	if (r->mode == CCS_CONFIG_DISABLED)
		return 0;
	do {
		error = ccs_path_acl(r, filename, 1 << operation, 1);
		msg = ccs_path2keyword(operation);
		ccs_audit_path_log(r, msg, filename->name, !error);
		if (!error)
			break;
		error = ccs_supervisor(r, "allow_%s %s\n", msg,
				       ccs_file_pattern(filename));
	} while (error == 1);
	if (r->mode != CCS_CONFIG_ENFORCING)
		error = 0;
	/*
	 * Since "allow_truncate" doesn't imply "allow_rewrite" permission,
	 * we need to check "allow_rewrite" permission if the filename is
	 * specified by "deny_rewrite" keyword.
	 */
	if (!error && operation == CCS_TYPE_TRUNCATE &&
	    ccs_is_no_rewrite_file(filename)) {
		operation = CCS_TYPE_REWRITE;
		goto repeat;
	}
	return error;
}

/**
 * ccs_path_number3_perm2 - Check permission for mkdev operation.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @operation: Type of operation.
 * @filename:  Filename to check.
 * @mode:      Create mode.
 * @dev:       Device number.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_path_number3_perm2(struct ccs_request_info *r,
				  const u8 operation,
				  const struct ccs_path_info *filename,
				  const unsigned int mode,
				  const unsigned int dev)
{
	int error;
	const char *msg = ccs_path_number32keyword(operation);
	const unsigned int major = MAJOR(dev);
	const unsigned int minor = MINOR(dev);
	if (!r->mode)
		return 0;
	do {
		error = ccs_path_number3_acl(r, filename, 1 << operation, mode,
					     major, minor);
		ccs_audit_path_number3_log(r, msg, filename->name, mode, major,
					   minor, !error);
		if (!error)
			break;
		error = ccs_supervisor(r, "allow_%s %s 0%o %u %u\n", msg,
				       ccs_file_pattern(filename), mode,
				       major, minor);
	} while (error == 1);
	if (r->mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_exec_perm - Check permission for "execute".
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @filename: Check permission for "execute".
 *
 * Returns 0 on success, 1 on retry, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
int ccs_exec_perm(struct ccs_request_info *r,
		  const struct ccs_path_info *filename)
{
	if (r->mode == CCS_CONFIG_DISABLED)
		return 0;
	return ccs_file_perm(r, filename, 1);
}

/*
 * Save original flags passed to sys_open().
 *
 * TOMOYO does not check "allow_write" if open(path, O_TRUNC | O_RDONLY) was
 * requested because write() is not permitted. Instead, TOMOYO checks
 * "allow_truncate" if O_TRUNC is passed.
 *
 * TOMOYO does not check "allow_read/write" if open(path, 3) was requested
 * because read()/write() are not permitted. Instead, TOMOYO checks
 * "allow_ioctl" when ioctl() is requested.
 */
void ccs_save_open_mode(int mode)
{
	current->ccs_flags |= (mode & O_ACCMODE) | CCS_USE_OPEN_MODE;
}

void ccs_clear_open_mode(void)
{
	current->ccs_flags &= ~(O_ACCMODE | CCS_USE_OPEN_MODE);
}

/**
 * ccs_open_permission - Check permission for "read" and "write".
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount".
 * @flag:   Flags for open().
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_open_permission(struct dentry *dentry, struct vfsmount *mnt,
			const int flag)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1.dentry = dentry,
		.path1.mnt = mnt
	};
	struct task_struct * const task = current;
	const u8 acc_mode = task->ccs_flags & CCS_USE_OPEN_MODE ?
		ACC_MODE((task->ccs_flags & O_ACCMODE) + 1) : ACC_MODE(flag);
	int error = 0;
	struct ccs_path_info buf;
	int idx;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	if (task->in_execve &&
	    !(task->ccs_flags & CCS_CHECK_READ_FOR_OPEN_EXEC))
		return 0;
#endif
	if (!mnt || (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)))
		return 0;
	buf.name = NULL;
	r.mode = 0;
	idx = ccs_read_lock();
	/*
	 * If the filename is specified by "deny_rewrite" keyword,
	 * we need to check "allow_rewrite" permission when the filename is not
	 * opened for append mode or the filename is truncated at open time.
	 */
	if ((acc_mode & MAY_WRITE) && !(flag & O_APPEND)
	    && ccs_init_request_info(&r, NULL, CCS_MAC_FILE_REWRITE)
	    != CCS_CONFIG_DISABLED) {
		if (!ccs_get_realpath(&buf, dentry, mnt)) {
			error = -ENOMEM;
			goto out;
		}
		if (ccs_is_no_rewrite_file(&buf)) {
			r.obj = &obj;
			error = ccs_path_permission(&r, CCS_TYPE_REWRITE,
						    &buf);
		}
	}
	if (!error && acc_mode &&
	    ccs_init_request_info(&r, NULL, CCS_MAC_FILE_OPEN)
	    != CCS_CONFIG_DISABLED) {
		if (!buf.name && !ccs_get_realpath(&buf, dentry, mnt)) {
			error = -ENOMEM;
			goto out;
		}
		r.obj = &obj;
		error = ccs_file_perm(&r, &buf, acc_mode);
	}
	if (!error && (flag & O_TRUNC) &&
	    ccs_init_request_info(&r, NULL, CCS_MAC_FILE_TRUNCATE)
	    != CCS_CONFIG_DISABLED) {
		if (!buf.name && !ccs_get_realpath(&buf, dentry, mnt)) {
			error = -ENOMEM;
			goto out;
		}
		r.obj = &obj;
		error = ccs_path_permission(&r, CCS_TYPE_TRUNCATE, &buf);
	}
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (r.mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_path_perm - Check permission for "unlink", "rmdir", "truncate" and "symlink".
 *
 * @operation: Type of operation.
 * @dentry:    Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount".
 * @target:    Symlink's target if @operation is CCS_TYPE_SYMLINK.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_perm(const u8 operation, struct dentry *dentry,
			 struct vfsmount *mnt, const char *target)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1.dentry = dentry,
		.path1.mnt = mnt
	};
	int error = -ENOMEM;
	struct ccs_path_info buf;
	bool is_enforce = false;
	struct ccs_path_info symlink_target;
	int idx;
	buf.name = NULL;
	symlink_target.name = NULL;
	idx = ccs_read_lock();
	if (!mnt || ccs_init_request_info(&r, NULL, ccs_p2mac[operation])
	    == CCS_CONFIG_DISABLED) {
		error = 0;
		goto out;
	}
	is_enforce = (r.mode == CCS_CONFIG_ENFORCING);
	if (!ccs_get_realpath(&buf, dentry, mnt))
		goto out;
	r.obj = &obj;
	switch (operation) {
	case CCS_TYPE_RMDIR:
		ccs_add_slash(&buf);
		break;
	case CCS_TYPE_SYMLINK:
		symlink_target.name = ccs_encode(target);
		if (!symlink_target.name)
			goto out;
		ccs_fill_path_info(&symlink_target);
		obj.symlink_target = &symlink_target;
		break;
	}
	error = ccs_path_permission(&r, operation, &buf);
	if (operation == CCS_TYPE_SYMLINK)
		kfree(symlink_target.name);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_path_number3_perm - Check permission for "mkblock" and "mkchar".
 *
 * @operation: Type of operation. (CCS_TYPE_MKCHAR or CCS_TYPE_MKBLOCK)
 * @dentry:    Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount".
 ` @mode:      Create mode.
 * @dev:       Device number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_number3_perm(const u8 operation, struct dentry *dentry,
				 struct vfsmount *mnt, const unsigned int mode,
				 const unsigned int dev)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1.dentry = dentry,
		.path1.mnt = mnt,
		.dev = dev
	};
	int error = -ENOMEM;
	struct ccs_path_info buf;
	int idx;
	buf.name = NULL;
	idx = ccs_read_lock();
	if (!mnt || ccs_init_request_info(&r, NULL, ccs_pnnn2mac[operation])
	    == CCS_CONFIG_DISABLED) {
		error = 0;
		goto out;
	}
	if (!ccs_get_realpath(&buf, dentry, mnt))
		goto out;
	r.obj = &obj;
	error = ccs_path_number3_perm2(&r, operation, &buf, mode, dev);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (r.mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_rewrite_permission - Check permission for "rewrite".
 *
 * @filp: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_rewrite_permission(struct file *filp)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1.dentry = filp->f_dentry,
		.path1.mnt = filp->f_vfsmnt
	};
	int error = -ENOMEM;
	bool is_enforce = false;
	struct ccs_path_info buf;
	int idx;
	buf.name = NULL;
	idx = ccs_read_lock();
	if (!filp->f_vfsmnt ||
	    ccs_init_request_info(&r, NULL, CCS_MAC_FILE_REWRITE)
	    == CCS_CONFIG_DISABLED) {
		error = 0;
		goto out;
	}
	is_enforce = (r.mode == CCS_CONFIG_ENFORCING);
	if (!ccs_get_realpath(&buf, filp->f_dentry, filp->f_vfsmnt))
		goto out;
	if (!ccs_is_no_rewrite_file(&buf)) {
		error = 0;
		goto out;
	}
	r.obj = &obj;
	error = ccs_path_permission(&r, CCS_TYPE_REWRITE, &buf);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_path2_perm - Check permission for "rename" and "link".
 *
 * @operation: Type of operation.
 * @dentry1:   Pointer to "struct dentry".
 * @dentry2:   Pointer to "struct dentry".
 * @mnt:       Pointer to "struct vfsmount".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path2_perm(const u8 operation, struct dentry *dentry1,
			  struct dentry *dentry2, struct vfsmount *mnt)
{
	struct ccs_request_info r;
	int error = -ENOMEM;
	const char *msg = ccs_path22keyword(operation);
	struct ccs_path_info buf1;
	struct ccs_path_info buf2;
	bool is_enforce = false;
	struct ccs_obj_info obj = {
		.path1.dentry = dentry1,
		.path1.mnt = mnt,
		.path2.dentry = dentry2,
		.path2.mnt = mnt
	};
	int idx;
	buf1.name = NULL;
	buf2.name = NULL;
	idx = ccs_read_lock();
	if (!mnt || ccs_init_request_info(&r, NULL, ccs_pp2mac[operation])
	    == CCS_CONFIG_DISABLED) {
		error = 0;
		goto out;
	}
	is_enforce = (r.mode == CCS_CONFIG_ENFORCING);
	if (!ccs_get_realpath(&buf1, dentry1, mnt) ||
	    !ccs_get_realpath(&buf2, dentry2, mnt))
		goto out;
	if (operation == CCS_TYPE_RENAME) {
		/* CCS_TYPE_LINK can't reach here for directory. */
		if (dentry1->d_inode && S_ISDIR(dentry1->d_inode->i_mode)) {
			ccs_add_slash(&buf1);
			ccs_add_slash(&buf2);
		}
	}
	r.obj = &obj;
	do {
		error = ccs_path2_acl(&r, operation, &buf1, &buf2);
		ccs_audit_path2_log(&r, msg, buf1.name, buf2.name, !error);
		if (!error)
			break;
		error = ccs_supervisor(&r, "allow_%s %s %s\n", msg,
				       ccs_file_pattern(&buf1),
				       ccs_file_pattern(&buf2));
	} while (error == 1);
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
static inline int ccs_update_path_number_acl(const u8 type,
					     const char *filename,
					     char *number,
					     struct ccs_domain_info * const
					     domain,
					     struct ccs_condition *condition,
					     const bool is_delete)
{
	const u8 perm = 1 << type;
	struct ccs_acl_info *ptr;
	struct ccs_path_number_acl e = {
		.head.type = CCS_TYPE_PATH_NUMBER_ACL,
		.head.cond = condition,
		.perm = perm
	};
	struct ccs_path_number_acl *entry = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!domain)
		return -EINVAL;
	if (!ccs_parse_name_union(filename, &e.name))
		return -EINVAL;
	if (!ccs_parse_number_union(number, &e.number))
		goto out;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number_acl *acl =
			container_of(ptr, struct ccs_path_number_acl,
				     head);
		if (ptr->type != CCS_TYPE_PATH_NUMBER_ACL ||
		    ptr->cond != condition ||
		    ccs_memcmp(acl, &e, offsetof(typeof(e), name), sizeof(e)))
			continue;
		if (is_delete) {
			acl->perm &= ~perm;
			if (!acl->perm)
				ptr->is_deleted = true;
		} else {
			if (ptr->is_deleted)
				acl->perm = 0;
			acl->perm |= perm;
			ptr->is_deleted = false;
		}
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.name);
	ccs_put_number_union(&e.number);
	kfree(entry);
	return error;
}

/**
 * ccs_path_number_acl - Check permission for ioctl/chmod/chown/chgrp operation.
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
static int ccs_path_number_acl(struct ccs_request_info *r, const u8 type,
			       const struct ccs_path_info *filename,
			       const unsigned long number)
{
	struct ccs_domain_info *domain = r->domain;
	struct ccs_acl_info *ptr;
	const u8 perm = 1 << type;
	int error = -EPERM;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_path_number_acl *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_PATH_NUMBER_ACL)
			continue;
		acl = container_of(ptr, struct ccs_path_number_acl,
				   head);
		if (!(acl->perm & perm) || !ccs_condition(r, ptr) ||
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
 * ccs_path_number_perm2 - Check permission for "create", "mkdir", "mkfifo", "mksock", "ioctl", "chmod", "chown", "chgrp".
 *
 * @r:        Pointer to "strct ccs_request_info".
 * @filename: Filename to check.
 * @numr:     Number.
 *
 * Returns 0 on success, 1 on retry, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_path_number_perm2(struct ccs_request_info *r, const u8 type,
				 const struct ccs_path_info *filename,
				 const unsigned long number)
{
	char buffer[64];
	int error;
	u8 radix;
	const char *msg = ccs_path_number2keyword(type);
	if (!filename)
		return 0;
	switch (type) {
	case CCS_TYPE_CREATE:
	case CCS_TYPE_MKDIR:
	case CCS_TYPE_MKFIFO:
	case CCS_TYPE_MKSOCK:
	case CCS_TYPE_CHMOD:
		radix = CCS_VALUE_TYPE_OCTAL;
		break;
	case CCS_TYPE_IOCTL:
		radix = CCS_VALUE_TYPE_HEXADECIMAL;
		break;
	default:
		radix = CCS_VALUE_TYPE_DECIMAL;
		break;
	}
	ccs_print_ulong(buffer, sizeof(buffer), number, radix);
	do {
		error = ccs_path_number_acl(r, type, filename, number);
		ccs_audit_path_number_log(r, msg, filename->name, buffer,
					  !error);
		if (!error)
			return 0;
		error = ccs_supervisor(r, "allow_%s %s %s\n", msg,
				       ccs_file_pattern(filename), buffer);
	} while (error == 1);
	if (r->mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_path_number_perm - Check permission for "create", "mkdir", "mkfifo", "mksock", "ioctl", "chmod", "chown", "chgrp".
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 * @number: Number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_number_perm(const u8 type, struct dentry *dentry,
				struct vfsmount *vfsmnt, unsigned long number)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1.dentry = dentry,
		.path1.mnt = vfsmnt
	};
	int error = -ENOMEM;
	struct ccs_path_info buf;
	int idx;
	if (!vfsmnt || !dentry)
		return 0;
	buf.name = NULL;
	idx = ccs_read_lock();
	if (ccs_init_request_info(&r, NULL, ccs_pn2mac[type])
	    == CCS_CONFIG_DISABLED) {
		error = 0;
		goto out;
	}
	if (!ccs_get_realpath(&buf, dentry, vfsmnt))
		goto out;
	r.obj = &obj;
	if (type == CCS_TYPE_MKDIR)
		ccs_add_slash(&buf);
	error = ccs_path_number_perm2(&r, type, &buf, number);
 out:
	kfree(buf.name);
	ccs_read_unlock(idx);
	if (r.mode != CCS_CONFIG_ENFORCING)
		error = 0;
	return error;
}

/**
 * ccs_ioctl_permission - Check permission for "ioctl".
 *
 * @file: Pointer to "struct file".
 * @cmd:  Ioctl command number.
 * @arg:  Param for @cmd .
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_ioctl_permission(struct file *filp, unsigned int cmd,
			 unsigned long arg)
{
	return ccs_path_number_perm(CCS_TYPE_IOCTL, filp->f_dentry,
				    filp->f_vfsmnt, cmd);
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
	return ccs_path_number_perm(CCS_TYPE_CHMOD, dentry, vfsmnt,
				    mode & S_IALLUGO);
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
		error = ccs_path_number_perm(CCS_TYPE_CHOWN, dentry, vfsmnt,
					     user);
	if (!error && group != (gid_t) -1)
		error = ccs_path_number_perm(CCS_TYPE_CHGRP, dentry, vfsmnt,
					     group);
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
	char *w[5];
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
	for (type = 0; type < CCS_MAX_PATH_OPERATION; type++) {
		if (strcmp(w[0], ccs_path_keyword[type]))
			continue;
		return ccs_update_path_acl(type, w[1], domain, condition,
					   is_delete);
	}
	if (!w[2][0])
		goto out;
	for (type = 0; type < CCS_MAX_PATH2_OPERATION; type++) {
		if (strcmp(w[0], ccs_path2_keyword[type]))
			continue;
		return ccs_update_path2_acl(type, w[1], w[2], domain,
					    condition, is_delete);
	}
	for (type = 0; type < CCS_MAX_PATH_NUMBER_OPERATION; type++) {
		if (strcmp(w[0], ccs_path_number_keyword[type]))
			continue;
		return ccs_update_path_number_acl(type, w[1], w[2], domain,
						  condition, is_delete);
	}
	if (!w[3][0] || !w[4][0])
		goto out;
	for (type = 0; type < CCS_MAX_PATH_NUMBER3_OPERATION; type++) {
		if (strcmp(w[0], ccs_path_number3_keyword[type]))
			continue;
		return ccs_update_path_number3_acl(type, w[1], w[2], w[3],
						   w[4], domain, condition,
						   is_delete);
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

/* Permission checks from vfs_create(). */
static int ccs_pre_vfs_create(struct inode *dir, struct dentry *dentry)
{
	int error = ccs_may_create(dir, dentry, 0);
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
	int error = ccs_may_create(dir, dentry, 0);
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
	int error = ccs_may_create(dir, dentry, 1);
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
	error = ccs_may_create(dir, new_dentry, 0);
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
	int error = ccs_may_create(dir, dentry, 0);
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
	if (!new_dentry->d_inode)
		error = ccs_may_create(new_dir, new_dentry, is_dir);
	else
		error = ccs_may_delete(new_dir, new_dentry, is_dir);
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
int ccs_mknod_permission(struct inode *dir, struct dentry *dentry,
			 struct vfsmount *mnt, const unsigned int mode,
			 unsigned int dev)
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
			error = ccs_path_number_perm(CCS_TYPE_CREATE, dentry,
						     mnt, mode & S_IALLUGO);
		return error;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
	error = ccs_pre_vfs_mknod(dir, dentry);
#else
	error = ccs_pre_vfs_mknod(dir, dentry, mode);
	dev = new_decode_dev(dev);
#endif
	if (error)
		return error;
	switch (mode & S_IFMT) {
	case S_IFCHR:
		error = ccs_path_number3_perm(CCS_TYPE_MKCHAR, dentry, mnt,
					      mode & S_IALLUGO, dev);
		break;
	case S_IFBLK:
		error = ccs_path_number3_perm(CCS_TYPE_MKBLOCK, dentry, mnt,
					      mode & S_IALLUGO, dev);
		break;
	case S_IFIFO:
		error = ccs_path_number_perm(CCS_TYPE_MKFIFO, dentry, mnt,
					     mode & S_IALLUGO);
		break;
	case S_IFSOCK:
		error = ccs_path_number_perm(CCS_TYPE_MKSOCK, dentry, mnt,
					     mode & S_IALLUGO);
		break;
	}
	return error;
}
EXPORT_SYMBOL(ccs_mknod_permission);

/* Permission checks for vfs_mkdir(). */
int ccs_mkdir_permission(struct inode *dir, struct dentry *dentry,
			 struct vfsmount *mnt, unsigned int mode)
{
	int error = ccs_pre_vfs_mkdir(dir, dentry);
	if (!error)
		error = ccs_path_number_perm(CCS_TYPE_MKDIR, dentry, mnt,
					     mode);
	return error;
}

/* Permission checks for vfs_rmdir(). */
int ccs_rmdir_permission(struct inode *dir, struct dentry *dentry,
			 struct vfsmount *mnt)
{
	int error = ccs_pre_vfs_rmdir(dir, dentry);
	if (!error)
		error = ccs_path_perm(CCS_TYPE_RMDIR, dentry, mnt,
				      NULL);
	return error;
}

/* Permission checks for vfs_unlink(). */
int ccs_unlink_permission(struct inode *dir, struct dentry *dentry,
			  struct vfsmount *mnt)
{
	int error;
	if (!ccs_capable(CCS_SYS_UNLINK))
		return -EPERM;
	error = ccs_pre_vfs_unlink(dir, dentry);
	if (!error)
		error = ccs_path_perm(CCS_TYPE_UNLINK, dentry, mnt,
				      NULL);
	return error;
}

/* Permission checks for vfs_symlink(). */
int ccs_symlink_permission(struct inode *dir, struct dentry *dentry,
			   struct vfsmount *mnt, char *from)
{
	int error;
	if (!ccs_capable(CCS_SYS_SYMLINK))
		return -EPERM;
	error = ccs_pre_vfs_symlink(dir, dentry);
	if (!error)
		error = ccs_path_perm(CCS_TYPE_SYMLINK, dentry, mnt,
				      from);
	return error;
}

/* Permission checks for notify_change(). */
int ccs_truncate_permission(struct dentry *dentry, struct vfsmount *mnt,
			    loff_t length, unsigned int time_attrs)
{
	return ccs_path_perm(CCS_TYPE_TRUNCATE, dentry, mnt, NULL);
}

/* Permission checks for vfs_rename(). */
int ccs_rename_permission(struct inode *old_dir,
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
		error = ccs_path2_perm(CCS_TYPE_RENAME, old_dentry,
				       new_dentry, mnt);
	return error;
}

/* Permission checks for vfs_link(). */
int ccs_link_permission(struct dentry *old_dentry, struct inode *new_dir,
			struct dentry *new_dentry, struct vfsmount *mnt)
{
	int error;
	if (!ccs_capable(CCS_SYS_LINK))
		return -EPERM;
	error = ccs_pre_vfs_link(old_dentry, new_dir, new_dentry);
	if (!error)
		error = ccs_path2_perm(CCS_TYPE_LINK, old_dentry,
				       new_dentry, mnt);
	return error;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
/* Permission checks for open_exec(). */
int ccs_open_exec_permission(struct dentry *dentry, struct vfsmount *mnt)
{
	return (current->ccs_flags & CCS_CHECK_READ_FOR_OPEN_EXEC) ?
		/* 01 means "read". */
		ccs_open_permission(dentry, mnt, 01) : 0;
}

/* Permission checks for sys_uselib(). */
int ccs_uselib_permission(struct dentry *dentry, struct vfsmount *mnt)
{
	/* 01 means "read". */
	return ccs_open_permission(dentry, mnt, 01);
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
	char *buffer = NULL;
	struct ccs_request_info r;
	int idx;
	if (oldval)
		op |= 004;
	if (newval)
		op |= 002;
	if (!op) /* Neither read nor write */
		return 0;
	idx = ccs_read_lock();
	if (ccs_init_request_info(&r, NULL, CCS_MAC_FILE_OPEN)
	    == CCS_CONFIG_DISABLED) {
		error = 0;
		goto out;
	}
	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer)
		goto out;
	snprintf(buffer, PAGE_SIZE - 1, "/proc/sys");
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
			int len = strlen(cp);
			if (len + 2 > PAGE_SIZE - 1)
				goto out;
			buffer[pos++] = '/';
			memmove(buffer + pos, cp, len + 1);
		} else {
			/* Assume nobody assigns "=\$=" for procname. */
			snprintf(buffer + pos, PAGE_SIZE - pos - 1,
				 "/=%d=", table->ctl_name);
			if (!memchr(buffer, '\0', PAGE_SIZE - 2))
				goto out;
		}
		if (table->child) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
			if (table->strategy) {
				/* printk("sysctl='%s'\n", buffer); */
				buf.name = ccs_encode(buffer);
				if (buf.name) {
					ccs_fill_path_info(&buf);
					error = ccs_file_perm(&r, &buf, op);
					kfree(buf.name);
				}
				if (error)
					goto out;
			}
#endif
			name++;
			nlen--;
			table = table->child;
			goto repeat;
		}
		/* printk("sysctl='%s'\n", buffer); */
		buf.name = ccs_encode(buffer);
		if (buf.name) {
			ccs_fill_path_info(&buf);
			error = ccs_file_perm(&r, &buf, op);
			kfree(buf.name);
		}
		goto out;
	}
	error = -ENOTDIR;
 out:
	ccs_read_unlock(idx);
	kfree(buffer);
	return error;
}
#endif
