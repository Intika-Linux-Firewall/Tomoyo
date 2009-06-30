/*
 * fs/sakura_chroot.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/05/28
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#else
#include <linux/fs.h>
#endif

/* The list for "struct ccs_chroot_entry". */
LIST_HEAD(ccs_chroot_list);

/**
 * ccs_update_chroot_acl - Update "struct ccs_chroot_entry" list.
 *
 * @dir:       The name of directory.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_chroot_acl(const char *dir, const bool is_delete)
{
	struct ccs_chroot_entry *entry = NULL;
	struct ccs_chroot_entry *ptr;
	const struct ccs_path_info *saved_dir;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(dir, 1, 0, 1))
		return -EINVAL;
	saved_dir = ccs_get_name(dir);
	if (!saved_dir)
		return -ENOMEM;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_chroot_list, list) {
		if (ptr->dir != saved_dir)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry)) {
		entry->dir = saved_dir;
		saved_dir = NULL;
		list_add_tail_rcu(&entry->list, &ccs_chroot_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	if (!is_delete && !error)
		printk(KERN_CONT "%sAllow chroot() to %s\n", ccs_log_level,
		       dir);
	ccs_put_name(saved_dir);
	kfree(entry);
	return error;
}

/**
 * ccs_print_error - Print error message.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @root_name: Requested directory name.
 *
 * Returns 0 if @r->mode is not enforcing mode or permitted by the
 * administrator's decision, negative value otherwise.
 */
static int ccs_print_error(struct ccs_request_info *r, const char *root_name)
{
	int error;
	const bool is_enforce = (r->mode == 3);
	const char *exename = ccs_get_exe();
	printk(KERN_WARNING "SAKURA-%s: chroot %s (pid=%d:exe=%s): "
	       "Permission denied.\n", ccs_get_msg(is_enforce),
	       root_name, (pid_t) sys_getpid(), exename);
	if (is_enforce)
		error = ccs_check_supervisor(r,
					     "# %s is requesting\nchroot %s\n",
					     exename, root_name);
	else
		error = 0;
	if (exename)
		ccs_free(exename);
	if (r->mode == 1 && root_name)
		ccs_update_chroot_acl(root_name, false);
	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#define PATH_or_NAMEIDATA path
#else
#define PATH_or_NAMEIDATA nameidata
#endif
/**
 * ccs_check_chroot_permission2 - Check permission for chroot().
 *
 * @path: Pointer to "struct path" (for 2.6.27 and later).
 *        Pointer to "struct nameidata" (for 2.6.26 and earlier).
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds srcu_read_lock(&ccs_ss).
 */
static int ccs_check_chroot_permission2(struct PATH_or_NAMEIDATA *path)
{
	struct ccs_request_info r;
	int error;
	char *root_name;
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_RESTRICT_CHROOT);
	if (!r.mode)
		return 0;
 retry:
	error = -EPERM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
	root_name = ccs_realpath_from_dentry(path->path.dentry, path->path.mnt);
#else
	root_name = ccs_realpath_from_dentry(path->dentry, path->mnt);
#endif
	if (root_name) {
		struct ccs_path_info dir;
		dir.name = root_name;
		ccs_fill_path_info(&dir);
		if (dir.is_dir) {
			struct ccs_chroot_entry *ptr;
			list_for_each_entry_rcu(ptr, &ccs_chroot_list, list) {
				if (ptr->is_deleted)
					continue;
				if (!ccs_path_matches_pattern(&dir, ptr->dir))
					continue;
				error = 0;
				break;
			}
		}
	}
	if (error)
		error = ccs_print_error(&r, root_name);
	ccs_free(root_name);
	if (error == 1)
		goto retry;
	return error;
}

/**
 * ccs_check_chroot_permission - Check permission for chroot().
 *
 * @path: Pointer to "struct path" (for 2.6.27 and later).
 *        Pointer to "struct nameidata" (for 2.6.26 and earlier).
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_chroot_permission(struct PATH_or_NAMEIDATA *path)
{
	const int idx = srcu_read_lock(&ccs_ss);
	const int error = ccs_check_chroot_permission2(path);
	srcu_read_unlock(&ccs_ss, idx);
	return error;
}

/**
 * ccs_write_chroot_policy - Write "struct ccs_chroot_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_chroot_policy(char *data, const bool is_delete)
{
	return ccs_update_chroot_acl(data, is_delete);
}

/**
 * ccs_read_chroot_policy - Read "struct ccs_chroot_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds srcu_read_lock(&ccs_ss).
 */
bool ccs_read_chroot_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	list_for_each_cookie(pos, head->read_var2, &ccs_chroot_list) {
		struct ccs_chroot_entry *ptr;
		ptr = list_entry(pos, struct ccs_chroot_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_ALLOW_CHROOT "%s\n",
				   ptr->dir->name))
			return false;
	}
	return true;
}
