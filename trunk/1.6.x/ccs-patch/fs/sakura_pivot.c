/*
 * fs/sakura_pivot.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.6.9   2011/04/01
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

/* Structure for "allow_pivot_root" keyword. */
struct ccs_pivot_root_entry {
	struct list1_head list;
	const struct ccs_path_info *old_root;
	const struct ccs_path_info *new_root;
	bool is_deleted;
};

/* The list for "struct ccs_pivot_root_entry". */
static LIST1_HEAD(ccs_pivot_root_list);

/**
 * ccs_update_pivot_root_acl - Update "struct ccs_pivot_root_entry" list.
 *
 * @old_root:  The name of old root directory.
 * @new_root:  The name of new root directory.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_pivot_root_acl(const char *old_root, const char *new_root,
				     const bool is_delete)
{
	struct ccs_pivot_root_entry *new_entry;
	struct ccs_pivot_root_entry *ptr;
	const struct ccs_path_info *saved_old_root;
	const struct ccs_path_info *saved_new_root;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if (!ccs_is_correct_path(old_root, 1, 0, 1, __func__) ||
	    !ccs_is_correct_path(new_root, 1, 0, 1, __func__))
		return -EINVAL;
	saved_old_root = ccs_save_name(old_root);
	saved_new_root = ccs_save_name(new_root);
	if (!saved_old_root || !saved_new_root)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_pivot_root_list, list) {
		if (ptr->old_root != saved_old_root ||
		    ptr->new_root != saved_new_root)
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
	new_entry->old_root = saved_old_root;
	new_entry->new_root = saved_new_root;
	list1_add_tail_mb(&new_entry->list, &ccs_pivot_root_list);
	error = 0;
	printk(KERN_CONT "%sAllow pivot_root(%s, %s)\n", ccs_log_level,
	       new_root, old_root);
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#define PATH_or_NAMEIDATA path
#else
#define PATH_or_NAMEIDATA nameidata
#endif
/**
 * ccs_check_pivot_root_permission - Check permission for pivot_root().
 *
 * @old_path: Pointer to "struct path" (for 2.6.27 and later).
 *            Pointer to "struct nameidata" (for 2.6.26 and earlier).
 * @new_path: Pointer to "struct path" (for 2.6.27 and later).
 *            Pointer to "struct nameidata" (for 2.6.26 and earlier).
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_pivot_root_permission(struct PATH_or_NAMEIDATA *old_path,
				    struct PATH_or_NAMEIDATA *new_path)
{
	struct ccs_request_info r;
	int error;
	char *old_root;
	char *new_root;
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_RESTRICT_PIVOT_ROOT);
	if (!r.mode)
		return 0;
 retry:
	error = -EPERM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
	old_root = ccs_realpath_from_dentry(old_path->path.dentry,
					    old_path->path.mnt);
	new_root = ccs_realpath_from_dentry(new_path->path.dentry,
					    new_path->path.mnt);
#else
	old_root = ccs_realpath_from_dentry(old_path->dentry, old_path->mnt);
	new_root = ccs_realpath_from_dentry(new_path->dentry, new_path->mnt);
#endif
	if (old_root && new_root) {
		struct ccs_path_info old_root_dir;
		struct ccs_path_info new_root_dir;
		old_root_dir.name = old_root;
		ccs_fill_path_info(&old_root_dir);
		new_root_dir.name = new_root;
		ccs_fill_path_info(&new_root_dir);
		if (old_root_dir.is_dir && new_root_dir.is_dir) {
			struct ccs_pivot_root_entry *ptr;
			list1_for_each_entry(ptr, &ccs_pivot_root_list, list) {
				if (ptr->is_deleted)
					continue;
				if (!ccs_path_matches_pattern(&old_root_dir,
							      ptr->old_root) ||
				    !ccs_path_matches_pattern(&new_root_dir,
							      ptr->new_root))
					continue;
				error = 0;
				break;
			}
		}
	}
	if (error) {
		const bool is_enforce = (r.mode == 3);
		const char *exename = ccs_get_exe();
		printk(KERN_WARNING "SAKURA-%s: pivot_root %s %s "
		       "(pid=%d:exe=%s): Permission denied.\n",
		       ccs_get_msg(is_enforce), new_root, old_root,
		       (pid_t) sys_getpid(), exename);
		if (is_enforce)
			error = ccs_check_supervisor(&r, "# %s is requesting\n"
						     "pivot_root %s %s\n",
						     exename, new_root,
						     old_root);
		else
			error = 0;
		if (exename)
			ccs_free(exename);
		if (r.mode == 1 && old_root && new_root)
			ccs_update_pivot_root_acl(old_root, new_root, false);
	}
	ccs_free(old_root);
	ccs_free(new_root);
	if (error == 1)
		goto retry;
	return error;
}

/**
 * ccs_write_pivot_root_policy - Write "struct ccs_pivot_root_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_pivot_root_policy(char *data, const bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return ccs_update_pivot_root_acl(cp, data, is_delete);
}

/**
 * ccs_read_pivot_root_policy - Read "struct ccs_pivot_root_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_pivot_root_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &ccs_pivot_root_list) {
		struct ccs_pivot_root_entry *ptr;
		ptr = list1_entry(pos, struct ccs_pivot_root_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_ALLOW_PIVOT_ROOT "%s %s\n",
				   ptr->new_root->name, ptr->old_root->name))
			goto out;
	}
	return true;
 out:
	return false;
}
