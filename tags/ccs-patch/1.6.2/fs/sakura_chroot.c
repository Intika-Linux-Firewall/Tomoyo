/*
 * fs/sakura_chroot.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.2   2008/06/25
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

/* Structure for "allow_chroot" keyword. */
struct chroot_entry {
	struct list1_head list;
	const struct path_info *dir;
	bool is_deleted;
};

/* The list for "struct chroot_entry". */
static LIST1_HEAD(chroot_list);

/**
 * update_chroot_acl - Update "struct chroot_entry" list.
 *
 * @dir:       The name of directory.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_chroot_acl(const char *dir, const bool is_delete)
{
	struct chroot_entry *new_entry;
	struct chroot_entry *ptr;
	const struct path_info *saved_dir;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if (!ccs_is_correct_path(dir, 1, 0, 1, __func__))
		return -EINVAL;
	saved_dir = ccs_save_name(dir);
	if (!saved_dir)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &chroot_list, list) {
		if (ptr->dir != saved_dir)
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
	new_entry->dir = saved_dir;
	list1_add_tail_mb(&new_entry->list, &chroot_list);
	error = 0;
	printk(KERN_CONT "%sAllow chroot() to %s\n", ccs_log_level, dir);
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
	return error;
}

/**
 * print_error - Print error message.
 *
 * @root_name: Requested directory name.
 * @mode:      Access control mode.
 *
 * Returns 0 if @mode is not enforcing mode or permitted by the administrator's
 * decision, negative value otherwise.
 */
static int print_error(const char *root_name, const u8 mode)
{
	int error;
	const bool is_enforce = (mode == 3);
	const char *exename = ccs_get_exe();
	printk(KERN_WARNING "SAKURA-%s: chroot %s (pid=%d:exe=%s): "
	       "Permission denied.\n", ccs_get_msg(is_enforce),
	       root_name, current->pid, exename);
	if (is_enforce)
		error = ccs_check_supervisor(NULL, "# %s is requesting\n"
					     "chroot %s\n", exename, root_name);
	else
		error = 0;
	if (exename)
		ccs_free(exename);
	if (mode == 1 && root_name)
		update_chroot_acl(root_name, false);
	return error;
}

/**
 * ccs_check_chroot_permission - Check permission for chroot().
 *
 * @nd: Pointer to "struct nameidata".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_chroot_permission(struct nameidata *nd)
{
	int error = -EPERM;
	char *root_name;
	const u8 mode = ccs_check_flags(CCS_SAKURA_RESTRICT_CHROOT);
	if (!mode)
		return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	root_name = ccs_realpath_from_dentry(nd->path.dentry, nd->path.mnt);
#else
	root_name = ccs_realpath_from_dentry(nd->dentry, nd->mnt);
#endif
	if (root_name) {
		struct path_info dir;
		dir.name = root_name;
		ccs_fill_path_info(&dir);
		if (dir.is_dir) {
			struct chroot_entry *ptr;
			list1_for_each_entry(ptr, &chroot_list, list) {
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
		error = print_error(root_name, mode);
	ccs_free(root_name);
	return error;
}

/**
 * ccs_write_chroot_policy - Write "struct chroot_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_chroot_policy(char *data, const bool is_delete)
{
	return update_chroot_acl(data, is_delete);
}

/**
 * ccs_read_chroot_policy - Read "struct chroot_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_chroot_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &chroot_list) {
		struct chroot_entry *ptr;
		ptr = list1_entry(pos, struct chroot_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_ALLOW_CHROOT "%s\n",
				   ptr->dir->name))
			goto out;
	}
	return true;
 out:
	return false;
}
