/*
 * fs/sakura_umount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.2-pre   2008/06/07
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
#include <linux/mount.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namespace.h>
#endif

/* Structure for "deny_unmount" keyword. */
struct no_umount_entry {
	struct list1_head list;
	const struct path_info *dir;
	bool is_deleted;
};

/* The list for "struct no_umount_entry". */
static LIST1_HEAD(no_umount_list);

/**
 * update_no_umount_acl - Update "struct no_umount_entry" list.
 *
 * @dir:       The name of directrory.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_no_umount_acl(const char *dir, const bool is_delete)
{
	struct no_umount_entry *new_entry;
	struct no_umount_entry *ptr;
	const struct path_info *saved_dir;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if (!ccs_is_correct_path(dir, 1, 0, 1, __func__))
		return -EINVAL;
	saved_dir = ccs_save_name(dir);
	if (!saved_dir)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &no_umount_list, list) {
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
	list1_add_tail_mb(&new_entry->list, &no_umount_list);
	error = 0;
	printk(KERN_CONT "%sDon't allow umount %s\n", ccs_log_level, dir);
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
	return error;
}

/**
 * ccs_may_umount - Check permission for unmount.
 *
 * @mnt: Pointer to "struct vfsmount".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_may_umount(struct vfsmount *mnt)
{
	int error = -EPERM;
	const char *dir0;
	const u8 mode = ccs_check_flags(CCS_SAKURA_RESTRICT_UNMOUNT);
	const bool is_enforce = (mode == 3);
	struct no_umount_entry *ptr;
	struct path_info dir;
	bool found = false;
	if (!mode)
		return 0;
	dir0 = ccs_realpath_from_dentry(mnt->mnt_root, mnt);
	if (!dir0)
		goto out;
	dir.name = dir0;
	ccs_fill_path_info(&dir);
	list1_for_each_entry(ptr, &no_umount_list, list) {
		if (ptr->is_deleted)
			continue;
		if (!ccs_path_matches_pattern(&dir, ptr->dir))
			continue;
		found = true;
		break;
	}
	if (found) {
		const char *exename = ccs_get_exe();
		printk(KERN_WARNING "SAKURA-%s: umount %s "
		       "(pid=%d:exe=%s): Permission denied.\n",
		       ccs_get_msg(is_enforce), dir0, current->pid,
		       exename);
		if (is_enforce)
			error = ccs_check_supervisor(NULL,
						     "# %s is requesting\n"
						     "unmount %s\n",
						     exename, dir0);
		ccs_free(exename);
	}
	ccs_free(dir0);
 out:
	if (!is_enforce)
		error = 0;
	return error;
}

/**
 * ccs_write_no_umount_policy - Write "struct no_umount_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on sucess, negative value otherwise.
 */
int ccs_write_no_umount_policy(char *data, const bool is_delete)
{
	return update_no_umount_acl(data, is_delete);
}

/**
 * ccs_read_no_umount_policy - Read "struct no_umount_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_no_umount_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &no_umount_list) {
		struct no_umount_entry *ptr;
		ptr = list1_entry(pos, struct no_umount_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_DENY_UNMOUNT "%s\n",
				   ptr->dir->name))
			goto out;
	}
	return true;
 out:
	return false;
}
