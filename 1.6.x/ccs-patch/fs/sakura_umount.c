/*
 * fs/sakura_umount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/04/01
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
struct ccs_no_umount_entry {
	struct list1_head list;
	const struct ccs_path_info *dir;
	bool is_deleted;
};

/* The list for "struct ccs_no_umount_entry". */
static LIST1_HEAD(ccs_no_umount_list);

/**
 * ccs_update_no_umount_acl - Update "struct ccs_no_umount_entry" list.
 *
 * @dir:       The name of directrory.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_no_umount_acl(const char *dir, const bool is_delete)
{
	struct ccs_no_umount_entry *new_entry;
	struct ccs_no_umount_entry *ptr;
	const struct ccs_path_info *saved_dir;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if (!ccs_is_correct_path(dir, 1, 0, 0, __func__))
		return -EINVAL;
	saved_dir = ccs_save_name(dir);
	if (!saved_dir)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_no_umount_list, list) {
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
	list1_add_tail_mb(&new_entry->list, &ccs_no_umount_list);
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
	struct ccs_request_info r;
	int error;
	const char *dir0;
	bool is_enforce;
	struct ccs_no_umount_entry *ptr;
	struct ccs_path_info dir;
	bool found = false;
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_RESTRICT_UNMOUNT);
	is_enforce = (r.mode == 3);
	if (!r.mode)
		return 0;
 retry:
	error = -EPERM;
	dir0 = ccs_realpath_from_dentry(mnt->mnt_root, mnt);
	if (!dir0)
		goto out;
	dir.name = dir0;
	ccs_fill_path_info(&dir);
	list1_for_each_entry(ptr, &ccs_no_umount_list, list) {
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
		       ccs_get_msg(is_enforce), dir0, (pid_t) sys_getpid(),
		       exename);
		if (is_enforce)
			error = ccs_check_supervisor(&r, "# %s is requesting\n"
						     "unmount %s\n",
						     exename, dir0);
		ccs_free(exename);
	} else
		error = 0;
	ccs_free(dir0);
 out:
	if (!is_enforce)
		error = 0;
	if (error == 1)
		goto retry;
	return error;
}

/**
 * ccs_write_no_umount_policy - Write "struct ccs_no_umount_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on sucess, negative value otherwise.
 */
int ccs_write_no_umount_policy(char *data, const bool is_delete)
{
	return ccs_update_no_umount_acl(data, is_delete);
}

/**
 * ccs_read_no_umount_policy - Read "struct ccs_no_umount_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_no_umount_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &ccs_no_umount_list) {
		struct ccs_no_umount_entry *ptr;
		ptr = list1_entry(pos, struct ccs_no_umount_entry, list);
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
