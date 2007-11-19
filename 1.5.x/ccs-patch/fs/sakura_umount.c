/*
 * fs/sakura_umount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.5.2-pre   2007/11/19
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/mount.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <linux/namespace.h>
#endif

extern const char *ccs_log_level;

/***** The structure for unmount restrictions. *****/

struct no_umount_entry {
	struct list_head list;
	const struct path_info *dir;
	bool is_deleted;
};

/*************************  UMOUNT RESTRICTION HANDLER  *************************/

static LIST_HEAD(no_umount_list);

static int AddNoUmountACL(const char *dir, const bool is_delete)
{
	struct no_umount_entry *new_entry, *ptr;
	const struct path_info *saved_dir;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if (!IsCorrectPath(dir, 1, 0, 1, __FUNCTION__)) return -EINVAL;
	if ((saved_dir = SaveName(dir)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list_for_each_entry(ptr, &no_umount_list, list) {
		if (ptr->dir == saved_dir) {
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
	new_entry->dir = saved_dir;
	list_add_tail_mb(&new_entry->list, &no_umount_list);
	error = 0;
	printk("%sDon't allow umount %s\n", ccs_log_level, dir);
 out:
	mutex_unlock(&lock);
	return error;
}

int SAKURA_MayUmount(struct vfsmount *mnt)
{
	int error = -EPERM;
	const char *dir0;
	const bool is_enforce = CheckCCSEnforce(CCS_SAKURA_RESTRICT_UNMOUNT);
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_UNMOUNT)) return 0;
	dir0 = realpath_from_dentry(mnt->mnt_root, mnt);
	if (dir0) {
		struct no_umount_entry *ptr;
		struct path_info dir;
		bool found = 0;
		dir.name = dir0;
		fill_path_info(&dir);
		list_for_each_entry(ptr, &no_umount_list, list) {
			if (ptr->is_deleted) continue;
			if (PathMatchesToPattern(&dir, ptr->dir)) {
				found = 1;
				break;
			}
		}
		if (found) {
			const char *exename = GetEXE();
			printk("SAKURA-%s: umount %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), dir0, current->pid, exename);
			if (is_enforce && CheckSupervisor("# %s is requesting\nunmount %s\n", exename, dir0) == 0) error = 0;
			ccs_free(exename);
		} else {
			error = 0;
		}
		ccs_free(dir0);
	}
	if (!is_enforce) error = 0;
	return error;
}
EXPORT_SYMBOL(SAKURA_MayUmount);

int AddNoUmountPolicy(char *data, const bool is_delete)
{
	return AddNoUmountACL(data, is_delete);
}

int ReadNoUmountPolicy(struct io_buffer *head)
{
	struct list_head *pos;
	list_for_each_cookie(pos, head->read_var2, &no_umount_list) {
		struct no_umount_entry *ptr;
		ptr = list_entry(pos, struct no_umount_entry, list);
		if (ptr->is_deleted) continue;
		if (io_printf(head, KEYWORD_DENY_UNMOUNT "%s\n", ptr->dir->name)) return -ENOMEM;
	}
	return 0;
}

/***** SAKURA Linux end. *****/
