/*
 * fs/sakura_umount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.4.1   2007/06/05
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
	struct no_umount_entry *next;
	const struct path_info *dir;
	int is_deleted;
};

/*************************  UMOUNT RESTRICTION HANDLER  *************************/

static struct no_umount_entry *no_umount_list = NULL;

static int AddNoUmountACL(const char *dir, const int is_delete)
{
	struct no_umount_entry *new_entry, *ptr;
	const struct path_info *saved_dir;
	static DECLARE_MUTEX(lock);
	int error = -ENOMEM;
	if (!IsCorrectPath(dir, 1, 0, 1, __FUNCTION__)) return -EINVAL;
	if ((saved_dir = SaveName(dir)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = no_umount_list; ptr; ptr = ptr->next) {
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
	mb(); /* Instead of using spinlock. */
	if ((ptr = no_umount_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		no_umount_list = new_entry;
	}
	error = 0;
	printk("%sDon't allow umount %s\n", ccs_log_level, dir);
 out:
	up(&lock);
	return error;
}

int SAKURA_MayUmount(struct vfsmount *mnt)
{
	int error = -EPERM;
	const char *dir0;
	const int is_enforce = CheckCCSEnforce(CCS_SAKURA_RESTRICT_UNMOUNT);
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_UNMOUNT)) return 0;
	dir0 = realpath_from_dentry(mnt->mnt_root, mnt);
	if (dir0) {
		struct no_umount_entry *ptr;
		struct path_info dir;
		dir.name = dir0;
		fill_path_info(&dir);
		for (ptr = no_umount_list; ptr; ptr = ptr->next) {
			if (ptr->is_deleted) continue;
			if (PathMatchesToPattern(&dir, ptr->dir)) break;
		}
		if (ptr) {
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

int AddNoUmountPolicy(char *data, const int is_delete)
{
	return AddNoUmountACL(data, is_delete);
}

int ReadNoUmountPolicy(struct io_buffer *head)
{
	struct no_umount_entry *ptr = head->read_var2;
	if (!ptr) ptr = no_umount_list;
	while (ptr) {
		head->read_var2 = ptr;
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_DENY_UNMOUNT "%s\n", ptr->dir->name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

/***** SAKURA Linux end. *****/
