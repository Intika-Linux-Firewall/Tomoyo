/*
 * fs/sakura_chroot.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.0-pre   2008/02/16
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <linux/namei.h>
#else
#include <linux/fs.h>
#endif

extern const char *ccs_log_level;

/***** The structure for chroot restrictions. *****/

struct chroot_entry {
	struct list1_head list;
	const struct path_info *dir;
	bool is_deleted;
};

/*************************  CHROOT RESTRICTION HANDLER  *************************/

static LIST1_HEAD(chroot_list);

static int AddChrootACL(const char *dir, const bool is_delete)
{
	struct chroot_entry *new_entry, *ptr;
	const struct path_info *saved_dir;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if (!IsCorrectPath(dir, 1, 0, 1, __FUNCTION__)) return -EINVAL;
	if ((saved_dir = SaveName(dir)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &chroot_list, list) {
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
	list1_add_tail_mb(&new_entry->list, &chroot_list);
	error = 0;
	printk("%sAllow chroot() to %s\n", ccs_log_level, dir);
 out:
	mutex_unlock(&lock);
	return error;
}

int CheckChRootPermission(struct nameidata *nd)
{
	int error = -EPERM;
	char *root_name;
	const u8 mode = CheckCCSFlags(CCS_SAKURA_RESTRICT_CHROOT); 
	if (!mode) return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,25)
	root_name = realpath_from_dentry(nd->path.dentry, nd->path.mnt);
#else
	root_name = realpath_from_dentry(nd->dentry, nd->mnt);
#endif
	if (root_name) {
		struct path_info dir;
		dir.name = root_name;
		fill_path_info(&dir);
		if (dir.is_dir) {
			struct chroot_entry *ptr;
			list1_for_each_entry(ptr, &chroot_list, list) {
				if (ptr->is_deleted) continue;
				if (PathMatchesToPattern(&dir, ptr->dir)) {
					error = 0;
					break;
				}
			}
		}
	}
	if (error) {
		const bool is_enforce = (mode == 3);
		const char *exename = GetEXE();
		printk("SAKURA-%s: chroot %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), root_name, current->pid, exename);
		if (is_enforce && CheckSupervisor("# %s is requesting\nchroot %s\n", exename, root_name) == 0) error = 0;
		if (exename) ccs_free(exename);
		if (mode == 1 && root_name) {
			AddChrootACL(root_name, 0);
			UpdateCounter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
		}
		if (!is_enforce) error = 0;
	}
	ccs_free(root_name);
	return error;
}

int AddChrootPolicy(char *data, const bool is_delete)
{
	return AddChrootACL(data, is_delete);
}

int ReadChrootPolicy(struct io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &chroot_list) {
		struct chroot_entry *ptr;
		ptr = list1_entry(pos, struct chroot_entry, list);
		if (ptr->is_deleted) continue;
		if (io_printf(head, KEYWORD_ALLOW_CHROOT "%s\n", ptr->dir->name)) return -ENOMEM;
	}
	return 0;
}

/***** SAKURA Linux end. *****/
