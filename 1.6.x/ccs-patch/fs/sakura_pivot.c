/*
 * fs/sakura_pivot.c
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

/***** The structure for pivot_root restrictions. *****/

struct pivot_root_entry {
	struct list1_head list;
	const struct path_info *old_root;
	const struct path_info *new_root;
	bool is_deleted;
};

/*************************  PIVOT_ROOT RESTRICTION HANDLER  *************************/

static LIST1_HEAD(pivot_root_list);

static int AddPivotRootACL(const char *old_root, const char *new_root, const bool is_delete)
{
	struct pivot_root_entry *new_entry, *ptr;
	const struct path_info *saved_old_root, *saved_new_root;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if (!IsCorrectPath(old_root, 1, 0, 1, __FUNCTION__) || !IsCorrectPath(new_root, 1, 0, 1, __FUNCTION__)) return -EINVAL;
	if ((saved_old_root = SaveName(old_root)) == NULL || (saved_new_root = SaveName(new_root)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &pivot_root_list, list) {
		if (ptr->old_root == saved_old_root && ptr->new_root == saved_new_root) {
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
	new_entry->old_root = saved_old_root;
	new_entry->new_root = saved_new_root;
	list1_add_tail_mb(&new_entry->list, &pivot_root_list);
	error = 0;
	printk("%sAllow pivot_root(%s, %s)\n", ccs_log_level, new_root, old_root);
 out:
	mutex_unlock(&lock);
	return error;
}

int CheckPivotRootPermission(struct nameidata *old_nd, struct nameidata *new_nd)
{
	int error = -EPERM;
	char *old_root, *new_root;
	const u8 mode = CheckCCSFlags(CCS_SAKURA_RESTRICT_PIVOT_ROOT);
	if (!mode) return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,25)
	old_root = realpath_from_dentry(old_nd->path.dentry, old_nd->path.mnt);
	new_root = realpath_from_dentry(new_nd->path.dentry, new_nd->path.mnt);
#else
	old_root = realpath_from_dentry(old_nd->dentry, old_nd->mnt);
	new_root = realpath_from_dentry(new_nd->dentry, new_nd->mnt);
#endif
	if (old_root && new_root) {
		struct path_info old_root_dir, new_root_dir;
		old_root_dir.name = old_root;
		fill_path_info(&old_root_dir);
		new_root_dir.name = new_root;
		fill_path_info(&new_root_dir);
		if (old_root_dir.is_dir && new_root_dir.is_dir) {
			struct pivot_root_entry *ptr;
			list1_for_each_entry(ptr, &pivot_root_list, list) {
				if (ptr->is_deleted) continue;
				if (PathMatchesToPattern(&old_root_dir, ptr->old_root) && PathMatchesToPattern(&new_root_dir, ptr->new_root)) {
					error = 0;
					break;
				}
			}
		}
	}
	if (error) {
		const bool is_enforce = (mode == 3);
		const char *exename = GetEXE();
		printk("SAKURA-%s: pivot_root %s %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), new_root, old_root, current->pid, exename);
		if (is_enforce && CheckSupervisor("# %s is requesting\npivot_root %s %s\n", exename, new_root, old_root) == 0) error = 0;
		if (exename) ccs_free(exename);
		if (mode == 1 && old_root && new_root) {
			AddPivotRootACL(old_root, new_root, 0);
			UpdateCounter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
		}
		if (!is_enforce) error = 0;
	}
	ccs_free(old_root);
	ccs_free(new_root);
	return error;
}

int AddPivotRootPolicy(char *data, const bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp++ = '\0';
	return AddPivotRootACL(cp, data, is_delete);
}

int ReadPivotRootPolicy(struct io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &pivot_root_list) {
		struct pivot_root_entry *ptr;
		ptr = list1_entry(pos, struct pivot_root_entry, list);
		if (ptr->is_deleted) continue;
		if (io_printf(head, KEYWORD_ALLOW_PIVOT_ROOT "%s %s\n", ptr->new_root->name, ptr->old_root->name)) return -ENOMEM;
	}
	return 0;
}

/***** SAKURA Linux end. *****/
