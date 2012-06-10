/*
 * fs/sakura_pivot.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.4   2007/04/01
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

typedef struct pivot_root_entry {
	struct pivot_root_entry *next;
	const struct path_info *old_root;
	const struct path_info *new_root;
	int is_deleted;
} PIVOT_ROOT_ENTRY;

/*************************  PIVOT_ROOT RESTRICTION HANDLER  *************************/

static PIVOT_ROOT_ENTRY *pivot_root_list = NULL;

static int AddPivotRootACL(const char *old_root, const char *new_root, const int is_delete)
{
	PIVOT_ROOT_ENTRY *new_entry, *ptr;
	const struct path_info *saved_old_root, *saved_new_root;
	static DECLARE_MUTEX(lock);
	int error = -ENOMEM;
	if (!IsCorrectPath(old_root, 1, 0, 1, __FUNCTION__) || !IsCorrectPath(new_root, 1, 0, 1, __FUNCTION__)) return -EINVAL;
	if ((saved_old_root = SaveName(old_root)) == NULL || (saved_new_root = SaveName(new_root)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = pivot_root_list; ptr; ptr = ptr->next) {
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
	if ((new_entry = (PIVOT_ROOT_ENTRY *) alloc_element(sizeof(PIVOT_ROOT_ENTRY))) == NULL) goto out;
	new_entry->old_root = saved_old_root;
	new_entry->new_root = saved_new_root;
	mb(); /* Instead of using spinlock. */
	if ((ptr = pivot_root_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		pivot_root_list = new_entry;
	}
	error = 0;
	printk("%sAllow pivot_root(%s, %s)\n", ccs_log_level, new_root, old_root);
 out:
	up(&lock);
	return error;
}

int CheckPivotRootPermission(struct nameidata *old_nd, struct nameidata *new_nd)
{
	int error = -EPERM;
	char *old_root, *new_root;
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_PIVOT_ROOT)) return 0;
	old_root = realpath_from_dentry(old_nd->dentry, old_nd->mnt);
	new_root = realpath_from_dentry(new_nd->dentry, new_nd->mnt);
	if (old_root && new_root) {
		struct path_info old_root_dir, new_root_dir;
		old_root_dir.name = old_root;
		fill_path_info(&old_root_dir);
		new_root_dir.name = new_root;
		fill_path_info(&new_root_dir);
		if (old_root_dir.is_dir && new_root_dir.is_dir) {
			PIVOT_ROOT_ENTRY *ptr;
			for (ptr = pivot_root_list; ptr; ptr = ptr->next) {
				if (ptr->is_deleted) continue;
				if (PathMatchesToPattern(&old_root_dir, ptr->old_root) && PathMatchesToPattern(&new_root_dir, ptr->new_root)) {
					error = 0;
					break;
				}
			}
		}
	}
	if (error) {
		const int is_enforce = CheckCCSEnforce(CCS_SAKURA_RESTRICT_PIVOT_ROOT);
		const char *exename = GetEXE();
		printk("SAKURA-%s: pivot_root %s %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), new_root, old_root, current->pid, exename);
		if (is_enforce && CheckSupervisor("# %s is requesting\npivot_root %s %s\n", exename, new_root, old_root) == 0) error = 0;
		if (exename) ccs_free(exename);
		if (!is_enforce && CheckCCSAccept(CCS_SAKURA_RESTRICT_PIVOT_ROOT) && old_root && new_root) {
			AddPivotRootACL(old_root, new_root, 0);
			UpdateCounter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
		}
		if (!is_enforce) error = 0;
	}
	ccs_free(old_root);
	ccs_free(new_root);
	return error;
}

int AddPivotRootPolicy(char *data, const int is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp++ = '\0';
	return AddPivotRootACL(cp, data, is_delete);
}

int ReadPivotRootPolicy(IO_BUFFER *head)
{
	PIVOT_ROOT_ENTRY *ptr = (PIVOT_ROOT_ENTRY *) head->read_var2;
	if (!ptr) ptr = pivot_root_list;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_ALLOW_PIVOT_ROOT "%s %s\n", ptr->new_root->name, ptr->old_root->name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

EXPORT_SYMBOL(CheckPivotRootPermission);

/***** SAKURA Linux end. *****/
