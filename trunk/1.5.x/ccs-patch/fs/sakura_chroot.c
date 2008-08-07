/*
 * fs/sakura_chroot.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.5.5-pre   2008/08/07
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#else
#include <linux/fs.h>
#endif

extern const char *ccs_log_level;

/***** The structure for chroot restrictions. *****/

struct chroot_entry {
	struct chroot_entry *next;
	const struct path_info *dir;
	int is_deleted;
};

/*************************  CHROOT RESTRICTION HANDLER  *************************/

static struct chroot_entry *chroot_list = NULL;

static int AddChrootACL(const char *dir, const int is_delete)
{
	struct chroot_entry *new_entry, *ptr;
	const struct path_info *saved_dir;
	static DECLARE_MUTEX(lock);
	int error = -ENOMEM;
	if (!IsCorrectPath(dir, 1, 0, 1, __FUNCTION__)) return -EINVAL;
	if ((saved_dir = SaveName(dir)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = chroot_list; ptr; ptr = ptr->next) {
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
	mb(); /* Avoid out-of-order execution. */
	if ((ptr = chroot_list) != NULL) {
		while (ptr->next) ptr = ptr->next; ptr->next = new_entry;
	} else {
		chroot_list = new_entry;
	}
	error = 0;
	printk("%sAllow chroot() to %s\n", ccs_log_level, dir);
 out:
	up(&lock);
	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#define PATH_or_NAMEIDATA path
#else
#define PATH_or_NAMEIDATA nameidata
#endif
int CheckChRootPermission(struct PATH_or_NAMEIDATA *path)
{
	int error = -EPERM;
	char *root_name;
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_CHROOT)) return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
	root_name = realpath_from_dentry(path->path.dentry, path->path.mnt);
#else
	root_name = realpath_from_dentry(path->dentry, path->mnt);
#endif
	if (root_name) {
		struct path_info dir;
		dir.name = root_name;
		fill_path_info(&dir);
		if (dir.is_dir) {
			struct chroot_entry *ptr;
			for (ptr = chroot_list; ptr; ptr = ptr->next) {
				if (ptr->is_deleted) continue;
				if (PathMatchesToPattern(&dir, ptr->dir)) {
					error = 0;
					break;
				}
			}
		}
	}
	if (error) {
		const int is_enforce = CheckCCSEnforce(CCS_SAKURA_RESTRICT_CHROOT);
		const char *exename = GetEXE();
		printk("SAKURA-%s: chroot %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), root_name, current->pid, exename);
		if (is_enforce && CheckSupervisor("# %s is requesting\nchroot %s\n", exename, root_name) == 0) error = 0;
		if (exename) ccs_free(exename);
		if (!is_enforce && CheckCCSAccept(CCS_SAKURA_RESTRICT_CHROOT, NULL) && root_name) {
			AddChrootACL(root_name, 0);
			UpdateCounter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
		}
		if (!is_enforce) error = 0;
	}
	ccs_free(root_name);
	return error;
}

int AddChrootPolicy(char *data, const int is_delete)
{
	return AddChrootACL(data, is_delete);
}

int ReadChrootPolicy(struct io_buffer *head)
{
	struct chroot_entry *ptr = head->read_var2;
	if (!ptr) ptr = chroot_list;
	while (ptr) {
		head->read_var2 = ptr;
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_ALLOW_CHROOT "%s\n", ptr->dir->name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

/***** SAKURA Linux end. *****/
