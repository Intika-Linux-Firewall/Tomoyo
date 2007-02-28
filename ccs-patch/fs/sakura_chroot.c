/*
 * fs/sakura_chroot.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.3.2   2007/02/14
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>

extern const char *ccs_log_level;

/***** The structure for chroot restrictions. *****/

typedef struct chroot_entry {
	struct chroot_entry *next;
	const struct path_info *dir;
	int is_deleted;
} CHROOT_ENTRY;

/*************************  CHROOT RESTRICTION HANDLER  *************************/

static CHROOT_ENTRY *chroot_list = NULL;

static int AddChrootACL(const char *dir, const int is_delete)
{
	CHROOT_ENTRY *new_entry, *ptr;
	const struct path_info *saved_dir;
	static DECLARE_MUTEX(lock);
	int error = -ENOMEM;
	if (!IsCorrectPath(dir, 1, 0, 1, __FUNCTION__)) return -EINVAL;
	if ((saved_dir = SaveName(dir)) == NULL) return -ENOMEM;
	down(&lock);
	for (ptr = chroot_list; ptr; ptr = ptr->next) {
		if (ptr->dir == saved_dir){
			ptr->is_deleted = is_delete;
			error = 0;
			goto out;
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = (CHROOT_ENTRY *) alloc_element(sizeof(CHROOT_ENTRY))) == NULL) goto out;
	new_entry->dir = saved_dir;
	mb(); /* Instead of using spinlock. */
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

int CheckChRootPermission(const char *pathname)
{
	int error_flag = 1;
	char *name;
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_CHROOT)) return 0;
	name = realpath(pathname);
	if (name) {
		struct path_info dir;
		dir.name = name;
		fill_path_info(&dir);
		if (dir.is_dir) {
			CHROOT_ENTRY *ptr;
			for (ptr = chroot_list; ptr; ptr = ptr->next) {
				if (ptr->is_deleted) continue;
				if (PathMatchesToPattern(&dir, ptr->dir)) {
					error_flag = 0;
					break;
				}
			}
		}
		ccs_free(name);
	}
	if (error_flag) {
		int error = -EPERM;
		const int is_enforce = CheckCCSEnforce(CCS_SAKURA_RESTRICT_CHROOT);
		const char *realname = realpath(pathname), *exename = GetEXE();
		printk("SAKURA-%s: chroot %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), realname ? realname : pathname, current->pid, exename);
		if (is_enforce && CheckSupervisor("# %s is requesting\nchroot %s\n", exename, realname ? realname : pathname) == 0) error = 0;
		if (exename) ccs_free(exename);
		if (!is_enforce && CheckCCSAccept(CCS_SAKURA_RESTRICT_CHROOT) && realname) {
			AddChrootACL(realname, 0);
			UpdateCounter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
		}
		if (realname) ccs_free(realname);
		if (is_enforce) return error;
	}
	return 0;
}

int AddChrootPolicy(char *data, const int is_delete)
{
	return AddChrootACL(data, is_delete);
}

int ReadChrootPolicy(IO_BUFFER *head)
{
	CHROOT_ENTRY *ptr = (CHROOT_ENTRY *) head->read_var2;
	if (!ptr) ptr = chroot_list;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_ALLOW_CHROOT "%s\n", ptr->dir->name)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

EXPORT_SYMBOL(CheckChRootPermission);

/***** SAKURA Linux end. *****/
