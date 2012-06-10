/*
 * fs/sakura_chroot.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.2   2006/09/03
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
	struct chroot_entry *next; /* Pointer to next record. NULL if none.             */
	int is_deleted;            /* Delete flag.                                      */
	const char *dir;           /* Directory name to allow to chroot to. Never NULL. */
} CHROOT_ENTRY;

/*************************  CHROOT RESTRICTION HANDLER  *************************/

static CHROOT_ENTRY chroot_list = { NULL, 0, "" };

static int AddChrootACL(const char *entry)
{
	CHROOT_ENTRY *new_entry, *ptr;
	const char *cp;
	if (!IsCorrectPath(entry, 1) || strendswith(entry, "/") == 0) {
		printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", __FUNCTION__, entry);
		return -EINVAL;
	}
	/* I don't want to add if it was already added. */
	for (ptr = chroot_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->dir, entry) == 0) { ptr->is_deleted = 0; return 0; }
	if ((cp = SaveName(entry)) == NULL || (new_entry = (CHROOT_ENTRY *) alloc_element(sizeof(CHROOT_ENTRY))) == NULL) goto out;
	new_entry->dir = cp;
	{
		static spinlock_t lock = SPIN_LOCK_UNLOCKED;
		/***** CRITICAL SECTION START *****/
		spin_lock(&lock);
		for (ptr = &chroot_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
		spin_unlock(&lock);
		/***** CRITICAL SECTION END *****/
	}
	printk("%sAllow chroot() to %s\n", ccs_log_level, entry);
 out:
	return 0;
}

int CheckChRootPermission(const char *pathname)
{
	int error_flag = 1;
	const char *name;
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_CHROOT)) return 0;
	name = realpath(pathname);
	if (name) {
		if (strendswith(name, "/")) {
			CHROOT_ENTRY *ptr;
			for (ptr = chroot_list.next; ptr; ptr = ptr->next) {
				if (ptr->is_deleted) continue;
				if (PathMatchesToPattern(name, ptr->dir)) {
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
		if (!is_enforce && CheckCCSAccept(CCS_SAKURA_RESTRICT_CHROOT) && realname) AddChrootACL(realname);
		if (realname) ccs_free(realname);
		if (is_enforce) return error;
	}
	return 0;
}

int AddChrootPolicy(char *data, const int is_delete)
{
	CHROOT_ENTRY *ptr;
	if (!is_delete) return AddChrootACL(data);
	for (ptr = chroot_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->dir, data) == 0) ptr->is_deleted = 1;
	return 0;
}

int ReadChrootPolicy(IO_BUFFER *head)
{
	CHROOT_ENTRY *ptr = (CHROOT_ENTRY *) head->read_var2;
	if (!ptr) ptr = chroot_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_ALLOW_CHROOT "%s\n", ptr->dir)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

EXPORT_SYMBOL(CheckChRootPermission);

/***** SAKURA Linux end. *****/
