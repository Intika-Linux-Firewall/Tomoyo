/*
 * fs/sakura_umount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.1   2006/04/01
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
#include <linux/namespace.h>
#endif

extern const char *ccs_log_level;

/***** The structure for unmount restrictions. *****/

typedef struct no_umount_entry {
	struct no_umount_entry *next; /* Pointer to next record. NULL if none.                */
	int is_deleted;               /* Delete flag.                                         */
	const char *dir;              /* Mount points that never allow to umount. Never NULL. */
} NO_UMOUNT_ENTRY;

/*************************  UMOUNT RESTRICTION HANDLER  *************************/

static NO_UMOUNT_ENTRY no_umount_list = { NULL, 0, "" };

static int AddNoUmountACL(const char *entry)
{
	NO_UMOUNT_ENTRY *new_entry, *ptr;
	const char *cp;
	if (!isRoot()) return -EPERM;
	if (!IsCorrectPath(entry, 1) || strendswith(entry, "/") == 0) {
		printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", __FUNCTION__, entry);
		return -EINVAL;
	}

	/* I don't want to add if it was already added. */
	for (ptr = no_umount_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->dir, entry) == 0) { ptr->is_deleted = 0; return 0; }
	if ((cp = SaveName(entry)) == NULL || (new_entry = (NO_UMOUNT_ENTRY *) alloc_element(sizeof(NO_UMOUNT_ENTRY))) == NULL) goto out;
	memset(new_entry, 0, sizeof(NO_UMOUNT_ENTRY));
	new_entry->next = NULL;
	new_entry->is_deleted = 0;
	new_entry->dir = cp;
	{
		static spinlock_t lock = SPIN_LOCK_UNLOCKED;
		/***** CRITICAL SECTION START *****/
		spin_lock(&lock);
		for (ptr = &no_umount_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
		spin_unlock(&lock);
		/***** CRITICAL SECTION END *****/
	}
	printk("%sDon't allow umount %s\n", ccs_log_level, entry);
 out:
	return 0;
}

int SAKURA_MayUmount(struct vfsmount *mnt)
{
	int error = -EPERM;
	char *page;
	const int is_enforce = CheckCCSEnforce(CCS_SAKURA_RESTRICT_UNMOUNT);
	if (!CheckCCSFlags(CCS_SAKURA_RESTRICT_UNMOUNT)) return 0;
	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (page) {
		memset(page, 0, PAGE_SIZE);
		if (realpath_from_dentry(mnt->mnt_root, mnt, page, PAGE_SIZE - 1) == 0) {
			NO_UMOUNT_ENTRY *ptr;
			for (ptr = no_umount_list.next; ptr; ptr = ptr->next) {
				if (ptr->is_deleted) continue;
				if (PathMatchesToPattern(page, ptr->dir)) break;
			}
			if (ptr) {
				const char *exename = GetEXE();
				printk("SAKURA-%s: umount %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), page, current->pid, exename);
				kfree(exename);
			} else {
				error = 0;
			}
		}
		kfree(page);
	}
	if (!is_enforce) error = 0;
	return error;
}

int AddNoUmountPolicy(char *data)
{
	if (!isRoot()) return -EPERM;
	return AddNoUmountACL(data);
}

int DelNoUmountPolicy(const char *data)
{
	NO_UMOUNT_ENTRY *ptr;
	if (!isRoot()) return -EPERM;
	for (ptr = no_umount_list.next; ptr; ptr = ptr->next) if (strcmp(ptr->dir, data) == 0) ptr->is_deleted = 1;
	return 0;
}

int ReadNoUmountPolicy(IO_BUFFER *head)
{
	NO_UMOUNT_ENTRY *ptr = (NO_UMOUNT_ENTRY *) head->read_var2;
	if (!ptr) ptr = no_umount_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (ptr->is_deleted == 0 && io_printf(head, KEYWORD_DENY_UNMOUNT "%s\n", ptr->dir)) break;
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

EXPORT_SYMBOL(SAKURA_MayUmount);

/***** SAKURA Linux end. *****/
