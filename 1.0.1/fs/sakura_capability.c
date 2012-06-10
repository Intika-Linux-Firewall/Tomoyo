/*
 * fs/sakura_capability.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005  NTT DATA CORPORATION
 *
 * Version: 1.0 2005/11/11
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/sakura.h>

/*************************  PERMISSION CONTROL HANDLER  *************************/

void RestoreTaskCapability(void)
{
	current->dropped_capability &= ~SAKURA_LOCAL_DISABLE_MASK;
}

int DropTaskCapability(char __user * __user *args)
{
	static const struct {
		const char *capability_name;
		const char *prompt;
		int capability_value;
	} entry[] = {
		{ "execve",        "do_execve",     SAKURA_DISABLE_LOCAL_EXECVE },
		{ "chroot",        "sys_chroot",    SAKURA_DISABLE_LOCAL_CHROOT },
		{ "pivotroot",     "sys_pivotroot", SAKURA_DISABLE_LOCAL_PIVOTROOT },
		{ "mount",         "sys_mount",     SAKURA_DISABLE_LOCAL_MOUNT },
		{ "euid0",         "seteuid(0)",    SAKURA_DISABLE_LOCAL_EUID0 },
		{ "all-chroot",    "sys_chroot",    SAKURA_DISABLE_INHERITABLE_CHROOT | SAKURA_DISABLE_LOCAL_CHROOT },
		{ "all-pivotroot", "sys_pivotroot", SAKURA_DISABLE_INHERITABLE_PIVOTROOT | SAKURA_DISABLE_LOCAL_PIVOTROOT },
		{ "all-mount",     "sys_mount",     SAKURA_DISABLE_INHERITABLE_MOUNT | SAKURA_DISABLE_LOCAL_MOUNT },
		{ "all-euid0",     "seteuid(0)",    SAKURA_DISABLE_INHERITABLE_EUID0 | SAKURA_DISABLE_LOCAL_EUID0 },
		{ NULL, NULL, 0 }
	};
	char *page;
	if (!args) return -EINVAL;
	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!page) return -ENOMEM;
	while (*args) {
		int i;
		memset(page, 0, PAGE_SIZE);
		if (strncpy_from_user(page, *args, PAGE_SIZE) < 0 || !memchr(page, '\0', PAGE_SIZE)) break;
		for (i = 0; entry[i].capability_name; i++) {
			if (strcmp(page, entry[i].capability_name) == 0) {
				current->dropped_capability |= entry[i].capability_value;
				if (current->euid) {
					if (entry[i].capability_value & SAKURA_DISABLE_INHERITABLE_EUID0) current->dropped_capability |= SAKURA_DISABLE_LOCAL_EUID0_DISABLED;
					if (entry[i].capability_value & SAKURA_DISABLE_LOCAL_EUID0) current->dropped_capability |= SAKURA_DISABLE_LOCAL_EUID0_DISABLED;
				}
				printk("%s for pid=%d disabled.\n", entry[i].prompt, current->pid);
				break;
			}
		}
		args++;
	}
	kfree(page);
	return 0;
}

int CheckTaskCapability(const unsigned int operation)
{
	if (current->dropped_capability & operation) {
		const char *exename = GetEXE();
		const char *name = "UNKNOWN";
		if (operation & (SAKURA_DISABLE_INHERITABLE_MOUNT | SAKURA_DISABLE_LOCAL_MOUNT)) name = "mount";
		else if (operation & (SAKURA_DISABLE_INHERITABLE_CHROOT | SAKURA_DISABLE_LOCAL_CHROOT)) name = "chroot";
		else if (operation & (SAKURA_DISABLE_INHERITABLE_PIVOTROOT | SAKURA_DISABLE_LOCAL_PIVOTROOT)) name = "pivot_root";
		else if (operation & SAKURA_DISABLE_LOCAL_EXECVE) name = "exec";
		printk("SAKURA-ERROR: %s (pid=%d:exe=%s): Permission denied.\n", name, current->pid, exename);
		if (exename) kfree(exename);
		return -EPERM;
	}
	return 0;
}

/*************************  EUID RESTRICTION HANDLER  *************************/

int CheckEUID(void)
{
	if (!current->euid) {
		if (current->dropped_capability & (SAKURA_DISABLE_INHERITABLE_EUID0_DISABLED | SAKURA_DISABLE_LOCAL_EUID0_DISABLED)) {
			pid_t pid = current->pid;
			const char *exename = GetEXE();
			printk("SAKURA-ERROR: seteuid(0)(pid=%d:exe=%s): Permission denied.\n", pid, exename);
			if (exename) kfree(exename);
			return -EPERM;
		}
	} else {
		if (current->dropped_capability & (SAKURA_DISABLE_INHERITABLE_EUID0 | SAKURA_DISABLE_LOCAL_EUID0)) {
			int flag = (current->dropped_capability & (SAKURA_DISABLE_INHERITABLE_EUID0_DISABLED | SAKURA_DISABLE_LOCAL_EUID0_DISABLED));
			if (!flag) {
				current->dropped_capability |= SAKURA_DISABLE_INHERITABLE_EUID0_DISABLED | SAKURA_DISABLE_LOCAL_EUID0_DISABLED;
				printk("seteuid(0) for pid=%d disabled.\n", current->pid);
			}
		}
	}
	return 0;
}

EXPORT_SYMBOL(RestoreTaskCapability);
EXPORT_SYMBOL(DropTaskCapability);
EXPORT_SYMBOL(CheckTaskCapability);
EXPORT_SYMBOL(CheckEUID);

/***** SAKURA Linux end. *****/
