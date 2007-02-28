/*
 * fs/sakura_capability.c
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

/*************************  PERMISSION CONTROL HANDLER  *************************/

void RestoreTaskCapability(void)
{
	unsigned int cap = current->dropped_capability;
	cap >>= SAKURA_INHERIT_OFFSET;
	cap |= cap << SAKURA_INHERIT_OFFSET;
	current->dropped_capability = cap;
}

int DropTaskCapability(char __user * __user *args)
{
	static const struct {
		const char *capability_name;
		const char *prompt;
		int capability_value;
	} entry[] = {
		{ "execve",        "do_execve",     (1 << SAKURA_DISABLE_EXECVE) },
		{ "chroot",        "sys_chroot",    (1 << SAKURA_DISABLE_CHROOT) },
		{ "pivotroot",     "sys_pivotroot", (1 << SAKURA_DISABLE_PIVOTROOT) },
		{ "mount",         "sys_mount",     (1 << SAKURA_DISABLE_MOUNT) },
		{ "euid0",         "seteuid(0)",    (1 << SAKURA_DISABLE_EUID0_PENDING) },
		{ "all-chroot",    "sys_chroot",    (1 << SAKURA_DISABLE_CHROOT) | (1 << (SAKURA_DISABLE_CHROOT + SAKURA_INHERIT_OFFSET)) },
		{ "all-pivotroot", "sys_pivotroot", (1 << SAKURA_DISABLE_PIVOTROOT) | (1 << (SAKURA_DISABLE_PIVOTROOT + SAKURA_INHERIT_OFFSET)) },
		{ "all-mount",     "sys_mount",     (1 << SAKURA_DISABLE_MOUNT) | (1 << (SAKURA_DISABLE_MOUNT + SAKURA_INHERIT_OFFSET)) },
		{ "all-euid0",     "seteuid(0)",    (1 << SAKURA_DISABLE_EUID0_PENDING) | (1 << (SAKURA_DISABLE_EUID0_PENDING + SAKURA_INHERIT_OFFSET)) },
		{ NULL, NULL, 0 }
	};
	char *page;
	if (!args) return -EINVAL;
	page = ccs_alloc(PAGE_SIZE);
	if (!page) return -ENOMEM;
	while (*args) {
		int i;
		memset(page, 0, PAGE_SIZE);
		if (strncpy_from_user(page, *args, PAGE_SIZE) < 0 || !memchr(page, '\0', PAGE_SIZE)) break;
		for (i = 0; entry[i].capability_name; i++) {
			if (strcmp(page, entry[i].capability_name) == 0) {
				current->dropped_capability |= entry[i].capability_value;
				if (current->euid) {
					if (entry[i].capability_value & (1 << SAKURA_DISABLE_EUID0_PENDING)) {
						current->dropped_capability |= (1 << SAKURA_DISABLE_EUID0_DISABLED);
						if (entry[i].capability_value & (1 << (SAKURA_DISABLE_EUID0_PENDING + SAKURA_INHERIT_OFFSET))) {
							current->dropped_capability |= (1 << (SAKURA_DISABLE_EUID0_DISABLED + SAKURA_INHERIT_OFFSET));
						}
					}
				}
				printk("%s for pid=%d disabled.\n", entry[i].prompt, current->pid);
				break;
			}
		}
		args++;
	}
	ccs_free(page);
	return -EAGAIN;
}

int CheckTaskCapability(const unsigned int operation)
{
	if (current->dropped_capability & (1 << operation)) {
		const char *exename = GetEXE(), *name = "UNKNOWN";
		switch (operation) {
		case SAKURA_DISABLE_MOUNT:
			name = "mount";
			break;
		case SAKURA_DISABLE_CHROOT:
			name = "chroot";
			break;
		case SAKURA_DISABLE_PIVOTROOT:
			name = "pivot_root";
			break;
		case SAKURA_DISABLE_EXECVE:
			name = "exec";
			break;
		case SAKURA_DISABLE_EUID0_DISABLED:
			name = "EUID=0";
			break;
		}
		printk("SAKURA-ERROR: %s (pid=%d:exe=%s): Permission denied.\n", name, current->pid, exename);
		if (exename) ccs_free(exename);
		return -EPERM;
	}
	return 0;
}

/*************************  EUID RESTRICTION HANDLER  *************************/

int CheckEUID(void)
{
	unsigned int cap = current->dropped_capability;
	if (!current->euid) return CheckTaskCapability(SAKURA_DISABLE_EUID0_DISABLED);
	if (cap & (1 << SAKURA_DISABLE_EUID0_PENDING)) {
		if ((cap & (1 << SAKURA_DISABLE_EUID0_DISABLED)) == 0) {
			cap |= 1 << SAKURA_DISABLE_EUID0_DISABLED;
			if (cap & (1 << (SAKURA_DISABLE_EUID0_PENDING + SAKURA_INHERIT_OFFSET))) {
				cap |= 1 << (SAKURA_DISABLE_EUID0_DISABLED + SAKURA_INHERIT_OFFSET);
			}
			printk("seteuid(0) for pid=%d disabled.\n", current->pid);
			current->dropped_capability = cap;
		}
	}
	return 0;
}

EXPORT_SYMBOL(RestoreTaskCapability);
EXPORT_SYMBOL(DropTaskCapability);
EXPORT_SYMBOL(CheckTaskCapability);
EXPORT_SYMBOL(CheckEUID);

/***** SAKURA Linux end. *****/
