/*
 * fs/proc/ccs_proc.c
 *
 * /proc interface for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.5.3-rc   2008/01/17
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ccs_proc.h>
#include <linux/ccs_common.h>

#if defined(CONFIG_SAKURA) || defined(CONFIG_TOMOYO)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,23)
static inline struct proc_dir_entry *PDE(const struct inode *inode)
{
	return (struct proc_dir_entry *) inode->u.generic_ip;
}
#endif

static int ccs_open(struct inode *inode, struct file *file)
{
	return CCS_OpenControl(((u8 *) PDE(inode)->data) - ((u8 *) NULL), file);
}

static int ccs_release(struct inode *inode, struct file *file)
{
	return CCS_CloseControl(file);
}

static unsigned int ccs_poll(struct file *file, poll_table *wait)
{
	return CCS_PollControl(file, wait);
}

static ssize_t ccs_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	return CCS_ReadControl(file, buf, count);
}

static ssize_t ccs_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	return CCS_WriteControl(file, buf, count);
}

static struct file_operations ccs_operations = {
	open:    ccs_open,
	release: ccs_release,
	poll:    ccs_poll,
	read:    ccs_read,
	write:   ccs_write
};

static __init void CreateEntry(const char *name, const mode_t mode, struct proc_dir_entry *parent, const int key)
{
	struct proc_dir_entry *entry = create_proc_entry(name, mode, parent);
	if (entry) {
		entry->proc_fops = &ccs_operations;
		entry->data = ((u8 *) NULL) + key;
	}
}

void __init CCSProc_Init(void)
{
	struct proc_dir_entry *ccs_dir = proc_mkdir("ccs", NULL);
	extern void __init realpath_Init(void);
	realpath_Init();
	FindDomain(""); /* Set domainname of KERNEL domain. */
	CreateEntry("query",            0600, ccs_dir, CCS_QUERY);
#ifdef CONFIG_SAKURA
	CreateEntry("system_policy",    0600, ccs_dir, CCS_SYSTEMPOLICY);
#endif
#ifdef CONFIG_TOMOYO
	CreateEntry("domain_policy",    0600, ccs_dir, CCS_DOMAINPOLICY);
	CreateEntry("exception_policy", 0600, ccs_dir, CCS_EXCEPTIONPOLICY);
	CreateEntry("grant_log",        0400, ccs_dir, CCS_GRANTLOG);
	CreateEntry("reject_log",       0400, ccs_dir, CCS_REJECTLOG);
#endif
	CreateEntry("self_domain",      0400, ccs_dir, CCS_SELFDOMAIN);
	CreateEntry(".domain_status",   0600, ccs_dir, CCS_DOMAIN_STATUS);
	CreateEntry(".process_status",  0400, ccs_dir, CCS_PROCESS_STATUS);
	CreateEntry("meminfo",          0400, ccs_dir, CCS_MEMINFO);
	CreateEntry("profile",          0600, ccs_dir, CCS_PROFILE);
	CreateEntry("manager",          0600, ccs_dir, CCS_MANAGER);
	CreateEntry(".updates_counter", 0400, ccs_dir, CCS_UPDATESCOUNTER);
	CreateEntry("version",          0400, ccs_dir, CCS_VERSION);
}

#else
void __init CCSProc_Init(void) {}
#endif
