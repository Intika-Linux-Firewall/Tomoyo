/*
 * fs/proc/ccs_proc.c
 *
 * /proc interface for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.1.2   2006/06/02
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
#include <linux/ccs_proc.h>
#include <linux/ccs_common.h>

#if defined(CONFIG_SAKURA) || defined(CONFIG_TOMOYO)

static int ccs_open(struct inode *inode, struct file *file)
{
	return CCS_OpenControl((const int) (PDE(inode)->data), file);
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
		entry->data = (void *) key;
	}
}

void __init CCSProc_Init(void)
{
	struct proc_dir_entry *ccs_dir = proc_mkdir("ccs", NULL);
	struct proc_dir_entry *policy_dir = proc_mkdir("policy", ccs_dir),
		*info_dir = proc_mkdir("info", ccs_dir);
	CreateEntry("query",            0600, policy_dir, CCS_POLICY_QUERY);
#ifdef CONFIG_SAKURA
	CreateEntry("system_policy",    0600, policy_dir, CCS_POLICY_SYSTEMPOLICY);
#endif
#ifdef CONFIG_TOMOYO
	CreateEntry("domain_policy",    0600, policy_dir, CCS_POLICY_DOMAINPOLICY);
	CreateEntry("exception_policy", 0600, policy_dir, CCS_POLICY_EXCEPTIONPOLICY);
	CreateEntry("trusted_pids",     0400, info_dir, CCS_INFO_TRUSTEDPIDS);
	CreateEntry("deleted_pids",     0400, info_dir, CCS_INFO_DELETEDPIDS);
	CreateEntry("grant_log",        0400, info_dir, CCS_INFO_GRANTLOG);
	CreateEntry("reject_log",       0400, info_dir, CCS_INFO_REJECTLOG);
	CreateEntry("self_domain",      0400, info_dir, CCS_INFO_SELFDOMAIN);
#ifdef CONFIG_TOMOYO_MAC_FOR_FILE
	CreateEntry("mapping",          0400, info_dir, CCS_INFO_MAPPING);
#endif
#endif
	CreateEntry("meminfo",          0400, info_dir, CCS_INFO_MEMINFO);
	CreateEntry("status",           0600, ccs_dir, CCS_STATUS);
}

#else
void __init CCSProc_Init(void) {}
#endif

EXPORT_SYMBOL(CCSProc_Init);
