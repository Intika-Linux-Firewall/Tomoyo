/*
 * fs/sakura_trace.c
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
#include <linux/realpath.h>

/*************************  ROFS Tracer  *************************/

void ROFS_Log_from_dentry(struct dentry *dentry, struct vfsmount *mnt, const char *how)
{
	char *buffer;
	if (!CheckCCSFlags(CCS_SAKURA_TRACE_READONLY)) return;
	if ((buffer = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL) return;
	memset(buffer, 0, PAGE_SIZE);
	if (realpath_from_dentry(dentry, mnt, buffer, PAGE_SIZE - 1) == 0) printk("ReadOnly:%s:%s\n", how, buffer);
	kfree(buffer);
}

void ROFS_Log(const char *filename, const char *how)
{
	const char *buffer;
	if (!CheckCCSFlags(CCS_SAKURA_TRACE_READONLY)) return;
	if ((buffer = realpath(filename)) == NULL) return;
	printk("ReadOnly:%s:%s\n", how, buffer);
	kfree(buffer);
}

EXPORT_SYMBOL(ROFS_Log_from_dentry);
EXPORT_SYMBOL(ROFS_Log);

/***** SAKURA Linux end. *****/
