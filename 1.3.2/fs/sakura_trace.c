/*
 * fs/sakura_trace.c
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

/*************************  ROFS Tracer  *************************/

void ROFS_Log_from_dentry(struct dentry *dentry, struct vfsmount *mnt, const char *how)
{
	const char *filename;
	if (!CheckCCSFlags(CCS_SAKURA_TRACE_READONLY)) return;
	if ((filename = realpath_from_dentry(dentry, mnt)) == NULL) return;
	printk("ReadOnly:%s:%s\n", how, filename);
	ccs_free(filename);
}

void ROFS_Log(const char *filename, const char *how)
{
	const char *buffer;
	if (!CheckCCSFlags(CCS_SAKURA_TRACE_READONLY)) return;
	if ((buffer = realpath(filename)) == NULL) return;
	printk("ReadOnly:%s:%s\n", how, buffer);
	ccs_free(buffer);
}

EXPORT_SYMBOL(ROFS_Log_from_dentry);
EXPORT_SYMBOL(ROFS_Log);

/***** SAKURA Linux end. *****/
