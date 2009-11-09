/*
 * include/linux/ccsecurity_vfs.h
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.1-rc   2009/11/09
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_CCSECURITY_VFS_H
#define _LINUX_CCSECURITY_VFS_H

#if defined(CONFIG_CCSECURITY)

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

int ccs_may_create(struct inode *dir, struct dentry *dentry)
{
	return may_create(dir, dentry);
}

int ccs_may_delete(struct inode *dir, struct dentry *dentry, int is_dir)
{
	return may_delete(dir, dentry, is_dir);
}

#else

int ccs_may_create(struct inode *dir, struct dentry *dentry, int is_dir)
{
	/* SUSE 11.0 adds is_dir for may_create(). */
#ifdef MS_WITHAPPEND
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
	return may_create(dir, dentry, NULL, is_dir);
#else
	return may_create(dir, dentry, is_dir);
#endif
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
	return may_create(dir, dentry, NULL);
#else
	return may_create(dir, dentry);
#endif
#endif
}

int ccs_may_delete(struct inode *dir, struct dentry *dentry, int is_dir)
{
	return may_delete(dir, dentry, is_dir);
}

#endif

#endif

#endif
