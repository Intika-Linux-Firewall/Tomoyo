/*
 * include/linux/realpath.h
 *
 * Get the canonicalized absolute pathnames. The basis for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.1.2   2006/06/02
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_REALPATH_H
#define _LINUX_REALPATH_H

/* Returns realpath(3) of the given pathname but ignores chroot'ed root. */
/* This function uses kmalloc(), so caller must kfree() if this function didn't return NULL. */
const char *realpath(const char *pathname);

/* Returns realpath(3) of the given dentry but ignores chroot'ed root. */
int realpath_from_dentry(struct dentry *dentry, struct vfsmount *mnt, char *newname, int newname_len);

/* Allocate memory for structures. The RAM is chunked, so NEVER try to kfree() the returned pointer. */
char *alloc_element(const unsigned int size);

/* Get used RAM size for alloc_elements() in KB. */
unsigned int GetMemoryUsedForElements(void);

/* Keep the given name on the RAM. The RAM is shared, so NEVER try to modify or kfree() the returned name. */
const char *SaveName(const char *name);

/* Get used RAM size for SaveName() in KB. */
unsigned int GetMemoryUsedForSaveName(void);

#endif
