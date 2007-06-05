/*
 * include/linux/realpath.h
 *
 * Get the canonicalized absolute pathnames. The basis for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.4.1   2007/06/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_REALPATH_H
#define _LINUX_REALPATH_H

struct path_info;

/* Returns realpath(3) of the given pathname but ignores chroot'ed root. */
int realpath_from_dentry2(struct dentry *dentry, struct vfsmount *mnt, char *newname, int newname_len);

/* Returns realpath(3) of the given pathname but ignores chroot'ed root. */
/* These functions use ccs_alloc(), so caller must ccs_free() if these functions didn't return NULL. */
char *realpath(const char *pathname);
char *realpath_nofollow(const char *pathname);
char *realpath_from_dentry(struct dentry *dentry, struct vfsmount *mnt);

/* Allocate memory for structures. The RAM is chunked, so NEVER try to kfree() the returned pointer. */
void *alloc_element(const unsigned int size);

/* Get used RAM size for alloc_elements(). */
unsigned int GetMemoryUsedForElements(void);

/* Keep the given name on the RAM. The RAM is shared, so NEVER try to modify or kfree() the returned name. */
const struct path_info *SaveName(const char *name);

/* Get used RAM size for SaveName(). */
unsigned int GetMemoryUsedForSaveName(void);

unsigned int GetMemoryUsedForDynamic(void);

#endif
