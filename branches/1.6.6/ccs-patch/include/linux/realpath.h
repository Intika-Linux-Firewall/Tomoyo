/*
 * include/linux/realpath.h
 *
 * Get the canonicalized absolute pathnames. The basis for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.6   2009/02/02
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_REALPATH_H
#define _LINUX_REALPATH_H

struct dentry;
struct vfsmount;
struct condition_list;
struct path_info;
struct ccs_io_buffer;

/* Returns realpath(3) of the given pathname but ignores chroot'ed root. */
int ccs_realpath_from_dentry2(struct dentry *dentry, struct vfsmount *mnt,
			      char *newname, int newname_len);

/*
 * Returns realpath(3) of the given pathname but ignores chroot'ed root.
 * These functions use ccs_alloc(), so caller must ccs_free()
 * if these functions didn't return NULL.
 */
char *ccs_realpath(const char *pathname);
/* Same with ccs_realpath() except that it doesn't follow the final symlink. */
char *ccs_realpath_nofollow(const char *pathname);
/* Same with ccs_realpath() except that the pathname is already solved. */
char *ccs_realpath_from_dentry(struct dentry *dentry, struct vfsmount *mnt);

/*
 * Allocate memory for ACL entry.
 * The RAM is chunked, so NEVER try to kfree() the returned pointer.
 */
void *ccs_alloc_element(const unsigned int size);

/*
 * Keep the given name on the RAM.
 * The RAM is shared, so NEVER try to modify or kfree() the returned name.
 */
const struct path_info *ccs_save_name(const char *name);

/* Allocate memory for temporary use (e.g. permission checks). */
void *ccs_alloc(const size_t size);

/* Free memory allocated by ccs_alloc(). */
void ccs_free(const void *p);

/* Check for memory usage. */
int ccs_read_memory_counter(struct ccs_io_buffer *head);

/* Set memory quota. */
int ccs_write_memory_quota(struct ccs_io_buffer *head);

#endif
