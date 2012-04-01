/*
 * include/linux/realpath.h
 *
 * Get the canonicalized absolute pathnames. The basis for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_REALPATH_H
#define _LINUX_REALPATH_H

struct dentry;
struct vfsmount;
struct ccs_condition_list;
struct ccs_path_info;
struct ccs_io_buffer;
struct ccs_execve_entry;

/* Returns realpath(3) of the given pathname but ignores chroot'ed root. */
int ccs_realpath_from_dentry2(struct dentry *dentry, struct vfsmount *mnt,
			      char *newname, int newname_len);

/*
 * Returns realpath(3) of the given pathname but ignores chroot'ed root.
 * These functions use ccs_alloc(), so caller must ccs_free()
 * if these functions didn't return NULL.
 */
char *ccs_realpath(const char *pathname);
/* Get ccs_realpath() of both symlink and dereferenced pathname. */
int ccs_realpath_both(const char *pathname, struct ccs_execve_entry *ee);
/* Same with ccs_realpath() except that the pathname is already solved. */
char *ccs_realpath_from_dentry(struct dentry *dentry, struct vfsmount *mnt);
/* Encode binary string to ascii string. */
char *ccs_encode(const char *str);

/*
 * Allocate memory for ACL entry.
 * The RAM is chunked, so NEVER try to kfree() the returned pointer.
 */
void *ccs_alloc_element(const unsigned int size);

/*
 * Keep the given name on the RAM.
 * The RAM is shared, so NEVER try to modify or kfree() the returned name.
 */
const struct ccs_path_info *ccs_save_name(const char *name);

/* Allocate memory for temporary use (e.g. permission checks). */
void *ccs_alloc(const size_t size, const _Bool check_quota);

/* Free memory allocated by ccs_alloc(). */
void ccs_free(const void *p);

/* Check for memory usage. */
int ccs_read_memory_counter(struct ccs_io_buffer *head);

/* Set memory quota. */
int ccs_write_memory_quota(struct ccs_io_buffer *head);

#endif
