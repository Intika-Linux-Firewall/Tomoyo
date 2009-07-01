/*
 * include/linux/realpath.h
 *
 * Get the canonicalized absolute pathnames. The basis for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/05/28
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_REALPATH_H
#define _LINUX_REALPATH_H

struct dentry;
struct vfsmount;
struct ccs_condition;
struct ccs_path_info;
struct ccs_io_buffer;
struct ccs_execve_entry;

/*
 * Returns realpath(3) of the given pathname but ignores chroot'ed root.
 * These functions use kzalloc(), so caller must kfree()
 * if these functions didn't return NULL.
 */
char *ccs_realpath(const char *pathname);
/* Same with ccs_realpath() except that the pathname is already solved. */
char *ccs_realpath_from_dentry(struct dentry *dentry, struct vfsmount *mnt);
/* Encode binary string to ascii string. */
char *ccs_encode(const char *str);

/* Get ccs_realpath() of both symlink and dereferenced pathname. */
int ccs_realpath_both(const char *pathname, struct ccs_execve_entry *ee);

/*  Check memory quota. */
bool ccs_memory_ok(const void *ptr);

/* Allocate memory for the given name. */
const struct ccs_path_info *ccs_get_name(const char *name);
/* Delete memory for the given name. */
void ccs_put_name(const struct ccs_path_info *name);

/* Allocate memory for the given IPv6 address. */
const struct in6_addr *ccs_get_ipv6_address(const struct in6_addr *addr);
/* Delete memory for the given IPv6 address. */
void ccs_put_ipv6_address(const struct in6_addr *addr);

/* Check for memory usage. */
int ccs_read_memory_counter(struct ccs_io_buffer *head);

/* Set memory quota. */
int ccs_write_memory_quota(struct ccs_io_buffer *head);

#endif
