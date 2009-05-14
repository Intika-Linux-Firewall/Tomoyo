/*
 * include/linux/realpath.h
 *
 * Get the canonicalized absolute pathnames. The basis for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.8-pre   2009/05/08
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

/* Allocate memory for temporary use (e.g. permission checks). */
void *ccs_alloc(const size_t size, const _Bool check_quota);
/* Free memory allocated by ccs_alloc(). */
void ccs_free(const void *p);

/* Check for memory usage. */
int ccs_read_memory_counter(struct ccs_io_buffer *head);

/* Set memory quota. */
int ccs_write_memory_quota(struct ccs_io_buffer *head);

/* Add a cookie to cookie list. */
void ccs_add_cookie(struct ccs_cookie *cookie, const void *ptr);
/**
 * ccs_update_cookie - Assign the given pointer to a cookie.
 *
 * @cookie: Pointer to "struct ccs_cookie".
 * @ptr:    Pointer to assign.
 *
 * Caller must hold ccs_policy_lock for reading unless either
 *   (a) @ptr is NULL
 *   (b) @ptr is already in cookie list
 *   (c) @ptr is not in memory for the policy
 *   (d) in the initialization phase
 * is true.
 */
static inline void ccs_update_cookie(struct ccs_cookie *cookie,
				     const void *ptr)
{
	cookie->u.ptr = ptr;
}
/* Delete a cookie from cookie list. */
void ccs_del_cookie(struct ccs_cookie *cookie);

#endif
