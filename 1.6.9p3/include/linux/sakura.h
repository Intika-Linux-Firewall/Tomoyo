/*
 * include/linux/sakura.h
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/*
 * A brief description about SAKURA:
 *
 *  SAKURA stands for "Security Advancement Know-how Upon Read-only Approach".
 *  As the name shows, SAKURA was originally a methodology to make root fs
 *  read-only to avoid tampering the system files.
 *  But now, SAKURA is not only a methodology but also a kernel patch
 *  that improves the system security with less effort.
 *
 *  SAKURA can restrict operations that affect systemwide.
 *  SAKURA manages the filesystem's namespace related operations so that
 *  files remains where the administrator expects.
 */

#ifndef _LINUX_SAKURA_H
#define _LINUX_SAKURA_H

#include <linux/version.h>

#ifndef __user
#define __user
#endif

#if defined(CONFIG_SAKURA)

/* Check whether the given pathname is allowed to chroot to. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
int ccs_check_chroot_permission(struct path *path);
#else
int ccs_check_chroot_permission(struct nameidata *nd);
#endif

/* Check whether the mount operation with the given parameters is allowed. */
int ccs_check_mount_permission(char *dev_name, char *dir_name, char *type,
			       const unsigned long *flags);

/* Check whether the current process is allowed to pivot_root. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
int ccs_check_pivot_root_permission(struct path *old_path,
				    struct path *new_path);
#else
int ccs_check_pivot_root_permission(struct nameidata *old_nd,
				    struct nameidata *new_nd);
#endif

/* Check whether the given mount operation hides an mounted partition. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
int ccs_may_mount(struct path *path);
#else
int ccs_may_mount(struct nameidata *nd);
#endif

/* Check whether the given mountpoint is allowed to umount. */
int ccs_may_umount(struct vfsmount *mnt);

/* Check whether the given local port is reserved. */
_Bool ccs_lport_reserved(const u16 port);

#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
static inline int ccs_check_chroot_permission(struct path *path)
{
	return 0;
}
#else
static inline int ccs_check_chroot_permission(struct nameidata *nd)
{
	return 0;
}
#endif
static inline int ccs_check_mount_permission(char *dev_name, char *dir_name,
					     char *type,
					     const unsigned long *flags)
{
	return 0;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
static inline int ccs_check_pivot_root_permission(struct path *old_path,
						  struct path *new_path)
{
	return 0;
}
#else
static inline int ccs_check_pivot_root_permission(struct nameidata *old_nd,
						  struct nameidata *new_nd)
{
	return 0;
}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
static inline int ccs_may_mount(struct path *path)
{
	return 0;
}
#else
static inline int ccs_may_mount(struct nameidata *nd)
{
	return 0;
}
#endif
static inline int ccs_may_umount(struct vfsmount *mnt)
{
	return 0;
}
static inline _Bool ccs_lport_reserved(const u16 port)
{
	return 0;
}

#endif

#endif
