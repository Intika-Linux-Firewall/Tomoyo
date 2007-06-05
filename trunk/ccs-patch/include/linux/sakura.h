/*
 * include/linux/sakura.h
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.4.1   2007/06/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/*
 * A brief description about SAKURA:
 *
 *  SAKURA stands for "Security Advancement Know-how Upon Read-only Approach".
 *  As the name shows, SAKURA was originally a methodology to make root fs read-only
 *  to avoid tampering the system files.
 *  But now, SAKURA is not only a methodology but also a kernel patch
 *  that improves the system security with less effort.
 *
 *  SAKURA can restrict operations that affect systemwide.
 */

#ifndef _LINUX_SAKURA_H
#define _LINUX_SAKURA_H

#ifndef __user
#define __user
#endif

/***** SAKURA Linux start. *****/

/* Check whether the given pathname is allowed to chroot to. */
#ifdef CONFIG_SAKURA_RESTRICT_CHROOT
int CheckChRootPermission(struct nameidata *nd);
#else
static inline int CheckChRootPermission(struct nameidata *nd) { return 0; }
#endif

/* Check whether the mount operation with the given parameters is allowed. */
#ifdef CONFIG_SAKURA_RESTRICT_MOUNT
int CheckMountPermission(char *dev_name, char *dir_name, char *type, unsigned long *flags);
#else
static inline int CheckMountPermission(char *dev_name, char *dir_name, char *type, unsigned long *flags) { return 0; }
#endif

/* Check whether the current process is allowed to pivot_root. */
#ifdef CONFIG_SAKURA_RESTRICT_PIVOT_ROOT
int CheckPivotRootPermission(struct nameidata *old_nd, struct nameidata *new_nd);
#else
static inline int CheckPivotRootPermission(struct nameidata *old_nd, struct nameidata *new_nd) { return 0; }
#endif

/* Check whether the given mount operation hides an mounted partition. */
#ifdef CONFIG_SAKURA_DENY_CONCEAL_MOUNT
int SAKURA_MayMount(struct nameidata *nd);
#else
static inline int SAKURA_MayMount(struct nameidata *nd) { return 0; }
#endif

/* Check whether the given mountpoint is allowed to umount. */
#ifdef CONFIG_SAKURA_RESTRICT_UNMOUNT
int SAKURA_MayUmount(struct vfsmount *mnt);
#else
static inline int SAKURA_MayUmount(struct vfsmount *mnt) { return 0; }
#endif

/* Check whether the given port is allowed to autobind. */
#ifdef CONFIG_SAKURA_RESTRICT_AUTOBIND
int SAKURA_MayAutobind(const u16 port);
#else
static inline int SAKURA_MayAutobind(const u16 port) { return 0; }
#endif

/***** SAKURA Linux end. *****/
#endif
