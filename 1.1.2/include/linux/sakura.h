/*
 * include/linux/sakura.h
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.1.2   2006/06/02
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
 *
 *  SAKURA can drop unnecessary capabilities to reduce the risk of exploitations.
 */

#ifndef _LINUX_SAKURA_H
#define _LINUX_SAKURA_H

/***** SAKURA Linux start. *****/

/* Check whether the given pathname is allowed to chroot to. */
#ifdef CONFIG_SAKURA_RESTRICT_CHROOT
int CheckChRootPermission(const char *pathname);
#else
static inline int CheckChRootPermission(const char *pathname) { return 0; }
#endif

/* Check whether the mount operation with the given parameters is allowed. */
#ifdef CONFIG_SAKURA_RESTRICT_MOUNT
int CheckMountPermission(char *dev_name, char *dir_name, char *type, unsigned long *flags);
#else
static inline int CheckMountPermission(char *dev_name, char *dir_name, char *type, unsigned long *flags) { return 0; }
#endif

/* Check whether the current process is allowed to pivot_root. */
#ifdef CONFIG_SAKURA_DENY_PIVOT_ROOT
int CheckPivotRootPermission(void);
#else
static inline int CheckPivotRootPermission(void) { return 0; }
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
int SAKURA_MayAutobind(const unsigned short int port);
#else
static inline int SAKURA_MayAutobind(const unsigned short int port) { return 0; }
#endif

#ifdef CONFIG_SAKURA_DROP_CAPABILITY_API
/* Interface to drop unnecessary capabilities. */
int DropTaskCapability(char __user * __user * args);
/* Reset current process's capabilities that is dropped only for the current program only. */
void RestoreTaskCapability(void);
/* Check whether the current process is allowed to use the given capability. */
int CheckTaskCapability(const unsigned int operation);
/* Check whether the current process has become euid = 0 when the process is not allowed to become euid = 0. */
int CheckEUID(void);
#else
static inline int CheckTaskCapability(const unsigned int operation) { return 0; }
static inline int CheckEUID(void) { return 0; }
#endif

#ifdef CONFIG_SAKURA_TRACE_READONLY
/* Show the given dentry which the operation is denied due to -EROFS. */
void ROFS_Log_from_dentry(struct dentry *dentry, struct vfsmount *mnt, const char *how);
/* Show the given filename which the operation is denied due to -EROFS. */
void ROFS_Log(const char *filename, const char *how);
#else
static inline void ROFS_Log_from_dentry(struct dentry *dentry, struct vfsmount *mnt, const char *how) {};
static inline void ROFS_Log(const char *filename, const char *how) {};
#endif

/* The following constants are used for dropping capabilities. */

#define SAKURA_DISABLE_EXECVE                  0  /* Forbid calling execve()                            */
#define SAKURA_DISABLE_CHROOT                  1  /* Forbid calling chroot()                            */
#define SAKURA_DISABLE_PIVOTROOT               2  /* Forbid calling pivot_root()                        */
#define SAKURA_DISABLE_MOUNT                   3  /* Forbid calling mount()                             */
#define SAKURA_DISABLE_EUID0_PENDING           4  /* Forbid becoming euid = 0 after becoming euid != 0. */
#define SAKURA_DISABLE_EUID0_DISABLED          5  /* Forbid becoming euid = 0 from now on.              */

/* Apply this restriction to not only current program but also all programs that use this task_struct. */
#define SAKURA_INHERIT_OFFSET                 16  /* Assume sizeof(current->dropped_capability) >= 4    */

/***** SAKURA Linux end. *****/
#endif
