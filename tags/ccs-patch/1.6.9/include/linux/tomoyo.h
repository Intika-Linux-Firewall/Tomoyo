/*
 * include/linux/tomoyo.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.6.9   2011/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/*
 * A brief description about TOMOYO:
 *
 *  TOMOYO stands for "Task Oriented Management Obviates Your Onus".
 *  TOMOYO is intended to provide the Domain-Based MAC utilizing task_struct.
 *
 *  The biggest feature of TOMOYO is that TOMOYO has "learning mode".
 *  The learning mode can automatically generate policy definition,
 *  and dramatically reduces the policy definition labors.
 *
 *  TOMOYO is applicable to figuring out the system's behavior, for
 *  TOMOYO uses the canonicalized absolute pathnames and
 *  TreeView style domain transitions.
 */

#ifndef _LINUX_TOMOYO_H
#define _LINUX_TOMOYO_H

#include <linux/version.h>

#ifndef __user
#define __user
#endif

struct dentry;
struct vfsmount;
struct nameidata;
struct inode;
struct linux_binprm;
struct pt_regs;
struct file;
struct ctl_table;

#if defined(CONFIG_TOMOYO)

int ccs_check_open_permission(struct dentry *dentry, struct vfsmount *mnt,
			      const int flag);
int ccs_check_rewrite_permission(struct file *filp);
int ccs_check_ioctl_permission(struct file *filp, unsigned int cmd,
			       unsigned long arg);
int ccs_parse_table(int __user *name, int nlen, void __user *oldval,
		    void __user *newval, struct ctl_table *table);

/* Check whether the given signal is allowed to use. */
int ccs_check_signal_acl(const int sig, const int pid);

/* Check whether the given capability is allowed to use. */
_Bool ccs_capable(const u8 operation);

int ccs_check_mknod_permission(struct inode *dir, struct dentry *dentry,
			       struct vfsmount *mnt, int mode, unsigned dev);
int ccs_check_mkdir_permission(struct inode *dir, struct dentry *dentry,
			       struct vfsmount *mnt, int mode);
int ccs_check_rmdir_permission(struct inode *dir, struct dentry *dentry,
			       struct vfsmount *mnt);
int ccs_check_unlink_permission(struct inode *dir, struct dentry *dentry,
				struct vfsmount *mnt);
int ccs_check_symlink_permission(struct inode *dir, struct dentry *dentry,
				 struct vfsmount *mnt, char *from);
int ccs_check_truncate_permission(struct dentry *dentry, struct vfsmount *mnt,
				  loff_t length, unsigned int time_attrs);
int ccs_check_rename_permission(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry,
				struct vfsmount *mnt);
int ccs_check_link_permission(struct dentry *old_dentry, struct inode *new_dir,
			      struct dentry *new_dentry, struct vfsmount *mnt);
int ccs_check_open_exec_permission(struct dentry *dentry, struct vfsmount *mnt);
int ccs_check_uselib_permission(struct dentry *dentry, struct vfsmount *mnt);

#else

static inline int ccs_check_open_permission(struct dentry *dentry,
					    struct vfsmount *mnt,
					    const int flag)
{
	return 0;
}

static inline int ccs_check_rewrite_permission(struct file *filp)
{
	return 0;
}

static inline int ccs_check_ioctl_permission(struct file *filp,
					     unsigned int cmd,
					     unsigned long arg)
{
	return 0;
}

static inline int ccs_parse_table(int __user *name, int nlen,
				  void __user *oldval, void __user *newval,
				  struct ctl_table *table)
{
	return 0;
}

static inline int ccs_check_signal_acl(const int sig, const int pid)
{
	return 0;
}

static inline _Bool ccs_capable(const u8 operation)
{
	return 1;
}

static inline int ccs_check_mknod_permission(struct inode *dir,
					     struct dentry *dentry,
					     struct vfsmount *mnt, int mode,
					     unsigned dev)
{
	return 0;
}

static inline int ccs_check_mkdir_permission(struct inode *dir,
					     struct dentry *dentry,
					     struct vfsmount *mnt, int mode)
{
	return 0;
}

static inline int ccs_check_rmdir_permission(struct inode *dir,
					     struct dentry *dentry,
					     struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_check_unlink_permission(struct inode *dir,
					      struct dentry *dentry,
					      struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_check_symlink_permission(struct inode *dir,
					       struct dentry *dentry,
					       struct vfsmount *mnt,
					       char *from)
{
	return 0;
}

static inline int ccs_check_truncate_permission(struct dentry *dentry,
						struct vfsmount *mnt,
						loff_t length,
						unsigned int time_attrs)
{
	return 0;
}

static inline int ccs_check_rename_permission(struct inode *old_dir,
					      struct dentry *old_dentry,
					      struct inode *new_dir,
					      struct dentry *new_dentry,
					      struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_check_link_permission(struct dentry *old_dentry,
					    struct inode *new_dir,
					    struct dentry *new_dentry,
					    struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_check_open_exec_permission(struct dentry *dentry,
						 struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_check_uselib_permission(struct dentry *dentry,
					      struct vfsmount *mnt)
{
	return 0;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
int ccs_may_create(struct inode *dir, struct dentry *dentry);
int ccs_may_delete(struct inode *dir, struct dentry *dentry, int is_dir);
#else
/* SUSE 11.0 adds is_dir for may_create(). */
#ifdef MS_WITHAPPEND
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
int ccs_may_create(struct inode *dir, struct dentry *dentry,
		   struct nameidata *nd, int is_dir);
#else
int ccs_may_create(struct inode *dir, struct dentry *dentry, int is_dir);
#endif
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
int ccs_may_create(struct inode *dir, struct dentry *dentry,
		   struct nameidata *nd);
#else
int ccs_may_create(struct inode *dir, struct dentry *dentry);
#endif
#endif
int ccs_may_delete(struct inode *dir, struct dentry *dentry, int is_dir);
#endif

int ccs_start_execve(struct linux_binprm *bprm);
void ccs_finish_execve(int retval);

int search_binary_handler(struct linux_binprm *, struct pt_regs *);

#if defined(CONFIG_SAKURA) || defined(CONFIG_TOMOYO)
static inline int ccs_search_binary_handler(struct linux_binprm *bprm,
					    struct pt_regs *regs)
{
	int retval = ccs_start_execve(bprm);
	if (!retval) {
		retval = search_binary_handler(bprm, regs);
		ccs_finish_execve(retval);
	}
	return retval;
}
#else
#define ccs_search_binary_handler search_binary_handler
#endif

/* Index numbers for Capability Controls. */
enum ccs_capability_acl_index {
	/* socket(PF_INET or PF_INET6, SOCK_STREAM, *)                 */
	CCS_INET_STREAM_SOCKET_CREATE,
	/* listen() for PF_INET or PF_INET6, SOCK_STREAM               */
	CCS_INET_STREAM_SOCKET_LISTEN,
	/* connect() for PF_INET or PF_INET6, SOCK_STREAM              */
	CCS_INET_STREAM_SOCKET_CONNECT,
	/* socket(PF_INET or PF_INET6, SOCK_DGRAM, *)                  */
	CCS_USE_INET_DGRAM_SOCKET,
	/* socket(PF_INET or PF_INET6, SOCK_RAW, *)                    */
	CCS_USE_INET_RAW_SOCKET,
	/* socket(PF_ROUTE, *, *)                                      */
	CCS_USE_ROUTE_SOCKET,
	/* socket(PF_PACKET, *, *)                                     */
	CCS_USE_PACKET_SOCKET,
	/* sys_mount()                                                 */
	CCS_SYS_MOUNT,
	/* sys_umount()                                                */
	CCS_SYS_UMOUNT,
	/* sys_reboot()                                                */
	CCS_SYS_REBOOT,
	/* sys_chroot()                                                */
	CCS_SYS_CHROOT,
	/* sys_kill(), sys_tkill(), sys_tgkill()                       */
	CCS_SYS_KILL,
	/* sys_vhangup()                                               */
	CCS_SYS_VHANGUP,
	/* do_settimeofday(), sys_adjtimex()                           */
	CCS_SYS_SETTIME,
	/* sys_nice(), sys_setpriority()                               */
	CCS_SYS_NICE,
	/* sys_sethostname(), sys_setdomainname()                      */
	CCS_SYS_SETHOSTNAME,
	/* sys_create_module(), sys_init_module(), sys_delete_module() */
	CCS_USE_KERNEL_MODULE,
	/* sys_mknod(S_IFIFO)                                          */
	CCS_CREATE_FIFO,
	/* sys_mknod(S_IFBLK)                                          */
	CCS_CREATE_BLOCK_DEV,
	/* sys_mknod(S_IFCHR)                                          */
	CCS_CREATE_CHAR_DEV,
	/* sys_mknod(S_IFSOCK)                                         */
	CCS_CREATE_UNIX_SOCKET,
	/* sys_link()                                                  */
	CCS_SYS_LINK,
	/* sys_symlink()                                               */
	CCS_SYS_SYMLINK,
	/* sys_rename()                                                */
	CCS_SYS_RENAME,
	/* sys_unlink()                                                */
	CCS_SYS_UNLINK,
	/* sys_chmod(), sys_fchmod()                                   */
	CCS_SYS_CHMOD,
	/* sys_chown(), sys_fchown(), sys_lchown()                     */
	CCS_SYS_CHOWN,
	/* sys_ioctl(), compat_sys_ioctl()                             */
	CCS_SYS_IOCTL,
	/* sys_kexec_load()                                            */
	CCS_SYS_KEXEC_LOAD,
	/* sys_pivot_root()                                            */
	CCS_SYS_PIVOT_ROOT,
	/* sys_ptrace()                                                */
	CCS_SYS_PTRACE,
	CCS_MAX_CAPABILITY_INDEX
};

#endif
