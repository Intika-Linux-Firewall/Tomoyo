/*
 * include/linux/tomoyo.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.7-rc   2009/03/18
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

#if defined(CONFIG_TOMOYO)

int ccs_check_file_perm(const char *filename, const u8 perm,
			const char *operation);
int ccs_check_open_permission(struct dentry *dentry, struct vfsmount *mnt,
			      const int flag);
int ccs_check_1path_perm(const u8 operation, struct dentry *dentry,
			 struct vfsmount *mnt);
int ccs_check_2path_perm(const u8 operation, struct dentry *dentry1,
			 struct vfsmount *mnt1, struct dentry *dentry2,
			 struct vfsmount *mnt2);
int ccs_check_rewrite_permission(struct file *filp);
int ccs_check_ioctl_permission(struct file *filp, unsigned int cmd,
			       unsigned long arg);

/* Check whether the given signal is allowed to use. */
int ccs_check_signal_acl(const int sig, const int pid);

/* Check whether the given capability is allowed to use. */
_Bool ccs_capable(const u8 operation);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
/* Some of permission checks from vfs_create(). */
int ccs_pre_vfs_create(struct inode *dir, struct dentry *dentry);
/* Some of permission checks from vfs_mknod(). */
int ccs_pre_vfs_mknod(struct inode *dir, struct dentry *dentry);
#else
/* Some of permission checks from vfs_mknod(). */
int ccs_pre_vfs_mknod(struct inode *dir, struct dentry *dentry, int mode);
#endif
/* Some of permission checks from vfs_mkdir(). */
int ccs_pre_vfs_mkdir(struct inode *dir, struct dentry *dentry);
/* Some of permission checks from vfs_rmdir(). */
int ccs_pre_vfs_rmdir(struct inode *dir, struct dentry *dentry);
/* Some of permission checks from vfs_unlink(). */
int ccs_pre_vfs_unlink(struct inode *dir, struct dentry *dentry);
/* Permission checks from vfs_symlink(). */
int ccs_pre_vfs_symlink(struct inode *dir, struct dentry *dentry);
/* Some of permission checks from vfs_link(). */
int ccs_pre_vfs_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *new_dentry);
/* Some of permission checks from vfs_rename(). */
int ccs_pre_vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry);

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
int ccs_may_create(struct inode *dir, struct dentry *dentry,
		   int is_dir);
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

#else

static inline int ccs_check_file_perm(const char *filename, const u8 perm,
				      const char *operation)
{
	return 0;
}
static inline int ccs_check_open_permission(struct dentry *dentry,
					    struct vfsmount *mnt,
					    const int flag)
{
	return 0;
}
static inline int ccs_check_1path_perm(const u8 operation,
				       struct dentry *dentry,
				       struct vfsmount *mnt)
{
	return 0;
}
static inline int ccs_check_2path_perm(const u8 operation,
				       struct dentry *dentry1,
				       struct vfsmount *mnt1,
				       struct dentry *dentry2,
				       struct vfsmount *mnt2)
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

static inline int ccs_check_signal_acl(const int sig, const int pid)
{
	return 0;
}
static inline _Bool ccs_capable(const u8 operation)
{
	return 1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

static inline int ccs_pre_vfs_create(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

static inline int ccs_pre_vfs_mknod(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

#else

static inline int ccs_pre_vfs_mknod(struct inode *dir, struct dentry *dentry,
				    int mode)
{
	return 0;
}

#endif

static inline int ccs_pre_vfs_mkdir(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

static inline int ccs_pre_vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

static inline int ccs_pre_vfs_unlink(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

static inline int ccs_pre_vfs_link(struct dentry *old_dentry, struct inode *dir,
				   struct dentry *new_dentry)
{
	return 0;
}

static inline int ccs_pre_vfs_symlink(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

static inline int ccs_pre_vfs_rename(struct inode *old_dir,
				     struct dentry *old_dentry,
				     struct inode *new_dir,
				     struct dentry *new_dentry)
{
	return 0;
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

#endif

int ccs_start_execve(struct linux_binprm *bprm);
void ccs_finish_execve(int retval);

int search_binary_handler(struct linux_binprm *, struct pt_regs *);

static inline int
search_binary_handler_with_transition(struct linux_binprm *bprm,
				      struct pt_regs *regs)
{
	int retval = ccs_start_execve(bprm);
	if (!retval) {
		retval = search_binary_handler(bprm, regs);
		ccs_finish_execve(retval);
	}
	return retval;
}

#define CCS_CHECK_READ_FOR_OPEN_EXEC    1
#define CCS_DONT_SLEEP_ON_ENFORCE_ERROR 2
#define CCS_TASK_IS_EXECUTE_HANDLER     4
#define CCS_TASK_IS_POLICY_MANAGER      8

/* Index numbers for File Controls. */

/*
 * TYPE_READ_WRITE_ACL is special. TYPE_READ_WRITE_ACL is automatically set
 * if both TYPE_READ_ACL and TYPE_WRITE_ACL are set. Both TYPE_READ_ACL and
 * TYPE_WRITE_ACL are automatically set if TYPE_READ_WRITE_ACL is set.
 * TYPE_READ_WRITE_ACL is automatically cleared if either TYPE_READ_ACL or
 * TYPE_WRITE_ACL is cleared. Both TYPE_READ_ACL and TYPE_WRITE_ACL are
 * automatically cleared if TYPE_READ_WRITE_ACL is cleared.
 */

enum ccs_single_path_acl_index {
	TYPE_READ_WRITE_ACL,
	TYPE_EXECUTE_ACL,
	TYPE_READ_ACL,
	TYPE_WRITE_ACL,
	TYPE_CREATE_ACL,
	TYPE_UNLINK_ACL,
	TYPE_MKDIR_ACL,
	TYPE_RMDIR_ACL,
	TYPE_MKFIFO_ACL,
	TYPE_MKSOCK_ACL,
	TYPE_MKBLOCK_ACL,
	TYPE_MKCHAR_ACL,
	TYPE_TRUNCATE_ACL,
	TYPE_SYMLINK_ACL,
	TYPE_REWRITE_ACL,
	MAX_SINGLE_PATH_OPERATION
};

enum ccs_double_path_acl_index {
	TYPE_LINK_ACL,
	TYPE_RENAME_ACL,
	MAX_DOUBLE_PATH_OPERATION
};

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

#define pre_vfs_create  ccs_pre_vfs_create
#define pre_vfs_mknod   ccs_pre_vfs_mknod
#define pre_vfs_mkdir   ccs_pre_vfs_mkdir
#define pre_vfs_rmdir   ccs_pre_vfs_rmdir
#define pre_vfs_unlink  ccs_pre_vfs_unlink
#define pre_vfs_symlink ccs_pre_vfs_symlink
#define pre_vfs_link    ccs_pre_vfs_link
#define pre_vfs_rename  ccs_pre_vfs_rename

#endif
