/*
 * include/linux/tomoyo.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.7-pre   2009/02/02
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

/* Check whether the given signal is allowed to use. */
int ccs_check_signal_acl(const int sig, const int pid);

/* Check whether the given capability is allowed to use. */
_Bool ccs_capable(const u8 operation);

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
static inline int ccs_check_signal_acl(const int sig, const int pid)
{
	return 0;
}
static inline _Bool ccs_capable(const u8 operation)
{
	return 1;
}

#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
int pre_vfs_mknod(struct inode *dir, struct dentry *dentry);
#else
int pre_vfs_mknod(struct inode *dir, struct dentry *dentry, int mode);
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

#define TOMOYO_CHECK_READ_FOR_OPEN_EXEC 1
#define CCS_DONT_SLEEP_ON_ENFORCE_ERROR 2
#define TOMOYO_TASK_IS_EXECUTE_HANDLER  4
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
	TOMOYO_INET_STREAM_SOCKET_CREATE,
	/* listen() for PF_INET or PF_INET6, SOCK_STREAM               */
	TOMOYO_INET_STREAM_SOCKET_LISTEN,
	/* connect() for PF_INET or PF_INET6, SOCK_STREAM              */
	TOMOYO_INET_STREAM_SOCKET_CONNECT,
	/* socket(PF_INET or PF_INET6, SOCK_DGRAM, *)                  */
	TOMOYO_USE_INET_DGRAM_SOCKET,
	/* socket(PF_INET or PF_INET6, SOCK_RAW, *)                    */
	TOMOYO_USE_INET_RAW_SOCKET,
	/* socket(PF_ROUTE, *, *)                                      */
	TOMOYO_USE_ROUTE_SOCKET,
	/* socket(PF_PACKET, *, *)                                     */
	TOMOYO_USE_PACKET_SOCKET,
	/* sys_mount()                                                 */
	TOMOYO_SYS_MOUNT,
	/* sys_umount()                                                */
	TOMOYO_SYS_UMOUNT,
	/* sys_reboot()                                                */
	TOMOYO_SYS_REBOOT,
	/* sys_chroot()                                                */
	TOMOYO_SYS_CHROOT,
	/* sys_kill(), sys_tkill(), sys_tgkill()                       */
	TOMOYO_SYS_KILL,
	/* sys_vhangup()                                               */
	TOMOYO_SYS_VHANGUP,
	/* do_settimeofday(), sys_adjtimex()                           */
	TOMOYO_SYS_SETTIME,
	/* sys_nice(), sys_setpriority()                               */
	TOMOYO_SYS_NICE,
	/* sys_sethostname(), sys_setdomainname()                      */
	TOMOYO_SYS_SETHOSTNAME,
	/* sys_create_module(), sys_init_module(), sys_delete_module() */
	TOMOYO_USE_KERNEL_MODULE,
	/* sys_mknod(S_IFIFO)                                          */
	TOMOYO_CREATE_FIFO,
	/* sys_mknod(S_IFBLK)                                          */
	TOMOYO_CREATE_BLOCK_DEV,
	/* sys_mknod(S_IFCHR)                                          */
	TOMOYO_CREATE_CHAR_DEV,
	/* sys_mknod(S_IFSOCK)                                         */
	TOMOYO_CREATE_UNIX_SOCKET,
	/* sys_link()                                                  */
	TOMOYO_SYS_LINK,
	/* sys_symlink()                                               */
	TOMOYO_SYS_SYMLINK,
	/* sys_rename()                                                */
	TOMOYO_SYS_RENAME,
	/* sys_unlink()                                                */
	TOMOYO_SYS_UNLINK,
	/* sys_chmod(), sys_fchmod()                                   */
	TOMOYO_SYS_CHMOD,
	/* sys_chown(), sys_fchown(), sys_lchown()                     */
	TOMOYO_SYS_CHOWN,
	/* sys_ioctl(), compat_sys_ioctl()                             */
	TOMOYO_SYS_IOCTL,
	/* sys_kexec_load()                                            */
	TOMOYO_SYS_KEXEC_LOAD,
	/* sys_pivot_root()                                            */
	TOMOYO_SYS_PIVOT_ROOT,
	/* sys_ptrace()                                                */
	TOMOYO_SYS_PTRACE,
	TOMOYO_MAX_CAPABILITY_INDEX
};

/* ccs-patch-\*.diff uses '#ifdef TOMOYO_SYS_PTRACE' .*/
#define TOMOYO_SYS_PTRACE TOMOYO_SYS_PTRACE

#endif
