/*
 * include/linux/tomoyo.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.1-rc   2008/04/24
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

struct path_info;
struct dentry;
struct vfsmount;
struct inode;
struct linux_binprm;
struct pt_regs;
struct ccs_page_buffer;

#if defined(CONFIG_TOMOYO)

int ccs_check_file_perm(const char *filename, const u8 perm,
			const char *operation);
int ccs_check_exec_perm(const struct path_info *filename,
			struct linux_binprm *bprm,
			struct ccs_page_buffer *buf);
int ccs_check_open_permission(struct dentry *dentry, struct vfsmount *mnt,
			      const int flag);
int ccs_check_1path_perm(const u8 operation,
				     struct dentry *dentry,
				     struct vfsmount *mnt);
int ccs_check_2path_perm(const u8 operation,
				     struct dentry *dentry1,
				     struct vfsmount *mnt1,
				     struct dentry *dentry2,
				     struct vfsmount *mnt2);
int ccs_check_rewrite_permission(struct file *filp);

/* Check whether the basename of program and argv0 is allowed to differ. */
int ccs_check_argv0_perm(const struct path_info *filename, const char *argv0);

/* Check whether the given environment is allowed to be received. */
int ccs_check_env_perm(const char *env, const u8 profile, const u8 mode);

/* Check whether the given IP address and port number are allowed to use. */
int ccs_check_network_listen_acl(const _Bool is_ipv6, const u8 *address,
				 const u16 port);
int ccs_check_network_connect_acl(const _Bool is_ipv6, const int sock_type,
				  const u8 *address, const u16 port);
int ccs_check_network_bind_acl(const _Bool is_ipv6, const int sock_type,
			       const u8 *address, const u16 port);
int ccs_check_network_accept_acl(const _Bool is_ipv6, const u8 *address,
				 const u16 port);
int ccs_check_network_sendmsg_acl(const _Bool is_ipv6, const int sock_type,
				  const u8 *address, const u16 port);
int ccs_check_network_recvmsg_acl(const _Bool is_ipv6, const int sock_type,
				  const u8 *address, const u16 port);

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
static inline int ccs_check_exec_perm(const struct path_info *filename,
				      struct linux_binprm *bprm,
				      struct ccs_page_buffer *buf)
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
static inline int ccs_check_argv0_perm(const struct path_info *filename,
				       const char *argv0)
{
	return 0;
}
static inline int ccs_check_env_perm(const char *env, const u8 profile,
				     const u8 mode)
{
	return 0;
}
static inline int ccs_check_network_listen_acl(const _Bool is_ipv6,
					       const u8 *address,
					       const u16 port)
{
	return 0;
}
static inline int ccs_check_network_connect_acl(const _Bool is_ipv6,
						const int sock_type,
						const u8 *address,
						const u16 port)
{
	return 0;
}
static inline int ccs_check_network_bind_acl(const _Bool is_ipv6,
					     const int sock_type,
					     const u8 *address, const u16 port)
{
	return 0;
}
static inline int ccs_check_network_accept_acl(const _Bool is_ipv6,
					       const u8 *address,
					       const u16 port)
{
	return 0;
}
static inline int ccs_check_network_sendmsg_acl(const _Bool is_ipv6,
						const int sock_type,
						const u8 *address,
						const u16 port)
{
	return 0;
}
static inline int ccs_check_network_recvmsg_acl(const _Bool is_ipv6,
						const int sock_type,
						const u8 *address,
						const u16 port)
{
	return 0;
}
static inline int ccs_check_signal_acl(const int sig, const int pid)
{
	return 0;
}
static inline _Bool ccs_capable(const u8 operation)
{
	return true;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
int pre_vfs_mknod(struct inode *dir, struct dentry *dentry);
#else
int pre_vfs_mknod(struct inode *dir, struct dentry *dentry, int mode);
#endif

int search_binary_handler_with_transition(struct linux_binprm *bprm,
					  struct pt_regs *regs);
#define TOMOYO_CHECK_READ_FOR_OPEN_EXEC 1
#define CCS_DONT_SLEEP_ON_ENFORCE_ERROR 2
#define TOMOYO_TASK_IS_EXECUTE_HANDLER  4

/* Index numbers for Access Controls. */

#define TYPE_SINGLE_PATH_ACL                 0
#define TYPE_DOUBLE_PATH_ACL                 1
#define TYPE_ARGV0_ACL                       2
#define TYPE_ENV_ACL                         3
#define TYPE_CAPABILITY_ACL                  4
#define TYPE_IP_NETWORK_ACL                  5
#define TYPE_SIGNAL_ACL                      6
#define TYPE_EXECUTE_HANDLER                 7
#define TYPE_DENIED_EXECUTE_HANDLER          8

/* Index numbers for File Controls. */

/*
 * TYPE_READ_WRITE_ACL is special. TYPE_READ_WRITE_ACL is automatically set
 * if both TYPE_READ_ACL and TYPE_WRITE_ACL are set. Both TYPE_READ_ACL and
 * TYPE_WRITE_ACL are automatically set if TYPE_READ_WRITE_ACL is set.
 * TYPE_READ_WRITE_ACL is automatically cleared if either TYPE_READ_ACL or
 * TYPE_WRITE_ACL is cleared. Both TYPE_READ_ACL and TYPE_WRITE_ACL are
 * automatically cleared if TYPE_READ_WRITE_ACL is cleared.
 */

#define TYPE_READ_WRITE_ACL        0
#define TYPE_EXECUTE_ACL           1
#define TYPE_READ_ACL              2
#define TYPE_WRITE_ACL             3
#define TYPE_CREATE_ACL            4
#define TYPE_UNLINK_ACL            5
#define TYPE_MKDIR_ACL             6
#define TYPE_RMDIR_ACL             7
#define TYPE_MKFIFO_ACL            8
#define TYPE_MKSOCK_ACL            9
#define TYPE_MKBLOCK_ACL          10
#define TYPE_MKCHAR_ACL           11
#define TYPE_TRUNCATE_ACL         12
#define TYPE_SYMLINK_ACL          13
#define TYPE_REWRITE_ACL          14
#define MAX_SINGLE_PATH_OPERATION 15

#define TYPE_LINK_ACL             0
#define TYPE_RENAME_ACL           1
#define MAX_DOUBLE_PATH_OPERATION 2

/* Index numbers for Capability Controls. */

/* socket(PF_INET or PF_INET6, SOCK_STREAM, *)                 */
#define TOMOYO_INET_STREAM_SOCKET_CREATE         0
/* listen() for PF_INET or PF_INET6, SOCK_STREAM               */
#define TOMOYO_INET_STREAM_SOCKET_LISTEN         1
/* connect() for PF_INET or PF_INET6, SOCK_STREAM              */
#define TOMOYO_INET_STREAM_SOCKET_CONNECT        2
/* socket(PF_INET or PF_INET6, SOCK_DGRAM, *)                  */
#define TOMOYO_USE_INET_DGRAM_SOCKET             3
/* socket(PF_INET or PF_INET6, SOCK_RAW, *)                    */
#define TOMOYO_USE_INET_RAW_SOCKET               4
/* socket(PF_ROUTE, *, *)                                      */
#define TOMOYO_USE_ROUTE_SOCKET                  5
/* socket(PF_PACKET, *, *)                                     */
#define TOMOYO_USE_PACKET_SOCKET                 6
/* sys_mount()                                                 */
#define TOMOYO_SYS_MOUNT                         7
/* sys_umount()                                                */
#define TOMOYO_SYS_UMOUNT                        8
/* sys_reboot()                                                */
#define TOMOYO_SYS_REBOOT                        9
/* sys_chroot()                                                */
#define TOMOYO_SYS_CHROOT                       10
/* sys_kill(), sys_tkill(), sys_tgkill()                       */
#define TOMOYO_SYS_KILL                         11
/* sys_vhangup()                                               */
#define TOMOYO_SYS_VHANGUP                      12
/* do_settimeofday(), sys_adjtimex()                           */
#define TOMOYO_SYS_SETTIME                      13
/* sys_nice(), sys_setpriority()                               */
#define TOMOYO_SYS_NICE                         14
/* sys_sethostname(), sys_setdomainname()                      */
#define TOMOYO_SYS_SETHOSTNAME                  15
/* sys_create_module(), sys_init_module(), sys_delete_module() */
#define TOMOYO_USE_KERNEL_MODULE                16
/* sys_mknod(S_IFIFO)                                          */
#define TOMOYO_CREATE_FIFO                      17
/* sys_mknod(S_IFBLK)                                          */
#define TOMOYO_CREATE_BLOCK_DEV                 18
/* sys_mknod(S_IFCHR)                                          */
#define TOMOYO_CREATE_CHAR_DEV                  19
/* sys_mknod(S_IFSOCK)                                         */
#define TOMOYO_CREATE_UNIX_SOCKET               20
/* sys_link()                                                  */
#define TOMOYO_SYS_LINK                         21
/* sys_symlink()                                               */
#define TOMOYO_SYS_SYMLINK                      22
/* sys_rename()                                                */
#define TOMOYO_SYS_RENAME                       23
/* sys_unlink()                                                */
#define TOMOYO_SYS_UNLINK                       24
/* sys_chmod(), sys_fchmod()                                   */
#define TOMOYO_SYS_CHMOD                        25
/* sys_chown(), sys_fchown(), sys_lchown()                     */
#define TOMOYO_SYS_CHOWN                        26
/* sys_ioctl(), compat_sys_ioctl()                             */
#define TOMOYO_SYS_IOCTL                        27
/* sys_kexec_load()                                            */
#define TOMOYO_SYS_KEXEC_LOAD                   28
/* sys_pivot_root()                                            */
#define TOMOYO_SYS_PIVOT_ROOT                   29
/* sys_ptrace()                                                */
#define TOMOYO_SYS_PTRACE                       30
#define TOMOYO_MAX_CAPABILITY_INDEX             31

/* Index numbers for Network Controls. */

#define NETWORK_ACL_UDP_BIND    0
#define NETWORK_ACL_UDP_CONNECT 1
#define NETWORK_ACL_TCP_BIND    2
#define NETWORK_ACL_TCP_LISTEN  3
#define NETWORK_ACL_TCP_CONNECT 4
#define NETWORK_ACL_TCP_ACCEPT  5
#define NETWORK_ACL_RAW_BIND    6
#define NETWORK_ACL_RAW_CONNECT 7

/* For compatibility with 1.4.x/1.5.x patches */
#define CheckSingleWritePermission ccs_check_1path_perm
#define CheckDoubleWritePermission ccs_check_2path_perm
static inline int CheckCapabilityACL(const int capability)
{
	return ccs_capable(capability) ? 0 : -EPERM;
}
#define CheckFilePerm              ccs_check_file_perm
#define CheckSignalACL             ccs_check_signal_acl
#define CheckOpenPermission        ccs_check_open_permission
#define CheckReWritePermission     ccs_check_rewrite_permission

#endif
