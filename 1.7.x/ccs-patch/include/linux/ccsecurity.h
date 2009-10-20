/*
 * include/linux/ccsecurity.h
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.1-pre   2009/10/20
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_CCSECURITY_H
#define _LINUX_CCSECURITY_H

#include <linux/version.h>

#ifndef __user
#define __user
#endif

struct path;
struct dentry;
struct vfsmount;
struct nameidata;
struct inode;
struct linux_binprm;
struct pt_regs;
struct file;
struct ctl_table;
struct iattr;
struct socket;
struct sockaddr;
struct sock;
struct sk_buff;
struct msghdr;

#if defined(CONFIG_CCSECURITY)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
/* Check whether the given pathname is allowed to chroot to. */
int ccs_chroot_permission(struct path *path);
/* Check whether the current process is allowed to pivot_root. */
int ccs_pivot_root_permission(struct path *old_path, struct path *new_path);
/* Check whether the given mount operation hides an mounted partition. */
int ccs_may_mount(struct path *path);
#else
int ccs_chroot_permission(struct nameidata *nd);
int ccs_pivot_root_permission(struct nameidata *old_nd,
			      struct nameidata *new_nd);
int ccs_may_mount(struct nameidata *nd);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
/* Check whether the mount operation with the given parameters is allowed. */
int ccs_mount_permission(char *dev_name, struct path *dir, char *type,
			 unsigned long flags, void *data_page);
#else
int ccs_mount_permission(char *dev_name, struct nameidata *nd, char *type,
			 unsigned long flags, void *data_page);
#endif

/* Check whether the given mountpoint is allowed to umount. */
int ccs_umount_permission(struct vfsmount *mnt, int flags);

/* Check whether the given local port is reserved. */
_Bool ccs_lport_reserved(const u16 port);

void ccs_save_open_mode(int mode);
void ccs_clear_open_mode(void);
int ccs_open_permission(struct dentry *dentry, struct vfsmount *mnt,
			const int flag);
int ccs_rewrite_permission(struct file *filp);
int ccs_ioctl_permission(struct file *filp, unsigned int cmd,
			 unsigned long arg);
int ccs_parse_table(int __user *name, int nlen, void __user *oldval,
		    void __user *newval, struct ctl_table *table);

/* Check whether the given capability is allowed to use. */
_Bool ccs_capable(const u8 operation);

int ccs_mknod_permission(struct inode *dir, struct dentry *dentry,
			 struct vfsmount *mnt, unsigned int mode,
			 unsigned int dev);
int ccs_mkdir_permission(struct inode *dir, struct dentry *dentry,
			 struct vfsmount *mnt, unsigned int mode);
int ccs_rmdir_permission(struct inode *dir, struct dentry *dentry,
			 struct vfsmount *mnt);
int ccs_unlink_permission(struct inode *dir, struct dentry *dentry,
			  struct vfsmount *mnt);
int ccs_symlink_permission(struct inode *dir, struct dentry *dentry,
			   struct vfsmount *mnt, const char *from);
int ccs_truncate_permission(struct dentry *dentry, struct vfsmount *mnt,
			    loff_t length, unsigned int time_attrs);
int ccs_rename_permission(struct inode *old_dir, struct dentry *old_dentry,
			  struct inode *new_dir, struct dentry *new_dentry,
			  struct vfsmount *mnt);
int ccs_link_permission(struct dentry *old_dentry, struct inode *new_dir,
			struct dentry *new_dentry, struct vfsmount *mnt);
int ccs_open_exec_permission(struct dentry *dentry, struct vfsmount *mnt);
int ccs_uselib_permission(struct dentry *dentry, struct vfsmount *mnt);
int ccs_kill_permission(pid_t pid, int sig);
int ccs_tgkill_permission(pid_t tgid, pid_t pid, int sig);
int ccs_tkill_permission(pid_t pid, int sig);

int ccs_socket_create_permission(int family, int type, int protocol);
int ccs_socket_listen_permission(struct socket *sock);
int ccs_socket_connect_permission(struct socket *sock, struct sockaddr *addr,
				  int addr_len);
int ccs_socket_bind_permission(struct socket *sock, struct sockaddr *addr,
			       int addr_len);
int ccs_socket_accept_permission(struct socket *sock, struct sockaddr *addr);
int ccs_socket_sendmsg_permission(struct socket *sock, struct msghdr *msg,
				  int size);
int ccs_socket_recvmsg_permission(struct sock *sk, struct sk_buff *skb,
				  const unsigned int flags);
int ccs_chown_permission(struct dentry *dentry, struct vfsmount *mnt,
			 uid_t user, gid_t group);
int ccs_chmod_permission(struct dentry *dentry, struct vfsmount *mnt,
			 mode_t mode);
int ccs_sigqueue_permission(pid_t pid, int sig);
int ccs_tgsigqueue_permission(pid_t tgid, pid_t pid, int sig);

#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
static inline int ccs_chroot_permission(struct path *path)
{
	return 0;
}

static inline int ccs_pivot_root_permission(struct path *old_path,
					    struct path *new_path)
{
	return 0;
}

static inline int ccs_may_mount(struct path *path)
{
	return 0;
}
#else
static inline int ccs_chroot_permission(struct nameidata *nd)
{
	return 0;
}

static inline int ccs_pivot_root_permission(struct nameidata *old_nd,
					    struct nameidata *new_nd)
{
	return 0;
}

static inline int ccs_may_mount(struct nameidata *nd)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
static inline int ccs_mount_permission(char *dev_name, struct path *dir,
				       char *type, unsigned long flags,
				       void *data_page)
{
	return 0;
}
#else
static inline int ccs_mount_permission(char *dev_name, struct nameidata *nd,
				       char *type, unsigned long flags,
				       void *data_page)
{
	return 0;
}
#endif

static inline int ccs_umount_permission(struct vfsmount *mnt, int flags)
{
	return 0;
}

static inline _Bool ccs_lport_reserved(const u16 port)
{
	return 0;
}

static inline void ccs_save_open_mode(int mode)
{
}

static inline void ccs_clear_open_mode(void)
{
}

static inline int ccs_open_permission(struct dentry *dentry,
				      struct vfsmount *mnt, const int flag)
{
	return 0;
}

static inline int ccs_rewrite_permission(struct file *filp)
{
	return 0;
}

static inline int ccs_ioctl_permission(struct file *filp, unsigned int cmd,
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

static inline _Bool ccs_capable(const u8 operation)
{
	return 1;
}

static inline int ccs_mknod_permission(struct inode *dir,
				       struct dentry *dentry,
				       struct vfsmount *mnt, unsigned int mode,
				       unsigned int dev)
{
	return 0;
}

static inline int ccs_mkdir_permission(struct inode *dir,
				       struct dentry *dentry,
				       struct vfsmount *mnt, unsigned int mode)
{
	return 0;
}

static inline int ccs_rmdir_permission(struct inode *dir,
				       struct dentry *dentry,
				       struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_unlink_permission(struct inode *dir,
					struct dentry *dentry,
					struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_symlink_permission(struct inode *dir,
					 struct dentry *dentry,
					 struct vfsmount *mnt, char *from)
{
	return 0;
}

static inline int ccs_truncate_permission(struct dentry *dentry,
					  struct vfsmount *mnt, loff_t length,
					  unsigned int time_attrs)
{
	return 0;
}

static inline int ccs_rename_permission(struct inode *old_dir,
					struct dentry *old_dentry,
					struct inode *new_dir,
					struct dentry *new_dentry,
					struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_link_permission(struct dentry *old_dentry,
				      struct inode *new_dir,
				      struct dentry *new_dentry,
				      struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_open_exec_permission(struct dentry *dentry,
					   struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_uselib_permission(struct dentry *dentry,
					struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_kill_permission(pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_tgkill_permission(pid_t tgid, pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_tkill_permission(pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_socket_create_permission(int family, int type,
					       int protocol)
{
	return 0;
}

static inline int ccs_socket_listen_permission(struct socket *sock)
{
	return 0;
}

static inline int ccs_socket_connect_permission(struct socket *sock,
						struct sockaddr *addr,
						int addr_len)
{
	return 0;
}

static inline int ccs_socket_bind_permission(struct socket *sock,
					     struct sockaddr *addr,
					     int addr_len)
{
	return 0;
}

static inline int ccs_socket_accept_permission(struct socket *sock,
					       struct sockaddr *addr)
{
	return 0;
}

static inline int ccs_socket_sendmsg_permission(struct socket *sock,
						struct msghdr *msg, int size)
{
	return 0;
}

static inline int ccs_socket_recvmsg_permission(struct sock *sk,
						struct sk_buff *skb,
						const unsigned int flags)
{
	return 0;
}

static inline int ccs_chown_permission(struct dentry *dentry,
				       struct vfsmount *mnt, uid_t user,
				       gid_t group)
{
	return 0;
}

static inline int ccs_chmod_permission(struct dentry *dentry,
				       struct vfsmount *mnt, mode_t mode)
{
	return 0;
}

static inline int ccs_sigqueue_permission(pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_tgsigqueue_permission(pid_t tgid, pid_t pid, int sig)
{
	return 0;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
int ccs_may_create(struct inode *dir, struct dentry *dentry);
int ccs_may_delete(struct inode *dir, struct dentry *dentry, int is_dir);
#else
int ccs_may_create(struct inode *dir, struct dentry *dentry, int is_dir);
int ccs_may_delete(struct inode *dir, struct dentry *dentry, int is_dir);
#endif

struct ccs_execve_entry;
int ccs_start_execve(struct linux_binprm *bprm, struct ccs_execve_entry **ee);
void ccs_finish_execve(int retval, struct ccs_execve_entry *ee);

int search_binary_handler(struct linux_binprm *, struct pt_regs *);

#if defined(CONFIG_CCSECURITY)
static inline int ccs_search_binary_handler(struct linux_binprm *bprm,
					    struct pt_regs *regs)
{
	struct ccs_execve_entry *ee;
	int retval = ccs_start_execve(bprm, &ee);
	if (!retval)
		retval = search_binary_handler(bprm, regs);
	ccs_finish_execve(retval, ee);
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
	/* conceal mount                                               */
	CCS_CONCEAL_MOUNT,
	CCS_MAX_CAPABILITY_INDEX
};

static inline int ccs_ptrace_permission(long request, long pid)
{
	return !ccs_capable(CCS_SYS_PTRACE);
}

#endif
