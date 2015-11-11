/*
 * include/linux/lsm2ccsecurity.h
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.8.5   2015/11/11
 */

#ifndef _LINUX_LSM2CCSECURITY_H
#define _LINUX_LSM2CCSECURITY_H

#include <linux/version.h>
#include <linux/uidgid.h>

#ifdef CONFIG_CCSECURITY

int ccs_settime(const struct timespec *ts, const struct timezone *tz);
int ccs_sb_mount(const char *dev_name, struct path *path, const char *type,
		 unsigned long flags, void *data);
int ccs_sb_umount(struct vfsmount *mnt, int flags);
int ccs_sb_pivotroot(struct path *old_path, struct path *new_path);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
int ccs_inode_getattr(struct vfsmount *mnt, struct dentry *dentry);
#else
int ccs_inode_getattr(const struct path *path);
#endif
int ccs_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int ccs_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg);
int ccs_file_open(struct file *file, const struct cred *cred);
int ccs_socket_create(int family, int type, int protocol, int kern);
int ccs_socket_bind(struct socket *sock, struct sockaddr *address,
		    int addrlen);
int ccs_socket_connect(struct socket *sock, struct sockaddr *address,
		       int addrlen);
int ccs_socket_listen(struct socket *sock, int backlog);
int ccs_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size);
int ccs_path_unlink(struct path *dir, struct dentry *dentry);
int ccs_path_mkdir(struct path *dir, struct dentry *dentry, umode_t mode);
int ccs_path_rmdir(struct path *dir, struct dentry *dentry);
int ccs_path_mknod(struct path *dir, struct dentry *dentry, umode_t mode,
		   unsigned int dev);
int ccs_path_truncate(struct path *path);
int ccs_path_symlink(struct path *dir, struct dentry *dentry,
		     const char *old_name);
int ccs_path_link(struct dentry *old_dentry, struct path *new_dir,
		  struct dentry *new_dentry);
int ccs_path_rename(struct path *old_dir, struct dentry *old_dentry,
		    struct path *new_dir, struct dentry *new_dentry);
int ccs_path_chmod(struct path *path, umode_t mode);
int ccs_path_chown(struct path *path, kuid_t uid, kgid_t gid);
int ccs_path_chroot(struct path *path);

#else

static inline int ccs_settime(const struct timespec *ts,
			      const struct timezone *tz)
{
	return 0;
}
static inline int ccs_sb_mount(const char *dev_name, struct path *path,
			       const char *type, unsigned long flags,
			       void *data)
{
	return 0;
}
static inline int ccs_sb_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}
static inline int ccs_sb_pivotroot(struct path *old_path,
				   struct path *new_path)
{
	return 0;
}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static inline int ccs_inode_getattr(struct vfsmount *mnt,
				    struct dentry *dentry)
{
	return 0;
}
#else
static inline int ccs_inode_getattr(const struct path *path)
{
	return 0;
}
#endif
static inline int ccs_file_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	return 0;
}
static inline int ccs_file_fcntl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	return 0;
}
static inline int ccs_file_open(struct file *file, const struct cred *cred)
{
	return 0;
}
static inline int ccs_socket_create(int family, int type, int protocol,
				    int kern)
{
	return 0;
}
static inline int ccs_socket_bind(struct socket *sock,
				  struct sockaddr *address, int addrlen)
{
	return 0;
}
static inline int ccs_socket_connect(struct socket *sock,
				     struct sockaddr *address, int addrlen)
{
	return 0;
}
static inline int ccs_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}
static inline int ccs_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				     int size)
{
	return 0;
}
static inline int ccs_path_unlink(struct path *dir, struct dentry *dentry)
{
	return 0;
}
static inline int ccs_path_mkdir(struct path *dir, struct dentry *dentry,
				 umode_t mode)
{
	return 0;
}
static inline int ccs_path_rmdir(struct path *dir, struct dentry *dentry)
{
	return 0;
}
static inline int ccs_path_mknod(struct path *dir, struct dentry *dentry,
				 umode_t mode, unsigned int dev)
{
	return 0;
}
static inline int ccs_path_truncate(struct path *path)
{
	return 0;
}
static inline int ccs_path_symlink(struct path *dir, struct dentry *dentry,
				   const char *old_name)
{
	return 0;
}
static inline int ccs_path_link(struct dentry *old_dentry,
				struct path *new_dir,
				struct dentry *new_dentry)
{
	return 0;
}
static inline int ccs_path_rename(struct path *old_dir,
				  struct dentry *old_dentry,
				  struct path *new_dir,
				  struct dentry *new_dentry)
{
	return 0;
}
static inline int ccs_path_chmod(struct path *path, umode_t mode)
{
	return 0;
}
static inline int ccs_path_chown(struct path *path, kuid_t uid, kgid_t gid)
{
	return 0;
}
static inline int ccs_path_chroot(struct path *path)
{
	return 0;
}

#endif /* defined(CONFIG_CCSECURITY) */

#endif /* !defined(_LINUX_LSM2CCSECURITY_H) */
