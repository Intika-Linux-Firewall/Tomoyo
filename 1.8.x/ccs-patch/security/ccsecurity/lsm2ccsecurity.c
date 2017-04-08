/*
 * security/ccsecurity/lsm2ccsecurity.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.8.5   2015/11/11
 */

#include <linux/path.h>
#include <linux/security.h>
#include <linux/ccsecurity.h>

int ccs_sb_umount(struct vfsmount *mnt, int flags)
{
	return ccs_umount_permission(mnt, flags);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
int ccs_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	return ccs_getattr_permission(mnt, dentry);
}
#else
int ccs_inode_getattr(const struct path *path)
{
	return ccs_getattr_permission(path->mnt, path->dentry);
}
#endif

int ccs_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return ccs_ioctl_permission(file, cmd, arg);
}

int ccs_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return ccs_fcntl_permission(file, cmd, arg);
}

int ccs_file_open(struct file *file, const struct cred *cred)
{
	return ccs_open_permission(file);
}

int ccs_socket_create(int family, int type, int protocol, int kern)
{
	return ccs_socket_create_permission(family, type, protocol);
}

int ccs_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return ccs_socket_bind_permission(sock, address, addrlen);
}

int ccs_socket_connect(struct socket *sock, struct sockaddr *address,
		       int addrlen)
{
	return ccs_socket_connect_permission(sock, address, addrlen);
}

int ccs_socket_listen(struct socket *sock, int backlog)
{
	return ccs_socket_listen_permission(sock);
}

int ccs_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	return ccs_socket_sendmsg_permission(sock, msg, size);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)

int ccs_settime(const struct timespec64 *ts, const struct timezone *tz)
{
	return ccs_capable(CCS_SYS_SETTIME) ? 0 : -EPERM;
}

int ccs_sb_mount(const char *dev_name, const struct path *path,
		 const char *type, unsigned long flags, void *data)
{
	return ccs_mount_permission(dev_name, path, type, flags, data);
}

int ccs_sb_pivotroot(const struct path *old_path, const struct path *new_path)
{
	return ccs_pivot_root_permission(old_path, new_path);
}

int ccs_path_unlink(const struct path *dir, struct dentry *dentry)
{
	return ccs_unlink_permission(dentry, dir->mnt);
}

int ccs_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
{
	return ccs_mkdir_permission(dentry, dir->mnt, mode);
}

int ccs_path_rmdir(const struct path *dir, struct dentry *dentry)
{
	return ccs_rmdir_permission(dentry, dir->mnt);
}

int ccs_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode,
		   unsigned int dev)
{
	return ccs_mknod_permission(dentry, dir->mnt, mode, dev);
}

int ccs_path_truncate(const struct path *path)
{
	return ccs_truncate_permission(path->dentry, path->mnt);
}

int ccs_path_symlink(const struct path *dir, struct dentry *dentry,
		     const char *old_name)
{
	return ccs_symlink_permission(dentry, dir->mnt, old_name);
}

int ccs_path_link(struct dentry *old_dentry, const struct path *new_dir,
		  struct dentry *new_dentry)
{
	return ccs_link_permission(old_dentry, new_dentry, new_dir->mnt);
}

int ccs_path_rename(const struct path *old_dir, struct dentry *old_dentry,
		    const struct path *new_dir, struct dentry *new_dentry)
{
	return ccs_rename_permission(old_dentry, new_dentry, new_dir->mnt);
}

int ccs_path_chmod(const struct path *path, umode_t mode)
{
	return ccs_chmod_permission(path->dentry, path->mnt, mode);
}

int ccs_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	return ccs_chown_permission(path->dentry, path->mnt, uid, gid);
}

int ccs_path_chroot(const struct path *path)
{
	return ccs_chroot_permission(path);
}

#else

int ccs_settime(const struct timespec *ts, const struct timezone *tz)
{
	return ccs_capable(CCS_SYS_SETTIME) ? 0 : -EPERM;
}

int ccs_sb_mount(const char *dev_name, struct path *path, const char *type,
		 unsigned long flags, void *data)
{
	return ccs_mount_permission(dev_name, path, type, flags, data);
}

int ccs_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	return ccs_pivot_root_permission(old_path, new_path);
}

int ccs_path_unlink(struct path *dir, struct dentry *dentry)
{
	return ccs_unlink_permission(dentry, dir->mnt);
}

int ccs_path_mkdir(struct path *dir, struct dentry *dentry, umode_t mode)
{
	return ccs_mkdir_permission(dentry, dir->mnt, mode);
}

int ccs_path_rmdir(struct path *dir, struct dentry *dentry)
{
	return ccs_rmdir_permission(dentry, dir->mnt);
}

int ccs_path_mknod(struct path *dir, struct dentry *dentry, umode_t mode,
		   unsigned int dev)
{
	return ccs_mknod_permission(dentry, dir->mnt, mode, dev);
}

int ccs_path_truncate(struct path *path)
{
	return ccs_truncate_permission(path->dentry, path->mnt);
}

int ccs_path_symlink(struct path *dir, struct dentry *dentry,
		     const char *old_name)
{
	return ccs_symlink_permission(dentry, dir->mnt, old_name);
}

int ccs_path_link(struct dentry *old_dentry, struct path *new_dir,
		  struct dentry *new_dentry)
{
	return ccs_link_permission(old_dentry, new_dentry, new_dir->mnt);
}

int ccs_path_rename(struct path *old_dir, struct dentry *old_dentry,
		    struct path *new_dir, struct dentry *new_dentry)
{
	return ccs_rename_permission(old_dentry, new_dentry, new_dir->mnt);
}

int ccs_path_chmod(struct path *path, umode_t mode)
{
	return ccs_chmod_permission(path->dentry, path->mnt, mode);
}

int ccs_path_chown(struct path *path, kuid_t uid, kgid_t gid)
{
	return ccs_chown_permission(path->dentry, path->mnt, uid, gid);
}

int ccs_path_chroot(struct path *path)
{
	return ccs_chroot_permission(path);
}

#endif

#if !defined(CONFIG_SECURITY_PATH)
EXPORT_SYMBOL(ccs_path_mkdir);
EXPORT_SYMBOL(ccs_path_mknod);
EXPORT_SYMBOL(ccs_path_unlink);
EXPORT_SYMBOL(ccs_path_rename);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) && defined(CONFIG_SECURITY)

#include <linux/lsm_hooks.h>

static struct security_hook_list ccsecurity_hooks[] = {
	LSM_HOOK_INIT(settime, ccs_settime),
	LSM_HOOK_INIT(sb_mount, ccs_sb_mount),
	LSM_HOOK_INIT(sb_umount, ccs_sb_umount),
	LSM_HOOK_INIT(sb_pivotroot, ccs_sb_pivotroot),
	LSM_HOOK_INIT(inode_getattr, ccs_inode_getattr),
	LSM_HOOK_INIT(file_ioctl, ccs_file_ioctl),
	LSM_HOOK_INIT(file_fcntl, ccs_file_fcntl),
	LSM_HOOK_INIT(file_open, ccs_file_open),
#if defined(CONFIG_SECURITY_NETWORK)
	LSM_HOOK_INIT(socket_create, ccs_socket_create),
	LSM_HOOK_INIT(socket_bind, ccs_socket_bind),
	LSM_HOOK_INIT(socket_connect, ccs_socket_connect),
	LSM_HOOK_INIT(socket_listen, ccs_socket_listen),
	LSM_HOOK_INIT(socket_sendmsg, ccs_socket_sendmsg),
#endif
#if defined(CONFIG_SECURITY_PATH)
	LSM_HOOK_INIT(path_unlink, ccs_path_unlink),
	LSM_HOOK_INIT(path_mkdir, ccs_path_mkdir),
	LSM_HOOK_INIT(path_rmdir, ccs_path_rmdir),
	LSM_HOOK_INIT(path_mknod, ccs_path_mknod),
	LSM_HOOK_INIT(path_truncate, ccs_path_truncate),
	LSM_HOOK_INIT(path_symlink, ccs_path_symlink),
	LSM_HOOK_INIT(path_link, ccs_path_link),
	LSM_HOOK_INIT(path_rename, ccs_path_rename),
	LSM_HOOK_INIT(path_chmod, ccs_path_chmod),
	LSM_HOOK_INIT(path_chown, ccs_path_chown),
	LSM_HOOK_INIT(path_chroot, ccs_path_chroot),
#endif
};

static int __init ccs_add_hooks(void)
{
	if (ccsecurity_ops.disabled)
		return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ccsecurity_hooks, ARRAY_SIZE(ccsecurity_hooks),
			   "ccsecurity");
#else
	security_add_hooks(ccsecurity_hooks, ARRAY_SIZE(ccsecurity_hooks));
#endif
	return 0;
}
late_initcall(ccs_add_hooks);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) && defined(CONFIG_SECURITY) */
