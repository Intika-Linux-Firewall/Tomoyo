/*
 * include/linux/tomoyo_vfs.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.6-pre   2008/12/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_TOMOYO_VFS_H
#define _LINUX_TOMOYO_VFS_H

#include <linux/version.h>

/*
 * This file contains copy of some of VFS helper functions.
 *
 * Since TOMOYO Linux requires "struct vfsmount" parameter to calculate
 * an absolute pathname of the requested "struct dentry" parameter
 * but the VFS helper functions don't receive "struct vfsmount" parameter,
 * TOMOYO Linux checks permission outside VFS helper functions.
 * To keep the DAC's permission checks are performed before the
 * TOMOYO Linux's permission checks are performed, I'm manually inserting
 * these functions that performs the DAC's permission checks into fs/namei.c.
 *
 * The approach to obtain "struct vfsmount" parameter from
 * the "struct task_struct" doesn't work because it triggers deadlock.
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

/* Some of permission checks from vfs_create(). */
static inline int pre_vfs_create(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = may_create(dir, dentry);
	if (!error && (!dir->i_op || !dir->i_op->create))
		error = -EACCES;
	up(&dir->i_zombie);
	return error;
}

/*
 * Some of permission checks from vfs_mknod().
 *
 * This function is exported because
 * vfs_mknod() is called from net/unix/af_unix.c.
 */
int pre_vfs_mknod(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = may_create(dir, dentry);
	if (!error && (!dir->i_op || !dir->i_op->mknod))
		error = -EPERM;
	up(&dir->i_zombie);
	return error;
}
EXPORT_SYMBOL(pre_vfs_mknod);

/* Some of permission checks from vfs_mkdir(). */
static inline int pre_vfs_mkdir(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = may_create(dir, dentry);
	if (!error && (!dir->i_op || !dir->i_op->mkdir))
		error = -EPERM;
	up(&dir->i_zombie);
	return error;
}

/* Some of permission checks from vfs_rmdir(). */
static inline int pre_vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 1);
	if (!error && (!dir->i_op || !dir->i_op->rmdir))
		error = -EPERM;
	return error;
}

/* Some of permission checks from vfs_unlink(). */
static inline int pre_vfs_unlink(struct inode *dir, struct dentry *dentry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 33)
	int error;
	down(&dir->i_zombie);
	error = may_delete(dir, dentry, 0);
	if (!error && (!dir->i_op || !dir->i_op->unlink))
		error = -EPERM;
	up(&dir->i_zombie);
	return error;
#else
	int error;
	struct inode *inode;
	error = may_delete(dir, dentry, 0);
	if (error)
		return error;
	inode = dentry->d_inode;
	atomic_inc(&inode->i_count);
	double_down(&dir->i_zombie, &inode->i_zombie);
	error = -EPERM;
	if (dir->i_op && dir->i_op->unlink)
		error = 0;
	double_up(&dir->i_zombie, &inode->i_zombie);
	iput(inode);
	return error;
#endif
}

/* Permission checks from vfs_symlink(). */
static inline int pre_vfs_symlink(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = may_create(dir, dentry);
	if (error)
		goto exit_lock;
	if (!dir->i_op || !dir->i_op->symlink)
		error = -EPERM;
 exit_lock:
	up(&dir->i_zombie);
	return error;
}

/* Some of permission checks from vfs_link(). */
static inline int pre_vfs_link(struct dentry *old_dentry, struct inode *dir,
			       struct dentry *new_dentry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 33)
	struct inode *inode;
	int error;
	down(&dir->i_zombie);
	error = -ENOENT;
	inode = old_dentry->d_inode;
	if (!inode)
		goto exit_lock;
	error = may_create(dir, new_dentry);
	if (error)
		goto exit_lock;
	error = -EXDEV;
	if (dir->i_dev != inode->i_dev)
		goto exit_lock;
	error = -EPERM;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		goto exit_lock;
	if (!dir->i_op || !dir->i_op->link)
		goto exit_lock;
	error = 0;
 exit_lock:
	up(&dir->i_zombie);
	return error;
#else
	struct inode *inode;
	int error;
	error = -ENOENT;
	inode = old_dentry->d_inode;
	if (!inode)
		goto exit;
	error = -EXDEV;
	if (dir->i_dev != inode->i_dev)
		goto exit;
	double_down(&dir->i_zombie, &old_dentry->d_inode->i_zombie);
	error = may_create(dir, new_dentry);
	if (error)
		goto exit_lock;
	error = -EPERM;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		goto exit_lock;
	if (!dir->i_op || !dir->i_op->link)
		goto exit_lock;
	error = 0;
 exit_lock:
	double_up(&dir->i_zombie, &old_dentry->d_inode->i_zombie);
 exit:
	return error;
#endif
}

/* Some of permission checks from vfs_rename_dir(). */
static inline int pre_vfs_rename_dir(struct inode *old_dir,
				     struct dentry *old_dentry,
				     struct inode *new_dir,
				     struct dentry *new_dentry)
{
	int error;
	if (old_dentry->d_inode == new_dentry->d_inode)
		return 0;
	error = may_delete(old_dir, old_dentry, 1);
	if (error)
		return error;
	if (new_dir->i_dev != old_dir->i_dev)
		return -EXDEV;
	if (!new_dentry->d_inode)
		error = may_create(new_dir, new_dentry);
	else
		error = may_delete(new_dir, new_dentry, 1);
	if (error)
		return error;
	if (!old_dir->i_op || !old_dir->i_op->rename)
		return -EPERM;
	if (new_dir != old_dir)
		error = permission(old_dentry->d_inode, MAY_WRITE);
	return error;
}

/* Some of permission checks from vfs_rename_other(). */
static inline int pre_vfs_rename_other(struct inode *old_dir,
				       struct dentry *old_dentry,
				       struct inode *new_dir,
				       struct dentry *new_dentry)
{
	int error;
	if (old_dentry->d_inode == new_dentry->d_inode)
		return 0;
	error = may_delete(old_dir, old_dentry, 0);
	if (error)
		return error;
	if (new_dir->i_dev != old_dir->i_dev)
		return -EXDEV;
	if (!new_dentry->d_inode)
		error = may_create(new_dir, new_dentry);
	else
		error = may_delete(new_dir, new_dentry, 0);
	if (error)
		return error;
	if (!old_dir->i_op || !old_dir->i_op->rename)
		return -EPERM;
	return 0;
}

/* Some of permission checks from vfs_rename(). */
static inline int pre_vfs_rename(struct inode *old_dir,
				 struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry)
{
	int error;
	lock_kernel(); /* From do_rename(). */
	if (S_ISDIR(old_dentry->d_inode->i_mode))
		error = pre_vfs_rename_dir(old_dir, old_dentry,
					   new_dir, new_dentry);
	else
		error = pre_vfs_rename_other(old_dir, old_dentry,
					     new_dir, new_dentry);
	unlock_kernel(); /* From do_rename(). */
	return error;
}

#else

/* SUSE 11.0 adds is_dir for may_create(). */
#ifdef MS_WITHAPPEND
#define HAVE_IS_DIR_FOR_MAY_CREATE
#endif

/*
 * Permission checks before security_inode_mknod() is called.
 *
 * This function is exported because
 * vfs_mknod() is called from net/unix/af_unix.c.
 */
int pre_vfs_mknod(struct inode *dir, struct dentry *dentry, int mode)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = may_create(dir, dentry, NULL, 0);
#else
	int error = may_create(dir, dentry, NULL);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = may_create(dir, dentry, 0);
#else
	int error = may_create(dir, dentry);
#endif
#endif
	if (error)
		return error;
	if ((S_ISCHR(mode) || S_ISBLK(mode)) && !capable(CAP_MKNOD))
		return -EPERM;
	if (!dir->i_op || !dir->i_op->mknod)
		return -EPERM;
	return 0;
}
EXPORT_SYMBOL(pre_vfs_mknod);

/* Permission checks before security_inode_mkdir() is called. */
static inline int pre_vfs_mkdir(struct inode *dir, struct dentry *dentry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = may_create(dir, dentry, NULL, 1);
#else
	int error = may_create(dir, dentry, NULL);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = may_create(dir, dentry, 1);
#else
	int error = may_create(dir, dentry);
#endif
#endif
	if (error)
		return error;
	if (!dir->i_op || !dir->i_op->mkdir)
		return -EPERM;
	return 0;
}

/* Some of permission checks before security_inode_rmdir() is called. */
static inline int pre_vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 1);
	if (error)
		return error;
	if (!dir->i_op || !dir->i_op->rmdir)
		return -EPERM;
	return 0;
}

/* Some of permission checks before security_inode_unlink() is called. */
static inline int pre_vfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 0);
	if (error)
		return error;
	if (!dir->i_op || !dir->i_op->unlink)
		return -EPERM;
	return 0;
}

/* Permission checks before security_inode_link() is called. */
static inline int pre_vfs_link(struct dentry *old_dentry, struct inode *dir,
			       struct dentry *new_dentry)
{
	struct inode *inode = old_dentry->d_inode;
	int error;
	if (!inode)
		return -ENOENT;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	error = may_create(dir, new_dentry, NULL, 0);
#else
	error = may_create(dir, new_dentry, NULL);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	error = may_create(dir, new_dentry, 0);
#else
	error = may_create(dir, new_dentry);
#endif
#endif
	if (error)
		return error;
	if (dir->i_sb != inode->i_sb)
		return -EXDEV;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;
	if (!dir->i_op || !dir->i_op->link)
		return -EPERM;
	if (S_ISDIR(old_dentry->d_inode->i_mode))
		return -EPERM;
	return 0;
}

/* Permission checks before security_inode_symlink() is called. */
static inline int pre_vfs_symlink(struct inode *dir, struct dentry *dentry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = may_create(dir, dentry, NULL, 0);
#else
	int error = may_create(dir, dentry, NULL);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	int error = may_create(dir, dentry, 0);
#else
	int error = may_create(dir, dentry);
#endif
#endif
	if (error)
		return error;
	if (!dir->i_op || !dir->i_op->symlink)
		return -EPERM;
	return 0;
}

/* Permission checks before security_inode_rename() is called. */
static inline int pre_vfs_rename(struct inode *old_dir,
				 struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry)
{
	int error;
	const int is_dir = S_ISDIR(old_dentry->d_inode->i_mode);
	if (old_dentry->d_inode == new_dentry->d_inode)
		return 0;
	error = may_delete(old_dir, old_dentry, is_dir);
	if (error)
		return error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	if (!new_dentry->d_inode)
		error = may_create(new_dir, new_dentry, NULL, is_dir);
	else
		error = may_delete(new_dir, new_dentry, is_dir);
#else
	if (!new_dentry->d_inode)
		error = may_create(new_dir, new_dentry, NULL);
	else
		error = may_delete(new_dir, new_dentry, is_dir);
#endif
#else
#ifdef HAVE_IS_DIR_FOR_MAY_CREATE
	if (!new_dentry->d_inode)
		error = may_create(new_dir, new_dentry, is_dir);
	else
		error = may_delete(new_dir, new_dentry, is_dir);
#else
	if (!new_dentry->d_inode)
		error = may_create(new_dir, new_dentry);
	else
		error = may_delete(new_dir, new_dentry, is_dir);
#endif
#endif
	if (error)
		return error;
	if (!old_dir->i_op || !old_dir->i_op->rename)
		return -EPERM;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
	if (is_dir && new_dir != old_dir)
		error = permission(old_dentry->d_inode, MAY_WRITE, NULL);
#else
	if (is_dir && new_dir != old_dir)
		error = inode_permission(old_dentry->d_inode, MAY_WRITE);
#endif
	return error;
}

#endif

#endif
