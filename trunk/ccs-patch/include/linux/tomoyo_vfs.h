/*
 * include/linux/tomoyo_socket.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.3.2   2007/02/14
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_TOMOYO_VFS_H
#define _LINUX_TOMOYO_VFS_H

/***** TOMOYO Linux start. *****/

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)

static inline int pre_vfs_create(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = may_create(dir, dentry);
	if (!error && (!dir->i_op || !dir->i_op->create)) error = -EPERM; /* -ENOSYS ? */
	up(&dir->i_zombie);
	return error;
}

int pre_vfs_mknod(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = may_create(dir, dentry);
	if (!error && (!dir->i_op || !dir->i_op->mknod)) error = -EPERM; /* -ENOSYS ? */
	up(&dir->i_zombie);
	return error;
}
EXPORT_SYMBOL(pre_vfs_mknod);

static inline int pre_vfs_mkdir(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = may_create(dir, dentry);
	if (!error && (!dir->i_op || !dir->i_op->mkdir)) error = -EPERM;
	up(&dir->i_zombie);
	return error;
}

static inline int pre_vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 1);
	if (!error && (!dir->i_op || !dir->i_op->rmdir)) error = -EPERM;
	return error;
}

static inline int pre_vfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = may_delete(dir, dentry, 0);
	if (!error && (!dir->i_op || !dir->i_op->unlink)) error = -EPERM;
	up(&dir->i_zombie);
	return error;
}

static inline int pre_vfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	struct inode *inode;
	int error;
	down(&dir->i_zombie);
	error = -ENOENT;
	inode = old_dentry->d_inode;
	if (!inode) goto exit_lock;
	error = may_create(dir, new_dentry);
	if (error) goto exit_lock;
	error = -EXDEV;
	if (dir->i_dev != inode->i_dev) goto exit_lock;
	error = -EPERM;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode)) goto exit_lock;
	if (!dir->i_op || !dir->i_op->link) goto exit_lock;
	error = 0;
 exit_lock:
	up(&dir->i_zombie);
	return error;
}

static inline int pre_vfs_symlink(struct inode *dir, struct dentry *dentry)
{
	int error;
	down(&dir->i_zombie);
	error = may_create(dir, dentry);
	if (error) goto exit_lock;
	if (!dir->i_op || !dir->i_op->symlink) error = -EPERM;
 exit_lock:
	up(&dir->i_zombie);
	return error;
}

static inline int pre_vfs_rename_dir(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
	int error;
	if (old_dentry->d_inode == new_dentry->d_inode) return 0;
	error = may_delete(old_dir, old_dentry, 1);
	if (error) return error;
	if (new_dir->i_dev != old_dir->i_dev) return -EXDEV;
	if (!new_dentry->d_inode) error = may_create(new_dir, new_dentry);
	else error = may_delete(new_dir, new_dentry, 1);
	if (error) return error;
	if (!old_dir->i_op || !old_dir->i_op->rename) return -EPERM;
	if (new_dir != old_dir) error = permission(old_dentry->d_inode, MAY_WRITE);
	return error;
}

static inline int pre_vfs_rename_other(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
	int error;
	if (old_dentry->d_inode == new_dentry->d_inode) return 0;
	error = may_delete(old_dir, old_dentry, 0);
	if (error) return error;
	if (new_dir->i_dev != old_dir->i_dev) return -EXDEV;
	if (!new_dentry->d_inode) error = may_create(new_dir, new_dentry);
	else error = may_delete(new_dir, new_dentry, 0);
	if (error) return error;
	if (!old_dir->i_op || !old_dir->i_op->rename) return -EPERM;
	return 0;
}

static inline int pre_vfs_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
	int error;
	lock_kernel();
	if (S_ISDIR(old_dentry->d_inode->i_mode)) error = pre_vfs_rename_dir(old_dir,old_dentry,new_dir,new_dentry);
	else error = pre_vfs_rename_other(old_dir,old_dentry,new_dir,new_dentry);
	unlock_kernel();
	return error;
}

#else

int pre_vfs_mknod(struct inode *dir, struct dentry *dentry, int mode)
{
	int error = may_create(dir, dentry, NULL);
	if (error) return error;
	if ((S_ISCHR(mode) || S_ISBLK(mode)) && !capable(CAP_MKNOD)) return -EPERM;
	if (!dir->i_op || !dir->i_op->mknod) return -EPERM;
	return 0;
}
EXPORT_SYMBOL(pre_vfs_mknod);

static inline int pre_vfs_mkdir(struct inode *dir, struct dentry *dentry)
{
	int error = may_create(dir, dentry, NULL);
	if (error) return error;
	if (!dir->i_op || !dir->i_op->mkdir) return -EPERM;
	return 0;
}

static inline int pre_vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 1);
	if (error) return error;
	if (!dir->i_op || !dir->i_op->rmdir) return -EPERM;
	return 0;
}

static inline int pre_vfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 0);
	if (error) return error;
	if (!dir->i_op || !dir->i_op->unlink) return -EPERM;
	return 0;
}

static inline int pre_vfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	struct inode *inode = old_dentry->d_inode;
	int error;
	if (!inode) return -ENOENT;
	error = may_create(dir, new_dentry, NULL);
	if (error) return error;
	if (dir->i_sb != inode->i_sb) return -EXDEV;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode)) return -EPERM;
	if (!dir->i_op || !dir->i_op->link) return -EPERM;
	if (S_ISDIR(old_dentry->d_inode->i_mode)) return -EPERM;
	return 0;
}

static inline int pre_vfs_symlink(struct inode *dir, struct dentry *dentry)
{
	int error = may_create(dir, dentry, NULL);
	if (error) return error;
	if (!dir->i_op || !dir->i_op->symlink) return -EPERM;
	return 0;
}

static inline int pre_vfs_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
	int error = 0;
	lock_kernel();
	if (S_ISDIR(old_dentry->d_inode->i_mode) && new_dir != old_dir) error = permission(old_dentry->d_inode, MAY_WRITE, NULL);
	unlock_kernel();
	return error;
}

#endif

/***** TOMOYO Linux end. *****/
#endif
