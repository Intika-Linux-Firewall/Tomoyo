/*
 * fs/syaoran_2.6.c
 *
 * Implementation of the Tamper-Proof Device Filesystem.
 *
 * Portions Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/05/05
 *
 * This file is applicable to 2.6.11 and later.
 * See README.ccs for ChangeLog.
 * This filesystem is developed using the ramfs implementation.
 *
 */
/*
 * Resizable simple ram filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 *
 * Usage limits added by David Gibson, Linuxcare Australia.
 * This file is released under the GPL.
 */

/*
 * NOTE! This filesystem is probably most useful
 * not as a real filesystem, but as an example of
 * how virtual filesystems can be written.
 *
 * It doesn't get much simpler than this. Consider
 * that this file implements the full semantics of
 * a POSIX-compliant read-write filesystem.
 *
 * Note in particular how the filesystem does not
 * need to implement any data structures of its own
 * to keep track of the virtual data: using the VFS
 * caches is sufficient.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/smp_lock.h>
#include <linux/backing-dev.h>

#include <asm/uaccess.h>

#include <linux/namei.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mm.h>

static struct super_operations ccs_ops;
static struct address_space_operations ccs_aops;
static struct inode_operations ccs_file_inode_operations;
static struct inode_operations ccs_dir_inode_operations;
static struct inode_operations ccs_symlink_inode_operations;
static struct file_operations ccs_file_operations;

static struct backing_dev_info ccs_backing_dev_info = {
	.ra_pages      = 0,    /* No readahead */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 12)
	.memory_backed = 1,    /* Does not contribute to dirty memory */
#else
	.capabilities  = BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_WRITEBACK |
	BDI_CAP_MAP_DIRECT | BDI_CAP_MAP_COPY |
	BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP |
	BDI_CAP_EXEC_MAP,
#endif
};

#include <linux/syaoran.h>

static struct inode *ccs_get_inode(struct super_block *sb, int mode,
				   dev_t dev)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		inode->i_mode = mode;
		inode->i_uid = current_fsuid();
		inode->i_gid = current_fsgid();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#ifndef HAVE_NO_I_BLKSIZE_IN_INODE
		inode->i_blksize = PAGE_CACHE_SIZE;
#endif
#endif
		inode->i_blocks = 0;
		inode->i_mapping->a_ops = &ccs_aops;
		inode->i_mapping->backing_dev_info = &ccs_backing_dev_info;
		inode->i_ctime = CURRENT_TIME;
		inode->i_mtime = inode->i_ctime;
		inode->i_atime = inode->i_mtime;
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			if (S_ISBLK(mode))
				inode->i_fop = &ccs_wrapped_def_blk_fops;
			else if (S_ISCHR(mode))
				inode->i_fop = &ccs_wrapped_def_chr_fops;
			inode->i_op = &ccs_file_inode_operations;
			break;
		case S_IFREG:
			inode->i_op = &ccs_file_inode_operations;
			inode->i_fop = &ccs_file_operations;
			break;
		case S_IFDIR:
			inode->i_op = &ccs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;
			/*
			 * directory inodes start off with i_nlink == 2
			 * (for "." entry)
			 */
			inode->i_nlink++;
			break;
		case S_IFLNK:
			inode->i_op = &ccs_symlink_inode_operations;
			break;
		}
	}
	return inode;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
/* SMP-safe */
static int ccs_mknod(struct inode *dir, struct dentry *dentry, int mode,
		     dev_t dev)
{
	struct inode *inode;
	int error = -ENOSPC;
	if (ccs_may_create_node(dentry, mode, dev) < 0)
		return -EPERM;
	inode = ccs_get_inode(dir->i_sb, mode, dev);
	if (inode) {
		if (dir->i_mode & S_ISGID) {
			inode->i_gid = dir->i_gid;
			if (S_ISDIR(mode))
				inode->i_mode |= S_ISGID;
		}
		d_instantiate(dentry, inode);
		dget(dentry); /* Extra count - pin the dentry in core */
		error = 0;
	}
	return error;
}

static int ccs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int retval = ccs_mknod(dir, dentry, mode | S_IFDIR, 0);
	if (!retval)
		dir->i_nlink++;
	return retval;
}

static int ccs_create(struct inode *dir, struct dentry *dentry, int mode,
		      struct nameidata *nd)
{
	return ccs_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int ccs_symlink(struct inode *dir, struct dentry *dentry,
		       const char *symname)
{
	struct inode *inode;
	int error = -ENOSPC;
	if (ccs_may_create_node(dentry, S_IFLNK, 0) < 0)
		return -EPERM;
	inode = ccs_get_inode(dir->i_sb, S_IFLNK|S_IRWXUGO, 0);
	if (inode) {
		int l = strlen(symname)+1;
		error = page_symlink(inode, symname, l);
		if (!error) {
			if (dir->i_mode & S_ISGID)
				inode->i_gid = dir->i_gid;
			d_instantiate(dentry, inode);
			dget(dentry);
		} else
			iput(inode);
	}
	return error;
}

static int ccs_link(struct dentry *old_dentry, struct inode *dir,
		    struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	if (!inode || ccs_may_create_node(dentry, inode->i_mode,
					  inode->i_rdev) < 0)
		return -EPERM;
	return simple_link(old_dentry, dir, dentry);
}

static int ccs_unlink(struct inode *dir, struct dentry *dentry)
{
	if (ccs_may_modify_node(dentry, MAY_DELETE) < 0)
		return -EPERM;
	return simple_unlink(dir, dentry);
}

static int ccs_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *inode = old_dentry->d_inode;
	if (!inode || ccs_may_modify_node(old_dentry, MAY_DELETE) < 0 ||
	    ccs_may_create_node(new_dentry, inode->i_mode,
				inode->i_rdev) < 0)
		return -EPERM;
	return simple_rename(old_dir, old_dentry, new_dir, new_dentry);
}

static int ccs_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (ccs_may_modify_node(dentry, MAY_DELETE) < 0)
		return -EPERM;
	return simple_rmdir(dir, dentry);
}

static int ccs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int error = inode_change_ok(inode, attr);
	if (!error) {
		unsigned int ia_valid = attr->ia_valid;
		unsigned int flags = 0;
		if (ia_valid & (ATTR_UID | ATTR_GID))
			flags |= MAY_CHOWN;
		if (ia_valid & ATTR_MODE)
			flags |= MAY_CHMOD;
		if (ccs_may_modify_node(dentry, flags) < 0)
			return -EPERM;
		if (!error)
			error = inode_setattr(inode, attr);
	}
	return error;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
static struct address_space_operations ccs_aops = {
	.readpage       = simple_readpage,
	.prepare_write  = simple_prepare_write,
	.commit_write   = simple_commit_write
};
#else
static int ccs_set_page_dirty_no_writeback(struct page *page)
{
	if (!PageDirty(page))
		SetPageDirty(page);
	return 0;
}
static struct address_space_operations ccs_aops = {
	.readpage       = simple_readpage,
	.write_begin    = simple_write_begin,
	.write_end      = simple_write_end,
	.set_page_dirty = ccs_set_page_dirty_no_writeback,
};
#endif

static struct file_operations ccs_file_operations = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	.read        = generic_file_read,
	.write       = generic_file_write,
#else
	.aio_read    = generic_file_aio_read,
	.read        = do_sync_read,
	.aio_write   = generic_file_aio_write,
	.write       = do_sync_write,
#endif
	.mmap        = generic_file_mmap,
	.fsync       = simple_sync_file,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23)
	.sendfile    = generic_file_sendfile,
#else
	.splice_read = generic_file_splice_read,
#endif
	.llseek      = generic_file_llseek,
};

static struct inode_operations ccs_file_inode_operations = {
	.getattr    = simple_getattr,
	.setattr    = ccs_setattr,
};

static struct inode_operations ccs_dir_inode_operations = {
	.create     = ccs_create,
	.lookup     = simple_lookup,
	.link       = ccs_link,
	.unlink     = ccs_unlink,
	.symlink    = ccs_symlink,
	.mkdir      = ccs_mkdir,
	.rmdir      = ccs_rmdir,
	.mknod      = ccs_mknod,
	.rename     = ccs_rename,
	.setattr    = ccs_setattr,
};

static struct inode_operations ccs_symlink_inode_operations = {
	.readlink       = generic_readlink,
	.follow_link    = page_follow_link_light,
	.put_link       = page_put_link,
	.setattr        = ccs_setattr,
};

static struct super_operations ccs_ops = {
	.statfs     = simple_statfs,
	.drop_inode = generic_delete_inode,
	.put_super  = ccs_put_super,
};

static int ccs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;
	struct dentry *root;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = CCS_MAGIC;
	sb->s_op = &ccs_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 9)
	sb->s_time_gran = 1;
#endif
	{
		int error = ccs_initialize(sb, data);
		if (error < 0)
			return error;
	}
	inode = ccs_get_inode(sb, S_IFDIR | 0755, 0);
	if (!inode)
		return -ENOMEM;

	root = d_alloc_root(inode);
	if (!root) {
		iput(inode);
		return -ENOMEM;
	}
	sb->s_root = root;
	ccs_make_initial_nodes(sb);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
static struct super_block *ccs_get_sb(struct file_system_type *fs_type,
				      int flags, const char *dev_name,
				      void *data)
{
	return get_sb_nodev(fs_type, flags, data, ccs_fill_super);
}
#else
static int ccs_get_sb(struct file_system_type *fs_type,
		      int flags, const char *dev_name, void *data,
		      struct vfsmount *mnt)
{
	return get_sb_nodev(fs_type, flags, data, ccs_fill_super, mnt);
}
#endif

static struct file_system_type ccs_fs_type = {
	.owner      = THIS_MODULE,
	.name       = "syaoran",
	.get_sb     = ccs_get_sb,
	.kill_sb    = kill_litter_super,
};

static int __init ccs_init_fs(void)
{
	return register_filesystem(&ccs_fs_type);
}

static void __exit ccs_exit_fs(void)
{
	unregister_filesystem(&ccs_fs_type);
}

module_init(ccs_init_fs);
module_exit(ccs_exit_fs);

MODULE_LICENSE("GPL");
