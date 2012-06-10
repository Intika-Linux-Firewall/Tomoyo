/*
 * fs/syaoran_2.6.c
 *
 * Implementation of the Tamper-Proof Device Filesystem.
 *
 * Portions Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.0.1 2005/12/06
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

static struct super_operations syaoran_ops;
static struct address_space_operations syaoran_aops;
static struct inode_operations syaoran_file_inode_operations;
static struct inode_operations syaoran_dir_inode_operations;
static struct inode_operations syaoran_symlink_inode_operations;
static struct file_operations syaoran_file_operations;

static struct backing_dev_info syaoran_backing_dev_info = {
	.ra_pages = 0,        /* No readahead */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
	.memory_backed  = 1,    /* Does not contribute to dirty memory */
#else
	.capabilities = BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_WRITEBACK |
					BDI_CAP_MAP_DIRECT | BDI_CAP_MAP_COPY |
					BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP,
#endif
};

#include <linux/syaoran.h>

struct inode *syaoran_get_inode(struct super_block *sb, int mode, dev_t dev)
{
	struct inode * inode = new_inode(sb);

	if (inode) {
		inode->i_mode = mode;
		inode->i_uid = current->fsuid;
		inode->i_gid = current->fsgid;
		inode->i_blksize = PAGE_CACHE_SIZE;
		inode->i_blocks = 0;
		inode->i_mapping->a_ops = &syaoran_aops;
		inode->i_mapping->backing_dev_info = &syaoran_backing_dev_info;
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			if (S_ISBLK(mode)) inode->i_fop = &wrapped_def_blk_fops;
			else if (S_ISCHR(mode)) inode->i_fop = &wrapped_def_chr_fops;
			inode->i_op = &syaoran_file_inode_operations;
			break;
		case S_IFREG:
			inode->i_op = &syaoran_file_inode_operations;
			inode->i_fop = &syaoran_file_operations;
			break;
		case S_IFDIR:
			inode->i_op = &syaoran_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;

			/* directory inodes start off with i_nlink == 2 (for "." entry) */
			inode->i_nlink++;
			break;
		case S_IFLNK:
			inode->i_op = &syaoran_symlink_inode_operations;
			break;
		}
	}
	return inode;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
/* SMP-safe */
static int
syaoran_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	struct inode * inode;
	int error = -ENOSPC;
	if (MayCreateNode(dentry, mode, dev) < 0) return -EPERM;
	inode = syaoran_get_inode(dir->i_sb, mode, dev);
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

static int syaoran_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
	int retval = syaoran_mknod(dir, dentry, mode | S_IFDIR, 0);
	if (!retval)
		dir->i_nlink++;
	return retval;
}

static int syaoran_create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd)
{
	return syaoran_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int syaoran_symlink(struct inode * dir, struct dentry *dentry, const char * symname)
{
	struct inode *inode;
	int error = -ENOSPC;
	if (MayCreateNode(dentry, S_IFLNK, 0) < 0) return -EPERM;
	inode = syaoran_get_inode(dir->i_sb, S_IFLNK|S_IRWXUGO, 0);
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

static int syaoran_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	if (!inode || MayCreateNode(dentry, inode->i_mode, inode->i_rdev) < 0) return -EPERM;
	return simple_link(old_dentry, dir, dentry);
}

static int syaoran_unlink(struct inode * dir, struct dentry *dentry)
{
	if (MayModifyNode(dentry, MAY_DELETE) < 0) return -EPERM;
	return simple_unlink(dir, dentry);
}

static int syaoran_rename(struct inode * old_dir, struct dentry *old_dentry, struct inode * new_dir,struct dentry *new_dentry)
{
	struct inode *inode = old_dentry->d_inode;
	if (!inode || MayModifyNode(old_dentry, MAY_DELETE) < 0 || MayCreateNode(new_dentry, inode->i_mode, inode->i_rdev) < 0) return -EPERM;
	return simple_rename(old_dir, old_dentry, new_dir, new_dentry);
}

static int syaoran_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (MayModifyNode(dentry, MAY_DELETE) < 0) return -EPERM;
	return simple_rmdir(dir, dentry);
}

static int syaoran_setattr(struct dentry * dentry, struct iattr * attr)
{
	struct inode *inode = dentry->d_inode;
	int error = inode_change_ok(inode, attr);
	if (!error) {
		unsigned int ia_valid = attr->ia_valid;
		unsigned int flags = 0;
		if (ia_valid & (ATTR_UID | ATTR_GID)) flags |= MAY_CHOWN;
		if (ia_valid & ATTR_MODE) flags |= MAY_CHMOD;
		if (MayModifyNode(dentry, flags) < 0) return -EPERM;
		if (!error) error = inode_setattr(inode, attr);
	}
	return error;
}

static struct address_space_operations syaoran_aops = {
	.readpage       = simple_readpage,
	.prepare_write  = simple_prepare_write,
	.commit_write   = simple_commit_write
};

static struct file_operations syaoran_file_operations = {
	.read       = generic_file_read,
	.write      = generic_file_write,
	.mmap       = generic_file_mmap,
	.fsync      = simple_sync_file,
	.sendfile   = generic_file_sendfile,
	.llseek     = generic_file_llseek,
};

static struct inode_operations syaoran_file_inode_operations = {
	.getattr    = simple_getattr,
	.setattr    = syaoran_setattr,
};

static struct inode_operations syaoran_dir_inode_operations = {
	.create     = syaoran_create,
	.lookup     = simple_lookup,
	.link       = syaoran_link,
	.unlink     = syaoran_unlink,
	.symlink    = syaoran_symlink,
	.mkdir      = syaoran_mkdir,
	.rmdir      = syaoran_rmdir,
	.mknod      = syaoran_mknod,
	.rename     = syaoran_rename,
	.setattr    = syaoran_setattr,
};

static struct inode_operations syaoran_symlink_inode_operations = {
	.readlink       = generic_readlink,
	.follow_link    = page_follow_link_light,
	.put_link       = page_put_link,
	.setattr        = syaoran_setattr,
};

static struct super_operations syaoran_ops = {
	.statfs     = simple_statfs,
	.drop_inode = generic_delete_inode,
	.put_super  = syaoran_put_super,
};

static int syaoran_fill_super(struct super_block * sb, void * data, int silent)
{
	struct inode * inode;
	struct dentry * root;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = SYAORAN_MAGIC;
	sb->s_op = &syaoran_ops;
	sb->s_time_gran = 1;
	{
		int error;
		if ((error = Syaoran_Initialize(sb, data)) < 0) return error;
	}
	inode = syaoran_get_inode(sb, S_IFDIR | 0755, 0);
	if (!inode)
		return -ENOMEM;

	root = d_alloc_root(inode);
	if (!root) {
		iput(inode);
		return -ENOMEM;
	}
	sb->s_root = root;
	MakeInitialNodes(sb);
	return 0;
}

struct super_block *syaoran_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return get_sb_nodev(fs_type, flags, data, syaoran_fill_super);
}

static struct file_system_type syaoran_fs_type = {
	.owner      = THIS_MODULE,
	.name       = "syaoran",
	.get_sb     = syaoran_get_sb,
	.kill_sb    = kill_litter_super,
};

static int __init init_syaoran_fs(void)
{
	return register_filesystem(&syaoran_fs_type);
}

static void __exit exit_syaoran_fs(void)
{
	unregister_filesystem(&syaoran_fs_type);
}

module_init(init_syaoran_fs)
module_exit(exit_syaoran_fs)

MODULE_LICENSE("GPL");

EXPORT_SYMBOL(syaoran_get_sb);
