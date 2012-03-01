/*
 * fs/syaoran.c
 *
 * Implementation of the Tamper-Proof Device Filesystem.
 *
 * Portions Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.6.9   2011/04/01
 *
 * This file is applicable to 2.4.30 and later.
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
#include <linux/init.h>
#include <linux/string.h>
#include <linux/locks.h>

#include <asm/uaccess.h>

#include <linux/smp_lock.h>
#include <linux/slab.h>

static struct super_operations ccs_ops;
static struct address_space_operations ccs_aops;
static struct file_operations ccs_file_operations;
static struct inode_operations ccs_dir_inode_operations;
static struct inode_operations ccs_file_inode_operations;
static struct inode_operations ccs_symlink_inode_operations;

#include <linux/syaoran.h>

static int ccs_statfs(struct super_block *sb, struct statfs *buf)
{
	buf->f_type = CCS_MAGIC;
	buf->f_bsize = PAGE_CACHE_SIZE;
	buf->f_namelen = NAME_MAX;
	return 0;
}

/*
 * Lookup the data. This is trivial - if the dentry didn't already
 * exist, we know it is negative.
 */
static struct dentry *ccs_lookup(struct inode *dir, struct dentry *dentry)
{
	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);
	d_add(dentry, NULL);
	return NULL;
}

/*
 * Read a page. Again trivial. If it didn't already exist
 * in the page cache, it is zero-filled.
 */
static int ccs_readpage(struct file *file, struct page *page)
{
	if (!Page_Uptodate(page)) {
		memset(kmap(page), 0, PAGE_CACHE_SIZE);
		kunmap(page);
		flush_dcache_page(page);
		SetPageUptodate(page);
	}
	UnlockPage(page);
	return 0;
}

static int ccs_prepare_write(struct file *file, struct page *page,
			     unsigned offset, unsigned to)
{
	void *addr = kmap(page);
	if (!Page_Uptodate(page)) {
		memset(addr, 0, PAGE_CACHE_SIZE);
		flush_dcache_page(page);
		SetPageUptodate(page);
	}
	SetPageDirty(page);
	return 0;
}

static int ccs_commit_write(struct file *file, struct page *page,
			    unsigned offset, unsigned to)
{
	struct inode *inode = page->mapping->host;
	loff_t pos = ((loff_t)page->index << PAGE_CACHE_SHIFT) + to;

	kunmap(page);
	if (pos > inode->i_size)
		inode->i_size = pos;
	return 0;
}

static struct inode *ccs_get_inode(struct super_block *sb, int mode,
				   int dev)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		inode->i_mode = mode;
		inode->i_uid = current->fsuid;
		inode->i_gid = current->fsgid;
		inode->i_blksize = PAGE_CACHE_SIZE;
		inode->i_blocks = 0;
		inode->i_rdev = NODEV;
		inode->i_mapping->a_ops = &ccs_aops;
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
			inode->i_fop = &dcache_dir_ops;
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
static int ccs_mknod(struct inode *dir, struct dentry *dentry, int mode,
		     int dev)
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
	return ccs_mknod(dir, dentry, mode | S_IFDIR, 0);
}

static int ccs_create(struct inode *dir, struct dentry *dentry, int mode)
{
	return ccs_mknod(dir, dentry, mode | S_IFREG, 0);
}

/*
 * Link a file..
 */
static int ccs_link(struct dentry *old_dentry, struct inode *dir,
		    struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;

	if (S_ISDIR(inode->i_mode))
		return -EPERM;
	if (ccs_may_create_node(dentry, inode->i_mode, inode->i_rdev) < 0)
		return -EPERM;

	inode->i_nlink++;
	atomic_inc(&inode->i_count); /* New dentry reference */
	dget(dentry); /* Extra pinning count for the created dentry */
	d_instantiate(dentry, inode);
	return 0;
}

static inline int ccs_positive(struct dentry *dentry)
{
	return dentry->d_inode && !d_unhashed(dentry);
}

/*
 * Check that a directory is empty (this works
 * for regular files too, they'll just always be
 * considered empty..).
 *
 * Note that an empty directory can still have
 * children, they just all have to be negative..
 */
static bool ccs_empty(struct dentry *dentry)
{
	struct list_head *list;

	/***** CRITICAL SECTION START *****/
	spin_lock(&dcache_lock);
	list = dentry->d_subdirs.next;

	while (list != &dentry->d_subdirs) {
		struct dentry *de = list_entry(list, struct dentry, d_child);

		if (ccs_positive(de)) {
			spin_unlock(&dcache_lock);
			return false;
		}
		list = list->next;
	}
	spin_unlock(&dcache_lock);
	/***** CRITICAL SECTION END *****/
	return true;
}

/*
 * This works for both directories and regular files.
 * (non-directories will always have empty subdirs)
 */
static int ccs_unlink(struct inode *dir, struct dentry *dentry)
{
	int retval = -ENOTEMPTY;
	if (ccs_may_modify_node(dentry, MAY_DELETE) < 0)
		return -EPERM;

	if (ccs_empty(dentry)) {
		struct inode *inode = dentry->d_inode;

		inode->i_nlink--;
		/* Undo the count from "create" - this does all the work */
		dput(dentry);
		retval = 0;
	}
	return retval;
}

#define ccs_rmdir ccs_unlink

/*
 * The VFS layer already does all the dentry stuff for rename,
 * we just have to decrement the usage count for the target if
 * it exists so that the VFS layer correctly free's it when it
 * gets overwritten.
 */
static int ccs_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry)
{
	int error = -ENOTEMPTY;
	struct inode *inode = old_dentry->d_inode;
	if (!inode || ccs_may_modify_node(old_dentry, MAY_DELETE) < 0 ||
	    ccs_may_create_node(new_dentry, inode->i_mode,
				inode->i_rdev) < 0)
		return -EPERM;

	if (ccs_empty(new_dentry)) {
		struct inode *inode = new_dentry->d_inode;
		if (inode) {
			inode->i_nlink--;
			dput(new_dentry);
		}
		error = 0;
	}
	return error;
}

static int ccs_symlink(struct inode *dir, struct dentry *dentry,
		       const char *symname)
{
	int error;
	if (ccs_may_create_node(dentry, S_IFLNK, 0) < 0)
		return -EPERM;

	error = ccs_mknod(dir, dentry, S_IFLNK | S_IRWXUGO, 0);
	if (!error) {
		int l = strlen(symname)+1;
		struct inode *inode = dentry->d_inode;
		error = block_symlink(inode, symname, l);
	}
	return error;
}

static int ccs_sync_file(struct file *file, struct dentry *dentry,
			 int datasync)
{
	return 0;
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

static struct address_space_operations ccs_aops = {
	.readpage      = ccs_readpage,
	.writepage     = fail_writepage,
	.prepare_write = ccs_prepare_write,
	.commit_write  = ccs_commit_write,
};

static struct file_operations ccs_file_operations = {
	.read  = generic_file_read,
	.write = generic_file_write,
	.mmap  = generic_file_mmap,
	.fsync = ccs_sync_file,
};

static struct inode_operations ccs_dir_inode_operations = {
	.create  = ccs_create,
	.lookup  = ccs_lookup,
	.link    = ccs_link,
	.unlink  = ccs_unlink,
	.symlink = ccs_symlink,
	.mkdir   = ccs_mkdir,
	.rmdir   = ccs_rmdir,
	.mknod   = ccs_mknod,
	.rename  = ccs_rename,
	.setattr = ccs_setattr,
};

static struct inode_operations ccs_symlink_inode_operations = {
	.readlink    = page_readlink,
	.follow_link = page_follow_link,
	.setattr     = ccs_setattr,
};

static struct inode_operations ccs_file_inode_operations = {
	.setattr = ccs_setattr,
};

static struct super_operations ccs_ops = {
	.statfs    = ccs_statfs,
	.put_inode = force_delete,
	.put_super = ccs_put_super,
};

static struct super_block *ccs_read_super(struct super_block *sb,
					  void *data, int silent)
{
	struct inode *inode;
	struct dentry *root;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = CCS_MAGIC;
	sb->s_op = &ccs_ops;
	if (ccs_initialize(sb, data) < 0)
		return NULL;
	inode = ccs_get_inode(sb, S_IFDIR | 0755, 0);
	if (!inode)
		return NULL;

	root = d_alloc_root(inode);
	if (!root) {
		iput(inode);
		return NULL;
	}
	sb->s_root = root;
	ccs_make_initial_nodes(sb);
	return sb;
}

static DECLARE_FSTYPE(ccs_fs_type, "syaoran", ccs_read_super, FS_LITTER);

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
