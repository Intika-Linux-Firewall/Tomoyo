/*
 * fs/syaoran.c
 *
 * Implementation of the Tamper-Proof Device Filesystem.
 *
 * Portions Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.4   2007/04/01
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

static struct super_operations syaoran_ops;
static struct address_space_operations syaoran_aops;
static struct file_operations syaoran_file_operations;
static struct inode_operations syaoran_dir_inode_operations;
static struct inode_operations syaoran_file_inode_operations;
static struct inode_operations syaoran_symlink_inode_operations;

#include <linux/syaoran.h>

static int syaoran_statfs(struct super_block *sb, struct statfs *buf)
{
	buf->f_type = SYAORAN_MAGIC;
	buf->f_bsize = PAGE_CACHE_SIZE;
	buf->f_namelen = NAME_MAX;
	return 0;
}

/*
 * Lookup the data. This is trivial - if the dentry didn't already
 * exist, we know it is negative.
 */
static struct dentry * syaoran_lookup(struct inode *dir, struct dentry *dentry)
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
static int syaoran_readpage(struct file *file, struct page * page)
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

static int syaoran_prepare_write(struct file *file, struct page *page, unsigned offset, unsigned to)
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

static int syaoran_commit_write(struct file *file, struct page *page, unsigned offset, unsigned to)
{
	struct inode *inode = page->mapping->host;
	loff_t pos = ((loff_t)page->index << PAGE_CACHE_SHIFT) + to;

	kunmap(page);
	if (pos > inode->i_size)
		inode->i_size = pos;
	return 0;
}

static struct inode *syaoran_get_inode(struct super_block *sb, int mode, int dev)
{
	struct inode * inode = new_inode(sb);

	if (inode) {
		inode->i_mode = mode;
		inode->i_uid = current->fsuid;
		inode->i_gid = current->fsgid;
		inode->i_blksize = PAGE_CACHE_SIZE;
		inode->i_blocks = 0;
		inode->i_rdev = NODEV;
		inode->i_mapping->a_ops = &syaoran_aops;
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
			inode->i_fop = &dcache_dir_ops;
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
static int syaoran_mknod(struct inode *dir, struct dentry *dentry, int mode, int dev)
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
	return syaoran_mknod(dir, dentry, mode | S_IFDIR, 0);
}

static int syaoran_create(struct inode *dir, struct dentry *dentry, int mode)
{
	return syaoran_mknod(dir, dentry, mode | S_IFREG, 0);
}

/*
 * Link a file..
 */
static int syaoran_link(struct dentry *old_dentry, struct inode * dir, struct dentry * dentry)
{
	struct inode *inode = old_dentry->d_inode;

	if (S_ISDIR(inode->i_mode))
		return -EPERM;
	if (MayCreateNode(dentry, inode->i_mode, inode->i_rdev) < 0) return -EPERM;

	inode->i_nlink++;
	atomic_inc(&inode->i_count); /* New dentry reference */
	dget(dentry); /* Extra pinning count for the created dentry */
	d_instantiate(dentry, inode);
	return 0;
}

static inline int syaoran_positive(struct dentry *dentry)
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
static int syaoran_empty(struct dentry *dentry)
{
	struct list_head *list;

	spin_lock(&dcache_lock);
	list = dentry->d_subdirs.next;

	while (list != &dentry->d_subdirs) {
		struct dentry *de = list_entry(list, struct dentry, d_child);

		if (syaoran_positive(de)) {
			spin_unlock(&dcache_lock);
			return 0;
		}
		list = list->next;
	}
	spin_unlock(&dcache_lock);
	return 1;
}

/*
 * This works for both directories and regular files.
 * (non-directories will always have empty subdirs)
 */
static int syaoran_unlink(struct inode * dir, struct dentry *dentry)
{
	int retval = -ENOTEMPTY;
	if (MayModifyNode(dentry, MAY_DELETE) < 0) return -EPERM;

	if (syaoran_empty(dentry)) {
		struct inode *inode = dentry->d_inode;

		inode->i_nlink--;
		dput(dentry); /* Undo the count from "create" - this does all the work */
		retval = 0;
	}
	return retval;
}

#define syaoran_rmdir syaoran_unlink

/*
 * The VFS layer already does all the dentry stuff for rename,
 * we just have to decrement the usage count for the target if
 * it exists so that the VFS layer correctly free's it when it
 * gets overwritten.
 */
static int syaoran_rename(struct inode * old_dir, struct dentry *old_dentry, struct inode * new_dir,struct dentry *new_dentry)
{
	int error = -ENOTEMPTY;
	struct inode *inode = old_dentry->d_inode;
	if (!inode || MayModifyNode(old_dentry, MAY_DELETE) < 0 || MayCreateNode(new_dentry, inode->i_mode, inode->i_rdev) < 0) return -EPERM;

	if (syaoran_empty(new_dentry)) {
		struct inode *inode = new_dentry->d_inode;
		if (inode) {
			inode->i_nlink--;
			dput(new_dentry);
		}
		error = 0;
	}
	return error;
}

static int syaoran_symlink(struct inode * dir, struct dentry *dentry, const char * symname)
{
	int error;
	if (MayCreateNode(dentry, S_IFLNK, 0) < 0) return -EPERM;

	error = syaoran_mknod(dir, dentry, S_IFLNK | S_IRWXUGO, 0);
	if (!error) {
		int l = strlen(symname)+1;
		struct inode *inode = dentry->d_inode;
		error = block_symlink(inode, symname, l);
	}
	return error;
}

static int syaoran_sync_file(struct file * file, struct dentry *dentry, int datasync)
{
	return 0;
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
	readpage:       syaoran_readpage,
	writepage:      fail_writepage,
	prepare_write:  syaoran_prepare_write,
	commit_write:   syaoran_commit_write
};

static struct file_operations syaoran_file_operations = {
	read:       generic_file_read,
	write:      generic_file_write,
	mmap:       generic_file_mmap,
	fsync:      syaoran_sync_file,
};

static struct inode_operations syaoran_dir_inode_operations = {
	create:     syaoran_create,
	lookup:     syaoran_lookup,
	link:       syaoran_link,
	unlink:     syaoran_unlink,
	symlink:    syaoran_symlink,
	mkdir:      syaoran_mkdir,
	rmdir:      syaoran_rmdir,
	mknod:      syaoran_mknod,
	rename:     syaoran_rename,
	setattr:    syaoran_setattr,
};

static struct inode_operations syaoran_symlink_inode_operations = {
	readlink:    page_readlink,
	follow_link: page_follow_link,
	setattr:     syaoran_setattr,
};

static struct inode_operations syaoran_file_inode_operations = {
	setattr: syaoran_setattr,
};

static struct super_operations syaoran_ops = {
	statfs:     syaoran_statfs,
	put_inode:  force_delete,
	put_super:  syaoran_put_super,
};

static struct super_block *syaoran_read_super(struct super_block * sb, void * data, int silent)
{
	struct inode * inode;
	struct dentry * root;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = SYAORAN_MAGIC;
	sb->s_op = &syaoran_ops;
	if (Syaoran_Initialize(sb, data) < 0) return NULL;
	inode = syaoran_get_inode(sb, S_IFDIR | 0755, 0);
	if (!inode)
		return NULL;

	root = d_alloc_root(inode);
	if (!root) {
		iput(inode);
		return NULL;
	}
	sb->s_root = root;
	MakeInitialNodes(sb);
	return sb;
}

static DECLARE_FSTYPE(syaoran_fs_type, "syaoran", syaoran_read_super, FS_LITTER);

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
