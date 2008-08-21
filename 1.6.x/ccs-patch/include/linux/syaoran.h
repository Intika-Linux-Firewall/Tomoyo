/*
 * include/linux/syaoran.h
 *
 * Implementation of the Tamper-Proof Device Filesystem.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.3+   2008/08/21
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/*
 * A brief description about SYAORAN:
 *
 *  SYAORAN stands for "Simple Yet All-important Object Realizing Abiding
 *  Nexus". SYAORAN is a filesystem for /dev with Mandatory Access Control.
 *
 *  /dev cannot be mounted for read-only mode, but this means that files on
 *  /dev might be tampered with. In other words, a device file might have
 *  inappropriate attributes (e.g. /dev/null has char-1-5 attributes).
 *  SYAORAN can restrict combinations of (pathname, attribute) that
 *  the system can create so that all files on this filesystem have appropriate
 *  attributes (e.g. /dev/null has char-1-3 attributes).
 *
 *  The attribute is one of directory, regular file, FIFO, UNIX domain socket,
 *  symbolic link, character or block device file with major/minor device
 *  numbers.
 *
 *  You can use SYAORAN alone, but I recommend you to use SYAORAN
 *  with SAKURA and TOMOYO.
 */

#ifndef _LINUX_SYAORAN_H
#define _LINUX_SYAORAN_H

#include <linux/version.h>

#define false 0
#define true 1

#ifndef __user
#define __user
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define s_fs_info u.generic_sbp
#else
#include <linux/audit.h>
#ifdef AUDIT_APPARMOR_AUDIT
/* AppArmor patch adds "struct vfsmount" to VFS helper functions. */
#define HAVE_VFSMOUNT_IN_VFS_HELPER
#endif
#endif

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#define bool _Bool
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14)
#define kzalloc(size, flags) ({						\
			void *ret = kmalloc((size), (flags));		\
			if (ret)					\
				memset(ret, 0, (size));			\
			ret; })
#endif

#ifndef list_for_each_entry_safe
#define list_for_each_entry_safe(pos, n, head, member)                  \
	for (pos = list_entry((head)->next, typeof(*pos), member),      \
		     n = list_entry(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#endif

/**
 * list_for_each_cookie - iterate over a list with cookie.
 * @pos:        the &struct list_head to use as a loop cursor.
 * @cookie:     the &struct list_head to use as a cookie.
 * @head:       the head for your list.
 *
 * Same with list_for_each except that this primitive uses cookie
 * so that we can continue iteration.
 */
#define list_for_each_cookie(pos, cookie, head)				\
	for (({ if (!cookie)						\
				     cookie = head; }), pos = (cookie)->next; \
	     prefetch(pos->next), pos != (head) || ((cookie) = NULL);	\
	     (cookie) = pos, pos = pos->next)

/* The following constants are used to restrict operations.*/
#define MAY_CREATE         1 /* This file is allowed to mknod()              */
#define MAY_DELETE         2 /* This file is allowed to unlink()             */
#define MAY_CHMOD          4 /* This file is allowed to chmod()              */
#define MAY_CHOWN          8 /* This file is allowed to chown()              */
#define DEVICE_USED       16 /* This block or character device file is used. */
#define NO_CREATE_AT_MOUNT 32 /* Don't create this file at mount().          */

/* some random number */
#define SYAORAN_MAGIC    0x2F646576 /* = '/dev' */

static void syaoran_put_super(struct super_block *sb);
static int syaoran_initialize(struct super_block *sb, void *data);
static void syaoran_make_initial_nodes(struct super_block *sb);
static int syaoran_may_create_node(struct dentry *dentry, int mode, int dev);
static int syaoran_may_modify_node(struct dentry *dentry, unsigned int flags);
static int syaoran_create_tracelog(struct super_block *sb,
				   const char *filename);

/* Wraps blkdev_open() to trace open operation for block devices. */
static int (*org_blkdev_open) (struct inode *inode, struct file *filp);
static struct file_operations wrapped_def_blk_fops;

static int wrapped_blkdev_open(struct inode *inode, struct file *filp)
{
	int error = org_blkdev_open(inode, filp);
	if (error != -ENXIO)
		syaoran_may_modify_node(filp->f_dentry, DEVICE_USED);
	return error;
}

/* Wraps chrdev_open() to trace open operation for character devices. */
static int (*org_chrdev_open) (struct inode *inode, struct file *filp);
static struct file_operations wrapped_def_chr_fops;

static int wrapped_chrdev_open(struct inode *inode, struct file *filp)
{
	int error = org_chrdev_open(inode, filp);
	if (error != -ENXIO)
		syaoran_may_modify_node(filp->f_dentry, DEVICE_USED);
	return error;
}

/* lookup_create() without nameidata. Called only while initialization. */
static struct dentry *lookup_create2(const char *name, struct dentry *base,
				     const bool is_dir)
{
	struct dentry *dentry;
	const int len = name ? strlen(name) : 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
	mutex_lock(&base->d_inode->i_mutex);
#else
	down(&base->d_inode->i_sem);
#endif
	dentry = lookup_one_len(name, base, len);
	if (IS_ERR(dentry))
		goto fail;
	if (!is_dir && name[len] && !dentry->d_inode)
		goto enoent;
	return dentry;
 enoent:
	dput(dentry);
	dentry = ERR_PTR(-ENOENT);
 fail:
	return dentry;
}

/* mkdir(). Called only while initialization. */
static int fs_mkdir(const char *pathname, struct dentry *base, int mode,
		    uid_t user, gid_t group)
{
	struct dentry *dentry = lookup_create2(pathname, base, 1);
	int error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
#ifdef HAVE_VFSMOUNT_IN_VFS_HELPER
		error = vfs_mkdir(base->d_inode, dentry, NULL, mode);
#else
		error = vfs_mkdir(base->d_inode, dentry, mode);
#endif
		if (!error) {
			lock_kernel();
			dentry->d_inode->i_uid = user;
			dentry->d_inode->i_gid = group;
			unlock_kernel();
		}
		dput(dentry);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
	mutex_unlock(&base->d_inode->i_mutex);
#else
	up(&base->d_inode->i_sem);
#endif
	return error;
}

/* mknod(). Called only while initialization. */
static int fs_mknod(const char *filename, struct dentry *base, int mode,
		    dev_t dev, uid_t user, gid_t group)
{
	struct dentry *dentry;
	int error;
	switch (mode & S_IFMT) {
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
	case S_IFREG:
		break;
	default:
		return -EPERM;
	}
	dentry = lookup_create2(filename, base, 0);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
#ifdef HAVE_VFSMOUNT_IN_VFS_HELPER
		error = vfs_mknod(base->d_inode, dentry, NULL, mode, dev);
#else
		error = vfs_mknod(base->d_inode, dentry, mode, dev);
#endif
		if (!error) {
			lock_kernel();
			dentry->d_inode->i_uid = user;
			dentry->d_inode->i_gid = group;
			unlock_kernel();
		}
		dput(dentry);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
	mutex_unlock(&base->d_inode->i_mutex);
#else
	up(&base->d_inode->i_sem);
#endif
	return error;
}

/* symlink(). Called only while initialization. */
static int fs_symlink(const char *pathname, struct dentry *base, char *oldname,
		      int mode, uid_t user, gid_t group)
{
	struct dentry *dentry = lookup_create2(pathname, base, 0);
	int error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
#ifdef HAVE_VFSMOUNT_IN_VFS_HELPER
		error = vfs_symlink(base->d_inode, dentry, NULL, oldname,
				    S_IALLUGO);
#else
		error = vfs_symlink(base->d_inode, dentry, oldname, S_IALLUGO);
#endif
#else
#ifdef HAVE_VFSMOUNT_IN_VFS_HELPER
		error = vfs_symlink(base->d_inode, dentry, NULL, oldname);
#else
		error = vfs_symlink(base->d_inode, dentry, oldname);
#endif
#endif
		if (!error) {
			lock_kernel();
			dentry->d_inode->i_mode = mode;
			dentry->d_inode->i_uid = user;
			dentry->d_inode->i_gid = group;
			unlock_kernel();
		}
		dput(dentry);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
	mutex_unlock(&base->d_inode->i_mutex);
#else
	up(&base->d_inode->i_sem);
#endif
	return error;
}

/*
 * Format string.
 * Leading and trailing whitespaces are removed.
 * Multiple whitespaces are packed into single space.
 */
static void normalize_line(unsigned char *buffer)
{
	unsigned char *sp = buffer;
	unsigned char *dp = buffer;
	bool first = true;
	while (*sp && (*sp <= ' ' || *sp >= 127))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (*sp > ' ' && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || *sp >= 127))
			sp++;
	}
	*dp = '\0';
}

/* Convert text form of filename into binary form. */
static void unescape(char *filename)
{
	char *cp = filename;
	char c;
	char d;
	char e;
	if (!cp)
		return;
	while ((c = *filename++) != '\0') {
		if (c != '\\') {
			*cp++ = c;
			continue;
		}
		c = *filename++;
		if (c == '\\') {
			*cp++ = c;
			continue;
		}
		if (c < '0' || c > '3')
			break;
		d = *filename++;
		if (d < '0' || d > '7')
			break;
		e = *filename++;
		if (e < '0' || e > '7')
			break;
		*(unsigned char *) cp++ = (unsigned char)
			(((unsigned char) (c - '0') << 6)
			 + ((unsigned char) (d - '0') << 3)
			 + (unsigned char) (e - '0'));
	}
	*cp = '\0';
}

static char *strdup(const char *str)
{
	const int len = str ? strlen(str) + 1 : 0;
	char *cp = kzalloc(len, GFP_KERNEL);
	if (cp)
		memmove(cp, str, len);
	return cp;
}

/* -1: Not specified, 0: Enforce by default, 1: Accept by default. */
static int syaoran_default_mode = -1;

#if !defined(MODULE)
static int __init syaoran_setup(char *str)
{
	if (!strcmp(str, "accept"))
		syaoran_default_mode = 1;
	else if (!strcmp(str, "enforce"))
		syaoran_default_mode = 0;
	return 0;
}

__setup("SYAORAN=", syaoran_setup);
#endif

/* The structure for possible device list. */
struct dev_entry {
	struct list_head list;
	/* Binary form of pathname under mount point. Never NULL. */
	char *name;
	/*
	 * Mode and permissions.
	 * setuid/setgid/sticky bits are not supported.
	 */
	mode_t mode;
	uid_t uid;
	gid_t gid;
	dev_t kdev;
	/*
	 * Binary form of initial contents for the symlink. NULL if not symlink.
	 */
	char *symlink_data;
	/* File access control flags. */
	unsigned int flags;
	/* Text form of pathname under mount point. Never NULL. */
	const char *printable_name;
	/*
	 * Text form of initial contents for the symlink. NULL if not symlink.
	 */
	const char *printable_symlink_data;
};

struct syaoran_sb_info {
	struct list_head list;
	bool initialize_done;     /* False if initialization is in progress. */
	bool is_permissive_mode;  /* True if permissive mode.                */
};

static int syaoran_register_node_info(char *buffer, struct super_block *sb)
{
	enum {
		ARG_FILENAME     = 0,
		ARG_PERMISSION   = 1,
		ARG_UID          = 2,
		ARG_GID          = 3,
		ARG_FLAGS        = 4,
		ARG_DEV_TYPE     = 5,
		ARG_SYMLINK_DATA = 6,
		ARG_DEV_MAJOR    = 6,
		ARG_DEV_MINOR    = 7,
		MAX_ARG          = 8
	};
	char *args[MAX_ARG];
	int i;
	int error = -EINVAL;
	unsigned int perm;
	unsigned int uid;
	unsigned int gid;
	unsigned int flags;
	unsigned int major = 0;
	unsigned int minor = 0;
	struct syaoran_sb_info *info =
		(struct syaoran_sb_info *) sb->s_fs_info;
	struct dev_entry *entry;
	if (!info)
		return -EINVAL;
	memset(args, 0, sizeof(args));
	args[0] = buffer;
	for (i = 1; i < MAX_ARG; i++) {
		args[i] = strchr(args[i - 1] + 1, ' ');
		if (!args[i])
			break;
		*args[i]++ = '\0';
	}
	/*
	  printk(KERN_DEBUG "<%s> <%s> <%s> <%s> <%s> <%s> <%s> <%s>\n",
	  args[0], args[1], args[2], args[3], args[4], args[5], args[6],
	  args[7]);
	*/
	if (!args[ARG_FILENAME] || !args[ARG_PERMISSION] || !args[ARG_UID] ||
	    !args[ARG_GID] || !args[ARG_DEV_TYPE] || !args[ARG_FLAGS])
		goto out;
	if (sscanf(args[ARG_PERMISSION], "%o", &perm) != 1 ||
	    !(perm <= 0777) || sscanf(args[ARG_UID], "%u", &uid) != 1 ||
	    sscanf(args[ARG_GID], "%u", &gid) != 1 ||
	    sscanf(args[ARG_FLAGS], "%u", &flags) != 1 ||
	    *(args[ARG_DEV_TYPE] + 1))
		goto out;
	switch (*args[ARG_DEV_TYPE]) {
	case 'c':
		perm |= S_IFCHR;
		if (!args[ARG_DEV_MAJOR] ||
		    sscanf(args[ARG_DEV_MAJOR], "%u", &major) != 1 ||
		    !args[ARG_DEV_MINOR] ||
		    sscanf(args[ARG_DEV_MINOR], "%u", &minor) != 1)
			goto out;
		break;
	case 'b':
		perm |= S_IFBLK;
		if (!args[ARG_DEV_MAJOR] ||
		    sscanf(args[ARG_DEV_MAJOR], "%u", &major) != 1 ||
		    !args[ARG_DEV_MINOR] ||
		    sscanf(args[ARG_DEV_MINOR], "%u", &minor) != 1)
			goto out;
		break;
	case 'l':
		perm |= S_IFLNK;
		if (!args[ARG_SYMLINK_DATA])
			goto out;
		break;
	case 'd':
		perm |= S_IFDIR;
		break;
	case 's':
		perm |= S_IFSOCK;
		break;
	case 'p':
		perm |= S_IFIFO;
		break;
	case 'f':
		perm |= S_IFREG;
		break;
	default:
		goto out;
	}
	error = -ENOMEM;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		goto out;
	if (S_ISLNK(perm)) {
		entry->printable_symlink_data = strdup(args[ARG_SYMLINK_DATA]);
		if (!entry->printable_symlink_data)
			goto out_freemem;
	}
	entry->printable_name = strdup(args[ARG_FILENAME]);
	if (!entry->printable_name)
		goto out_freemem;
	if (S_ISLNK(perm)) {
		entry->symlink_data = strdup(entry->printable_symlink_data);
		if (!entry->symlink_data)
			goto out_freemem;
		unescape(entry->symlink_data);
	}
	entry->name = strdup(entry->printable_name);
	if (!entry->name)
		goto out_freemem;
	unescape(entry->name);
	{
		/*
		 * Drop trailing '/', for get_local_absolute_path() doesn't
		 * append trailing '/'.
		 */
		const int len = strlen(entry->name);
		if (len && entry->name[len - 1] == '/')
			entry->name[len - 1] = '\0';
	}
	entry->mode = perm;
	entry->uid = uid;
	entry->gid = gid;
	entry->kdev = S_ISCHR(perm) || S_ISBLK(perm) ? MKDEV(major, minor) : 0;
	entry->flags = flags;
	list_add_tail(&entry->list, &info->list);
	/* printk(KERN_DEBUG "Entry added.\n"); */
	error = 0;
 out:
	return error;
 out_freemem:
	kfree(entry->printable_symlink_data);
	kfree(entry->printable_name);
	kfree(entry->symlink_data);
	kfree(entry);
	goto out;
}

static void syaoran_put_super(struct super_block *sb)
{
	struct syaoran_sb_info *info;
	struct dev_entry *entry;
	struct dev_entry *tmp;
	if (!sb)
		return;
	info = (struct syaoran_sb_info *) sb->s_fs_info;
	if (!info)
		return;
	sb->s_fs_info = NULL;
	list_for_each_entry_safe(entry, tmp, &info->list, list) {
		kfree(entry->name);
		kfree(entry->symlink_data);
		kfree(entry->printable_name);
		kfree(entry->printable_symlink_data);
		list_del(&entry->list);
		/* printk(KERN_DEBUG "Entry removed.\n"); */
		kfree(entry);
	}
	kfree(info);
	printk(KERN_INFO "%s: Unused memory freed.\n", __func__);
}

static int syaoran_read_config_file(struct file *file, struct super_block *sb)
{
	char *buffer;
	int len;
	char *cp;
	unsigned long offset = 0;
	int error = -ENOMEM;
	if (!file)
		return -EINVAL;
	buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer)
		goto out;
	while ((len = kernel_read(file, offset, buffer, PAGE_SIZE)) > 0 &&
	       (cp = memchr(buffer, '\n', len)) != NULL) {
		*cp = '\0';
		offset += cp - buffer + 1;
		normalize_line(buffer);
		if (syaoran_register_node_info(buffer, sb) == -ENOMEM)
			goto out;
	}
	error = 0;
 out:
	kfree(buffer);
	return error;
}

static void syaoran_make_node(struct dev_entry *entry, struct dentry *root)
{
	struct dentry *base = dget(root);
	char *filename = entry->name;
	char *name = filename;
	unsigned int c;
	const mode_t perm = entry->mode;
	const uid_t uid = entry->uid;
	const gid_t gid = entry->gid;
	goto start;
	while ((c = *(unsigned char *) filename) != '\0') {
		if (c == '/') {
			struct dentry *new_base;
			const int len = filename - name;
			*filename = '\0';
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
			mutex_lock(&base->d_inode->i_mutex);
			new_base = lookup_one_len(name, base, len);
			mutex_unlock(&base->d_inode->i_mutex);
#else
			down(&base->d_inode->i_sem);
			new_base = lookup_one_len(name, base, len);
			up(&base->d_inode->i_sem);
#endif
			dput(base);
			*filename++ = '/';
			if (IS_ERR(new_base)) {
				/*
				  printk(KERN_DEBUG "'%s' = %ld\n", entry->name,
				  PTR_ERR(new_base));
				*/
				return;
			} else if (!new_base->d_inode ||
				   !S_ISDIR(new_base->d_inode->i_mode)) {
				/*
				  printk(KERN_DEBUG
				  "Directory '%s' does not exist.\n",
				  entry->name);
				*/
				dput(new_base);
				return;
			}
			/*
			  printk(KERN_DEBUG "Directory '%s' exists.\n",
			  entry->name);
			*/
			base = new_base;
 start:
			name = filename;
		} else {
			filename++;
		}
	}
	filename = (char *) name;
	if (S_ISLNK(perm))
		fs_symlink(filename, base, entry->symlink_data, perm, uid, gid);
	else if (S_ISDIR(perm))
		fs_mkdir(filename, base, perm ^ S_IFDIR, uid, gid);
	else if (S_ISSOCK(perm) || S_ISFIFO(perm) || S_ISREG(perm))
		fs_mknod(filename, base, perm, 0, uid, gid);
	else if (S_ISCHR(perm) || S_ISBLK(perm))
		fs_mknod(filename, base, perm, entry->kdev, uid, gid);
	dput(base);
}

/* Create files according to the policy file. */
static void syaoran_make_initial_nodes(struct super_block *sb)
{
	struct syaoran_sb_info *info;
	struct dev_entry *entry;
	if (!sb)
		return;
	info = (struct syaoran_sb_info *) sb->s_fs_info;
	if (!info)
		return;
	if (info->is_permissive_mode) {
		syaoran_create_tracelog(sb, ".syaoran");
		syaoran_create_tracelog(sb, ".syaoran_all");
	}
	list_for_each_entry(entry, &info->list, list) {
		if ((entry->flags & NO_CREATE_AT_MOUNT) == 0)
			syaoran_make_node(entry, sb->s_root);
	}
	info->initialize_done = true;
}

/* Read policy file. */
static int syaoran_initialize(struct super_block *sb, void *data)
{
	int error = -EINVAL;
	struct file *f;
	char *filename = (char *) data;
	bool is_permissive_mode = syaoran_default_mode;
	static bool first = true;
	if (first) {
		first = false;
		printk(KERN_INFO "SYAORAN: 1.6.3   2008/08/21\n");
	}
	{
		struct inode *inode = new_inode(sb);
		if (!inode)
			return -EINVAL;
		/* Create /dev/ram0 to get the value of blkdev_open(). */
		init_special_inode(inode, S_IFBLK | 0666, MKDEV(1, 0));
		wrapped_def_blk_fops = *inode->i_fop;
		iput(inode);
		org_blkdev_open = wrapped_def_blk_fops.open;
		wrapped_def_blk_fops.open = wrapped_blkdev_open;
	}
	{
		struct inode *inode = new_inode(sb);
		if (!inode)
			return -EINVAL;
		/* Create /dev/null to get the value of chrdev_open(). */
		init_special_inode(inode, S_IFCHR | 0666, MKDEV(1, 3));
		wrapped_def_chr_fops = *inode->i_fop;
		iput(inode);
		org_chrdev_open = wrapped_def_chr_fops.open;
		wrapped_def_chr_fops.open = wrapped_chrdev_open;
	}
	if (!filename) {
		printk(KERN_WARNING "SYAORAN: Missing config-file path.\n");
		return -EINVAL;
	}
	/* If mode is given with mount operation, use it. */
	if (!strncmp(filename, "accept=", 7)) {
		filename += 7;
		is_permissive_mode = true;
	} else if (!strncmp(filename, "enforce=", 8)) {
		filename += 8;
		is_permissive_mode = false;
	} else if (syaoran_default_mode == -1) {
		/*
		 * If mode is not given with command line,
		 * abort mount.
		 */
		printk(KERN_WARNING
		       "SYAORAN: Missing 'accept=' or 'enforce='.\n");
		return -EINVAL;
	}
	f = filp_open(filename, O_RDONLY, 0600);
	if (IS_ERR(f)) {
		printk(KERN_WARNING "SYAORAN: Can't open '%s'\n", filename);
		return -EINVAL;
	}
	if (!S_ISREG(f->f_dentry->d_inode->i_mode))
		goto out;
	sb->s_fs_info = kzalloc(sizeof(struct syaoran_sb_info), GFP_KERNEL);
	if (!sb->s_fs_info)
		goto out;
	((struct syaoran_sb_info *) sb->s_fs_info)->is_permissive_mode
		= is_permissive_mode;
	INIT_LIST_HEAD(&((struct syaoran_sb_info *) sb->s_fs_info)->list);
	printk(KERN_INFO "SYAORAN: Reading '%s'\n", filename);
	error = syaoran_read_config_file(f, sb);
 out:
	if (error)
		printk(KERN_WARNING "SYAORAN: Can't read '%s'\n", filename);
	filp_close(f, NULL);
	return error;
}

/* Get absolute pathname from mount point. */
static int get_local_absolute_path(struct dentry *dentry, char *buffer,
				   int buflen)
{
	/***** CRITICAL SECTION START *****/
	char *start = buffer;
	char *end = buffer + buflen;
	int namelen;

	if (buflen < 256)
		goto out;

	*--end = '\0';
	buflen--;
	for (;;) {
		struct dentry *parent;
		if (IS_ROOT(dentry))
			break;
		parent = dentry->d_parent;
		namelen = dentry->d_name.len;
		buflen -= namelen + 1;
		if (buflen < 0)
			goto out;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		dentry = parent;
	}
	if (*end == '/') {
		buflen++;
		end++;
	}
	namelen = dentry->d_name.len;
	buflen -= namelen;
	if (buflen < 0)
		goto out;
	end -= namelen;
	memcpy(end, dentry->d_name.name, namelen);
	memmove(start, end, strlen(end) + 1);
	return 0;
 out:
	return -ENOMEM;
	/***** CRITICAL SECTION END *****/
}

/* Get absolute pathname of the given dentry from mount point. */
static int local_ccs_realpath_from_dentry(struct dentry *dentry, char *newname,
					  int newname_len)
{
	/***** CRITICAL SECTION START *****/
	int error;
	struct dentry *d_dentry;
	if (!dentry || !newname || newname_len <= 0)
		return -EINVAL;
	d_dentry = dget(dentry);
	spin_lock(&dcache_lock);
	error = get_local_absolute_path(d_dentry, newname, newname_len);
	spin_unlock(&dcache_lock);
	dput(d_dentry);
	return error;
	/***** CRITICAL SECTION END *****/
}

static int syaoran_check_flags(struct syaoran_sb_info *info,
			       struct dentry *dentry,
			       int mode, int dev, unsigned int flags)
{
	int error;
	/*
	 * I use static buffer, for local_ccs_realpath_from_dentry() needs
	 * dcache_lock.
	 */
	static char filename[PAGE_SIZE];
	static DEFINE_SPINLOCK(lock);
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	memset(filename, 0, sizeof(filename));
	error = local_ccs_realpath_from_dentry(dentry, filename,
					       sizeof(filename) - 1);
	if (!error) {
		struct dev_entry *entry;
		error = -EPERM;
		list_for_each_entry(entry, &info->list, list) {
			if ((mode & S_IFMT) != (entry->mode & S_IFMT))
				continue;
			if ((S_ISBLK(mode) || S_ISCHR(mode)) &&
			    dev != entry->kdev)
				continue;
			if (strcmp(entry->name, filename + 1))
				continue;
			if (info->is_permissive_mode) {
				entry->flags |= flags;
				error = 0;
			} else if ((entry->flags & flags) == flags)
				error = 0;
			break;
		}
	}
	if (!error) {
		const char *name;
		struct task_struct *task = current;
		const uid_t uid = task->fsuid;
		const gid_t gid = task->fsgid;
		const mode_t perm = mode & 0777;
		flags &= ~DEVICE_USED;
		{
			char *end = filename + sizeof(filename) - 1;
			const char *cp = strchr(filename, '\0') - 1;
			while (cp > filename && end > cp &&
			       end > filename + 16) {
				const unsigned char c = *cp--;
				if (c == '\\') {
					*--end = '\\';
					*--end = '\\';
				} else if (c > ' ' && c < 127) {
					*--end = c;
				} else {
					*--end = (c & 7) + '0';
					*--end = ((c >> 3) & 7) + '0';
					*--end = (c >> 6) + '0';
					*--end = '\\';
				}
			}
			name = end;
		}
		switch (mode & S_IFMT) {
		case S_IFCHR:
			printk(KERN_DEBUG
			       "SYAORAN-ERROR: %s %3o %3u %3u %2u %c %3u %3u\n",
			       name, perm, uid, gid, flags, 'c',
			       MAJOR(dev), MINOR(dev));
			break;
		case S_IFBLK:
			printk(KERN_DEBUG
			       "SYAORAN-ERROR: %s %3o %3u %3u %2u %c %3u %3u\n",
			       name, perm, uid, gid, flags, 'b',
			       MAJOR(dev), MINOR(dev));
			break;
		case S_IFIFO:
			printk(KERN_DEBUG
			       "SYAORAN-ERROR: %s %3o %3u %3u %2u %c\n", name,
			       perm, uid, gid, flags, 'p');
			break;
		case S_IFSOCK:
			printk(KERN_DEBUG
			       "SYAORAN-ERROR: %s %3o %3u %3u %2u %c\n", name,
			       perm, uid, gid, flags, 's');
			break;
		case S_IFDIR:
			printk(KERN_DEBUG
			       "SYAORAN-ERROR: %s %3o %3u %3u %2u %c\n", name,
			       perm, uid, gid, flags, 'd');
			break;
		case S_IFLNK:
			printk(KERN_DEBUG
			       "SYAORAN-ERROR: %s %3o %3u %3u %2u %c %s\n",
			       name, perm, uid, gid, flags, 'l', "unknown");
			break;
		case S_IFREG:
			printk(KERN_DEBUG
			       "SYAORAN-ERROR: %s %3o %3u %3u %2u %c\n", name,
			       perm, uid, gid, flags, 'f');
			break;
		}
	}
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	return error;
}

/* Check whether the given dentry is allowed to mknod. */
static int syaoran_may_create_node(struct dentry *dentry, int mode, int dev)
{
	struct syaoran_sb_info *info
		= (struct syaoran_sb_info *) dentry->d_sb->s_fs_info;
	if (!info) {
		printk(KERN_WARNING "%s: dentry->d_sb->s_fs_info == NULL\n",
		       __func__);
		return -EPERM;
	}
	if (!info->initialize_done)
		return 0;
	return syaoran_check_flags(info, dentry, mode, dev, MAY_CREATE);
}

/* Check whether the given dentry is allowed to chmod/chown/unlink. */
static int syaoran_may_modify_node(struct dentry *dentry, unsigned int flags)
{
	struct syaoran_sb_info *info
		= (struct syaoran_sb_info *) dentry->d_sb->s_fs_info;
	if (!info) {
		printk(KERN_WARNING "%s: dentry->d_sb->s_fs_info == NULL\n",
		       __func__);
		return -EPERM;
	}
	if (flags == DEVICE_USED && !info->is_permissive_mode)
		return 0;
	if (!dentry->d_inode)
		return -ENOENT;
	return syaoran_check_flags(info, dentry, dentry->d_inode->i_mode,
				   dentry->d_inode->i_rdev, flags);
}

/*
 * The following structure and codes are used for transferring data
 * to interfaces files.
 */

struct syaoran_read_struct {
	char *buf;               /* Buffer for reading.                */
	int avail;               /* Bytes available for reading.       */
	struct super_block *sb;  /* The super_block of this partition. */
	struct dev_entry *entry; /* The entry currently reading from.  */
	bool read_all;           /* Print all entries?                 */
	struct list_head *pos;   /* Current position.                  */
};

static void syaoran_read_table(struct syaoran_read_struct *head, char *buf,
			       int count)
{
	struct super_block *sb = head->sb;
	struct syaoran_sb_info *info = (struct syaoran_sb_info *) sb->s_fs_info;
	struct list_head *pos;
	const bool read_all = head->read_all;
	if (!info)
		return;
	if (!head->pos)
		return;
	list_for_each_cookie(pos, head->pos, &info->list) {
		struct dev_entry *entry
			= list_entry(pos, struct dev_entry, list);
		const unsigned int flags
			= read_all ? entry->flags : entry->flags & ~DEVICE_USED;
		const char *name = entry->printable_name;
		const uid_t uid = entry->uid;
		const gid_t gid = entry->gid;
		const mode_t perm = entry->mode & 0777;
		int len = 0;
		switch (entry->mode & S_IFMT) {
		case S_IFCHR:
			if (!head->read_all && !(entry->flags & DEVICE_USED))
				break;
			len = snprintf(buf, count,
				       "%-20s %3o %3u %3u %2u %c %3u %3u\n",
				       name, perm, uid, gid, flags, 'c',
				       MAJOR(entry->kdev), MINOR(entry->kdev));
			break;
		case S_IFBLK:
			if (!head->read_all && !(entry->flags & DEVICE_USED))
				break;
			len = snprintf(buf, count,
				       "%-20s %3o %3u %3u %2u %c %3u %3u\n",
				       name, perm, uid, gid, flags, 'b',
				       MAJOR(entry->kdev), MINOR(entry->kdev));
			break;
		case S_IFIFO:
			len = snprintf(buf, count, "%-20s %3o %3u %3u %2u %c\n",
				       name, perm, uid, gid, flags, 'p');
			break;
		case S_IFSOCK:
			len = snprintf(buf, count, "%-20s %3o %3u %3u %2u %c\n",
				       name, perm, uid, gid, flags, 's');
			break;
		case S_IFDIR:
			len = snprintf(buf, count, "%-20s %3o %3u %3u %2u %c\n",
				       name, perm, uid, gid, flags, 'd');
			break;
		case S_IFLNK:
			len = snprintf(buf, count,
				       "%-20s %3o %3u %3u %2u %c %s\n", name,
				       perm, uid, gid, flags, 'l',
				       entry->printable_symlink_data);
			break;
		case S_IFREG:
			len = snprintf(buf, count, "%-20s %3o %3u %3u %2u %c\n",
				       name, perm, uid, gid, flags, 'f');
			break;
		}
		if (len < 0 || count <= len)
			break;
		count -= len;
		buf += len;
		head->avail += len;
	}
}

static int syaoran_trace_open(struct inode *inode, struct file *file)
{
	struct syaoran_read_struct *head = kzalloc(sizeof(*head), GFP_KERNEL);
	if (!head)
		return -ENOMEM;
	head->sb = inode->i_sb;
	head->read_all
		= (strcmp(file->f_dentry->d_name.name, ".syaoran_all") == 0);
	head->pos = &((struct syaoran_sb_info *) head->sb->s_fs_info)->list;
	/* Don't allow open() after unmount() */
	if (head->sb->s_fs_info)
		head->buf = kzalloc(PAGE_SIZE * 2, GFP_KERNEL);
	if (!head->buf) {
		kfree(head);
		return -ENOMEM;
	}
	file->private_data = head;
	return 0;
}

static int syaoran_trace_release(struct inode *inode, struct file *file)
{
	struct syaoran_read_struct *head = file->private_data;
	kfree(head->buf);
	kfree(head);
	file->private_data = NULL;
	return 0;
}

static ssize_t syaoran_trace_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct syaoran_read_struct *head
		= (struct syaoran_read_struct *) file->private_data;
	int len = head->avail;
	char *cp = head->buf;
	if (!access_ok(VERIFY_WRITE, buf, count))
		return -EFAULT;
	syaoran_read_table(head, cp + len, PAGE_SIZE * 2 - len);
	len = head->avail;
	if (len > count)
		len = count;
	if (len > 0) {
		if (copy_to_user(buf, cp, len))
			return -EFAULT;
		head->avail -= len;
		memmove(cp, cp + len, head->avail);
	}
	return len;
}

static struct file_operations syaoran_trace_operations = {
	.open    = syaoran_trace_open,
	.release = syaoran_trace_release,
	.read    = syaoran_trace_read,
};

/* Create interface files for reading status. */
static int syaoran_create_tracelog(struct super_block *sb, const char *filename)
{
	struct dentry *base = dget(sb->s_root);
	struct dentry *dentry = lookup_create2(filename, base, 0);
	int error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		struct inode *inode = new_inode(sb);
		if (inode) {
			inode->i_mode = S_IFREG | 0400;
			inode->i_uid = 0;
			inode->i_gid = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#if !defined(RHEL_MAJOR) || RHEL_MAJOR != 5
			inode->i_blksize = PAGE_CACHE_SIZE;
#endif
#endif
			inode->i_blocks = 0;
			inode->i_mapping->a_ops = &syaoran_aops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
			inode->i_mapping->backing_dev_info
				= &syaoran_backing_dev_info;
			inode->i_op = &syaoran_file_inode_operations;
#else
			inode->i_rdev = NODEV;
#endif
			inode->i_ctime = CURRENT_TIME;
			inode->i_mtime = inode->i_ctime;
			inode->i_atime = inode->i_mtime;
			inode->i_fop = &syaoran_trace_operations;
			d_instantiate(dentry, inode);
			dget(dentry); /* Extra count - pin the dentry in core */
			error = 0;
		}
		dput(dentry);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
	mutex_unlock(&base->d_inode->i_mutex);
#else
	up(&base->d_inode->i_sem);
#endif
	dput(base);
	return error;
}

#endif
