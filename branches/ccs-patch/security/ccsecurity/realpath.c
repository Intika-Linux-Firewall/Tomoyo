/*
 * security/ccsecurity/realpath.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#include <linux/smp_lock.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#include <linux/mount.h>
static const int ccs_lookup_flags = LOOKUP_FOLLOW;
#else
static const int ccs_lookup_flags = LOOKUP_FOLLOW | LOOKUP_POSITIVE;
#endif
#include <net/sock.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/kthread.h>
#endif
#include <linux/proc_fs.h>
#include "internal.h"

static int ccs_kern_path(const char *pathname, int flags, struct path *path)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
	if (!pathname || kern_path(pathname, flags, path))
		return -ENOENT;
#else
	struct nameidata nd;
	if (!pathname || path_lookup(pathname, flags, &nd))
		return -ENOENT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	*path = nd.path;
#else
	path->dentry = nd.dentry;
	path->mnt = nd.mnt;
#endif
#endif
	return 0;
}

/**
 * ccs_get_absolute_path - Get the path of a dentry but ignores chroot'ed root.
 *
 * @path:   Pointer to "struct path".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns 0 on success, -ENOMEM otherwise.
 *
 * Caller holds the dcache_lock and vfsmount_lock.
 * Based on __d_path() in fs/dcache.c
 *
 * If dentry is a directory, trailing '/' is appended.
 * Characters out of 0x20 < c < 0x7F range are converted to
 * \ooo style octal string.
 * Character \ is converted to \\ string.
 */
static int ccs_get_absolute_path(struct path *path, char *buffer, int buflen)
{
	/***** CRITICAL SECTION START *****/
	char *start = buffer;
	char *end = buffer + buflen;
	struct dentry *dentry = path->dentry;
	struct vfsmount *vfsmnt = path->mnt;
	bool is_dir = (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode));

	if (buflen < 256)
		goto out;

	*--end = '\0';
	buflen--;

	for (;;) {
		struct dentry *parent;

		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
			if (vfsmnt->mnt_parent == vfsmnt)
				break;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		if (is_dir) {
			is_dir = false;
			*--end = '/';
			buflen--;
		}
		parent = dentry->d_parent;
		{
			const char *sp = dentry->d_name.name;
			const char *cp = sp + dentry->d_name.len - 1;
			unsigned char c;

			/*
			 * Exception: Use /proc/self/ rather than
			 * /proc/\$/ for current process.
			 */
			if (IS_ROOT(parent) && *sp > '0' && *sp <= '9' &&
			    parent->d_sb &&
			    parent->d_sb->s_magic == PROC_SUPER_MAGIC) {
				char *ep;
				const pid_t pid
					= (pid_t) simple_strtoul(sp, &ep, 10);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
				const pid_t tgid
					= task_tgid_nr_ns(current,
							  dentry->d_sb->
							  s_fs_info);
				if (!*ep && pid == tgid && tgid) {
					sp = "self";
					cp = sp + 3;
				}
#else
				if (!*ep && pid == sys_getpid()) {
					sp = "self";
					cp = sp + 3;
				}
#endif
			}

			while (sp <= cp) {
				c = *(unsigned char *) cp;
				if (c == '\\') {
					buflen -= 2;
					if (buflen < 0)
						goto out;
					*--end = '\\';
					*--end = '\\';
				} else if (c > ' ' && c < 127) {
					if (--buflen < 0)
						goto out;
					*--end = (char) c;
				} else {
					buflen -= 4;
					if (buflen < 0)
						goto out;
					*--end = (c & 7) + '0';
					*--end = ((c >> 3) & 7) + '0';
					*--end = (c >> 6) + '0';
					*--end = '\\';
				}
				cp--;
			}
			if (--buflen < 0)
				goto out;
			*--end = '/';
		}
		dentry = parent;
	}
	if (*end == '/') {
		buflen++;
		end++;
	}
	{
		const char *sp = dentry->d_name.name;
		const char *cp = sp + dentry->d_name.len - 1;
		unsigned char c;
		while (sp <= cp) {
			c = *(unsigned char *) cp;
			if (c == '\\') {
				buflen -= 2;
				if (buflen < 0)
					goto out;
				*--end = '\\';
				*--end = '\\';
			} else if (c > ' ' && c < 127) {
				if (--buflen < 0)
					goto out;
				*--end = (char) c;
			} else {
				buflen -= 4;
				if (buflen < 0)
					goto out;
				*--end = (c & 7) + '0';
				*--end = ((c >> 3) & 7) + '0';
				*--end = (c >> 6) + '0';
				*--end = '\\';
			}
			cp--;
		}
	}
	/* Move the pathname to the top of the buffer. */
	memmove(start, end, strlen(end) + 1);
	return 0;
 out:
	return -ENOMEM;
	/***** CRITICAL SECTION END *****/
}

#define SOCKFS_MAGIC 0x534F434B

/**
 * ccs_realpath_from_path2 - Returns realpath(3) of the given dentry but ignores chroot'ed root.
 *
 * @path:        Pointer to "struct path".
 * @newname:     Pointer to buffer to return value in.
 * @newname_len: Size of @newname.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_realpath_from_path2(struct path *path, char *newname,
				   int newname_len)
{
	int error = -EINVAL;
	struct dentry *dentry = path->dentry;
	if (!dentry || !newname || newname_len <= 2048)
		goto out;
	/* Get better name for socket. */
	if (dentry->d_sb && dentry->d_sb->s_magic == SOCKFS_MAGIC) {
		struct inode *inode = dentry->d_inode;
		struct socket *sock = inode ? SOCKET_I(inode) : NULL;
		struct sock *sk = sock ? sock->sk : NULL;
		if (sk) {
			snprintf(newname, newname_len - 1,
				 "socket:[family=%u:type=%u:protocol=%u]",
				 sk->sk_family, sk->sk_type, sk->sk_protocol);
		} else {
			snprintf(newname, newname_len - 1, "socket:[unknown]");
		}
		return 0;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22)
	if (dentry->d_op && dentry->d_op->d_dname) {
		/* For "socket:[\$]" and "pipe:[\$]". */
		static const int offset = 1536;
		char *dp = newname;
		char *sp = dentry->d_op->d_dname(dentry, newname + offset,
						 newname_len - offset);
		if (IS_ERR(sp)) {
			error = PTR_ERR(sp);
			goto out;
		}
		error = -ENOMEM;
		newname += offset;
		while (1) {
			const unsigned char c = *(unsigned char *) sp++;
			if (c == '\\') {
				if (dp + 2 >= newname)
					break;
				*dp++ = '\\';
				*dp++ = '\\';
			} else if (c > ' ' && c < 127) {
				if (dp + 1 >= newname)
					break;
				*dp++ = (char) c;
			} else if (c) {
				if (dp + 4 >= newname)
					break;
				*dp++ = '\\';
				*dp++ = (c >> 6) + '0';
				*dp++ = ((c >> 3) & 7) + '0';
				*dp++ = (c & 7) + '0';
			} else {
				*dp = '\0';
				return 0;
			}
		}
		goto out;
	}
#endif
	if (!path->mnt)
		goto out;
	path_get(path);
	/***** CRITICAL SECTION START *****/
	ccs_realpath_lock();
	error = ccs_get_absolute_path(path, newname, newname_len);
	ccs_realpath_unlock();
	/***** CRITICAL SECTION END *****/
	path_put(path);
 out:
	if (error)
		printk(KERN_WARNING "ccs_realpath: Pathname too long. (%d)\n",
		       error);
	return error;
}

/**
 * ccs_realpath_from_path - Returns realpath(3) of the given pathname but ignores chroot'ed root.
 *
 * @path: Pointer to "struct path".
 *
 * Returns the realpath of the given @path on success, NULL otherwise.
 *
 * These functions use kzalloc(), so caller must kfree()
 * if these functions didn't return NULL.
 */
char *ccs_realpath_from_path(struct path *path)
{
	char *buf = kzalloc(CCS_MAX_PATHNAME_LEN, GFP_KERNEL);
	if (buf &&
	    ccs_realpath_from_path2(path, buf, CCS_MAX_PATHNAME_LEN - 2) == 0)
		return buf;
	kfree(buf);
	return NULL;
}

/**
 * ccs_realpath - Get realpath of a pathname.
 *
 * @pathname: The pathname to solve.
 *
 * Returns the realpath of @pathname on success, NULL otherwise.
 */
char *ccs_realpath(const char *pathname)
{
	struct path path;
	if (ccs_kern_path(pathname, ccs_lookup_flags, &path) == 0) {
		char *buf = ccs_realpath_from_path(&path);
		path_put(&path);
		return buf;
	}
	return NULL;
}

/**
 * ccs_symlink_path - Get symlink's pathname.
 *
 * @pathname: The pathname to solve.
 * @ee:       Pointer to "struct ccs_execve_entry".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_symlink_path(const char *pathname, struct ccs_execve_entry *ee)
{
	struct path path;
	int ret;
	if (ccs_kern_path(pathname, ccs_lookup_flags ^ LOOKUP_FOLLOW, &path))
		return -ENOENT;
	ret = ccs_realpath_from_path2(&path, ee->program_path,
				      CCS_MAX_PATHNAME_LEN - 1);
	path_put(&path);
	return ret;
}

/**
 * ccs_encode: Encode binary string to ascii string.
 *
 * @str: String in binary format.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *ccs_encode(const char *str)
{
	int len = 0;
	const char *p = str;
	char *cp;
	char *cp0;
	if (!p)
		return NULL;
	while (*p) {
		const unsigned char c = *p++;
		if (c == '\\')
			len += 2;
		else if (c > ' ' && c < 127)
			len++;
		else
			len += 4;
	}
	len++;
	cp = kzalloc(len, GFP_KERNEL);
	if (!cp)
		return NULL;
	cp0 = cp;
	p = str;
	while (*p) {
		const unsigned char c = *p++;
		if (c == '\\') {
			*cp++ = '\\';
			*cp++ = '\\';
		} else if (c > ' ' && c < 127) {
			*cp++ = c;
		} else {
			*cp++ = '\\';
			*cp++ = (c >> 6) + '0';
			*cp++ = ((c >> 3) & 7) + '0';
			*cp++ = (c & 7) + '0';
		}
	}
	return cp0;
}

/**
 * ccs_get_path - Get dentry/vfsmmount of a pathname.
 *
 * @pathname: The pathname to solve.
 * @path:     Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_get_path(const char *pathname, struct path *path)
{
	return ccs_kern_path(pathname, ccs_lookup_flags, path);
}
