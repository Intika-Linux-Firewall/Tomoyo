/*
 * fs/realpath.c
 *
 * Get the canonicalized absolute pathnames. The basis for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.6.9   2011/04/01
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
#include <linux/realpath.h>
#include <linux/proc_fs.h>
#include <linux/ccs_common.h>
#include <net/sock.h>

/**
 * ccs_get_absolute_path - Get the path of a dentry but ignores chroot'ed root.
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
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
static int ccs_get_absolute_path(struct dentry *dentry, struct vfsmount *vfsmnt,
				 char *buffer, int buflen)
{
	/***** CRITICAL SECTION START *****/
	char *start = buffer;
	char *end = buffer + buflen;
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
 * ccs_realpath_from_dentry2 - Returns realpath(3) of the given dentry but ignores chroot'ed root.
 *
 * @dentry:      Pointer to "struct dentry".
 * @mnt:         Pointer to "struct vfsmount".
 * @newname:     Pointer to buffer to return value in.
 * @newname_len: Size of @newname.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_realpath_from_dentry2(struct dentry *dentry, struct vfsmount *mnt,
			      char *newname, int newname_len)
{
	int error = -EINVAL;
	struct dentry *d_dentry;
	struct vfsmount *d_mnt;
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
	if (!mnt)
		goto out;
	d_dentry = dget(dentry);
	d_mnt = mntget(mnt);
	/***** CRITICAL SECTION START *****/
	ccs_realpath_lock();
	error = ccs_get_absolute_path(d_dentry, d_mnt, newname, newname_len);
	ccs_realpath_unlock();
	/***** CRITICAL SECTION END *****/
	dput(d_dentry);
	mntput(d_mnt);
 out:
	if (error)
		printk(KERN_WARNING "ccs_realpath: Pathname too long. (%d)\n",
		       error);
	return error;
}

/**
 * ccs_realpath_from_dentry - Returns realpath(3) of the given pathname but ignores chroot'ed root.
 *
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount".
 *
 * Returns the realpath of the given @dentry and @mnt on success,
 * NULL otherwise.
 *
 * These functions use ccs_alloc(), so caller must ccs_free()
 * if these functions didn't return NULL.
 */
char *ccs_realpath_from_dentry(struct dentry *dentry, struct vfsmount *mnt)
{
	char *buf = ccs_alloc(CCS_MAX_PATHNAME_LEN, false);
	if (buf && ccs_realpath_from_dentry2(dentry, mnt, buf,
					     CCS_MAX_PATHNAME_LEN - 1) == 0)
		return buf;
	ccs_free(buf);
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
	struct nameidata nd;
	if (pathname && path_lookup(pathname, ccs_lookup_flags, &nd) == 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		char *buf = ccs_realpath_from_dentry(nd.path.dentry,
						     nd.path.mnt);
		path_put(&nd.path);
#else
		char *buf = ccs_realpath_from_dentry(nd.dentry, nd.mnt);
		path_release(&nd);
#endif
		return buf;
	}
	return NULL;
}

/**
 * ccs_realpath_both - Get realpath of a pathname and symlink.
 *
 * @pathname: The pathname to solve.
 * @ee:       Pointer to "struct ccs_execve_entry".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_realpath_both(const char *pathname, struct ccs_execve_entry *ee)
{
	struct nameidata nd;
	int ret;
	bool is_symlink;
	if (!pathname ||
	    path_lookup(pathname, ccs_lookup_flags ^ LOOKUP_FOLLOW, &nd))
		return -ENOENT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	is_symlink = nd.path.dentry->d_inode &&
		S_ISLNK(nd.path.dentry->d_inode->i_mode);
	ret = ccs_realpath_from_dentry2(nd.path.dentry, nd.path.mnt,
					ee->tmp, CCS_EXEC_TMPSIZE - 1);
	path_put(&nd.path);
#else
	is_symlink = nd.dentry->d_inode && S_ISLNK(nd.dentry->d_inode->i_mode);
	ret = ccs_realpath_from_dentry2(nd.dentry, nd.mnt, ee->tmp,
					CCS_EXEC_TMPSIZE - 1);
	path_release(&nd);
#endif
	if (ret)
		return -ENOMEM;
	if (strlen(ee->tmp) > CCS_MAX_PATHNAME_LEN - 1)
		return -ENOMEM;
	ee->program_path[CCS_MAX_PATHNAME_LEN - 1] = '\0';
	if (!is_symlink) {
		strncpy(ee->program_path, ee->tmp,
			CCS_MAX_PATHNAME_LEN - 1);
		return 0;
	}
	if (path_lookup(pathname, ccs_lookup_flags, &nd))
		return -ENOENT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	ret = ccs_realpath_from_dentry2(nd.path.dentry, nd.path.mnt,
					ee->program_path,
					CCS_MAX_PATHNAME_LEN - 1);
	path_put(&nd.path);
#else
	ret = ccs_realpath_from_dentry2(nd.dentry, nd.mnt, ee->program_path,
					CCS_MAX_PATHNAME_LEN - 1);
	path_release(&nd);
#endif
	return ret ? -ENOMEM : 0;
}

/**
 * ccs_encode: Encode binary string to ascii string.
 *
 * @str: String in binary format.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses ccs_alloc(), so caller must ccs_free() if this function
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
	cp = ccs_alloc(len, false);
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
 * ccs_round_up - Round up an integer so that the returned pointers are appropriately aligned.
 *
 * @size: Size in bytes.
 *
 * Returns rounded value of @size.
 *
 * FIXME: Are there more requirements that is needed for assigning value
 * atomically?
 */
static inline unsigned int ccs_round_up(const unsigned int size)
{
	if (sizeof(void *) >= sizeof(long))
		return ((size + sizeof(void *) - 1)
			/ sizeof(void *)) * sizeof(void *);
	else
		return ((size + sizeof(long) - 1)
			/ sizeof(long)) * sizeof(long);
}

static unsigned int ccs_allocated_memory_for_elements;
static unsigned int ccs_quota_for_elements;

/**
 * ccs_alloc_element - Allocate permanent memory for structures.
 *
 * @size: Size in bytes.
 *
 * Returns pointer to allocated memory on success, NULL otherwise.
 *
 * The RAM is chunked, so NEVER try to kfree() the returned pointer.
 */
void *ccs_alloc_element(const unsigned int size)
{
	static DEFINE_MUTEX(lock);
	static char *ccs_buf;
	static unsigned int ccs_buf_used_len = PAGE_SIZE;
	char *ptr = NULL;
	const unsigned int word_aligned_size = ccs_round_up(size);
	if (word_aligned_size > PAGE_SIZE)
		return NULL;
	mutex_lock(&lock);
	if (ccs_buf_used_len + word_aligned_size > PAGE_SIZE) {
		if (!ccs_quota_for_elements || ccs_allocated_memory_for_elements
		    + PAGE_SIZE <= ccs_quota_for_elements)
			ptr = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!ptr) {
			printk(KERN_WARNING "ERROR: Out of memory "
			       "for ccs_alloc_element().\n");
			if (!ccs_policy_loaded)
				panic("MAC Initialization failed.\n");
		} else {
			ccs_buf = ptr;
			ccs_allocated_memory_for_elements += PAGE_SIZE;
			ccs_buf_used_len = word_aligned_size;
		}
	} else if (word_aligned_size) {
		int i;
		ptr = ccs_buf + ccs_buf_used_len;
		ccs_buf_used_len += word_aligned_size;
		for (i = 0; i < word_aligned_size; i++) {
			if (!ptr[i])
				continue;
			printk(KERN_ERR "WARNING: Reserved memory was tainted! "
			       "The system might go wrong.\n");
			ptr[i] = '\0';
		}
	}
	mutex_unlock(&lock);
	return ptr;
}

static unsigned int ccs_allocated_memory_for_savename;
static unsigned int ccs_quota_for_savename;

#define MAX_HASH 256

/* Structure for string data. */
struct ccs_name_entry {
	struct list1_head list;
	struct ccs_path_info entry;
};

/* Structure for available memory region. */
struct ccs_free_memory_block_list {
	struct list_head list;
	char *ptr;             /* Pointer to a free area. */
	int len;               /* Length of the area.     */
};

/* The list for "struct ccs_name_entry". */
static struct list1_head ccs_name_list[MAX_HASH];

/**
 * ccs_save_name - Allocate permanent memory for string data.
 *
 * @name: The string to store into the permernent memory.
 *
 * Returns pointer to "struct ccs_path_info" on success, NULL otherwise.
 *
 * The RAM is shared, so NEVER try to modify or kfree() the returned name.
 */
const struct ccs_path_info *ccs_save_name(const char *name)
{
	static LIST_HEAD(ccs_fmb_list);
	static DEFINE_MUTEX(lock);
	struct ccs_name_entry *ptr;
	unsigned int hash;
	struct ccs_free_memory_block_list *fmb;
	int len;
	char *cp;
	if (!name)
		return NULL;
	len = strlen(name) + 1;
	if (len > CCS_MAX_PATHNAME_LEN) {
		printk(KERN_WARNING "ERROR: Name too long "
		       "for ccs_save_name().\n");
		return NULL;
	}
	hash = full_name_hash((const unsigned char *) name, len - 1);
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_name_list[hash % MAX_HASH], list) {
		if (hash == ptr->entry.hash && !strcmp(name, ptr->entry.name))
			goto out;
	}
	list_for_each_entry(fmb, &ccs_fmb_list, list) {
		if (len <= fmb->len)
			goto ready;
	}
	if (!ccs_quota_for_savename ||
	    ccs_allocated_memory_for_savename + PAGE_SIZE
	    <= ccs_quota_for_savename)
		cp = kzalloc(PAGE_SIZE, GFP_KERNEL);
	else
		cp = NULL;
	fmb = kzalloc(sizeof(*fmb), GFP_KERNEL);
	if (!cp || !fmb) {
		kfree(cp);
		kfree(fmb);
		printk(KERN_WARNING "ERROR: Out of memory "
		       "for ccs_save_name().\n");
		if (!ccs_policy_loaded)
			panic("MAC Initialization failed.\n");
		ptr = NULL;
		goto out;
	}
	ccs_allocated_memory_for_savename += PAGE_SIZE;
	list_add(&fmb->list, &ccs_fmb_list);
	fmb->ptr = cp;
	fmb->len = PAGE_SIZE;
 ready:
	ptr = ccs_alloc_element(sizeof(*ptr));
	if (!ptr)
		goto out;
	ptr->entry.name = fmb->ptr;
	memmove(fmb->ptr, name, len);
	ccs_fill_path_info(&ptr->entry);
	fmb->ptr += len;
	fmb->len -= len;
	list1_add_tail_mb(&ptr->list, &ccs_name_list[hash % MAX_HASH]);
	if (fmb->len == 0) {
		list_del(&fmb->list);
		kfree(fmb);
	}
 out:
	mutex_unlock(&lock);
	return ptr ? &ptr->entry : NULL;
}

/* Structure for temporarily allocated memory. */
struct ccs_cache_entry {
	struct list_head list;
	void *ptr;
	int size;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
static struct kmem_cache *ccs_cachep;
#else
static kmem_cache_t *ccs_cachep;
#endif

/**
 * ccs_realpath_init - Initialize realpath related code.
 *
 * Returns 0.
 */
static int __init ccs_realpath_init(void)
{
	int i;
	/* Constraint for ccs_save_name(). */
	if (CCS_MAX_PATHNAME_LEN > PAGE_SIZE)
		panic("Bad size.");
	/* Constraint for "struct ccs_execve_entry"->tmp users. */
	if (CCS_MAX_PATHNAME_LEN > CCS_EXEC_TMPSIZE)
		panic("Bad size.");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)
	ccs_cachep = kmem_cache_create("ccs_cache",
				       sizeof(struct ccs_cache_entry),
				       0, 0, NULL);
#else
	ccs_cachep = kmem_cache_create("ccs_cache",
				       sizeof(struct ccs_cache_entry),
				       0, 0, NULL, NULL);
#endif
	if (!ccs_cachep)
		panic("Can't create cache.\n");
	for (i = 0; i < MAX_HASH; i++)
		INIT_LIST1_HEAD(&ccs_name_list[i]);
	INIT_LIST1_HEAD(&ccs_kernel_domain.acl_info_list);
	ccs_kernel_domain.domainname = ccs_save_name(ROOT_NAME);
	list1_add_tail_mb(&ccs_kernel_domain.list, &ccs_domain_list);
	if (ccs_find_domain(ROOT_NAME) != &ccs_kernel_domain)
		panic("Can't register ccs_kernel_domain");
#ifdef CONFIG_TOMOYO_BUILTIN_INITIALIZERS
	{
		/* Load built-in policy. */
		static char ccs_builtin_initializers[] __initdata
			= CONFIG_TOMOYO_BUILTIN_INITIALIZERS;
		char *cp = ccs_builtin_initializers;
		ccs_normalize_line(cp);
		while (cp && *cp) {
			char *cp2 = strchr(cp, ' ');
			if (cp2)
				*cp2++ = '\0';
			ccs_write_domain_initializer_policy(cp, false, false);
			cp = cp2;
		}
	}
#endif
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
__initcall(ccs_realpath_init);
#else
core_initcall(ccs_realpath_init);
#endif

/* The list for "struct ccs_cache_entry". */
static LIST_HEAD(ccs_audit_cache_list);
static LIST_HEAD(ccs_acl_cache_list);
static DEFINE_SPINLOCK(ccs_cache_list_lock);

static unsigned int ccs_dynamic_memory_size;
static unsigned int ccs_quota_for_dynamic;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
/**
 * ccs_round2 - Rounded up to power-of-two value.
 *
 * @size: Size in bytes.
 *
 * Returns power-of-two of @size.
 */
static int ccs_round2(size_t size)
{
#if PAGE_SIZE == 4096
	size_t bsize = 32;
#else
	size_t bsize = 64;
#endif
	while (size > bsize)
		bsize <<= 1;
	return bsize;
}
#endif

/**
 * ccs_alloc - Allocate memory for temporary purpose.
 *
 * @size:        Size in bytes.
 * @check_quota: True to check memory quota, false otherwise.
 *
 * Returns pointer to allocated memory on success, NULL otherwise.
 */
void *ccs_alloc(const size_t size, const _Bool check_quota)
{
	struct ccs_cache_entry *new_entry;
	void *ret = kzalloc(size, GFP_KERNEL);
	if (!ret)
		goto out;
	new_entry = kmem_cache_alloc(ccs_cachep, GFP_KERNEL);
	if (!new_entry) {
		kfree(ret);
		ret = NULL;
		goto out;
	}
	INIT_LIST_HEAD(&new_entry->list);
	new_entry->ptr = ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	new_entry->size = ksize(ret);
#else
	new_entry->size = ccs_round2(size);
#endif
	if (check_quota) {
		bool quota_exceeded = false;
		/***** CRITICAL SECTION START *****/
		spin_lock(&ccs_cache_list_lock);
		if (!ccs_quota_for_dynamic ||
		    ccs_dynamic_memory_size + new_entry->size
		    <= ccs_quota_for_dynamic) {
			list_add_tail(&new_entry->list, &ccs_audit_cache_list);
			ccs_dynamic_memory_size += new_entry->size;
		} else {
			quota_exceeded = true;
		}
		spin_unlock(&ccs_cache_list_lock);
		/***** CRITICAL SECTION END *****/
		if (quota_exceeded) {
			kfree(ret);
			kmem_cache_free(ccs_cachep, new_entry);
			ret = NULL;
		}
	} else {
		/***** CRITICAL SECTION START *****/
		spin_lock(&ccs_cache_list_lock);
		list_add(&new_entry->list, &ccs_acl_cache_list);
		ccs_dynamic_memory_size += new_entry->size;
		spin_unlock(&ccs_cache_list_lock);
		/***** CRITICAL SECTION END *****/
	}
 out:
	return ret;
}

/**
 * ccs_free - Release memory allocated by ccs_alloc().
 *
 * @p: Pointer returned by ccs_alloc(). May be NULL.
 *
 * Returns nothing.
 */
void ccs_free(const void *p)
{
	struct list_head *v;
	struct ccs_cache_entry *entry = NULL;
	if (!p)
		return;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_cache_list_lock);
	list_for_each(v, &ccs_acl_cache_list) {
		entry = list_entry(v, struct ccs_cache_entry, list);
		if (entry->ptr == p)
			break;
		entry = NULL;
	}
	if (!entry) {
		list_for_each(v, &ccs_audit_cache_list) {
			entry = list_entry(v, struct ccs_cache_entry, list);
			if (entry->ptr == p)
				break;
			entry = NULL;
		}
	}
	if (entry) {
		list_del(&entry->list);
		ccs_dynamic_memory_size -= entry->size;
	}
	spin_unlock(&ccs_cache_list_lock);
	/***** CRITICAL SECTION END *****/
	if (entry) {
		kfree(p);
		kmem_cache_free(ccs_cachep, entry);
	} else {
		printk(KERN_WARNING "BUG: ccs_free() with invalid pointer.\n");
	}
}

/**
 * ccs_read_memory_counter - Check for memory usage.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns memory usage.
 */
int ccs_read_memory_counter(struct ccs_io_buffer *head)
{
	if (!head->read_eof) {
		const unsigned int shared = ccs_allocated_memory_for_savename;
		const unsigned int private = ccs_allocated_memory_for_elements;
		const unsigned int dynamic = ccs_dynamic_memory_size;
		char buffer[64];
		memset(buffer, 0, sizeof(buffer));
		if (ccs_quota_for_savename)
			snprintf(buffer, sizeof(buffer) - 1,
				 "   (Quota: %10u)", ccs_quota_for_savename);
		else
			buffer[0] = '\0';
		ccs_io_printf(head, "Shared:  %10u%s\n", shared, buffer);
		if (ccs_quota_for_elements)
			snprintf(buffer, sizeof(buffer) - 1,
				 "   (Quota: %10u)", ccs_quota_for_elements);
		else
			buffer[0] = '\0';
		ccs_io_printf(head, "Private: %10u%s\n", private, buffer);
		if (ccs_quota_for_dynamic)
			snprintf(buffer, sizeof(buffer) - 1,
				 "   (Quota: %10u)", ccs_quota_for_dynamic);
		else
			buffer[0] = '\0';
		ccs_io_printf(head, "Dynamic: %10u%s\n", dynamic, buffer);
		ccs_io_printf(head, "Total:   %10u\n",
			      shared + private + dynamic);
		head->read_eof = true;
	}
	return 0;
}

/**
 * ccs_write_memory_quota - Set memory quota.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
int ccs_write_memory_quota(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	unsigned int size;
	if (sscanf(data, "Shared: %u", &size) == 1)
		ccs_quota_for_savename = size;
	else if (sscanf(data, "Private: %u", &size) == 1)
		ccs_quota_for_elements = size;
	else if (sscanf(data, "Dynamic: %u", &size) == 1)
		ccs_quota_for_dynamic = size;
	return 0;
}
