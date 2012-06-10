/*
 * fs/realpath.c
 *
 * Get the canonicalized absolute pathnames. The basis for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005  NTT DATA CORPORATION
 *
 * Version: 1.0 2005/11/11
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
#include <linux/dnotify.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <linux/namei.h>
#include <linux/mount.h>
static const int lookup_flags = LOOKUP_FOLLOW;
#else
static const int lookup_flags = LOOKUP_FOLLOW | LOOKUP_POSITIVE;
#endif
#include <linux/realpath.h>

/***** realpath handler *****/

/*
 * GetAbsolutePath - return the path of a dentry but ignores chroot'ed root.
 * @dentry: dentry to report
 * @vfsmnt: vfsmnt to which the dentry belongs
 * @buffer: buffer to return value in
 * @buflen: buffer length
 *
 * Caller holds the dcache_lock.
 * Based on __d_path() in fs/dcache.c
 *
 * If dentry is a directory, trailing '/' is appended.
 * Characters other than ' ' < c < 127 are converted to \ooo style octal string.
 * Character \ is converted to \\ string.
 */
static int GetAbsolutePath(struct dentry *dentry, struct vfsmount *vfsmnt, char *buffer, int buflen)
{
	char *start = buffer;
	char *end = buffer + buflen;
	char *retval;
	int namelen;
	int is_dir = (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode));

	if (buflen < 256) goto out;

	*--end = '\0';
	buflen--;

	/* Get '/' right */
	retval = end - 1;
	*retval = '/';

	for (;;) {
		struct dentry *parent;

		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
			if (vfsmnt->mnt_parent == vfsmnt) break;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		if (is_dir) {
			is_dir = 0; *--end = '/'; buflen--;
		}
		parent = dentry->d_parent;
		namelen = dentry->d_name.len;
#if 0   /* Don't use binary form. */
		buflen -= namelen + 1;
		if (buflen < 0) goto out;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
#else   /* I need text form. */
		{
			const char *sp = dentry->d_name.name;
			const char *cp = sp + namelen - 1;
			unsigned char c;
			while (sp <= cp) {
				c = * (unsigned char *) cp;
				if (c == '\\') {
					buflen -= 2;
					if (buflen < 0) goto out;
					*--end = '\\';
					*--end = '\\';
				} else if (c > ' ' && c < 127) {
					if (--buflen < 0) goto out;
					*--end = (char) c;
				} else {
					buflen -= 4;
					if (buflen < 0) goto out;
					*--end = (c & 7) + '0';
					*--end = ((c >> 3) & 7) + '0';
					*--end = (c >> 6) + '0';
					*--end = '\\';
				}
				cp--;
			}
			if (--buflen < 0) goto out;
			*--end = '/';
		}
#endif
		retval = end;
		dentry = parent;
	}
	namelen = dentry->d_name.len;
#if 0    /* Don't use binary form. */
	buflen -= namelen;
	if (buflen < 0) goto out;
	retval -= namelen - 1;  /* hit the slash */
	memcpy(retval, dentry->d_name.name, namelen);
#else    /* I need text form. */
	{
		const char *sp = dentry->d_name.name;
		const char *cp = sp + namelen - 1;
		unsigned char c;
		while (sp <= cp) {
			c = * (unsigned char *) cp;
			if (c == '\\') {
				buflen -= 2;
				if (buflen < 0) goto out;
				*--end = '\\';
				*--end = '\\';
				namelen++;
			} else if (c > ' ' && c < 127) {
				if (--buflen < 0) goto out;
				*--end = (char) c;
			} else {
				buflen -= 4;
				if (buflen < 0) goto out;
				*--end = (c & 7) + '0';
				*--end = ((c >> 3) & 7) + '0';
				*--end = (c >> 6) + '0';
				*--end = '\\';
				namelen += 3;
			}
			cp--;
		}
		retval -= namelen - 1;
	}
#endif
	/* Move the pathnamre to the top of the buffer. */
	memmove(start, retval, strlen(retval) + 1);
	return 0;
 out:
	return -ENOMEM;
}

/* Returns realpath(3) of the given dentry but ignores chroot'ed root. */
int realpath_from_dentry(struct dentry *dentry, struct vfsmount *mnt, char *newname, int newname_len)
{
	int error = -ENOENT;
	struct dentry *d_dentry;
	struct vfsmount *d_mnt;
	if (!dentry || !mnt || !newname || newname_len <= 0) return -EINVAL;
	if (!current->fs) {
		printk("%s: current->fs == NULL for pid=%d\n", __FUNCTION__, current->pid);
		return -ENOENT;
	}
	d_dentry = dget(dentry);
	d_mnt = mntget(mnt);
	/***** CRITICAL SECTION START *****/
	spin_lock(&dcache_lock);
	if (IS_ROOT(d_dentry) || !d_unhashed(d_dentry)) error = GetAbsolutePath(d_dentry, d_mnt, newname, newname_len);
	spin_unlock(&dcache_lock);
	/***** CRITICAL SECTION END *****/
	dput(d_dentry);
	mntput(d_mnt);
	return error;
}

/* Returns realpath(3) of the given pathname but ignores chroot'ed root. */
/* This function uses kmalloc(), so caller must kfree() if this function didn't return NULL. */
const char *realpath(const char *pathname)
{
	struct nameidata nd;
	int error;
	char *buf;
	if (pathname == NULL) return NULL;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL) return NULL;
	memset(buf, 0, PAGE_SIZE);
	if ((error = path_lookup(pathname, lookup_flags, &nd)) == 0) {
		error = realpath_from_dentry(nd.dentry, nd.mnt, buf, PAGE_SIZE - 1);
		path_release(&nd);
		if (error == 0) return buf;
	}
	kfree(buf);
	return NULL;
}

/***** Private memory allocator. *****/

/*
 * Round up an integer so that the returned pointers are always multiple of sizeof(int).
 * FIXME: Are there more requirements that is needed for assigning value atomically?
 */
#define ROUNDUP(x)           ((((x) + (sizeof(int)) - 1) / (sizeof(int))) * (sizeof(int)))

static unsigned int allocated_memory_for_elements = 0;

unsigned int GetMemoryUsedForElements(void)
{
	return allocated_memory_for_elements / 1024;
}

/* Allocate memory for structures. The RAM is chunked, so NEVER try to kfree() the returned pointer. */
char *alloc_element(const unsigned int size)
{
	static DECLARE_MUTEX(lock);
	static char *buf = NULL;
	static unsigned int buf_used_len = PAGE_SIZE;
	char *ptr = NULL;
	const unsigned int word_aligned_size = ROUNDUP(size);
	down(&lock);
	if (buf_used_len + word_aligned_size > PAGE_SIZE) {
		if ((ptr = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL) {
			printk("ERROR: Out of memory for alloc_element().\n");
		} else {
			buf = ptr;
			memset(buf, 0, PAGE_SIZE);
			allocated_memory_for_elements += PAGE_SIZE;
			buf_used_len = word_aligned_size;
			ptr = buf;
		}
	} else if (word_aligned_size) {
		ptr = buf + buf_used_len;
		buf_used_len += word_aligned_size;
	}
	up(&lock);
	return ptr;
}

/***** Shared memory allocator. *****/

static unsigned int allocated_memory_for_savename = 0;

unsigned int GetMemoryUsedForSaveName(void)
{
	return allocated_memory_for_savename / 1024;
}

#define MAX_HASH 256

typedef struct name_entry {
	struct name_entry *next; /* Pointer to next record. NULL if none.             */
	unsigned int hash;       /* hash and length                                   */
	const char *name;        /* Text form of filename and domainname. Never NULL. */
} NAME_ENTRY;

typedef struct free_memory_block_list {
	struct free_memory_block_list *next; /* Pointer to next record. NULL if none. */
	char *ptr;                           /* Pointer to a free area.               */
	int len;                             /* Length of the area.                   */
} FREE_MEMORY_BLOCK_LIST;

/* Keep the given name on the RAM. The RAM is shared, so NEVER try to modify or kfree() the returned name. */
const char *SaveName(const char *name)
{
	static FREE_MEMORY_BLOCK_LIST fmb_list = { NULL, NULL, 0 };
	static NAME_ENTRY name_list[MAX_HASH]; /* The list of names. */
	static DECLARE_MUTEX(lock);
	NAME_ENTRY *ptr, *prev = NULL;
	unsigned int hash;
	FREE_MEMORY_BLOCK_LIST *fmb = &fmb_list;
	int len;
	static int first_call = 1;
	if (!name) return NULL;
	len = strlen(name) + 1;
	if (len > PAGE_SIZE) {
		printk("ERROR: Name too long for SaveName().\n");
		return NULL;
	}
	hash = full_name_hash((const unsigned char *) name, len - 1);
	down(&lock);
	if (first_call) {
		int i;
		first_call = 0;
		memset(&name_list, 0, sizeof(name_list));
		for (i = 0; i < MAX_HASH; i++) name_list[i].name = "/";
	}
	ptr = &name_list[hash % MAX_HASH];
	hash ^= len; /* The hash % MAX_HASH are always same for ptr->hash, so embed length into the hash value. */
	while (ptr) {
		if (hash == ptr->hash && strcmp(name, ptr->name) == 0) goto out;
		prev = ptr; ptr = ptr->next;
	}
	/* while (fmb->next) fmb = fmb->next; */ /* This is for comparison. */
	while (len > fmb->len) {
		if (fmb->next) {
			fmb = fmb->next;
		} else {
			char *cp;
			if ((cp = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL || (fmb->next = (FREE_MEMORY_BLOCK_LIST *) alloc_element(sizeof(FREE_MEMORY_BLOCK_LIST))) == NULL) {
				kfree(cp);
				printk("ERROR: Out of memory for SaveName().\n");
				goto out; /* ptr == NULL */
			}
			memset(cp, 0, PAGE_SIZE);
			allocated_memory_for_savename += PAGE_SIZE;
			fmb = fmb->next;
			fmb->ptr = cp;
			fmb->len = PAGE_SIZE;
			fmb->next = NULL;
		}
	}
	if ((ptr = (NAME_ENTRY *) alloc_element(sizeof(NAME_ENTRY))) == NULL) goto out;
	memset(ptr, 0, sizeof(NAME_ENTRY));
	ptr->next = NULL;
	ptr->hash = hash;
	ptr->name = fmb->ptr;
	memmove(fmb->ptr, name, len);
	fmb->ptr += len;
	fmb->len -= len;
	prev->next = ptr; /* prev != NULL because name_list is not empty. */
	if (fmb->len == 0) {
		FREE_MEMORY_BLOCK_LIST *ptr = &fmb_list;
		while (ptr->next != fmb) ptr = ptr->next; ptr->next = fmb->next;
	}
 out:
	up(&lock);
	return ptr ? (const char *) ptr->name : NULL;
}

EXPORT_SYMBOL(realpath_from_dentry);
EXPORT_SYMBOL(realpath);
EXPORT_SYMBOL(GetMemoryUsedForElements);
EXPORT_SYMBOL(alloc_element);
EXPORT_SYMBOL(GetMemoryUsedForSaveName);
EXPORT_SYMBOL(SaveName);
