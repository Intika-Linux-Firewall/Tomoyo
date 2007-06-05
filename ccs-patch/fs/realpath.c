/*
 * fs/realpath.c
 *
 * Get the canonicalized absolute pathnames. The basis for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.4.1   2007/06/05
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <linux/namei.h>
#include <linux/mount.h>
static const int lookup_flags = LOOKUP_FOLLOW;
#else
static const int lookup_flags = LOOKUP_FOLLOW | LOOKUP_POSITIVE;
#endif
#include <linux/realpath.h>
#include <linux/proc_fs.h>
#include <linux/ccs_common.h>

extern int sbin_init_started;

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
	int is_dir = (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode));

	if (buflen < 256) goto out;

	*--end = '\0';
	buflen--;

	for (;;) {
		struct dentry *parent;

		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
			spin_lock(&vfsmount_lock);
#endif
			if (vfsmnt->mnt_parent == vfsmnt) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
				spin_unlock(&vfsmount_lock);
#endif
				break;
			}
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
			spin_unlock(&vfsmount_lock);
#endif
			continue;
		}
		if (is_dir) {
			is_dir = 0; *--end = '/'; buflen--;
		}
		parent = dentry->d_parent;
		{
			const char *sp = dentry->d_name.name;
			const char *cp = sp + dentry->d_name.len - 1;
			unsigned char c;

			/* Exception: Use /proc/self/ rather than /proc/\$/ for current process. */
			if (IS_ROOT(parent) && *sp > '0' && *sp <= '9' && parent->d_sb && parent->d_sb->s_magic == PROC_SUPER_MAGIC) {
				char *ep;
				const pid_t pid = (pid_t) simple_strtoul(sp, &ep, 10);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
				if (!*ep && pid == current->tgid) { sp = "self"; cp = sp + 3; }
#else
				if (!*ep && pid == current->pid) { sp = "self"; cp = sp + 3; }
#endif
			}

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
		dentry = parent;
	}
	if (*end == '/') { buflen++; end++; }
	{
		const char *sp = dentry->d_name.name;
		const char *cp = sp + dentry->d_name.len - 1;
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
	}
	/* Move the pathname to the top of the buffer. */
	memmove(start, end, strlen(end) + 1);
	return 0;
 out:
	return -ENOMEM;
}

/* Returns realpath(3) of the given dentry but ignores chroot'ed root. */
int realpath_from_dentry2(struct dentry *dentry, struct vfsmount *mnt, char *newname, int newname_len)
{
	int error;
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
	error = GetAbsolutePath(d_dentry, d_mnt, newname, newname_len);
	spin_unlock(&dcache_lock);
	/***** CRITICAL SECTION END *****/
	dput(d_dentry);
	mntput(d_mnt);
	return error;
}

/* Returns realpath(3) of the given pathname but ignores chroot'ed root. */
/* These functions use ccs_alloc(), so caller must ccs_free() if these functions didn't return NULL. */
char *realpath_from_dentry(struct dentry *dentry, struct vfsmount *mnt)
{
	char *buf = ccs_alloc(CCS_MAX_PATHNAME_LEN);
	if (buf && realpath_from_dentry2(dentry, mnt, buf, CCS_MAX_PATHNAME_LEN - 1) == 0) return buf;
	ccs_free(buf);
	return NULL;
}

char *realpath(const char *pathname)
{
	struct nameidata nd;
	if (pathname && path_lookup(pathname, lookup_flags, &nd) == 0) {
		char *buf = realpath_from_dentry(nd.dentry, nd.mnt);
		path_release(&nd);
		return buf;
	}
	return NULL;
}

char *realpath_nofollow(const char *pathname)
{
	struct nameidata nd;
	if (pathname && path_lookup(pathname, lookup_flags ^ LOOKUP_FOLLOW, &nd) == 0) {
		char *buf = realpath_from_dentry(nd.dentry, nd.mnt);
		path_release(&nd);
		return buf;
	}
	return NULL;
}

/***** Private memory allocator. *****/

/*
 * Round up an integer so that the returned pointers are appropriately aligned.
 * FIXME: Are there more requirements that is needed for assigning value atomically?
 */
static inline unsigned int ROUNDUP(const unsigned int size) {
	if (sizeof(void *) >= sizeof(long)) {
		return ((size + sizeof(void *) - 1) / sizeof(void *)) * sizeof(void *);
	} else {
		return ((size + sizeof(long) - 1) / sizeof(long)) * sizeof(long);
	}
}

static unsigned int allocated_memory_for_elements = 0;

unsigned int GetMemoryUsedForElements(void)
{
	return allocated_memory_for_elements;
}

/* Allocate memory for structures. The RAM is chunked, so NEVER try to kfree() the returned pointer. */
void *alloc_element(const unsigned int size)
{
	static DECLARE_MUTEX(lock);
	static char *buf = NULL;
	static unsigned int buf_used_len = PAGE_SIZE;
	char *ptr = NULL;
	const unsigned int word_aligned_size = ROUNDUP(size);
	if (word_aligned_size > PAGE_SIZE) return NULL;
	down(&lock);
	if (buf_used_len + word_aligned_size > PAGE_SIZE) {
		if ((ptr = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL) {
			printk("ERROR: Out of memory for alloc_element().\n");
			if (!sbin_init_started) panic("MAC Initialization failed.\n");
		} else {
			memset(ptr, 0, PAGE_SIZE);
			buf = ptr;
			allocated_memory_for_elements += PAGE_SIZE;
			buf_used_len = word_aligned_size;
			ptr = buf;
		}
	} else if (word_aligned_size) {
		int i;
		ptr = buf + buf_used_len;
		buf_used_len += word_aligned_size;
		for (i = 0; i < word_aligned_size; i++) {
			if (ptr[i]) {
				printk(KERN_ERR "WARNING: Reserved memory was tainted! The system might go wrong.\n");
				ptr[i] = '\0';
			}
		}
	}
	up(&lock);
	return ptr;
}

/***** Shared memory allocator. *****/

static unsigned int allocated_memory_for_savename = 0;

unsigned int GetMemoryUsedForSaveName(void)
{
	return allocated_memory_for_savename;
}

#define MAX_HASH 256

struct name_entry {
	struct name_entry *next; /* Pointer to next record. NULL if none.             */
	struct path_info entry;
};

struct free_memory_block_list {
	struct free_memory_block_list *next; /* Pointer to next record. NULL if none. */
	char *ptr;                           /* Pointer to a free area.               */
	int len;                             /* Length of the area.                   */
};

/* Keep the given name on the RAM. The RAM is shared, so NEVER try to modify or kfree() the returned name. */
const struct path_info *SaveName(const char *name)
{
	static struct free_memory_block_list fmb_list = { NULL, NULL, 0 };
	static struct name_entry name_list[MAX_HASH]; /* The list of names. */
	static DECLARE_MUTEX(lock);
	struct name_entry *ptr, *prev = NULL;
	unsigned int hash;
	struct free_memory_block_list *fmb = &fmb_list;
	int len;
	static int first_call = 1;
	if (!name) return NULL;
	len = strlen(name) + 1;
	if (len > CCS_MAX_PATHNAME_LEN) {
		printk("ERROR: Name too long for SaveName().\n");
		return NULL;
	}
	hash = full_name_hash((const unsigned char *) name, len - 1);
	down(&lock);
	if (first_call) {
		int i;
		first_call = 0;
		memset(&name_list, 0, sizeof(name_list));
		for (i = 0; i < MAX_HASH; i++) {
			name_list[i].entry.name = "/";
			fill_path_info(&name_list[i].entry);
		}
		if (CCS_MAX_PATHNAME_LEN > PAGE_SIZE) panic("Bad size.");
	}
	ptr = &name_list[hash % MAX_HASH];
	while (ptr) {
		if (hash == ptr->entry.hash && strcmp(name, ptr->entry.name) == 0) goto out;
		prev = ptr; ptr = ptr->next;
	}
	while (len > fmb->len) {
		if (fmb->next) {
			fmb = fmb->next;
		} else {
			char *cp;
			if ((cp = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL || (fmb->next = alloc_element(sizeof(*fmb))) == NULL) {
				kfree(cp);
				printk("ERROR: Out of memory for SaveName().\n");
				if (!sbin_init_started) panic("MAC Initialization failed.\n");
				goto out; /* ptr == NULL */
			}
			memset(cp, 0, PAGE_SIZE);
			allocated_memory_for_savename += PAGE_SIZE;
			fmb = fmb->next;
			fmb->ptr = cp;
			fmb->len = PAGE_SIZE;
		}
	}
	if ((ptr = alloc_element(sizeof(*ptr))) == NULL) goto out;
	ptr->entry.name = fmb->ptr;
	memmove(fmb->ptr, name, len);
	fill_path_info(&ptr->entry);
	fmb->ptr += len;
	fmb->len -= len;
	prev->next = ptr; /* prev != NULL because name_list is not empty. */
	if (fmb->len == 0) {
		struct free_memory_block_list *ptr = &fmb_list;
		while (ptr->next != fmb) ptr = ptr->next; ptr->next = fmb->next;
	}
 out:
	up(&lock);
	return ptr ? &ptr->entry : NULL;
}

/***** Dynamic memory allocator. *****/

struct cache_entry {
	struct list_head list;
	void *ptr;
	int size;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
static struct kmem_cache *ccs_cachep = NULL;
#else
static kmem_cache_t *ccs_cachep = NULL;
#endif

void __init realpath_Init(void)
{
	ccs_cachep = kmem_cache_create("ccs_cache", sizeof(struct cache_entry), 0, 0, NULL, NULL);
	if (!ccs_cachep) panic("Can't create cache.\n");
}

static LIST_HEAD(cache_list);
static spinlock_t cache_list_lock = SPIN_LOCK_UNLOCKED;
static unsigned int dynamic_memory_size = 0;

unsigned int GetMemoryUsedForDynamic(void)
{
	return dynamic_memory_size;
}

void *ccs_alloc(const size_t size)
{
	void *ret = kmalloc(size, GFP_KERNEL);
	if (ret) {
		struct cache_entry *new_entry = kmem_cache_alloc(ccs_cachep, GFP_KERNEL);
		if (!new_entry) {
			kfree(ret); ret = NULL;
		} else {
			INIT_LIST_HEAD(&new_entry->list);
			new_entry->ptr = ret;
			new_entry->size = size;
			spin_lock(&cache_list_lock);
			list_add_tail(&new_entry->list, &cache_list);
			dynamic_memory_size += size;
			spin_unlock(&cache_list_lock);
			memset(ret, 0, size);
		}
	}
	return ret;
}

void ccs_free(const void *p)
{
	struct list_head *v;
	struct cache_entry *entry = NULL;
	if (!p) return;
	spin_lock(&cache_list_lock);
	list_for_each(v, &cache_list) {
		entry = list_entry(v, struct cache_entry, list);
		if (entry->ptr != p) {
			entry = NULL; continue;
		}
		list_del(&entry->list);
		dynamic_memory_size -= entry->size;
		break;
	}
	spin_unlock(&cache_list_lock);
	if (entry) {
		kfree(p);
		kmem_cache_free(ccs_cachep, entry);
	} else {
		printk("BUG: ccs_free() with invalid pointer.\n");
	}
}
