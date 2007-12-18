/*
 * fs/sakura_mount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.5.3-pre   2007/12/18
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#include <linux/namespace.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#define MS_UNBINDABLE	(1<<17)	/* change to unbindable */
#define MS_PRIVATE	(1<<18)	/* change to private */
#define MS_SLAVE	(1<<19)	/* change to slave */
#define MS_SHARED	(1<<20)	/* change to shared */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <linux/namei.h>
#else
static inline void module_put(struct module *module)
{
	if (module) __MOD_DEC_USE_COUNT(module);
}
#endif

extern const char *ccs_log_level;

/***** KEYWORDS for mount restrictions. *****/

#define MOUNT_BIND_KEYWORD    "--bind"    /* Allow to call 'mount --bind /source_dir /dest_dir' */
#define MOUNT_MOVE_KEYWORD    "--move"    /* Allow to call 'mount --move /old_dir    /new_dir ' */
#define MOUNT_REMOUNT_KEYWORD "--remount" /* Allow to call 'mount -o remount /dir             ' */
#define MOUNT_MAKE_UNBINDABLE_KEYWORD "--make-unbindable" /* Allow to call 'mount --make-unbindable /dir' */
#define MOUNT_MAKE_PRIVATE_KEYWORD    "--make-private"    /* Allow to call 'mount --make-private /dir'    */
#define MOUNT_MAKE_SLAVE_KEYWORD      "--make-slave"      /* Allow to call 'mount --make-slave /dir'      */
#define MOUNT_MAKE_SHARED_KEYWORD     "--make-shared"     /* Allow to call 'mount --make-shared /dir'     */

/***** The structure for mount restrictions. *****/

struct mount_entry {
	struct list1_head list;
	const struct path_info *dev_name;
	const struct path_info *dir_name;
	const struct path_info *fs_type;
	unsigned long flags;
	bool is_deleted;
};

/*************************  MOUNT RESTRICTION HANDLER  *************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static void put_filesystem(struct file_system_type *fs)
{
	module_put(fs->owner);
}
#endif

static LIST1_HEAD(mount_list);

static int AddMountACL(const char *dev_name, const char *dir_name, const char *fs_type, const unsigned long flags, const bool is_delete)
{
	struct mount_entry *new_entry, *ptr;
	const struct path_info *fs, *dev, *dir;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if ((fs = SaveName(fs_type)) == NULL) return -EINVAL;
	if (!dev_name) dev_name = "<NULL>"; /* Map dev_name to "<NULL>" for if no dev_name given. */
	if (strcmp(fs->name, MOUNT_REMOUNT_KEYWORD) == 0) dev_name = "any"; /* Fix dev_name to "any" for remount permission. */
	if (strcmp(fs->name, MOUNT_MAKE_UNBINDABLE_KEYWORD) == 0 ||
		strcmp(fs->name, MOUNT_MAKE_PRIVATE_KEYWORD) == 0 ||
		strcmp(fs->name, MOUNT_MAKE_SLAVE_KEYWORD) == 0 ||
		strcmp(fs->name, MOUNT_MAKE_SHARED_KEYWORD) == 0) dev_name = "any";
	if (!IsCorrectPath(dev_name, 0, 0, 0, __FUNCTION__) || !IsCorrectPath(dir_name, 0, 0, 0, __FUNCTION__)) return -EINVAL;
	if ((dev = SaveName(dev_name)) == NULL || (dir = SaveName(dir_name)) == NULL) return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &mount_list, list) {
		if (ptr->flags != flags || pathcmp(ptr->dev_name, dev) || pathcmp(ptr->dir_name, dir) || pathcmp(ptr->fs_type, fs)) continue;
		error = 0;
		if (is_delete) {
			ptr->is_deleted = 1;
			goto out;
		} else {
			if (ptr->is_deleted) {
				ptr->is_deleted = 0;
				goto update;
			}
			goto out; /* No changes. */
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if ((new_entry = alloc_element(sizeof(*new_entry))) == NULL) goto out;
	new_entry->dev_name = dev;
	new_entry->dir_name = dir;
	new_entry->fs_type = fs;
	new_entry->flags = flags;
	list1_add_tail_mb(&new_entry->list, &mount_list);
	error = 0;
	ptr = new_entry;
 update:
	{
		struct file_system_type *type = NULL;
		if (strcmp(fs->name, MOUNT_REMOUNT_KEYWORD) == 0) {
			printk("%sAllow remount %s with options 0x%lX.\n", ccs_log_level, dir->name, ptr->flags);
		} else if (strcmp(fs->name, MOUNT_BIND_KEYWORD) == 0 || strcmp(fs->name, MOUNT_MOVE_KEYWORD) == 0) {
			printk("%sAllow mount %s %s %s with options 0x%lX\n", ccs_log_level, fs->name, dev->name, dir->name, ptr->flags);
		} else if (strcmp(fs->name, MOUNT_MAKE_UNBINDABLE_KEYWORD) == 0 ||
				   strcmp(fs->name, MOUNT_MAKE_PRIVATE_KEYWORD) == 0 ||
				   strcmp(fs->name, MOUNT_MAKE_SLAVE_KEYWORD) == 0 ||
				   strcmp(fs->name, MOUNT_MAKE_SHARED_KEYWORD) == 0) {
			printk("%sAllow mount %s %s with options 0x%lX.\n", ccs_log_level, fs->name, dir->name, ptr->flags);
		} else if ((type = get_fs_type(fs->name)) != NULL && (type->fs_flags & FS_REQUIRES_DEV) != 0) {
			printk("%sAllow mount -t %s %s %s with options 0x%lX.\n", ccs_log_level, fs->name, dev->name, dir->name, ptr->flags);
		} else {
			printk("%sAllow mount %s on %s with options 0x%lX.\n", ccs_log_level, fs->name, dir->name, ptr->flags);
		}
		if (type) put_filesystem(type);
	}
 out:
	mutex_unlock(&lock);
	return error;
}

static int CheckMountPermission2(char *dev_name, char *dir_name, char *type, unsigned long flags)
{
	const unsigned int mode = CheckCCSFlags(CCS_SAKURA_RESTRICT_MOUNT);
	const bool is_enforce = (mode == 3);
	int error = -EPERM;
	if (!mode) return 0;
	if (!type) type = "<NULL>";
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL) flags &= ~MS_MGC_MSK;
	switch (flags & (MS_REMOUNT | MS_MOVE | MS_BIND)) {
	case MS_REMOUNT:
	case MS_MOVE:
	case MS_BIND:
	case 0:
		break;
	default:
		printk("SAKURA-ERROR: %s%s%sare given for single mount operation.\n",
		       flags & MS_REMOUNT ? "'remount' " : "",
		       flags & MS_MOVE    ? "'move' " : "",
		       flags & MS_BIND    ? "'bind' " : "");
		return -EINVAL;
	}
	switch (flags & (MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED)) {
	case MS_UNBINDABLE:
	case MS_PRIVATE:
	case MS_SLAVE:
	case MS_SHARED:
	case 0:
		break;
	default:
		printk("SAKURA-ERROR: %s%s%s%sare given for single mount operation.\n",
		       flags & MS_UNBINDABLE ? "'unbindable' " : "",
		       flags & MS_PRIVATE    ? "'private' " : "",
		       flags & MS_SLAVE      ? "'slave' " : "",
		       flags & MS_SHARED     ? "'shared' " : "");
		return -EINVAL;
	}
	if (flags & MS_REMOUNT) {
		error = CheckMountPermission2(dev_name, dir_name, MOUNT_REMOUNT_KEYWORD, flags & ~MS_REMOUNT);
	} else if (flags & MS_MOVE) {
		error = CheckMountPermission2(dev_name, dir_name, MOUNT_MOVE_KEYWORD, flags & ~MS_MOVE);
	} else if (flags & MS_BIND) {
		error = CheckMountPermission2(dev_name, dir_name, MOUNT_BIND_KEYWORD, flags & ~MS_BIND);
	} else if (flags & MS_UNBINDABLE) {
		error = CheckMountPermission2(dev_name, dir_name, MOUNT_MAKE_UNBINDABLE_KEYWORD, flags & ~MS_UNBINDABLE);
	} else if (flags & MS_PRIVATE) {
		error = CheckMountPermission2(dev_name, dir_name, MOUNT_MAKE_PRIVATE_KEYWORD, flags & ~MS_PRIVATE);
	} else if (flags & MS_SLAVE) {
		error = CheckMountPermission2(dev_name, dir_name, MOUNT_MAKE_SLAVE_KEYWORD, flags & ~MS_SLAVE);
	} else if (flags & MS_SHARED) {
		error = CheckMountPermission2(dev_name, dir_name, MOUNT_MAKE_SHARED_KEYWORD, flags & ~MS_SHARED);
	} else {
		struct mount_entry *ptr;
		struct file_system_type *fstype = NULL;
		const char *requested_dir_name = NULL;
		const char *requested_dev_name = NULL;
		struct path_info rdev, rdir;
		int need_dev = 0;
		
		if ((requested_dir_name = realpath(dir_name)) == NULL) {
			error = -ENOENT;
			goto cleanup;
		}
		rdir.name = requested_dir_name;
		fill_path_info(&rdir);
		
		/* Compare fs name. */
		if (strcmp(type, MOUNT_REMOUNT_KEYWORD) == 0) {
			/* Needn't to resolve dev_name */
		} else if (strcmp(type, MOUNT_MAKE_UNBINDABLE_KEYWORD) == 0 ||
			   strcmp(type, MOUNT_MAKE_PRIVATE_KEYWORD) == 0 ||
			   strcmp(type, MOUNT_MAKE_SLAVE_KEYWORD) == 0 ||
			   strcmp(type, MOUNT_MAKE_SHARED_KEYWORD) == 0) {
			/* Needn't to resolve dev_name */
		} else if (strcmp(type, MOUNT_BIND_KEYWORD) == 0 || strcmp(type, MOUNT_MOVE_KEYWORD) == 0) {
			if ((requested_dev_name = realpath(dev_name)) == NULL) {
				error = -ENOENT;
				goto cleanup;
			}
			rdev.name = requested_dev_name;
			fill_path_info(&rdev);
			need_dev = -1; /* dev_name is a directory */
		} else if ((fstype = get_fs_type(type)) != NULL) {
			if (fstype->fs_flags & FS_REQUIRES_DEV) {
				if ((requested_dev_name = realpath(dev_name)) == NULL) {
					error = -ENOENT;
					goto cleanup;
				}
				rdev.name = requested_dev_name;
				fill_path_info(&rdev);
				need_dev = 1; /* dev_name is a block device file */
			}
		} else {
			error = -ENODEV;
			goto cleanup;
		}
		list1_for_each_entry(ptr, &mount_list, list) {
			if (ptr->is_deleted) continue;
			
			/* Compare options */
			if (ptr->flags != flags) continue;
			
			/* Compare fs name. */
			if (strcmp(type, ptr->fs_type->name)) continue;
			
			/* Compare mount point. */
			if (PathMatchesToPattern(&rdir, ptr->dir_name) == 0) continue;
			
			/* Compare device name. */
			if (requested_dev_name && PathMatchesToPattern(&rdev, ptr->dev_name) == 0) continue;
			
			/* OK. */
			error = 0;
			
			if (need_dev > 0) {
				printk(KERN_DEBUG "SAKURA-NOTICE: 'mount -t %s %s %s 0x%lX' accepted.\n", type, requested_dev_name, requested_dir_name, flags);
			} else if (need_dev < 0) {
				printk(KERN_DEBUG "SAKURA-NOTICE: 'mount %s %s %s 0x%lX' accepted.\n", type, requested_dev_name, requested_dir_name, flags);
			} else if (strcmp(type, MOUNT_REMOUNT_KEYWORD) == 0) {
				printk(KERN_DEBUG "SAKURA-NOTICE: 'mount -o remount %s 0x%lX' accepted.\n", requested_dir_name, flags);
			} else if (strcmp(type, MOUNT_MAKE_UNBINDABLE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_PRIVATE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_SLAVE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_SHARED_KEYWORD) == 0) {
				printk(KERN_DEBUG "SAKURA-NOTICE: 'mount %s %s 0x%lX' accepted.\n", type, requested_dir_name, flags);
			} else {
				printk(KERN_DEBUG "SAKURA-NOTICE: 'mount %s on %s 0x%lX' accepted.\n", type, requested_dir_name, flags);
			}
			break;
		}
		if (error) {
			const char *realname1 = realpath(dev_name), *realname2 = realpath(dir_name), *exename = GetEXE();
			if (strcmp(type, MOUNT_REMOUNT_KEYWORD) == 0) {
				printk("SAKURA-%s: mount -o remount %s 0x%lX (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), realname2 ? realname2 : dir_name, flags, current->pid, exename);
				if (is_enforce && CheckSupervisor("# %s is requesting\nmount -o remount %s 0x%lX\n", exename, realname2 ? realname2 : dir_name, flags) == 0) error = 0;
			} else if (strcmp(type, MOUNT_BIND_KEYWORD) == 0 || strcmp(type, MOUNT_MOVE_KEYWORD) == 0) {
				printk("SAKURA-%s: mount %s %s %s 0x%lX (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), type, realname1 ? realname1 : dev_name, realname2 ? realname2 : dir_name, flags, current->pid, exename);
				if (is_enforce && CheckSupervisor("# %s is requesting\nmount %s %s %s 0x%lX\n", exename, type, realname1 ? realname1 : dev_name, realname2 ? realname2 : dir_name, flags) == 0) error = 0;
			} else if (strcmp(type, MOUNT_MAKE_UNBINDABLE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_PRIVATE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_SLAVE_KEYWORD) == 0 ||
				   strcmp(type, MOUNT_MAKE_SHARED_KEYWORD) == 0) {
				printk("SAKURA-%s: mount %s %s 0x%lX (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), type, realname2 ? realname2 : dir_name, flags, current->pid, exename);
				if (is_enforce && CheckSupervisor("# %s is requesting\nmount %s %s 0x%lX", exename, type, realname2 ? realname2 : dir_name, flags) == 0) error = 0;
			} else {
				printk("SAKURA-%s: mount -t %s %s %s 0x%lX (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), type, realname1 ? realname1 : dev_name, realname2 ? realname2 : dir_name, flags, current->pid, exename);
				if (is_enforce && CheckSupervisor("# %s is requesting\nmount -t %s %s %s 0x%lX\n", exename, type, realname1 ? realname1 : dev_name, realname2 ? realname2 : dir_name, flags) == 0) error = 0;
			}
			ccs_free(exename);
			ccs_free(realname2);
			ccs_free(realname1);
		}
		if (error && mode == 1) {
			AddMountACL(need_dev ? requested_dev_name : dev_name, requested_dir_name, type, flags, 0);
			UpdateCounter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
		}
	cleanup:
		ccs_free(requested_dev_name);
		ccs_free(requested_dir_name);
		if (fstype) put_filesystem(fstype);
	}
	if (!is_enforce) error = 0;
	return error;
}

/* This is a wrapper to allow use of 1.4.x patch for 1.5.x . */
int CheckMountPermission(char *dev_name, char *dir_name, char *type, const unsigned long *flags)
{
	return CheckMountPermission2(dev_name, dir_name, type, *flags);
}

int AddMountPolicy(char *data, const bool is_delete)
{
	char *cp, *cp2;
	const char *fs, *dev, *dir;
	unsigned long flags = 0;
	cp2 = data; if ((cp = strchr(cp2, ' ')) == NULL) return -EINVAL; *cp = '\0'; dev = cp2;
	cp2 = cp + 1; if ((cp = strchr(cp2, ' ')) == NULL) return -EINVAL; *cp = '\0'; dir = cp2;
	cp2 = cp + 1; if ((cp = strchr(cp2, ' ')) == NULL) return -EINVAL; *cp = '\0'; fs = cp2;
	flags = simple_strtoul(cp + 1, NULL, 0);
	return AddMountACL(dev, dir, fs, flags, is_delete);
}

int ReadMountPolicy(struct io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &mount_list) {
		struct mount_entry *ptr;
		ptr = list1_entry(pos, struct mount_entry, list);
		if (ptr->is_deleted) continue;
		if (io_printf(head, KEYWORD_ALLOW_MOUNT "%s %s %s 0x%lX\n", ptr->dev_name->name, ptr->dir_name->name, ptr->fs_type->name, ptr->flags)) return -ENOMEM;
	}
	return 0;
}

/***** SAKURA Linux end. *****/
