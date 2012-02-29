/*
 * fs/sakura_mount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/02/29
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#include <linux/namespace.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
#define MS_UNBINDABLE	(1<<17)	/* change to unbindable */
#define MS_PRIVATE	(1<<18)	/* change to private */
#define MS_SLAVE	(1<<19)	/* change to slave */
#define MS_SHARED	(1<<20)	/* change to shared */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#else
/* For compatibility with older kernels. */
static inline void module_put(struct module *module)
{
	if (module)
		__MOD_DEC_USE_COUNT(module);
}
#endif

/* Keywords for mount restrictions. */

/* Allow to call 'mount --bind /source_dir /dest_dir' */
#define MOUNT_BIND_KEYWORD                               "--bind"
/* Allow to call 'mount --move /old_dir    /new_dir ' */
#define MOUNT_MOVE_KEYWORD                               "--move"
/* Allow to call 'mount -o remount /dir             ' */
#define MOUNT_REMOUNT_KEYWORD                            "--remount"
/* Allow to call 'mount --make-unbindable /dir'       */
#define MOUNT_MAKE_UNBINDABLE_KEYWORD                    "--make-unbindable"
/* Allow to call 'mount --make-private /dir'          */
#define MOUNT_MAKE_PRIVATE_KEYWORD                       "--make-private"
/* Allow to call 'mount --make-slave /dir'            */
#define MOUNT_MAKE_SLAVE_KEYWORD                         "--make-slave"
/* Allow to call 'mount --make-shared /dir'           */
#define MOUNT_MAKE_SHARED_KEYWORD                        "--make-shared"

/* Structure for "allow_mount" keyword. */
struct ccs_mount_entry {
	struct list1_head list;
	const struct ccs_path_info *dev_name;
	const struct ccs_path_info *dir_name;
	const struct ccs_path_info *fs_type;
	unsigned long flags;
	bool is_deleted;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
/* For compatibility with older kernels. */
static void put_filesystem(struct file_system_type *fs)
{
	module_put(fs->owner);
}
#endif

/* The list for "struct ccs_mount_entry". */
static LIST1_HEAD(ccs_mount_list);

/**
 * ccs_update_mount_acl - Update "struct ccs_mount_entry" list.
 *
 * @dev_name:  Name of device file.
 * @dir_name:  Name of mount point.
 * @fs_type:   Name of filesystem.
 * @flags:     Mount options.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_mount_acl(const char *dev_name, const char *dir_name,
				const char *fs_type, const unsigned long flags,
				const bool is_delete)
{
	struct file_system_type *type = NULL;
	struct ccs_mount_entry *new_entry;
	struct ccs_mount_entry *ptr;
	const struct ccs_path_info *fs;
	const struct ccs_path_info *dev;
	const struct ccs_path_info *dir;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if (!ccs_is_correct_path(fs_type, 0, 0, 0, __func__))
		return -EINVAL;
	fs = ccs_save_name(fs_type);
	if (!fs)
		return -EINVAL;
	if (!dev_name)
		dev_name = "<NULL>";
	if (!strcmp(fs->name, MOUNT_REMOUNT_KEYWORD))
		/* Fix dev_name to "any" for remount permission. */
		dev_name = "any";
	if (!strcmp(fs->name, MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
	    !strcmp(fs->name, MOUNT_MAKE_PRIVATE_KEYWORD) ||
	    !strcmp(fs->name, MOUNT_MAKE_SLAVE_KEYWORD) ||
	    !strcmp(fs->name, MOUNT_MAKE_SHARED_KEYWORD))
		dev_name = "any";
	if (!ccs_is_correct_path(dev_name, 0, 0, 0, __func__) ||
	    !ccs_is_correct_path(dir_name, 0, 0, 0, __func__))
		return -EINVAL;
	dev = ccs_save_name(dev_name);
	dir = ccs_save_name(dir_name);
	if (!dev || !dir)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_mount_list, list) {
		if (ptr->flags != flags ||
		    ccs_pathcmp(ptr->dev_name, dev) ||
		    ccs_pathcmp(ptr->dir_name, dir) ||
		    ccs_pathcmp(ptr->fs_type, fs))
			continue;
		error = 0;
		if (is_delete) {
			ptr->is_deleted = true;
			goto out;
		} else {
			if (ptr->is_deleted) {
				ptr->is_deleted = false;
				goto update;
			}
			goto out; /* No changes. */
		}
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	new_entry = ccs_alloc_element(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	new_entry->dev_name = dev;
	new_entry->dir_name = dir;
	new_entry->fs_type = fs;
	new_entry->flags = flags;
	list1_add_tail_mb(&new_entry->list, &ccs_mount_list);
	error = 0;
	ptr = new_entry;
 update:
	if (!strcmp(fs->name, MOUNT_REMOUNT_KEYWORD)) {
		printk(KERN_CONT "%sAllow remount %s with options 0x%lX.\n",
		       ccs_log_level, dir->name, ptr->flags);
	} else if (!strcmp(fs->name, MOUNT_BIND_KEYWORD)
		   || !strcmp(fs->name, MOUNT_MOVE_KEYWORD)) {
		printk(KERN_CONT "%sAllow mount %s %s %s with options 0x%lX\n",
		       ccs_log_level, fs->name, dev->name, dir->name,
		       ptr->flags);
	} else if (!strcmp(fs->name, MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
		   !strcmp(fs->name, MOUNT_MAKE_PRIVATE_KEYWORD) ||
		   !strcmp(fs->name, MOUNT_MAKE_SLAVE_KEYWORD) ||
		   !strcmp(fs->name, MOUNT_MAKE_SHARED_KEYWORD)) {
		printk(KERN_CONT "%sAllow mount %s %s with options 0x%lX.\n",
		       ccs_log_level, fs->name, dir->name, ptr->flags);
	} else {
		mutex_unlock(&lock);
		type = get_fs_type(fs->name);
		mutex_lock(&lock);
		if (type && (type->fs_flags & FS_REQUIRES_DEV) != 0)
			printk(KERN_CONT "%sAllow mount -t %s %s %s "
			       "with options 0x%lX.\n", ccs_log_level,
			       fs->name, dev->name, dir->name, ptr->flags);
		else
			printk(KERN_CONT "%sAllow mount %s on %s "
			       "with options 0x%lX.\n", ccs_log_level,
			       fs->name, dir->name, ptr->flags);
	}
	if (type)
		put_filesystem(type);
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_SYSTEM_POLICY);
	return error;
}

/**
 * ccs_print_success - Print success messages.
 *
 * @dev_name: Name of device file.
 * @dir_name: Name of mount point.
 * @type:     Name of filesystem type.
 * @flags:    Mount options.
 * @need_dev: Type of @dev_name.
 *
 * Returns nothing.
 */
static void ccs_print_success(const char *dev_name, const char *dir_name,
			      const char *type, const unsigned long flags,
			      const int need_dev)
{
	if (need_dev > 0) {
		printk(KERN_DEBUG "SAKURA-NOTICE: "
		       "'mount -t %s %s %s 0x%lX' accepted.\n",
		       type, dev_name, dir_name, flags);
	} else if (need_dev < 0) {
		printk(KERN_DEBUG "SAKURA-NOTICE: "
		       "'mount %s %s %s 0x%lX' accepted.\n",
		       type, dev_name, dir_name, flags);
	} else if (!strcmp(type, MOUNT_REMOUNT_KEYWORD)) {
		printk(KERN_DEBUG "SAKURA-NOTICE: "
		       "'mount -o remount %s 0x%lX' accepted.\n",
		       dir_name, flags);
	} else if (!strcmp(type, MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
		   !strcmp(type, MOUNT_MAKE_PRIVATE_KEYWORD) ||
		   !strcmp(type, MOUNT_MAKE_SLAVE_KEYWORD) ||
		   !strcmp(type, MOUNT_MAKE_SHARED_KEYWORD)) {
		printk(KERN_DEBUG "SAKURA-NOTICE: "
		       "'mount %s %s 0x%lX' accepted.\n",
		       type, dir_name, flags);
	} else {
		printk(KERN_DEBUG "SAKURA-NOTICE: "
		       "'mount %s on %s 0x%lX' accepted.\n",
		       type, dir_name, flags);
	}
}

/**
 * ccs_print_error - Print error messages.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @dev_name: Name of device file.
 * @dir_name: Name of mount point.
 * @type:     Name of filesystem type.
 * @flags:    Mount options.
 * @error:    Error value.
 *
 * Returns 0 if permitted by the administrator's decision, negative value
 * otherwise.
 */
static int ccs_print_error(struct ccs_request_info *r,
			   const char *dev_name, const char *dir_name,
			   const char *type, const unsigned long flags,
			   int error)
{
	const bool is_enforce = (r->mode == 3);
	const char *exename = ccs_get_exe();
	const pid_t pid = (pid_t) sys_getpid();
	if (!strcmp(type, MOUNT_REMOUNT_KEYWORD)) {
		printk(KERN_WARNING "SAKURA-%s: mount -o remount %s 0x%lX "
		       "(pid=%d:exe=%s): Permission denied.\n",
		       ccs_get_msg(is_enforce), dir_name, flags, pid, exename);
		if (is_enforce)
			error = ccs_check_supervisor(r, "# %s is requesting\n"
						     "mount -o remount %s "
						     "0x%lX\n", exename,
						     dir_name, flags);
	} else if (!strcmp(type, MOUNT_BIND_KEYWORD)
		   || !strcmp(type, MOUNT_MOVE_KEYWORD)) {
		printk(KERN_WARNING "SAKURA-%s: mount %s %s %s 0x%lX "
		       "(pid=%d:exe=%s): Permission denied.\n",
		       ccs_get_msg(is_enforce), type, dev_name, dir_name,
		       flags, pid, exename);
		if (is_enforce)
			error = ccs_check_supervisor(r, "# %s is requesting\n"
						     "mount %s %s %s 0x%lX\n",
						     exename, type, dev_name,
						     dir_name, flags);
	} else if (!strcmp(type, MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
		   !strcmp(type, MOUNT_MAKE_PRIVATE_KEYWORD) ||
		   !strcmp(type, MOUNT_MAKE_SLAVE_KEYWORD) ||
		   !strcmp(type, MOUNT_MAKE_SHARED_KEYWORD)) {
		printk(KERN_WARNING "SAKURA-%s: mount %s %s 0x%lX "
		       "(pid=%d:exe=%s): Permission denied.\n",
		       ccs_get_msg(is_enforce), type, dir_name, flags, pid,
		       exename);
		if (is_enforce)
			error = ccs_check_supervisor(r, "# %s is requesting\n"
						     "mount %s %s 0x%lX",
						     exename, type, dir_name,
						     flags);
	} else {
		printk(KERN_WARNING "SAKURA-%s: mount -t %s %s %s 0x%lX "
		       "(pid=%d:exe=%s): Permission denied.\n",
		       ccs_get_msg(is_enforce), type, dev_name, dir_name,
		       flags, pid, exename);
		if (is_enforce)
			error = ccs_check_supervisor(r, "# %s is requesting\n"
						     "mount -t %s %s %s "
						     "0x%lX\n", exename, type,
						     dev_name, dir_name,
						     flags);
	}
	ccs_free(exename);
	return error;
}

/**
 * ccs_check_mount_permission2 - Check permission for mount() operation.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @dev_name: Name of device file.
 * @dir_name: Name of mount point.
 * @type:     Name of filesystem type. May be NULL.
 * @flags:    Mount options.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_mount_permission2(struct ccs_request_info *r,
				       char *dev_name, char *dir_name,
				       char *type, unsigned long flags)
{
	const bool is_enforce = (r->mode == 3);
	int error;
 retry:
	error = -EPERM;
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;
	if (flags & MS_REMOUNT) {
		type = MOUNT_REMOUNT_KEYWORD;
		flags &= ~MS_REMOUNT;
	} else if (flags & MS_BIND) {
		type = MOUNT_BIND_KEYWORD;
		flags &= ~MS_BIND;
	} else if (flags & MS_SHARED) {
		if (flags & (MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
			return -EINVAL;
		type = MOUNT_MAKE_SHARED_KEYWORD;
		flags &= ~MS_SHARED;
	} else if (flags & MS_PRIVATE) {
		if (flags & (MS_SHARED | MS_SLAVE | MS_UNBINDABLE))
			return -EINVAL;
		type = MOUNT_MAKE_PRIVATE_KEYWORD;
		flags &= ~MS_PRIVATE;
	} else if (flags & MS_SLAVE) {
		if (flags & (MS_SHARED | MS_PRIVATE | MS_UNBINDABLE))
			return -EINVAL;
		type = MOUNT_MAKE_SLAVE_KEYWORD;
		flags &= ~MS_SLAVE;
	} else if (flags & MS_UNBINDABLE) {
		if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE))
			return -EINVAL;
		type = MOUNT_MAKE_UNBINDABLE_KEYWORD;
		flags &= ~MS_UNBINDABLE;
	} else if (flags & MS_MOVE) {
		type = MOUNT_MOVE_KEYWORD;
		flags &= ~MS_MOVE;
	}
	if (!type)
		type = "<NULL>";
	{
		struct ccs_mount_entry *ptr;
		struct file_system_type *fstype = NULL;
		const char *requested_type = NULL;
		const char *requested_dir_name = NULL;
		const char *requested_dev_name = NULL;
		struct ccs_path_info rdev;
		struct ccs_path_info rdir;
		int need_dev = 0;

		requested_type = ccs_encode(type);
		if (!requested_type) {
			error = -ENOMEM;
			goto cleanup;
		}
		requested_dir_name = ccs_realpath(dir_name);
		if (!requested_dir_name) {
			error = -ENOENT;
			goto cleanup;
		}
		rdir.name = requested_dir_name;
		ccs_fill_path_info(&rdir);

		/* Compare fs name. */
		if (!strcmp(type, MOUNT_REMOUNT_KEYWORD)) {
			/* dev_name is ignored. */
		} else if (!strcmp(type, MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
			   !strcmp(type, MOUNT_MAKE_PRIVATE_KEYWORD) ||
			   !strcmp(type, MOUNT_MAKE_SLAVE_KEYWORD) ||
			   !strcmp(type, MOUNT_MAKE_SHARED_KEYWORD)) {
			/* dev_name is ignored. */
		} else if (!strcmp(type, MOUNT_BIND_KEYWORD) ||
			   !strcmp(type, MOUNT_MOVE_KEYWORD)) {
			need_dev = -1; /* dev_name is a directory */
		} else {
			fstype = get_fs_type(type);
			if (!fstype) {
				error = -ENODEV;
				goto cleanup;
			}
			if (fstype->fs_flags & FS_REQUIRES_DEV)
				/* dev_name is a block device file. */
				need_dev = 1;
		}
		if (need_dev) {
			requested_dev_name = ccs_realpath(dev_name);
			if (!requested_dev_name) {
				error = -ENOENT;
				goto cleanup;
			}
		} else {
			/* Map dev_name to "<NULL>" if no dev_name given. */
			if (!dev_name)
				dev_name = "<NULL>";
			requested_dev_name = ccs_encode(dev_name);
			if (!requested_dev_name) {
				error = -ENOMEM;
				goto cleanup;
			}
		}
		rdev.name = requested_dev_name;
		ccs_fill_path_info(&rdev);
		list1_for_each_entry(ptr, &ccs_mount_list, list) {
			if (ptr->is_deleted)
				continue;

			/* Compare options */
			if (ptr->flags != flags)
				continue;

			/* Compare fs name. */
			if (strcmp(type, ptr->fs_type->name))
				continue;

			/* Compare mount point. */
			if (!ccs_path_matches_pattern(&rdir, ptr->dir_name))
				continue;

			/* Compare device name. */
			if (need_dev &&
			    !ccs_path_matches_pattern(&rdev, ptr->dev_name))
				continue;

			/* OK. */
			error = 0;
			ccs_print_success(requested_dev_name,
					  requested_dir_name,
					  requested_type, flags, need_dev);
			break;
		}
		if (error)
			error = ccs_print_error(r, requested_dev_name,
						requested_dir_name,
						requested_type,
						flags, error);
		if (error && r->mode == 1)
			ccs_update_mount_acl(requested_dev_name,
					     requested_dir_name,
					     requested_type, flags, false);
 cleanup:
		ccs_free(requested_dev_name);
		ccs_free(requested_dir_name);
		if (fstype)
			put_filesystem(fstype);
		ccs_free(requested_type);
	}
	if (!is_enforce)
		error = 0;
	if (error == 1)
		goto retry;
	return error;
}

/**
 * ccs_check_mount_permission - Check permission for mount() operation.
 *
 * @dev_name: Name of device file.
 * @dir_name: Name of mount point.
 * @type:     Name of filesystem type. May be NULL.
 * @flags:    Mount options.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_mount_permission(char *dev_name, char *dir_name, char *type,
			       const unsigned long *flags)
{
	struct ccs_request_info r;
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_RESTRICT_MOUNT);
	if (!r.mode)
		return 0;
	return ccs_check_mount_permission2(&r, dev_name, dir_name, type,
					   *flags);
}

/**
 * ccs_write_mount_policy - Write "struct ccs_mount_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_mount_policy(char *data, const bool is_delete)
{
	char *cp;
	char *cp2;
	const char *fs;
	const char *dev;
	const char *dir;
	unsigned long flags = 0;
	cp2 = data;
	cp = strchr(cp2, ' ');
	if (!cp)
		return -EINVAL;
	*cp = '\0';
	dev = cp2;
	cp2 = cp + 1;
	cp = strchr(cp2, ' ');
	if (!cp)
		return -EINVAL;
	*cp = '\0';
	dir = cp2;
	cp2 = cp + 1;
	cp = strchr(cp2, ' ');
	if (!cp)
		return -EINVAL;
	*cp = '\0';
	fs = cp2;
	flags = simple_strtoul(cp + 1, NULL, 0);
	return ccs_update_mount_acl(dev, dir, fs, flags, is_delete);
}

/**
 * ccs_read_mount_policy - Read "struct ccs_mount_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_mount_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	list1_for_each_cookie(pos, head->read_var2, &ccs_mount_list) {
		struct ccs_mount_entry *ptr;
		ptr = list1_entry(pos, struct ccs_mount_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_ALLOW_MOUNT "%s %s %s 0x%lX\n",
				   ptr->dev_name->name, ptr->dir_name->name,
				   ptr->fs_type->name, ptr->flags))
			goto out;
	}
	return true;
 out:
	return false;
}
