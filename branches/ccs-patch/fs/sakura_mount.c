/*
 * fs/sakura_mount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/05/28
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
/* For compatibility with older kernels. */
static void put_filesystem(struct file_system_type *fs)
{
	module_put(fs->owner);
}
#endif

/* The list for "struct ccs_mount_entry". */
LIST_HEAD(ccs_mount_list);

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
	struct ccs_mount_entry *entry = NULL;
	struct ccs_mount_entry *ptr;
	const struct ccs_path_info *saved_fs;
	const struct ccs_path_info *saved_dev;
	const struct ccs_path_info *saved_dir;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(fs_type, 0, 0, 0))
		return -EINVAL;
	saved_fs = ccs_get_name(fs_type);
	if (!saved_fs)
		return -ENOMEM;
	if (!dev_name)
		dev_name = "<NULL>";
	if (!strcmp(saved_fs->name, MOUNT_REMOUNT_KEYWORD))
		/* Fix dev_name to "any" for remount permission. */
		dev_name = "any";
	if (!strcmp(saved_fs->name, MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
	    !strcmp(saved_fs->name, MOUNT_MAKE_PRIVATE_KEYWORD) ||
	    !strcmp(saved_fs->name, MOUNT_MAKE_SLAVE_KEYWORD) ||
	    !strcmp(saved_fs->name, MOUNT_MAKE_SHARED_KEYWORD))
		dev_name = "any";
	if (!ccs_is_correct_path(dev_name, 0, 0, 0) ||
	    !ccs_is_correct_path(dir_name, 0, 0, 0)) {
		ccs_put_name(saved_fs);
		return -EINVAL;
	}
	saved_dev = ccs_get_name(dev_name);
	saved_dir = ccs_get_name(dir_name);
	if (!saved_dev || !saved_dir)
		goto out;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_mount_list, list) {
		if (ptr->flags != flags ||
		    ccs_pathcmp(ptr->dev_name, saved_dev) ||
		    ccs_pathcmp(ptr->dir_name, saved_dir) ||
		    ccs_pathcmp(ptr->fs_type, saved_fs))
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry)) {
		entry->dev_name = saved_dev;
		saved_dev = NULL;
		entry->dir_name = saved_dir;
		saved_dir = NULL;
		entry->fs_type = saved_fs;
		saved_fs = NULL;
		entry->flags = flags;
		list_add_tail_rcu(&entry->list, &ccs_mount_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	if (is_delete || error)
		goto out;
	if (!strcmp(fs_type, MOUNT_REMOUNT_KEYWORD))
		printk(KERN_CONT "%sAllow remount %s with options 0x%lX.\n",
		       ccs_log_level, dir_name, flags);
	else if (!strcmp(fs_type, MOUNT_BIND_KEYWORD)
		 || !strcmp(fs_type, MOUNT_MOVE_KEYWORD))
		printk(KERN_CONT "%sAllow mount %s %s %s with options 0x%lX\n",
		       ccs_log_level, fs_type, dev_name, dir_name, flags);
	else if (!strcmp(fs_type, MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
		 !strcmp(fs_type, MOUNT_MAKE_PRIVATE_KEYWORD) ||
		 !strcmp(fs_type, MOUNT_MAKE_SLAVE_KEYWORD) ||
		 !strcmp(fs_type, MOUNT_MAKE_SHARED_KEYWORD))
		printk(KERN_CONT "%sAllow mount %s %s with options 0x%lX.\n",
		       ccs_log_level, fs_type, dir_name, flags);
	else {
		struct file_system_type *type = get_fs_type(fs_type);
		if (type && (type->fs_flags & FS_REQUIRES_DEV) != 0)
			printk(KERN_CONT "%sAllow mount -t %s %s %s "
			       "with options 0x%lX.\n", ccs_log_level,
			       fs_type, dev_name, dir_name, flags);
		else
			printk(KERN_CONT "%sAllow mount %s on %s "
			       "with options 0x%lX.\n", ccs_log_level,
			       fs_type, dir_name, flags);
		if (type)
			put_filesystem(type);
	}
 out:
	ccs_put_name(saved_dev);
	ccs_put_name(saved_dir);
	ccs_put_name(saved_fs);
	kfree(entry);
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
 *
 * Caller holds srcu_read_lock(&ccs_ss).
 */
static int ccs_check_mount_permission2(struct ccs_request_info *r,
				       char *dev_name, char *dir_name,
				       char *type, unsigned long flags)
{
	const bool is_enforce = (r->mode == 3);
	int error;
 retry:
	error = -EPERM;
	if (!type)
		type = "<NULL>";
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;
	switch (flags & (MS_REMOUNT | MS_MOVE | MS_BIND)) {
	case MS_REMOUNT:
	case MS_MOVE:
	case MS_BIND:
	case 0:
		break;
	default:
		printk(KERN_WARNING "SAKURA-ERROR: "
		       "%s%s%sare given for single mount operation.\n",
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
		printk(KERN_WARNING "SAKURA-ERROR: "
		       "%s%s%s%sare given for single mount operation.\n",
		       flags & MS_UNBINDABLE ? "'unbindable' " : "",
		       flags & MS_PRIVATE    ? "'private' " : "",
		       flags & MS_SLAVE      ? "'slave' " : "",
		       flags & MS_SHARED     ? "'shared' " : "");
		return -EINVAL;
	}
	if (flags & MS_REMOUNT) {
		error = ccs_check_mount_permission2(r, dev_name, dir_name,
						    MOUNT_REMOUNT_KEYWORD,
						    flags & ~MS_REMOUNT);
	} else if (flags & MS_MOVE) {
		error = ccs_check_mount_permission2(r, dev_name, dir_name,
						    MOUNT_MOVE_KEYWORD,
						    flags & ~MS_MOVE);
	} else if (flags & MS_BIND) {
		error = ccs_check_mount_permission2(r, dev_name, dir_name,
						    MOUNT_BIND_KEYWORD,
						    flags & ~MS_BIND);
	} else if (flags & MS_UNBINDABLE) {
		error = ccs_check_mount_permission2(r, dev_name, dir_name,
					    MOUNT_MAKE_UNBINDABLE_KEYWORD,
						    flags & ~MS_UNBINDABLE);
	} else if (flags & MS_PRIVATE) {
		error = ccs_check_mount_permission2(r, dev_name, dir_name,
						    MOUNT_MAKE_PRIVATE_KEYWORD,
						    flags & ~MS_PRIVATE);
	} else if (flags & MS_SLAVE) {
		error = ccs_check_mount_permission2(r, dev_name, dir_name,
						    MOUNT_MAKE_SLAVE_KEYWORD,
						    flags & ~MS_SLAVE);
	} else if (flags & MS_SHARED) {
		error = ccs_check_mount_permission2(r, dev_name, dir_name,
						    MOUNT_MAKE_SHARED_KEYWORD,
						    flags & ~MS_SHARED);
	} else {
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
		list_for_each_entry_rcu(ptr, &ccs_mount_list, list) {
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
	int error;
	int idx;
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_RESTRICT_MOUNT);
	if (!r.mode)
		return 0;
	idx = srcu_read_lock(&ccs_ss);
	error = ccs_check_mount_permission2(&r, dev_name, dir_name, type,
					    *flags);
	srcu_read_unlock(&ccs_ss, idx);
	return error;
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
 *
 * Caller holds srcu_read_lock(&ccs_ss).
 */
bool ccs_read_mount_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	list_for_each_cookie(pos, head->read_var2, &ccs_mount_list) {
		struct ccs_mount_entry *ptr;
		ptr = list_entry(pos, struct ccs_mount_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_ALLOW_MOUNT "%s %s %s 0x%lX\n",
				   ptr->dev_name->name, ptr->dir_name->name,
				   ptr->fs_type->name, ptr->flags))
			return false;
	}
	return true;
}
