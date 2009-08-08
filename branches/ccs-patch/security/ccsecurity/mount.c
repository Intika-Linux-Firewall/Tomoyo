/*
 * security/ccsecurity/mount.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/slab.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/dcache.h>
#include <linux/namei.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#include <linux/namespace.h>
#endif
#include "internal.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
#define MS_UNBINDABLE	(1<<17)	/* change to unbindable */
#define MS_PRIVATE	(1<<18)	/* change to private */
#define MS_SLAVE	(1<<19)	/* change to slave */
#define MS_SHARED	(1<<20)	/* change to shared */
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

/**
 * ccs_audit_mount_log - Audit mount log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @dev_name:   Device file.
 * @dir_name:   Mount point.
 * @type:       Filesystem type.
 * @flags:      Mount flags.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_mount_log(struct ccs_request_info *r,
			       const char *dev_name, const char *dir_name,
			       const char *type, const unsigned long flags,
			       const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain)) {
		const bool is_enforce = (r->mode == 3);
		const char *msg = ccs_get_msg(is_enforce);
		const char *domainname = ccs_get_last_name(r->domain);
		if (!strcmp(type, MOUNT_REMOUNT_KEYWORD))
			printk(KERN_WARNING
			       "SAKURA-%s: mount -o remount %s 0x%lX "
			       "denied for %s.\n", msg, dir_name, flags,
			       domainname);
		else if (!strcmp(type, MOUNT_BIND_KEYWORD)
			 || !strcmp(type, MOUNT_MOVE_KEYWORD))
			printk(KERN_WARNING "SAKURA-%s: mount %s %s %s 0x%lX "
			       "denied for %s\n", msg, type, dev_name,
			       dir_name, flags, domainname);
		else if (!strcmp(type, MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
			 !strcmp(type, MOUNT_MAKE_PRIVATE_KEYWORD) ||
			 !strcmp(type, MOUNT_MAKE_SLAVE_KEYWORD) ||
			 !strcmp(type, MOUNT_MAKE_SHARED_KEYWORD))
			printk(KERN_WARNING
			       "SAKURA-%s: mount %s %s 0x%lX denied for %s\n",
			       msg, type, dir_name, flags, domainname);
		else
			printk(KERN_WARNING
			       "SAKURA-%s: mount -t %s %s %s 0x%lX "
			       "denied for %s\n", msg, type, dev_name,
			       dir_name, flags, domainname);
	}
	return ccs_write_audit_log(is_granted, r, KEYWORD_ALLOW_MOUNT
				   "%s %s %s 0x%lu\n", dev_name, dir_name,
				   type, flags);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
/* For compatibility with older kernels. */
static inline void module_put(struct module *module)
{
	if (module)
		__MOD_DEC_USE_COUNT(module);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
/* For compatibility with older kernels. */
static void put_filesystem(struct file_system_type *fs)
{
	module_put(fs->owner);
}
#endif

/**
 * ccs_update_mount_acl - Update "struct ccs_mount_acl_record" list.
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
				struct ccs_domain_info *domain,
				struct ccs_condition *condition,
				const bool is_delete)
{
	struct ccs_mount_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
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
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_mount_acl_record *acl;
		if (ccs_acl_type1(ptr) != TYPE_MOUNT_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_mount_acl_record, head);
		if (acl->flags != flags ||
		    ccs_pathcmp(acl->dev_name, saved_dev) ||
		    ccs_pathcmp(acl->dir_name, saved_dir) ||
		    ccs_pathcmp(acl->fs_type, saved_fs))
			continue;
		if (is_delete)
			error = ccs_del_domain_acl(ptr);
		else
			error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->head.type = TYPE_MOUNT_ACL;
		entry->head.cond = condition;
		entry->dev_name = saved_dev;
		saved_dev = NULL;
		entry->dir_name = saved_dir;
		saved_dir = NULL;
		entry->fs_type = saved_fs;
		saved_fs = NULL;
		entry->flags = flags;
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(saved_dev);
	ccs_put_name(saved_dir);
	ccs_put_name(saved_fs);
	kfree(entry);
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
 * Caller holds ccs_read_lock().
 */
static int ccs_check_mount_permission2(struct ccs_request_info *r,
				       char *dev_name, char *dir_name,
				       char *type, unsigned long flags)
{
	const bool is_enforce = (r->mode == 3);
	int error;
	ccs_check_read_lock();
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
		struct ccs_acl_info *ptr;
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
			goto out;
		}
		requested_dir_name = ccs_realpath(dir_name);
		if (!requested_dir_name) {
			error = -ENOENT;
			goto out;
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
				goto out;
			}
			if (fstype->fs_flags & FS_REQUIRES_DEV)
				/* dev_name is a block device file. */
				need_dev = 1;
		}
		if (need_dev) {
			requested_dev_name = ccs_realpath(dev_name);
			if (!requested_dev_name) {
				error = -ENOENT;
				goto out;
			}
		} else {
			/* Map dev_name to "<NULL>" if no dev_name given. */
			if (!dev_name)
				dev_name = "<NULL>";
			requested_dev_name = ccs_encode(dev_name);
			if (!requested_dev_name) {
				error = -ENOMEM;
				goto out;
			}
		}
		rdev.name = requested_dev_name;
		ccs_fill_path_info(&rdev);
		list_for_each_entry_rcu(ptr, &r->domain->acl_info_list, list) {
			struct ccs_mount_acl_record *acl;
			if (ccs_acl_type2(ptr) != TYPE_MOUNT_ACL)
				continue;
			acl = container_of(ptr, struct ccs_mount_acl_record,
					   head);

			/* Compare options */
			if (acl->flags != flags)
				continue;

			/* Compare fs name. */
			if (strcmp(type, acl->fs_type->name))
				continue;

			/* Compare mount point. */
			if (!ccs_path_matches_pattern(&rdir, acl->dir_name))
				continue;

			/* Compare device name. */
			if (need_dev &&
			    !ccs_path_matches_pattern(&rdev, acl->dev_name))
				continue;

			if (!ccs_check_condition(r, ptr))
				continue;

			/* OK. */
			r->cond = ptr->cond;
			error = 0;
			break;
		}
		ccs_audit_mount_log(r, requested_dev_name, requested_dir_name,
				    requested_type, flags, !error);
		if (!error)
			goto out;
		if (is_enforce)
			error = ccs_check_supervisor(r, KEYWORD_ALLOW_MOUNT
						     "%s %s %s 0x%lX\n",
						     requested_dev_name,
						     requested_dir_name,
						     requested_type, flags);
		else if (ccs_domain_quota_ok(r))
			ccs_update_mount_acl(requested_dev_name,
					     requested_dir_name,
					     requested_type, flags,
					     r->domain, NULL, false);
 out:
		kfree(requested_dev_name);
		kfree(requested_dir_name);
		if (fstype)
			put_filesystem(fstype);
		kfree(requested_type);
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
	if (!ccs_capable(CCS_SYS_MOUNT))
		return -EPERM;
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_NAMESPACE);
	if (!r.mode)
		return 0;
	idx = ccs_read_lock();
	error = ccs_check_mount_permission2(&r, dev_name, dir_name, type,
					    *flags);
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_write_mount_policy - Write "struct ccs_mount_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_mount_policy(char *data, struct ccs_domain_info *domain,
			   struct ccs_condition *condition,
			   const bool is_delete)
{
	char *w[4];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[3][0])
		return -EINVAL;
	return ccs_update_mount_acl(w[0], w[1], w[2],
				    simple_strtoul(w[3], NULL, 0),
				    domain, condition, is_delete);
}
