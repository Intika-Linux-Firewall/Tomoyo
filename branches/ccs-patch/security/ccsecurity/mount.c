/*
 * security/ccsecurity/mount.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/06/04
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
#define CCS_MOUNT_BIND_KEYWORD                           "--bind"
/* Allow to call 'mount --move /old_dir    /new_dir ' */
#define CCS_MOUNT_MOVE_KEYWORD                           "--move"
/* Allow to call 'mount -o remount /dir             ' */
#define CCS_MOUNT_REMOUNT_KEYWORD                        "--remount"
/* Allow to call 'mount --make-unbindable /dir'       */
#define CCS_MOUNT_MAKE_UNBINDABLE_KEYWORD                "--make-unbindable"
/* Allow to call 'mount --make-private /dir'          */
#define CCS_MOUNT_MAKE_PRIVATE_KEYWORD                   "--make-private"
/* Allow to call 'mount --make-slave /dir'            */
#define CCS_MOUNT_MAKE_SLAVE_KEYWORD                     "--make-slave"
/* Allow to call 'mount --make-shared /dir'           */
#define CCS_MOUNT_MAKE_SHARED_KEYWORD                    "--make-shared"

/**
 * ccs_audit_mount_log - Audit mount log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_mount_log(struct ccs_request_info *r)
{
	const char *dev = r->param.mount.dev->name;
	const char *dir = r->param.mount.dir->name;
	const char *type = r->param.mount.type->name;
	const unsigned long flags = r->param.mount.flags;
	ccs_write_log(r, "file mount %s %s %s 0x%lX\n", dev, dir, type, flags);
	if (r->granted)
		return 0;
	if (!strcmp(type, CCS_MOUNT_REMOUNT_KEYWORD))
		ccs_warn_log(r, "file mount -o remount %s 0x%lX", dir, flags);
	else if (!strcmp(type, CCS_MOUNT_BIND_KEYWORD)
		 || !strcmp(type, CCS_MOUNT_MOVE_KEYWORD))
		ccs_warn_log(r, "file mount %s %s %s 0x%lX", type, dev, dir, flags);
	else if (!strcmp(type, CCS_MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
		 !strcmp(type, CCS_MOUNT_MAKE_PRIVATE_KEYWORD) ||
		 !strcmp(type, CCS_MOUNT_MAKE_SLAVE_KEYWORD) ||
		 !strcmp(type, CCS_MOUNT_MAKE_SHARED_KEYWORD))
		ccs_warn_log(r, "file mount %s %s 0x%lX", type, dir, flags);
	else
		ccs_warn_log(r, "file mount -t %s %s %s 0x%lX", type, dev, dir,
			     flags);
	return ccs_supervisor(r, "file mount %s %s %s 0x%lX\n",
			      ccs_file_pattern(r->param.mount.dev),
			      ccs_file_pattern(r->param.mount.dir), type,
			      flags);
}

static bool ccs_check_mount_acl(const struct ccs_request_info *r,
				const struct ccs_acl_info *ptr)
{
	const struct ccs_mount_acl *acl =
		container_of(ptr, typeof(*acl), head);
	return ccs_compare_number_union(r->param.mount.flags, &acl->flags) &&
		ccs_compare_name_union(r->param.mount.type, &acl->fs_type) &&
		ccs_compare_name_union(r->param.mount.dir, &acl->dir_name) &&
		(!r->param.mount.need_dev ||
		 ccs_compare_name_union(r->param.mount.dev, &acl->dev_name));
}

/**
 * ccs_mount_acl - Check permission for mount() operation.
 *
 * @r:        Pointer to "struct ccs_request_info".
 * @dev_name: Name of device file.
 * @dir:      Pointer to "struct path".
 * @type:     Name of filesystem type.
 * @flags:    Mount options.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_mount_acl(struct ccs_request_info *r, char *dev_name,
			 struct path *dir, char *type, unsigned long flags)
{
	struct ccs_obj_info obj = { };
	struct path path;
	struct file_system_type *fstype = NULL;
	const char *requested_type = NULL;
	const char *requested_dir_name = NULL;
	const char *requested_dev_name = NULL;
	struct ccs_path_info rtype;
	struct ccs_path_info rdev;
	struct ccs_path_info rdir;
	int need_dev = 0;
	int error = -ENOMEM;
	r->obj = &obj;

	/* Get fstype. */
	requested_type = ccs_encode(type);
	if (!requested_type)
		goto out;
	rtype.name = requested_type;
	ccs_fill_path_info(&rtype);

	/* Get mount point. */
	obj.path2 = *dir;
	requested_dir_name = ccs_realpath_from_path(dir);
	if (!requested_dir_name) {
		error = -ENOMEM;
		goto out;
	}
	rdir.name = requested_dir_name;
	ccs_fill_path_info(&rdir);

	/* Compare fs name. */
	if (!strcmp(type, CCS_MOUNT_REMOUNT_KEYWORD)) {
		/* dev_name is ignored. */
	} else if (!strcmp(type, CCS_MOUNT_MAKE_UNBINDABLE_KEYWORD) ||
		   !strcmp(type, CCS_MOUNT_MAKE_PRIVATE_KEYWORD) ||
		   !strcmp(type, CCS_MOUNT_MAKE_SLAVE_KEYWORD) ||
		   !strcmp(type, CCS_MOUNT_MAKE_SHARED_KEYWORD)) {
		/* dev_name is ignored. */
	} else if (!strcmp(type, CCS_MOUNT_BIND_KEYWORD) ||
		   !strcmp(type, CCS_MOUNT_MOVE_KEYWORD)) {
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
		/* Get mount point or device file. */
		if (ccs_get_path(dev_name, &path)) {
			error = -ENOENT;
			goto out;
		}
		obj.path1 = path;
		requested_dev_name = ccs_realpath_from_path(&path);
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
	r->param_type = CCS_TYPE_MOUNT_ACL;
	r->param.mount.need_dev = need_dev;
	r->param.mount.dev = &rdev;
	r->param.mount.dir = &rdir;
	r->param.mount.type = &rtype;
	r->param.mount.flags = flags;
	do {
		ccs_check_acl(r, ccs_check_mount_acl);
		error = ccs_audit_mount_log(r);
	} while (error == CCS_RETRY_REQUEST);
 out:
	kfree(requested_dev_name);
	kfree(requested_dir_name);
	if (fstype)
		ccsecurity_exports.put_filesystem(fstype);
	kfree(requested_type);
	/* Drop refcount obtained by ccs_get_path(). */
	if (obj.path1.dentry)
		path_put(&obj.path1);
	return error;
}

/**
 * ccs_mount_permission - Check permission for mount() operation.
 *
 * @dev_name:  Name of device file.
 * @path:      Pointer to "struct path".
 * @type:      Name of filesystem type. Maybe NULL.
 * @flags:     Mount options.
 * @data_page: Optional data. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_mount_permission(char *dev_name, struct path *path,
				  char *type, unsigned long flags,
				  void *data_page)
{
	struct ccs_request_info r;
	int error;
	int idx;
	if (!ccs_capable(CCS_SYS_MOUNT))
		return -EPERM;
	if (ccs_init_request_info(&r, CCS_MAC_FILE_MOUNT)
	    == CCS_CONFIG_DISABLED)
		return 0;
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;
	if (flags & MS_REMOUNT) {
		type = CCS_MOUNT_REMOUNT_KEYWORD;
		flags &= ~MS_REMOUNT;
	}
	if (flags & MS_MOVE) {
		type = CCS_MOUNT_MOVE_KEYWORD;
		flags &= ~MS_MOVE;
	}
	if (flags & MS_BIND) {
		type = CCS_MOUNT_BIND_KEYWORD;
		flags &= ~MS_BIND;
	}
	if (flags & MS_UNBINDABLE) {
		type = CCS_MOUNT_MAKE_UNBINDABLE_KEYWORD;
		flags &= ~MS_UNBINDABLE;
	}
	if (flags & MS_PRIVATE) {
		type = CCS_MOUNT_MAKE_PRIVATE_KEYWORD;
		flags &= ~MS_PRIVATE;
	}
	if (flags & MS_SLAVE) {
		type = CCS_MOUNT_MAKE_SLAVE_KEYWORD;
		flags &= ~MS_SLAVE;
	}
	if (flags & MS_SHARED) {
		type = CCS_MOUNT_MAKE_SHARED_KEYWORD;
		flags &= ~MS_SHARED;
	}
	if (!type)
		type = "<NULL>";
	idx = ccs_read_lock();
	error = ccs_mount_acl(&r, dev_name, path, type, flags);
	ccs_read_unlock(idx);
	return error;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
static int ccs_old_mount_permission(char *dev_name, struct nameidata *nd,
				    char *type, unsigned long flags,
				    void *data_page)
{
	struct path path = { nd->mnt, nd->dentry };
	return __ccs_mount_permission(dev_name, &path, type, flags, data_page);
}
#endif

void __init ccs_mount_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	ccsecurity_ops.mount_permission = __ccs_mount_permission;
#else
	ccsecurity_ops.mount_permission = ccs_old_mount_permission;
#endif
}
