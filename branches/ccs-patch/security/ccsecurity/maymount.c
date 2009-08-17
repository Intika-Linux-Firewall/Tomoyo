/*
 * security/ccsecurity/maymount.c
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#else
#include <linux/namespace.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/dcache.h>
#include <linux/namei.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
#include <linux/nsproxy.h>
#endif
#include "internal.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#define PATH_or_NAMEIDATA path
#else
#define PATH_or_NAMEIDATA nameidata
#endif

/**
 * ccs_check_conceal_mount - Check whether this mount request shadows existing mounts.
 *
 * @path:   Pointer to "struct path" (for 2.6.27 and later).
 *          Pointer to "struct nameidata" (for 2.6.26 and earlier).
 * @vfsmnt: Pointer to "struct vfsmount".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns true if @vfsmnt is parent directory compared to @nd, false otherwise.
 */
static bool ccs_check_conceal_mount(struct PATH_or_NAMEIDATA *path,
				    struct vfsmount *vfsmnt,
				    struct dentry *dentry)
{
	/***** CRITICAL SECTION START *****/
	while (1) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
		if (path->path.mnt->mnt_root == vfsmnt->mnt_root &&
		    path->path.dentry == dentry)
			return true;
#else
		if (path->mnt->mnt_root == vfsmnt->mnt_root &&
		    path->dentry == dentry)
			return true;
#endif
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			if (vfsmnt->mnt_parent == vfsmnt)
				break;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		dentry = dentry->d_parent;
	}
	return false;
	/***** CRITICAL SECTION END *****/
}

/**
 * ccs_may_mount - Check whether this mount request shadows existing mounts.
 *
 * @nd: Pointer to "struct nameidata".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_may_mount(struct PATH_or_NAMEIDATA *path)
{
	struct ccs_request_info r;
	struct list_head *p;
	bool found = false;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	struct namespace *namespace = current->namespace;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct namespace *namespace = current->nsproxy->namespace;
#else
	struct mnt_namespace *namespace = current->nsproxy->mnt_ns;
#endif
	if (!namespace || !ccs_can_sleep() ||
	    !ccs_init_request_info(&r, NULL,
				   CCS_MAX_MAC_INDEX + CCS_CONCEAL_MOUNT))
		return 0;
	found = false;
	list_for_each(p, &namespace->list) {
		struct vfsmount *vfsmnt = list_entry(p, struct vfsmount,
						     mnt_list);
		struct dentry *dentry = vfsmnt->mnt_root;
		/***** CRITICAL SECTION START *****/
		ccs_realpath_lock();
		if (IS_ROOT(dentry) || !d_unhashed(dentry))
			found = ccs_check_conceal_mount(path, vfsmnt, dentry);
		ccs_realpath_unlock();
		/***** CRITICAL SECTION END *****/
		if (found)
			break;
	}
	if (!found)
		return 0;
	return ccs_capable(CCS_CONCEAL_MOUNT) ? 0 : -EPERM;
}
