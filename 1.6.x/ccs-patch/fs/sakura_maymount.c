/*
 * fs/sakura_maymount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/05/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#else
#include <linux/namespace.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
#include <linux/nsproxy.h>
#endif

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
 * ccs_print_error - Print error message.
 *
 * @r:    Pointer to "struct ccs_request_info".
 * @path: Pointer to "struct path" (for 2.6.27 and later).
 *        Pointer to "struct nameidata" (for 2.6.26 and earlier).
 *
 * Returns 0 if @r->mode is not enforcing or permitted by the administrator's
 * decision, negative value otherwise.
 */
static int ccs_print_error(struct ccs_request_info *r,
			   struct PATH_or_NAMEIDATA *path)
{
	int error;
	const bool is_enforce = (r->mode == 3);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
	const char *dir = ccs_realpath_from_dentry(path->path.dentry,
						   path->path.mnt);
#else
	const char *dir = ccs_realpath_from_dentry(path->dentry, path->mnt);
#endif
	const char *exename = ccs_get_exe();
	printk(KERN_WARNING "SAKURA-%s: mount %s (pid=%d:exe=%s): "
	       "Permission denied.\n", ccs_get_msg(is_enforce), dir,
	       (pid_t) sys_getpid(), exename);
	if (is_enforce)
		error = ccs_check_supervisor(r, "# %s is requesting\n"
					     "mount on %s\n", exename, dir);
	else
		error = 0;
	ccs_free(exename);
	ccs_free(dir);
	return error;
}

/**
 * ccs_may_mount - Check whether this mount request shadows existing mounts.
 *
 * @path: Pointer to "struct nameidata" or "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_may_mount(struct PATH_or_NAMEIDATA *path)
{
	struct ccs_request_info r;
	struct list_head *p;
	bool flag = false;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	struct namespace *namespace = current->namespace;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct namespace *namespace = current->nsproxy->namespace;
#else
	struct mnt_namespace *namespace = current->nsproxy->mnt_ns;
#endif
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_DENY_CONCEAL_MOUNT);
	if (!r.mode)
		return 0;
	if (!namespace)
		return 0;
 retry:
	list_for_each(p, &namespace->list) {
		struct vfsmount *vfsmnt = list_entry(p, struct vfsmount,
						     mnt_list);
		struct dentry *dentry = vfsmnt->mnt_root;
		/***** CRITICAL SECTION START *****/
		ccs_realpath_lock();
		if (IS_ROOT(dentry) || !d_unhashed(dentry))
			flag = ccs_check_conceal_mount(path, vfsmnt, dentry);
		ccs_realpath_unlock();
		/***** CRITICAL SECTION END *****/
		if (flag)
			break;
	}
	if (flag) {
		int error = ccs_print_error(&r, path);
		if (error == 1)
			goto retry;
		return error;
	}
	return 0;
}
