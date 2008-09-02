/*
 * fs/sakura_maymount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.4   2008/09/03
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#define PATH_or_NAMEIDATA path
#else
#define PATH_or_NAMEIDATA nameidata
#endif

/**
 * check_conceal_mount - Check whether this mount request shadows existing mounts.
 *
 * @path:   Pointer to "struct path" (for 2.6.27 and later).
 *          Pointer to "struct nameidata" (for 2.6.26 and earlier).
 * @vfsmnt: Pointer to "struct vfsmount".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns true if @vfsmnt is parent directory compared to @nd, false otherwise.
 */
static bool check_conceal_mount(struct PATH_or_NAMEIDATA *path,
				struct vfsmount *vfsmnt, struct dentry *dentry)
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
 * print_error - Print error message.
 *
 * @path: Pointer to "struct path" (for 2.6.27 and later).
 *        Pointer to "struct nameidata" (for 2.6.26 and earlier).
 * @mode: Access control mode.
 *
 * Returns 0 if @mode is not enforcing or permitted by the administrator's
 * decision, negative value otherwise.
 */
static int print_error(struct PATH_or_NAMEIDATA *path, const u8 mode)
{
	int error;
	const bool is_enforce = (mode == 3);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
	const char *dir = ccs_realpath_from_dentry(path->path.dentry,
						   path->path.mnt);
#else
	const char *dir = ccs_realpath_from_dentry(path->dentry, path->mnt);
#endif
	const char *exename = ccs_get_exe();
	printk(KERN_WARNING "SAKURA-%s: mount %s (pid=%d:exe=%s): "
	       "Permission denied.\n", ccs_get_msg(is_enforce), dir,
	       current->pid, exename);
	if (is_enforce)
		error = ccs_check_supervisor(NULL,
					     "# %s is requesting\n"
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
 * @nd: Pointer to "struct nameidata".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_may_mount(struct PATH_or_NAMEIDATA *path)
{
	struct list_head *p;
	bool flag = false;
	const u8 mode = ccs_check_flags(CCS_SAKURA_DENY_CONCEAL_MOUNT);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	struct namespace *namespace = current->namespace;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct namespace *namespace = current->nsproxy->namespace;
#else
	struct mnt_namespace *namespace = current->nsproxy->mnt_ns;
#endif
	if (!mode)
		return 0;
	if (!namespace)
		return 0;
	list_for_each(p, &namespace->list) {
		struct vfsmount *vfsmnt = list_entry(p, struct vfsmount,
						     mnt_list);
		struct dentry *dentry = vfsmnt->mnt_root;
		/***** CRITICAL SECTION START *****/
		ccs_realpath_lock();
		if (IS_ROOT(dentry) || !d_unhashed(dentry))
			flag = check_conceal_mount(path, vfsmnt, dentry);
		ccs_realpath_unlock();
		/***** CRITICAL SECTION END *****/
		if (flag)
			break;
	}
	if (flag)
		return print_error(path, mode);
	return 0;
}
