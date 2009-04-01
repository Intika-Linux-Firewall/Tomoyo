/*
 * fs/sakura_maymount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.5.5   2008/09/03
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

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

/*************************  CONCEAL MOUNT PROTECTOR  *************************/

int SAKURA_MayMount(struct PATH_or_NAMEIDATA *path)
{
	int flag = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	struct namespace *namespace = current->namespace;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct namespace *namespace = current->nsproxy->namespace;
#else
	struct mnt_namespace *namespace = current->nsproxy->mnt_ns;
#endif
	if (!CheckCCSFlags(CCS_SAKURA_DENY_CONCEAL_MOUNT)) return 0;
	if (namespace) {
		struct list_head *p;
		list_for_each(p, &namespace->list) {
			struct vfsmount *vfsmnt = list_entry(p, struct vfsmount, mnt_list);
			struct dentry *dentry = vfsmnt->mnt_root;
			ccs_realpath_lock();
			if (IS_ROOT(dentry) || !d_unhashed(dentry)) {
				while (1) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
					if (path->path.mnt->mnt_root == vfsmnt->mnt_root && path->path.dentry == dentry) {
						flag = 1;
						break;
					}
#else
					if (path->mnt->mnt_root == vfsmnt->mnt_root && path->dentry == dentry) {
						flag = 1;
						break;
					}
#endif
					if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
						if (vfsmnt->mnt_parent == vfsmnt) {
							break;
						}
						dentry = vfsmnt->mnt_mountpoint;
						vfsmnt = vfsmnt->mnt_parent;
						continue;
					}
					dentry = dentry->d_parent;
				}
			}
			ccs_realpath_unlock();
			if (flag) break;
		}
	}
	if (flag) {
		int error = -EPERM;
		const int is_enforce = CheckCCSEnforce(CCS_SAKURA_DENY_CONCEAL_MOUNT);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
		const char *dir = realpath_from_dentry(path->path.dentry, path->path.mnt);
#else
		const char *dir = realpath_from_dentry(path->dentry, path->mnt);
#endif
		if (dir) {
			const char *exename = GetEXE();
			printk("SAKURA-%s: mount %s (pid=%d:exe=%s): Permission denied.\n", GetMSG(is_enforce), dir, current->pid, exename);
			if (is_enforce && CheckSupervisor("# %s is requesting\nmount on %s\n", exename, dir) == 0) error = 0;
			ccs_free(exename);
		}
		ccs_free(dir);
		if (is_enforce) return error;
	}
	return 0;
}

/***** SAKURA Linux end. *****/
