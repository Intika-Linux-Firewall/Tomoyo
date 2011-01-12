/*
 * fs/sakura_maymount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.5.4   2008/05/10
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

/*************************  CONCEAL MOUNT PROTECTOR  *************************/

int SAKURA_MayMount(struct nameidata *nd)
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
			spin_lock(&dcache_lock);
			if (IS_ROOT(dentry) || !d_unhashed(dentry)) {
				while (1) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
					if (nd->path.mnt->mnt_root == vfsmnt->mnt_root && nd->path.dentry == dentry) {
						flag = 1;
						break;
					}
#else
					if (nd->mnt->mnt_root == vfsmnt->mnt_root && nd->dentry == dentry) {
						flag = 1;
						break;
					}
#endif
					if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
						spin_lock(&vfsmount_lock);
#endif
						if (vfsmnt->mnt_parent == vfsmnt) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
							spin_unlock(&vfsmount_lock);
#endif
							break;
						}
						dentry = vfsmnt->mnt_mountpoint;
						vfsmnt = vfsmnt->mnt_parent;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
						spin_unlock(&vfsmount_lock);
#endif
						continue;
					}
					dentry = dentry->d_parent;
				}
			}
			spin_unlock(&dcache_lock);
			if (flag) break;
		}
	}
	if (flag) {
		int error = -EPERM;
		const int is_enforce = CheckCCSEnforce(CCS_SAKURA_DENY_CONCEAL_MOUNT);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		const char *dir = realpath_from_dentry(nd->path.dentry, nd->path.mnt);
#else
		const char *dir = realpath_from_dentry(nd->dentry, nd->mnt);
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