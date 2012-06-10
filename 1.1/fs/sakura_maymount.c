/*
 * fs/sakura_maymount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.1   2006/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** SAKURA Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/sakura.h>
#include <linux/realpath.h>
#include <linux/namespace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <linux/namei.h>
#endif

/*************************  CONCEAL MOUNT PROTECTOR  *************************/

int SAKURA_MayMount(struct nameidata *nd)
{
	int flag = 0;
	struct namespace *namespace = current->namespace;
	if (!CheckCCSFlags(CCS_SAKURA_DENY_CONCEAL_MOUNT)) return 0;
	if (namespace) {
		struct list_head *p;
		list_for_each(p, &namespace->list) {
			struct vfsmount *vfsmnt = list_entry(p, struct vfsmount, mnt_list);
			struct dentry *dentry = vfsmnt->mnt_root;
			spin_lock(&dcache_lock);
			if (IS_ROOT(dentry) || !d_unhashed(dentry)) {
				while (1) {
					if (nd->mnt->mnt_root == vfsmnt->mnt_root && nd->dentry == dentry) {
						flag = 1;
						break;
					}
					if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
						if (vfsmnt->mnt_parent == vfsmnt) break;
						dentry = vfsmnt->mnt_mountpoint;
						vfsmnt = vfsmnt->mnt_parent;
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
		const int is_enforce = CheckCCSEnforce(CCS_SAKURA_DENY_CONCEAL_MOUNT);
		char *page = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (page) {
			memset(page, 0, PAGE_SIZE);
			if (realpath_from_dentry(nd->dentry, nd->mnt, page, PAGE_SIZE - 1) == 0) printk("SAKURA-%s: mount %s : Permission denied.\n", GetMSG(is_enforce), page);
			kfree(page);
		}
		if (is_enforce) return -EPERM;
	}
	return 0;
}

EXPORT_SYMBOL(SAKURA_MayMount);

/***** SAKURA Linux end. *****/
