/*
 * fs/sakura_umount.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.5   2008/11/11
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
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namespace.h>
#endif

/**
 * update_no_umount_acl - Update "struct no_umount_entry" list.
 *
 * @dir:       The name of directrory.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL. 
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_no_umount_acl(const char *dir, struct domain_info *domain,
				const struct condition_list *condition,
				const bool is_delete)
{
	struct acl_info *ptr;
	struct no_umount_entry *acl;
	const struct path_info *saved_dir;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if (!ccs_is_correct_path(dir, 1, 0, 1, __func__))
		return -EINVAL;
	saved_dir = ccs_save_name(dir);
	if (!saved_dir)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
                if (ccs_acl_type1(ptr) != TYPE_NO_UMOUNT_ACL)
                        continue;
                if (ccs_get_condition_part(ptr) != condition)
                        continue;
		acl = container_of(ptr, struct no_umount_entry, head);
		if (acl->dir != saved_dir)
			continue;
		if (is_delete)
			ptr->type |= ACL_DELETED;
		else
			ptr->type &= ~ACL_DELETED;
		error = 0;
		goto out;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	acl = ccs_alloc_acl_element(TYPE_NO_UMOUNT_ACL, condition);
	if (!acl)
		goto out;
	acl->dir = saved_dir;
	error = ccs_add_domain_acl(domain, &acl->head);
	printk(KERN_CONT "%sDon't allow umount %s\n", ccs_log_level, dir);
 out:
	mutex_unlock(&lock);
	return error;
}

/**
 * ccs_may_umount - Check permission for unmount.
 *
 * @mnt: Pointer to "struct vfsmount".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_may_umount(struct vfsmount *mnt)
{
	struct ccs_request_info r;
	int error;
	const char *dir0;
	bool is_enforce;
	struct acl_info *ptr;
	struct path_info dir;
	bool found = false;
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_SAKURA_RESTRICT_UNMOUNT);
	is_enforce = (r.mode == 3);
	if (!r.mode)
		return 0;
 retry:
	error = -EPERM;
	dir0 = ccs_realpath_from_dentry(mnt->mnt_root, mnt);
	if (!dir0)
		goto out;
	dir.name = dir0;
	ccs_fill_path_info(&dir);
	list1_for_each_entry(ptr, &r.domain->acl_info_list, list) {
		struct no_umount_entry *acl;
		if (ccs_acl_type2(ptr) != TYPE_NO_UMOUNT_ACL)
                        continue;
		acl = container_of(ptr, struct no_umount_entry, head);
		if (!ccs_path_matches_pattern(&dir, acl->dir) ||
		    !ccs_check_condition(&r, ptr))
			continue;
		found = true;
		break;
	}
	if (found) {
		const char *exename = ccs_get_exe();
		printk(KERN_WARNING "SAKURA-%s: umount %s "
		       "(pid=%d:exe=%s): Permission denied.\n",
		       ccs_get_msg(is_enforce), dir0, (pid_t) sys_getpid(),
		       exename);
		if (is_enforce)
			error = ccs_check_supervisor(&r, "# %s is requesting\n"
						     "unmount %s\n",
						     exename, dir0);
		ccs_free(exename);
	} else
		error = 0;
	ccs_free(dir0);
 out:
	if (!is_enforce)
		error = 0;
	if (error == 1)
		goto retry;
	return error;
}

/**
 * ccs_write_no_umount_policy - Write "struct no_umount_entry" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL. 
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on sucess, negative value otherwise.
 */
int ccs_write_no_umount_policy(char *data, struct domain_info *domain,
			       const struct condition_list *condition,
			       const bool is_delete)
{
	return update_no_umount_acl(data, domain, condition, is_delete);
}
