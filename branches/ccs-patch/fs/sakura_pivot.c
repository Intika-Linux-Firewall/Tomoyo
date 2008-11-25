/*
 * fs/sakura_pivot.c
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#else
#include <linux/fs.h>
#endif

/**
 * update_pivot_root_acl - Update "struct pivot_root_entry" list.
 *
 * @old_root:  The name of old root directory.
 * @new_root:  The name of new root directory.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_pivot_root_acl(const char *old_root, const char *new_root,
				 struct domain_info *domain,
				 const struct condition_list *condition,
				 const bool is_delete)
{
	struct acl_info *ptr;
	struct pivot_root_entry *acl;
	const struct path_info *saved_old_root;
	const struct path_info *saved_new_root;
	static DEFINE_MUTEX(lock);
	int error = -ENOMEM;
	if (!ccs_is_correct_path(old_root, 1, 0, 1, __func__) ||
	    !ccs_is_correct_path(new_root, 1, 0, 1, __func__))
		return -EINVAL;
	saved_old_root = ccs_save_name(old_root);
	saved_new_root = ccs_save_name(new_root);
	if (!saved_old_root || !saved_new_root)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != TYPE_PIVOT_ROOT_ACL)
                        continue;
                if (ccs_get_condition_part(ptr) != condition)
                        continue;
                acl = container_of(ptr, struct pivot_root_entry, head);
		if (acl->old_root != saved_old_root ||
		    acl->new_root != saved_new_root)
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
	acl = ccs_alloc_acl_element(TYPE_PIVOT_ROOT_ACL, condition);
	if (!acl)
		goto out;
	acl->old_root = saved_old_root;
	acl->new_root = saved_new_root;
	error = ccs_add_domain_acl(domain, &acl->head);
	printk(KERN_CONT "%sAllow pivot_root(%s, %s)\n", ccs_log_level,
	       new_root, old_root);
 out:
	mutex_unlock(&lock);
	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#define PATH_or_NAMEIDATA path
#else
#define PATH_or_NAMEIDATA nameidata
#endif
/**
 * ccs_check_pivot_root_permission - Check permission for pivot_root().
 *
 * @old_path: Pointer to "struct path" (for 2.6.27 and later).
 *            Pointer to "struct nameidata" (for 2.6.26 and earlier).
 * @new_path: Pointer to "struct path" (for 2.6.27 and later).
 *            Pointer to "struct nameidata" (for 2.6.26 and earlier).
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_pivot_root_permission(struct PATH_or_NAMEIDATA *old_path,
				    struct PATH_or_NAMEIDATA *new_path)
{
	struct ccs_request_info r;
	int error;
	char *old_root;
	char *new_root;
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_SAKURA_RESTRICT_PIVOT_ROOT);
	if (!r.mode)
		return 0;
 retry:
	error = -EPERM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
	old_root = ccs_realpath_from_dentry(old_path->path.dentry,
					    old_path->path.mnt);
	new_root = ccs_realpath_from_dentry(new_path->path.dentry,
					    new_path->path.mnt);
#else
	old_root = ccs_realpath_from_dentry(old_path->dentry, old_path->mnt);
	new_root = ccs_realpath_from_dentry(new_path->dentry, new_path->mnt);
#endif
	if (old_root && new_root) {
		struct path_info old_root_dir;
		struct path_info new_root_dir;
		old_root_dir.name = old_root;
		ccs_fill_path_info(&old_root_dir);
		new_root_dir.name = new_root;
		ccs_fill_path_info(&new_root_dir);
		if (old_root_dir.is_dir && new_root_dir.is_dir) {
			struct acl_info *ptr;
			list1_for_each_entry(ptr, &r.domain->acl_info_list,
					     list) {
				struct pivot_root_entry *acl;
				if (ccs_acl_type2(ptr) != TYPE_PIVOT_ROOT_ACL)
					continue;
				acl = container_of(ptr, struct pivot_root_entry,
						   head);
				if (!ccs_path_matches_pattern(&old_root_dir,
							      acl->old_root) ||
				    !ccs_path_matches_pattern(&new_root_dir,
							      acl->new_root) ||
				    !ccs_check_condition(&r, ptr))
					continue;
				error = 0;
				break;
			}
		}
	}
	if (error) {
		const bool is_enforce = (r.mode == 3);
		const char *exename = ccs_get_exe();
		printk(KERN_WARNING "SAKURA-%s: pivot_root %s %s "
		       "(pid=%d:exe=%s): Permission denied.\n",
		       ccs_get_msg(is_enforce), new_root, old_root,
		       (pid_t) sys_getpid(), exename);
		if (is_enforce)
			error = ccs_check_supervisor(&r, "# %s is requesting\n"
						     "pivot_root %s %s\n",
						     exename, new_root,
						     old_root);
		else
			error = 0;
		if (exename)
			ccs_free(exename);
		if (r.mode == 1 && old_root && new_root)
			update_pivot_root_acl(old_root, new_root, r.domain,
					      ccs_handler_cond(), false);
	}
	ccs_free(old_root);
	ccs_free(new_root);
	if (error == 1)
		goto retry;
	return error;
}

/**
 * ccs_write_pivot_root_policy - Write "struct pivot_root_entry" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL. 
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_pivot_root_policy(char *data, struct domain_info *domain,
				const struct condition_list *condition,
				const bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return update_pivot_root_acl(cp, data, domain, condition, is_delete);
}
