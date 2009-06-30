/*
 * fs/sakura_pivot.c
 *
 * Implementation of the Domain-Free Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/05/28
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
 * ccs_update_pivot_root_acl - Update "struct ccs_pivot_root_acl_record" list.
 *
 * @old_root:  The name of old root directory.
 * @new_root:  The name of new root directory.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_pivot_root_acl(const char *old_root, const char *new_root,
				     struct ccs_domain_info *domain,
				     struct ccs_condition *condition,
				     const bool is_delete)
{
	struct ccs_pivot_root_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
	const struct ccs_path_info *saved_old_root;
	const struct ccs_path_info *saved_new_root;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(old_root, 1, 0, 1) ||
	    !ccs_is_correct_path(new_root, 1, 0, 1))
		return -EINVAL;
	saved_old_root = ccs_get_name(old_root);
	saved_new_root = ccs_get_name(new_root);
	if (!saved_old_root || !saved_new_root)
		goto out;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_pivot_root_acl_record *acl;
		if (ccs_acl_type1(ptr) != TYPE_PIVOT_ROOT_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_pivot_root_acl_record, head);
		if (acl->old_root != saved_old_root ||
                    acl->new_root != saved_new_root)
                        continue;
		if (is_delete)
			error = ccs_del_domain_acl(ptr);
		else
			error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry)) {
		entry->head.type = TYPE_PIVOT_ROOT_ACL;
		entry->head.cond = condition;
		entry->old_root = saved_old_root;
		saved_old_root = NULL;
		entry->new_root = saved_new_root;
		saved_new_root = NULL;
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name(saved_old_root);
	ccs_put_name(saved_new_root);
	kfree(entry);
	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#define PATH_or_NAMEIDATA path
#else
#define PATH_or_NAMEIDATA nameidata
#endif
/**
 * ccs_check_pivot_root_permission2 - Check permission for pivot_root().
 *
 * @old_path: Pointer to "struct path" (for 2.6.27 and later).
 *            Pointer to "struct nameidata" (for 2.6.26 and earlier).
 * @new_path: Pointer to "struct path" (for 2.6.27 and later).
 *            Pointer to "struct nameidata" (for 2.6.26 and earlier).
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds srcu_read_lock(&ccs_ss).
 */
static int ccs_check_pivot_root_permission2(struct PATH_or_NAMEIDATA *old_path,
					    struct PATH_or_NAMEIDATA *new_path)
{
	struct ccs_request_info r;
	int error;
	char *old_root;
	char *new_root;
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_RESTRICT_PIVOT_ROOT);
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
		struct ccs_path_info old_root_dir;
		struct ccs_path_info new_root_dir;
		old_root_dir.name = old_root;
		ccs_fill_path_info(&old_root_dir);
		new_root_dir.name = new_root;
		ccs_fill_path_info(&new_root_dir);
		if (old_root_dir.is_dir && new_root_dir.is_dir) {
			struct ccs_acl_info *ptr;
			list_for_each_entry_rcu(ptr, &r.domain->acl_info_list,
						list) {
				struct ccs_pivot_root_acl_record *acl;
				if (ccs_acl_type2(ptr) != TYPE_PIVOT_ROOT_ACL)
					continue;
				acl = container_of(ptr,
					   struct ccs_pivot_root_acl_record,
						   head);
				if (!ccs_path_matches_pattern(&old_root_dir,
							      acl->old_root) ||
				    !ccs_path_matches_pattern(&new_root_dir,
							      acl->new_root))
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
			ccs_update_pivot_root_acl(old_root, new_root, r.domain,
						  NULL, false);
	}
	ccs_free(old_root);
	ccs_free(new_root);
	if (error == 1)
		goto retry;
	return error;
}

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
	const int idx = srcu_read_lock(&ccs_ss);
	const int error = ccs_check_pivot_root_permission2(old_path, new_path);
	srcu_read_unlock(&ccs_ss, idx);
	return error;
}

/**
 * ccs_write_pivot_root_policy - Write "struct ccs_pivot_root_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_pivot_root_policy(char *data, struct ccs_domain_info *domain,
				struct ccs_condition *condition,
				const bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return ccs_update_pivot_root_acl(cp, data, domain, condition,
					 is_delete);
}

#if 0
/**
 * ccs_read_pivot_root_policy - Read "struct ccs_pivot_root_acl_record" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds srcu_read_lock(&ccs_ss).
 */
static bool ccs_read_pivot_root_policy(struct ccs_io_buffer *head)
{
	struct list_head *pos;
	list_for_each_cookie(pos, head->read_var2, &ccs_pivot_root_list) {
		struct ccs_pivot_root_acl_record *ptr;
		ptr = list_entry(pos, struct ccs_pivot_root_acl_record, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, KEYWORD_ALLOW_PIVOT_ROOT "%s %s\n",
				   ptr->new_root->name, ptr->old_root->name))
			return false;
	}
	return true;
}
#endif
