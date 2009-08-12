/*
 * security/ccsecurity/pivot_root.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/dcache.h>
#include <linux/namei.h>
#else
#include <linux/fs.h>
#endif
#include "internal.h"

/**
 * ccs_audit_pivot_root_log - Audit pivot_root log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @new_root:   New root directory.
 * @old_root:   Old root directory.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_pivot_root_log(struct ccs_request_info *r,
				    const char *new_root,
				    const char *old_root,
				    const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "SAKURA-%s: pivot_root %s %s "
		       "denied for %s\n", ccs_get_msg(r->mode == 3), new_root,
		       old_root, ccs_get_last_name(r->domain));
	return ccs_write_audit_log(is_granted, r, CCS_KEYWORD_ALLOW_PIVOT_ROOT
				   "%s %s\n", new_root, old_root);
}

/**
 * ccs_update_pivot_root_acl - Update "struct ccs_pivot_root_acl_record" list.
 *
 * @old_root:  The name of old root directory.
 * @new_root:  The name of new root directory.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_pivot_root_acl(char *old_root, char *new_root,
				     struct ccs_domain_info *domain,
				     struct ccs_condition *condition,
				     const bool is_delete)
{
	struct ccs_pivot_root_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
	struct ccs_pivot_root_acl_record e;
	int error = is_delete ? -ENOENT : -ENOMEM;
	memset(&e, 0, sizeof(e));
	e.head.type = CCS_TYPE_PIVOT_ROOT_ACL;
	e.head.cond = condition;
	if (!ccs_parse_name_union(old_root, &e.old_root) ||
	    !ccs_parse_name_union(new_root, &e.new_root))
		goto out;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_pivot_root_acl_record *acl;
		if (ccs_acl_type1(ptr) != CCS_TYPE_PIVOT_ROOT_ACL)
			continue;
		acl = container_of(ptr, struct ccs_pivot_root_acl_record, head);
		if (ccs_memcmp(acl, &e,
			       offsetof(struct ccs_pivot_root_acl_record,
					head.cond), sizeof(e)))
			continue;
		if (is_delete)
			error = ccs_del_domain_acl(ptr);
		else
			error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry, sizeof(*entry))) {
		memmove(entry, &e, sizeof(e));
		memset(&e, 0, sizeof(e));
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.old_root);
	ccs_put_name_union(&e.new_root);
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
 * Caller holds ccs_read_lock().
 */
static int ccs_check_pivot_root_permission2(struct PATH_or_NAMEIDATA *old_path,
					    struct PATH_or_NAMEIDATA *new_path)
{
	struct ccs_request_info r;
	int error;
	char *old_root;
	char *new_root;
	struct ccs_path_info old_root_dir;
	struct ccs_path_info new_root_dir;
	bool is_enforce;
	ccs_check_read_lock();
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_NAMESPACE);
	is_enforce = (r.mode == 3);
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
	if (!old_root || !new_root)
		goto out;
	old_root_dir.name = old_root;
	ccs_fill_path_info(&old_root_dir);
	new_root_dir.name = new_root;
	ccs_fill_path_info(&new_root_dir);
	if (old_root_dir.is_dir && new_root_dir.is_dir) {
		struct ccs_acl_info *ptr;
		list_for_each_entry_rcu(ptr, &r.domain->acl_info_list, list) {
			struct ccs_pivot_root_acl_record *acl;
			if (ccs_acl_type2(ptr) != CCS_TYPE_PIVOT_ROOT_ACL)
				continue;
			acl = container_of(ptr,
					   struct ccs_pivot_root_acl_record,
					   head);
			if (!ccs_compare_name_union(&old_root_dir,
						    &acl->old_root) ||
			    !ccs_compare_name_union(&new_root_dir,
						    &acl->new_root) ||
			    !ccs_check_condition(&r, ptr))
				continue;
			r.cond = ptr->cond;
			error = 0;
			break;
		}
	}
	ccs_audit_pivot_root_log(&r, new_root, old_root, !error);
	if (error)
		error = ccs_check_supervisor(&r, CCS_KEYWORD_ALLOW_PIVOT_ROOT
					     "%s %s\n",
					     ccs_file_pattern(&new_root_dir),
					     ccs_file_pattern(&old_root_dir));
 out:
	kfree(old_root);
	kfree(new_root);
	if (error == 1)
		goto retry;
	if (!is_enforce)
		error = 0;
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
	const int idx = ccs_read_lock();
	const int error = ccs_check_pivot_root_permission2(old_path, new_path);
	ccs_read_unlock(idx);
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
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	return ccs_update_pivot_root_acl(w[1], w[0], domain, condition,
					 is_delete);
}
