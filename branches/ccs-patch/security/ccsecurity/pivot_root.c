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
				    const char *new_root, const char *old_root,
				    const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "%s: pivot_root %s %s "
		       "denied for %s\n", ccs_get_msg(r->mode == 3), new_root,
		       old_root, ccs_get_last_name(r->domain));
	return ccs_write_audit_log(is_granted, r, CCS_KEYWORD_ALLOW_PIVOT_ROOT
				   "%s %s\n", new_root, old_root);
}

/**
 * ccs_pivot_root_acl - Check permission for pivot_root().
 *
 * @old: Pointer to "struct path".
 * @new: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_pivot_root_acl(struct path *old, struct path *new)
{
	struct ccs_request_info r;
	struct ccs_obj_info obj = {
		.path1 = *new,
		.path2 = *old
	};
	int error;
	char *old_root;
	char *new_root;
	struct ccs_path_info old_root_dir;
	struct ccs_path_info new_root_dir;
	bool is_enforce;
	ccs_assert_read_lock();
	if (!ccs_can_sleep() ||
	    !ccs_init_request_info(&r, NULL, CCS_MAC_PIVOT_ROOT))
		return 0;
	is_enforce = (r.mode == 3);
	r.obj = &obj;
 retry:
	error = -EPERM;
	old_root = ccs_realpath_from_path(old);
	new_root = ccs_realpath_from_path(new);
	if (!old_root || !new_root)
		goto out;
	old_root_dir.name = old_root;
	ccs_fill_path_info(&old_root_dir);
	new_root_dir.name = new_root;
	ccs_fill_path_info(&new_root_dir);
	if (old_root_dir.is_dir && new_root_dir.is_dir) {
		struct ccs_acl_info *ptr;
		list_for_each_entry_rcu(ptr, &r.domain->acl_info_list, list) {
			struct ccs_pivot_root_acl *acl;
			if (ptr->is_deleted ||
			    ptr->type != CCS_TYPE_PIVOT_ROOT_ACL)
				continue;
			acl = container_of(ptr,
					   struct ccs_pivot_root_acl,
					   head);
			if (!ccs_compare_name_union(&old_root_dir,
						    &acl->old_root) ||
			    !ccs_compare_name_union(&new_root_dir,
						    &acl->new_root) ||
			    !ccs_condition(&r, ptr))
				continue;
			r.cond = ptr->cond;
			error = 0;
			break;
		}
	}
	ccs_audit_pivot_root_log(&r, new_root, old_root, !error);
	if (error)
		error = ccs_supervisor(&r, CCS_KEYWORD_ALLOW_PIVOT_ROOT
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#define PATH_or_NAMEIDATA path
#else
#define PATH_or_NAMEIDATA nameidata
#endif

/**
 * ccs_pivot_root_permission - Check permission for pivot_root().
 *
 * @old_path: Pointer to "struct path" (for 2.6.27 and later).
 *            Pointer to "struct nameidata" (for 2.6.26 and earlier).
 * @new_path: Pointer to "struct path" (for 2.6.27 and later).
 *            Pointer to "struct nameidata" (for 2.6.26 and earlier).
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_pivot_root_permission(struct PATH_or_NAMEIDATA *old_path,
				    struct PATH_or_NAMEIDATA *new_path)
{
#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 25) || LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 26)
	struct path old = { old_path->path.mnt, old_path->path.dentry };
	struct path new = { new_path->path.mnt, new_path->path.dentry };
#else
	struct path old = { old_path->mnt, old_path->dentry };
	struct path new = { new_path->mnt, new_path->dentry };
#endif
	const int idx = ccs_read_lock();
	const int error = ccs_pivot_root_acl(&old, &new);
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_write_pivot_root_policy - Write "struct ccs_pivot_root_acl" list.
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
	struct ccs_pivot_root_acl *entry = NULL;
	struct ccs_acl_info *ptr;
	struct ccs_pivot_root_acl e = {
		.head.type = CCS_TYPE_PIVOT_ROOT_ACL,
		.head.cond = condition
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0] ||
	    (w[0][0] != '@' && !ccs_is_correct_path(w[0], 1, 0, 1)) ||
	    (w[1][0] != '@' && !ccs_is_correct_path(w[1], 1, 0, 1)))
		return -EINVAL;
	if (!ccs_parse_name_union(w[1], &e.old_root) ||
	    !ccs_parse_name_union(w[0], &e.new_root))
		goto out;
	if (!is_delete)
		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_pivot_root_acl *acl =
			container_of(ptr, struct ccs_pivot_root_acl, head);
		if (ptr->type != CCS_TYPE_PIVOT_ROOT_ACL ||
		    ptr->cond != condition ||
		    ccs_memcmp(acl, &e, offsetof(typeof(e), old_root),
			       sizeof(e)))
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_name_union(&e.old_root);
	ccs_put_name_union(&e.new_root);
	kfree(entry);
	return error;
}
