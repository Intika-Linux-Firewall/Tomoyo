/*
 * security/ccsecurity/chroot.c
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
 * ccs_audit_chroot_log - Audit chroot log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @root:       New root directory.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_chroot_log(struct ccs_request_info *r,
				const char *root, const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "SAKURA-%s: chroot %s denied for %s\n",
		       ccs_get_msg(r->mode == 3), root,
		       ccs_get_last_name(r->domain));
	return ccs_write_audit_log(is_granted, r, CCS_KEYWORD_ALLOW_CHROOT
				   "%s\n", root);
}

/**
 * ccs_check_chroot_acl - Check permission for chroot().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_chroot_acl(struct path *path)
{
	struct ccs_request_info r;
	int error;
	struct ccs_path_info dir;
	char *root_name;
	bool is_enforce;
	struct ccs_obj_info obj = {
		.path1_dentry = path->dentry,
		.path1_vfsmnt = path->mnt
	};
	ccs_check_read_lock();
	if (!ccs_can_sleep() ||
	    !ccs_init_request_info(&r, NULL, CCS_MAC_FOR_NAMESPACE))
		return 0;
	is_enforce = (r.mode == 3);
	r.obj = &obj;
 retry:
	error = -EPERM;
	root_name = ccs_realpath_from_path(path);
	if (!root_name)
		goto out;
	dir.name = root_name;
	ccs_fill_path_info(&dir);
	if (dir.is_dir) {
		struct ccs_acl_info *ptr;
		list_for_each_entry_rcu(ptr, &r.domain->acl_info_list, list) {
			struct ccs_chroot_acl_record *acl;
			if (ptr->is_deleted ||
			    ptr->type != CCS_TYPE_CHROOT_ACL)
				continue;
			acl = container_of(ptr, struct ccs_chroot_acl_record,
					   head);
			if (!ccs_compare_name_union(&dir, &acl->dir) ||
			    !ccs_check_condition(&r, ptr))
				continue;
			r.cond = ptr->cond;
			error = 0;
			break;
		}
	}
	ccs_audit_chroot_log(&r, root_name, !error);
	if (error)
		error = ccs_check_supervisor(&r, CCS_KEYWORD_ALLOW_CHROOT
					     "%s\n", ccs_file_pattern(&dir));
 out:
	kfree(root_name);
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
 * ccs_check_chroot_permission - Check permission for chroot().
 *
 * @path: Pointer to "struct path" (for 2.6.27 and later).
 *        Pointer to "struct nameidata" (for 2.6.26 and earlier).
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_chroot_permission(struct PATH_or_NAMEIDATA *path)
{
#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 25) || LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 26)
	struct path tmp_path = { path->path.mnt, path->path.dentry };
#else
	struct path tmp_path = { path->mnt, path->dentry };
#endif
	const int idx = ccs_read_lock();
	const int error = ccs_check_chroot_acl(&tmp_path);
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_write_chroot_policy - Write "struct ccs_chroot_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_chroot_policy(char *data, struct ccs_domain_info *domain,
			    struct ccs_condition *condition,
			    const bool is_delete)
{
	struct ccs_chroot_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
	struct ccs_chroot_acl_record e = {
		.head.type = CCS_TYPE_CHROOT_ACL,
		.head.cond = condition
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (data[0] != '@' && !ccs_is_correct_path(data, 1, 0, 1))
		return -EINVAL;
	if (!ccs_parse_name_union(data, &e.dir))
		return error;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_chroot_acl_record *acl =
			container_of(ptr, struct ccs_chroot_acl_record, head);
		if (ptr->type != CCS_TYPE_CHROOT_ACL || ptr->cond != condition
		    || memcmp(&acl->dir, &e.dir, sizeof(e.dir)))
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
	ccs_put_name_union(&e.dir);
	kfree(entry);
	return error;
}
