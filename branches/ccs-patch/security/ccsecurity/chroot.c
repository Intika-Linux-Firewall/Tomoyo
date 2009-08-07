/*
 * fs/ccsecurity/chroot.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/07/03
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
	return ccs_write_audit_log(is_granted, r, KEYWORD_ALLOW_CHROOT
				   "%s\n", root);
}

/**
 * ccs_update_chroot_acl - Update "struct ccs_chroot_acl_record" list.
 *
 * @dir:       The name of directory.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_chroot_acl(const char *dir,
				 struct ccs_domain_info *domain,
				 struct ccs_condition *condition,
				 const bool is_delete)
{
	struct ccs_chroot_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
	const struct ccs_path_info *saved_dir;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_is_correct_path(dir, 1, 0, 1))
		return -EINVAL;
	saved_dir = ccs_get_name(dir);
	if (!saved_dir)
		return -ENOMEM;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_chroot_acl_record *acl;
		if (ccs_acl_type1(ptr) != TYPE_CHROOT_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_chroot_acl_record, head);
		if (acl->dir != saved_dir)
			continue;
		if (is_delete)
			error = ccs_del_domain_acl(ptr);
		else
			error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->head.type = TYPE_CHROOT_ACL;
		entry->head.cond = condition;
		entry->dir = saved_dir;
		saved_dir = NULL;
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(saved_dir);
	kfree(entry);
	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#define PATH_or_NAMEIDATA path
#else
#define PATH_or_NAMEIDATA nameidata
#endif
/**
 * ccs_check_chroot_permission2 - Check permission for chroot().
 *
 * @path: Pointer to "struct path" (for 2.6.27 and later).
 *        Pointer to "struct nameidata" (for 2.6.26 and earlier).
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_chroot_permission2(struct PATH_or_NAMEIDATA *path)
{
	struct ccs_request_info r;
	int error;
	struct ccs_path_info dir;
	char *root_name;
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
	root_name = ccs_realpath_from_dentry(path->path.dentry, path->path.mnt);
#else
	root_name = ccs_realpath_from_dentry(path->dentry, path->mnt);
#endif
	if (!root_name)
		goto out;
	dir.name = root_name;
	ccs_fill_path_info(&dir);
	if (dir.is_dir) {
		struct ccs_acl_info *ptr;
		list_for_each_entry_rcu(ptr, &r.domain->acl_info_list, list) {
			struct ccs_chroot_acl_record *acl;
			if (ccs_acl_type2(ptr) != TYPE_CHROOT_ACL)
				continue;
			acl = container_of(ptr, struct ccs_chroot_acl_record,
					   head); 
			if (!ccs_path_matches_pattern(&dir, acl->dir) ||
			    !ccs_check_condition(&r, ptr))
				continue;
			r.cond = ptr->cond;
			error = 0;
			break;
		}
	}
	ccs_audit_chroot_log(&r, root_name, !error);
	if (!error)
		goto out;
	if (is_enforce)
		error = ccs_check_supervisor(&r, KEYWORD_ALLOW_CHROOT"%s\n",
					     root_name);
	else if (ccs_domain_quota_ok(&r))
		ccs_update_chroot_acl(root_name, r.domain, NULL, false);
 out:
	kfree(root_name);
	if (error == 1)
		goto retry;
	if (!is_enforce)
		error = 0;
	return error;
}

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
	const int idx = ccs_read_lock();
	const int error = ccs_check_chroot_permission2(path);
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
	return ccs_update_chroot_acl(data, domain, condition, is_delete);
}
