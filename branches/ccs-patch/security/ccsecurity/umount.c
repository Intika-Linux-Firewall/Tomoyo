/*
 * security/ccsecurity/umount.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/slab.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
#include <linux/mount.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namespace.h>
#endif
#include "internal.h"

/**
 * ccs_audit_umount_log - Audit unmount log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @dir:        Mount point.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_umount_log(struct ccs_request_info *r,
				const char *dir, const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "SAKURA-%s: umount %s denied for %s\n",
		       ccs_get_msg(r->mode == 3), dir,
		       ccs_get_last_name(r->domain));
	return ccs_write_audit_log(is_granted, r, CCS_KEYWORD_ALLOW_UNMOUNT
				   "%s\n", dir);
}

/**
 * ccs_may_umount2 - Check permission for unmount.
 *
 * @mnt: Pointer to "struct vfsmount".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_may_umount2(struct vfsmount *mnt)
{
	struct ccs_request_info r;
	int error;
	const char *dir0;
	bool is_enforce;
	struct ccs_acl_info *ptr;
	struct ccs_path_info dir;
	ccs_check_read_lock();
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_NAMESPACE);
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
	list_for_each_entry_rcu(ptr, &r.domain->acl_info_list, list) {
		struct ccs_umount_acl_record *acl;
		if (ptr->type != CCS_TYPE_UMOUNT_ACL)
			continue;
		acl = container_of(ptr, struct ccs_umount_acl_record, head);
		if (!ccs_compare_name_union(&dir, &acl->dir) ||
		    !ccs_check_condition(&r, ptr))
			continue;
		r.cond = ptr->cond;
		error = 0;
		break;
	}
	ccs_audit_umount_log(&r, dir0, !error);
	if (error)
		error = ccs_check_supervisor(&r, CCS_KEYWORD_ALLOW_UNMOUNT
					     "%s", ccs_file_pattern(&dir));
 out:
	kfree(dir0);
	if (!is_enforce)
		error = 0;
	if (error == 1)
		goto retry;
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
	const int idx = ccs_read_lock();
	const int error = ccs_may_umount2(mnt);
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_write_umount_policy - Write "struct ccs_umount_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on sucess, negative value otherwise.
 */
int ccs_write_umount_policy(char *data, struct ccs_domain_info *domain,
			    struct ccs_condition *condition,
			    const bool is_delete)
{
	struct ccs_umount_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
	struct ccs_umount_acl_record e = { .head.type = CCS_TYPE_UMOUNT_ACL,
					   .head.cond = condition };
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!ccs_parse_name_union(data, &e.dir))
		return error;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_umount_acl_record *acl =
			container_of(ptr, struct ccs_umount_acl_record, head);
		if (ptr->type != CCS_TYPE_UMOUNT_ACL ||
		    ptr->cond != condition || memcmp(&acl->dir, &e.dir,
						     sizeof(e.dir)))
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
