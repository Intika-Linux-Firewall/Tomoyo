/*
 * fs/sakura_chroot.c
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
 * update_chroot_acl - Update "struct chroot_entry" list.
 *
 * @dir:       The name of directory.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_chroot_acl(const char *dir, struct domain_info *domain,
			     const struct condition_list *condition,
			     const bool is_delete)
{
	struct acl_info *ptr;
	struct chroot_entry *acl;
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
		if (ccs_acl_type1(ptr) != TYPE_CHROOT_ACL)
                        continue;
                if (ccs_get_condition_part(ptr) != condition)
                        continue;
                acl = container_of(ptr, struct chroot_entry, head);
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
	acl = ccs_alloc_acl_element(TYPE_CHROOT_ACL, condition);
	if (!acl)
		goto out;
	acl->dir = saved_dir;
	error = ccs_add_domain_acl(domain, &acl->head);
	printk(KERN_CONT "%sAllow chroot() to %s\n", ccs_log_level, dir);
 out:
	mutex_unlock(&lock);
	return error;
}

/**
 * print_error - Print error message.
 *
 * @r:         Pointer to "struct ccs_request_info".
 * @root_name: Requested directory name.
 *
 * Returns 0 if @r->mode is not enforcing mode or permitted by the
 * administrator's decision, negative value otherwise.
 */
static int print_error(struct ccs_request_info *r, const char *root_name)
{
	int error;
	const bool is_enforce = (r->mode == 3);
	const char *exename = ccs_get_exe();
	printk(KERN_WARNING "SAKURA-%s: chroot %s (pid=%d:exe=%s): "
	       "Permission denied.\n", ccs_get_msg(is_enforce),
	       root_name, (pid_t) sys_getpid(), exename);
	if (is_enforce)
		error = ccs_check_supervisor(r,
					     "# %s is requesting\nchroot %s\n",
					     exename, root_name);
	else
		error = 0;
	if (exename)
		ccs_free(exename);
	if (r->mode == 1 && root_name)
		update_chroot_acl(root_name, r->domain, ccs_handler_cond(),
				  false);
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
	struct ccs_request_info r;
	int error;
	char *root_name;
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_SAKURA_RESTRICT_CHROOT);
	if (!r.mode)
		return 0;
 retry:
	error = -EPERM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25) && LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)
	root_name = ccs_realpath_from_dentry(path->path.dentry, path->path.mnt);
#else
	root_name = ccs_realpath_from_dentry(path->dentry, path->mnt);
#endif
	if (root_name) {
		struct path_info dir;
		dir.name = root_name;
		ccs_fill_path_info(&dir);
		if (dir.is_dir) {
			struct acl_info *ptr;
			list1_for_each_entry(ptr, &r.domain->acl_info_list,
					     list) {
				struct chroot_entry *acl;
				if (ccs_acl_type2(ptr) != TYPE_NO_UMOUNT_ACL)
					continue;
				acl = container_of(ptr, struct chroot_entry,
						   head);
				if (!ccs_path_matches_pattern(&dir, acl->dir))
					continue;
				if (!ccs_check_condition(&r, ptr))
					continue;
				error = 0;
				break;
			}
		}
	}
	if (error)
		error = print_error(&r, root_name);
	ccs_free(root_name);
	if (error == 1)
		goto retry;
	return error;
}

/**
 * ccs_write_chroot_policy - Write "struct chroot_entry" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL. 
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_chroot_policy(char *data, struct domain_info *domain,
			    const struct condition_list *condition,
			    const bool is_delete)
{
	return update_chroot_acl(data, condition, domain, is_delete);
}
