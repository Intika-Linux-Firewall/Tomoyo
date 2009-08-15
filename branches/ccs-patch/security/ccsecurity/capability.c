/*
 * security/ccsecurity/capability.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

/**
 * ccs_cap2name - Convert capability operation to capability message.
 *
 * @operation: Type of operation.
 *
 * Returns the name of capability.
 */
static const char *ccs_cap2name(const u8 operation)
{
	static const char *ccs_capability_name[CCS_MAX_CAPABILITY_INDEX] = {
		[CCS_INET_STREAM_SOCKET_CREATE]  =
		"socket(PF_INET, SOCK_STREAM)",
		[CCS_INET_STREAM_SOCKET_LISTEN]  =
		"listen(PF_INET, SOCK_STREAM)",
		[CCS_INET_STREAM_SOCKET_CONNECT] =
		"connect(PF_INET, SOCK_STREAM)",
		[CCS_USE_INET_DGRAM_SOCKET]      =
		"socket(PF_INET, SOCK_DGRAM)",
		[CCS_USE_INET_RAW_SOCKET]        =
		"socket(PF_INET, SOCK_RAW)",
		[CCS_USE_ROUTE_SOCKET]           = "socket(PF_ROUTE)",
		[CCS_USE_PACKET_SOCKET]          = "socket(PF_PACKET)",
		[CCS_SYS_MOUNT]                  = "sys_mount()",
		[CCS_SYS_UMOUNT]                 = "sys_umount()",
		[CCS_SYS_REBOOT]                 = "sys_reboot()",
		[CCS_SYS_CHROOT]                 = "sys_chroot()",
		[CCS_SYS_KILL]                   = "sys_kill()",
		[CCS_SYS_VHANGUP]                = "sys_vhangup()",
		[CCS_SYS_SETTIME]                = "sys_settimeofday()",
		[CCS_SYS_NICE]                   = "sys_nice()",
		[CCS_SYS_SETHOSTNAME]            = "sys_sethostname()",
		[CCS_USE_KERNEL_MODULE]          = "kernel_module",
		[CCS_CREATE_FIFO]                = "mknod(FIFO)",
		[CCS_CREATE_BLOCK_DEV]           = "mknod(BDEV)",
		[CCS_CREATE_CHAR_DEV]            = "mknod(CDEV)",
		[CCS_CREATE_UNIX_SOCKET]         = "mknod(SOCKET)",
		[CCS_SYS_LINK]                   = "sys_link()",
		[CCS_SYS_SYMLINK]                = "sys_symlink()",
		[CCS_SYS_RENAME]                 = "sys_rename()",
		[CCS_SYS_UNLINK]                 = "sys_unlink()",
		[CCS_SYS_CHMOD]                  = "sys_chmod()",
		[CCS_SYS_CHOWN]                  = "sys_chown()",
		[CCS_SYS_IOCTL]                  = "sys_ioctl()",
		[CCS_SYS_KEXEC_LOAD]             = "sys_kexec_load()",
		[CCS_SYS_PIVOT_ROOT]             = "sys_pivot_root()",
		[CCS_SYS_PTRACE]                 = "sys_ptrace()",
		[CCS_CONCEAL_MOUNT]              = "conceal-mount",
	};
	if (operation < CCS_MAX_CAPABILITY_INDEX)
		return ccs_capability_name[operation];
	return NULL;
}

static inline bool ccs_capability_enabled(const u8 profile, const u8 operation)
{
	return operation < CCS_MAX_CAPABILITY_INDEX ?
		ccs_profile_ptr[profile]->enabled_capabilities[operation] :
		false;
}

/**
 * ccs_audit_capability_log - Audit capability log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  Type of operation.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_capability_log(struct ccs_request_info *r,
				    const u8 operation, const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "TOMOYO-%s: %s denied for %s\n",
		       ccs_get_msg(r->mode == 3), ccs_cap2name(operation),
		       ccs_get_last_name(r->domain));
	return ccs_write_audit_log(is_granted, r, CCS_KEYWORD_ALLOW_CAPABILITY
				   "%s\n", ccs_cap2keyword(operation));
}

/**
 * ccs_capable - Check permission for capability.
 *
 * @operation: Type of operation.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_capable2(const u8 operation)
{
	struct ccs_request_info r;
	struct ccs_acl_info *ptr;
	bool is_enforce;
	int error;
	ccs_check_read_lock();
	if (!ccs_can_sleep())
		return true;
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_CAPABILITY);
	if (!r.mode)
		return true;
	if (!ccs_capability_enabled(r.profile, operation))
		return true;
	is_enforce = (r.mode == 3);
 retry:
	error = -EPERM;
	list_for_each_entry_rcu(ptr, &r.domain->acl_info_list, list) {
		struct ccs_capability_acl_record *acl;
		if (ptr->is_deleted || ptr->type != CCS_TYPE_CAPABILITY_ACL)
			continue;
		acl = container_of(ptr, struct ccs_capability_acl_record, head);
		if (acl->operation != operation ||
		    !ccs_check_condition(&r, ptr))
			continue;
		r.cond = ptr->cond;
		error = 0;
		break;
	}
	ccs_audit_capability_log(&r, operation, !error);
	if (error)
		error = ccs_check_supervisor(&r, CCS_KEYWORD_ALLOW_CAPABILITY
					     "%s\n",
					     ccs_cap2keyword(operation));
	if (error == 1)
		goto retry;
	if (!is_enforce)
		error = 0;
	return !error;
}

/**
 * ccs_capable - Check permission for capability.
 *
 * @operation: Type of operation.
 *
 * Returns true on success, false otherwise.
 */
bool ccs_capable(const u8 operation)
{
	const int idx = ccs_read_lock();
	const int error = ccs_capable2(operation);
	ccs_read_unlock(idx);
	return error;
}
EXPORT_SYMBOL(ccs_capable); /* for net/unix/af_unix.c */

/**
 * ccs_write_capability_policy - Write "struct ccs_capability_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_capability_policy(char *data, struct ccs_domain_info *domain,
				struct ccs_condition *condition,
				const bool is_delete)
{
	struct ccs_capability_acl_record e = {
		.head.type = CCS_TYPE_CAPABILITY_ACL,
		.head.cond = condition,
	};
	struct ccs_capability_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
	int error = is_delete ? -ENOENT : -ENOMEM;
	u8 capability;
	for (capability = 0; capability < CCS_MAX_CAPABILITY_INDEX;
	     capability++) {
		if (strcmp(data, ccs_cap2keyword(capability)))
			continue;
		break;
	}
	if (capability == CCS_MAX_CAPABILITY_INDEX)
		return -EINVAL;
	e.operation = capability;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_capability_acl_record *acl =
			container_of(ptr, struct ccs_capability_acl_record,
				     head);
		if (ptr->type != CCS_TYPE_CAPABILITY_ACL ||
		    ptr->cond != condition || acl->operation != capability)
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
	kfree(entry);
	return error;
}

/**
 * ccs_check_setattr_permission - Check permission for chmod/chown.
 *
 * @dentry: Pointer to "struct dentry".
 * @attr:   Pointer to "struct iattr".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_check_setattr_permission(struct dentry *dentry, struct iattr *attr)
{
	if ((attr->ia_valid & ATTR_MODE) && !ccs_capable(CCS_SYS_CHMOD))
		return -EPERM;
	if ((attr->ia_valid & (ATTR_UID | ATTR_GID)) &&
	    !ccs_capable(CCS_SYS_CHOWN))
		return -EPERM;
	return 0;
}
