/*
 * fs/tomoyo_capability.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.7-rc   2009/03/18
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>

/**
 * ccs_cap2name - Convert capability operation to capability message.
 *
 * @operation: Type of operation.
 *
 * Returns the name of capability.
 */
static const char *ccs_cap2name(const u8 operation)
{
	static const char *ccs_capability_name[TOMOYO_MAX_CAPABILITY_INDEX] = {
		[TOMOYO_INET_STREAM_SOCKET_CREATE]  =
		"socket(PF_INET, SOCK_STREAM)",
		[TOMOYO_INET_STREAM_SOCKET_LISTEN]  =
		"listen(PF_INET, SOCK_STREAM)",
		[TOMOYO_INET_STREAM_SOCKET_CONNECT] =
		"connect(PF_INET, SOCK_STREAM)",
		[TOMOYO_USE_INET_DGRAM_SOCKET]      =
		"socket(PF_INET, SOCK_DGRAM)",
		[TOMOYO_USE_INET_RAW_SOCKET]        =
		"socket(PF_INET, SOCK_RAW)",
		[TOMOYO_USE_ROUTE_SOCKET]           = "socket(PF_ROUTE)",
		[TOMOYO_USE_PACKET_SOCKET]          = "socket(PF_PACKET)",
		[TOMOYO_SYS_MOUNT]                  = "sys_mount()",
		[TOMOYO_SYS_UMOUNT]                 = "sys_umount()",
		[TOMOYO_SYS_REBOOT]                 = "sys_reboot()",
		[TOMOYO_SYS_CHROOT]                 = "sys_chroot()",
		[TOMOYO_SYS_KILL]                   = "sys_kill()",
		[TOMOYO_SYS_VHANGUP]                = "sys_vhangup()",
		[TOMOYO_SYS_SETTIME]                = "sys_settimeofday()",
		[TOMOYO_SYS_NICE]                   = "sys_nice()",
		[TOMOYO_SYS_SETHOSTNAME]            = "sys_sethostname()",
		[TOMOYO_USE_KERNEL_MODULE]          = "kernel_module",
		[TOMOYO_CREATE_FIFO]                = "mknod(FIFO)",
		[TOMOYO_CREATE_BLOCK_DEV]           = "mknod(BDEV)",
		[TOMOYO_CREATE_CHAR_DEV]            = "mknod(CDEV)",
		[TOMOYO_CREATE_UNIX_SOCKET]         = "mknod(SOCKET)",
		[TOMOYO_SYS_LINK]                   = "sys_link()",
		[TOMOYO_SYS_SYMLINK]                = "sys_symlink()",
		[TOMOYO_SYS_RENAME]                 = "sys_rename()",
		[TOMOYO_SYS_UNLINK]                 = "sys_unlink()",
		[TOMOYO_SYS_CHMOD]                  = "sys_chmod()",
		[TOMOYO_SYS_CHOWN]                  = "sys_chown()",
		[TOMOYO_SYS_IOCTL]                  = "sys_ioctl()",
		[TOMOYO_SYS_KEXEC_LOAD]             = "sys_kexec_load()",
		[TOMOYO_SYS_PIVOT_ROOT]             = "sys_pivot_root()",
		[TOMOYO_SYS_PTRACE]                 = "sys_ptrace()",
	};
	if (operation < TOMOYO_MAX_CAPABILITY_INDEX)
		return ccs_capability_name[operation];
	return NULL;
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
	return ccs_write_audit_log(is_granted, r, KEYWORD_ALLOW_CAPABILITY
				   "%s\n", ccs_cap2keyword(operation));
}

/**
 * ccs_update_capability_acl - Update "struct ccs_capability_acl_record" list.
 *
 * @operation: Type of operation.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct ccs_condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_capability_acl(const u8 operation,
				     struct domain_info *domain,
				     const struct ccs_condition_list *condition,
				     const bool is_delete)
{
	static DEFINE_MUTEX(lock);
	struct ccs_acl_info *ptr;
	struct ccs_capability_acl_record *acl;
	int error = -ENOMEM;
	if (!domain)
		return -EINVAL;
	mutex_lock(&lock);
	if (is_delete)
		goto delete;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != TYPE_CAPABILITY_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ccs_capability_acl_record, head);
		if (acl->operation != operation)
			continue;
		error = ccs_add_domain_acl(NULL, ptr);
		goto out;
	}
	/* Not found. Append it to the tail. */
	acl = ccs_alloc_acl_element(TYPE_CAPABILITY_ACL, condition);
	if (!acl)
		goto out;
	acl->operation = operation;
	error = ccs_add_domain_acl(domain, &acl->head);
	goto out;
 delete:
	error = -ENOENT;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type2(ptr) != TYPE_CAPABILITY_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ccs_capability_acl_record, head);
		if (acl->operation != operation)
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
 out:
	mutex_unlock(&lock);
	return error;
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
	struct ccs_request_info r;
	struct ccs_acl_info *ptr;
	bool is_enforce;
	bool found = false;
	if (!ccs_can_sleep())
		return true;
	ccs_init_request_info(&r, NULL, CCS_MAX_CONTROL_INDEX + operation);
	is_enforce = (r.mode == 3);
	if (!r.mode)
		return true;
 retry:
	list1_for_each_entry(ptr, &r.domain->acl_info_list, list) {
		struct ccs_capability_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_CAPABILITY_ACL)
			continue;
		acl = container_of(ptr, struct ccs_capability_acl_record, head);
		if (acl->operation != operation ||
		    !ccs_check_condition(&r, ptr))
			continue;
		r.cond = ccs_get_condition_part(ptr);
		found = true;
		break;
	}
	ccs_audit_capability_log(&r, operation, found);
	if (found)
		return true;
	if (ccs_verbose_mode(r.domain))
		printk(KERN_WARNING "TOMOYO-%s: %s denied for %s\n",
		       ccs_get_msg(is_enforce), ccs_cap2name(operation),
		       ccs_get_last_name(r.domain));
	if (is_enforce) {
		int error = ccs_check_supervisor(&r, KEYWORD_ALLOW_CAPABILITY
						 "%s\n",
						 ccs_cap2keyword(operation));
		if (error == 1)
			goto retry;
		return !error;
	}
	if (r.mode == 1 && ccs_domain_quota_ok(r.domain))
		ccs_update_capability_acl(operation, r.domain,
					  ccs_handler_cond(), false);
	return true;
}
EXPORT_SYMBOL(ccs_capable); /* for net/unix/af_unix.c */

/**
 * ccs_write_capability_policy - Write "struct ccs_capability_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct ccs_condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_capability_policy(char *data, struct domain_info *domain,
				const struct ccs_condition_list *condition,
				const bool is_delete)
{
	u8 capability;
	for (capability = 0; capability < TOMOYO_MAX_CAPABILITY_INDEX;
	     capability++) {
		if (strcmp(data, ccs_cap2keyword(capability)))
			continue;
		return ccs_update_capability_acl(capability, domain, condition,
						 is_delete);
	}
	return -EINVAL;
}
