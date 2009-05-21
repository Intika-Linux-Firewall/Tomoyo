/*
 * fs/tomoyo_capability.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.8-pre   2009/05/08
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
	};
	if (operation < CCS_MAX_CAPABILITY_INDEX)
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
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_capability_acl(const u8 operation,
				     struct ccs_domain_info *domain,
				     struct ccs_condition *condition,
				     const bool is_delete)
{
	struct ccs_capability_acl_record *entry = NULL;
	struct ccs_acl_info *ptr;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (!domain)
		return -EINVAL;
	if (is_delete)
		goto delete;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	/***** WRITER SECTION START *****/
	down_write(&ccs_policy_lock);
	list_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct ccs_capability_acl_record *acl;
		if (ccs_acl_type1(ptr) != TYPE_CAPABILITY_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_capability_acl_record, head);
		if (acl->operation != operation)
			continue;
		error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (error && ccs_memory_ok(entry)) {
		entry->head.type = TYPE_CAPABILITY_ACL;
		entry->head.cond = condition;
		entry->operation = operation;
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	up_write(&ccs_policy_lock);
	/***** WRITER SECTION END *****/
	goto out;
 delete:
	/***** WRITER SECTION START *****/
	down_write(&ccs_policy_lock);
	list_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct ccs_capability_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_CAPABILITY_ACL)
			continue;
		if (ptr->cond != condition)
			continue;
		acl = container_of(ptr, struct ccs_capability_acl_record, head);
		if (acl->operation != operation)
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
	up_write(&ccs_policy_lock);
	/***** WRITER SECTION END *****/
 out:
	kfree(entry);
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
	if (!r.mode) {
		found = true;
		goto done;
	}
 retry:
	/***** READER SECTION START *****/
	down_read(&ccs_policy_lock);
	list_for_each_entry(ptr, &r.cookie.u.domain->acl_info_list, list) {
		struct ccs_capability_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_CAPABILITY_ACL)
			continue;
		acl = container_of(ptr, struct ccs_capability_acl_record, head);
		if (acl->operation != operation ||
		    !ccs_check_condition(&r, ptr))
			continue;
		r.condition_cookie.u.cond = ptr->cond;
		found = true;
		break;
	}
	up_read(&ccs_policy_lock);
	/***** READER SECTION START *****/
	ccs_audit_capability_log(&r, operation, found);
	if (found)
		goto done;
	if (ccs_verbose_mode(r.cookie.u.domain))
		printk(KERN_WARNING "TOMOYO-%s: %s denied for %s\n",
		       ccs_get_msg(is_enforce), ccs_cap2name(operation),
		       ccs_get_last_name(r.cookie.u.domain));
	if (is_enforce) {
		int error = ccs_check_supervisor(&r, KEYWORD_ALLOW_CAPABILITY
						 "%s\n",
						 ccs_cap2keyword(operation));
		if (error == 1)
			goto retry;
		found = !error;
		goto done;
	}
	if (r.mode == 1 && ccs_domain_quota_ok(r.cookie.u.domain))
		ccs_update_capability_acl(operation, r.cookie.u.domain,
					  ccs_handler_cond(), false);
	found = true;
 done:
	ccs_exit_request_info(&r);
	return found;
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
	u8 capability;
	for (capability = 0; capability < CCS_MAX_CAPABILITY_INDEX;
	     capability++) {
		if (strcmp(data, ccs_cap2keyword(capability)))
			continue;
		return ccs_update_capability_acl(capability, domain, condition,
						 is_delete);
	}
	return -EINVAL;
}
