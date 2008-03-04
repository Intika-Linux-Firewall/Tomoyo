/*
 * fs/tomoyo_capability.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.0-pre   2008/03/04
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>

/*************************  UTILITY FUNCTIONS  *************************/

static const char *cap_operation2name(const u8 operation)
{
	static const char *capability_name[TOMOYO_MAX_CAPABILITY_INDEX] = {
		[TOMOYO_INET_STREAM_SOCKET_CREATE]  = "socket(PF_INET, SOCK_STREAM)",
		[TOMOYO_INET_STREAM_SOCKET_LISTEN]  = "listen(PF_INET, SOCK_STREAM)",
		[TOMOYO_INET_STREAM_SOCKET_CONNECT] = "connect(PF_INET, SOCK_STREAM)",
		[TOMOYO_USE_INET_DGRAM_SOCKET]      = "socket(PF_INET, SOCK_DGRAM)",
		[TOMOYO_USE_INET_RAW_SOCKET]        = "socket(PF_INET, SOCK_RAW)",
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
	return operation < TOMOYO_MAX_CAPABILITY_INDEX ? capability_name[operation] : NULL;
}

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditCapabilityLog(const u8 operation, const bool is_granted, const u8 profile, const u8 mode)
{
	char *buf;
	int len = 64;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	if ((buf = InitAuditLog(&len, profile, mode, NULL)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_CAPABILITY "%s\n", cap_operation2keyword(operation));
	return WriteAuditLog(buf, is_granted);
}

/*************************  CAPABILITY ACL HANDLER  *************************/

static int AddCapabilityACL(const u8 operation, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	struct acl_info *ptr;
	struct capability_acl_record *acl;
	int error = -ENOMEM;
	if (!domain) return -EINVAL;
	mutex_lock(&domain_acl_lock);
	if (!is_delete) {
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			if ((ptr->type & ~(ACL_DELETED | ACL_WITH_CONDITION)) != TYPE_CAPABILITY_ACL) continue;
			if (GetConditionPart(ptr) != condition) continue;
			acl = container_of(ptr, struct capability_acl_record, head);
			if (acl->operation != operation) continue;
			error = AddDomainACL(NULL, ptr);
			goto out;
		}
		/* Not found. Append it to the tail. */
		if ((acl = alloc_acl_element(TYPE_CAPABILITY_ACL, condition)) == NULL) goto out;
		acl->operation = operation;
		error = AddDomainACL(domain, &acl->head);
	} else {
		error = -ENOENT;
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			if ((ptr->type & ~ACL_WITH_CONDITION) != TYPE_CAPABILITY_ACL) continue;
			if (GetConditionPart(ptr) != condition) continue;
			acl = container_of(ptr, struct capability_acl_record, head);
			if (acl->operation != operation) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
 out: ;
	mutex_unlock(&domain_acl_lock);
	return error;
}

int CheckCapabilityACL(const u8 operation)
{
	struct domain_info * const domain = current->domain_info;
	struct acl_info *ptr;
	const u8 profile = current->domain_info->profile;
	const u8 mode = CheckCapabilityFlags(operation);
	const bool is_enforce = (mode == 3);
	bool found = false;
	if (!mode) return 0;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct capability_acl_record *acl;
		if ((ptr->type & ~ACL_WITH_CONDITION) != TYPE_CAPABILITY_ACL) continue;
		acl = container_of(ptr, struct capability_acl_record, head);
		if (acl->operation != operation || !CheckCondition(ptr, NULL)) continue;
		UpdateCondition(ptr);
		found = true;
		break;
	}
	AuditCapabilityLog(operation, found, profile, mode);
	if (found) return 0;
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: %s denied for %s\n", GetMSG(is_enforce), cap_operation2name(operation), GetLastName(domain));
	}
	if (is_enforce) return CheckSupervisor("%s\n" KEYWORD_ALLOW_CAPABILITY "%s\n", domain->domainname->name, cap_operation2keyword(operation));
	else if (mode == 1 && CheckDomainQuota(domain)) AddCapabilityACL(operation, domain, NULL, 0);
	return 0;
}
EXPORT_SYMBOL(CheckCapabilityACL);

int AddCapabilityPolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	u8 capability;
	for (capability = 0; capability < TOMOYO_MAX_CAPABILITY_INDEX; capability++) {
		if (strcmp(data, cap_operation2keyword(capability))) continue;
		return AddCapabilityACL(capability, domain, condition, is_delete);
	}
	return -EINVAL;
}

/***** TOMOYO Linux end. *****/
