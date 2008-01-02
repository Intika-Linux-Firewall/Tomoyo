/*
 * fs/tomoyo_capability.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.5.3-pre   2008/01/02
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>

/*************************  VARIABLES  *************************/

extern struct mutex domain_acl_lock;
extern int sbin_init_started;

static struct {
	const char *keyword;
	unsigned int current_value;
	const char *capability_name;
} capability_control_array[TOMOYO_MAX_CAPABILITY_INDEX] = { /* domain_policy.conf */
	[TOMOYO_INET_STREAM_SOCKET_CREATE]  = { "inet_tcp_create", 0,     "socket(PF_INET, SOCK_STREAM)" },
	[TOMOYO_INET_STREAM_SOCKET_LISTEN]  = { "inet_tcp_listen", 0,     "listen(PF_INET, SOCK_STREAM)" },
	[TOMOYO_INET_STREAM_SOCKET_CONNECT] = { "inet_tcp_connect", 0,    "connect(PF_INET, SOCK_STREAM)" },
	[TOMOYO_USE_INET_DGRAM_SOCKET]      = { "use_inet_udp", 0,        "socket(PF_INET, SOCK_DGRAM)" },
	[TOMOYO_USE_INET_RAW_SOCKET]        = { "use_inet_ip", 0,         "socket(PF_INET, SOCK_RAW)" },
	[TOMOYO_USE_ROUTE_SOCKET]           = { "use_route", 0,           "socket(PF_ROUTE)" },
	[TOMOYO_USE_PACKET_SOCKET]          = { "use_packet", 0,          "socket(PF_PACKET)" },
	[TOMOYO_SYS_MOUNT]                  = { "SYS_MOUNT", 0,           "sys_mount()" },
	[TOMOYO_SYS_UMOUNT]                 = { "SYS_UMOUNT", 0,          "sys_umount()" },
	[TOMOYO_SYS_REBOOT]                 = { "SYS_REBOOT", 0,          "sys_reboot()" },
	[TOMOYO_SYS_CHROOT]                 = { "SYS_CHROOT", 0,          "sys_chroot()" },
	[TOMOYO_SYS_KILL]                   = { "SYS_KILL", 0,            "sys_kill()" },
	[TOMOYO_SYS_VHANGUP]                = { "SYS_VHANGUP", 0,         "sys_vhangup()" },
	[TOMOYO_SYS_SETTIME]                = { "SYS_TIME", 0,            "sys_settimeofday()" },
	[TOMOYO_SYS_NICE]                   = { "SYS_NICE", 0,            "sys_nice()" },
	[TOMOYO_SYS_SETHOSTNAME]            = { "SYS_SETHOSTNAME", 0,     "sys_sethostname()" },
	[TOMOYO_USE_KERNEL_MODULE]          = { "use_kernel_module", 0,   "kernel_module" },
	[TOMOYO_CREATE_FIFO]                = { "create_fifo", 0,         "mknod(FIFO)" },
	[TOMOYO_CREATE_BLOCK_DEV]           = { "create_block_dev", 0,    "mknod(BDEV)" },
	[TOMOYO_CREATE_CHAR_DEV]            = { "create_char_dev", 0,     "mknod(CDEV)" },
	[TOMOYO_CREATE_UNIX_SOCKET]         = { "create_unix_socket", 0,  "mknod(SOCKET)" },
	[TOMOYO_SYS_LINK]                   = { "SYS_LINK", 0,            "sys_link()"  },
	[TOMOYO_SYS_SYMLINK]                = { "SYS_SYMLINK", 0,         "sys_symlink()" },
	[TOMOYO_SYS_RENAME]                 = { "SYS_RENAME", 0,          "sys_rename()" },
	[TOMOYO_SYS_UNLINK]                 = { "SYS_UNLINK", 0,          "sys_unlink()" },
	[TOMOYO_SYS_CHMOD]                  = { "SYS_CHMOD", 0,           "sys_chmod()" },
	[TOMOYO_SYS_CHOWN]                  = { "SYS_CHOWN", 0,           "sys_chown()" },
	[TOMOYO_SYS_IOCTL]                  = { "SYS_IOCTL", 0,           "sys_ioctl()" },
	[TOMOYO_SYS_KEXEC_LOAD]             = { "SYS_KEXEC_LOAD", 0,      "sys_kexec_load()" },
	[TOMOYO_SYS_PIVOT_ROOT]             = { "SYS_PIVOT_ROOT", 0,      "sys_pivot_root()" },
};

struct profile {
	unsigned char value[TOMOYO_MAX_CAPABILITY_INDEX];
};

static struct profile *profile_ptr[MAX_PROFILES];

/*************************  UTILITY FUNCTIONS  *************************/

const char *capability2keyword(const unsigned int capability)
{
	return capability < TOMOYO_MAX_CAPABILITY_INDEX	? capability_control_array[capability].keyword : NULL;
}

static const char *capability2name(const unsigned int capability)
{
	return capability < TOMOYO_MAX_CAPABILITY_INDEX	? capability_control_array[capability].capability_name : NULL;
}

/* Check whether the given capability control is enabled. */
static unsigned int CheckCapabilityFlags(const unsigned int index)
{
	const u8 profile = current->domain_info->profile;
	return sbin_init_started && index < TOMOYO_MAX_CAPABILITY_INDEX
#if MAX_PROFILES != 256
		&& profile < MAX_PROFILES
#endif
		&& profile_ptr[profile] ? profile_ptr[profile]->value[index] : 0;
}

static struct profile *FindOrAssignNewProfile(const unsigned int profile)
{
	static DEFINE_MUTEX(profile_lock);
	struct profile *ptr = NULL;
	mutex_lock(&profile_lock);
	if (profile < MAX_PROFILES && (ptr = profile_ptr[profile]) == NULL) {
		if ((ptr = alloc_element(sizeof(*ptr))) != NULL) {
			int i;
			for (i = 0; i < TOMOYO_MAX_CAPABILITY_INDEX; i++) ptr->value[i] = capability_control_array[i].current_value;
			mb(); /* Avoid out-of-order execution. */
			profile_ptr[profile] = ptr;
		}
	}
	mutex_unlock(&profile_lock);
	return ptr;
}

int SetCapabilityStatus(const char *data, unsigned int value, const unsigned int profile)
{
	int i;
	struct profile *ptr = FindOrAssignNewProfile(profile);
	if (!ptr) return -EINVAL;
	for (i = 0; i < TOMOYO_MAX_CAPABILITY_INDEX; i++) {
		if (strcmp(data, capability_control_array[i].keyword)) continue;
		if (value > 3) value = 3;
		ptr->value[i] = value;
		return 0;
	}
	return -EINVAL;
}

int ReadCapabilityStatus(struct io_buffer *head)
{
	int step;
	for (step = head->read_step; step < MAX_PROFILES * TOMOYO_MAX_CAPABILITY_INDEX; step++) {
		const int i = step / TOMOYO_MAX_CAPABILITY_INDEX, j = step % TOMOYO_MAX_CAPABILITY_INDEX;
		const struct profile *profile = profile_ptr[i];
		head->read_step = step;
		if (!profile) continue;
		if (io_printf(head, "%u-" KEYWORD_MAC_FOR_CAPABILITY "%s=%u\n", i, capability_control_array[j].keyword, profile->value[j])) break;
	}
	return step < MAX_PROFILES * TOMOYO_MAX_CAPABILITY_INDEX ? -ENOMEM : 0;
}

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditCapabilityLog(const unsigned int capability, const bool is_granted, const u8 profile, const unsigned int mode)
{
	char *buf;
	int len = 64;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	if ((buf = InitAuditLog(&len, profile, mode)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_CAPABILITY "%s\n", capability2keyword(capability));
	return WriteAuditLog(buf, is_granted);
}

/*************************  CAPABILITY ACL HANDLER  *************************/

static int AddCapabilityACL(const unsigned int capability, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	struct acl_info *ptr;
	struct capability_acl_record *acl;
	int error = -ENOMEM;
	const u32 bit = 1 << capability;
	if (!domain) return -EINVAL;
	mutex_lock(&domain_acl_lock);
	if (!is_delete) {
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = container_of(ptr, struct capability_acl_record, head);
			if (ptr->type == TYPE_CAPABILITY_ACL && ptr->cond == condition) {
				acl->capability |= bit;
				/* Found. Nothing to do. */
				error = 0;
				goto out;
			}
		}
		/* Not found. Append it to the tail. */
		if ((acl = alloc_element(sizeof(*acl))) == NULL) goto out;
		acl->head.type = TYPE_CAPABILITY_ACL;
		acl->capability = 1 << capability;
		acl->head.cond = condition;
		error = AddDomainACL(domain, &acl->head);
	} else {
		error = -ENOENT;
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			acl = container_of(ptr, struct capability_acl_record, head);
			if (ptr->type != TYPE_CAPABILITY_ACL || ptr->cond != condition) continue;
			acl->capability &= ~bit;
			//error = DelDomainACL(ptr);
			break;
		}
	}
 out: ;
	mutex_unlock(&domain_acl_lock);
	return error;
}

int CheckCapabilityACL(const unsigned int capability)
{
	struct domain_info * const domain = current->domain_info;
	struct acl_info *ptr;
	const u8 profile = current->domain_info->profile;
	const unsigned int mode = CheckCapabilityFlags(capability);
	const bool is_enforce = (mode == 3);
	const u32 bit = 1 << capability;
	if (!mode) return 0;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct capability_acl_record *acl;
		acl = container_of(ptr, struct capability_acl_record, head);
		if (ptr->type != TYPE_CAPABILITY_ACL || !(acl->capability & bit) || CheckCondition(ptr->cond, NULL)) continue;
		AuditCapabilityLog(capability, 1, profile, mode);
		return 0;
	}
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: %s denied for %s\n", GetMSG(is_enforce), capability2name(capability), GetLastName(domain));
	}
	AuditCapabilityLog(capability, 0, profile, capability);
	if (is_enforce) return CheckSupervisor("%s\n" KEYWORD_ALLOW_CAPABILITY "%s\n", domain->domainname->name, capability2keyword(capability));
	if (mode == 1 && CheckDomainQuota(domain)) AddCapabilityACL(capability, domain, NULL, 0);
	return 0;
}
EXPORT_SYMBOL(CheckCapabilityACL);

int AddCapabilityPolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	unsigned int capability;
	for (capability = 0; capability < TOMOYO_MAX_CAPABILITY_INDEX; capability++) {
		if (strcmp(data, capability_control_array[capability].keyword) == 0) {
			return AddCapabilityACL(capability, domain, condition, is_delete);
		}
	}
	return -EINVAL;
}

/***** TOMOYO Linux end. *****/
