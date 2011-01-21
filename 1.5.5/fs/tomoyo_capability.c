/*
 * fs/tomoyo_capability.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.5.5   2008/09/03
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

extern struct semaphore domain_acl_lock;
extern int sbin_init_started;

static struct {
	const char *keyword;
	const char *capability_name;
} capability_control_array[TOMOYO_MAX_CAPABILITY_INDEX] = { /* domain_policy.txt */
	[TOMOYO_INET_STREAM_SOCKET_CREATE]  = { "inet_tcp_create",      "socket(PF_INET, SOCK_STREAM)" },
	[TOMOYO_INET_STREAM_SOCKET_LISTEN]  = { "inet_tcp_listen",      "listen(PF_INET, SOCK_STREAM)" },
	[TOMOYO_INET_STREAM_SOCKET_CONNECT] = { "inet_tcp_connect",     "connect(PF_INET, SOCK_STREAM)" },
	[TOMOYO_USE_INET_DGRAM_SOCKET]      = { "use_inet_udp",         "socket(PF_INET, SOCK_DGRAM)" },
	[TOMOYO_USE_INET_RAW_SOCKET]        = { "use_inet_ip",          "socket(PF_INET, SOCK_RAW)" },
	[TOMOYO_USE_ROUTE_SOCKET]           = { "use_route",            "socket(PF_ROUTE)" },
	[TOMOYO_USE_PACKET_SOCKET]          = { "use_packet",           "socket(PF_PACKET)" },
	[TOMOYO_SYS_MOUNT]                  = { "SYS_MOUNT",            "sys_mount()" },
	[TOMOYO_SYS_UMOUNT]                 = { "SYS_UMOUNT",           "sys_umount()" },
	[TOMOYO_SYS_REBOOT]                 = { "SYS_REBOOT",           "sys_reboot()" },
	[TOMOYO_SYS_CHROOT]                 = { "SYS_CHROOT",           "sys_chroot()" },
	[TOMOYO_SYS_KILL]                   = { "SYS_KILL",             "sys_kill()" },
	[TOMOYO_SYS_VHANGUP]                = { "SYS_VHANGUP",          "sys_vhangup()" },
	[TOMOYO_SYS_SETTIME]                = { "SYS_TIME",             "sys_settimeofday()" },
	[TOMOYO_SYS_NICE]                   = { "SYS_NICE",             "sys_nice()" },
	[TOMOYO_SYS_SETHOSTNAME]            = { "SYS_SETHOSTNAME",      "sys_sethostname()" },
	[TOMOYO_USE_KERNEL_MODULE]          = { "use_kernel_module",    "kernel_module" },
	[TOMOYO_CREATE_FIFO]                = { "create_fifo",          "mknod(FIFO)" },
	[TOMOYO_CREATE_BLOCK_DEV]           = { "create_block_dev",     "mknod(BDEV)" },
	[TOMOYO_CREATE_CHAR_DEV]            = { "create_char_dev",      "mknod(CDEV)" },
	[TOMOYO_CREATE_UNIX_SOCKET]         = { "create_unix_socket",   "mknod(SOCKET)" },
	[TOMOYO_SYS_LINK]                   = { "SYS_LINK",             "sys_link()" },
	[TOMOYO_SYS_SYMLINK]                = { "SYS_SYMLINK",          "sys_symlink()" },
	[TOMOYO_SYS_RENAME]                 = { "SYS_RENAME",           "sys_rename()" },
	[TOMOYO_SYS_UNLINK]                 = { "SYS_UNLINK",           "sys_unlink()" },
	[TOMOYO_SYS_CHMOD]                  = { "SYS_CHMOD",            "sys_chmod()" },
	[TOMOYO_SYS_CHOWN]                  = { "SYS_CHOWN",            "sys_chown()" },
	[TOMOYO_SYS_IOCTL]                  = { "SYS_IOCTL",            "sys_ioctl()" },
	[TOMOYO_SYS_KEXEC_LOAD]             = { "SYS_KEXEC_LOAD",       "sys_kexec_load()" },
	[TOMOYO_SYS_PIVOT_ROOT]             = { "SYS_PIVOT_ROOT",       "sys_pivot_root()" },
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

/* Check whether the given capability control is enforce mode. */
static unsigned int CheckCapabilityEnforce(const unsigned int index)
{
	return CheckCapabilityFlags(index) == 3;
}

/* Check whether the given capability control is learning mode. */
static unsigned int CheckCapabilityAccept(const unsigned int index, struct domain_info * const domain)
{
	if (CheckCapabilityFlags(index) != 1) return 0;
	return CheckDomainQuota(domain);
}

static struct profile *FindOrAssignNewProfile(const unsigned int profile)
{
	static DECLARE_MUTEX(profile_lock);
	struct profile *ptr = NULL;
	down(&profile_lock);
	if (profile < MAX_PROFILES && (ptr = profile_ptr[profile]) == NULL) {
		if ((ptr = alloc_element(sizeof(*ptr))) != NULL) {
			mb(); /* Avoid out-of-order execution. */
			profile_ptr[profile] = ptr;
		}
	}
	up(&profile_lock);
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

static int AuditCapabilityLog(const unsigned int capability, const int is_granted)
{
	char *buf;
	int len = 64;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_CAPABILITY "%s\n", capability2keyword(capability));
	return WriteAuditLog(buf, is_granted);
}

/*************************  CAPABILITY ACL HANDLER  *************************/

static int AddCapabilityACL(const unsigned int capability, struct domain_info *domain, const struct condition_list *condition, const u8 is_delete)
{
	struct acl_info *ptr;
	int error = -ENOMEM;
	const u16 hash = capability;
	if (!domain) return -EINVAL;
	down(&domain_acl_lock);
	if (!is_delete) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			struct capability_acl_record *new_ptr = (struct capability_acl_record *) ptr;
			if (ptr->type == TYPE_CAPABILITY_ACL && new_ptr->capability == hash && ptr->cond == condition) {
				ptr->is_deleted = 0;
				/* Found. Nothing to do. */
				error = 0;
				break;
			}
			if (ptr->next) {
				ptr = ptr->next;
				continue;
			}
		first_entry: ;
			/* Not found. Append it to the tail. */
			if ((new_ptr = alloc_element(sizeof(*new_ptr))) == NULL) break;
			new_ptr->head.type = TYPE_CAPABILITY_ACL;
			new_ptr->capability = hash;
			new_ptr->head.cond = condition;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
			struct capability_acl_record *ptr2 = (struct capability_acl_record *) ptr;
			if (ptr->type != TYPE_CAPABILITY_ACL || ptr->is_deleted || ptr2->capability != hash || ptr->cond != condition) continue;
			error = DelDomainACL(ptr);
			break;
		}
	}
	up(&domain_acl_lock);
	return error;
}

int CheckCapabilityACL(const unsigned int capability)
{
	struct domain_info * const domain = current->domain_info;
	struct acl_info *ptr;
	const int is_enforce = CheckCapabilityEnforce(capability);
	const u16 hash = capability;
	if (!CheckCapabilityFlags(capability)) return 0;
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		struct capability_acl_record *ptr2 = (struct capability_acl_record *) ptr;
		if (ptr->type != TYPE_CAPABILITY_ACL || ptr->is_deleted || ptr2->capability != hash || CheckCondition(ptr->cond, NULL)) continue;
		AuditCapabilityLog(capability, 1);
		return 0;
	}
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: %s denied for %s\n", GetMSG(is_enforce), capability2name(capability), GetLastName(domain));
	}
	AuditCapabilityLog(capability, 0);
	if (is_enforce) return CheckSupervisor("%s\n" KEYWORD_ALLOW_CAPABILITY "%s\n", domain->domainname->name, capability2keyword(capability));
	if (CheckCapabilityAccept(capability, domain)) AddCapabilityACL(capability, domain, NULL, 0);
	return 0;
}
EXPORT_SYMBOL(CheckCapabilityACL);

int AddCapabilityPolicy(char *data, struct domain_info *domain, const int is_delete)
{
	unsigned int capability;
	const struct condition_list *condition = NULL;
	char *cp = FindConditionPart(data);
	if (cp && (condition = FindOrAssignNewCondition(cp)) == NULL) return -EINVAL;
	for (capability = 0; capability < TOMOYO_MAX_CAPABILITY_INDEX; capability++) {
		if (strcmp(data, capability_control_array[capability].keyword) == 0) {
			return AddCapabilityACL(capability, domain, condition, is_delete);
		}
	}
	return -EINVAL;
}

/***** TOMOYO Linux end. *****/