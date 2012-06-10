/*
 * fs/tomoyo_capability.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.3.1   2006/12/08
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
	unsigned int current_value;
	const char *capability_name;
} capability_control_array[TOMOYO_MAX_CAPABILITY_INDEX] = { /* domain_policy.txt */
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
};

typedef struct {
	unsigned char value[TOMOYO_MAX_CAPABILITY_INDEX];
} PROFILE;

static PROFILE *profile_ptr[MAX_PROFILES];

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
	return sbin_init_started && index < TOMOYO_MAX_CAPABILITY_INDEX && profile < MAX_PROFILES && profile_ptr[profile] ? profile_ptr[profile]->value[index] : 0;
}

/* Check whether the given capability control is enforce mode. */
static unsigned int CheckCapabilityEnforce(const unsigned int index)
{
	return CheckCapabilityFlags(index) == 3;
}

/* Check whether the given capability control is accept mode. */
static unsigned int CheckCapabilityAccept(const unsigned int index)
{
	return CheckCapabilityFlags(index) == 1;
}

static PROFILE *FindOrAssignNewProfile(const unsigned int profile)
{
	static DECLARE_MUTEX(profile_lock);
	PROFILE *ptr = NULL;
	down(&profile_lock);
	if (profile < MAX_PROFILES && (ptr = profile_ptr[profile]) == NULL) {
		if ((ptr = (PROFILE *) alloc_element(sizeof(PROFILE))) != NULL) {
			int i;
			for (i = 0; i < TOMOYO_MAX_CAPABILITY_INDEX; i++) ptr->value[i] = capability_control_array[i].current_value;
			mb(); /* Instead of using spinlock. */
			profile_ptr[profile] = ptr;
		}
	}
	up(&profile_lock);
	return ptr;
}

int SetCapabilityStatus(const char *data, unsigned int value, const unsigned int profile)
{
	int i;
	PROFILE *ptr = FindOrAssignNewProfile(profile);
	if (!ptr) return -EINVAL;
	for (i = 0; i < TOMOYO_MAX_CAPABILITY_INDEX; i++) {
		if (strcmp(data, capability_control_array[i].keyword)) continue;
		if (value > 3) value = 3;
		ptr->value[i] = value;
		return 0;
	}
	return -EINVAL;
}

int ReadCapabilityStatus(IO_BUFFER *head)
{
	int step;
	for (step = head->read_step; step < MAX_PROFILES * TOMOYO_MAX_CAPABILITY_INDEX; step++) {
		const int i = step / TOMOYO_MAX_CAPABILITY_INDEX, j = step % TOMOYO_MAX_CAPABILITY_INDEX;
		const PROFILE *profile = profile_ptr[i];
		head->read_step = step;
		if (!profile) continue;
		if (io_printf(head, "%u-" KEYWORD_MAC_FOR_CAPABILITY "%s=%u\n", i, capability_control_array[j].keyword, profile->value[j])) break;
	}
	return step < MAX_PROFILES * TOMOYO_MAX_CAPABILITY_INDEX ? -ENOMEM : 0;
}

/*************************  AUDIT FUNCTIONS  *************************/

#ifdef CONFIG_TOMOYO_AUDIT
static int AuditCapabilityLog(const unsigned int capability, const int is_granted)
{
	char *buf;
	int len = 64;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_CAPABILITY "%s\n", capability2keyword(capability));
	return WriteAuditLog(buf, is_granted);
}
#else
static inline void AuditCapabilityLog(const unsigned int capability, const int is_granted) {}
#endif

/*************************  CAPABILITY ACL HANDLER  *************************/

static int AddCapabilityACL(const unsigned int capability, struct domain_info *domain, const int is_delete, const struct condition_list *condition)
{
	struct acl_info *ptr;
	int error = -ENOMEM;
	const unsigned int type_hash = MAKE_ACL_TYPE(TYPE_CAPABILITY_ACL) + MAKE_ACL_HASH(capability);
	if (!domain) return -EINVAL;
	down(&domain_acl_lock);
	if (!is_delete) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			CAPABILITY_ACL_RECORD *new_ptr;
			if (ptr->type_hash == type_hash && ptr->cond == condition) {
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
			if ((new_ptr = (CAPABILITY_ACL_RECORD *) alloc_element(sizeof(CAPABILITY_ACL_RECORD))) == NULL) break;
			new_ptr->head.type_hash = type_hash;
			new_ptr->head.cond = condition;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		struct acl_info *prev = NULL;
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; prev = ptr, ptr = ptr->next) {
			if (type_hash != ptr->type_hash || ptr->cond != condition) continue;
			error = DelDomainACL(prev, domain, ptr);
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
	const unsigned int type_hash = MAKE_ACL_TYPE(TYPE_CAPABILITY_ACL) + MAKE_ACL_HASH(capability);
	if (!CheckCapabilityFlags(capability)) return 0;
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type_hash != type_hash || CheckCondition(ptr->cond, NULL)) continue;
		AuditCapabilityLog(capability, 1);
		return 0;
	}
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: %s denied for %s\n", GetMSG(is_enforce), capability2name(capability), GetLastName(domain));
	}
	AuditCapabilityLog(capability, 0);
	if (is_enforce) return CheckSupervisor("%s\n" KEYWORD_ALLOW_CAPABILITY "%s\n", domain->domainname, capability2keyword(capability));
	if (CheckCapabilityAccept(capability)) AddCapabilityACL(capability, domain, 0, NULL);
	return 0;
}

int AddCapabilityPolicy(char *data, struct domain_info *domain, const int is_delete)
{
	unsigned int capability;
	const struct condition_list *condition = NULL;
	char *cp = FindConditionPart(data);
	if (cp && (condition = FindOrAssignNewCondition(cp)) == NULL) return -EINVAL;
	for (capability = 0; capability < TOMOYO_MAX_CAPABILITY_INDEX; capability++) {
		if (strcmp(data, capability_control_array[capability].keyword) == 0) {
			return AddCapabilityACL(capability, domain, is_delete, condition);
		}
	}
	return -EINVAL;
}

EXPORT_SYMBOL(CheckCapabilityACL);

/***** TOMOYO Linux end. *****/
