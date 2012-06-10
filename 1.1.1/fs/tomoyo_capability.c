/*
 * fs/tomoyo_capability.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.1.1   2006/05/15
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

static struct {
	const char *keyword;
	unsigned int current_value;
	const unsigned int max_value;
	const char *capability_name;
} capability_control_array[] = { /* domain_policy.txt */
	{ "inet_tcp_create", 0, 3,    "socket(PF_INET, SOCK_STREAM)" },  // TOMOYO_INET_STREAM_SOCKET_CREATE
	{ "inet_tcp_listen", 0, 3,    "listen(PF_INET, SOCK_STREAM)" },  // TOMOYO_INET_STREAM_SOCKET_LISTEN
	{ "inet_tcp_connect", 0, 3,   "connect(PF_INET, SOCK_STREAM)" }, // TOMOYO_INET_STREAM_SOCKET_CONNECT
	{ "use_inet_udp", 0, 3,       "socket(PF_INET, SOCK_DGRAM)" },   // TOMOYO_USE_INET_DGRAM_SOCKET
	{ "use_inet_ip", 0, 3,        "socket(PF_INET, SOCK_RAW)" },     // TOMOYO_USE_INET_RAW_SOCKET
	{ "use_route", 0, 3,          "socket(PF_ROUTE)" },              // TOMOYO_USE_ROUTE_SOCKET
	{ "use_packet", 0, 3,         "socket(PF_PACKET)" },             // TOMOYO_USE_PACKET_SOCKET
	{ "SYS_MOUNT", 0, 3,          "sys_mount()" },                   // TOMOYO_SYS_MOUNT
	{ "SYS_UMOUNT", 0, 3,         "sys_umount()" },                  // TOMOYO_SYS_UMOUNT
	{ "SYS_REBOOT", 0, 3,         "sys_reboot()" },                  // TOMOYO_SYS_REBOOT
	{ "SYS_CHROOT", 0, 3,         "sys_chroot()" },                  // TOMOYO_SYS_CHROOT
	{ "SYS_KILL", 0, 3,           "sys_kill()" },                    // TOMOYO_SYS_KILL
	{ "SYS_VHANGUP", 0, 3,        "sys_vhangup()" },                 // TOMOYO_SYS_VHANGUP
	{ "SYS_TIME", 0, 3,           "sys_settimeofday()" },            // TOMOYO_SYS_SETTIME
	{ "SYS_NICE", 0, 3,           "sys_nice()" },                    // TOMOYO_SYS_NICE
	{ "SYS_SETHOSTNAME", 0, 3,    "sys_sethostname()" },             // TOMOYO_SYS_SETHOSTNAME
	{ "use_kernel_module", 0, 3,  "kernel_module" },                 // TOMOYO_USE_KERNEL_MODULE
	{ "create_fifo", 0, 3,        "mknod(FIFO)" },                   // TOMOYO_CREATE_FIFO
	{ "create_block_dev", 0, 3,   "mknod(BDEV)" },                   // TOMOYO_CREATE_BLOCK_DEV
	{ "create_char_dev", 0, 3,    "mknod(CDEV)" },                   // TOMOYO_CREATE_CHAR_DEV
	{ "create_unix_socket", 0, 3, "mknod(SOCKET)" },                 // TOMOYO_CREATE_UNIX_SOCKET
	{ "SYS_LINK", 0, 3,           "sys_link()"  },                   // TOMOYO_SYS_LINK
	{ "SYS_SYMLINK", 0, 3,        "sys_symlink()" },                 // TOMOYO_SYS_SYMLINK
	{ "SYS_RENAME", 0, 3,         "sys_rename()" },                  // TOMOYO_SYS_RENAME
	{ "SYS_UNLINK", 0, 3,         "sys_unlink()" },                  // TOMOYO_SYS_UNLINK
	{ "SYS_CHMOD", 0, 3,          "sys_chmod()" },                   // TOMOYO_SYS_CHMOD
	{ "SYS_CHOWN", 0, 3,          "sys_chown()" },                   // TOMOYO_SYS_CHOWN
	{ "SYS_IOCTL", 0, 3,          "sys_ioctl()" },                   // TOMOYO_SYS_IOCTL
	{ NULL, 0, 0, NULL }
};

/*************************  UTILITY FUNCTIONS  *************************/

const char *capability2keyword(const unsigned int capability)
{
	return (capability < sizeof(capability_control_array) / sizeof(capability_control_array[0]))
		? capability_control_array[capability].keyword : NULL;
}

static const char *capability2name(const unsigned int capability)
{
	return (capability < sizeof(capability_control_array) / sizeof(capability_control_array[0]))
		? capability_control_array[capability].capability_name : NULL;
}

static int keyword2capability(const char *data)
{
	int i;
	for (i = 0; capability_control_array[i].keyword; i++) {
		if (strstr(data, capability_control_array[i].keyword)) return i;
	}
	return -1;
}

/* Check whether the given capability control is enabled. */
static unsigned int CheckCapabilityFlags(const unsigned int index)
{
	if (index < (sizeof(capability_control_array) / sizeof(capability_control_array[0])) - 1)
		return capability_control_array[index].current_value;
	printk("%s: Index %u is out of range. Fix the kernel source.\n", __FUNCTION__, index);
	return 0;
}

/* Check whether the given capability control is enforce mode. */
static unsigned int CheckCapabilityEnforce(const unsigned int index)
{
	if (index < (sizeof(capability_control_array) / sizeof(capability_control_array[0])) - 1)
		return capability_control_array[index].current_value == 3;
	printk("%s: Index %u is out of range. Fix the kernel source.\n", __FUNCTION__, index);
	return 0;
}

/* Check whether the given capability control is accept mode. */
static unsigned int CheckCapabilityAccept(const unsigned int index)
{
	if (index < (sizeof(capability_control_array) / sizeof(capability_control_array[0])) - 1)
		return capability_control_array[index].current_value == 1;
	printk("%s: Index %u is out of range. Fix the kernel source.\n", __FUNCTION__, index);
	return 0;
}

int SetCapabilityStatus(const char *data, unsigned int value)
{
	int i;
	for (i = 0; capability_control_array[i].keyword; i++) {
		if (strcmp(data, capability_control_array[i].keyword)) continue;
		if (value > capability_control_array[i].max_value) value = capability_control_array[i].max_value;
		capability_control_array[i].current_value = value;
		break;
	}
	return capability_control_array[i].keyword ? 0 : -EINVAL;
}

int ReadCapabilityStatus(IO_BUFFER *head) {
	int i;
	for (i = head->read_step; capability_control_array[i].keyword; i++) {
		if (io_printf(head, KEYWORD_MAC_FOR_CAPABILITY "%s=%u\n", capability_control_array[i].keyword, capability_control_array[i].current_value)) break;
		head->read_step = i;
	}
	return capability_control_array[i].keyword ? -ENOMEM : 0;
}

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditCapabilityLog(const unsigned int capability, const int is_granted);

/*************************  CAPABILITY ACL HANDLER  *************************/

static int AddCapabilityACL(const unsigned int capability, struct domain_info *domain)
{
	struct acl_info *ptr;
	int error = -ENOMEM;
	const unsigned int type_hash = MAKE_ACL_TYPE(TYPE_CAPABILITY_ACL) + MAKE_ACL_HASH(capability);
	if (!domain) return -EINVAL;
	down(&domain_acl_lock);
	if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
	while (1) {
		if (ptr->type_hash == type_hash) {
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
		{
			CAPABILITY_ACL_RECORD *new_ptr = (CAPABILITY_ACL_RECORD *) alloc_element(sizeof(CAPABILITY_ACL_RECORD));
			if (!new_ptr) break;
			new_ptr->next = NULL;
			new_ptr->type_hash = type_hash;
			mb(); /* Instead of using spinlock. */
			if (!ptr) domain->first_acl_ptr = (struct acl_info *) new_ptr;
			else ptr->next = (struct acl_info *) new_ptr;
		}
		error = 0;
		break;
	}
	up(&domain_acl_lock);
	return error;
}

int CheckCapabilityACL(const unsigned int capability)
{
	struct domain_info * const domain = GetCurrentDomain();
	struct acl_info *ptr;
	const int is_enforce = CheckCapabilityEnforce(capability);
	const unsigned int type_hash = MAKE_ACL_TYPE(TYPE_CAPABILITY_ACL) + MAKE_ACL_HASH(capability);
	if (!CheckCapabilityFlags(capability)) return 0;
	if (domain->attribute & DOMAIN_ATTRIBUTE_TRUSTED) {
		AuditCapabilityLog(capability, 1);
		return 0;
	}
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type_hash != type_hash) continue;
		AuditCapabilityLog(capability, 1);
		return 0;
	}
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: %s denied for %s\n", GetMSG(is_enforce), capability2name(capability), GetLastName(domain));
	}
	AuditCapabilityLog(capability, 0);
	if (is_enforce) return CheckSupervisor("%s\n" KEYWORD_ALLOW_CAPABILITY "%s\n", domain->domainname, capability2keyword(capability));
	if (CheckCapabilityAccept(capability)) AddCapabilityACL(capability, domain);
	return 0;
}

int AddCapabilityPolicy(char *data, void **domain)
{
	int capability;
	if (!isRoot()) return -EPERM;
	if ((capability = keyword2capability(data)) < 0) return -EINVAL;
	AddCapabilityACL((unsigned int) capability, (struct domain_info *) *domain);
	return 0;
}

EXPORT_SYMBOL(CheckCapabilityACL);

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditCapabilityLog(const unsigned int capability, const int is_granted)
{
	char *buf;
	int len;
	struct timeval tv;
	struct task_struct *task = current;
	const char *domainname = task->domain_info->domainname;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	do_gettimeofday(&tv);
	len = strlen(domainname) + 256;
	if ((buf = kzalloc(len, GFP_KERNEL)) == NULL) return -ENOMEM;
	snprintf(buf, len - 1, "#timestamp=%lu pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d\n%s\n" KEYWORD_ALLOW_CAPABILITY "%s\n", tv.tv_sec, task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, domainname, capability2keyword(capability));
	return WriteAuditLog(buf, is_granted);
}

/***** TOMOYO Linux end. *****/
