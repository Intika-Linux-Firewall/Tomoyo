/*
 * fs/tomoyo_capability.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.0 2005/11/11
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>

/***** The structure for capability list. *****/

typedef struct capability_entry {
	struct capability_entry *next; /* Pointer to next record. NULL if none.                            */
	DOMAIN_INFO *domain;           /* Pointer to domain record that this entry applies to. Never NULL. */
	unsigned int capability;       /* Capability.                                                      */
} CAPABILITY_ENTRY;

/*************************  VARIABLES  *************************/

static struct {
	const unsigned int assertion_index;
	const char *keyword;
	unsigned int current_value;
	const unsigned int max_value;
	const char *capability_name;
} capability_control_array[] = { /* domain_policy.txt */
	{ TOMOYO_INET_STREAM_SOCKET_CREATE,  "inet_tcp_create", 0, 3,    "socket(PF_INET, SOCK_STREAM)" },
	{ TOMOYO_INET_STREAM_SOCKET_LISTEN,  "inet_tcp_listen", 0, 3,    "listen(PF_INET, SOCK_STREAM)" },
	{ TOMOYO_INET_STREAM_SOCKET_CONNECT, "inet_tcp_connect", 0, 3,   "connect(PF_INET, SOCK_STREAM)" },
	{ TOMOYO_USE_INET_DGRAM_SOCKET,      "use_inet_udp", 0, 3,       "socket(PF_INET, SOCK_DGRAM)" },
	{ TOMOYO_USE_INET_RAW_SOCKET,        "use_inet_ip", 0, 3,        "socket(PF_INET, SOCK_RAW)" },
	{ TOMOYO_USE_ROUTE_SOCKET,           "use_route", 0, 3,          "socket(PF_ROUTE)" },
	{ TOMOYO_USE_PACKET_SOCKET,          "use_packet", 0, 3,         "socket(PF_PACKET)" },
	{ TOMOYO_SYS_MOUNT,                  "SYS_MOUNT", 0, 3,          "sys_mount()" },
	{ TOMOYO_SYS_UMOUNT,                 "SYS_UMOUNT", 0, 3,         "sys_umount()" },
	{ TOMOYO_SYS_REBOOT,                 "SYS_REBOOT", 0, 3,         "sys_reboot()" },
	{ TOMOYO_SYS_CHROOT,                 "SYS_CHROOT", 0, 3,         "sys_chroot()" },
	{ TOMOYO_SYS_KILL,                   "SYS_KILL", 0, 3,           "sys_kill()" },
	{ TOMOYO_SYS_VHANGUP,                "SYS_VHANGUP", 0, 3,        "sys_vhangup()" },
	{ TOMOYO_SYS_SETTIME,                "SYS_TIME", 0, 3,           "sys_settimeofday()" },
	{ TOMOYO_SYS_NICE,                   "SYS_NICE", 0, 3,           "sys_nice()" },
	{ TOMOYO_SYS_SETHOSTNAME,            "SYS_SETHOSTNAME", 0, 3,    "sys_sethostname()" },
	{ TOMOYO_USE_KERNEL_MODULE,          "use_kernel_module", 0, 3,  "kernel_module" },
	{ TOMOYO_CREATE_FIFO,                "create_fifo", 0, 3,        "mknod(FIFO)" },
	{ TOMOYO_CREATE_BLOCK_DEV,           "create_block_dev", 0, 3,   "mknod(BDEV)" },
	{ TOMOYO_CREATE_CHAR_DEV,            "create_char_dev", 0, 3,    "mknod(CDEV)" },
	{ TOMOYO_CREATE_UNIX_SOCKET,         "create_unix_socket", 0, 3, "mknod(SOCKET)" },
	{ TOMOYO_SYS_LINK,                   "SYS_LINK", 0, 3,           "sys_link()"  },
	{ TOMOYO_SYS_SYMLINK,                "SYS_SYMLINK", 0, 3,        "sys_symlink()" },
	{ TOMOYO_SYS_RENAME,                 "SYS_RENAME", 0, 3,         "sys_rename()" },
	{ TOMOYO_SYS_UNLINK,                 "SYS_UNLINK", 0, 3,         "sys_unlink()" },
	{ TOMOYO_SYS_CHMOD,                  "SYS_CHMOD", 0, 3,          "sys_chmod()" },
	{ TOMOYO_SYS_CHOWN,                  "SYS_CHOWN", 0, 3,          "sys_chown()" },
	{ TOMOYO_SYS_IOCTL,                  "SYS_IOCTL", 0, 3,          "sys_ioctl()" },
	{ 0, NULL, 0, 0, NULL }
};

/*************************  UTILITY FUNCTIONS  *************************/

static void CheckCapabilityList(void) {
	static int first = 1;
	if (first) {
		int i;
		first = 0;
		for (i = 0; capability_control_array[i].keyword; i++) {
			if (capability_control_array[i].assertion_index == i) continue;
			panic("%s: FATAL: Capability array index is broken. Fix the kernel source.\n", __FUNCTION__);
		}
	}
}

static const char *capability2keyword(const unsigned int capability)
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
	CheckCapabilityList();
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
	CheckCapabilityList();
	for (i = 0; capability_control_array[i].keyword; i++) {
		if (strcmp(data, capability_control_array[i].keyword) == 0) {
			if (value > capability_control_array[i].max_value) value = capability_control_array[i].max_value;
			capability_control_array[i].current_value = value;
			break;
		}
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

static CAPABILITY_ENTRY capability_list = { NULL, NULL, 0 };

static int AddCapabilityACL(const unsigned int capability, struct domain_info *domain)
{
	CAPABILITY_ENTRY *new_entry, *ptr;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	if (!domain) {
		printk("%s: ERROR: domain == NULL\n", __FUNCTION__);
		return -EINVAL;
	}
	/* I don't want to add if it was already added. */
	for (ptr = capability_list.next; ptr; ptr = ptr->next) {
		if (ptr->domain == domain && ptr->capability == capability) return 0;
	}
	if ((new_entry = (CAPABILITY_ENTRY *) alloc_element(sizeof(CAPABILITY_ENTRY))) == NULL) return -ENOMEM;
	memset(new_entry, 0, sizeof(CAPABILITY_ENTRY));
	new_entry->next = NULL;
	new_entry->domain = domain;
	new_entry->capability = capability;
	/***** CRITICAL SECTION START *****/
	spin_lock(&lock);
	for (ptr = &capability_list; ptr->next; ptr = ptr->next); ptr->next = new_entry;
	spin_unlock(&lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

int CheckCapabilityACL(const unsigned int capability)
{
	struct domain_info * const domain = GetCurrentDomain();
	CAPABILITY_ENTRY *ptr;
	const int is_enforce = CheckCapabilityEnforce(capability);
	if (!CheckCapabilityFlags(capability)) return 0;
	if (domain->attribute & DOMAIN_ATTRIBUTE_TRUSTED) {
		AuditCapabilityLog(capability, 1);
		return 0;
	}
	for (ptr = capability_list.next; ptr; ptr = ptr->next) {
		if (ptr->domain == domain && ptr->capability == capability) break;
	}
	if (ptr) {
		AuditCapabilityLog(capability, 1);
		return 0;
	}
	if (TomoyoVerboseMode()) {
		printk("TOMOYO-%s: %s denied for %s\n", GetMSG(is_enforce), capability2name(capability), GetLastName(domain));
	}
	AuditCapabilityLog(capability, 0);
	if (is_enforce) return -EPERM;
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

int ReadCapabilityPolicy(IO_BUFFER *head)
{
	struct domain_info *domain = (struct domain_info *) head->read_var1;
	CAPABILITY_ENTRY *ptr = (CAPABILITY_ENTRY *) head->read_var2;
	if (!ptr) ptr = capability_list.next;
	while (ptr) {
		head->read_var2 = (void *) ptr;
		if (domain == ptr->domain) {
			if (io_printf(head, KEYWORD_ALLOW_CAPABILITY "%s\n", capability2keyword(ptr->capability))) break;
		}
		ptr = ptr->next;
	}
	return ptr ? -ENOMEM : 0;
}

EXPORT_SYMBOL(CheckCapabilityACL);

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditCapabilityLog(const unsigned int capability, const int is_granted)
{
	char *buf;
	const struct domain_info *domain = current->domain_info;
	int len;
	struct timeval tv;
	struct task_struct *task = current;
	if (!domain) {
		printk("%s: ERROR: domain == NULL\n", __FUNCTION__);
		return -EINVAL;
	}
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	do_gettimeofday(&tv);
	len = strlen(domain->domainname) + 256;
	if ((buf = kmalloc(len, GFP_KERNEL)) == NULL) return -ENOMEM;
	memset(buf, 0, len);
	snprintf(buf, len - 1, "#timestamp=%lu pid=%d uid=%d gid=%d euid=%d egid=%d suid=%d sgid=%d fsuid=%d fsgid=%d\n%s\n" KEYWORD_ALLOW_CAPABILITY "%s\n", tv.tv_sec, task->pid, task->uid, task->gid, task->euid, task->egid, task->suid, task->sgid, task->fsuid, task->fsgid, domain->domainname, capability2keyword(capability));
	return WriteAuditLog(buf, is_granted);
}

/***** TOMOYO Linux end. *****/
