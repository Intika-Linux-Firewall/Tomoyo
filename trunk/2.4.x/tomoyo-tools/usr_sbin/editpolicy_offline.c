/*
 * editpolicy_offline.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0-pre   2011/06/20
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
#include "tomoyotools.h"
#include "editpolicy.h"
#include <poll.h>

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_for_each_entry(pos, head, member)                          \
        for (pos = list_entry((head)->next, typeof(*pos), member);      \
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

static inline void __list_add(struct list_head *new, struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

#ifndef HIPQUAD
#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr)				\
	((unsigned char *)&addr)[3],		\
		((unsigned char *)&addr)[2],	\
		((unsigned char *)&addr)[1],	\
		((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD(addr)				\
	((unsigned char *)&addr)[0],		\
		((unsigned char *)&addr)[1],	\
		((unsigned char *)&addr)[2],	\
		((unsigned char *)&addr)[3]
#else
#error "Please fix asm/byteorder.h"
#endif /* __LITTLE_ENDIAN */
#endif

#if !defined(NIP6)
#define NIP6(addr)							\
	ntohs((addr).s6_addr16[0]), ntohs((addr).s6_addr16[1]),		\
		ntohs((addr).s6_addr16[2]), ntohs((addr).s6_addr16[3]), \
		ntohs((addr).s6_addr16[4]), ntohs((addr).s6_addr16[5]), \
		ntohs((addr).s6_addr16[6]), ntohs((addr).s6_addr16[7])
#endif

/* Enumeration definition for internal use. */

/* Index numbers for Access Controls. */
enum tomoyo_acl_entry_type_index {
	TOMOYO_TYPE_PATH_ACL,
	TOMOYO_TYPE_PATH2_ACL,
	TOMOYO_TYPE_PATH_NUMBER_ACL,
	TOMOYO_TYPE_MKDEV_ACL,
	TOMOYO_TYPE_MOUNT_ACL,
	TOMOYO_TYPE_ENV_ACL,
	TOMOYO_TYPE_CAPABILITY_ACL,
	TOMOYO_TYPE_INET_ACL,
	TOMOYO_TYPE_UNIX_ACL,
	TOMOYO_TYPE_SIGNAL_ACL,
	TOMOYO_TYPE_AUTO_EXECUTE_HANDLER,
	TOMOYO_TYPE_DENIED_EXECUTE_HANDLER,
	TOMOYO_TYPE_AUTO_TASK_ACL,
	TOMOYO_TYPE_MANUAL_TASK_ACL,
};

/* Index numbers for Capability Controls. */
enum tomoyo_capability_acl_index {
	/* socket(PF_ROUTE, *, *)                                      */
	TOMOYO_USE_ROUTE_SOCKET,
	/* socket(PF_PACKET, *, *)                                     */
	TOMOYO_USE_PACKET_SOCKET,
	/* sys_reboot()                                                */
	TOMOYO_SYS_REBOOT,
	/* sys_vhangup()                                               */
	TOMOYO_SYS_VHANGUP,
	/* do_settimeofday(), sys_adjtimex()                           */
	TOMOYO_SYS_SETTIME,
	/* sys_nice(), sys_setpriority()                               */
	TOMOYO_SYS_NICE,
	/* sys_sethostname(), sys_setdomainname()                      */
	TOMOYO_SYS_SETHOSTNAME,
	/* sys_create_module(), sys_init_module(), sys_delete_module() */
	TOMOYO_USE_KERNEL_MODULE,
	/* sys_kexec_load()                                            */
	TOMOYO_SYS_KEXEC_LOAD,
	/* sys_ptrace()                                                */
	TOMOYO_SYS_PTRACE,
	TOMOYO_MAX_CAPABILITY_INDEX
};

/* Index numbers for "struct tomoyo_condition". */
enum tomoyo_conditions_index {
	TOMOYO_TASK_UID,             /* current_uid()   */
	TOMOYO_TASK_EUID,            /* current_euid()  */
	TOMOYO_TASK_SUID,            /* current_suid()  */
	TOMOYO_TASK_FSUID,           /* current_fsuid() */
	TOMOYO_TASK_GID,             /* current_gid()   */
	TOMOYO_TASK_EGID,            /* current_egid()  */
	TOMOYO_TASK_SGID,            /* current_sgid()  */
	TOMOYO_TASK_FSGID,           /* current_fsgid() */
	TOMOYO_TASK_PID,             /* sys_getpid()   */
	TOMOYO_TASK_PPID,            /* sys_getppid()  */
	TOMOYO_EXEC_ARGC,            /* "struct linux_binprm *"->argc */
	TOMOYO_EXEC_ENVC,            /* "struct linux_binprm *"->envc */
	TOMOYO_TYPE_IS_SOCKET,       /* S_IFSOCK */
	TOMOYO_TYPE_IS_SYMLINK,      /* S_IFLNK */
	TOMOYO_TYPE_IS_FILE,         /* S_IFREG */
	TOMOYO_TYPE_IS_BLOCK_DEV,    /* S_IFBLK */
	TOMOYO_TYPE_IS_DIRECTORY,    /* S_IFDIR */
	TOMOYO_TYPE_IS_CHAR_DEV,     /* S_IFCHR */
	TOMOYO_TYPE_IS_FIFO,         /* S_IFIFO */
	TOMOYO_MODE_SETUID,          /* S_ISUID */
	TOMOYO_MODE_SETGID,          /* S_ISGID */
	TOMOYO_MODE_STICKY,          /* S_ISVTX */
	TOMOYO_MODE_OWNER_READ,      /* S_IRUSR */
	TOMOYO_MODE_OWNER_WRITE,     /* S_IWUSR */
	TOMOYO_MODE_OWNER_EXECUTE,   /* S_IXUSR */
	TOMOYO_MODE_GROUP_READ,      /* S_IRGRP */
	TOMOYO_MODE_GROUP_WRITE,     /* S_IWGRP */
	TOMOYO_MODE_GROUP_EXECUTE,   /* S_IXGRP */
	TOMOYO_MODE_OTHERS_READ,     /* S_IROTH */
	TOMOYO_MODE_OTHERS_WRITE,    /* S_IWOTH */
	TOMOYO_MODE_OTHERS_EXECUTE,  /* S_IXOTH */
	TOMOYO_TASK_TYPE,            /* ((u8) task->tomoyo_flags) &
					TOMOYO_TASK_IS_EXECUTE_HANDLER */
	TOMOYO_TASK_EXECUTE_HANDLER, /* TOMOYO_TASK_IS_EXECUTE_HANDLER */
	TOMOYO_EXEC_REALPATH,
	TOMOYO_SYMLINK_TARGET,
	TOMOYO_PATH1_UID,
	TOMOYO_PATH1_GID,
	TOMOYO_PATH1_INO,
	TOMOYO_PATH1_MAJOR,
	TOMOYO_PATH1_MINOR,
	TOMOYO_PATH1_PERM,
	TOMOYO_PATH1_TYPE,
	TOMOYO_PATH1_DEV_MAJOR,
	TOMOYO_PATH1_DEV_MINOR,
	TOMOYO_PATH2_UID,
	TOMOYO_PATH2_GID,
	TOMOYO_PATH2_INO,
	TOMOYO_PATH2_MAJOR,
	TOMOYO_PATH2_MINOR,
	TOMOYO_PATH2_PERM,
	TOMOYO_PATH2_TYPE,
	TOMOYO_PATH2_DEV_MAJOR,
	TOMOYO_PATH2_DEV_MINOR,
	TOMOYO_PATH1_PARENT_UID,
	TOMOYO_PATH1_PARENT_GID,
	TOMOYO_PATH1_PARENT_INO,
	TOMOYO_PATH1_PARENT_PERM,
	TOMOYO_PATH2_PARENT_UID,
	TOMOYO_PATH2_PARENT_GID,
	TOMOYO_PATH2_PARENT_INO,
	TOMOYO_PATH2_PARENT_PERM,
	TOMOYO_MAX_CONDITION_KEYWORD,
	TOMOYO_NUMBER_UNION,
	TOMOYO_NAME_UNION,
	TOMOYO_ARGV_ENTRY,
	TOMOYO_ENVP_ENTRY,
};

/* Index numbers for domain's attributes. */
enum tomoyo_domain_info_flags_index {
	/* Quota warnning flag.   */
	TOMOYO_DIF_QUOTA_WARNED,
	/*
	 * This domain was unable to create a new domain at
	 * tomoyo_find_next_domain() because the name of the domain to be
	 * created was too long or it could not allocate memory.
	 * More than one process continued execve() without domain transition.
	 */
	TOMOYO_DIF_TRANSITION_FAILED,
	TOMOYO_MAX_DOMAIN_INFO_FLAGS
};

/* Index numbers for audit type. */
enum tomoyo_grant_log {
	/* Follow profile's configuration. */
	TOMOYO_GRANTLOG_AUTO,
	/* Do not generate grant log. */
	TOMOYO_GRANTLOG_NO,
	/* Generate grant_log. */
	TOMOYO_GRANTLOG_YES,
};

/* Index numbers for group entries. */
enum tomoyo_group_id {
	TOMOYO_PATH_GROUP,
	TOMOYO_NUMBER_GROUP,
	TOMOYO_ADDRESS_GROUP,
	TOMOYO_MAX_GROUP
};

/* Index numbers for category of functionality. */
enum tomoyo_mac_category_index {
	TOMOYO_MAC_CATEGORY_FILE,
	TOMOYO_MAC_CATEGORY_NETWORK,
	TOMOYO_MAC_CATEGORY_MISC,
	TOMOYO_MAC_CATEGORY_IPC,
	TOMOYO_MAC_CATEGORY_CAPABILITY,
	TOMOYO_MAX_MAC_CATEGORY_INDEX
};

/* Index numbers for functionality. */
enum tomoyo_mac_index {
	TOMOYO_MAC_FILE_EXECUTE,
	TOMOYO_MAC_FILE_OPEN,
	TOMOYO_MAC_FILE_CREATE,
	TOMOYO_MAC_FILE_UNLINK,
	TOMOYO_MAC_FILE_GETATTR,
	TOMOYO_MAC_FILE_MKDIR,
	TOMOYO_MAC_FILE_RMDIR,
	TOMOYO_MAC_FILE_MKFIFO,
	TOMOYO_MAC_FILE_MKSOCK,
	TOMOYO_MAC_FILE_TRUNCATE,
	TOMOYO_MAC_FILE_SYMLINK,
	TOMOYO_MAC_FILE_MKBLOCK,
	TOMOYO_MAC_FILE_MKCHAR,
	TOMOYO_MAC_FILE_LINK,
	TOMOYO_MAC_FILE_RENAME,
	TOMOYO_MAC_FILE_CHMOD,
	TOMOYO_MAC_FILE_CHOWN,
	TOMOYO_MAC_FILE_CHGRP,
	TOMOYO_MAC_FILE_IOCTL,
	TOMOYO_MAC_FILE_CHROOT,
	TOMOYO_MAC_FILE_MOUNT,
	TOMOYO_MAC_FILE_UMOUNT,
	TOMOYO_MAC_FILE_PIVOT_ROOT,
	TOMOYO_MAC_NETWORK_INET_STREAM_BIND,
	TOMOYO_MAC_NETWORK_INET_STREAM_LISTEN,
	TOMOYO_MAC_NETWORK_INET_STREAM_CONNECT,
	TOMOYO_MAC_NETWORK_INET_STREAM_ACCEPT,
	TOMOYO_MAC_NETWORK_INET_DGRAM_BIND,
	TOMOYO_MAC_NETWORK_INET_DGRAM_SEND,
	TOMOYO_MAC_NETWORK_INET_DGRAM_RECV,
	TOMOYO_MAC_NETWORK_INET_RAW_BIND,
	TOMOYO_MAC_NETWORK_INET_RAW_SEND,
	TOMOYO_MAC_NETWORK_INET_RAW_RECV,
	TOMOYO_MAC_NETWORK_UNIX_STREAM_BIND,
	TOMOYO_MAC_NETWORK_UNIX_STREAM_LISTEN,
	TOMOYO_MAC_NETWORK_UNIX_STREAM_CONNECT,
	TOMOYO_MAC_NETWORK_UNIX_STREAM_ACCEPT,
	TOMOYO_MAC_NETWORK_UNIX_DGRAM_BIND,
	TOMOYO_MAC_NETWORK_UNIX_DGRAM_SEND,
	TOMOYO_MAC_NETWORK_UNIX_DGRAM_RECV,
	TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_BIND,
	TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_LISTEN,
	TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_CONNECT,
	TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT,
	TOMOYO_MAC_ENVIRON,
	TOMOYO_MAC_SIGNAL,
	TOMOYO_MAC_CAPABILITY_USE_ROUTE_SOCKET,
	TOMOYO_MAC_CAPABILITY_USE_PACKET_SOCKET,
	TOMOYO_MAC_CAPABILITY_SYS_REBOOT,
	TOMOYO_MAC_CAPABILITY_SYS_VHANGUP,
	TOMOYO_MAC_CAPABILITY_SYS_SETTIME,
	TOMOYO_MAC_CAPABILITY_SYS_NICE,
	TOMOYO_MAC_CAPABILITY_SYS_SETHOSTNAME,
	TOMOYO_MAC_CAPABILITY_USE_KERNEL_MODULE,
	TOMOYO_MAC_CAPABILITY_SYS_KEXEC_LOAD,
	TOMOYO_MAC_CAPABILITY_SYS_PTRACE,
	TOMOYO_MAX_MAC_INDEX
};

/* Index numbers for /proc/tomoyo/stat interface. */
enum tomoyo_memory_stat_type {
	TOMOYO_MEMORY_POLICY,
	TOMOYO_MEMORY_AUDIT,
	TOMOYO_MEMORY_QUERY,
	TOMOYO_MAX_MEMORY_STAT
};

/* Index numbers for access controls with one pathname and three numbers. */
enum tomoyo_mkdev_acl_index {
	TOMOYO_TYPE_MKBLOCK,
	TOMOYO_TYPE_MKCHAR,
	TOMOYO_MAX_MKDEV_OPERATION
};

/* Index numbers for operation mode. */
enum tomoyo_mode_value {
	TOMOYO_CONFIG_DISABLED,
	TOMOYO_CONFIG_LEARNING,
	TOMOYO_CONFIG_PERMISSIVE,
	TOMOYO_CONFIG_ENFORCING,
	TOMOYO_CONFIG_MAX_MODE,
	TOMOYO_CONFIG_WANT_REJECT_LOG =  64,
	TOMOYO_CONFIG_WANT_GRANT_LOG  = 128,
	TOMOYO_CONFIG_USE_DEFAULT     = 255,
};

/* Index numbers for socket operations. */
enum tomoyo_network_acl_index {
	TOMOYO_NETWORK_BIND,    /* bind() operation. */
	TOMOYO_NETWORK_LISTEN,  /* listen() operation. */
	TOMOYO_NETWORK_CONNECT, /* connect() operation. */
	TOMOYO_NETWORK_ACCEPT,  /* accept() operation. */
	TOMOYO_NETWORK_SEND,    /* send() operation. */
	TOMOYO_NETWORK_RECV,    /* recv() operation. */
	TOMOYO_MAX_NETWORK_OPERATION
};

/* Index numbers for access controls with two pathnames. */
enum tomoyo_path2_acl_index {
	TOMOYO_TYPE_LINK,
	TOMOYO_TYPE_RENAME,
	TOMOYO_TYPE_PIVOT_ROOT,
	TOMOYO_MAX_PATH2_OPERATION
};

/* Index numbers for access controls with one pathname. */
enum tomoyo_path_acl_index {
	TOMOYO_TYPE_EXECUTE,
	TOMOYO_TYPE_READ,
	TOMOYO_TYPE_WRITE,
	TOMOYO_TYPE_APPEND,
	TOMOYO_TYPE_UNLINK,
	TOMOYO_TYPE_GETATTR,
	TOMOYO_TYPE_RMDIR,
	TOMOYO_TYPE_TRUNCATE,
	TOMOYO_TYPE_SYMLINK,
	TOMOYO_TYPE_CHROOT,
	TOMOYO_TYPE_UMOUNT,
	TOMOYO_MAX_PATH_OPERATION
};

/* Index numbers for access controls with one pathname and one number. */
enum tomoyo_path_number_acl_index {
	TOMOYO_TYPE_CREATE,
	TOMOYO_TYPE_MKDIR,
	TOMOYO_TYPE_MKFIFO,
	TOMOYO_TYPE_MKSOCK,
	TOMOYO_TYPE_IOCTL,
	TOMOYO_TYPE_CHMOD,
	TOMOYO_TYPE_CHOWN,
	TOMOYO_TYPE_CHGRP,
	TOMOYO_MAX_PATH_NUMBER_OPERATION
};

/* Index numbers for stat(). */
enum tomoyo_path_stat_index {
	/* Do not change this order. */
	TOMOYO_PATH1,
	TOMOYO_PATH1_PARENT,
	TOMOYO_PATH2,
	TOMOYO_PATH2_PARENT,
	TOMOYO_MAX_PATH_STAT
};

/* Index numbers for /proc/tomoyo/stat interface. */
enum tomoyo_policy_stat_type {
	/* Do not change this order. */
	TOMOYO_STAT_POLICY_UPDATES,
	TOMOYO_STAT_POLICY_LEARNING,   /* == TOMOYO_CONFIG_LEARNING */
	TOMOYO_STAT_POLICY_PERMISSIVE, /* == TOMOYO_CONFIG_PERMISSIVE */
	TOMOYO_STAT_POLICY_ENFORCING,  /* == TOMOYO_CONFIG_ENFORCING */
	TOMOYO_MAX_POLICY_STAT
};

/* Index numbers for profile's PREFERENCE values. */
enum tomoyo_pref_index {
	TOMOYO_PREF_MAX_AUDIT_LOG,
	TOMOYO_PREF_MAX_LEARNING_ENTRY,
	TOMOYO_PREF_ENFORCING_PENALTY,
	TOMOYO_MAX_PREF
};

/* Index numbers for /proc/tomoyo/ interfaces. */
enum tomoyo_proc_interface_index {
	TOMOYO_DOMAINPOLICY,
	TOMOYO_EXCEPTIONPOLICY,
	TOMOYO_DOMAIN_STATUS,
	TOMOYO_PROCESS_STATUS,
	TOMOYO_STAT,
	TOMOYO_AUDIT,
	TOMOYO_VERSION,
	TOMOYO_PROFILE,
	TOMOYO_QUERY,
	TOMOYO_MANAGER,
	TOMOYO_EXECUTE_HANDLER,
};

/* Index numbers for special mount operations. */
enum tomoyo_special_mount {
	TOMOYO_MOUNT_BIND,            /* mount --bind /source /dest   */
	TOMOYO_MOUNT_MOVE,            /* mount --move /old /new       */
	TOMOYO_MOUNT_REMOUNT,         /* mount -o remount /dir        */
	TOMOYO_MOUNT_MAKE_UNBINDABLE, /* mount --make-unbindable /dir */
	TOMOYO_MOUNT_MAKE_PRIVATE,    /* mount --make-private /dir    */
	TOMOYO_MOUNT_MAKE_SLAVE,      /* mount --make-slave /dir      */
	TOMOYO_MOUNT_MAKE_SHARED,     /* mount --make-shared /dir     */
	TOMOYO_MAX_SPECIAL_MOUNT
};

/* Index numbers for type of numeric values. */
enum tomoyo_value_type {
	TOMOYO_VALUE_TYPE_INVALID,
	TOMOYO_VALUE_TYPE_DECIMAL,
	TOMOYO_VALUE_TYPE_OCTAL,
	TOMOYO_VALUE_TYPE_HEXADECIMAL,
};

/* Constants definition for internal use. */

/*
 * TOMOYO uses this hash only when appending a string into the string table.
 * Frequency of appending strings is very low. So we don't need large (e.g.
 * 64k) hash size. 256 will be sufficient.
 */
#define TOMOYO_HASH_BITS 8
#define TOMOYO_MAX_HASH (1u << TOMOYO_HASH_BITS)

/*
 * TOMOYO checks only SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET.
 * Therefore, we don't need SOCK_MAX.
 */
#define TOMOYO_SOCK_MAX 6

/* Size of temporary buffer for execve() operation. */
#define TOMOYO_EXEC_TMPSIZE     4096

/* Profile number is an integer between 0 and 255. */
#define TOMOYO_MAX_PROFILES 256

/* Group number is an integer between 0 and 255. */
#define TOMOYO_MAX_ACL_GROUPS 256

/* Structure definition for internal use. */

struct tomoyo_policy_namespace;

/* Common header for holding ACL entries. */
struct tomoyo_acl_head {
	struct list_head list;
	bool is_deleted;
} __attribute__((__packed__));

/* Common header for shared entries. */
struct tomoyo_shared_acl_head {
	struct list_head list;
	unsigned int users;
} __attribute__((__packed__));

/* Common header for individual entries. */
struct tomoyo_acl_info {
	struct list_head list;
	struct tomoyo_condition *cond; /* Maybe NULL. */
	bool is_deleted;
	u8 type; /* One of values in "enum tomoyo_acl_entry_type_index". */
} __attribute__((__packed__));

/* Structure for holding a word. */
struct tomoyo_name_union {
	/* Either @filename or @group is NULL. */
	const struct tomoyo_path_info *filename;
	struct tomoyo_group *group;
};

/* Structure for holding a number. */
struct tomoyo_number_union {
	unsigned long values[2];
	struct tomoyo_group *group; /* Maybe NULL. */
	/* One of values in "enum tomoyo_value_type". */
	u8 value_type[2];
};

/* Structure for holding an IP address. */
struct tomoyo_ipaddr_union {
	/*
	 * Big endian if storing IPv6 address range.
	 * Host endian if storing IPv4 address range.
	 */
	struct in6_addr ip[2];
	/* Pointer to address group. */
	struct tomoyo_group *group;
	bool is_ipv6; /* Valid only if @group == NULL. */
};

/* Structure for "path_group"/"number_group"/"address_group" directive. */
struct tomoyo_group {
	struct tomoyo_shared_acl_head head;
	struct tomoyo_policy_namespace *ns;
	/* Name of group (without leading '@'). */
	const struct tomoyo_path_info *group_name;
	/*
	 * List of "struct tomoyo_path_group" or "struct tomoyo_number_group"
	 * or "struct tomoyo_address_group".
	 */
	struct list_head member_list;
};

/* Structure for "path_group" directive. */
struct tomoyo_path_group {
	struct tomoyo_acl_head head;
	const struct tomoyo_path_info *member_name;
};

/* Structure for "number_group" directive. */
struct tomoyo_number_group {
	struct tomoyo_acl_head head;
	struct tomoyo_number_union number;
};

/* Structure for "address_group" directive. */
struct tomoyo_address_group {
	struct tomoyo_acl_head head;
	/* Structure for holding an IP address. */
	struct tomoyo_ipaddr_union address;
};

/* Structure for entries which follows "struct tomoyo_condition". */
struct tomoyo_condition_element {
	/*
	 * Left hand operand. A "struct tomoyo_argv" for TOMOYO_ARGV_ENTRY, a
	 * "struct tomoyo_envp" for TOMOYO_ENVP_ENTRY is attached to the tail
	 * of the array of this struct.
	 */
	u8 left;
	/*
	 * Right hand operand. A "struct tomoyo_number_union" for
	 * TOMOYO_NUMBER_UNION, a "struct tomoyo_name_union" for
	 * TOMOYO_NAME_UNION is attached to the tail of the array of this
	 * struct.
	 */
	u8 right;
	/* Equation operator. True if equals or overlaps, false otherwise. */
	bool equals;
};

/* Structure for optional arguments. */
struct tomoyo_condition {
	struct tomoyo_shared_acl_head head;
	u32 size; /* Memory size allocated for this entry. */
	u16 condc; /* Number of conditions in this struct. */
	u16 numbers_count; /* Number of "struct tomoyo_number_union values". */
	u16 names_count; /* Number of "struct tomoyo_name_union names". */
	u16 argc; /* Number of "struct tomoyo_argv". */
	u16 envc; /* Number of "struct tomoyo_envp". */
	u8 grant_log; /* One of values in "enum tomoyo_grant_log". */
	const struct tomoyo_path_info *transit; /* Maybe NULL. */
	/*
	 * struct tomoyo_condition_element condition[condc];
	 * struct tomoyo_number_union values[numbers_count];
	 * struct tomoyo_name_union names[names_count];
	 * struct tomoyo_argv argv[argc];
	 * struct tomoyo_envp envp[envc];
	 */
};

/*
 * Structure for "reset_domain"/"no_reset_domain"/"initialize_domain"/
 * "no_initialize_domain"/"keep_domain"/"no_keep_domain" keyword.
 */
struct tomoyo_transition_control {
	struct tomoyo_acl_head head;
	u8 type; /* One of values in "enum tomoyo_transition_type" */
	bool is_last_name; /* True if the domainname is tomoyo_last_word(). */
	const struct tomoyo_path_info *domainname; /* Maybe NULL */
	const struct tomoyo_path_info *program;    /* Maybe NULL */
	struct tomoyo_policy_namespace *ns;
};

/* Structure for "aggregator" keyword. */
struct tomoyo_aggregator {
	struct tomoyo_acl_head head;
	const struct tomoyo_path_info *original_name;
	const struct tomoyo_path_info *aggregated_name;
	struct tomoyo_policy_namespace *ns;
};

/* Structure for "deny_autobind" keyword. */
struct tomoyo_reserved {
	struct tomoyo_acl_head head;
	struct tomoyo_number_union port;
	struct tomoyo_policy_namespace *ns;
};

/* Structure for policy manager. */
struct tomoyo_manager {
	struct tomoyo_acl_head head;
	bool is_domain;  /* True if manager is a domainname. */
	/* A path to program or a domainname. */
	const struct tomoyo_path_info *manager;
};

/* Structure for argv[]. */
struct tomoyo_argv {
	unsigned long index;
	const struct tomoyo_path_info *value;
	bool is_not;
};

/* Structure for envp[]. */
struct tomoyo_envp {
	const struct tomoyo_path_info *name;
	const struct tomoyo_path_info *value;
	bool is_not;
};

/*
 * Structure for "task auto_execute_handler" and "task denied_execute_handler"
 * directive.
 *
 * If "task auto_execute_handler" directive exists and the current process is
 * not an execute handler, all execve() requests are replaced by execve()
 * requests of a program specified by "task auto_execute_handler" directive.
 * If the current process is an execute handler, "task auto_execute_handler"
 * and "task denied_execute_handler" directives are ignored.
 * The program specified by "task execute_handler" validates execve()
 * parameters and executes the original execve() requests if appropriate.
 *
 * "task denied_execute_handler" directive is used only when execve() request
 * was rejected in enforcing mode (i.e. CONFIG::file::execute={ mode=enforcing
 * }). The program specified by "task denied_execute_handler" does whatever it
 * wants to do (e.g. silently terminate, change firewall settings, redirect the
 * user to honey pot etc.).
 */
struct tomoyo_handler_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_*_EXECUTE_HANDLER */
	/* Pointer to single pathname.  */
	const struct tomoyo_path_info *handler;
};

/*
 * Structure for "task auto_domain_transition" and
 * "task manual_domain_transition" directive.
 */
struct tomoyo_task_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_*_TASK_ACL */
	/* Pointer to domainname. */
	const struct tomoyo_path_info *domainname;
};

/*
 * Structure for "file execute", "file read", "file write", "file append",
 * "file unlink", "file getattr", "file rmdir", "file truncate",
 * "file symlink", "file chroot" and "file unmount" directive.
 */
struct tomoyo_path_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_PATH_ACL */
	u16 perm; /* Bitmask of values in "enum tomoyo_path_acl_index". */
	struct tomoyo_name_union name;
};

/*
 * Structure for "file rename", "file link" and "file pivot_root" directive.
 */
struct tomoyo_path2_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_PATH2_ACL */
	u8 perm; /* Bitmask of values in "enum tomoyo_path2_acl_index". */
	struct tomoyo_name_union name1;
	struct tomoyo_name_union name2;
};

/*
 * Structure for "file create", "file mkdir", "file mkfifo", "file mksock",
 * "file ioctl", "file chmod", "file chown" and "file chgrp" directive.
 */
struct tomoyo_path_number_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_PATH_NUMBER_ACL */
	/* Bitmask of values in "enum tomoyo_path_number_acl_index". */
	u8 perm;
	struct tomoyo_name_union name;
	struct tomoyo_number_union number;
};

/* Structure for "file mkblock" and "file mkchar" directive. */
struct tomoyo_mkdev_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_MKDEV_ACL */
	u8 perm; /* Bitmask of values in "enum tomoyo_mkdev_acl_index". */
	struct tomoyo_name_union name;
	struct tomoyo_number_union mode;
	struct tomoyo_number_union major;
	struct tomoyo_number_union minor;
};

/* Structure for "file mount" directive. */
struct tomoyo_mount_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_MOUNT_ACL */
	struct tomoyo_name_union dev_name;
	struct tomoyo_name_union dir_name;
	struct tomoyo_name_union fs_type;
	struct tomoyo_number_union flags;
};

/* Structure for "misc env" directive in domain policy. */
struct tomoyo_env_acl {
	struct tomoyo_acl_info head;        /* type = TOMOYO_TYPE_ENV_ACL  */
	const struct tomoyo_path_info *env; /* environment variable */
};

/* Structure for "capability" directive. */
struct tomoyo_capability_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_CAPABILITY_ACL */
	/* One of values in "enum tomoyo_capability_acl_index". */
	u8 operation;
};

/* Structure for "ipc signal" directive. */
struct tomoyo_signal_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_SIGNAL_ACL */
	struct tomoyo_number_union sig;
	/* Pointer to destination pattern. */
	const struct tomoyo_path_info *domainname;
};

/* Structure for "network inet" directive. */
struct tomoyo_inet_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_INET_ACL */
	u8 protocol;
	u8 perm; /* Bitmask of values in "enum tomoyo_network_acl_index" */
	struct tomoyo_ipaddr_union address;
	struct tomoyo_number_union port;
};

/* Structure for "network unix" directive. */
struct tomoyo_unix_acl {
	struct tomoyo_acl_info head; /* type = TOMOYO_TYPE_UNIX_ACL */
	u8 protocol;
	u8 perm; /* Bitmask of values in "enum tomoyo_network_acl_index" */
	struct tomoyo_name_union name;
};

/* Structure for holding string data. */
struct tomoyo_name {
	struct tomoyo_shared_acl_head head;
	int size; /* Memory size allocated for this entry. */
	struct tomoyo_path_info entry;
};

/* Structure for holding a line from /proc/tomoyo/ interface. */
struct tomoyo_acl_param {
	char *namespace;
	char *data; /* Unprocessed data. */
	struct list_head *list; /* List to add or remove. */
	struct tomoyo_policy_namespace *ns; /* Namespace to use. */
	bool is_delete; /* True if it is a delete request. */
};

/* Structure for /proc/tomoyo/profile interface. */
struct tomoyo_profile {
	const struct tomoyo_path_info *comment;
	u8 default_config;
	u8 config[TOMOYO_MAX_MAC_INDEX + TOMOYO_MAX_MAC_CATEGORY_INDEX];
	unsigned int pref[TOMOYO_MAX_PREF];
};

/* Structure for representing YYYY/MM/DD hh/mm/ss. */
struct tomoyo_time {
	u16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 min;
	u8 sec;
};

/* Structure for policy namespace. */
struct tomoyo_policy_namespace {
	/* Profile table. Memory is allocated as needed. */
	struct tomoyo_profile *profile_ptr[TOMOYO_MAX_PROFILES];
	/* The global ACL referred by "use_group" keyword. */
	struct list_head acl_group[TOMOYO_MAX_ACL_GROUPS];
	/* List for connecting to tomoyo_namespace_list list. */
	struct list_head namespace_list;
	/* Profile version. Currently only 20100903 is defined. */
	unsigned int profile_version;
	/* Name of this namespace (e.g. "<kernel>", "</usr/sbin/httpd>" ). */
	const char *name;
};

struct tomoyo_domain2_info {
	struct list_head list;
	struct list_head acl_info_list;
	/* Name of this domain. Never NULL.          */
	const struct tomoyo_path_info *domainname;
	u8 profile;        /* Profile number to use. */
	u8 group;          /* Group number to use.   */
	bool is_deleted;   /* Delete flag.           */
	bool flags[TOMOYO_MAX_DOMAIN_INFO_FLAGS];
};

struct tomoyo_io_buffer {
	char *data;
	struct tomoyo_policy_namespace *ns;
	struct tomoyo_domain2_info *domain;
	struct tomoyo_domain2_info *print_this_domain_only;
	bool is_delete;
	bool print_transition_related_only;
	bool eof;
	bool reset;
	u8 type;
	u8 acl_group_index;
};

/* String table for operation mode. */
static const char * const tomoyo_mode[TOMOYO_CONFIG_MAX_MODE] = {
	[TOMOYO_CONFIG_DISABLED]   = "disabled",
	[TOMOYO_CONFIG_LEARNING]   = "learning",
	[TOMOYO_CONFIG_PERMISSIVE] = "permissive",
	[TOMOYO_CONFIG_ENFORCING]  = "enforcing"
};

/* String table for /proc/tomoyo/profile interface. */
static const char * const tomoyo_mac_keywords[TOMOYO_MAX_MAC_INDEX
					      + TOMOYO_MAX_MAC_CATEGORY_INDEX]
= {
	/* CONFIG::file group */
	[TOMOYO_MAC_FILE_EXECUTE]    = "execute",
	[TOMOYO_MAC_FILE_OPEN]       = "open",
	[TOMOYO_MAC_FILE_CREATE]     = "create",
	[TOMOYO_MAC_FILE_UNLINK]     = "unlink",
	[TOMOYO_MAC_FILE_GETATTR]    = "getattr",
	[TOMOYO_MAC_FILE_MKDIR]      = "mkdir",
	[TOMOYO_MAC_FILE_RMDIR]      = "rmdir",
	[TOMOYO_MAC_FILE_MKFIFO]     = "mkfifo",
	[TOMOYO_MAC_FILE_MKSOCK]     = "mksock",
	[TOMOYO_MAC_FILE_TRUNCATE]   = "truncate",
	[TOMOYO_MAC_FILE_SYMLINK]    = "symlink",
	[TOMOYO_MAC_FILE_MKBLOCK]    = "mkblock",
	[TOMOYO_MAC_FILE_MKCHAR]     = "mkchar",
	[TOMOYO_MAC_FILE_LINK]       = "link",
	[TOMOYO_MAC_FILE_RENAME]     = "rename",
	[TOMOYO_MAC_FILE_CHMOD]      = "chmod",
	[TOMOYO_MAC_FILE_CHOWN]      = "chown",
	[TOMOYO_MAC_FILE_CHGRP]      = "chgrp",
	[TOMOYO_MAC_FILE_IOCTL]      = "ioctl",
	[TOMOYO_MAC_FILE_CHROOT]     = "chroot",
	[TOMOYO_MAC_FILE_MOUNT]      = "mount",
	[TOMOYO_MAC_FILE_UMOUNT]     = "unmount",
	[TOMOYO_MAC_FILE_PIVOT_ROOT] = "pivot_root",
	/* CONFIG::misc group */
	[TOMOYO_MAC_ENVIRON] = "env",
	/* CONFIG::network group */
	[TOMOYO_MAC_NETWORK_INET_STREAM_BIND]       = "inet_stream_bind",
	[TOMOYO_MAC_NETWORK_INET_STREAM_LISTEN]     = "inet_stream_listen",
	[TOMOYO_MAC_NETWORK_INET_STREAM_CONNECT]    = "inet_stream_connect",
	[TOMOYO_MAC_NETWORK_INET_STREAM_ACCEPT]     = "inet_stream_accept",
	[TOMOYO_MAC_NETWORK_INET_DGRAM_BIND]        = "inet_dgram_bind",
	[TOMOYO_MAC_NETWORK_INET_DGRAM_SEND]        = "inet_dgram_send",
	[TOMOYO_MAC_NETWORK_INET_DGRAM_RECV]        = "inet_dgram_recv",
	[TOMOYO_MAC_NETWORK_INET_RAW_BIND]          = "inet_raw_bind",
	[TOMOYO_MAC_NETWORK_INET_RAW_SEND]          = "inet_raw_send",
	[TOMOYO_MAC_NETWORK_INET_RAW_RECV]          = "inet_raw_recv",
	[TOMOYO_MAC_NETWORK_UNIX_STREAM_BIND]       = "unix_stream_bind",
	[TOMOYO_MAC_NETWORK_UNIX_STREAM_LISTEN]     = "unix_stream_listen",
	[TOMOYO_MAC_NETWORK_UNIX_STREAM_CONNECT]    = "unix_stream_connect",
	[TOMOYO_MAC_NETWORK_UNIX_STREAM_ACCEPT]     = "unix_stream_accept",
	[TOMOYO_MAC_NETWORK_UNIX_DGRAM_BIND]        = "unix_dgram_bind",
	[TOMOYO_MAC_NETWORK_UNIX_DGRAM_SEND]        = "unix_dgram_send",
	[TOMOYO_MAC_NETWORK_UNIX_DGRAM_RECV]        = "unix_dgram_recv",
	[TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_BIND]    = "unix_seqpacket_bind",
	[TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_LISTEN]  = "unix_seqpacket_listen",
	[TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_CONNECT] = "unix_seqpacket_connect",
	[TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT]  = "unix_seqpacket_accept",
	/* CONFIG::ipc group */
	[TOMOYO_MAC_SIGNAL] = "signal",
	/* CONFIG::capability group */
	[TOMOYO_MAC_CAPABILITY_USE_ROUTE_SOCKET]  = "use_route",
	[TOMOYO_MAC_CAPABILITY_USE_PACKET_SOCKET] = "use_packet",
	[TOMOYO_MAC_CAPABILITY_SYS_REBOOT]        = "SYS_REBOOT",
	[TOMOYO_MAC_CAPABILITY_SYS_VHANGUP]       = "SYS_VHANGUP",
	[TOMOYO_MAC_CAPABILITY_SYS_SETTIME]       = "SYS_TIME",
	[TOMOYO_MAC_CAPABILITY_SYS_NICE]          = "SYS_NICE",
	[TOMOYO_MAC_CAPABILITY_SYS_SETHOSTNAME]   = "SYS_SETHOSTNAME",
	[TOMOYO_MAC_CAPABILITY_USE_KERNEL_MODULE] = "use_kernel_module",
	[TOMOYO_MAC_CAPABILITY_SYS_KEXEC_LOAD]    = "SYS_KEXEC_LOAD",
	[TOMOYO_MAC_CAPABILITY_SYS_PTRACE]        = "SYS_PTRACE",
	/* CONFIG group */
	[TOMOYO_MAX_MAC_INDEX + TOMOYO_MAC_CATEGORY_FILE]       = "file",
	[TOMOYO_MAX_MAC_INDEX + TOMOYO_MAC_CATEGORY_NETWORK]    = "network",
	[TOMOYO_MAX_MAC_INDEX + TOMOYO_MAC_CATEGORY_MISC]       = "misc",
	[TOMOYO_MAX_MAC_INDEX + TOMOYO_MAC_CATEGORY_IPC]        = "ipc",
	[TOMOYO_MAX_MAC_INDEX + TOMOYO_MAC_CATEGORY_CAPABILITY] = "capability",
};

/* String table for path operation. */
static const char * const tomoyo_path_keyword[TOMOYO_MAX_PATH_OPERATION] = {
	[TOMOYO_TYPE_EXECUTE]    = "execute",
	[TOMOYO_TYPE_READ]       = "read",
	[TOMOYO_TYPE_WRITE]      = "write",
	[TOMOYO_TYPE_APPEND]     = "append",
	[TOMOYO_TYPE_UNLINK]     = "unlink",
	[TOMOYO_TYPE_GETATTR]    = "getattr",
	[TOMOYO_TYPE_RMDIR]      = "rmdir",
	[TOMOYO_TYPE_TRUNCATE]   = "truncate",
	[TOMOYO_TYPE_SYMLINK]    = "symlink",
	[TOMOYO_TYPE_CHROOT]     = "chroot",
	[TOMOYO_TYPE_UMOUNT]     = "unmount",
};

/* String table for socket's operation. */
static const char * const tomoyo_socket_keyword[TOMOYO_MAX_NETWORK_OPERATION]
= {
	[TOMOYO_NETWORK_BIND]    = "bind",
	[TOMOYO_NETWORK_LISTEN]  = "listen",
	[TOMOYO_NETWORK_CONNECT] = "connect",
	[TOMOYO_NETWORK_ACCEPT]  = "accept",
	[TOMOYO_NETWORK_SEND]    = "send",
	[TOMOYO_NETWORK_RECV]    = "recv",
};

/* String table for categories. */
static const char * const tomoyo_category_keywords
[TOMOYO_MAX_MAC_CATEGORY_INDEX] = {
	[TOMOYO_MAC_CATEGORY_FILE]       = "file",
	[TOMOYO_MAC_CATEGORY_NETWORK]    = "network",
	[TOMOYO_MAC_CATEGORY_MISC]       = "misc",
	[TOMOYO_MAC_CATEGORY_IPC]        = "ipc",
	[TOMOYO_MAC_CATEGORY_CAPABILITY] = "capability",
};

/* String table for conditions. */
static const char * const tomoyo_condition_keyword
[TOMOYO_MAX_CONDITION_KEYWORD] = {
	[TOMOYO_TASK_UID]             = "task.uid",
	[TOMOYO_TASK_EUID]            = "task.euid",
	[TOMOYO_TASK_SUID]            = "task.suid",
	[TOMOYO_TASK_FSUID]           = "task.fsuid",
	[TOMOYO_TASK_GID]             = "task.gid",
	[TOMOYO_TASK_EGID]            = "task.egid",
	[TOMOYO_TASK_SGID]            = "task.sgid",
	[TOMOYO_TASK_FSGID]           = "task.fsgid",
	[TOMOYO_TASK_PID]             = "task.pid",
	[TOMOYO_TASK_PPID]            = "task.ppid",
	[TOMOYO_EXEC_ARGC]            = "exec.argc",
	[TOMOYO_EXEC_ENVC]            = "exec.envc",
	[TOMOYO_TYPE_IS_SOCKET]       = "socket",
	[TOMOYO_TYPE_IS_SYMLINK]      = "symlink",
	[TOMOYO_TYPE_IS_FILE]         = "file",
	[TOMOYO_TYPE_IS_BLOCK_DEV]    = "block",
	[TOMOYO_TYPE_IS_DIRECTORY]    = "directory",
	[TOMOYO_TYPE_IS_CHAR_DEV]     = "char",
	[TOMOYO_TYPE_IS_FIFO]         = "fifo",
	[TOMOYO_MODE_SETUID]          = "setuid",
	[TOMOYO_MODE_SETGID]          = "setgid",
	[TOMOYO_MODE_STICKY]          = "sticky",
	[TOMOYO_MODE_OWNER_READ]      = "owner_read",
	[TOMOYO_MODE_OWNER_WRITE]     = "owner_write",
	[TOMOYO_MODE_OWNER_EXECUTE]   = "owner_execute",
	[TOMOYO_MODE_GROUP_READ]      = "group_read",
	[TOMOYO_MODE_GROUP_WRITE]     = "group_write",
	[TOMOYO_MODE_GROUP_EXECUTE]   = "group_execute",
	[TOMOYO_MODE_OTHERS_READ]     = "others_read",
	[TOMOYO_MODE_OTHERS_WRITE]    = "others_write",
	[TOMOYO_MODE_OTHERS_EXECUTE]  = "others_execute",
	[TOMOYO_TASK_TYPE]            = "task.type",
	[TOMOYO_TASK_EXECUTE_HANDLER] = "execute_handler",
	[TOMOYO_EXEC_REALPATH]        = "exec.realpath",
	[TOMOYO_SYMLINK_TARGET]       = "symlink.target",
	[TOMOYO_PATH1_UID]            = "path1.uid",
	[TOMOYO_PATH1_GID]            = "path1.gid",
	[TOMOYO_PATH1_INO]            = "path1.ino",
	[TOMOYO_PATH1_MAJOR]          = "path1.major",
	[TOMOYO_PATH1_MINOR]          = "path1.minor",
	[TOMOYO_PATH1_PERM]           = "path1.perm",
	[TOMOYO_PATH1_TYPE]           = "path1.type",
	[TOMOYO_PATH1_DEV_MAJOR]      = "path1.dev_major",
	[TOMOYO_PATH1_DEV_MINOR]      = "path1.dev_minor",
	[TOMOYO_PATH2_UID]            = "path2.uid",
	[TOMOYO_PATH2_GID]            = "path2.gid",
	[TOMOYO_PATH2_INO]            = "path2.ino",
	[TOMOYO_PATH2_MAJOR]          = "path2.major",
	[TOMOYO_PATH2_MINOR]          = "path2.minor",
	[TOMOYO_PATH2_PERM]           = "path2.perm",
	[TOMOYO_PATH2_TYPE]           = "path2.type",
	[TOMOYO_PATH2_DEV_MAJOR]      = "path2.dev_major",
	[TOMOYO_PATH2_DEV_MINOR]      = "path2.dev_minor",
	[TOMOYO_PATH1_PARENT_UID]     = "path1.parent.uid",
	[TOMOYO_PATH1_PARENT_GID]     = "path1.parent.gid",
	[TOMOYO_PATH1_PARENT_INO]     = "path1.parent.ino",
	[TOMOYO_PATH1_PARENT_PERM]    = "path1.parent.perm",
	[TOMOYO_PATH2_PARENT_UID]     = "path2.parent.uid",
	[TOMOYO_PATH2_PARENT_GID]     = "path2.parent.gid",
	[TOMOYO_PATH2_PARENT_INO]     = "path2.parent.ino",
	[TOMOYO_PATH2_PARENT_PERM]    = "path2.parent.perm",
};

/* String table for PREFERENCE keyword. */
static const char * const tomoyo_pref_keywords[TOMOYO_MAX_PREF] = {
	[TOMOYO_PREF_MAX_AUDIT_LOG]      = "max_audit_log",
	[TOMOYO_PREF_MAX_LEARNING_ENTRY] = "max_learning_entry",
	[TOMOYO_PREF_ENFORCING_PENALTY]  = "enforcing_penalty",
};

/*
 * Mapping table from "enum tomoyo_path_acl_index" to "enum tomoyo_mac_index".
 */
static const u8 tomoyo_p2mac[TOMOYO_MAX_PATH_OPERATION] = {
	[TOMOYO_TYPE_EXECUTE]    = TOMOYO_MAC_FILE_EXECUTE,
	[TOMOYO_TYPE_READ]       = TOMOYO_MAC_FILE_OPEN,
	[TOMOYO_TYPE_WRITE]      = TOMOYO_MAC_FILE_OPEN,
	[TOMOYO_TYPE_APPEND]     = TOMOYO_MAC_FILE_OPEN,
	[TOMOYO_TYPE_UNLINK]     = TOMOYO_MAC_FILE_UNLINK,
	[TOMOYO_TYPE_GETATTR]    = TOMOYO_MAC_FILE_GETATTR,
	[TOMOYO_TYPE_RMDIR]      = TOMOYO_MAC_FILE_RMDIR,
	[TOMOYO_TYPE_TRUNCATE]   = TOMOYO_MAC_FILE_TRUNCATE,
	[TOMOYO_TYPE_SYMLINK]    = TOMOYO_MAC_FILE_SYMLINK,
	[TOMOYO_TYPE_CHROOT]     = TOMOYO_MAC_FILE_CHROOT,
	[TOMOYO_TYPE_UMOUNT]     = TOMOYO_MAC_FILE_UMOUNT,
};

/*
 * Mapping table from "enum tomoyo_mkdev_acl_index" to "enum tomoyo_mac_index".
 */
static const u8 tomoyo_pnnn2mac[TOMOYO_MAX_MKDEV_OPERATION] = {
	[TOMOYO_TYPE_MKBLOCK] = TOMOYO_MAC_FILE_MKBLOCK,
	[TOMOYO_TYPE_MKCHAR]  = TOMOYO_MAC_FILE_MKCHAR,
};

/*
 * Mapping table from "enum tomoyo_path2_acl_index" to "enum tomoyo_mac_index".
 */
static const u8 tomoyo_pp2mac[TOMOYO_MAX_PATH2_OPERATION] = {
	[TOMOYO_TYPE_LINK]       = TOMOYO_MAC_FILE_LINK,
	[TOMOYO_TYPE_RENAME]     = TOMOYO_MAC_FILE_RENAME,
	[TOMOYO_TYPE_PIVOT_ROOT] = TOMOYO_MAC_FILE_PIVOT_ROOT,
};

/*
 * Mapping table from "enum tomoyo_path_number_acl_index" to
 * "enum tomoyo_mac_index".
 */
static const u8 tomoyo_pn2mac[TOMOYO_MAX_PATH_NUMBER_OPERATION] = {
	[TOMOYO_TYPE_CREATE] = TOMOYO_MAC_FILE_CREATE,
	[TOMOYO_TYPE_MKDIR]  = TOMOYO_MAC_FILE_MKDIR,
	[TOMOYO_TYPE_MKFIFO] = TOMOYO_MAC_FILE_MKFIFO,
	[TOMOYO_TYPE_MKSOCK] = TOMOYO_MAC_FILE_MKSOCK,
	[TOMOYO_TYPE_IOCTL]  = TOMOYO_MAC_FILE_IOCTL,
	[TOMOYO_TYPE_CHMOD]  = TOMOYO_MAC_FILE_CHMOD,
	[TOMOYO_TYPE_CHOWN]  = TOMOYO_MAC_FILE_CHOWN,
	[TOMOYO_TYPE_CHGRP]  = TOMOYO_MAC_FILE_CHGRP,
};

/*
 * Mapping table from "enum tomoyo_network_acl_index" to
 * "enum tomoyo_mac_index" for inet domain socket.
 */
static const u8 tomoyo_inet2mac[TOMOYO_SOCK_MAX][TOMOYO_MAX_NETWORK_OPERATION]
= {
	[SOCK_STREAM] = {
		[TOMOYO_NETWORK_BIND]    = TOMOYO_MAC_NETWORK_INET_STREAM_BIND,
		[TOMOYO_NETWORK_LISTEN]  =
		TOMOYO_MAC_NETWORK_INET_STREAM_LISTEN,
		[TOMOYO_NETWORK_CONNECT] =
		TOMOYO_MAC_NETWORK_INET_STREAM_CONNECT,
		[TOMOYO_NETWORK_ACCEPT]  =
		TOMOYO_MAC_NETWORK_INET_STREAM_ACCEPT,
	},
	[SOCK_DGRAM] = {
		[TOMOYO_NETWORK_BIND]    = TOMOYO_MAC_NETWORK_INET_DGRAM_BIND,
		[TOMOYO_NETWORK_SEND]    = TOMOYO_MAC_NETWORK_INET_DGRAM_SEND,
		[TOMOYO_NETWORK_RECV]    = TOMOYO_MAC_NETWORK_INET_DGRAM_RECV,
	},
	[SOCK_RAW]    = {
		[TOMOYO_NETWORK_BIND]    = TOMOYO_MAC_NETWORK_INET_RAW_BIND,
		[TOMOYO_NETWORK_SEND]    = TOMOYO_MAC_NETWORK_INET_RAW_SEND,
		[TOMOYO_NETWORK_RECV]    = TOMOYO_MAC_NETWORK_INET_RAW_RECV,
	},
};

/*
 * Mapping table from "enum tomoyo_network_acl_index" to
 * "enum tomoyo_mac_index" for unix domain socket.
 */
static const u8 tomoyo_unix2mac[TOMOYO_SOCK_MAX][TOMOYO_MAX_NETWORK_OPERATION]
= {
	[SOCK_STREAM] = {
		[TOMOYO_NETWORK_BIND]    = TOMOYO_MAC_NETWORK_UNIX_STREAM_BIND,
		[TOMOYO_NETWORK_LISTEN]  =
		TOMOYO_MAC_NETWORK_UNIX_STREAM_LISTEN,
		[TOMOYO_NETWORK_CONNECT] =
		TOMOYO_MAC_NETWORK_UNIX_STREAM_CONNECT,
		[TOMOYO_NETWORK_ACCEPT]  =
		TOMOYO_MAC_NETWORK_UNIX_STREAM_ACCEPT,
	},
	[SOCK_DGRAM] = {
		[TOMOYO_NETWORK_BIND]    = TOMOYO_MAC_NETWORK_UNIX_DGRAM_BIND,
		[TOMOYO_NETWORK_SEND]    = TOMOYO_MAC_NETWORK_UNIX_DGRAM_SEND,
		[TOMOYO_NETWORK_RECV]    = TOMOYO_MAC_NETWORK_UNIX_DGRAM_RECV,
	},
	[SOCK_SEQPACKET] = {
		[TOMOYO_NETWORK_BIND]    =
		TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_BIND,
		[TOMOYO_NETWORK_LISTEN]  =
		TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_LISTEN,
		[TOMOYO_NETWORK_CONNECT] =
		TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_CONNECT,
		[TOMOYO_NETWORK_ACCEPT]  =
		TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT,
	},
};

/* String table for socket's protocols. */
static const char * const tomoyo_proto_keyword[TOMOYO_SOCK_MAX] = {
	[SOCK_STREAM]    = "stream",
	[SOCK_DGRAM]     = "dgram",
	[SOCK_RAW]       = "raw",
	[SOCK_SEQPACKET] = "seqpacket",
	[0] = " ", /* Dummy for avoiding NULL pointer dereference. */
	[4] = " ", /* Dummy for avoiding NULL pointer dereference. */
};

/*
 * Mapping table from "enum tomoyo_capability_acl_index" to
 * "enum tomoyo_mac_index".
 */
static const u8 tomoyo_c2mac[TOMOYO_MAX_CAPABILITY_INDEX] = {
	[TOMOYO_USE_ROUTE_SOCKET]  = TOMOYO_MAC_CAPABILITY_USE_ROUTE_SOCKET,
	[TOMOYO_USE_PACKET_SOCKET] = TOMOYO_MAC_CAPABILITY_USE_PACKET_SOCKET,
	[TOMOYO_SYS_REBOOT]        = TOMOYO_MAC_CAPABILITY_SYS_REBOOT,
	[TOMOYO_SYS_VHANGUP]       = TOMOYO_MAC_CAPABILITY_SYS_VHANGUP,
	[TOMOYO_SYS_SETTIME]       = TOMOYO_MAC_CAPABILITY_SYS_SETTIME,
	[TOMOYO_SYS_NICE]          = TOMOYO_MAC_CAPABILITY_SYS_NICE,
	[TOMOYO_SYS_SETHOSTNAME]   = TOMOYO_MAC_CAPABILITY_SYS_SETHOSTNAME,
	[TOMOYO_USE_KERNEL_MODULE] = TOMOYO_MAC_CAPABILITY_USE_KERNEL_MODULE,
	[TOMOYO_SYS_KEXEC_LOAD]    = TOMOYO_MAC_CAPABILITY_SYS_KEXEC_LOAD,
	[TOMOYO_SYS_PTRACE]        = TOMOYO_MAC_CAPABILITY_SYS_PTRACE,
};

/* String table for /proc/tomoyo/stat interface. */
static const char * const tomoyo_memory_headers[TOMOYO_MAX_MEMORY_STAT] = {
	[TOMOYO_MEMORY_POLICY]     = "policy:",
	[TOMOYO_MEMORY_AUDIT]      = "audit log:",
	[TOMOYO_MEMORY_QUERY]      = "query message:",
};

/* String table for domain transition control keywords. */
static const char * const tomoyo_transition_type[TOMOYO_MAX_TRANSITION_TYPE]
= {
	[TOMOYO_TRANSITION_CONTROL_NO_RESET]      = "no_reset_domain ",
	[TOMOYO_TRANSITION_CONTROL_RESET]         = "reset_domain ",
	[TOMOYO_TRANSITION_CONTROL_NO_INITIALIZE] = "no_initialize_domain ",
	[TOMOYO_TRANSITION_CONTROL_INITIALIZE]    = "initialize_domain ",
	[TOMOYO_TRANSITION_CONTROL_NO_KEEP]       = "no_keep_domain ",
	[TOMOYO_TRANSITION_CONTROL_KEEP]          = "keep_domain ",
};

/* String table for grouping keywords. */
static const char * const tomoyo_group_name[TOMOYO_MAX_GROUP] = {
	[TOMOYO_PATH_GROUP]    = "path_group ",
	[TOMOYO_NUMBER_GROUP]  = "number_group ",
	[TOMOYO_ADDRESS_GROUP] = "address_group ",
};

/* String table for domain flags. */
static const char * const tomoyo_dif[TOMOYO_MAX_DOMAIN_INFO_FLAGS] = {
	[TOMOYO_DIF_QUOTA_WARNED]      = "quota_exceeded\n",
	[TOMOYO_DIF_TRANSITION_FAILED] = "transition_failed\n",
};

/*
 * Mapping table from "enum tomoyo_mac_index" to
 * "enum tomoyo_mac_category_index".
 */
static const u8 tomoyo_index2category[TOMOYO_MAX_MAC_INDEX] = {
	/* CONFIG::file group */
	[TOMOYO_MAC_FILE_EXECUTE]    = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_OPEN]       = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_CREATE]     = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_UNLINK]     = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_GETATTR]    = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_MKDIR]      = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_RMDIR]      = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_MKFIFO]     = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_MKSOCK]     = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_TRUNCATE]   = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_SYMLINK]    = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_MKBLOCK]    = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_MKCHAR]     = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_LINK]       = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_RENAME]     = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_CHMOD]      = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_CHOWN]      = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_CHGRP]      = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_IOCTL]      = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_CHROOT]     = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_MOUNT]      = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_UMOUNT]     = TOMOYO_MAC_CATEGORY_FILE,
	[TOMOYO_MAC_FILE_PIVOT_ROOT] = TOMOYO_MAC_CATEGORY_FILE,
	/* CONFIG::misc group */
	[TOMOYO_MAC_ENVIRON]         = TOMOYO_MAC_CATEGORY_MISC,
	/* CONFIG::network group */
	[TOMOYO_MAC_NETWORK_INET_STREAM_BIND]       =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_INET_STREAM_LISTEN]     =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_INET_STREAM_CONNECT]    =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_INET_STREAM_ACCEPT]     =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_INET_DGRAM_BIND]        =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_INET_DGRAM_SEND]        =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_INET_DGRAM_RECV]        =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_INET_RAW_BIND]          =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_INET_RAW_SEND]          =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_INET_RAW_RECV]          =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_STREAM_BIND]       =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_STREAM_LISTEN]     =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_STREAM_CONNECT]    =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_STREAM_ACCEPT]     =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_DGRAM_BIND]        =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_DGRAM_SEND]        =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_DGRAM_RECV]        =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_BIND]    =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_LISTEN]  =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_CONNECT] =
	TOMOYO_MAC_CATEGORY_NETWORK,
	[TOMOYO_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT]  =
	TOMOYO_MAC_CATEGORY_NETWORK,
	/* CONFIG::ipc group */
	[TOMOYO_MAC_SIGNAL]          = TOMOYO_MAC_CATEGORY_IPC,
	/* CONFIG::capability group */
	[TOMOYO_MAC_CAPABILITY_USE_ROUTE_SOCKET]  =
	TOMOYO_MAC_CATEGORY_CAPABILITY,
	[TOMOYO_MAC_CAPABILITY_USE_PACKET_SOCKET] =
	TOMOYO_MAC_CATEGORY_CAPABILITY,
	[TOMOYO_MAC_CAPABILITY_SYS_REBOOT]        =
	TOMOYO_MAC_CATEGORY_CAPABILITY,
	[TOMOYO_MAC_CAPABILITY_SYS_VHANGUP]       =
	TOMOYO_MAC_CATEGORY_CAPABILITY,
	[TOMOYO_MAC_CAPABILITY_SYS_SETTIME]       =
	TOMOYO_MAC_CATEGORY_CAPABILITY,
	[TOMOYO_MAC_CAPABILITY_SYS_NICE]          =
	TOMOYO_MAC_CATEGORY_CAPABILITY,
	[TOMOYO_MAC_CAPABILITY_SYS_SETHOSTNAME]   =
	TOMOYO_MAC_CATEGORY_CAPABILITY,
	[TOMOYO_MAC_CAPABILITY_USE_KERNEL_MODULE] =
	TOMOYO_MAC_CATEGORY_CAPABILITY,
	[TOMOYO_MAC_CAPABILITY_SYS_KEXEC_LOAD]    =
	TOMOYO_MAC_CATEGORY_CAPABILITY,
	[TOMOYO_MAC_CAPABILITY_SYS_PTRACE]        =
	TOMOYO_MAC_CATEGORY_CAPABILITY,
};

static struct tomoyo_io_buffer head;
static struct tomoyo_domain2_info tomoyo_kernel_domain;
static struct tomoyo_policy_namespace tomoyo_kernel_namespace;
static LIST_HEAD(tomoyo_domain_list);
static LIST_HEAD(tomoyo_manager_list);
static LIST_HEAD(tomoyo_path_group);
static LIST_HEAD(tomoyo_number_group);
static LIST_HEAD(tomoyo_address_group);
static LIST_HEAD(tomoyo_transition_list);
static LIST_HEAD(tomoyo_aggregator_list);
static LIST_HEAD(tomoyo_reserved_list);
static LIST_HEAD(tomoyo_namespace_list);
static bool tomoyo_namespace_enabled;
static struct list_head tomoyo_name_list[TOMOYO_MAX_HASH];
static unsigned int tomoyo_memory_quota[TOMOYO_MAX_MEMORY_STAT];

/**
 * tomoyo_put_condition - Drop reference on "struct tomoyo_condition".
 *
 * @cond: Pointer to "struct tomoyo_condition". Maybe NULL.
 *
 * Returns nothing.
 */
static inline void tomoyo_put_condition(struct tomoyo_condition *cond)
{
	if (cond)
		cond->head.users--;
}

/**
 * tomoyo_put_group - Drop reference on "struct tomoyo_group".
 *
 * @group: Pointer to "struct tomoyo_group". Maybe NULL.
 *
 * Returns nothing.
 */
static inline void tomoyo_put_group(struct tomoyo_group *group)
{
	if (group)
		group->head.users--;
}

/**
 * tomoyo_put_name - Drop reference on "struct tomoyo_name".
 *
 * @name: Pointer to "struct tomoyo_path_info". Maybe NULL.
 *
 * Returns nothing.
 */
static inline void tomoyo_put_name(const struct tomoyo_path_info *name)
{
	if (name)
		container_of(name, struct tomoyo_name, entry)->head.users--;
}

/**
 * tomoyo_put_name_union - Drop reference on "struct tomoyo_name_union".
 *
 * @ptr: Pointer to "struct tomoyo_name_union".
 *
 * Returns nothing.
 */
static void tomoyo_put_name_union(struct tomoyo_name_union *ptr)
{
	tomoyo_put_group(ptr->group);
	tomoyo_put_name(ptr->filename);
}

/**
 * tomoyo_put_number_union - Drop reference on "struct tomoyo_number_union".
 *
 * @ptr: Pointer to "struct tomoyo_number_union".
 *
 * Returns nothing.
 */
static void tomoyo_put_number_union(struct tomoyo_number_union *ptr)
{
	tomoyo_put_group(ptr->group);
}

/**
 * tomoyo_del_condition - Delete members in "struct tomoyo_condition".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static void tomoyo_del_condition(struct list_head *element)
{
	struct tomoyo_condition *cond = container_of(element, typeof(*cond),
						     head.list);
	const u16 condc = cond->condc;
	const u16 numbers_count = cond->numbers_count;
	const u16 names_count = cond->names_count;
	const u16 argc = cond->argc;
	const u16 envc = cond->envc;
	unsigned int i;
	const struct tomoyo_condition_element *condp
		= (const struct tomoyo_condition_element *) (cond + 1);
	struct tomoyo_number_union *numbers_p
		= (struct tomoyo_number_union *) (condp + condc);
	struct tomoyo_name_union *names_p
		= (struct tomoyo_name_union *) (numbers_p + numbers_count);
	const struct tomoyo_argv *argv
		= (const struct tomoyo_argv *) (names_p + names_count);
	const struct tomoyo_envp *envp
		= (const struct tomoyo_envp *) (argv + argc);
	for (i = 0; i < numbers_count; i++)
		tomoyo_put_number_union(numbers_p++);
	for (i = 0; i < names_count; i++)
		tomoyo_put_name_union(names_p++);
	for (i = 0; i < argc; argv++, i++)
		tomoyo_put_name(argv->value);
	for (i = 0; i < envc; envp++, i++) {
		tomoyo_put_name(envp->name);
		tomoyo_put_name(envp->value);
	}
	tomoyo_put_name(cond->transit);
}

/**
 * tomoyo_yesno - Return "yes" or "no".
 *
 * @value: Bool value.
 *
 * Returns "yes" if @value is not 0, "no" otherwise.
 */
static const char *tomoyo_yesno(const unsigned int value)
{
	return value ? "yes" : "no";
}

/**
 * tomoyo_same_name_union - Check for duplicated "struct tomoyo_name_union" entry.
 *
 * @a: Pointer to "struct tomoyo_name_union".
 * @b: Pointer to "struct tomoyo_name_union".
 *
 * Returns true if @a == @b, false otherwise.
 */
static inline bool tomoyo_same_name_union(const struct tomoyo_name_union *a,
					  const struct tomoyo_name_union *b)
{
	return a->filename == b->filename && a->group == b->group;
}

/**
 * tomoyo_same_number_union - Check for duplicated "struct tomoyo_number_union" entry.
 *
 * @a: Pointer to "struct tomoyo_number_union".
 * @b: Pointer to "struct tomoyo_number_union".
 *
 * Returns true if @a == @b, false otherwise.
 */
static inline bool tomoyo_same_number_union
(const struct tomoyo_number_union *a, const struct tomoyo_number_union *b)
{
	return a->values[0] == b->values[0] && a->values[1] == b->values[1] &&
		a->group == b->group && a->value_type[0] == b->value_type[0] &&
		a->value_type[1] == b->value_type[1];
}

/**
 * tomoyo_same_ipaddr_union - Check for duplicated "struct tomoyo_ipaddr_union" entry.
 *
 * @a: Pointer to "struct tomoyo_ipaddr_union".
 * @b: Pointer to "struct tomoyo_ipaddr_union".
 *
 * Returns true if @a == @b, false otherwise.
 */
static inline bool tomoyo_same_ipaddr_union
(const struct tomoyo_ipaddr_union *a, const struct tomoyo_ipaddr_union *b)
{
	return !memcmp(a->ip, b->ip, sizeof(a->ip)) && a->group == b->group &&
		a->is_ipv6 == b->is_ipv6;
}

/**
 * tomoyo_partial_name_hash - Hash name.
 *
 * @c:        A unsigned long value.
 * @prevhash: A previous hash value.
 *
 * Returns new hash value.
 *
 * This function is copied from partial_name_hash() in the kernel source.
 */
static inline unsigned long tomoyo_partial_name_hash(unsigned long c,
						     unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

/**
 * tomoyo_full_name_hash - Hash full name.
 *
 * @name: Pointer to "const unsigned char".
 * @len:  Length of @name in byte.
 *
 * Returns hash value.
 *
 * This function is copied from full_name_hash() in the kernel source.
 */
static inline unsigned int tomoyo_full_name_hash(const unsigned char *name,
						 unsigned int len)
{
	unsigned long hash = 0;
	while (len--)
		hash = tomoyo_partial_name_hash(*name++, hash);
	return (unsigned int) hash;
}

/**
 * tomoyo_get_name - Allocate memory for string data.
 *
 * @name: The string to store into the permernent memory.
 *
 * Returns pointer to "struct tomoyo_path_info" on success, abort otherwise.
 */
static const struct tomoyo_path_info *tomoyo_get_name(const char *name)
{
	struct tomoyo_name *ptr;
	unsigned int hash;
	int len;
	int allocated_len;
	struct list_head *head;

	if (!name)
		name = "";
	len = strlen(name) + 1;
	hash = tomoyo_full_name_hash((const unsigned char *) name, len - 1);
	head = &tomoyo_name_list[hash % TOMOYO_MAX_HASH];
	list_for_each_entry(ptr, head, head.list) {
		if (hash != ptr->entry.hash || strcmp(name, ptr->entry.name))
			continue;
		ptr->head.users++;
		goto out;
	}
	allocated_len = sizeof(*ptr) + len;
	ptr = tomoyo_malloc(allocated_len);
	ptr->entry.name = ((char *) ptr) + sizeof(*ptr);
	memmove((char *) ptr->entry.name, name, len);
	ptr->head.users = 1;
	tomoyo_fill_path_info(&ptr->entry);
	ptr->size = allocated_len;
	list_add_tail(&ptr->head.list, head);
out:
	return &ptr->entry;
}


/**
 * tomoyo_commit_ok - Allocate memory and check memory quota.
 *
 * @data: Data to copy from.
 * @size: Size in byte.
 *
 * Returns pointer to allocated memory on success, abort otherwise.
 * @data is zero-cleared on success.
 */
static void *tomoyo_commit_ok(void *data, const unsigned int size)
{
	void *ptr = tomoyo_malloc(size);
	memmove(ptr, data, size);
	memset(data, 0, size);
	return ptr;
}

/**
 * tomoyo_permstr - Find permission keywords.
 *
 * @string: String representation for permissions in foo/bar/buz format.
 * @keyword: Keyword to find from @string/
 *
 * Returns ture if @keyword was found in @string, false otherwise.
 *
 * This function assumes that strncmp(w1, w2, strlen(w1)) != 0 if w1 != w2.
 */
static bool tomoyo_permstr(const char *string, const char *keyword)
{
	const char *cp = strstr(string, keyword);
	if (cp)
		return cp == string || *(cp - 1) == '/';
	return false;
}

/**
 * tomoyo_read_token - Read a word from a line.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns a word on success, "" otherwise.
 *
 * To allow the caller to skip NULL check, this function returns "" rather than
 * NULL if there is no more words to read.
 */
static char *tomoyo_read_token(struct tomoyo_acl_param *param)
{
	char *pos = param->data;
	char *del = strchr(pos, ' ');
	if (del)
		*del++ = '\0';
	else
		del = pos + strlen(pos);
	param->data = del;
	return pos;
}

/**
 * tomoyo_get_domainname - Read a domainname from a line.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns a domainname on success, NULL otherwise.
 */
static const struct tomoyo_path_info *tomoyo_get_domainname
(struct tomoyo_acl_param *param)
{
	char *start = param->data;
	char *pos = start;
	while (*pos) {
		if (*pos++ != ' ' || *pos++ == '/')
			continue;
		pos -= 2;
		*pos++ = '\0';
		break;
	}
	param->data = pos;
	if (tomoyo_correct_domain(start))
		return tomoyo_get_name(start);
	return NULL;
}

/**
 * tomoyo_get_group - Allocate memory for "struct tomoyo_path_group"/"struct tomoyo_number_group"/"struct tomoyo_address_group".
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 * @list:  List to use.
 *
 * Returns pointer to "struct tomoyo_group" on success, NULL otherwise.
 */
static struct tomoyo_group *tomoyo_get_group(struct tomoyo_acl_param *param,
					     struct list_head *list)
{
	struct tomoyo_group e = { };
	struct tomoyo_group *group = NULL;
	const char *group_name = tomoyo_read_token(param);
	bool found = false;
	if (!tomoyo_correct_word(group_name))
		return NULL;
	e.ns = param->ns;
	e.group_name = tomoyo_get_name(group_name);
	list_for_each_entry(group, list, head.list) {
		if (e.ns != group->ns || e.group_name != group->group_name)
			continue;
		group->head.users++;
		found = true;
		break;
	}
	if (!found) {
		struct tomoyo_group *entry = tomoyo_commit_ok(&e, sizeof(e));
		INIT_LIST_HEAD(&entry->member_list);
		entry->head.users = 1;
		list_add_tail(&entry->head.list, list);
		group = entry;
		found = true;
	}
	tomoyo_put_name(e.group_name);
	return found ? group : NULL;
}

/**
 * tomoyo_parse_ulong - Parse an "unsigned long" value.
 *
 * @result: Pointer to "unsigned long".
 * @str:    Pointer to string to parse.
 *
 * Returns one of values in "enum tomoyo_value_type".
 *
 * The @src is updated to point the first character after the value
 * on success.
 */
static u8 tomoyo_parse_ulong(unsigned long *result, char **str)
{
	const char *cp = *str;
	char *ep;
	int base = 10;
	if (*cp == '0') {
		char c = *(cp + 1);
		if (c == 'x' || c == 'X') {
			base = 16;
			cp += 2;
		} else if (c >= '0' && c <= '7') {
			base = 8;
			cp++;
		}
	}
	*result = strtoul(cp, &ep, base);
	if (cp == ep)
		return TOMOYO_VALUE_TYPE_INVALID;
	*str = ep;
	switch (base) {
	case 16:
		return TOMOYO_VALUE_TYPE_HEXADECIMAL;
	case 8:
		return TOMOYO_VALUE_TYPE_OCTAL;
	default:
		return TOMOYO_VALUE_TYPE_DECIMAL;
	}
}

/**
 * tomoyo_parse_name_union - Parse a tomoyo_name_union.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 * @ptr:   Pointer to "struct tomoyo_name_union".
 *
 * Returns true on success, false otherwise.
 */
static bool tomoyo_parse_name_union(struct tomoyo_acl_param *param,
				    struct tomoyo_name_union *ptr)
{
	char *filename;
	if (param->data[0] == '@') {
		param->data++;
		ptr->group = tomoyo_get_group(param, &tomoyo_path_group);
		return ptr->group != NULL;
	}
	filename = tomoyo_read_token(param);
	if (!tomoyo_correct_word(filename))
		return false;
	ptr->filename = tomoyo_get_name(filename);
	return true;
}

/**
 * tomoyo_parse_number_union - Parse a tomoyo_number_union.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 * @ptr:   Pointer to "struct tomoyo_number_union".
 *
 * Returns true on success, false otherwise.
 */
static bool tomoyo_parse_number_union(struct tomoyo_acl_param *param,
				      struct tomoyo_number_union *ptr)
{
	char *data;
	u8 type;
	unsigned long v;
	memset(ptr, 0, sizeof(*ptr));
	if (param->data[0] == '@') {
		param->data++;
		ptr->group = tomoyo_get_group(param, &tomoyo_number_group);
		return ptr->group != NULL;
	}
	data = tomoyo_read_token(param);
	type = tomoyo_parse_ulong(&v, &data);
	if (type == TOMOYO_VALUE_TYPE_INVALID)
		return false;
	ptr->values[0] = v;
	ptr->value_type[0] = type;
	if (!*data) {
		ptr->values[1] = v;
		ptr->value_type[1] = type;
		return true;
	}
	if (*data++ != '-')
		return false;
	type = tomoyo_parse_ulong(&v, &data);
	if (type == TOMOYO_VALUE_TYPE_INVALID || *data || ptr->values[0] > v)
		return false;
	ptr->values[1] = v;
	ptr->value_type[1] = type;
	return true;
}

/**
 * tomoyo_find_domain2 - Find a domain by the given name.
 *
 * @domainname: The domainname to find.
 *
 * Returns pointer to "struct tomoyo_domain2_info" if found, NULL otherwise.
 */
static struct tomoyo_domain2_info *tomoyo_find_domain2(const char *domainname)
{
	struct tomoyo_domain2_info *domain;
	struct tomoyo_path_info name;
	name.name = domainname;
	tomoyo_fill_path_info(&name);
	list_for_each_entry(domain, &tomoyo_domain_list, list) {
		if (!domain->is_deleted &&
		    !tomoyo_pathcmp(&name, domain->domainname))
			return domain;
	}
	return NULL;
}

static int client_fd = EOF;

static void cprintf(const char *fmt, ...)
     __attribute__ ((format(printf, 1, 2)));

/**
 * cprintf - printf() over socket.
 *
 * @fmt: The printf()'s format string, followed by parameters.
 *
 * Returns nothing.
 */
static void cprintf(const char *fmt, ...)
{
	va_list args;
	static char *buffer = NULL;
	static unsigned int buffer_len = 0;
	static unsigned int buffer_pos = 0;
	int len;
	if (head.reset) {
		head.reset = false;
		buffer_pos = 0;
	}
	while (1) {
		va_start(args, fmt);
		len = vsnprintf(buffer + buffer_pos, buffer_len - buffer_pos,
				fmt, args);
		va_end(args);
		if (len < 0)
			_exit(1);
		if (buffer_pos + len < buffer_len) {
			buffer_pos += len;
			break;
		}
		buffer_len = buffer_pos + len + 4096;
		buffer = tomoyo_realloc(buffer, buffer_len);
	}
	if (len && buffer_pos < 1048576)
		return;
	if (write(client_fd, buffer, buffer_pos) != buffer_pos)
		_exit(1);
	buffer_pos = 0;
}

/**
 * tomoyo_update_policy - Update an entry for exception policy.
 *
 * @new_entry:       Pointer to "struct tomoyo_acl_info".
 * @size:            Size of @new_entry in bytes.
 * @param:           Pointer to "struct tomoyo_acl_param".
 * @check_duplicate: Callback function to find duplicated entry.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_update_policy(struct tomoyo_acl_head *new_entry,
				const int size, struct tomoyo_acl_param *param,
				bool (*check_duplicate)
				(const struct tomoyo_acl_head *,
				 const struct tomoyo_acl_head *))
{
	int error = param->is_delete ? -ENOENT : -ENOMEM;
	struct tomoyo_acl_head *entry;
	struct list_head *list = param->list;
	list_for_each_entry(entry, list, list) {
		if (!check_duplicate(entry, new_entry))
			continue;
		entry->is_deleted = param->is_delete;
		error = 0;
		break;
	}
	if (error && !param->is_delete) {
		entry = tomoyo_commit_ok(new_entry, size);
		list_add_tail(&entry->list, list);
		error = 0;
	}
	return error;
}

/* List of "struct tomoyo_condition". */
static LIST_HEAD(tomoyo_condition_list);

/**
 * tomoyo_get_dqword - tomoyo_get_name() for a quoted string.
 *
 * @start: String to save.
 *
 * Returns pointer to "struct tomoyo_path_info" on success, NULL otherwise.
 */
static const struct tomoyo_path_info *tomoyo_get_dqword(char *start)
{
	char *cp = start + strlen(start) - 1;
	if (cp == start || *start++ != '"' || *cp != '"')
		return NULL;
	*cp = '\0';
	if (*start && !tomoyo_correct_word(start))
		return NULL;
	return tomoyo_get_name(start);
}

/**
 * tomoyo_parse_name_union_quoted - Parse a quoted word.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 * @ptr:   Pointer to "struct tomoyo_name_union".
 *
 * Returns true on success, false otherwise.
 */
static bool tomoyo_parse_name_union_quoted(struct tomoyo_acl_param *param,
					   struct tomoyo_name_union *ptr)
{
	char *filename = param->data;
	if (*filename == '@')
		return tomoyo_parse_name_union(param, ptr);
	ptr->filename = tomoyo_get_dqword(filename);
	return ptr->filename != NULL;
}

/**
 * tomoyo_parse_argv - Parse an argv[] condition part.
 *
 * @left:  Lefthand value.
 * @right: Righthand value.
 * @argv:  Pointer to "struct tomoyo_argv".
 *
 * Returns true on success, false otherwise.
 */
static bool tomoyo_parse_argv(char *left, char *right,
			      struct tomoyo_argv *argv)
{
	if (tomoyo_parse_ulong(&argv->index, &left) !=
	    TOMOYO_VALUE_TYPE_DECIMAL || *left++ != ']' || *left)
		return false;
	argv->value = tomoyo_get_dqword(right);
	return argv->value != NULL;
}

/**
 * tomoyo_parse_envp - Parse an envp[] condition part.
 *
 * @left:  Lefthand value.
 * @right: Righthand value.
 * @envp:  Pointer to "struct tomoyo_envp".
 *
 * Returns true on success, false otherwise.
 */
static bool tomoyo_parse_envp(char *left, char *right,
			      struct tomoyo_envp *envp)
{
	const struct tomoyo_path_info *name;
	const struct tomoyo_path_info *value;
	char *cp = left + strlen(left) - 1;
	if (*cp-- != ']' || *cp != '"')
		goto out;
	*cp = '\0';
	if (!tomoyo_correct_word(left))
		goto out;
	name = tomoyo_get_name(left);
	if (!strcmp(right, "NULL")) {
		value = NULL;
	} else {
		value = tomoyo_get_dqword(right);
		if (!value) {
			tomoyo_put_name(name);
			goto out;
		}
	}
	envp->name = name;
	envp->value = value;
	return true;
out:
	return false;
}

/**
 * tomoyo_same_condition - Check for duplicated "struct tomoyo_condition" entry.
 *
 * @a: Pointer to "struct tomoyo_condition".
 * @b: Pointer to "struct tomoyo_condition".
 *
 * Returns true if @a == @b, false otherwise.
 */
static inline bool tomoyo_same_condition(const struct tomoyo_condition *a,
					 const struct tomoyo_condition *b)
{
	return a->size == b->size && a->condc == b->condc &&
		a->numbers_count == b->numbers_count &&
		a->names_count == b->names_count &&
		a->argc == b->argc && a->envc == b->envc &&
		a->grant_log == b->grant_log && a->transit == b->transit &&
		!memcmp(a + 1, b + 1, a->size - sizeof(*a));
}

/**
 * tomoyo_condition_type - Get condition type.
 *
 * @word: Keyword string.
 *
 * Returns one of values in "enum tomoyo_conditions_index" on success,
 * TOMOYO_MAX_CONDITION_KEYWORD otherwise.
 */
static u8 tomoyo_condition_type(const char *word)
{
	u8 i;
	for (i = 0; i < TOMOYO_MAX_CONDITION_KEYWORD; i++) {
		if (!strcmp(word, tomoyo_condition_keyword[i]))
			break;
	}
	return i;
}

/* Define this to enable debug mode. */
/* #define DEBUG_CONDITION */

#ifdef DEBUG_CONDITION
#define dprintk printk
#else
#define dprintk(...) do { } while (0)
#endif

/**
 * tomoyo_commit_condition - Commit "struct tomoyo_condition".
 *
 * @entry: Pointer to "struct tomoyo_condition".
 *
 * Returns pointer to "struct tomoyo_condition" on success, NULL otherwise.
 *
 * This function merges duplicated entries. This function returns NULL if
 * @entry is not duplicated but memory quota for policy has exceeded.
 */
static struct tomoyo_condition *tomoyo_commit_condition
(struct tomoyo_condition *entry)
{
	struct tomoyo_condition *ptr;
	bool found = false;
	list_for_each_entry(ptr, &tomoyo_condition_list, head.list) {
		if (!tomoyo_same_condition(ptr, entry))
			continue;
		/* Same entry found. Share this entry. */
		ptr->head.users++;
		found = true;
		break;
	}
	if (!found) {
		if (entry) {
			entry->head.users = 1;
			list_add(&entry->head.list, &tomoyo_condition_list);
		} else {
			found = true;
			ptr = NULL;
		}
	}
	if (found) {
		tomoyo_del_condition(&entry->head.list);
		free(entry);
		entry = ptr;
	}
	return entry;
}

/**
 * tomoyo_get_condition - Parse condition part.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns pointer to "struct tomoyo_condition" on success, NULL otherwise.
 */
static struct tomoyo_condition *tomoyo_get_condition
(struct tomoyo_acl_param *param)
{
	struct tomoyo_condition *entry = NULL;
	struct tomoyo_condition_element *condp = NULL;
	struct tomoyo_number_union *numbers_p = NULL;
	struct tomoyo_name_union *names_p = NULL;
	struct tomoyo_argv *argv = NULL;
	struct tomoyo_envp *envp = NULL;
	struct tomoyo_condition e = { };
	char * const start_of_string = param->data;
	char * const end_of_string = start_of_string + strlen(start_of_string);
	char *pos;
rerun:
	pos = start_of_string;
	while (1) {
		u8 left = -1;
		u8 right = -1;
		char *left_word = pos;
		char *cp;
		char *right_word;
		bool is_not;
		if (!*left_word)
			break;
		/*
		 * Since left-hand condition does not allow use of "path_group"
		 * or "number_group" and environment variable's names do not
		 * accept '=', it is guaranteed that the original line consists
		 * of one or more repetition of $left$operator$right blocks
		 * where "$left is free from '=' and ' '" and "$operator is
		 * either '=' or '!='" and "$right is free from ' '".
		 * Therefore, we can reconstruct the original line at the end
		 * of dry run even if we overwrite $operator with '\0'.
		 */
		cp = strchr(pos, ' ');
		if (cp) {
			*cp = '\0'; /* Will restore later. */
			pos = cp + 1;
		} else {
			pos = "";
		}
		right_word = strchr(left_word, '=');
		if (!right_word || right_word == left_word)
			goto out;
		is_not = *(right_word - 1) == '!';
		if (is_not)
			*(right_word++ - 1) = '\0'; /* Will restore later. */
		else if (*(right_word + 1) != '=')
			*right_word++ = '\0'; /* Will restore later. */
		else
			goto out;
		dprintk(KERN_WARNING "%u: <%s>%s=<%s>\n", __LINE__, left_word,
			is_not ? "!" : "", right_word);
		if (!strcmp(left_word, "grant_log")) {
			if (entry) {
				if (is_not ||
				    entry->grant_log != TOMOYO_GRANTLOG_AUTO)
					goto out;
				else if (!strcmp(right_word, "yes"))
					entry->grant_log = TOMOYO_GRANTLOG_YES;
				else if (!strcmp(right_word, "no"))
					entry->grant_log = TOMOYO_GRANTLOG_NO;
				else
					goto out;
			}
			continue;
		}
		if (!strcmp(left_word, "auto_domain_transition")) {
			if (entry) {
				if (is_not || entry->transit)
					goto out;
				entry->transit = tomoyo_get_dqword(right_word);
				if (!entry->transit ||
				    (entry->transit->name[0] != '/' &&
				     !tomoyo_domain_def(entry->transit->name)))
					goto out;
			}
			continue;
		}
		if (!strncmp(left_word, "exec.argv[", 10)) {
			if (!argv) {
				e.argc++;
				e.condc++;
			} else {
				e.argc--;
				e.condc--;
				left = TOMOYO_ARGV_ENTRY;
				argv->is_not = is_not;
				if (!tomoyo_parse_argv(left_word + 10,
						       right_word, argv++))
					goto out;
			}
			goto store_value;
		}
		if (!strncmp(left_word, "exec.envp[\"", 11)) {
			if (!envp) {
				e.envc++;
				e.condc++;
			} else {
				e.envc--;
				e.condc--;
				left = TOMOYO_ENVP_ENTRY;
				envp->is_not = is_not;
				if (!tomoyo_parse_envp(left_word + 11,
						       right_word, envp++))
					goto out;
			}
			goto store_value;
		}
		left = tomoyo_condition_type(left_word);
		dprintk(KERN_WARNING "%u: <%s> left=%u\n", __LINE__, left_word,
			left);
		if (left == TOMOYO_MAX_CONDITION_KEYWORD) {
			if (!numbers_p) {
				e.numbers_count++;
			} else {
				e.numbers_count--;
				left = TOMOYO_NUMBER_UNION;
				param->data = left_word;
				if (*left_word == '@' ||
				    !tomoyo_parse_number_union(param,
							       numbers_p++))
					goto out;
			}
		}
		if (!condp)
			e.condc++;
		else
			e.condc--;
		if (left == TOMOYO_EXEC_REALPATH ||
		    left == TOMOYO_SYMLINK_TARGET) {
			if (!names_p) {
				e.names_count++;
			} else {
				e.names_count--;
				right = TOMOYO_NAME_UNION;
				param->data = right_word;
				if (!tomoyo_parse_name_union_quoted(param,
								    names_p++))
					goto out;
			}
			goto store_value;
		}
		right = tomoyo_condition_type(right_word);
		if (right == TOMOYO_MAX_CONDITION_KEYWORD) {
			if (!numbers_p) {
				e.numbers_count++;
			} else {
				e.numbers_count--;
				right = TOMOYO_NUMBER_UNION;
				param->data = right_word;
				if (!tomoyo_parse_number_union(param,
							       numbers_p++))
					goto out;
			}
		}
store_value:
		if (!condp) {
			dprintk(KERN_WARNING "%u: dry_run left=%u right=%u "
				"match=%u\n", __LINE__, left, right, !is_not);
			continue;
		}
		condp->left = left;
		condp->right = right;
		condp->equals = !is_not;
		dprintk(KERN_WARNING "%u: left=%u right=%u match=%u\n",
			__LINE__, condp->left, condp->right,
			condp->equals);
		condp++;
	}
	dprintk(KERN_INFO "%u: cond=%u numbers=%u names=%u ac=%u ec=%u\n",
		__LINE__, e.condc, e.numbers_count, e.names_count, e.argc,
		e.envc);
	if (entry)
		return tomoyo_commit_condition(entry);
	e.size = sizeof(*entry)
		+ e.condc * sizeof(struct tomoyo_condition_element)
		+ e.numbers_count * sizeof(struct tomoyo_number_union)
		+ e.names_count * sizeof(struct tomoyo_name_union)
		+ e.argc * sizeof(struct tomoyo_argv)
		+ e.envc * sizeof(struct tomoyo_envp);
	entry = tomoyo_malloc(e.size);
	*entry = e;
	condp = (struct tomoyo_condition_element *) (entry + 1);
	numbers_p = (struct tomoyo_number_union *) (condp + e.condc);
	names_p = (struct tomoyo_name_union *) (numbers_p + e.numbers_count);
	argv = (struct tomoyo_argv *) (names_p + e.names_count);
	envp = (struct tomoyo_envp *) (argv + e.argc);
	{
		bool flag = false;
		for (pos = start_of_string; pos < end_of_string; pos++) {
			if (*pos)
				continue;
			if (flag) /* Restore " ". */
				*pos = ' ';
			else if (*(pos + 1) == '=') /* Restore "!=". */
				*pos = '!';
			else /* Restore "=". */
				*pos = '=';
			flag = !flag;
		}
	}
	goto rerun;
out:
	dprintk(KERN_WARNING "%u: %s failed\n", __LINE__, __func__);
	if (entry) {
		tomoyo_del_condition(&entry->head.list);
		free(entry);
	}
	return NULL;
}

/**
 * tomoyo_same_acl_head - Check for duplicated "struct tomoyo_acl_info" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static inline bool tomoyo_same_acl_head(const struct tomoyo_acl_info *a,
					const struct tomoyo_acl_info *b)
{
	return a->type == b->type && a->cond == b->cond;
}

/**
 * tomoyo_update_domain - Update an entry for domain policy.
 *
 * @new_entry:       Pointer to "struct tomoyo_acl_info".
 * @size:            Size of @new_entry in bytes.
 * @param:           Pointer to "struct tomoyo_acl_param".
 * @check_duplicate: Callback function to find duplicated entry.
 * @merge_duplicate: Callback function to merge duplicated entry. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_update_domain(struct tomoyo_acl_info *new_entry,
				const int size, struct tomoyo_acl_param *param,
				bool (*check_duplicate)
				(const struct tomoyo_acl_info *,
				 const struct tomoyo_acl_info *),
				bool (*merge_duplicate)
				(struct tomoyo_acl_info *,
				 struct tomoyo_acl_info *,
				 const bool))
{
	const bool is_delete = param->is_delete;
	int error = is_delete ? -ENOENT : -ENOMEM;
	struct tomoyo_acl_info *entry;
	struct list_head * const list = param->list;
	if (param->data[0]) {
		new_entry->cond = tomoyo_get_condition(param);
		if (!new_entry->cond)
			return -EINVAL;
	}
	list_for_each_entry(entry, list, list) {
		if (!tomoyo_same_acl_head(entry, new_entry) ||
		    !check_duplicate(entry, new_entry))
			continue;
		if (merge_duplicate)
			entry->is_deleted = merge_duplicate(entry, new_entry,
							    is_delete);
		else
			entry->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (error && !is_delete) {
		entry = tomoyo_commit_ok(new_entry, size);
		list_add_tail(&entry->list, list);
		error = 0;
	}
	tomoyo_put_condition(new_entry->cond);
	return error;
}

/**
 * tomoyo_same_transition_control - Check for duplicated "struct tomoyo_transition_control" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_head".
 * @b: Pointer to "struct tomoyo_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_transition_control(const struct tomoyo_acl_head *a,
					   const struct tomoyo_acl_head *b)
{
	const struct tomoyo_transition_control *p1 =
		container_of(a, typeof(*p1), head);
	const struct tomoyo_transition_control *p2 =
		container_of(b, typeof(*p2), head);
	return p1->type == p2->type && p1->is_last_name == p2->is_last_name
		&& p1->domainname == p2->domainname
		&& p1->program == p2->program && p1->ns == p2->ns;
}

/**
 * tomoyo_write_transition_control - Write "struct tomoyo_transition_control" list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 * @type:  Type of this entry.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_transition_control(struct tomoyo_acl_param *param,
					   const u8 type)
{
	struct tomoyo_transition_control e = { .type = type, .ns = param->ns };
	int error = param->is_delete ? -ENOENT : -ENOMEM;
	char *program = param->data;
	char *domainname = strstr(program, " from ");
	if (domainname) {
		*domainname = '\0';
		domainname += 6;
	} else if (type == TOMOYO_TRANSITION_CONTROL_NO_KEEP ||
		   type == TOMOYO_TRANSITION_CONTROL_KEEP) {
		domainname = program;
		program = NULL;
	}
	if (program && strcmp(program, "any")) {
		if (!tomoyo_correct_path(program))
			return -EINVAL;
		e.program = tomoyo_get_name(program);
	}
	if (domainname && strcmp(domainname, "any")) {
		if (!tomoyo_correct_domain(domainname)) {
			if (!tomoyo_correct_path(domainname))
				goto out;
			e.is_last_name = true;
		}
		e.domainname = tomoyo_get_name(domainname);
	}
	param->list = &tomoyo_transition_list;
	error = tomoyo_update_policy(&e.head, sizeof(e), param,
				     tomoyo_same_transition_control);
out:
	tomoyo_put_name(e.domainname);
	tomoyo_put_name(e.program);
	return error;
}

/**
 * tomoyo_same_aggregator - Check for duplicated "struct tomoyo_aggregator" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_head".
 * @b: Pointer to "struct tomoyo_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_aggregator(const struct tomoyo_acl_head *a,
				   const struct tomoyo_acl_head *b)
{
	const struct tomoyo_aggregator *p1 = container_of(a, typeof(*p1),
							  head);
	const struct tomoyo_aggregator *p2 = container_of(b, typeof(*p2),
							  head);
	return p1->original_name == p2->original_name &&
		p1->aggregated_name == p2->aggregated_name && p1->ns == p2->ns;
}

/**
 * tomoyo_write_aggregator - Write "struct tomoyo_aggregator" list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_aggregator(struct tomoyo_acl_param *param)
{
	struct tomoyo_aggregator e = { .ns = param->ns };
	int error = param->is_delete ? -ENOENT : -ENOMEM;
	const char *original_name = tomoyo_read_token(param);
	const char *aggregated_name = tomoyo_read_token(param);
	if (!tomoyo_correct_word(original_name) ||
	    !tomoyo_correct_path(aggregated_name))
		return -EINVAL;
	e.original_name = tomoyo_get_name(original_name);
	e.aggregated_name = tomoyo_get_name(aggregated_name);
	if (e.aggregated_name->is_patterned) /* No patterns allowed. */
		goto out;
	param->list = &tomoyo_aggregator_list;
	error = tomoyo_update_policy(&e.head, sizeof(e), param,
				     tomoyo_same_aggregator);
out:
	tomoyo_put_name(e.original_name);
	tomoyo_put_name(e.aggregated_name);
	return error;
}

/* Domain create handler. */

/**
 * tomoyo_find_namespace - Find specified namespace.
 *
 * @name: Name of namespace to find.
 * @len:  Length of @name.
 *
 * Returns pointer to "struct tomoyo_policy_namespace" if found, NULL
 * otherwise.
 */
static struct tomoyo_policy_namespace *tomoyo_find_namespace
(const char *name, const unsigned int len)
{
	struct tomoyo_policy_namespace *ns;
	list_for_each_entry(ns, &tomoyo_namespace_list, namespace_list) {
		if (strncmp(name, ns->name, len) ||
		    (name[len] && name[len] != ' '))
			continue;
		return ns;
	}
	return NULL;
}

/**
 * tomoyo_assign_namespace - Create a new namespace.
 *
 * @domainname: Name of namespace to create.
 *
 * Returns pointer to "struct tomoyo_policy_namespace" on success, NULL
 * otherwise.
 */
static struct tomoyo_policy_namespace *tomoyo_assign_namespace
(const char *domainname)
{
	struct tomoyo_policy_namespace *ptr;
	struct tomoyo_policy_namespace *entry;
	const char *cp = domainname;
	unsigned int len = 0;
	while (*cp && *cp++ != ' ')
		len++;
	ptr = tomoyo_find_namespace(domainname, len);
	if (ptr)
		return ptr;
	if (len >= TOMOYO_EXEC_TMPSIZE - 10 || !tomoyo_domain_def(domainname))
		return NULL;
	entry = tomoyo_malloc(sizeof(*entry) + len + 1);
	{
		char *name = (char *) (entry + 1);
		memmove(name, domainname, len);
		name[len] = '\0';
		entry->name = name;
	}
	entry->profile_version = 20100903;
	for (len = 0; len < TOMOYO_MAX_ACL_GROUPS; len++)
		INIT_LIST_HEAD(&entry->acl_group[len]);
	tomoyo_namespace_enabled = !list_empty(&tomoyo_namespace_list);
	list_add_tail(&entry->namespace_list, &tomoyo_namespace_list);
	return entry;
}

/**
 * tomoyo_assign_domain2 - Create a domain or a namespace.
 *
 * @domainname: The name of domain.
 *
 * Returns pointer to "struct tomoyo_domain2_info" on success, NULL otherwise.
 */
static struct tomoyo_domain2_info *tomoyo_assign_domain2
(const char *domainname)
{
	struct tomoyo_domain2_info e = { };
	struct tomoyo_domain2_info *entry = tomoyo_find_domain2(domainname);
	if (entry)
		return entry;
	/* Requested domain does not exist. */
	/* Don't create requested domain if domainname is invalid. */
	if (strlen(domainname) >= TOMOYO_EXEC_TMPSIZE - 10 ||
	    !tomoyo_correct_domain(domainname))
		return NULL;
	e.domainname = tomoyo_get_name(domainname);
	entry = tomoyo_commit_ok(&e, sizeof(e));
	INIT_LIST_HEAD(&entry->acl_info_list);
	list_add_tail(&entry->list, &tomoyo_domain_list);
	tomoyo_put_name(e.domainname);
	return entry;
}

/**
 * tomoyo_same_path_acl - Check for duplicated "struct tomoyo_path_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b except permission bits, false otherwise.
 */
static bool tomoyo_same_path_acl(const struct tomoyo_acl_info *a,
				 const struct tomoyo_acl_info *b)
{
	const struct tomoyo_path_acl *p1 = container_of(a, typeof(*p1), head);
	const struct tomoyo_path_acl *p2 = container_of(b, typeof(*p2), head);
	return tomoyo_same_name_union(&p1->name, &p2->name);
}

/**
 * tomoyo_merge_path_acl - Merge duplicated "struct tomoyo_path_acl" entry.
 *
 * @a:         Pointer to "struct tomoyo_acl_info".
 * @b:         Pointer to "struct tomoyo_acl_info".
 * @is_delete: True for @a &= ~@b, false for @a |= @b.
 *
 * Returns true if @a is empty, false otherwise.
 */
static bool tomoyo_merge_path_acl(struct tomoyo_acl_info *a,
				  struct tomoyo_acl_info *b,
				  const bool is_delete)
{
	u16 * const a_perm = &container_of(a, struct tomoyo_path_acl, head)
		->perm;
	u16 perm = *a_perm;
	const u16 b_perm = container_of(b, struct tomoyo_path_acl, head)->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * tomoyo_update_path_acl - Update "struct tomoyo_path_acl" list.
 *
 * @perm:  Permission.
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_update_path_acl(const u16 perm,
				  struct tomoyo_acl_param *param)
{
	struct tomoyo_path_acl e = {
		.head.type = TOMOYO_TYPE_PATH_ACL,
		.perm = perm
	};
	int error;
	if (!tomoyo_parse_name_union(param, &e.name))
		error = -EINVAL;
	else
		error = tomoyo_update_domain(&e.head, sizeof(e), param,
					     tomoyo_same_path_acl,
					     tomoyo_merge_path_acl);
	tomoyo_put_name_union(&e.name);
	return error;
}

/**
 * tomoyo_same_mkdev_acl - Check for duplicated "struct tomoyo_mkdev_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b except permission bits, false otherwise.
 */
static bool tomoyo_same_mkdev_acl(const struct tomoyo_acl_info *a,
				  const struct tomoyo_acl_info *b)
{
	const struct tomoyo_mkdev_acl *p1 = container_of(a, typeof(*p1), head);
	const struct tomoyo_mkdev_acl *p2 = container_of(b, typeof(*p2), head);
	return tomoyo_same_name_union(&p1->name, &p2->name) &&
		tomoyo_same_number_union(&p1->mode, &p2->mode) &&
		tomoyo_same_number_union(&p1->major, &p2->major) &&
		tomoyo_same_number_union(&p1->minor, &p2->minor);
}

/**
 * tomoyo_merge_mkdev_acl - Merge duplicated "struct tomoyo_mkdev_acl" entry.
 *
 * @a:         Pointer to "struct tomoyo_acl_info".
 * @b:         Pointer to "struct tomoyo_acl_info".
 * @is_delete: True for @a &= ~@b, false for @a |= @b.
 *
 * Returns true if @a is empty, false otherwise.
 */
static bool tomoyo_merge_mkdev_acl(struct tomoyo_acl_info *a,
				   struct tomoyo_acl_info *b,
				   const bool is_delete)
{
	u8 *const a_perm = &container_of(a, struct tomoyo_mkdev_acl, head)
		->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct tomoyo_mkdev_acl, head)->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * tomoyo_update_mkdev_acl - Update "struct tomoyo_mkdev_acl" list.
 *
 * @perm:  Permission.
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_update_mkdev_acl(const u8 perm,
				   struct tomoyo_acl_param *param)
{
	struct tomoyo_mkdev_acl e = {
		.head.type = TOMOYO_TYPE_MKDEV_ACL,
		.perm = perm
	};
	int error;
	if (!tomoyo_parse_name_union(param, &e.name) ||
	    !tomoyo_parse_number_union(param, &e.mode) ||
	    !tomoyo_parse_number_union(param, &e.major) ||
	    !tomoyo_parse_number_union(param, &e.minor))
		error = -EINVAL;
	else
		error = tomoyo_update_domain(&e.head, sizeof(e), param,
					     tomoyo_same_mkdev_acl,
					     tomoyo_merge_mkdev_acl);
	tomoyo_put_name_union(&e.name);
	tomoyo_put_number_union(&e.mode);
	tomoyo_put_number_union(&e.major);
	tomoyo_put_number_union(&e.minor);
	return error;
}

/**
 * tomoyo_same_path2_acl - Check for duplicated "struct tomoyo_path2_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b except permission bits, false otherwise.
 */
static bool tomoyo_same_path2_acl(const struct tomoyo_acl_info *a,
				  const struct tomoyo_acl_info *b)
{
	const struct tomoyo_path2_acl *p1 = container_of(a, typeof(*p1), head);
	const struct tomoyo_path2_acl *p2 = container_of(b, typeof(*p2), head);
	return tomoyo_same_name_union(&p1->name1, &p2->name1) &&
		tomoyo_same_name_union(&p1->name2, &p2->name2);
}

/**
 * tomoyo_merge_path2_acl - Merge duplicated "struct tomoyo_path2_acl" entry.
 *
 * @a:         Pointer to "struct tomoyo_acl_info".
 * @b:         Pointer to "struct tomoyo_acl_info".
 * @is_delete: True for @a &= ~@b, false for @a |= @b.
 *
 * Returns true if @a is empty, false otherwise.
 */
static bool tomoyo_merge_path2_acl(struct tomoyo_acl_info *a,
				   struct tomoyo_acl_info *b,
				   const bool is_delete)
{
	u8 * const a_perm = &container_of(a, struct tomoyo_path2_acl, head)
		->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct tomoyo_path2_acl, head)->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * tomoyo_update_path2_acl - Update "struct tomoyo_path2_acl" list.
 *
 * @perm:  Permission.
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_update_path2_acl(const u8 perm,
				   struct tomoyo_acl_param *param)
{
	struct tomoyo_path2_acl e = {
		.head.type = TOMOYO_TYPE_PATH2_ACL,
		.perm = perm
	};
	int error;
	if (!tomoyo_parse_name_union(param, &e.name1) ||
	    !tomoyo_parse_name_union(param, &e.name2))
		error = -EINVAL;
	else
		error = tomoyo_update_domain(&e.head, sizeof(e), param,
					     tomoyo_same_path2_acl,
					     tomoyo_merge_path2_acl);
	tomoyo_put_name_union(&e.name1);
	tomoyo_put_name_union(&e.name2);
	return error;
}

/**
 * tomoyo_same_path_number_acl - Check for duplicated "struct tomoyo_path_number_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b except permission bits, false otherwise.
 */
static bool tomoyo_same_path_number_acl(const struct tomoyo_acl_info *a,
					const struct tomoyo_acl_info *b)
{
	const struct tomoyo_path_number_acl *p1 = container_of(a, typeof(*p1),
							       head);
	const struct tomoyo_path_number_acl *p2 = container_of(b, typeof(*p2),
							       head);
	return tomoyo_same_name_union(&p1->name, &p2->name) &&
		tomoyo_same_number_union(&p1->number, &p2->number);
}

/**
 * tomoyo_merge_path_number_acl - Merge duplicated "struct tomoyo_path_number_acl" entry.
 *
 * @a:         Pointer to "struct tomoyo_acl_info".
 * @b:         Pointer to "struct tomoyo_acl_info".
 * @is_delete: True for @a &= ~@b, false for @a |= @b.
 *
 * Returns true if @a is empty, false otherwise.
 */
static bool tomoyo_merge_path_number_acl(struct tomoyo_acl_info *a,
					 struct tomoyo_acl_info *b,
					 const bool is_delete)
{
	u8 * const a_perm = &container_of(a, struct tomoyo_path_number_acl,
					  head)->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct tomoyo_path_number_acl, head)
		->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * tomoyo_update_path_number_acl - Update create/mkdir/mkfifo/mksock/ioctl/chmod/chown/chgrp ACL.
 *
 * @perm:  Permission.
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_update_path_number_acl(const u8 perm,
					 struct tomoyo_acl_param *param)
{
	struct tomoyo_path_number_acl e = {
		.head.type = TOMOYO_TYPE_PATH_NUMBER_ACL,
		.perm = perm
	};
	int error;
	if (!tomoyo_parse_name_union(param, &e.name) ||
	    !tomoyo_parse_number_union(param, &e.number))
		error = -EINVAL;
	else
		error = tomoyo_update_domain(&e.head, sizeof(e), param,
					     tomoyo_same_path_number_acl,
					     tomoyo_merge_path_number_acl);
	tomoyo_put_name_union(&e.name);
	tomoyo_put_number_union(&e.number);
	return error;
}

/**
 * tomoyo_same_mount_acl - Check for duplicated "struct tomoyo_mount_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_mount_acl(const struct tomoyo_acl_info *a,
				  const struct tomoyo_acl_info *b)
{
	const struct tomoyo_mount_acl *p1 = container_of(a, typeof(*p1), head);
	const struct tomoyo_mount_acl *p2 = container_of(b, typeof(*p2), head);
	return tomoyo_same_name_union(&p1->dev_name, &p2->dev_name) &&
		tomoyo_same_name_union(&p1->dir_name, &p2->dir_name) &&
		tomoyo_same_name_union(&p1->fs_type, &p2->fs_type) &&
		tomoyo_same_number_union(&p1->flags, &p2->flags);
}

/**
 * tomoyo_update_mount_acl - Write "struct tomoyo_mount_acl" list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_update_mount_acl(struct tomoyo_acl_param *param)
{
	struct tomoyo_mount_acl e = { .head.type = TOMOYO_TYPE_MOUNT_ACL };
	int error;
	if (!tomoyo_parse_name_union(param, &e.dev_name) ||
	    !tomoyo_parse_name_union(param, &e.dir_name) ||
	    !tomoyo_parse_name_union(param, &e.fs_type) ||
	    !tomoyo_parse_number_union(param, &e.flags))
		error = -EINVAL;
	else
		error = tomoyo_update_domain(&e.head, sizeof(e), param,
					     tomoyo_same_mount_acl, NULL);
	tomoyo_put_name_union(&e.dev_name);
	tomoyo_put_name_union(&e.dir_name);
	tomoyo_put_name_union(&e.fs_type);
	tomoyo_put_number_union(&e.flags);
	return error;
}

/**
 * tomoyo_write_file - Update file related list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_file(struct tomoyo_acl_param *param)
{
	u16 perm = 0;
	u8 type;
	const char *operation = tomoyo_read_token(param);
	for (type = 0; type < TOMOYO_MAX_PATH_OPERATION; type++)
		if (tomoyo_permstr(operation, tomoyo_path_keyword[type]))
			perm |= 1 << type;
	if (perm)
		return tomoyo_update_path_acl(perm, param);
	for (type = 0; type < TOMOYO_MAX_PATH2_OPERATION; type++)
		if (tomoyo_permstr(operation,
				   tomoyo_mac_keywords[tomoyo_pp2mac[type]]))
			perm |= 1 << type;
	if (perm)
		return tomoyo_update_path2_acl(perm, param);
	for (type = 0; type < TOMOYO_MAX_PATH_NUMBER_OPERATION; type++)
		if (tomoyo_permstr(operation,
				   tomoyo_mac_keywords[tomoyo_pn2mac[type]]))
			perm |= 1 << type;
	if (perm)
		return tomoyo_update_path_number_acl(perm, param);
	for (type = 0; type < TOMOYO_MAX_MKDEV_OPERATION; type++)
		if (tomoyo_permstr(operation,
				   tomoyo_mac_keywords[tomoyo_pnnn2mac[type]]))
			perm |= 1 << type;
	if (perm)
		return tomoyo_update_mkdev_acl(perm, param);
	if (tomoyo_permstr(operation,
			   tomoyo_mac_keywords[TOMOYO_MAC_FILE_MOUNT]))
		return tomoyo_update_mount_acl(param);
	return -EINVAL;
}

/* Structure for holding inet domain socket's address. */
struct tomoyo_inet_addr_info {
	u16 port;           /* In network byte order. */
	const u32 *address; /* In network byte order. */
	bool is_ipv6;
};

/* Structure for holding unix domain socket's address. */
struct tomoyo_unix_addr_info {
	u8 *addr; /* This may not be '\0' terminated string. */
	unsigned int addr_len;
};

/* Structure for holding socket address. */
struct tomoyo_addr_info {
	u8 protocol;
	u8 operation;
	struct tomoyo_inet_addr_info inet;
	struct tomoyo_unix_addr_info unix0;
};

/**
 * tomoyo_parse_ipaddr_union - Parse an IP address.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 * @ptr:   Pointer to "struct tomoyo_ipaddr_union".
 *
 * Returns true on success, false otherwise.
 */
static bool tomoyo_parse_ipaddr_union(struct tomoyo_acl_param *param,
				      struct tomoyo_ipaddr_union *ptr)
{
	u16 * const min = ptr->ip[0].s6_addr16;
	u16 * const max = ptr->ip[1].s6_addr16;
	char *address = tomoyo_read_token(param);
	int count = sscanf(address, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx"
			   "-%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
			   &min[0], &min[1], &min[2], &min[3],
			   &min[4], &min[5], &min[6], &min[7],
			   &max[0], &max[1], &max[2], &max[3],
			   &max[4], &max[5], &max[6], &max[7]);
	if (count == 8 || count == 16) {
		u8 i;
		if (count == 8)
			memmove(max, min, sizeof(u16) * 8);
		for (i = 0; i < 8; i++) {
			min[i] = htons(min[i]);
			max[i] = htons(max[i]);
		}
		ptr->is_ipv6 = true;
		return true;
	}
	count = sscanf(address, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
		       &min[0], &min[1], &min[2], &min[3],
		       &max[0], &max[1], &max[2], &max[3]);
	if (count == 4 || count == 8) {
		/* use host byte order to allow u32 comparison.*/
		ptr->ip[0].s6_addr32[0] =
			(((u8) min[0]) << 24) + (((u8) min[1]) << 16)
			+ (((u8) min[2]) << 8) + (u8) min[3];
		if (count == 4)
			ptr->ip[1].s6_addr32[0] = ptr->ip[0].s6_addr32[0];
		else
			ptr->ip[1].s6_addr32[0] =
				(((u8) max[0]) << 24) + (((u8) max[1]) << 16)
				+ (((u8) max[2]) << 8) + (u8) max[3];
		ptr->is_ipv6 = false;
		return true;
	}
	return false;
}

/**
 * tomoyo_print_ipv4 - Print an IPv4 address.
 *
 * @min_ip: Min address in host byte order.
 * @max_ip: Max address in host byte order.
 *
 * Returns nothing.
 */
static void tomoyo_print_ipv4(const u32 min_ip, const u32 max_ip)
{
	cprintf("%u.%u.%u.%u", HIPQUAD(min_ip));
	if (min_ip != max_ip)
		cprintf("-%u.%u.%u.%u", HIPQUAD(max_ip));
}

/**
 * tomoyo_print_ipv6 - Print an IPv6 address.
 *
 * @min_ip: Pointer to "struct in6_addr".
 * @max_ip: Pointer to "struct in6_addr".
 *
 * Returns nothing.
 */
static void tomoyo_print_ipv6(const struct in6_addr *min_ip,
			      const struct in6_addr *max_ip)
{
	cprintf("%x:%x:%x:%x:%x:%x:%x:%x", NIP6(*min_ip));
	if (memcmp(min_ip, max_ip, 16))
		cprintf("-%x:%x:%x:%x:%x:%x:%x:%x", NIP6(*max_ip));
}

/**
 * tomoyo_print_ip - Print an IP address.
 *
 * @ptr: Pointer to "struct ipaddr_union".
 *
 * Returns nothing.
 */
static void tomoyo_print_ip(const struct tomoyo_ipaddr_union *ptr)
{
	if (ptr->is_ipv6)
		tomoyo_print_ipv6(&ptr->ip[0], &ptr->ip[1]);
	else
		tomoyo_print_ipv4(ptr->ip[0].s6_addr32[0],
				  ptr->ip[1].s6_addr32[0]);
}

/**
 * tomoyo_same_inet_acl - Check for duplicated "struct tomoyo_inet_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b except permission bits, false otherwise.
 */
static bool tomoyo_same_inet_acl(const struct tomoyo_acl_info *a,
				 const struct tomoyo_acl_info *b)
{
	const struct tomoyo_inet_acl *p1 = container_of(a, typeof(*p1), head);
	const struct tomoyo_inet_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->protocol == p2->protocol &&
		tomoyo_same_ipaddr_union(&p1->address, &p2->address) &&
		tomoyo_same_number_union(&p1->port, &p2->port);
}

/**
 * tomoyo_same_unix_acl - Check for duplicated "struct tomoyo_unix_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b except permission bits, false otherwise.
 */
static bool tomoyo_same_unix_acl(const struct tomoyo_acl_info *a,
				 const struct tomoyo_acl_info *b)
{
	const struct tomoyo_unix_acl *p1 = container_of(a, typeof(*p1), head);
	const struct tomoyo_unix_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->protocol == p2->protocol &&
		tomoyo_same_name_union(&p1->name, &p2->name);
}

/**
 * tomoyo_merge_inet_acl - Merge duplicated "struct tomoyo_inet_acl" entry.
 *
 * @a:         Pointer to "struct tomoyo_acl_info".
 * @b:         Pointer to "struct tomoyo_acl_info".
 * @is_delete: True for @a &= ~@b, false for @a |= @b.
 *
 * Returns true if @a is empty, false otherwise.
 */
static bool tomoyo_merge_inet_acl(struct tomoyo_acl_info *a,
				  struct tomoyo_acl_info *b,
				  const bool is_delete)
{
	u8 * const a_perm = &container_of(a, struct tomoyo_inet_acl, head)
		->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct tomoyo_inet_acl, head)->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * tomoyo_merge_unix_acl - Merge duplicated "struct tomoyo_unix_acl" entry.
 *
 * @a:         Pointer to "struct tomoyo_acl_info".
 * @b:         Pointer to "struct tomoyo_acl_info".
 * @is_delete: True for @a &= ~@b, false for @a |= @b.
 *
 * Returns true if @a is empty, false otherwise.
 */
static bool tomoyo_merge_unix_acl(struct tomoyo_acl_info *a,
				  struct tomoyo_acl_info *b,
				  const bool is_delete)
{
	u8 * const a_perm = &container_of(a, struct tomoyo_unix_acl, head)
		->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct tomoyo_unix_acl, head)->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * tomoyo_write_inet_network - Write "struct tomoyo_inet_acl" list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_inet_network(struct tomoyo_acl_param *param)
{
	struct tomoyo_inet_acl e = { .head.type = TOMOYO_TYPE_INET_ACL };
	int error = -EINVAL;
	u8 type;
	const char *protocol = tomoyo_read_token(param);
	const char *operation = tomoyo_read_token(param);
	for (e.protocol = 0; e.protocol < TOMOYO_SOCK_MAX; e.protocol++)
		if (!strcmp(protocol, tomoyo_proto_keyword[e.protocol]))
			break;
	for (type = 0; type < TOMOYO_MAX_NETWORK_OPERATION; type++)
		if (tomoyo_permstr(operation, tomoyo_socket_keyword[type]))
			e.perm |= 1 << type;
	if (e.protocol == TOMOYO_SOCK_MAX || !e.perm)
		return -EINVAL;
	if (param->data[0] == '@') {
		param->data++;
		e.address.group = tomoyo_get_group(param,
						   &tomoyo_address_group);
		if (!e.address.group)
			return -ENOMEM;
	} else {
		if (!tomoyo_parse_ipaddr_union(param, &e.address))
			goto out;
	}
	if (!tomoyo_parse_number_union(param, &e.port) ||
	    e.port.values[1] > 65535)
		goto out;
	error = tomoyo_update_domain(&e.head, sizeof(e), param,
				     tomoyo_same_inet_acl,
				     tomoyo_merge_inet_acl);
out:
	tomoyo_put_group(e.address.group);
	tomoyo_put_number_union(&e.port);
	return error;
}

/**
 * tomoyo_write_unix_network - Write "struct tomoyo_unix_acl" list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_unix_network(struct tomoyo_acl_param *param)
{
	struct tomoyo_unix_acl e = { .head.type = TOMOYO_TYPE_UNIX_ACL };
	int error;
	u8 type;
	const char *protocol = tomoyo_read_token(param);
	const char *operation = tomoyo_read_token(param);
	for (e.protocol = 0; e.protocol < TOMOYO_SOCK_MAX; e.protocol++)
		if (!strcmp(protocol, tomoyo_proto_keyword[e.protocol]))
			break;
	for (type = 0; type < TOMOYO_MAX_NETWORK_OPERATION; type++)
		if (tomoyo_permstr(operation, tomoyo_socket_keyword[type]))
			e.perm |= 1 << type;
	if (e.protocol == TOMOYO_SOCK_MAX || !e.perm)
		return -EINVAL;
	if (!tomoyo_parse_name_union(param, &e.name))
		return -EINVAL;
	error = tomoyo_update_domain(&e.head, sizeof(e), param,
				     tomoyo_same_unix_acl,
				     tomoyo_merge_unix_acl);
	tomoyo_put_name_union(&e.name);
	return error;
}

/**
 * tomoyo_same_capability_acl - Check for duplicated "struct tomoyo_capability_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_capability_acl(const struct tomoyo_acl_info *a,
				       const struct tomoyo_acl_info *b)
{
	const struct tomoyo_capability_acl *p1 = container_of(a, typeof(*p1),
							      head);
	const struct tomoyo_capability_acl *p2 = container_of(b, typeof(*p2),
							      head);
	return p1->operation == p2->operation;
}

/**
 * tomoyo_write_capability - Write "struct tomoyo_capability_acl" list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_capability(struct tomoyo_acl_param *param)
{
	struct tomoyo_capability_acl e = {
		.head.type = TOMOYO_TYPE_CAPABILITY_ACL };
	const char *operation = tomoyo_read_token(param);
	for (e.operation = 0; e.operation < TOMOYO_MAX_CAPABILITY_INDEX;
	     e.operation++) {
		if (strcmp(operation,
			   tomoyo_mac_keywords[tomoyo_c2mac[e.operation]]))
			continue;
		return tomoyo_update_domain(&e.head, sizeof(e), param,
					    tomoyo_same_capability_acl, NULL);
	}
	return -EINVAL;
}

/**
 * tomoyo_same_env_acl - Check for duplicated "struct tomoyo_env_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_env_acl(const struct tomoyo_acl_info *a,
				const struct tomoyo_acl_info *b)
{
	const struct tomoyo_env_acl *p1 = container_of(a, typeof(*p1), head);
	const struct tomoyo_env_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->env == p2->env;
}

/**
 * tomoyo_write_env - Write "struct tomoyo_env_acl" list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_env(struct tomoyo_acl_param *param)
{
	struct tomoyo_env_acl e = { .head.type = TOMOYO_TYPE_ENV_ACL };
	int error = -ENOMEM;
	const char *data = tomoyo_read_token(param);
	if (!tomoyo_correct_word(data) || strchr(data, '='))
		return -EINVAL;
	e.env = tomoyo_get_name(data);
	error = tomoyo_update_domain(&e.head, sizeof(e), param,
				     tomoyo_same_env_acl, NULL);
	tomoyo_put_name(e.env);
	return error;
}

/**
 * tomoyo_write_misc - Update environment variable list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_misc(struct tomoyo_acl_param *param)
{
	if (tomoyo_str_starts(param->data, "env "))
		return tomoyo_write_env(param);
	return -EINVAL;
}

/**
 * tomoyo_same_signal_acl - Check for duplicated "struct tomoyo_signal_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_signal_acl(const struct tomoyo_acl_info *a,
				   const struct tomoyo_acl_info *b)
{
	const struct tomoyo_signal_acl *p1 = container_of(a, typeof(*p1),
							  head);
	const struct tomoyo_signal_acl *p2 = container_of(b, typeof(*p2),
							  head);
	return tomoyo_same_number_union(&p1->sig, &p2->sig) &&
		p1->domainname == p2->domainname;
}

/**
 * tomoyo_write_ipc - Update "struct tomoyo_signal_acl" list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_ipc(struct tomoyo_acl_param *param)
{
	struct tomoyo_signal_acl e = { .head.type = TOMOYO_TYPE_SIGNAL_ACL };
	int error;
	if (!tomoyo_parse_number_union(param, &e.sig))
		return -EINVAL;
	e.domainname = tomoyo_get_domainname(param);
	if (!e.domainname)
		error = -EINVAL;
	else
		error = tomoyo_update_domain(&e.head, sizeof(e), param,
					     tomoyo_same_signal_acl, NULL);
	tomoyo_put_name(e.domainname);
	tomoyo_put_number_union(&e.sig);
	return error;
}


/**
 * tomoyo_same_reserved - Check for duplicated "struct tomoyo_reserved" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_head".
 * @b: Pointer to "struct tomoyo_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_reserved(const struct tomoyo_acl_head *a,
				 const struct tomoyo_acl_head *b)
{
	const struct tomoyo_reserved *p1 = container_of(a, typeof(*p1), head);
	const struct tomoyo_reserved *p2 = container_of(b, typeof(*p2), head);
	return p1->ns == p2->ns && tomoyo_same_number_union(&p1->port,
							    &p2->port);
}

/**
 * tomoyo_write_reserved_port - Update "struct tomoyo_reserved" list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_reserved_port(struct tomoyo_acl_param *param)
{
	struct tomoyo_reserved e = { .ns = param->ns };
	int error;
	if (param->data[0] == '@' || !tomoyo_parse_number_union(param, &e.port)
	    || e.port.values[1] > 65535 || param->data[0])
		return -EINVAL;
	param->list = &tomoyo_reserved_list;
	error = tomoyo_update_policy(&e.head, sizeof(e), param,
				     tomoyo_same_reserved);
	/*
	 * tomoyo_put_number_union() is not needed because
	 * param->data[0] != '@'.
	 */
	return error;
}

/**
 * tomoyo_print_namespace - Print namespace header.
 *
 * @ns: Pointer to "struct tomoyo_policy_namespace".
 *
 * Returns nothing.
 */
static void tomoyo_print_namespace(const struct tomoyo_policy_namespace *ns)
{
	if (!tomoyo_namespace_enabled)
		return;
	cprintf("%s ", ns->name);
}

/**
 * tomoyo_assign_profile - Create a new profile.
 *
 * @ns:      Pointer to "struct tomoyo_policy_namespace".
 * @profile: Profile number to create.
 *
 * Returns pointer to "struct tomoyo_profile" on success, NULL otherwise.
 */
static struct tomoyo_profile *tomoyo_assign_profile
(struct tomoyo_policy_namespace *ns, const unsigned int profile)
{
	struct tomoyo_profile *ptr;
	if (profile >= TOMOYO_MAX_PROFILES)
		return NULL;
	ptr = ns->profile_ptr[profile];
	if (ptr)
		return ptr;
	ptr = tomoyo_malloc(sizeof(*ptr));
	ptr->default_config = TOMOYO_CONFIG_DISABLED |
		TOMOYO_CONFIG_WANT_GRANT_LOG | TOMOYO_CONFIG_WANT_REJECT_LOG;
	memset(ptr->config, TOMOYO_CONFIG_USE_DEFAULT,
	       sizeof(ptr->config));
	ptr->pref[TOMOYO_PREF_MAX_AUDIT_LOG] = 1024;
	ptr->pref[TOMOYO_PREF_MAX_LEARNING_ENTRY] = 2048;
	ns->profile_ptr[profile] = ptr;
	return ptr;
}

/**
 * tomoyo_find_yesno - Find values for specified keyword.
 *
 * @string: String to check.
 * @find:   Name of keyword.
 *
 * Returns 1 if "@find=yes" was found, 0 if "@find=no" was found, -1 otherwise.
 */
static s8 tomoyo_find_yesno(const char *string, const char *find)
{
	const char *cp = strstr(string, find);
	if (cp) {
		cp += strlen(find);
		if (!strncmp(cp, "=yes", 4))
			return 1;
		else if (!strncmp(cp, "=no", 3))
			return 0;
	}
	return -1;
}

/**
 * tomoyo_set_uint - Set value for specified preference.
 *
 * @i:      Pointer to "unsigned int".
 * @string: String to check.
 * @find:   Name of keyword.
 *
 * Returns nothing.
 */
static void tomoyo_set_uint(unsigned int *i, const char *string,
			    const char *find)
{
	const char *cp = strstr(string, find);
	if (cp)
		sscanf(cp + strlen(find), "=%u", i);
}

/**
 * tomoyo_set_mode - Set mode for specified profile.
 *
 * @name:    Name of functionality.
 * @value:   Mode for @name.
 * @profile: Pointer to "struct tomoyo_profile".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_set_mode(char *name, const char *value,
			   struct tomoyo_profile *profile)
{
	u8 i;
	u8 config;
	if (!strcmp(name, "CONFIG")) {
		i = TOMOYO_MAX_MAC_INDEX + TOMOYO_MAX_MAC_CATEGORY_INDEX;
		config = profile->default_config;
	} else if (tomoyo_str_starts(name, "CONFIG::")) {
		config = 0;
		for (i = 0;
		     i < TOMOYO_MAX_MAC_INDEX + TOMOYO_MAX_MAC_CATEGORY_INDEX;
		     i++) {
			int len = 0;
			if (i < TOMOYO_MAX_MAC_INDEX) {
				const u8 c = tomoyo_index2category[i];
				const char *category =
					tomoyo_category_keywords[c];
				len = strlen(category);
				if (strncmp(name, category, len) ||
				    name[len++] != ':' || name[len++] != ':')
					continue;
			}
			if (strcmp(name + len, tomoyo_mac_keywords[i]))
				continue;
			config = profile->config[i];
			break;
		}
		if (i == TOMOYO_MAX_MAC_INDEX + TOMOYO_MAX_MAC_CATEGORY_INDEX)
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	if (strstr(value, "use_default")) {
		config = TOMOYO_CONFIG_USE_DEFAULT;
	} else {
		u8 mode;
		for (mode = 0; mode < TOMOYO_CONFIG_MAX_MODE; mode++)
			if (strstr(value, tomoyo_mode[mode]))
				/*
				 * Update lower 3 bits in order to distinguish
				 * 'config' from 'TOMOYO_CONFIG_USE_DEAFULT'.
				 */
				config = (config & ~7) | mode;
		if (config != TOMOYO_CONFIG_USE_DEFAULT) {
			switch (tomoyo_find_yesno(value, "grant_log")) {
			case 1:
				config |= TOMOYO_CONFIG_WANT_GRANT_LOG;
				break;
			case 0:
				config &= ~TOMOYO_CONFIG_WANT_GRANT_LOG;
				break;
			}
			switch (tomoyo_find_yesno(value, "reject_log")) {
			case 1:
				config |= TOMOYO_CONFIG_WANT_REJECT_LOG;
				break;
			case 0:
				config &= ~TOMOYO_CONFIG_WANT_REJECT_LOG;
				break;
			}
		}
	}
	if (i < TOMOYO_MAX_MAC_INDEX + TOMOYO_MAX_MAC_CATEGORY_INDEX)
		profile->config[i] = config;
	else if (config != TOMOYO_CONFIG_USE_DEFAULT)
		profile->default_config = config;
	return 0;
}

/**
 * tomoyo_write_profile - Write profile table.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_profile(void)
{
	char *data = head.data;
	unsigned int i;
	char *cp;
	struct tomoyo_profile *profile;
	if (sscanf(data, "PROFILE_VERSION=%u", &head.ns->profile_version)
	    == 1)
		return 0;
	i = strtoul(data, &cp, 10);
	if (*cp != '-')
		return -EINVAL;
	data = cp + 1;
	profile = tomoyo_assign_profile(head.ns, i);
	if (!profile)
		return -EINVAL;
	cp = strchr(data, '=');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	if (!strcmp(data, "COMMENT")) {
		const struct tomoyo_path_info *new_comment =
			tomoyo_get_name(cp);
		const struct tomoyo_path_info *old_comment = profile->comment;
		profile->comment = new_comment;
		tomoyo_put_name(old_comment);
		return 0;
	}
	if (!strcmp(data, "PREFERENCE")) {
		for (i = 0; i < TOMOYO_MAX_PREF; i++)
			tomoyo_set_uint(&profile->pref[i], cp,
					tomoyo_pref_keywords[i]);
		return 0;
	}
	return tomoyo_set_mode(data, cp, profile);
}

/**
 * tomoyo_print_config - Print mode for specified functionality.
 *
 * @config: Mode for that functionality.
 *
 * Returns nothing.
 *
 * Caller prints functionality's name.
 */
static void tomoyo_print_config(const u8 config)
{
	cprintf("={ mode=%s grant_log=%s reject_log=%s }\n",
		tomoyo_mode[config & 3],
		tomoyo_yesno(config & TOMOYO_CONFIG_WANT_GRANT_LOG),
		tomoyo_yesno(config & TOMOYO_CONFIG_WANT_REJECT_LOG));
}

/**
 * tomoyo_read_profile - Read profile table.
 *
 * Returns nothing.
 */
static void tomoyo_read_profile(void)
{
	struct tomoyo_policy_namespace *ns;
	if (head.eof)
		return;
	list_for_each_entry(ns, &tomoyo_namespace_list, namespace_list) {
		u16 index;
		tomoyo_print_namespace(ns);
		cprintf("PROFILE_VERSION=%u\n", ns->profile_version);
		for (index = 0; index < TOMOYO_MAX_PROFILES; index++) {
			u8 i;
			const struct tomoyo_profile *profile =
				ns->profile_ptr[index];
			if (!profile)
				continue;
			tomoyo_print_namespace(ns);
			cprintf("%u-COMMENT=%s\n", index, profile->comment ?
				profile->comment->name : "");
			tomoyo_print_namespace(ns);
			cprintf("%u-PREFERENCE={ ", index);
			for (i = 0; i < TOMOYO_MAX_PREF; i++)
				cprintf("%s=%u ", tomoyo_pref_keywords[i],
					profile->pref[i]);
			cprintf("}\n");
			tomoyo_print_namespace(ns);
			cprintf("%u-CONFIG", index);
			tomoyo_print_config(profile->default_config);
			for (i = 0; i < TOMOYO_MAX_MAC_INDEX
				     + TOMOYO_MAX_MAC_CATEGORY_INDEX; i++) {
				const u8 config = profile->config[i];
				if (config == TOMOYO_CONFIG_USE_DEFAULT)
					continue;
				tomoyo_print_namespace(ns);
				if (i < TOMOYO_MAX_MAC_INDEX)
					cprintf("%u-CONFIG::%s::%s", index,
						tomoyo_category_keywords
						[tomoyo_index2category[i]],
						tomoyo_mac_keywords[i]);
				else
					cprintf("%u-CONFIG::%s", index,
						tomoyo_mac_keywords[i]);
				tomoyo_print_config(config);
			}
		}
	}
	head.eof = true;
}

/**
 * tomoyo_same_manager - Check for duplicated "struct tomoyo_manager" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_head".
 * @b: Pointer to "struct tomoyo_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_manager(const struct tomoyo_acl_head *a,
				const struct tomoyo_acl_head *b)
{
	return container_of(a, struct tomoyo_manager, head)->manager
		== container_of(b, struct tomoyo_manager, head)->manager;
}

/**
 * tomoyo_update_manager_entry - Add a manager entry.
 *
 * @manager:   The path to manager or the domainnamme.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int tomoyo_update_manager_entry(const char *manager,
					      const bool is_delete)
{
	struct tomoyo_manager e = { };
	struct tomoyo_acl_param param = {
		.is_delete = is_delete,
		.list = &tomoyo_manager_list,
	};
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (tomoyo_domain_def(manager)) {
		if (!tomoyo_correct_domain(manager))
			return -EINVAL;
		e.is_domain = true;
	} else {
		if (!tomoyo_correct_path(manager))
			return -EINVAL;
	}
	e.manager = tomoyo_get_name(manager);
	error = tomoyo_update_policy(&e.head, sizeof(e), &param,
				     tomoyo_same_manager);
	tomoyo_put_name(e.manager);
	return error;
}

/**
 * tomoyo_write_manager - Write manager policy.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_manager(void)
{
	return tomoyo_update_manager_entry(head.data, head.is_delete);
}

/**
 * tomoyo_read_manager - Read manager policy.
 *
 * Returns nothing.
 */
static void tomoyo_read_manager(void)
{
	struct tomoyo_manager *ptr;
	if (head.eof)
		return;
	list_for_each_entry(ptr, &tomoyo_manager_list, head.list)
		if (!ptr->head.is_deleted)
			cprintf("%s\n", ptr->manager->name);
	head.eof = true;
}

/**
 * tomoyo_select_domain - Parse select command.
 *
 * @data: String to parse.
 *
 * Returns true on success, false otherwise.
 */
static bool tomoyo_select_domain(const char *data)
{
	struct tomoyo_domain2_info *domain = NULL;
	if (strncmp(data, "select ", 7))
		return false;
	data += 7;
	if (!strncmp(data, "domain=", 7)) {
		if (*(data + 7) == '<')
			domain = tomoyo_find_domain2(data + 7);
	} else
		return false;
	if (domain) {
		head.domain = domain;
		head.print_this_domain_only = domain;
	} else
		head.eof = true;
	cprintf("# select %s\n", data);
	return true;
}

/**
 * tomoyo_same_handler_acl - Check for duplicated "struct tomoyo_handler_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_handler_acl(const struct tomoyo_acl_info *a,
				    const struct tomoyo_acl_info *b)
{
	const struct tomoyo_handler_acl *p1 = container_of(a, typeof(*p1),
							   head);
	const struct tomoyo_handler_acl *p2 = container_of(b, typeof(*p2),
							   head);
	return p1->handler == p2->handler;
}

/**
 * tomoyo_same_task_acl - Check for duplicated "struct tomoyo_task_acl" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_info".
 * @b: Pointer to "struct tomoyo_acl_info".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_task_acl(const struct tomoyo_acl_info *a,
				 const struct tomoyo_acl_info *b)
{
	const struct tomoyo_task_acl *p1 = container_of(a, typeof(*p1), head);
	const struct tomoyo_task_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->domainname == p2->domainname;
}

/**
 * tomoyo_write_task - Update task related list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_task(struct tomoyo_acl_param *param)
{
	int error;
	const bool is_auto = tomoyo_str_starts(param->data,
					       "auto_domain_transition ");
	if (!is_auto && !tomoyo_str_starts(param->data,
					   "manual_domain_transition ")) {
		struct tomoyo_handler_acl e = { };
		char *handler;
		if (tomoyo_str_starts(param->data, "auto_execute_handler "))
			e.head.type = TOMOYO_TYPE_AUTO_EXECUTE_HANDLER;
		else if (tomoyo_str_starts(param->data,
					   "denied_execute_handler "))
			e.head.type = TOMOYO_TYPE_DENIED_EXECUTE_HANDLER;
		else
			return -EINVAL;
		handler = tomoyo_read_token(param);
		if (!tomoyo_correct_path(handler))
			return -EINVAL;
		e.handler = tomoyo_get_name(handler);
		if (e.handler->is_patterned)
			error = -EINVAL; /* No patterns allowed. */
		else
			error = tomoyo_update_domain(&e.head, sizeof(e), param,
						     tomoyo_same_handler_acl,
						     NULL);
		tomoyo_put_name(e.handler);
	} else {
		struct tomoyo_task_acl e = {
			.head.type = is_auto ? TOMOYO_TYPE_AUTO_TASK_ACL :
			TOMOYO_TYPE_MANUAL_TASK_ACL,
			.domainname = tomoyo_get_domainname(param),
		};
		if (!e.domainname)
			error = -EINVAL;
		else
			error = tomoyo_update_domain(&e.head, sizeof(e), param,
						     tomoyo_same_task_acl,
						     NULL);
		tomoyo_put_name(e.domainname);
	}
	return error;
}

/**
 * tomoyo_write_domain2 - Write domain policy.
 *
 * @ns:        Pointer to "struct tomoyo_policy_namespace".
 * @list:      Pointer to "struct list_head".
 * @data:      Policy to be interpreted.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_domain2(struct tomoyo_policy_namespace *ns,
				struct list_head *list, char *data,
				const bool is_delete)
{
	struct tomoyo_acl_param param = {
		.ns = ns,
		.list = list,
		.data = data,
		.is_delete = is_delete,
	};
	static const struct {
		const char *keyword;
		int (*write) (struct tomoyo_acl_param *);
	} tomoyo_callback[7] = {
		{ "file ", tomoyo_write_file },
		{ "network inet ", tomoyo_write_inet_network },
		{ "network unix ", tomoyo_write_unix_network },
		{ "misc ", tomoyo_write_misc },
		{ "capability ", tomoyo_write_capability },
		{ "ipc signal ", tomoyo_write_ipc },
		{ "task ", tomoyo_write_task },
	};
	u8 i;
	for (i = 0; i < 7; i++) {
		if (!tomoyo_str_starts(param.data, tomoyo_callback[i].keyword))
			continue;
		return tomoyo_callback[i].write(&param);
	}
	return -EINVAL;
}

/**
 * tomoyo_delete_domain2 - Delete a domain from domain policy.
 *
 * @domainname: Name of domain.
 *
 * Returns nothing.
 */
static void tomoyo_delete_domain2(const char *domainname)
{
	struct tomoyo_domain2_info *domain;
	list_for_each_entry(domain, &tomoyo_domain_list, list) {
		if (domain == &tomoyo_kernel_domain)
			continue;
		if (strcmp(domain->domainname->name, domainname))
			continue;
		domain->is_deleted = true;
	}
}

/**
 * tomoyo_write_domain - Write domain policy.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_domain(void)
{
	char *data = head.data;
	struct tomoyo_policy_namespace *ns;
	struct tomoyo_domain2_info *domain = head.domain;
	const bool is_delete = head.is_delete;
	const bool is_select = !is_delete &&
		tomoyo_str_starts(data, "select ");
	unsigned int profile;
	if (*data == '<') {
		domain = NULL;
		if (is_delete)
			tomoyo_delete_domain2(data);
		else if (is_select)
			domain = tomoyo_find_domain2(data);
		else
			domain = tomoyo_assign_domain2(data);
		head.domain = domain;
		return 0;
	}
	if (!domain)
		return -EINVAL;
	ns = tomoyo_assign_namespace(domain->domainname->name);
	if (!ns)
		return -EINVAL;
	if (sscanf(data, "use_profile %u\n", &profile) == 1
	    && profile < TOMOYO_MAX_PROFILES) {
		if (ns->profile_ptr[(u8) profile])
			if (!is_delete)
				domain->profile = (u8) profile;
		return 0;
	}
	if (sscanf(data, "use_group %u\n", &profile) == 1
	    && profile < TOMOYO_MAX_ACL_GROUPS) {
		if (!is_delete)
			domain->group = (u8) profile;
		return 0;
	}
	for (profile = 0; profile < TOMOYO_MAX_DOMAIN_INFO_FLAGS; profile++) {
		const char *cp = tomoyo_dif[profile];
		if (strncmp(data, cp, strlen(cp) - 1))
			continue;
		domain->flags[profile] = !is_delete;
		return 0;
	}
	return tomoyo_write_domain2(ns, &domain->acl_info_list, data,
				    is_delete);
}

/**
 * tomoyo_print_name_union - Print a tomoyo_name_union.
 *
 * @ptr: Pointer to "struct tomoyo_name_union".
 *
 * Returns nothing.
 */
static void tomoyo_print_name_union(const struct tomoyo_name_union *ptr)
{
	if (ptr->group)
		cprintf(" @%s", ptr->group->group_name->name);
	else
		cprintf(" %s", ptr->filename->name);
}

/**
 * tomoyo_print_name_union_quoted - Print a tomoyo_name_union with a quote.
 *
 * @ptr: Pointer to "struct tomoyo_name_union".
 *
 * Returns nothing.
 */
static void tomoyo_print_name_union_quoted(const struct tomoyo_name_union *ptr)
{
	if (ptr->group)
		cprintf("@%s", ptr->group->group_name->name);
	else
		cprintf("\"%s\"", ptr->filename->name);
}

/**
 * tomoyo_print_number_union_nospace - Print a tomoyo_number_union without a space.
 *
 * @ptr: Pointer to "struct tomoyo_number_union".
 *
 * Returns nothing.
 */
static void tomoyo_print_number_union_nospace
(const struct tomoyo_number_union *ptr)
{
	if (ptr->group) {
		cprintf("@%s", ptr->group->group_name->name);
	} else {
		int i;
		unsigned long min = ptr->values[0];
		const unsigned long max = ptr->values[1];
		u8 min_type = ptr->value_type[0];
		const u8 max_type = ptr->value_type[1];
		for (i = 0; i < 2; i++) {
			switch (min_type) {
			case TOMOYO_VALUE_TYPE_HEXADECIMAL:
				cprintf("0x%lX", min);
				break;
			case TOMOYO_VALUE_TYPE_OCTAL:
				cprintf("0%lo", min);
				break;
			default:
				cprintf("%lu", min);
				break;
			}
			if (min == max && min_type == max_type)
				break;
			cprintf("-");
			min_type = max_type;
			min = max;
		}
	}
}

/**
 * tomoyo_print_number_union - Print a tomoyo_number_union.
 *
 * @ptr: Pointer to "struct tomoyo_number_union".
 *
 * Returns nothing.
 */
static void tomoyo_print_number_union(const struct tomoyo_number_union *ptr)
{
	cprintf(" ");
	tomoyo_print_number_union_nospace(ptr);
}

/**
 * tomoyo_print_condition - Print condition part.
 *
 * @cond: Pointer to "struct tomoyo_condition".
 *
 * Returns true on success, false otherwise.
 */
static void tomoyo_print_condition(const struct tomoyo_condition *cond)
{
	const u16 condc = cond->condc;
	const struct tomoyo_condition_element *condp =
		(typeof(condp)) (cond + 1);
	const struct tomoyo_number_union *numbers_p =
		(typeof(numbers_p)) (condp + condc);
	const struct tomoyo_name_union *names_p =
		(typeof(names_p)) (numbers_p + cond->numbers_count);
	const struct tomoyo_argv *argv =
		(typeof(argv)) (names_p + cond->names_count);
	const struct tomoyo_envp *envp = (typeof(envp)) (argv + cond->argc);
	u16 i;
	for (i = 0; i < condc; i++) {
		const u8 match = condp->equals;
		const u8 left = condp->left;
		const u8 right = condp->right;
		condp++;
		cprintf(" ");
		switch (left) {
		case TOMOYO_ARGV_ENTRY:
			cprintf("exec.argv[%lu]%s=\"%s\"", argv->index,
				argv->is_not ? "!" : "", argv->value->name);
			argv++;
			continue;
		case TOMOYO_ENVP_ENTRY:
			cprintf("exec.envp[\"%s\"]%s=",
				envp->name->name, envp->is_not ? "!" : "");
			if (envp->value)
				cprintf("\"%s\"", envp->value->name);
			else
				cprintf("NULL");
			envp++;
			continue;
		case TOMOYO_NUMBER_UNION:
			tomoyo_print_number_union_nospace(numbers_p++);
			break;
		default:
			cprintf("%s", tomoyo_condition_keyword[left]);
			break;
		}
		cprintf("%s", match ? "=" : "!=");
		switch (right) {
		case TOMOYO_NAME_UNION:
			tomoyo_print_name_union_quoted(names_p++);
			break;
		case TOMOYO_NUMBER_UNION:
			tomoyo_print_number_union_nospace(numbers_p++);
			break;
		default:
			cprintf("%s", tomoyo_condition_keyword[right]);
			break;
		}
	}
	if (cond->grant_log != TOMOYO_GRANTLOG_AUTO)
		cprintf(" grant_log=%s",
			tomoyo_yesno(cond->grant_log == TOMOYO_GRANTLOG_YES));
	if (cond->transit)
		cprintf(" auto_domain_transition=\"%s\"",
			cond->transit->name);
}

/**
 * tomoyo_set_group - Print "acl_group " header keyword and category name.
 *
 * @category: Category name.
 *
 * Returns nothing.
 */
static void tomoyo_set_group(const char *category)
{
	if (head.type == TOMOYO_EXCEPTIONPOLICY) {
		tomoyo_print_namespace(head.ns);
		cprintf("acl_group %u ", head.acl_group_index);
	}
	cprintf("%s", category);
}

/**
 * tomoyo_print_entry - Print an ACL entry.
 *
 * @acl: Pointer to an ACL entry.
 *
 * Returns nothing.
 */
static void tomoyo_print_entry(const struct tomoyo_acl_info *acl)
{
	const u8 acl_type = acl->type;
	const bool may_trigger_transition = acl->cond && acl->cond->transit;
	bool first = true;
	u8 bit;
	if (acl->is_deleted)
		return;
	if (acl_type == TOMOYO_TYPE_PATH_ACL) {
		struct tomoyo_path_acl *ptr
			= container_of(acl, typeof(*ptr), head);
		const u16 perm = ptr->perm;
		for (bit = 0; bit < TOMOYO_MAX_PATH_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (head.print_transition_related_only &&
			    bit != TOMOYO_TYPE_EXECUTE &&
			    !may_trigger_transition)
				continue;
			if (first) {
				tomoyo_set_group("file ");
				first = false;
			} else {
				cprintf("/");
			}
			cprintf("%s", tomoyo_path_keyword[bit]);
		}
		if (first)
			return;
		tomoyo_print_name_union(&ptr->name);
	} else if (acl_type == TOMOYO_TYPE_AUTO_EXECUTE_HANDLER ||
		   acl_type == TOMOYO_TYPE_DENIED_EXECUTE_HANDLER) {
		struct tomoyo_handler_acl *ptr
			= container_of(acl, typeof(*ptr), head);
		tomoyo_set_group("task ");
		cprintf(acl_type == TOMOYO_TYPE_AUTO_EXECUTE_HANDLER ?
			"auto_execute_handler " : "denied_execute_handler ");
		cprintf("%s", ptr->handler->name);
	} else if (acl_type == TOMOYO_TYPE_AUTO_TASK_ACL ||
		   acl_type == TOMOYO_TYPE_MANUAL_TASK_ACL) {
		struct tomoyo_task_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		tomoyo_set_group("task ");
		cprintf(acl_type == TOMOYO_TYPE_AUTO_TASK_ACL ?
			"auto_domain_transition " :
			"manual_domain_transition ");
		cprintf("%s", ptr->domainname->name);
	} else if (head.print_transition_related_only &&
		   !may_trigger_transition) {
		return;
	} else if (acl_type == TOMOYO_TYPE_MKDEV_ACL) {
		struct tomoyo_mkdev_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		const u8 perm = ptr->perm;
		for (bit = 0; bit < TOMOYO_MAX_MKDEV_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (first) {
				tomoyo_set_group("file ");
				first = false;
			} else {
				cprintf("/");
			}
			cprintf("%s",
				tomoyo_mac_keywords[tomoyo_pnnn2mac[bit]]);
		}
		if (first)
			return;
		tomoyo_print_name_union(&ptr->name);
		tomoyo_print_number_union(&ptr->mode);
		tomoyo_print_number_union(&ptr->major);
		tomoyo_print_number_union(&ptr->minor);
	} else if (acl_type == TOMOYO_TYPE_PATH2_ACL) {
		struct tomoyo_path2_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		const u8 perm = ptr->perm;
		for (bit = 0; bit < TOMOYO_MAX_PATH2_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (first) {
				tomoyo_set_group("file ");
				first = false;
			} else {
				cprintf("/");
			}
			cprintf("%s", tomoyo_mac_keywords[tomoyo_pp2mac[bit]]);
		}
		if (first)
			return;
		tomoyo_print_name_union(&ptr->name1);
		tomoyo_print_name_union(&ptr->name2);
	} else if (acl_type == TOMOYO_TYPE_PATH_NUMBER_ACL) {
		struct tomoyo_path_number_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		const u8 perm = ptr->perm;
		for (bit = 0; bit < TOMOYO_MAX_PATH_NUMBER_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (first) {
				tomoyo_set_group("file ");
				first = false;
			} else {
				cprintf("/");
			}
			cprintf("%s", tomoyo_mac_keywords[tomoyo_pn2mac[bit]]);
		}
		if (first)
			return;
		tomoyo_print_name_union(&ptr->name);
		tomoyo_print_number_union(&ptr->number);
	} else if (acl_type == TOMOYO_TYPE_ENV_ACL) {
		struct tomoyo_env_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		tomoyo_set_group("misc env ");
		cprintf("%s", ptr->env->name);
	} else if (acl_type == TOMOYO_TYPE_CAPABILITY_ACL) {
		struct tomoyo_capability_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		tomoyo_set_group("capability ");
		cprintf("%s",
			tomoyo_mac_keywords[tomoyo_c2mac[ptr->operation]]);
	} else if (acl_type == TOMOYO_TYPE_INET_ACL) {
		struct tomoyo_inet_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		const u8 perm = ptr->perm;
		for (bit = 0; bit < TOMOYO_MAX_NETWORK_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (first) {
				tomoyo_set_group("network inet ");
				cprintf("%s ",
					tomoyo_proto_keyword[ptr->protocol]);
				first = false;
			} else {
				cprintf("/");
			}
			cprintf("%s", tomoyo_socket_keyword[bit]);
		}
		if (first)
			return;
		cprintf(" ");
		if (ptr->address.group)
			cprintf("@%s", ptr->address.group->group_name->name);
		else
			tomoyo_print_ip(&ptr->address);
		tomoyo_print_number_union(&ptr->port);
	} else if (acl_type == TOMOYO_TYPE_UNIX_ACL) {
		struct tomoyo_unix_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		const u8 perm = ptr->perm;
		for (bit = 0; bit < TOMOYO_MAX_NETWORK_OPERATION; bit++) {
			if (!(perm & (1 << bit)))
				continue;
			if (first) {
				tomoyo_set_group("network unix ");
				cprintf("%s ",
					tomoyo_proto_keyword[ptr->protocol]);
				first = false;
			} else {
				cprintf("/");
			}
			cprintf("%s", tomoyo_socket_keyword[bit]);
		}
		if (first)
			return;
		tomoyo_print_name_union(&ptr->name);
	} else if (acl_type == TOMOYO_TYPE_SIGNAL_ACL) {
		struct tomoyo_signal_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		tomoyo_set_group("ipc signal ");
		tomoyo_print_number_union_nospace(&ptr->sig);
		cprintf(" %s", ptr->domainname->name);
	} else if (acl_type == TOMOYO_TYPE_MOUNT_ACL) {
		struct tomoyo_mount_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		tomoyo_set_group("file mount");
		tomoyo_print_name_union(&ptr->dev_name);
		tomoyo_print_name_union(&ptr->dir_name);
		tomoyo_print_name_union(&ptr->fs_type);
		tomoyo_print_number_union(&ptr->flags);
	}
	if (acl->cond)
		tomoyo_print_condition(acl->cond);
	cprintf("\n");
}

/**
 * tomoyo_read_domain2 - Read domain policy.
 *
 * @list: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static void tomoyo_read_domain2(struct list_head *list)
{
	struct tomoyo_acl_info *ptr;
	list_for_each_entry(ptr, list, list)
		tomoyo_print_entry(ptr);
}

/**
 * tomoyo_read_domain - Read domain policy.
 *
 * Returns nothing.
 */
static void tomoyo_read_domain(void)
{
	struct tomoyo_domain2_info *domain;
	if (head.eof)
		return;
	list_for_each_entry(domain, &tomoyo_domain_list, list) {
		u8 i;
		if (domain->is_deleted)
			continue;
		if (head.print_this_domain_only &&
		    head.print_this_domain_only != domain)
			continue;
		/* Print domainname and flags. */
		cprintf("%s\n", domain->domainname->name);
		cprintf("use_profile %u\n", domain->profile);
		cprintf("use_group %u\n", domain->group);
		for (i = 0; i < TOMOYO_MAX_DOMAIN_INFO_FLAGS; i++)
			if (domain->flags[i])
				cprintf("%s", tomoyo_dif[i]);
		cprintf("\n");
		tomoyo_read_domain2(&domain->acl_info_list);
		cprintf("\n");
	}
	head.eof = true;
}

/**
 * tomoyo_same_path_group - Check for duplicated "struct tomoyo_path_group" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_head".
 * @b: Pointer to "struct tomoyo_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_path_group(const struct tomoyo_acl_head *a,
				   const struct tomoyo_acl_head *b)
{
	return container_of(a, struct tomoyo_path_group, head)->member_name ==
		container_of(b, struct tomoyo_path_group, head)->member_name;
}

/**
 * tomoyo_same_number_group - Check for duplicated "struct tomoyo_number_group" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_head".
 * @b: Pointer to "struct tomoyo_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_number_group(const struct tomoyo_acl_head *a,
				     const struct tomoyo_acl_head *b)
{
	return !memcmp(&container_of(a, struct tomoyo_number_group, head)
		       ->number,
		       &container_of(b, struct tomoyo_number_group, head)
		       ->number,
		       sizeof(container_of(a, struct tomoyo_number_group, head)
			      ->number));
}

/**
 * tomoyo_same_address_group - Check for duplicated "struct tomoyo_address_group" entry.
 *
 * @a: Pointer to "struct tomoyo_acl_head".
 * @b: Pointer to "struct tomoyo_acl_head".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool tomoyo_same_address_group(const struct tomoyo_acl_head *a,
				      const struct tomoyo_acl_head *b)
{
	const struct tomoyo_address_group *p1 = container_of(a, typeof(*p1),
							     head);
	const struct tomoyo_address_group *p2 = container_of(b, typeof(*p2),
							     head);
	return tomoyo_same_ipaddr_union(&p1->address, &p2->address);
}

/**
 * tomoyo_write_group - Write "struct tomoyo_path_group"/"struct tomoyo_number_group"/"struct tomoyo_address_group" list.
 *
 * @param: Pointer to "struct tomoyo_acl_param".
 * @type:  Type of this group.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_group(struct tomoyo_acl_param *param, const u8 type)
{
	struct tomoyo_group *group =
		tomoyo_get_group(param, type == TOMOYO_PATH_GROUP ?
				 &tomoyo_path_group :
				 type == TOMOYO_NUMBER_GROUP ?
				 &tomoyo_number_group : &tomoyo_address_group);
	int error = -EINVAL;
	if (!group)
		return -ENOMEM;
	param->list = &group->member_list;
	if (type == TOMOYO_PATH_GROUP) {
		struct tomoyo_path_group e = { };
		e.member_name = tomoyo_get_name(tomoyo_read_token(param));
		error = tomoyo_update_policy(&e.head, sizeof(e), param,
					     tomoyo_same_path_group);
		tomoyo_put_name(e.member_name);
	} else if (type == TOMOYO_NUMBER_GROUP) {
		struct tomoyo_number_group e = { };
		if (param->data[0] == '@' ||
		    !tomoyo_parse_number_union(param, &e.number))
			goto out;
		error = tomoyo_update_policy(&e.head, sizeof(e), param,
					     tomoyo_same_number_group);
		/*
		 * tomoyo_put_number_union() is not needed because
		 * param->data[0] != '@'.
		 */
	} else {
		struct tomoyo_address_group e = { };
		if (param->data[0] == '@' ||
		    !tomoyo_parse_ipaddr_union(param, &e.address))
			goto out;
		error = tomoyo_update_policy(&e.head, sizeof(e), param,
					     tomoyo_same_address_group);
	}
out:
	tomoyo_put_group(group);
	return error;
}

/**
 * tomoyo_write_exception - Write exception policy.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_write_exception(void)
{
	const bool is_delete = head.is_delete;
	struct tomoyo_acl_param param = {
		.ns = head.ns,
		.is_delete = is_delete,
		.data = head.data,
	};
	u8 i;
	if (tomoyo_str_starts(param.data, "aggregator "))
		return tomoyo_write_aggregator(&param);
	if (tomoyo_str_starts(param.data, "deny_autobind "))
		return tomoyo_write_reserved_port(&param);
	for (i = 0; i < TOMOYO_MAX_TRANSITION_TYPE; i++)
		if (tomoyo_str_starts(param.data, tomoyo_transition_type[i]))
			return tomoyo_write_transition_control(&param, i);
	for (i = 0; i < TOMOYO_MAX_GROUP; i++)
		if (tomoyo_str_starts(param.data, tomoyo_group_name[i]))
			return tomoyo_write_group(&param, i);
	if (tomoyo_str_starts(param.data, "acl_group ")) {
		unsigned int group;
		char *data;
		group = strtoul(param.data, &data, 10);
		if (group < TOMOYO_MAX_ACL_GROUPS && *data++ == ' ')
			return tomoyo_write_domain2(head.ns,
						    &head.ns->acl_group[group],
						    data, is_delete);
	}
	return -EINVAL;
}

/**
 * tomoyo_read_group - Read "struct tomoyo_path_group"/"struct tomoyo_number_group"/"struct tomoyo_address_group" list.
 *
 * @ns: Pointer to "struct tomoyo_policy_namespace".
 *
 * Returns nothing.
 */
static void tomoyo_read_group(const struct tomoyo_policy_namespace *ns)
{
	struct tomoyo_group *group;
	list_for_each_entry(group, &tomoyo_path_group, head.list) {
		struct tomoyo_acl_head *ptr;
		list_for_each_entry(ptr, &group->member_list, list) {
			if (group->ns != ns)
				continue;
			tomoyo_print_namespace(group->ns);
			cprintf("%s%s", tomoyo_group_name[TOMOYO_PATH_GROUP],
				group->group_name->name);
			cprintf(" %s",
				container_of(ptr, struct tomoyo_path_group,
					     head)->member_name->name);
			cprintf("\n");
		}
	}
	list_for_each_entry(group, &tomoyo_number_group, head.list) {
		struct tomoyo_acl_head *ptr;
		list_for_each_entry(ptr, &group->member_list, list) {
			if (group->ns != ns)
				continue;
			tomoyo_print_namespace(group->ns);
			cprintf("%s%s", tomoyo_group_name[TOMOYO_NUMBER_GROUP],
				group->group_name->name);
			tomoyo_print_number_union(&container_of
						  (ptr,
						   struct tomoyo_number_group,
						   head)->number);
			cprintf("\n");
		}
	}
	list_for_each_entry(group, &tomoyo_address_group, head.list) {
		struct tomoyo_acl_head *ptr;
		list_for_each_entry(ptr, &group->member_list, list) {
			if (group->ns != ns)
				continue;
			tomoyo_print_namespace(group->ns);
			cprintf("%s%s",
				tomoyo_group_name[TOMOYO_ADDRESS_GROUP],
				group->group_name->name);
			cprintf(" ");
			tomoyo_print_ip(&container_of
					(ptr, struct tomoyo_address_group,
					 head)->address);
			cprintf("\n");
		}
	}
}

/**
 * tomoyo_read_policy - Read "struct tomoyo_..._entry" list.
 *
 * @ns: Pointer to "struct tomoyo_policy_namespace".
 *
 * Returns nothing.
 */
static void tomoyo_read_policy(const struct tomoyo_policy_namespace *ns)
{
	struct tomoyo_acl_head *acl;
	if (head.print_transition_related_only)
		goto transition_only;
	list_for_each_entry(acl, &tomoyo_reserved_list, list) {
		struct tomoyo_reserved *ptr =
			container_of(acl, typeof(*ptr), head);
		if (acl->is_deleted || ptr->ns != ns)
			continue;
		tomoyo_print_namespace(ptr->ns);
		cprintf("deny_autobind ");
		tomoyo_print_number_union_nospace(&ptr->port);
		cprintf("\n");
	}
	list_for_each_entry(acl, &tomoyo_aggregator_list, list) {
		struct tomoyo_aggregator *ptr =
			container_of(acl, typeof(*ptr), head);
		if (acl->is_deleted || ptr->ns != ns)
			continue;
		tomoyo_print_namespace(ptr->ns);
		cprintf("aggregator %s %s\n", ptr->original_name->name,
			ptr->aggregated_name->name);
	}
transition_only:
	list_for_each_entry(acl, &tomoyo_transition_list, list) {
		struct tomoyo_transition_control *ptr =
			container_of(acl, typeof(*ptr), head);
		if (acl->is_deleted || ptr->ns != ns)
			continue;
		tomoyo_print_namespace(ptr->ns);
		cprintf("%s%s from %s\n", tomoyo_transition_type[ptr->type],
			ptr->program ? ptr->program->name : "any",
			ptr->domainname ? ptr->domainname->name : "any");
	}
}

/**
 * tomoyo_read_exception - Read exception policy.
 *
 * Returns nothing.
 */
static void tomoyo_read_exception(void)
{
	struct tomoyo_policy_namespace *ns;
	if (head.eof)
		return;
	list_for_each_entry(ns, &tomoyo_namespace_list, namespace_list) {
		unsigned int i;
		head.ns = ns;
		tomoyo_read_policy(ns);
		tomoyo_read_group(ns);
		for (i = 0; i < TOMOYO_MAX_ACL_GROUPS; i++)
			tomoyo_read_domain2(&ns->acl_group[i]);
	}
	head.eof = true;
}

/**
 * tomoyo_read_stat - Read statistic data.
 *
 * Returns nothing.
 */
static void tomoyo_read_stat(void)
{
	u8 i;
	if (head.eof)
		return;
	for (i = 0; i < TOMOYO_MAX_MEMORY_STAT; i++)
		cprintf("Memory used by %-22s %10u\n",
			tomoyo_memory_headers[i], tomoyo_memory_quota[i]);
	head.eof = true;
}

/**
 * tomoyo_write_stat - Set memory quota.
 *
 * Returns 0.
 */
static int tomoyo_write_stat(void)
{
	char *data = head.data;
	u8 i;
	if (tomoyo_str_starts(data, "Memory used by "))
		for (i = 0; i < TOMOYO_MAX_MEMORY_STAT; i++)
			if (tomoyo_str_starts(data, tomoyo_memory_headers[i]))
				tomoyo_memory_quota[i] = strtoul(data, NULL,
								 10);
	return 0;
}

/**
 * tomoyo_parse_policy - Parse a policy line.
 *
 * @line: Line to parse.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_parse_policy(char *line)
{
	/* Delete request? */
	head.is_delete = !strncmp(line, "delete ", 7);
	if (head.is_delete)
		memmove(line, line + 7, strlen(line + 7) + 1);
	/* Selecting namespace to update. */
	if (head.type == TOMOYO_EXCEPTIONPOLICY ||
	    head.type == TOMOYO_PROFILE) {
		if (*line == '<') {
			char *cp = strchr(line, ' ');
			if (cp) {
				*cp++ = '\0';
				head.ns = tomoyo_assign_namespace(line);
				memmove(line, cp, strlen(cp) + 1);
			} else
				head.ns = NULL;
			/* Don't allow updating if namespace is invalid. */
			if (!head.ns)
				return -ENOENT;
		} else
			head.ns = &tomoyo_kernel_namespace;
	}
	/* Do the update. */
	switch (head.type) {
	case TOMOYO_DOMAINPOLICY:
		return tomoyo_write_domain();
	case TOMOYO_EXCEPTIONPOLICY:
		return tomoyo_write_exception();
	case TOMOYO_STAT:
		return tomoyo_write_stat();
	case TOMOYO_PROFILE:
		return tomoyo_write_profile();
	case TOMOYO_MANAGER:
		return tomoyo_write_manager();
	default:
		return -ENOSYS;
	}
}

/**
 * tomoyo_write_control - write() for /proc/tomoyo/ interface.
 *
 * @buffer:     Pointer to buffer to read from.
 * @buffer_len: Size of @buffer.
 *
 * Returns @buffer_len on success, negative value otherwise.
 */
static void tomoyo_write_control(char *buffer, const size_t buffer_len)
{
	static char *line = NULL;
	static int line_len = 0;
	size_t avail_len = buffer_len;
	while (avail_len > 0) {
		const char c = *buffer++;
		avail_len--;
		line = tomoyo_realloc(line, line_len + 1);
		line[line_len++] = c;
		if (c != '\n')
			continue;
		line[line_len - 1] = '\0';
		line_len = 0;
		head.data = line;
		tomoyo_normalize_line(line);
		if (!strcmp(line, "reset")) {
			const u8 type = head.type;
			memset(&head, 0, sizeof(head));
			head.reset = true;
			head.type = type;
			continue;
		}
		/* Don't allow updating policies by non manager programs. */
		switch (head.type) {
		case TOMOYO_DOMAINPOLICY:
			if (tomoyo_select_domain(line))
				continue;
			/* fall through */
		case TOMOYO_EXCEPTIONPOLICY:
			if (!strcmp(line, "select transition_only")) {
				head.print_transition_related_only = true;
				continue;
			}
		}
		tomoyo_parse_policy(line);
	}
}

static void init(coid)
{
	static _Bool first = true;
	int i;
	if (!first)
		return;
	first = false;
	memset(&head, 0, sizeof(head));
	memset(&tomoyo_kernel_domain, 0, sizeof(tomoyo_kernel_domain));
	memset(&tomoyo_kernel_namespace, 0, sizeof(tomoyo_kernel_namespace));
	tomoyo_namespace_enabled = false;
	tomoyo_kernel_namespace.name = "<kernel>";
	for (i = 0; i < TOMOYO_MAX_ACL_GROUPS; i++)
		INIT_LIST_HEAD(&tomoyo_kernel_namespace.acl_group[i]);
	list_add_tail(&tomoyo_kernel_namespace.namespace_list,
		      &tomoyo_namespace_list);
	for (i = 0; i < TOMOYO_MAX_HASH; i++)
		INIT_LIST_HEAD(&tomoyo_name_list[i]);
	memset(tomoyo_memory_quota, 0, sizeof(tomoyo_memory_quota));
}

static void handle_policy(const int fd)
{
	int i;
	static char buffer[4096];
	init();
	/* Read filename. */
	for (i = 0; i < sizeof(buffer); i++) {
		if (read(fd, buffer + i, 1) != 1)
			goto out;
		if (!buffer[i])
			break;
	}
	if (!memchr(buffer, '\0', sizeof(buffer)))
		goto out;
	memset(&head, 0, sizeof(head));
	head.reset = true;
	if (!strcmp(buffer, TOMOYO_PROC_POLICY_DOMAIN_POLICY))
		head.type = TOMOYO_DOMAINPOLICY;
	else if (!strcmp(buffer, TOMOYO_PROC_POLICY_EXCEPTION_POLICY))
		head.type = TOMOYO_EXCEPTIONPOLICY;
	else if (!strcmp(buffer, TOMOYO_PROC_POLICY_PROFILE))
		head.type = TOMOYO_PROFILE;
	else if (!strcmp(buffer, TOMOYO_PROC_POLICY_MANAGER))
		head.type = TOMOYO_MANAGER;
	else if (!strcmp(buffer, TOMOYO_PROC_POLICY_STAT))
		head.type = TOMOYO_STAT;
	else
		goto out;
	/* Return \0 to indicate success. */
	if (write(fd, "", 1) != 1)
		goto out;
	client_fd = fd;
	while (1) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN};
		int len;
		int nonzero_len;
		poll(&pfd, 1, -1);
		len = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
		if (len <= 0)
			break;
restart:
		for (nonzero_len = 0 ; nonzero_len < len; nonzero_len++)
			if (!buffer[nonzero_len])
				break;
		if (nonzero_len) {
			tomoyo_write_control(buffer, nonzero_len);
		} else {
			switch (head.type) {
			case TOMOYO_DOMAINPOLICY:
				tomoyo_read_domain();
				break;
			case TOMOYO_EXCEPTIONPOLICY:
				tomoyo_read_exception();
				break;
			case TOMOYO_STAT:
				tomoyo_read_stat();
				break;
			case TOMOYO_PROFILE:
				tomoyo_read_profile();
				break;
			case TOMOYO_MANAGER:
				tomoyo_read_manager();
				break;
			}
			/* Flush data. */
			cprintf("%s", "");
			/* Return \0 to indicate EOF. */
			if (write(fd, "", 1) != 1)
				goto out;
			nonzero_len = 1;
		}
		len -= nonzero_len;
		memmove(buffer, buffer + nonzero_len, len);
		if (len)
			goto restart;
	}
out:
	return;
}

/**
 * tomoyo_editpolicy_offline_daemon - Emulate /proc/tomoyo/ interface.
 *
 * @listener: Listener fd.
 *
 * This function does not return.
 */
void tomoyo_editpolicy_offline_daemon(const int listener)
{
	while (1) {
		struct sockaddr_in addr;
		socklen_t size = sizeof(addr);
		const int fd = accept(listener, (struct sockaddr *) &addr,
				      &size);
		if (fd == EOF)
			_exit(1);
		handle_policy(fd);
		close(fd);
	}
}
