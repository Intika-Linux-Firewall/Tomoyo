/*
 * editpolicy_offline.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
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
#include "ccstools.h"
#include "editpolicy.h"
#include <poll.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

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

/* Enumeration definition for internal use. */

/* Index numbers for Capability Controls. */
enum ccs_capability_acl_index {
	/* socket(PF_ROUTE, *, *)                                      */
	CCS_USE_ROUTE_SOCKET,
	/* socket(PF_PACKET, *, *)                                     */
	CCS_USE_PACKET_SOCKET,
	/* sys_reboot()                                                */
	CCS_SYS_REBOOT,
	/* sys_vhangup()                                               */
	CCS_SYS_VHANGUP,
	/* do_settimeofday(), sys_adjtimex()                           */
	CCS_SYS_SETTIME,
	/* sys_nice(), sys_setpriority()                               */
	CCS_SYS_NICE,
	/* sys_sethostname(), sys_setdomainname()                      */
	CCS_SYS_SETHOSTNAME,
	/* sys_create_module(), sys_init_module(), sys_delete_module() */
	CCS_USE_KERNEL_MODULE,
	/* sys_kexec_load()                                            */
	CCS_SYS_KEXEC_LOAD,
	CCS_MAX_CAPABILITY_INDEX
};

/* Index numbers for Access Controls. */
enum ccs_acl_entry_type_index {
	CCS_TYPE_EXECUTE_ACL,
	CCS_TYPE_PATH_ACL,
	CCS_TYPE_PATH2_ACL,
	CCS_TYPE_PATH_NUMBER_ACL,
	CCS_TYPE_MKDEV_ACL,
	CCS_TYPE_MOUNT_ACL,
	CCS_TYPE_ENV_ACL,
	CCS_TYPE_CAPABILITY_ACL,
	CCS_TYPE_INET_ACL,
	CCS_TYPE_UNIX_ACL,
	CCS_TYPE_PTRACE_ACL,
	CCS_TYPE_AUTO_EXECUTE_HANDLER,
	CCS_TYPE_DENIED_EXECUTE_HANDLER,
	CCS_TYPE_AUTO_TASK_ACL,
	CCS_TYPE_MANUAL_TASK_ACL,
	CCS_TYPE_USE_GROUP_ACL,
};

/* Index numbers for "struct ccs_condition". */
enum ccs_conditions_index {
	CCS_TASK_UID,             /* current_uid()   */
	CCS_TASK_EUID,            /* current_euid()  */
	CCS_TASK_SUID,            /* current_suid()  */
	CCS_TASK_FSUID,           /* current_fsuid() */
	CCS_TASK_GID,             /* current_gid()   */
	CCS_TASK_EGID,            /* current_egid()  */
	CCS_TASK_SGID,            /* current_sgid()  */
	CCS_TASK_FSGID,           /* current_fsgid() */
	CCS_TASK_PID,             /* sys_getpid()   */
	CCS_TASK_PPID,            /* sys_getppid()  */
	CCS_EXEC_ARGC,            /* "struct linux_binprm *"->argc */
	CCS_EXEC_ENVC,            /* "struct linux_binprm *"->envc */
	CCS_TYPE_IS_SOCKET,       /* S_IFSOCK */
	CCS_TYPE_IS_SYMLINK,      /* S_IFLNK */
	CCS_TYPE_IS_FILE,         /* S_IFREG */
	CCS_TYPE_IS_BLOCK_DEV,    /* S_IFBLK */
	CCS_TYPE_IS_DIRECTORY,    /* S_IFDIR */
	CCS_TYPE_IS_CHAR_DEV,     /* S_IFCHR */
	CCS_TYPE_IS_FIFO,         /* S_IFIFO */
	CCS_MODE_SETUID,          /* S_ISUID */
	CCS_MODE_SETGID,          /* S_ISGID */
	CCS_MODE_STICKY,          /* S_ISVTX */
	CCS_MODE_OWNER_READ,      /* S_IRUSR */
	CCS_MODE_OWNER_WRITE,     /* S_IWUSR */
	CCS_MODE_OWNER_EXECUTE,   /* S_IXUSR */
	CCS_MODE_GROUP_READ,      /* S_IRGRP */
	CCS_MODE_GROUP_WRITE,     /* S_IWGRP */
	CCS_MODE_GROUP_EXECUTE,   /* S_IXGRP */
	CCS_MODE_OTHERS_READ,     /* S_IROTH */
	CCS_MODE_OTHERS_WRITE,    /* S_IWOTH */
	CCS_MODE_OTHERS_EXECUTE,  /* S_IXOTH */
	CCS_TASK_TYPE,            /* ((u8) task->ccs_flags) &
				     CCS_TASK_IS_EXECUTE_HANDLER */
	CCS_TASK_EXECUTE_HANDLER, /* CCS_TASK_IS_EXECUTE_HANDLER */
	CCS_EXEC_REALPATH,
	CCS_PATH1_UID,
	CCS_PATH1_GID,
	CCS_PATH1_INO,
	CCS_PATH1_MAJOR,
	CCS_PATH1_MINOR,
	CCS_PATH1_PERM,
	CCS_PATH1_TYPE,
	CCS_PATH1_DEV_MAJOR,
	CCS_PATH1_DEV_MINOR,
	CCS_PATH2_UID,
	CCS_PATH2_GID,
	CCS_PATH2_INO,
	CCS_PATH2_MAJOR,
	CCS_PATH2_MINOR,
	CCS_PATH2_PERM,
	CCS_PATH2_TYPE,
	CCS_PATH2_DEV_MAJOR,
	CCS_PATH2_DEV_MINOR,
	CCS_PATH1_PARENT_UID,
	CCS_PATH1_PARENT_GID,
	CCS_PATH1_PARENT_INO,
	CCS_PATH1_PARENT_PERM,
	CCS_PATH2_PARENT_UID,
	CCS_PATH2_PARENT_GID,
	CCS_PATH2_PARENT_INO,
	CCS_PATH2_PARENT_PERM,
	CCS_MAX_CONDITION_KEYWORD,
	CCS_NUMBER_UNION,
	CCS_NAME_UNION,
	CCS_ARGV_ENTRY,
	CCS_ENVP_ENTRY,
};

/* Index numbers for audit type. */
enum ccs_grant_log {
	/* Follow profile's configuration. */
	CCS_GRANTLOG_AUTO,
	/* Do not generate grant log. */
	CCS_GRANTLOG_NO,
	/* Generate grant_log. */
	CCS_GRANTLOG_YES,
};

/* Index numbers for group entries. */
enum ccs_group_id {
	CCS_PATH_GROUP,
	CCS_NUMBER_GROUP,
	CCS_ACL_GROUP,
	CCS_ADDRESS_GROUP,
	CCS_MAX_GROUP
};

/* Index numbers for category of functionality. */
enum ccs_mac_category_index {
	CCS_MAC_CATEGORY_FILE,
	CCS_MAC_CATEGORY_NETWORK,
	CCS_MAC_CATEGORY_MISC,
	CCS_MAC_CATEGORY_IPC,
	CCS_MAC_CATEGORY_CAPABILITY,
	CCS_MAX_MAC_CATEGORY_INDEX
};

/* Index numbers for functionality. */
enum ccs_mac_index {
	CCS_MAC_FILE_EXECUTE,
	CCS_MAC_FILE_READ,
	CCS_MAC_FILE_WRITE,
	CCS_MAC_FILE_APPEND,
	CCS_MAC_FILE_CREATE,
	CCS_MAC_FILE_UNLINK,
	CCS_MAC_FILE_GETATTR,
	CCS_MAC_FILE_MKDIR,
	CCS_MAC_FILE_RMDIR,
	CCS_MAC_FILE_MKFIFO,
	CCS_MAC_FILE_MKSOCK,
	CCS_MAC_FILE_TRUNCATE,
	CCS_MAC_FILE_SYMLINK,
	CCS_MAC_FILE_MKBLOCK,
	CCS_MAC_FILE_MKCHAR,
	CCS_MAC_FILE_LINK,
	CCS_MAC_FILE_RENAME,
	CCS_MAC_FILE_CHMOD,
	CCS_MAC_FILE_CHOWN,
	CCS_MAC_FILE_CHGRP,
	CCS_MAC_FILE_IOCTL,
	CCS_MAC_FILE_CHROOT,
	CCS_MAC_FILE_MOUNT,
	CCS_MAC_FILE_UMOUNT,
	CCS_MAC_FILE_PIVOT_ROOT,
	CCS_MAC_NETWORK_INET_STREAM_BIND,
	CCS_MAC_NETWORK_INET_STREAM_LISTEN,
	CCS_MAC_NETWORK_INET_STREAM_CONNECT,
	CCS_MAC_NETWORK_INET_STREAM_ACCEPT,
	CCS_MAC_NETWORK_INET_DGRAM_BIND,
	CCS_MAC_NETWORK_INET_DGRAM_SEND,
	CCS_MAC_NETWORK_INET_DGRAM_RECV,
	CCS_MAC_NETWORK_INET_RAW_BIND,
	CCS_MAC_NETWORK_INET_RAW_SEND,
	CCS_MAC_NETWORK_INET_RAW_RECV,
	CCS_MAC_NETWORK_UNIX_STREAM_BIND,
	CCS_MAC_NETWORK_UNIX_STREAM_LISTEN,
	CCS_MAC_NETWORK_UNIX_STREAM_CONNECT,
	CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT,
	CCS_MAC_NETWORK_UNIX_DGRAM_BIND,
	CCS_MAC_NETWORK_UNIX_DGRAM_SEND,
	CCS_MAC_NETWORK_UNIX_DGRAM_RECV,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT,
	CCS_MAC_ENVIRON,
	CCS_MAC_PTRACE,
	CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET,
	CCS_MAC_CAPABILITY_USE_PACKET_SOCKET,
	CCS_MAC_CAPABILITY_SYS_REBOOT,
	CCS_MAC_CAPABILITY_SYS_VHANGUP,
	CCS_MAC_CAPABILITY_SYS_SETTIME,
	CCS_MAC_CAPABILITY_SYS_NICE,
	CCS_MAC_CAPABILITY_SYS_SETHOSTNAME,
	CCS_MAC_CAPABILITY_USE_KERNEL_MODULE,
	CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD,
	CCS_MAX_MAC_INDEX
};

/* Index numbers for /proc/ccs/stat interface. */
enum ccs_memory_stat_type {
	CCS_MEMORY_POLICY,
	CCS_MEMORY_AUDIT,
	CCS_MEMORY_QUERY,
	CCS_MAX_MEMORY_STAT
};

/* Index numbers for access controls with one pathname and three numbers. */
enum ccs_mkdev_acl_index {
	CCS_TYPE_MKBLOCK,
	CCS_TYPE_MKCHAR,
	CCS_MAX_MKDEV_OPERATION
};

/* Index numbers for operation mode. */
enum ccs_mode_value {
	CCS_CONFIG_DISABLED,
	CCS_CONFIG_LEARNING,
	CCS_CONFIG_PERMISSIVE,
	CCS_CONFIG_ENFORCING,
	CCS_CONFIG_MAX_MODE,
	CCS_CONFIG_WANT_REJECT_LOG =  64,
	CCS_CONFIG_WANT_GRANT_LOG  = 128,
	CCS_CONFIG_USE_DEFAULT     = 255,
};

/* Index numbers for socket operations. */
enum ccs_network_acl_index {
	CCS_NETWORK_BIND,    /* bind() operation. */
	CCS_NETWORK_LISTEN,  /* listen() operation. */
	CCS_NETWORK_CONNECT, /* connect() operation. */
	CCS_NETWORK_ACCEPT,  /* accept() operation. */
	CCS_NETWORK_SEND,    /* send() operation. */
	CCS_NETWORK_RECV,    /* recv() operation. */
	CCS_MAX_NETWORK_OPERATION
};

/* Index numbers for access controls with two pathnames. */
enum ccs_path2_acl_index {
	CCS_TYPE_LINK,
	CCS_TYPE_RENAME,
	CCS_TYPE_PIVOT_ROOT,
	CCS_TYPE_SYMLINK,
	CCS_MAX_PATH2_OPERATION
};

/* Index numbers for access controls with one pathname. */
enum ccs_path_acl_index {
	CCS_TYPE_READ,
	CCS_TYPE_WRITE,
	CCS_TYPE_APPEND,
	CCS_TYPE_UNLINK,
	CCS_TYPE_GETATTR,
	CCS_TYPE_RMDIR,
	CCS_TYPE_TRUNCATE,
	CCS_TYPE_CHROOT,
	CCS_TYPE_UMOUNT,
	CCS_MAX_PATH_OPERATION
};

/* Index numbers for access controls with one pathname and one number. */
enum ccs_path_number_acl_index {
	CCS_TYPE_CREATE,
	CCS_TYPE_MKDIR,
	CCS_TYPE_MKFIFO,
	CCS_TYPE_MKSOCK,
	CCS_TYPE_IOCTL,
	CCS_TYPE_CHMOD,
	CCS_TYPE_CHOWN,
	CCS_TYPE_CHGRP,
	CCS_MAX_PATH_NUMBER_OPERATION
};

/* Index numbers for stat(). */
enum ccs_path_stat_index {
	/* Do not change this order. */
	CCS_PATH1,
	CCS_PATH1_PARENT,
	CCS_PATH2,
	CCS_PATH2_PARENT,
	CCS_MAX_PATH_STAT
};

/* Index numbers for entry type. */
enum ccs_policy_id {
	CCS_ID_GROUP,
	CCS_ID_ADDRESS_GROUP,
	CCS_ID_PATH_GROUP,
	CCS_ID_NUMBER_GROUP,
	CCS_ID_MANAGER,
	CCS_ID_CONDITION,
	CCS_ID_NAME,
	CCS_ID_ACL,
	CCS_ID_DOMAIN,
	CCS_MAX_POLICY
};

/* Index numbers for /proc/ccs/stat interface. */
enum ccs_policy_stat_type {
	CCS_STAT_POLICY_UPDATES,
	CCS_STAT_POLICY_LEARNING,
	CCS_STAT_POLICY_PERMISSIVE,
	CCS_STAT_POLICY_ENFORCING,
	CCS_MAX_POLICY_STAT
};

/* Index numbers for profile's PREFERENCE values. */
enum ccs_pref_index {
	CCS_PREF_MAX_AUDIT_LOG,
	CCS_PREF_MAX_LEARNING_ENTRY,
	CCS_PREF_ENFORCING_PENALTY,
	CCS_MAX_PREF
};

/* Index numbers for /proc/ccs/ interfaces. */
enum ccs_proc_interface_index {
	CCS_DOMAIN_POLICY,
	CCS_EXCEPTION_POLICY,
	CCS_PROCESS_STATUS,
	CCS_STAT,
	CCS_AUDIT,
	CCS_VERSION,
	CCS_PROFILE,
	CCS_QUERY,
	CCS_MANAGER,
	CCS_EXECUTE_HANDLER,
	CCS_ACL_POLICY,
};

/* Index numbers for special mount operations. */
enum ccs_special_mount {
	CCS_MOUNT_BIND,            /* mount --bind /source /dest   */
	CCS_MOUNT_MOVE,            /* mount --move /old /new       */
	CCS_MOUNT_REMOUNT,         /* mount -o remount /dir        */
	CCS_MOUNT_MAKE_UNBINDABLE, /* mount --make-unbindable /dir */
	CCS_MOUNT_MAKE_PRIVATE,    /* mount --make-private /dir    */
	CCS_MOUNT_MAKE_SLAVE,      /* mount --make-slave /dir      */
	CCS_MOUNT_MAKE_SHARED,     /* mount --make-shared /dir     */
	CCS_MAX_SPECIAL_MOUNT
};

/* Index numbers for type of numeric values. */
enum ccs_value_type {
	CCS_VALUE_TYPE_INVALID,
	CCS_VALUE_TYPE_DECIMAL,
	CCS_VALUE_TYPE_OCTAL,
	CCS_VALUE_TYPE_HEXADECIMAL,
};

/* Constants definition for internal use. */

/*
 * TOMOYO uses this hash only when appending a string into the string table.
 * Frequency of appending strings is very low. So we don't need large (e.g.
 * 64k) hash size. 256 will be sufficient.
 */
#define CCS_HASH_BITS 8
#define CCS_MAX_HASH (1u << CCS_HASH_BITS)

/*
 * TOMOYO checks only SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET.
 * Therefore, we don't need SOCK_MAX.
 */
#define CCS_SOCK_MAX 6

/* Size of temporary buffer for execve() operation. */
#define CCS_EXEC_TMPSIZE     4096

/* Profile number is an integer between 0 and 255. */
#define CCS_MAX_PROFILES 256

/* Structure definition for internal use. */

/* Common header for holding ACL entries. */
struct ccs_acl_head {
	struct list_head list;
	s8 is_deleted; /* true or false or CCS_GC_IN_PROGRESS */
};

/* Common header for shared entries. */
struct ccs_shared_acl_head {
	struct list_head list;
};

/* Common header for individual entries. */
struct ccs_acl_info {
	struct list_head list;
	struct list_head domain_list; /* Used by inverse mode. */
	struct ccs_condition *cond; /* Maybe NULL. */
	s8 is_deleted; /* true or false or CCS_GC_IN_PROGRESS */
	u8 type; /* One of values in "enum ccs_acl_entry_type_index". */
	u8 mode; /* Used by inverse mode. */
	u16 perm;
};

/* Structure for holding a word. */
struct ccs_name_union {
	/* Either @filename or @group is NULL. */
	const struct ccs_path_info *filename;
	struct ccs_group *group;
	bool is_not;
};

/* Structure for holding a number. */
struct ccs_number_union {
	unsigned long values[2];
	struct ccs_group *group; /* Maybe NULL. */
	/* One of values in "enum ccs_value_type". */
	u8 value_type[2];
	bool is_not;
};

/* Structure for holding an IP address. */
struct ccs_ipaddr_union {
	struct in6_addr ip[2]; /* Big endian. */
	struct ccs_group *group; /* Pointer to address group. */
	bool is_ipv6; /* Valid only if @group == NULL. */
	bool is_not;
};

/* Structure for "path_group"/"number_group"/"address_group" directive. */
struct ccs_group {
	struct ccs_shared_acl_head head;
	/* Name of group (without leading "\\=" or "\\!"). */
	const struct ccs_path_info *group_name;
	/*
	 * List of "struct ccs_path_group" or "struct ccs_number_group" or
	 * "struct ccs_address_group".
	 */
	struct list_head member_list;
};

/* Structure for "path_group" directive. */
struct ccs_path_group {
	struct ccs_acl_head head;
	const struct ccs_path_info *member_name;
};

/* Structure for "number_group" directive. */
struct ccs_number_group {
	struct ccs_acl_head head;
	struct ccs_number_union number;
};

/* Structure for "address_group" directive. */
struct ccs_address_group {
	struct ccs_acl_head head;
	/* Structure for holding an IP address. */
	struct ccs_ipaddr_union address;
	bool is_not;
};

/* Structure for entries which follows "struct ccs_condition". */
struct ccs_condition_element {
	/*
	 * Left hand operand. A "struct ccs_argv" for CCS_ARGV_ENTRY, a
	 * "struct ccs_envp" for CCS_ENVP_ENTRY is attached to the tail
	 * of the array of this struct.
	 */
	u8 left;
	/*
	 * Right hand operand. A "struct ccs_number_union" for
	 * CCS_NUMBER_UNION, a "struct ccs_name_union" for CCS_NAME_UNION is
	 * attached to the tail of the array of this struct.
	 */
	u8 right;
	/* Equation operator. True if equals or overlaps, false otherwise. */
	bool equals;
};

/* Structure for optional arguments. */
struct ccs_condition {
	struct ccs_shared_acl_head head;
	u32 size; /* Memory size allocated for this entry. */
	u16 condc; /* Number of conditions in this struct. */
	u16 numbers_count; /* Number of "struct ccs_number_union values". */
	u16 names_count; /* Number of "struct ccs_name_union names". */
	u16 argc; /* Number of "struct ccs_argv". */
	u16 envc; /* Number of "struct ccs_envp". */
	u8 grant_log; /* One of values in "enum ccs_grant_log". */
	/*
	 * struct ccs_condition_element condition[condc];
	 * struct ccs_number_union values[numbers_count];
	 * struct ccs_name_union names[names_count];
	 * struct ccs_argv argv[argc];
	 * struct ccs_envp envp[envc];
	 */
};

struct ccs_policy_namespace;

/* Structure for domain information. */
struct ccs_domain_info4 {
	struct list_head list;
	struct list_head acl_info_list;
	/* Name of this domain. Never NULL.          */
	const struct ccs_path_info *domainname;
	/* Namespace for this domain. Never NULL. */
	struct ccs_policy_namespace *ns;
	/* Default domain transition. Never NULL. */
	const struct ccs_path_info *default_transition;
	u8 profile;        /* Profile number to use. */
	bool quota_exceeded;
	s8 is_deleted;     /* Delete flag.           */
	struct ccs_condition *cond; /* Used by inverse mode. */
};

/* Structure for policy manager. */
struct ccs_manager {
	struct ccs_acl_head head;
	bool is_domain;  /* True if manager is a domainname. */
	/* A path to program or a domainname. */
	const struct ccs_path_info *manager;
};

/* Structure for argv[]. */
struct ccs_argv {
	unsigned long index;
	const struct ccs_path_info *value;
	bool is_not;
};

/* Structure for envp[]. */
struct ccs_envp {
	const struct ccs_path_info *name;
	const struct ccs_path_info *value;
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
struct ccs_handler_acl {
	struct ccs_acl_info head;       /* type = CCS_TYPE_*_EXECUTE_HANDLER */
	const struct ccs_path_info *handler; /* Pointer to single pathname.  */
	const struct ccs_path_info *transit; /* Maybe NULL. */
};

/*
 * Structure for "task auto_domain_transition" and
 * "task manual_domain_transition" directive.
 */
struct ccs_task_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_*_TASK_ACL */
	/* Pointer to domainname. */
	const struct ccs_path_info *domainname;
};

/* Structure for "file execute" directive. */
struct ccs_execute_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_EXECUTE_ACL */
	struct ccs_name_union program;
	const struct ccs_path_info *transit; /* Maybe NULL. */
};

/*
 * Structure for "file read", "file write", "file append", "file unlink",
 * "file getattr", "file rmdir", "file truncate", "file chroot" and
 * "file unmount" directive.
 */
struct ccs_path_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PATH_ACL */
	struct ccs_name_union name;
};

/*
 * Structure for "file rename", "file link", "file pivot_root" and
 * "file symlink" directive.
 */
struct ccs_path2_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PATH2_ACL */
	struct ccs_name_union name1;
	struct ccs_name_union name2;
};

/*
 * Structure for "file create", "file mkdir", "file mkfifo", "file mksock",
 * "file ioctl", "file chmod", "file chown" and "file chgrp" directive.
 */
struct ccs_path_number_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PATH_NUMBER_ACL */
	struct ccs_name_union name;
	struct ccs_number_union number;
};

/* Structure for "file mkblock" and "file mkchar" directive. */
struct ccs_mkdev_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_MKDEV_ACL */
	struct ccs_name_union name;
	struct ccs_number_union mode;
	struct ccs_number_union major;
	struct ccs_number_union minor;
};

/* Structure for "file mount" directive. */
struct ccs_mount_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_MOUNT_ACL */
	struct ccs_name_union dev_name;
	struct ccs_name_union dir_name;
	struct ccs_name_union fs_type;
	struct ccs_number_union flags;
};

/* Structure for "misc env" directive in domain policy. */
struct ccs_env_acl {
	struct ccs_acl_info head;  /* type = CCS_TYPE_ENV_ACL  */
	struct ccs_name_union env; /* environment variable */
};

/* Structure for "capability" directive. */
struct ccs_capability_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_CAPABILITY_ACL */
	u8 operation; /* One of values in "enum ccs_capability_acl_index". */
};

/* Structure for "ipc ptrace" directive. */
struct ccs_ptrace_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PTRACE_ACL */
	struct ccs_number_union request;
	const struct ccs_path_info *domainname;
};

/* Structure for "network inet" directive. */
struct ccs_inet_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_INET_ACL */
	u8 protocol;
	struct ccs_ipaddr_union address;
	struct ccs_number_union port;
};

/* Structure for "network unix" directive. */
struct ccs_unix_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_UNIX_ACL */
	u8 protocol;
	struct ccs_name_union name;
};

/* Structure for "use_group" directive. */
struct ccs_use_group_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_USE_GROUP_ACL */
	struct ccs_group *group;
	bool is_not;
};

/* Structure for holding string data. */
struct ccs_name {
	struct ccs_shared_acl_head head;
	int size; /* Memory size allocated for this entry. */
	struct ccs_path_info entry;
};

/* Structure for holding a line from /proc/ccs/ interface. */
struct ccs_acl_param {
	char *data; /* Unprocessed data. */
	struct list_head *list; /* List to add or remove. */
	struct ccs_policy_namespace *ns; /* Namespace to use. */
	bool is_delete; /* True if it is a delete request. */
	union ccs_acl_union {
		struct ccs_acl_info acl_info;
		struct ccs_handler_acl handler_acl;
		struct ccs_task_acl task_acl;
		struct ccs_execute_acl execute_acl;
		struct ccs_path_acl path_acl;
		struct ccs_path2_acl path2_acl;
		struct ccs_path_number_acl path_number_acl;
		struct ccs_mkdev_acl mkdev_acl;
		struct ccs_mount_acl mount_acl;
		struct ccs_env_acl env_acl;
		struct ccs_capability_acl capability_acl;
		struct ccs_ptrace_acl ptrace_acl;
		struct ccs_inet_acl inet_acl;
		struct ccs_unix_acl unix_acl;
		struct ccs_use_group_acl use_group_acl;
		/**/
		struct ccs_acl_head acl_head;
		struct ccs_manager manager;
		struct ccs_path_group path_group;
		struct ccs_number_group number_group;
		struct ccs_address_group address_group;
	} e;
	struct ccs_acl_info *matched_entry; /* Used by inverse mode. */
};

/* Structure for reading/writing policy via /proc/ccs/ interfaces. */
struct ccs_io_buffer {
	const struct ccs_path_info *acl_group_name;
	struct ccs_policy_namespace *ns;
	struct ccs_domain_info4 *domain;
	struct ccs_acl_info *acl; /* Used by inverse mode. */
	char *write_buf;
	u8 type;
	bool reset;
	bool print_this_domain_only;
	bool print_transition_related_only;
	bool print_default_transition;
	bool is_delete;
} head;

/* Structure for /proc/ccs/profile interface. */
struct ccs_profile {
	const struct ccs_path_info *comment;
	u8 default_config;
	u8 config[CCS_MAX_MAC_INDEX + CCS_MAX_MAC_CATEGORY_INDEX];
	unsigned int pref[CCS_MAX_PREF];
};

/* Structure for policy namespace. */
struct ccs_policy_namespace {
	/* Profile table. Memory is allocated as needed. */
	struct ccs_profile *profile_ptr[CCS_MAX_PROFILES];
	/* List of "struct ccs_group". */
	struct list_head group_list[CCS_MAX_GROUP];
	/* List of default transition pattern. */
	struct list_head default_transition_list;
	/* List for connecting to ccs_namespace_list list. */
	struct list_head namespace_list;
	/* Profile version. Currently only 20100903 is defined. */
	unsigned int profile_version;
	/* Name of this namespace (e.g. "<kernel>", "</usr/sbin/httpd>" ). */
	const char *name;
};

/* Prototype definition for internal use. */

static bool ccs_memory_ok(const void *ptr, const unsigned int size);
static struct ccs_domain_info4 *ccs_assign_domain4(const char *domainname);
static void *ccs_commit_ok(void *data, const unsigned int size);

/* Variable definition for internal use. */

/* Mapping table from "enum ccs_path_acl_index" to "enum ccs_mac_index". */
static const u8 ccs_p2mac[CCS_MAX_PATH_OPERATION] = {
	[CCS_TYPE_READ]       = CCS_MAC_FILE_READ,
	[CCS_TYPE_WRITE]      = CCS_MAC_FILE_WRITE,
	[CCS_TYPE_APPEND]     = CCS_MAC_FILE_APPEND,
	[CCS_TYPE_UNLINK]     = CCS_MAC_FILE_UNLINK,
	[CCS_TYPE_GETATTR]    = CCS_MAC_FILE_GETATTR,
	[CCS_TYPE_RMDIR]      = CCS_MAC_FILE_RMDIR,
	[CCS_TYPE_TRUNCATE]   = CCS_MAC_FILE_TRUNCATE,
	[CCS_TYPE_CHROOT]     = CCS_MAC_FILE_CHROOT,
	[CCS_TYPE_UMOUNT]     = CCS_MAC_FILE_UMOUNT,
};

/* Mapping table from "enum ccs_mkdev_acl_index" to "enum ccs_mac_index". */
static const u8 ccs_pnnn2mac[CCS_MAX_MKDEV_OPERATION] = {
	[CCS_TYPE_MKBLOCK] = CCS_MAC_FILE_MKBLOCK,
	[CCS_TYPE_MKCHAR]  = CCS_MAC_FILE_MKCHAR,
};

/* Mapping table from "enum ccs_path2_acl_index" to "enum ccs_mac_index". */
static const u8 ccs_pp2mac[CCS_MAX_PATH2_OPERATION] = {
	[CCS_TYPE_LINK]       = CCS_MAC_FILE_LINK,
	[CCS_TYPE_RENAME]     = CCS_MAC_FILE_RENAME,
	[CCS_TYPE_PIVOT_ROOT] = CCS_MAC_FILE_PIVOT_ROOT,
	[CCS_TYPE_SYMLINK]    = CCS_MAC_FILE_SYMLINK,
};

/*
 * Mapping table from "enum ccs_path_number_acl_index" to "enum ccs_mac_index".
 */
static const u8 ccs_pn2mac[CCS_MAX_PATH_NUMBER_OPERATION] = {
	[CCS_TYPE_CREATE] = CCS_MAC_FILE_CREATE,
	[CCS_TYPE_MKDIR]  = CCS_MAC_FILE_MKDIR,
	[CCS_TYPE_MKFIFO] = CCS_MAC_FILE_MKFIFO,
	[CCS_TYPE_MKSOCK] = CCS_MAC_FILE_MKSOCK,
	[CCS_TYPE_IOCTL]  = CCS_MAC_FILE_IOCTL,
	[CCS_TYPE_CHMOD]  = CCS_MAC_FILE_CHMOD,
	[CCS_TYPE_CHOWN]  = CCS_MAC_FILE_CHOWN,
	[CCS_TYPE_CHGRP]  = CCS_MAC_FILE_CHGRP,
};

/*
 * Mapping table from "enum ccs_capability_acl_index" to "enum ccs_mac_index".
 */
static const u8 ccs_c2mac[CCS_MAX_CAPABILITY_INDEX] = {
	[CCS_USE_ROUTE_SOCKET]  = CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET,
	[CCS_USE_PACKET_SOCKET] = CCS_MAC_CAPABILITY_USE_PACKET_SOCKET,
	[CCS_SYS_REBOOT]        = CCS_MAC_CAPABILITY_SYS_REBOOT,
	[CCS_SYS_VHANGUP]       = CCS_MAC_CAPABILITY_SYS_VHANGUP,
	[CCS_SYS_SETTIME]       = CCS_MAC_CAPABILITY_SYS_SETTIME,
	[CCS_SYS_NICE]          = CCS_MAC_CAPABILITY_SYS_NICE,
	[CCS_SYS_SETHOSTNAME]   = CCS_MAC_CAPABILITY_SYS_SETHOSTNAME,
	[CCS_USE_KERNEL_MODULE] = CCS_MAC_CAPABILITY_USE_KERNEL_MODULE,
	[CCS_SYS_KEXEC_LOAD]    = CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD,
};

static struct ccs_domain_info4 ccs_kernel_domain;
static struct ccs_group ccs_group_any;
static LIST_HEAD(ccs_domain_list);
static LIST_HEAD(ccs_inversed_acl_list);
static unsigned int ccs_memory_quota[CCS_MAX_MEMORY_STAT];
static unsigned int ccs_memory_used[CCS_MAX_MEMORY_STAT];

/* Inlined functions for internal use. */

/**
 * ccs_put_condition - Drop reference on "struct ccs_condition".
 *
 * @cond: Pointer to "struct ccs_condition". Maybe NULL.
 *
 * Returns nothing.
 */
static inline void ccs_put_condition(struct ccs_condition *cond)
{
}

/**
 * ccs_put_group - Drop reference on "struct ccs_group".
 *
 * @group: Pointer to "struct ccs_group". Maybe NULL.
 *
 * Returns nothing.
 */
static inline void ccs_put_group(struct ccs_group *group)
{
}

/**
 * ccs_put_name - Drop reference on "struct ccs_name".
 *
 * @name: Pointer to "struct ccs_path_info". Maybe NULL.
 *
 * Returns nothing.
 */
static inline void ccs_put_name(const struct ccs_path_info *name)
{
}

/***** SECTION1: Constants definition *****/

/* Mapping table from "enum ccs_mac_index" to "enum ccs_mac_category_index". */
static const u8 ccs_index2category[CCS_MAX_MAC_INDEX] = {
	/* CONFIG::file group */
	[CCS_MAC_FILE_EXECUTE]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_READ]       = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_WRITE]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_APPEND]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CREATE]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_UNLINK]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_GETATTR]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKDIR]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_RMDIR]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKFIFO]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKSOCK]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_TRUNCATE]   = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_SYMLINK]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKBLOCK]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MKCHAR]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_LINK]       = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_RENAME]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHMOD]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHOWN]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHGRP]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_IOCTL]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CHROOT]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_MOUNT]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_UMOUNT]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_PIVOT_ROOT] = CCS_MAC_CATEGORY_FILE,
	/* CONFIG::misc group */
	[CCS_MAC_ENVIRON]         = CCS_MAC_CATEGORY_MISC,
	/* CONFIG::network group */
	[CCS_MAC_NETWORK_INET_STREAM_BIND]       = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_STREAM_LISTEN]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_STREAM_CONNECT]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_STREAM_ACCEPT]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_DGRAM_BIND]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_DGRAM_SEND]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_DGRAM_RECV]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_RAW_BIND]          = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_RAW_SEND]          = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_RAW_RECV]          = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_BIND]       = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_LISTEN]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_CONNECT]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_DGRAM_BIND]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_DGRAM_SEND]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_DGRAM_RECV]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN]  = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT] = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT]  = CCS_MAC_CATEGORY_NETWORK,
	/* CONFIG::ipc group */
	[CCS_MAC_PTRACE]          = CCS_MAC_CATEGORY_IPC,
	/* CONFIG::capability group */
	[CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET]  = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_USE_PACKET_SOCKET] = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_REBOOT]        = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_VHANGUP]       = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_SETTIME]       = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_NICE]          = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_SETHOSTNAME]   = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_USE_KERNEL_MODULE] = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD]    = CCS_MAC_CATEGORY_CAPABILITY,
};

/* String table for operation mode. */
static const char * const ccs_mode[CCS_CONFIG_MAX_MODE] = {
	[CCS_CONFIG_DISABLED]   = "disabled",
	[CCS_CONFIG_LEARNING]   = "learning",
	[CCS_CONFIG_PERMISSIVE] = "permissive",
	[CCS_CONFIG_ENFORCING]  = "enforcing"
};

/* String table for /proc/ccs/profile interface. */
static const char * const ccs_mac_keywords[CCS_MAX_MAC_INDEX
					   + CCS_MAX_MAC_CATEGORY_INDEX] = {
	/* CONFIG::file group */
	[CCS_MAC_FILE_EXECUTE]    = "execute",
	[CCS_MAC_FILE_READ]       = "read",
	[CCS_MAC_FILE_WRITE]      = "write",
	[CCS_MAC_FILE_APPEND]     = "append",
	[CCS_MAC_FILE_CREATE]     = "create",
	[CCS_MAC_FILE_UNLINK]     = "unlink",
	[CCS_MAC_FILE_GETATTR]    = "getattr",
	[CCS_MAC_FILE_MKDIR]      = "mkdir",
	[CCS_MAC_FILE_RMDIR]      = "rmdir",
	[CCS_MAC_FILE_MKFIFO]     = "mkfifo",
	[CCS_MAC_FILE_MKSOCK]     = "mksock",
	[CCS_MAC_FILE_TRUNCATE]   = "truncate",
	[CCS_MAC_FILE_SYMLINK]    = "symlink",
	[CCS_MAC_FILE_MKBLOCK]    = "mkblock",
	[CCS_MAC_FILE_MKCHAR]     = "mkchar",
	[CCS_MAC_FILE_LINK]       = "link",
	[CCS_MAC_FILE_RENAME]     = "rename",
	[CCS_MAC_FILE_CHMOD]      = "chmod",
	[CCS_MAC_FILE_CHOWN]      = "chown",
	[CCS_MAC_FILE_CHGRP]      = "chgrp",
	[CCS_MAC_FILE_IOCTL]      = "ioctl",
	[CCS_MAC_FILE_CHROOT]     = "chroot",
	[CCS_MAC_FILE_MOUNT]      = "mount",
	[CCS_MAC_FILE_UMOUNT]     = "unmount",
	[CCS_MAC_FILE_PIVOT_ROOT] = "pivot_root",
	/* CONFIG::misc group */
	[CCS_MAC_ENVIRON] = "env",
	/* CONFIG::network group */
	[CCS_MAC_NETWORK_INET_STREAM_BIND]       = "inet_stream_bind",
	[CCS_MAC_NETWORK_INET_STREAM_LISTEN]     = "inet_stream_listen",
	[CCS_MAC_NETWORK_INET_STREAM_CONNECT]    = "inet_stream_connect",
	[CCS_MAC_NETWORK_INET_STREAM_ACCEPT]     = "inet_stream_accept",
	[CCS_MAC_NETWORK_INET_DGRAM_BIND]        = "inet_dgram_bind",
	[CCS_MAC_NETWORK_INET_DGRAM_SEND]        = "inet_dgram_send",
	[CCS_MAC_NETWORK_INET_DGRAM_RECV]        = "inet_dgram_recv",
	[CCS_MAC_NETWORK_INET_RAW_BIND]          = "inet_raw_bind",
	[CCS_MAC_NETWORK_INET_RAW_SEND]          = "inet_raw_send",
	[CCS_MAC_NETWORK_INET_RAW_RECV]          = "inet_raw_recv",
	[CCS_MAC_NETWORK_UNIX_STREAM_BIND]       = "unix_stream_bind",
	[CCS_MAC_NETWORK_UNIX_STREAM_LISTEN]     = "unix_stream_listen",
	[CCS_MAC_NETWORK_UNIX_STREAM_CONNECT]    = "unix_stream_connect",
	[CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT]     = "unix_stream_accept",
	[CCS_MAC_NETWORK_UNIX_DGRAM_BIND]        = "unix_dgram_bind",
	[CCS_MAC_NETWORK_UNIX_DGRAM_SEND]        = "unix_dgram_send",
	[CCS_MAC_NETWORK_UNIX_DGRAM_RECV]        = "unix_dgram_recv",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND]    = "unix_seqpacket_bind",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN]  = "unix_seqpacket_listen",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT] = "unix_seqpacket_connect",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT]  = "unix_seqpacket_accept",
	/* CONFIG::ipc group */
	[CCS_MAC_PTRACE] = "ptrace",
	/* CONFIG::capability group */
	[CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET]  = "use_route",
	[CCS_MAC_CAPABILITY_USE_PACKET_SOCKET] = "use_packet",
	[CCS_MAC_CAPABILITY_SYS_REBOOT]        = "SYS_REBOOT",
	[CCS_MAC_CAPABILITY_SYS_VHANGUP]       = "SYS_VHANGUP",
	[CCS_MAC_CAPABILITY_SYS_SETTIME]       = "SYS_TIME",
	[CCS_MAC_CAPABILITY_SYS_NICE]          = "SYS_NICE",
	[CCS_MAC_CAPABILITY_SYS_SETHOSTNAME]   = "SYS_SETHOSTNAME",
	[CCS_MAC_CAPABILITY_USE_KERNEL_MODULE] = "use_kernel_module",
	[CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD]    = "SYS_KEXEC_LOAD",
	/* CONFIG group */
	[CCS_MAX_MAC_INDEX + CCS_MAC_CATEGORY_FILE]       = "file",
	[CCS_MAX_MAC_INDEX + CCS_MAC_CATEGORY_NETWORK]    = "network",
	[CCS_MAX_MAC_INDEX + CCS_MAC_CATEGORY_MISC]       = "misc",
	[CCS_MAX_MAC_INDEX + CCS_MAC_CATEGORY_IPC]        = "ipc",
	[CCS_MAX_MAC_INDEX + CCS_MAC_CATEGORY_CAPABILITY] = "capability",
};

/* String table for socket's operation. */
static const char * const ccs_socket_keyword[CCS_MAX_NETWORK_OPERATION] = {
	[CCS_NETWORK_BIND]    = "bind",
	[CCS_NETWORK_LISTEN]  = "listen",
	[CCS_NETWORK_CONNECT] = "connect",
	[CCS_NETWORK_ACCEPT]  = "accept",
	[CCS_NETWORK_SEND]    = "send",
	[CCS_NETWORK_RECV]    = "recv",
};

/* String table for socket's protocols. */
static const char * const ccs_proto_keyword[CCS_SOCK_MAX] = {
	[SOCK_STREAM]    = "stream",
	[SOCK_DGRAM]     = "dgram",
	[SOCK_RAW]       = "raw",
	[SOCK_SEQPACKET] = "seqpacket",
	[0] = " ", /* Dummy for avoiding NULL pointer dereference. */
	[4] = " ", /* Dummy for avoiding NULL pointer dereference. */
};

/* String table for categories. */
static const char * const ccs_category_keywords[CCS_MAX_MAC_CATEGORY_INDEX] = {
	[CCS_MAC_CATEGORY_FILE]       = "file",
	[CCS_MAC_CATEGORY_NETWORK]    = "network",
	[CCS_MAC_CATEGORY_MISC]       = "misc",
	[CCS_MAC_CATEGORY_IPC]        = "ipc",
	[CCS_MAC_CATEGORY_CAPABILITY] = "capability",
};

/* String table for conditions. */
static const char * const ccs_condition_keyword[CCS_MAX_CONDITION_KEYWORD] = {
	[CCS_TASK_UID]             = "task.uid",
	[CCS_TASK_EUID]            = "task.euid",
	[CCS_TASK_SUID]            = "task.suid",
	[CCS_TASK_FSUID]           = "task.fsuid",
	[CCS_TASK_GID]             = "task.gid",
	[CCS_TASK_EGID]            = "task.egid",
	[CCS_TASK_SGID]            = "task.sgid",
	[CCS_TASK_FSGID]           = "task.fsgid",
	[CCS_TASK_PID]             = "task.pid",
	[CCS_TASK_PPID]            = "task.ppid",
	[CCS_EXEC_ARGC]            = "exec.argc",
	[CCS_EXEC_ENVC]            = "exec.envc",
	[CCS_TYPE_IS_SOCKET]       = "socket",
	[CCS_TYPE_IS_SYMLINK]      = "symlink",
	[CCS_TYPE_IS_FILE]         = "file",
	[CCS_TYPE_IS_BLOCK_DEV]    = "block",
	[CCS_TYPE_IS_DIRECTORY]    = "directory",
	[CCS_TYPE_IS_CHAR_DEV]     = "char",
	[CCS_TYPE_IS_FIFO]         = "fifo",
	[CCS_MODE_SETUID]          = "setuid",
	[CCS_MODE_SETGID]          = "setgid",
	[CCS_MODE_STICKY]          = "sticky",
	[CCS_MODE_OWNER_READ]      = "owner_read",
	[CCS_MODE_OWNER_WRITE]     = "owner_write",
	[CCS_MODE_OWNER_EXECUTE]   = "owner_execute",
	[CCS_MODE_GROUP_READ]      = "group_read",
	[CCS_MODE_GROUP_WRITE]     = "group_write",
	[CCS_MODE_GROUP_EXECUTE]   = "group_execute",
	[CCS_MODE_OTHERS_READ]     = "others_read",
	[CCS_MODE_OTHERS_WRITE]    = "others_write",
	[CCS_MODE_OTHERS_EXECUTE]  = "others_execute",
	[CCS_TASK_TYPE]            = "task.type",
	[CCS_TASK_EXECUTE_HANDLER] = "execute_handler",
	[CCS_EXEC_REALPATH]        = "exec.realpath",
	[CCS_PATH1_UID]            = "path1.uid",
	[CCS_PATH1_GID]            = "path1.gid",
	[CCS_PATH1_INO]            = "path1.ino",
	[CCS_PATH1_MAJOR]          = "path1.major",
	[CCS_PATH1_MINOR]          = "path1.minor",
	[CCS_PATH1_PERM]           = "path1.perm",
	[CCS_PATH1_TYPE]           = "path1.type",
	[CCS_PATH1_DEV_MAJOR]      = "path1.dev_major",
	[CCS_PATH1_DEV_MINOR]      = "path1.dev_minor",
	[CCS_PATH2_UID]            = "path2.uid",
	[CCS_PATH2_GID]            = "path2.gid",
	[CCS_PATH2_INO]            = "path2.ino",
	[CCS_PATH2_MAJOR]          = "path2.major",
	[CCS_PATH2_MINOR]          = "path2.minor",
	[CCS_PATH2_PERM]           = "path2.perm",
	[CCS_PATH2_TYPE]           = "path2.type",
	[CCS_PATH2_DEV_MAJOR]      = "path2.dev_major",
	[CCS_PATH2_DEV_MINOR]      = "path2.dev_minor",
	[CCS_PATH1_PARENT_UID]     = "path1.parent.uid",
	[CCS_PATH1_PARENT_GID]     = "path1.parent.gid",
	[CCS_PATH1_PARENT_INO]     = "path1.parent.ino",
	[CCS_PATH1_PARENT_PERM]    = "path1.parent.perm",
	[CCS_PATH2_PARENT_UID]     = "path2.parent.uid",
	[CCS_PATH2_PARENT_GID]     = "path2.parent.gid",
	[CCS_PATH2_PARENT_INO]     = "path2.parent.ino",
	[CCS_PATH2_PARENT_PERM]    = "path2.parent.perm",
};

/* String table for PREFERENCE keyword. */
static const char * const ccs_pref_keywords[CCS_MAX_PREF] = {
	[CCS_PREF_MAX_AUDIT_LOG]      = "max_audit_log",
	[CCS_PREF_MAX_LEARNING_ENTRY] = "max_learning_entry",
	[CCS_PREF_ENFORCING_PENALTY]  = "enforcing_penalty",
};

/* String table for domain flags. */
#define CCS_QUOTA_EXCEEDED "quota_exceeded\n"

/* String table for grouping keywords. */
static const char * const ccs_group_name[CCS_MAX_GROUP] = {
	[CCS_PATH_GROUP]    = "path_group ",
	[CCS_NUMBER_GROUP]  = "number_group ",
	[CCS_ACL_GROUP]     = "acl_group ",
	[CCS_ADDRESS_GROUP] = "address_group ",
};

/* String table for /proc/ccs/stat interface. */
static const char * const ccs_policy_headers[CCS_MAX_POLICY_STAT] = {
	[CCS_STAT_POLICY_UPDATES]    = "update:",
	[CCS_STAT_POLICY_LEARNING]   = "violation in learning mode:",
	[CCS_STAT_POLICY_PERMISSIVE] = "violation in permissive mode:",
	[CCS_STAT_POLICY_ENFORCING]  = "violation in enforcing mode:",
};

/* String table for /proc/ccs/stat interface. */
static const char * const ccs_memory_headers[CCS_MAX_MEMORY_STAT] = {
	[CCS_MEMORY_POLICY]     = "policy:",
	[CCS_MEMORY_AUDIT]      = "audit log:",
	[CCS_MEMORY_QUERY]      = "query message:",
};

/***** SECTION2: Structure definition *****/

/***** SECTION3: Prototype definition section *****/

static _Bool ccs_parse_argv(char *left, char *right, struct ccs_argv *argv);
static _Bool ccs_parse_envp(char *left, char *right, struct ccs_envp *envp);
static _Bool ccs_parse_name_union(struct ccs_acl_param *param,
				 struct ccs_name_union *ptr);
static _Bool ccs_parse_name_union_quoted(struct ccs_acl_param *param,
					struct ccs_name_union *ptr);
static _Bool ccs_parse_number_union(struct ccs_acl_param *param,
				   struct ccs_number_union *ptr);
static _Bool ccs_permstr(const char *string, const char *keyword);
static void ccs_print_condition(const struct ccs_condition *cond);
static void ccs_print_entry(const struct ccs_acl_info *acl);
static _Bool ccs_print_group(const _Bool is_not, const struct ccs_group *group);
static void ccs_read_acl(struct list_head *list);
static void ccs_read_group(const int idx);
static _Bool ccs_same_condition(const struct ccs_condition *a,
			       const struct ccs_condition *b);
static _Bool ccs_select_domain(const char *data);
static _Bool ccs_set_lf(void);
static _Bool ccs_str_starts2(char **src, const char *find);
static char *ccs_get_transit_preference(struct ccs_acl_param *param,
					struct ccs_execute_acl *e);
static char *ccs_read_token(struct ccs_acl_param *param);
static const char *ccs_yesno(const unsigned int value);
static const struct ccs_path_info *ccs_get_domainname
(struct ccs_acl_param *param);
static const struct ccs_path_info *ccs_get_dqword(char *start);
static void ccs_delete_domain4(char *domainname);
static int ccs_parse_policy(char *line);
static int ccs_set_mode(char *name, const char *value,
			struct ccs_profile *profile);
static int ccs_update_acl(const int size, struct ccs_acl_param *param);
static int ccs_update_inverse_list(struct ccs_acl_info *new_entry,
				   const int size,
				   struct ccs_acl_param *param);
static int ccs_update_manager_entry(const char *manager, const _Bool is_delete);
static int ccs_update_policy(const int size, struct ccs_acl_param *param);
static int ccs_write_acl(struct ccs_policy_namespace *ns,
			 struct list_head *list, char *data,
			 const _Bool is_delete);
static int ccs_write_acl_policy(void);
static int ccs_write_domain(void);
static int ccs_write_exception(void);
static int ccs_write_file(struct ccs_acl_param *param);
static int ccs_write_group(struct ccs_acl_param *param, const u8 type);
static int ccs_write_manager(void);
static int ccs_write_profile(void);
static int ccs_write_stat(void);
static int ccs_write_task(struct ccs_acl_param *param);
static int ccs_write_transition_control(struct ccs_acl_param *param);
static int ccs_write_use_group_acl(struct ccs_acl_param *param);
static s8 ccs_find_yesno(const char *string, const char *find);
static struct ccs_condition *ccs_commit_condition(struct ccs_condition *entry);
static struct ccs_condition *ccs_get_condition(struct ccs_acl_param *param);
static struct ccs_domain_info4 *ccs_assign_domain4(const char *domainname);
static struct ccs_domain_info4 *ccs_find_domain4(const char *domainname);
static struct ccs_group *ccs_get_group(struct ccs_acl_param *param,
				       const u8 idx);
static struct ccs_policy_namespace *ccs_assign_namespace
(const char *domainname);
static struct ccs_policy_namespace *ccs_find_namespace(const char *name,
						       const unsigned int len);
static struct ccs_profile *ccs_assign_profile(struct ccs_policy_namespace *ns,
					      const unsigned int profile);
static u8 ccs_condition_type(const char *word);
static u8 ccs_group_type(char **src);
static u8 ccs_parse_ulong(unsigned long *result, char **str);
static void ccs_init_policy_namespace(struct ccs_policy_namespace *ns);
static void cprint(const char *string);
static void cprintf(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void ccs_print_config(const u8 config);
static void ccs_print_name_union(const struct ccs_name_union *ptr);
static void ccs_print_name_union_quoted(const struct ccs_name_union *ptr);
static void ccs_print_namespace(void);
static void ccs_print_number_union(const struct ccs_number_union *ptr);
static void ccs_print_number_union_nospace(const struct ccs_number_union *ptr);
static void ccs_read_domain(void);
static void ccs_read_exception(void);
static void ccs_read_inverse_policy(void);
static void ccs_read_manager(void);
static void ccs_read_profile(void);
static void ccs_read_stat(void);
static void ccs_set_group(const char *category);
static void ccs_set_slash(void);
static void ccs_set_space(void);
static void ccs_set_uint(unsigned int *i, const char *string,
			 const char *find);
static _Bool ccs_parse_ipaddr_union(struct ccs_acl_param *param,
				   struct ccs_ipaddr_union *ptr);
static void ccs_print_ipv4(const u32 *ip);
static void ccs_print_ipv6(const struct in6_addr *ip);
static int ccs_write_inet_network(struct ccs_acl_param *param);
static int ccs_write_unix_network(struct ccs_acl_param *param);
static void ccs_print_ip(const struct ccs_ipaddr_union *ptr);
static int ccs_write_capability(struct ccs_acl_param *param);
static int ccs_write_misc(struct ccs_acl_param *param);
static int ccs_write_ipc(struct ccs_acl_param *param);

/***** SECTION4: Standalone functions section *****/

/*
 * Routines for parsing IPv4 or IPv6 address.
 * These are copied from lib/hexdump.c net/core/utils.c .
 */
#include <ctype.h>

static int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

#define IN6PTON_XDIGIT		0x00010000
#define IN6PTON_DIGIT		0x00020000
#define IN6PTON_COLON_MASK	0x00700000
#define IN6PTON_COLON_1		0x00100000	/* single : requested */
#define IN6PTON_COLON_2		0x00200000	/* second : requested */
#define IN6PTON_COLON_1_2	0x00400000	/* :: requested */
#define IN6PTON_DOT		0x00800000	/* . */
#define IN6PTON_DELIM		0x10000000
#define IN6PTON_NULL		0x20000000	/* first/tail */
#define IN6PTON_UNKNOWN		0x40000000

static inline int xdigit2bin(char c, int delim)
{
	int val;

	if (c == delim || c == '\0')
		return IN6PTON_DELIM;
	if (c == ':')
		return IN6PTON_COLON_MASK;
	if (c == '.')
		return IN6PTON_DOT;

	val = hex_to_bin(c);
	if (val >= 0)
		return val | IN6PTON_XDIGIT | (val < 10 ? IN6PTON_DIGIT : 0);

	if (delim == -1)
		return IN6PTON_DELIM;
	return IN6PTON_UNKNOWN;
}

static int ccs_in4_pton(const char *src, int srclen, u8 *dst, int delim,
			const char **end)
{
	const char *s;
	u8 *d;
	u8 dbuf[4];
	int ret = 0;
	int i;
	int w = 0;

	if (srclen < 0)
		srclen = strlen(src);
	s = src;
	d = dbuf;
	i = 0;
	while (1) {
		int c;
		c = xdigit2bin(srclen > 0 ? *s : '\0', delim);
		if (!(c & (IN6PTON_DIGIT | IN6PTON_DOT | IN6PTON_DELIM |
			   IN6PTON_COLON_MASK)))
			goto out;
		if (c & (IN6PTON_DOT | IN6PTON_DELIM | IN6PTON_COLON_MASK)) {
			if (w == 0)
				goto out;
			*d++ = w & 0xff;
			w = 0;
			i++;
			if (c & (IN6PTON_DELIM | IN6PTON_COLON_MASK)) {
				if (i != 4)
					goto out;
				break;
			}
			goto cont;
		}
		w = (w * 10) + c;
		if ((w & 0xffff) > 255)
			goto out;
cont:
		if (i >= 4)
			goto out;
		s++;
		srclen--;
	}
	ret = 1;
	memcpy(dst, dbuf, sizeof(dbuf));
out:
	if (end)
		*end = s;
	return ret;
}

static int ccs_in6_pton(const char *src, int srclen, u8 *dst, int delim,
			const char **end)
{
	const char *s, *tok = NULL;
	u8 *d, *dc = NULL;
	u8 dbuf[16];
	int ret = 0;
	int i;
	int state = IN6PTON_COLON_1_2 | IN6PTON_XDIGIT | IN6PTON_NULL;
	int w = 0;

	memset(dbuf, 0, sizeof(dbuf));

	s = src;
	d = dbuf;
	if (srclen < 0)
		srclen = strlen(src);

	while (1) {
		int c;

		c = xdigit2bin(srclen > 0 ? *s : '\0', delim);
		if (!(c & state))
			goto out;
		if (c & (IN6PTON_DELIM | IN6PTON_COLON_MASK)) {
			/* process one 16-bit word */
			if (!(state & IN6PTON_NULL)) {
				*d++ = (w >> 8) & 0xff;
				*d++ = w & 0xff;
			}
			w = 0;
			if (c & IN6PTON_DELIM) {
				/* We've processed last word */
				break;
			}
			/*
			 * COLON_1 => XDIGIT
			 * COLON_2 => XDIGIT|DELIM
			 * COLON_1_2 => COLON_2
			 */
			switch (state & IN6PTON_COLON_MASK) {
			case IN6PTON_COLON_2:
				dc = d;
				state = IN6PTON_XDIGIT | IN6PTON_DELIM;
				if (dc - dbuf >= sizeof(dbuf))
					state |= IN6PTON_NULL;
				break;
			case IN6PTON_COLON_1|IN6PTON_COLON_1_2:
				state = IN6PTON_XDIGIT | IN6PTON_COLON_2;
				break;
			case IN6PTON_COLON_1:
				state = IN6PTON_XDIGIT;
				break;
			case IN6PTON_COLON_1_2:
				state = IN6PTON_COLON_2;
				break;
			default:
				state = 0;
			}
			tok = s + 1;
			goto cont;
		}

		if (c & IN6PTON_DOT) {
			ret = ccs_in4_pton(tok ? tok : s, srclen +
					   (int)(s - tok), d, delim, &s);
			if (ret > 0) {
				d += 4;
				break;
			}
			goto out;
		}

		w = (w << 4) | (0xff & c);
		state = IN6PTON_COLON_1 | IN6PTON_DELIM;
		if (!(w & 0xf000))
			state |= IN6PTON_XDIGIT;
		if (!dc && d + 2 < dbuf + sizeof(dbuf)) {
			state |= IN6PTON_COLON_1_2;
			state &= ~IN6PTON_DELIM;
		}
		if (d + 2 >= dbuf + sizeof(dbuf))
			state &= ~(IN6PTON_COLON_1|IN6PTON_COLON_1_2);
cont:
		if ((dc && d + 4 < dbuf + sizeof(dbuf)) ||
		    d + 4 == dbuf + sizeof(dbuf))
			state |= IN6PTON_DOT;
		if (d >= dbuf + sizeof(dbuf))
			state &= ~(IN6PTON_XDIGIT|IN6PTON_COLON_MASK);
		s++;
		srclen--;
	}

	i = 15; d--;

	if (dc) {
		while (d >= dc)
			dst[i--] = *d--;
		while (i >= dc - dbuf)
			dst[i--] = 0;
		while (i >= 0)
			dst[i--] = *d--;
	} else
		memcpy(dst, dbuf, sizeof(dbuf));

	ret = 1;
out:
	if (end)
		*end = s;
	return ret;
}

/*
 * Routines for printing IPv4 or IPv6 address.
 * These are copied from include/linux/kernel.h include/net/ipv6.h
 * include/net/addrconf.h lib/hexdump.c lib/vsprintf.c and simplified.
 */
static const char hex_asc[] = "0123456789abcdef";
#define hex_asc_lo(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)   hex_asc[((x) & 0xf0) >> 4]

static inline char *pack_hex_byte(char *buf, u8 byte)
{
	*buf++ = hex_asc_hi(byte);
	*buf++ = hex_asc_lo(byte);
	return buf;
}

static inline int ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return (a->s6_addr32[0] | a->s6_addr32[1] |
		(a->s6_addr32[2] ^ htonl(0x0000ffff))) == 0;
}

static inline int ipv6_addr_is_isatap(const struct in6_addr *addr)
{
	return (addr->s6_addr32[2] | htonl(0x02000000)) == htonl(0x02005EFE);
}

static char *ip4_string(char *p, const u8 *addr)
{
	/*
	 * Since this function is called outside vsnprintf(), I can use
	 * sprintf() here.
	 */
	return p +
		sprintf(p, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
}

static char *ip6_compressed_string(char *p, const char *addr)
{
	int i, j, range;
	unsigned char zerolength[8];
	int longest = 1;
	int colonpos = -1;
	u16 word;
	u8 hi, lo;
	_Bool needcolon = false;
	_Bool useIPv4;
	struct in6_addr in6;

	memcpy(&in6, addr, sizeof(struct in6_addr));

	useIPv4 = ipv6_addr_v4mapped(&in6) || ipv6_addr_is_isatap(&in6);

	memset(zerolength, 0, sizeof(zerolength));

	if (useIPv4)
		range = 6;
	else
		range = 8;

	/* find position of longest 0 run */
	for (i = 0; i < range; i++) {
		for (j = i; j < range; j++) {
			if (in6.s6_addr16[j] != 0)
				break;
			zerolength[i]++;
		}
	}
	for (i = 0; i < range; i++) {
		if (zerolength[i] > longest) {
			longest = zerolength[i];
			colonpos = i;
		}
	}
	if (longest == 1)		/* don't compress a single 0 */
		colonpos = -1;

	/* emit address */
	for (i = 0; i < range; i++) {
		if (i == colonpos) {
			if (needcolon || i == 0)
				*p++ = ':';
			*p++ = ':';
			needcolon = false;
			i += longest - 1;
			continue;
		}
		if (needcolon) {
			*p++ = ':';
			needcolon = false;
		}
		/* hex u16 without leading 0s */
		word = ntohs(in6.s6_addr16[i]);
		hi = word >> 8;
		lo = word & 0xff;
		if (hi) {
			if (hi > 0x0f)
				p = pack_hex_byte(p, hi);
			else
				*p++ = hex_asc_lo(hi);
			p = pack_hex_byte(p, lo);
		} else if (lo > 0x0f)
			p = pack_hex_byte(p, lo);
		else
			*p++ = hex_asc_lo(lo);
		needcolon = true;
	}

	if (useIPv4) {
		if (needcolon)
			*p++ = ':';
		p = ip4_string(p, &in6.s6_addr[12]);
	}
	*p = '\0';

	return p;
}

/**
 * ccs_print_ipv4 - Print an IPv4 address.
 *
 * @ip: Pointer to "u32 in network byte order".
 *
 * Returns nothing.
 */
static void ccs_print_ipv4(const u32 *ip)
{
	char addr[sizeof("255.255.255.255")];
	ip4_string(addr, (const u8 *) ip);
	cprint(addr);
}

/**
 * ccs_print_ipv6 - Print an IPv6 address.
 *
 * @ip: Pointer to "struct in6_addr".
 *
 * Returns nothing.
 */
static void ccs_print_ipv6(const struct in6_addr *ip)
{
	char addr[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];
	ip6_compressed_string(addr, (const u8 *) ip);
	cprintf(addr);
}

/***** SECTION5: Variables definition section *****/

static int client_fd;

/* List of namespaces. */
static LIST_HEAD(ccs_namespace_list);
/* True if namespace other than ccs_kernel_namespace is defined. */
static _Bool ccs_namespace_enabled;

/* Initial namespace.*/
static struct ccs_policy_namespace ccs_kernel_namespace;

static struct ccs_group ccs_group_any;

/* List of "struct ccs_condition". */
static LIST_HEAD(ccs_condition_list);

/* List of "struct ccs_manager". */
static LIST_HEAD(ccs_manager_list);

/***** SECTION6: Dependent functions section *****/

/**
 * ccs_memory_ok - Check memory quota.
 *
 * @ptr:  Pointer to allocated memory. Maybe NULL.
 * @size: Size in byte. Not used if @ptr is NULL.
 *
 * Returns true if @ptr is not NULL and quota not exceeded, false otherwise.
 *
 * Caller holds ccs_policy_lock mutex.
 */
static bool ccs_memory_ok(const void *ptr, const unsigned int size)
{
	return ptr != NULL;
}

/**
 * ccs_commit_ok - Allocate memory and check memory quota.
 *
 * @data: Data to copy from.
 * @size: Size in byte.
 *
 * Returns pointer to allocated memory on success, NULL otherwise.
 * @data is zero-cleared on success.
 *
 * Caller holds ccs_policy_lock mutex.
 */
static void *ccs_commit_ok(void *data, const unsigned int size)
{
	void *ptr = ccs_malloc(size);
	memmove(ptr, data, size);
	memset(data, 0, size);
	return ptr;
}

/**
 * ccs_print_ip - Print an IP address.
 *
 * @ptr: Pointer to "struct ipaddr_union".
 *
 * Returns nothing.
 */
static void ccs_print_ip(const struct ccs_ipaddr_union *ptr)
{
	if (ptr->is_ipv6)
		ccs_print_ipv6(&ptr->ip[0]);
	else
		ccs_print_ipv4(&ptr->ip[0].s6_addr32[0]);
	if (!memcmp(&ptr->ip[0], &ptr->ip[1], 16))
		return;
	cprint("-");
	if (ptr->is_ipv6)
		ccs_print_ipv6(&ptr->ip[1]);
	else
		ccs_print_ipv4(&ptr->ip[1].s6_addr32[0]);
}

/**
 * ccs_read_token - Read a word from a line.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns a word on success, "" otherwise.
 *
 * To allow the caller to skip NULL check, this function returns "" rather than
 * NULL if there is no more words to read.
 */
static char *ccs_read_token(struct ccs_acl_param *param)
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
 * ccs_get_group - Allocate memory for "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group".
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @idx:   Index number.
 *
 * Returns pointer to "struct ccs_group" on success, NULL otherwise.
 */
static struct ccs_group *ccs_get_group(struct ccs_acl_param *param,
				       const u8 idx)
{
	struct ccs_group e = { };
	struct ccs_group *group = NULL;
	struct list_head *list;
	const char *group_name = ccs_read_token(param);
	_Bool found = false;
	if (!strcmp(group_name, "any"))
		return &ccs_group_any;
	if (!ccs_correct_word(group_name) || idx >= CCS_MAX_GROUP)
		return NULL;
	e.group_name = ccs_savename(group_name);
	list = &param->ns->group_list[idx];
	list_for_each_entry(group, list, head.list) {
		if (e.group_name != group->group_name)
			continue;
		found = true;
		break;
	}
	if (!found) {
		struct ccs_group *entry = ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			INIT_LIST_HEAD(&entry->member_list);
			list_add_tail(&entry->head.list, list);
			group = entry;
			found = true;
		}
	}
	ccs_put_name(e.group_name);
	return found ? group : NULL;
}

/**
 * ccs_parse_name_union - Parse a ccs_name_union.
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @ptr:   Pointer to "struct ccs_name_union".
 *
 * Returns true on success, false otherwise.
 */
static _Bool ccs_parse_name_union(struct ccs_acl_param *param,
				 struct ccs_name_union *ptr)
{
	char *filename;
	switch (ccs_group_type(&param->data)) {
	case 2:
		ptr->is_not = true;
		/* fall through */
	case 1:
		ptr->group = ccs_get_group(param, CCS_PATH_GROUP);
		return ptr->group != NULL;
	}
	filename = ccs_read_token(param);
	if (!ccs_correct_word(filename))
		return false;
	ptr->filename = ccs_savename(filename);
	return true;
}

/**
 * ccs_parse_ulong - Parse an "unsigned long" value.
 *
 * @result: Pointer to "unsigned long".
 * @str:    Pointer to string to parse.
 *
 * Returns one of values in "enum ccs_value_type".
 *
 * The @src is updated to point the first character after the value
 * on success.
 */
static u8 ccs_parse_ulong(unsigned long *result, char **str)
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
		return CCS_VALUE_TYPE_INVALID;
	*str = ep;
	switch (base) {
	case 16:
		return CCS_VALUE_TYPE_HEXADECIMAL;
	case 8:
		return CCS_VALUE_TYPE_OCTAL;
	default:
		return CCS_VALUE_TYPE_DECIMAL;
	}
}

/**
 * ccs_parse_number_union - Parse a ccs_number_union.
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @ptr:   Pointer to "struct ccs_number_union".
 *
 * Returns true on success, false otherwise.
 */
static _Bool ccs_parse_number_union(struct ccs_acl_param *param,
				   struct ccs_number_union *ptr)
{
	char *data;
	u8 type;
	unsigned long v;
	memset(ptr, 0, sizeof(*ptr));
	switch (ccs_group_type(&param->data)) {
	case 2:
		ptr->is_not = true;
		/* fall through */
	case 1:
		ptr->group = ccs_get_group(param, CCS_NUMBER_GROUP);
		return ptr->group != NULL;
	}
	data = ccs_read_token(param);
	type = ccs_parse_ulong(&v, &data);
	if (type == CCS_VALUE_TYPE_INVALID)
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
	type = ccs_parse_ulong(&v, &data);
	if (type == CCS_VALUE_TYPE_INVALID || *data || ptr->values[0] > v)
		return false;
	ptr->values[1] = v;
	ptr->value_type[1] = type;
	return true;
}

/**
 * ccs_parse_ipaddr_union - Parse an IP address.
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @ptr:   Pointer to "struct ccs_ipaddr_union".
 *
 * Returns true on success, false otherwise.
 */
static _Bool ccs_parse_ipaddr_union(struct ccs_acl_param *param,
				   struct ccs_ipaddr_union *ptr)
{
	u8 * const min = ptr->ip[0].in6_u.u6_addr8;
	u8 * const max = ptr->ip[1].in6_u.u6_addr8;
	char *address;
	const char *end;
	switch (ccs_group_type(&param->data)) {
	case 2:
		ptr->is_not = true;
		/* fall through */
	case 1:
		ptr->group = ccs_get_group(param, CCS_ADDRESS_GROUP);
		return ptr->group != NULL;
	}
	address = ccs_read_token(param);
	if (!strchr(address, ':') &&
	    ccs_in4_pton(address, -1, min, '-', &end) > 0) {
		ptr->is_ipv6 = false;
		if (!*end)
			ptr->ip[1].s6_addr32[0] = ptr->ip[0].s6_addr32[0];
		else if (*end++ != '-' ||
			 ccs_in4_pton(end, -1, max, '\0', &end) <= 0 || *end)
			return false;
		return true;
	}
	if (ccs_in6_pton(address, -1, min, '-', &end) > 0) {
		ptr->is_ipv6 = true;
		if (!*end)
			memmove(max, min, sizeof(u16) * 8);
		else if (*end++ != '-' ||
			 ccs_in6_pton(end, -1, max, '\0', &end) <= 0 || *end)
			return false;
		return true;
	}
	return false;
}

/**
 * ccs_get_dqword - ccs_savename() for a quoted string.
 *
 * @start: String to save.
 *
 * Returns pointer to "struct ccs_path_info" on success, NULL otherwise.
 */
static const struct ccs_path_info *ccs_get_dqword(char *start)
{
	char *cp = start + strlen(start) - 1;
	if (cp == start || *start++ != '"' || *cp != '"')
		return NULL;
	*cp = '\0';
	if (*start && !ccs_correct_word(start))
		return NULL;
	return ccs_savename(start);
}

/**
 * ccs_parse_name_union_quoted - Parse a quoted word.
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @ptr:   Pointer to "struct ccs_name_union".
 *
 * Returns true on success, false otherwise.
 */
static _Bool ccs_parse_name_union_quoted(struct ccs_acl_param *param,
					struct ccs_name_union *ptr)
{
	char *filename = param->data;
	if (ccs_group_type(&filename))
		return ccs_parse_name_union(param, ptr);
	ptr->filename = ccs_get_dqword(filename);
	return ptr->filename != NULL;
}

/**
 * ccs_parse_argv - Parse an argv[] condition part.
 *
 * @left:  Lefthand value.
 * @right: Righthand value.
 * @argv:  Pointer to "struct ccs_argv".
 *
 * Returns true on success, false otherwise.
 */
static _Bool ccs_parse_argv(char *left, char *right, struct ccs_argv *argv)
{
	if (ccs_parse_ulong(&argv->index, &left) != CCS_VALUE_TYPE_DECIMAL ||
	    *left++ != ']' || *left)
		return false;
	argv->value = ccs_get_dqword(right);
	return argv->value != NULL;
}

/**
 * ccs_parse_envp - Parse an envp[] condition part.
 *
 * @left:  Lefthand value.
 * @right: Righthand value.
 * @envp:  Pointer to "struct ccs_envp".
 *
 * Returns true on success, false otherwise.
 */
static _Bool ccs_parse_envp(char *left, char *right, struct ccs_envp *envp)
{
	const struct ccs_path_info *name;
	const struct ccs_path_info *value;
	char *cp = left + strlen(left) - 1;
	if (*cp-- != ']' || *cp != '"')
		goto out;
	*cp = '\0';
	if (!ccs_correct_word(left))
		goto out;
	name = ccs_savename(left);
	if (!name)
		goto out;
	if (!strcmp(right, "NULL")) {
		value = NULL;
	} else {
		value = ccs_get_dqword(right);
		if (!value) {
			ccs_put_name(name);
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
 * ccs_same_condition - Check for duplicated "struct ccs_condition" entry.
 *
 * @a: Pointer to "struct ccs_condition".
 * @b: Pointer to "struct ccs_condition".
 *
 * Returns true if @a == @b, false otherwise.
 */
static _Bool ccs_same_condition(const struct ccs_condition *a,
			       const struct ccs_condition *b)
{
	return a->size == b->size && a->condc == b->condc &&
		a->numbers_count == b->numbers_count &&
		a->names_count == b->names_count &&
		a->argc == b->argc && a->envc == b->envc &&
		a->grant_log == b->grant_log &&
		!memcmp(a + 1, b + 1, a->size - sizeof(*a));
}

/**
 * ccs_condition_type - Get condition type.
 *
 * @word: Keyword string.
 *
 * Returns one of values in "enum ccs_conditions_index" on success,
 * CCS_MAX_CONDITION_KEYWORD otherwise.
 */
static u8 ccs_condition_type(const char *word)
{
	u8 i;
	for (i = 0; i < CCS_MAX_CONDITION_KEYWORD; i++) {
		if (!strcmp(word, ccs_condition_keyword[i]))
			break;
	}
	return i;
}

/**
 * ccs_commit_condition - Commit "struct ccs_condition".
 *
 * @entry: Pointer to "struct ccs_condition".
 *
 * Returns pointer to "struct ccs_condition" on success, NULL otherwise.
 *
 * This function merges duplicated entries. This function returns NULL if
 * @entry is not duplicated but memory quota for policy has exceeded.
 */
static struct ccs_condition *ccs_commit_condition(struct ccs_condition *entry)
{
	struct ccs_condition *ptr;
	_Bool found = false;
	list_for_each_entry(ptr, &ccs_condition_list, head.list) {
		if (!ccs_same_condition(ptr, entry))
			continue;
		/* Same entry found. Share this entry. */
		found = true;
		break;
	}
	if (!found) {
		if (ccs_memory_ok(entry, entry->size)) {
			list_add(&entry->head.list, &ccs_condition_list);
		} else {
			found = true;
			ptr = NULL;
		}
	}
	if (found) {
		free(entry);
		entry = ptr;
	}
	return entry;
}

/**
 * ccs_get_domainname - Read a domainname from a line.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns a domainname on success, NULL otherwise.
 */
static const struct ccs_path_info *ccs_get_domainname
(struct ccs_acl_param *param)
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
	if (ccs_correct_domain(start))
		return ccs_savename(start);
	return NULL;
}

/**
 * ccs_get_transit_preference - Parse domain transition preference for execve().
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @e:     Pointer to "struct ccs_condition".
 *
 * Returns the condition string part.
 */
static char *ccs_get_transit_preference(struct ccs_acl_param *param,
					struct ccs_execute_acl *e)
{
	char * const pos = param->data;
	_Bool flag;
	if (*pos == '<') {
		e->transit = ccs_get_domainname(param);
		goto done;
	}
	{
		char *cp = strchr(pos, ' ');
		if (cp)
			*cp = '\0';
		flag = ccs_correct_path(pos) || !strcmp(pos, "keep") ||
			!strcmp(pos, "child");
		if (cp)
			*cp = ' ';
	}
	if (!flag)
		return pos;
	e->transit = ccs_savename(ccs_read_token(param));
done:
	if (e->transit)
		return param->data;
	return NULL;
}

/**
 * ccs_get_condition - Parse condition part.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns pointer to "struct ccs_condition" on success, NULL otherwise.
 */
struct ccs_condition *ccs_get_condition(struct ccs_acl_param *param)
{
	struct ccs_condition *entry = NULL;
	struct ccs_condition_element *condp = NULL;
	struct ccs_number_union *numbers_p = NULL;
	struct ccs_name_union *names_p = NULL;
	struct ccs_argv *argv = NULL;
	struct ccs_envp *envp = NULL;
	struct ccs_condition e = { };
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
		_Bool is_not;
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
		if (!strcmp(left_word, "grant_log")) {
			if (entry) {
				if (is_not ||
				    entry->grant_log != CCS_GRANTLOG_AUTO)
					goto out;
				else if (!strcmp(right_word, "yes"))
					entry->grant_log = CCS_GRANTLOG_YES;
				else if (!strcmp(right_word, "no"))
					entry->grant_log = CCS_GRANTLOG_NO;
				else
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
				left = CCS_ARGV_ENTRY;
				argv->is_not = is_not;
				if (!ccs_parse_argv(left_word + 10,
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
				left = CCS_ENVP_ENTRY;
				envp->is_not = is_not;
				if (!ccs_parse_envp(left_word + 11,
						    right_word, envp++))
					goto out;
			}
			goto store_value;
		}
		left = ccs_condition_type(left_word);
		if (left == CCS_MAX_CONDITION_KEYWORD) {
			if (!numbers_p) {
				e.numbers_count++;
			} else {
				e.numbers_count--;
				left = CCS_NUMBER_UNION;
				param->data = left_word;
				if (ccs_group_type(&left_word) ||
				    !ccs_parse_number_union(param,
							    numbers_p++))
					goto out;
			}
		}
		if (!condp)
			e.condc++;
		else
			e.condc--;
		if (left == CCS_EXEC_REALPATH) {
			if (!names_p) {
				e.names_count++;
			} else {
				e.names_count--;
				right = CCS_NAME_UNION;
				param->data = right_word;
				if (!ccs_parse_name_union_quoted(param,
								 names_p++))
					goto out;
			}
			goto store_value;
		}
		right = ccs_condition_type(right_word);
		if (right == CCS_MAX_CONDITION_KEYWORD) {
			if (!numbers_p) {
				e.numbers_count++;
			} else {
				e.numbers_count--;
				right = CCS_NUMBER_UNION;
				param->data = right_word;
				if (!ccs_parse_number_union(param,
							    numbers_p++))
					goto out;
			}
		}
store_value:
		if (!condp)
			continue;
		condp->left = left;
		condp->right = right;
		condp->equals = !is_not;
		condp++;
	}
	if (entry)
		return ccs_commit_condition(entry);
	e.size = sizeof(*entry)
		+ e.condc * sizeof(struct ccs_condition_element)
		+ e.numbers_count * sizeof(struct ccs_number_union)
		+ e.names_count * sizeof(struct ccs_name_union)
		+ e.argc * sizeof(struct ccs_argv)
		+ e.envc * sizeof(struct ccs_envp);
	entry = ccs_malloc(e.size);
	*entry = e;
	condp = (struct ccs_condition_element *) (entry + 1);
	numbers_p = (struct ccs_number_union *) (condp + e.condc);
	names_p = (struct ccs_name_union *) (numbers_p + e.numbers_count);
	argv = (struct ccs_argv *) (names_p + e.names_count);
	envp = (struct ccs_envp *) (argv + e.argc);
	{
		_Bool flag = false;
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
	free(entry);
	return NULL;
}

/**
 * ccs_yesno - Return "yes" or "no".
 *
 * @value: _Bool value.
 *
 * Returns "yes" if @value is not 0, "no" otherwise.
 */
static const char *ccs_yesno(const unsigned int value)
{
	return value ? "yes" : "no";
}

/**
 * cprint - Print a string.
 *
 * @string: String to print.
 *
 * Returns nothing.
 */
static void cprint(const char *string)
{
	cprintf("%s", string);
}

/**
 * cprintf - printf() to editor process.
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
		buffer = ccs_realloc(buffer, buffer_len);
	}
	if (len && buffer_pos < 1048576)
		return;
	/*
	 * Reader might close connection without reading until EOF.
	 * In that case, we should not call _exit() because offline daemon does
	 * not call fork() for each accept()ed socket connection.
	 */
	if (write(client_fd, buffer, buffer_pos) != buffer_pos) {
		close(client_fd);
		client_fd = EOF;
	}
	buffer_pos = 0;
}

/**
 * ccs_set_space - Put a space.
 *
 * Returns nothing.
 */
static void ccs_set_space(void)
{
	cprint(" ");
}

/**
 * ccs_set_lf - Put a line feed.
 *
 * Returns nothing.
 */
static _Bool ccs_set_lf(void)
{
	cprint("\n");
	return true;
}

/**
 * ccs_set_slash - Put a shash.
 *
 * Returns nothing.
 */
static void ccs_set_slash(void)
{
	cprint("/");
}

/**
 * ccs_init_policy_namespace - Initialize namespace.
 *
 * @ns: Pointer to "struct ccs_policy_namespace".
 *
 * Returns nothing.
 */
static void ccs_init_policy_namespace(struct ccs_policy_namespace *ns)
{
	unsigned int idx;
	for (idx = 0; idx < CCS_MAX_GROUP; idx++)
		INIT_LIST_HEAD(&ns->group_list[idx]);
	INIT_LIST_HEAD(&ns->default_transition_list);
	ns->profile_version = 20100903;
	ccs_namespace_enabled = !list_empty(&ccs_namespace_list);
	list_add_tail(&ns->namespace_list, &ccs_namespace_list);
}

/**
 * ccs_print_namespace - Print namespace header.
 *
 * Returns nothing.
 */
static void ccs_print_namespace(void)
{
	if (!ccs_namespace_enabled)
		return;
	cprint(head.ns->name);
	ccs_set_space();
}

/**
 * ccs_assign_profile - Create a new profile.
 *
 * @ns:      Pointer to "struct ccs_policy_namespace".
 * @profile: Profile number to create.
 *
 * Returns pointer to "struct ccs_profile" on success, NULL otherwise.
 */
static struct ccs_profile *ccs_assign_profile(struct ccs_policy_namespace *ns,
					      const unsigned int profile)
{
	struct ccs_profile *ptr;
	if (profile >= CCS_MAX_PROFILES)
		return NULL;
	ptr = ns->profile_ptr[profile];
	if (ptr)
		return ptr;
	ptr = ccs_malloc(sizeof(*ptr));
	ptr->default_config =
		CCS_CONFIG_WANT_GRANT_LOG | CCS_CONFIG_WANT_REJECT_LOG;
	memset(ptr->config, CCS_CONFIG_USE_DEFAULT, sizeof(ptr->config));
	ptr->pref[CCS_PREF_MAX_AUDIT_LOG] = 2048;
	ns->profile_ptr[profile] = ptr;
	return ptr;
}

/**
 * ccs_find_yesno - Find values for specified keyword.
 *
 * @string: String to check.
 * @find:   Name of keyword.
 *
 * Returns 1 if "@find=yes" was found, 0 if "@find=no" was found, -1 otherwise.
 */
static s8 ccs_find_yesno(const char *string, const char *find)
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
 * ccs_set_uint - Set value for specified preference.
 *
 * @i:      Pointer to "unsigned int".
 * @string: String to check.
 * @find:   Name of keyword.
 *
 * Returns nothing.
 */
static void ccs_set_uint(unsigned int *i, const char *string, const char *find)
{
	const char *cp = strstr(string, find);
	if (cp)
		sscanf(cp + strlen(find), "=%u", i);
}

/**
 * ccs_str_starts2 - Check whether the given string starts with the given keyword.
 *
 * @src:  Pointer to pointer to the string.
 * @find: Pointer to the keyword.
 *
 * Returns true if @src starts with @find, false otherwise.
 *
 * The @src is updated to point the first character after the @find
 * if @src starts with @find.
 */
static _Bool ccs_str_starts2(char **src, const char *find)
{
	const int len = strlen(find);
	char *tmp = *src;
	if (strncmp(tmp, find, len))
		return false;
	tmp += len;
	*src = tmp;
	return true;
}

/**
 * ccs_group_type - Check whether the given string refers group or not.
 *
 * @src:  Pointer to pointer to the string.
 *
 * Returns 1 if @src refers a group in positive match, 2 if psrc refers a group
 * in negative match, 0 otherwise.
 *
 * The @src is updated to point the first character of a group name if @src
 * refers a group.
 */
static u8 ccs_group_type(char **src)
{
	if (ccs_str_starts2(src, "\\="))
		return 1;
	if (ccs_str_starts2(src, "\\!"))
		return 2;
	return 0;
}

/**
 * ccs_print_group - Print group's name.
 *
 * @is_not: True if @group is negative match, false otherwise.
 * @group:  Pointer to "struct ccsgroup". Maybe NULL.
 *
 * Returns true if @group is not NULL. false otherwise.
 */
static _Bool ccs_print_group(const _Bool is_not, const struct ccs_group *group)
{
	if (group) {
		cprint(is_not ? "\\!" : "\\=");
		cprint(group->group_name->name);
		return true;
	}
	return false;
}

/**
 * ccs_set_mode - Set mode for specified profile.
 *
 * @name:    Name of functionality.
 * @value:   Mode for @name.
 * @profile: Pointer to "struct ccs_profile".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_set_mode(char *name, const char *value,
			struct ccs_profile *profile)
{
	u8 i;
	u8 config;
	if (!strcmp(name, "CONFIG")) {
		i = CCS_MAX_MAC_INDEX + CCS_MAX_MAC_CATEGORY_INDEX;
		config = profile->default_config;
	} else if (ccs_str_starts2(&name, "CONFIG::")) {
		config = 0;
		for (i = 0; i < CCS_MAX_MAC_INDEX + CCS_MAX_MAC_CATEGORY_INDEX;
		     i++) {
			int len = 0;
			if (i < CCS_MAX_MAC_INDEX) {
				const u8 c = ccs_index2category[i];
				const char *category =
					ccs_category_keywords[c];
				len = strlen(category);
				if (strncmp(name, category, len) ||
				    name[len++] != ':' || name[len++] != ':')
					continue;
			}
			if (strcmp(name + len, ccs_mac_keywords[i]))
				continue;
			config = profile->config[i];
			break;
		}
		if (i == CCS_MAX_MAC_INDEX + CCS_MAX_MAC_CATEGORY_INDEX)
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	if (strstr(value, "use_default")) {
		config = CCS_CONFIG_USE_DEFAULT;
	} else {
		u8 mode;
		for (mode = 0; mode < CCS_CONFIG_MAX_MODE; mode++)
			if (strstr(value, ccs_mode[mode]))
				/*
				 * Update lower 3 bits in order to distinguish
				 * 'config' from 'CCS_CONFIG_USE_DEAFULT'.
				 */
				config = (config & ~7) | mode;
		if (config != CCS_CONFIG_USE_DEFAULT) {
			switch (ccs_find_yesno(value, "grant_log")) {
			case 1:
				config |= CCS_CONFIG_WANT_GRANT_LOG;
				break;
			case 0:
				config &= ~CCS_CONFIG_WANT_GRANT_LOG;
				break;
			}
			switch (ccs_find_yesno(value, "reject_log")) {
			case 1:
				config |= CCS_CONFIG_WANT_REJECT_LOG;
				break;
			case 0:
				config &= ~CCS_CONFIG_WANT_REJECT_LOG;
				break;
			}
		}
	}
	if (i < CCS_MAX_MAC_INDEX + CCS_MAX_MAC_CATEGORY_INDEX)
		profile->config[i] = config;
	else if (config != CCS_CONFIG_USE_DEFAULT)
		profile->default_config = config;
	return 0;
}

/**
 * ccs_write_profile - Write profile table.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_profile(void)
{
	char *data = head.write_buf;
	unsigned int i;
	char *cp;
	struct ccs_profile *profile;
	if (sscanf(data, "PROFILE_VERSION=%u", &head.ns->profile_version)
	    == 1)
		return 0;
	i = strtoul(data, &cp, 10);
	if (*cp != '-')
		return -EINVAL;
	data = cp + 1;
	profile = ccs_assign_profile(head.ns, i);
	if (!profile)
		return -EINVAL;
	cp = strchr(data, '=');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	if (!strcmp(data, "COMMENT")) {
		const struct ccs_path_info *new_comment = ccs_savename(cp);
		const struct ccs_path_info *old_comment;
		if (!new_comment)
			return -ENOMEM;
		old_comment = profile->comment;
		profile->comment = new_comment;
		ccs_put_name(old_comment);
		return 0;
	}
	if (!strcmp(data, "PREFERENCE")) {
		for (i = 0; i < CCS_MAX_PREF; i++)
			ccs_set_uint(&profile->pref[i], cp,
				     ccs_pref_keywords[i]);
		return 0;
	}
	return ccs_set_mode(data, cp, profile);
}

/**
 * ccs_print_config - Print mode for specified functionality.
 *
 * @config: Mode for that functionality.
 *
 * Returns nothing.
 *
 * Caller prints functionality's name.
 */
static void ccs_print_config(const u8 config)
{
	cprintf("={ mode=%s grant_log=%s reject_log=%s }\n",
		ccs_mode[config & 3],
		ccs_yesno(config & CCS_CONFIG_WANT_GRANT_LOG),
		ccs_yesno(config & CCS_CONFIG_WANT_REJECT_LOG));
}

/**
 * ccs_read_profile - Read profile table.
 *
 * Returns nothing.
 */
static void ccs_read_profile(void)
{
	list_for_each_entry(head.ns, &ccs_namespace_list, namespace_list) {
		u16 index;
		struct ccs_policy_namespace *ns = head.ns;
		ccs_print_namespace();
		cprintf("PROFILE_VERSION=%u\n", ns->profile_version);
		for (index = 0; index < CCS_MAX_PROFILES; index++) {
			u8 i;
			const struct ccs_path_info *comment;
			const struct ccs_profile *profile =
				ns->profile_ptr[index];
			if (!profile)
				continue;
			comment = profile->comment;
			ccs_print_namespace();
			cprintf("%u-COMMENT=", index);
			if (comment)
				cprint(comment->name);
			ccs_set_lf();
			ccs_print_namespace();
			cprintf("%u-PREFERENCE={ ", index);
			for (i = 0; i < CCS_MAX_PREF; i++)
				cprintf("%s=%u ", ccs_pref_keywords[i],
					profile->pref[i]);
			cprint("}\n");
			ccs_print_namespace();
			cprintf("%u-%s", index, "CONFIG");
			ccs_print_config(profile->default_config);
			for (i = 0; i < CCS_MAX_MAC_INDEX +
				     CCS_MAX_MAC_CATEGORY_INDEX; i++) {
				const u8 config = profile->config[i];
				if (config == CCS_CONFIG_USE_DEFAULT)
					continue;
				ccs_print_namespace();
				if (i < CCS_MAX_MAC_INDEX)
					cprintf("%u-CONFIG::%s::%s", index,
						ccs_category_keywords
						[ccs_index2category[i]],
						ccs_mac_keywords[i]);
				else
					cprintf("%u-CONFIG::%s", index,
						ccs_mac_keywords[i]);
				ccs_print_config(config);
			}
		}
	}
}

/**
 * ccs_update_policy - Update an entry for exception policy.
 *
 * @size:  Size of new entry in bytes.
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_update_policy(const int size, struct ccs_acl_param *param)
{
	struct ccs_acl_head *new_entry = &param->e.acl_head;
	int error = param->is_delete ? -ENOENT : -ENOMEM;
	struct ccs_acl_head *entry;
	struct list_head *list = param->list;
	list_for_each_entry(entry, list, list) {
		if (memcmp(entry + 1, new_entry + 1, size - sizeof(*entry)))
			continue;
		entry->is_deleted = param->is_delete;
		error = 0;
		break;
	}
	if (error && !param->is_delete) {
		entry = ccs_commit_ok(new_entry, size);
		if (entry) {
			list_add_tail(&entry->list, list);
			error = 0;
		}
	}
	return error;
}

/**
 * ccs_update_manager_entry - Add a manager entry.
 *
 * @manager:   The path to manager or the domainnamme.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_manager_entry(const char *manager,
				    const _Bool is_delete)
{
	struct ccs_acl_param param = {
		/* .ns = &ccs_kernel_namespace, */
		.is_delete = is_delete,
		.list = &ccs_manager_list,
	};
	struct ccs_manager *e = &param.e.manager;
	int error = is_delete ? -ENOENT : -ENOMEM;
	/* Forced zero clear for using memcmp() at ccs_update_policy(). */
	memset(&param.e, 0, sizeof(param.e));
	if (ccs_domain_def(manager)) {
		if (!ccs_correct_domain(manager))
			return -EINVAL;
		e->is_domain = true;
	} else {
		if (!ccs_correct_path(manager))
			return -EINVAL;
	}
	e->manager = ccs_savename(manager);
	if (e->manager) {
		error = ccs_update_policy(sizeof(*e), &param);
		ccs_put_name(e->manager);
	}
	return error;
}

/**
 * ccs_write_manager - Write manager policy.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_manager(void)
{
	const char *data = head.write_buf;
	return ccs_update_manager_entry(data, head.is_delete);
}

/**
 * ccs_read_manager - Read manager policy.
 *
 * Returns nothing.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_manager(void)
{
	struct ccs_manager *ptr;
	list_for_each_entry(ptr, &ccs_manager_list, head.list) {
		if (ptr->head.is_deleted)
			continue;
		cprint(ptr->manager->name);
		ccs_set_lf();
	}
}

/**
 * ccs_find_domain4 - Find a domain by the given name.
 *
 * @domainname: The domainname to find.
 *
 * Returns pointer to "struct ccs_domain_info4" if found, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static struct ccs_domain_info4 *ccs_find_domain4(const char *domainname)
{
	struct ccs_domain_info4 *domain;
	struct ccs_path_info name;
	name.name = domainname;
	ccs_fill_path_info(&name);
	list_for_each_entry(domain, &ccs_domain_list, list) {
		if (!domain->is_deleted &&
		    !ccs_pathcmp(&name, domain->domainname))
			return domain;
	}
	return NULL;
}

/**
 * ccs_select_domain - Parse select command.
 *
 * @data: String to parse.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static _Bool ccs_select_domain(const char *data)
{
	struct ccs_domain_info4 *domain = NULL;
	if (strncmp(data, "select ", 7))
		return false;
	data += 7;
	if (!strncmp(data, "domain=", 7)) {
		if (*(data + 7) == '<')
			domain = ccs_find_domain4(data + 7);
	} else
		return false;
	head.domain = domain;
	head.print_this_domain_only = true;
	return true;
}

/**
 * ccs_update_inverse_list - Update an entry for domain policy.
 *
 * @new_entry: Pointer to "struct ccs_acl_info".
 * @size:      Size of @new_entry in bytes.
 * @param:     Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_update_inverse_list(struct ccs_acl_info *new_entry,
				   const int size, struct ccs_acl_param *param)
{
	const _Bool is_delete = param->is_delete;
	struct ccs_acl_info *entry;
	list_for_each_entry(entry, &ccs_inversed_acl_list, list) {
		if (entry->perm != new_entry->perm ||
		    entry->type != new_entry->type ||
		    entry->cond != new_entry->cond ||
		    memcmp(entry + 1, new_entry + 1, size - sizeof(*entry)))
			continue;
		entry->is_deleted = is_delete;
		param->matched_entry = entry;
		return 0;
	}
	if (is_delete)
		return -ENOENT;
	entry = ccs_commit_ok(new_entry, size);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->domain_list);
	list_add_tail(&entry->list, &ccs_inversed_acl_list);
	param->matched_entry = entry;
	return 0;
}

/**
 * ccs_update_acl - Update "struct ccs_acl_info" entry.
 *
 * @size:  Size of new entry in bytes.
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_update_acl(const int size, struct ccs_acl_param *param)
{
	struct ccs_acl_info *new_entry = &param->e.acl_info;
	const _Bool is_delete = param->is_delete;
	int error = is_delete ? -ENOENT : -ENOMEM;
	struct ccs_acl_info *entry;
	struct list_head * const list = param->list;
	if (param->data[0]) {
		new_entry->cond = ccs_get_condition(param);
		if (!new_entry->cond)
			return -EINVAL;
	}
	if (!list)
		return ccs_update_inverse_list(new_entry, size, param);
	list_for_each_entry(entry, list, list) {
		if (entry->type != new_entry->type ||
		    entry->cond != new_entry->cond ||
		    memcmp(entry + 1, new_entry + 1, size - sizeof(*entry)))
			continue;
		if (is_delete)
			entry->perm &= ~new_entry->perm;
		else
			entry->perm |= new_entry->perm;
		entry->is_deleted = !entry->perm;
		error = 0;
		break;
	}
	if (error && !is_delete) {
		entry = ccs_commit_ok(new_entry, size);
		if (entry) {
			list_add_tail(&entry->list, list);
			error = 0;
		}
	}
	return error;
}

/**
 * ccs_permstr - Find permission keywords.
 *
 * @string: String representation for permissions in foo/bar/buz format.
 * @keyword: Keyword to find from @string/
 *
 * Returns ture if @keyword was found in @string, false otherwise.
 *
 * This function assumes that strncmp(w1, w2, strlen(w1)) != 0 if w1 != w2.
 */
static _Bool ccs_permstr(const char *string, const char *keyword)
{
	const char *cp = strstr(string, keyword);
	if (cp)
		return cp == string || *(cp - 1) == '/';
	return false;
}

/**
 * ccs_write_task - Update task related list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_task(struct ccs_acl_param *param)
{
	int error;
	const _Bool is_auto = ccs_str_starts2(&param->data,
					    "auto_domain_transition ");
	if (!is_auto && !ccs_str_starts2(&param->data,
					"manual_domain_transition ")) {
		struct ccs_handler_acl *e = &param->e.handler_acl;
		char *handler;
		if (ccs_str_starts2(&param->data, "auto_execute_handler "))
			e->head.type = CCS_TYPE_AUTO_EXECUTE_HANDLER;
		else if (ccs_str_starts2(&param->data,
					"denied_execute_handler "))
			e->head.type = CCS_TYPE_DENIED_EXECUTE_HANDLER;
		else
			return -EINVAL;
		handler = ccs_read_token(param);
		if (!ccs_correct_path(handler))
			return -EINVAL;
		e->handler = ccs_savename(handler);
		if (!e->handler)
			return -ENOMEM;
		if (e->handler->is_patterned)
			return -EINVAL; /* No patterns allowed. */
		return ccs_update_acl(sizeof(*e), param);
	} else {
		struct ccs_task_acl *e = &param->e.task_acl;
		e->head.type = is_auto ?
			CCS_TYPE_AUTO_TASK_ACL : CCS_TYPE_MANUAL_TASK_ACL;
		e->domainname = ccs_get_domainname(param);
		if (!e->domainname)
			return -EINVAL;
		return ccs_update_acl(sizeof(*e), param);
	}
	return error;
}

/**
 * ccs_write_inet_network - Write "struct ccs_inet_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_inet_network(struct ccs_acl_param *param)
{
	struct ccs_inet_acl *e = &param->e.inet_acl;
	u8 type;
	const char *protocol = ccs_read_token(param);
	const char *operation = ccs_read_token(param);
	e->head.type = CCS_TYPE_INET_ACL;
	for (type = 0; type < CCS_SOCK_MAX; type++)
		if (!strcmp(protocol, ccs_proto_keyword[type]))
			break;
	if (type == CCS_SOCK_MAX)
		return -EINVAL;
	e->protocol = type;
	e->head.perm = 0;
	for (type = 0; type < CCS_MAX_NETWORK_OPERATION; type++)
		if (ccs_permstr(operation, ccs_socket_keyword[type]))
			e->head.perm |= 1 << type;
	if (!e->head.perm)
		return -EINVAL;
	if (!ccs_parse_ipaddr_union(param, &e->address))
		return -EINVAL;
	if (!ccs_parse_number_union(param, &e->port) ||
	    e->port.values[1] > 65535)
		return -EINVAL;
	return ccs_update_acl(sizeof(*e), param);
}

/**
 * ccs_write_unix_network - Write "struct ccs_unix_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_unix_network(struct ccs_acl_param *param)
{
	struct ccs_unix_acl *e = &param->e.unix_acl;
	u8 type;
	const char *protocol = ccs_read_token(param);
	const char *operation = ccs_read_token(param);
	e->head.type = CCS_TYPE_UNIX_ACL;
	for (type = 0; type < CCS_SOCK_MAX; type++)
		if (!strcmp(protocol, ccs_proto_keyword[type]))
			break;
	if (type == CCS_SOCK_MAX)
		return -EINVAL;
	e->protocol = type;
	e->head.perm = 0;
	for (type = 0; type < CCS_MAX_NETWORK_OPERATION; type++)
		if (ccs_permstr(operation, ccs_socket_keyword[type]))
			e->head.perm |= 1 << type;
	if (!e->head.perm)
		return -EINVAL;
	if (!ccs_parse_name_union(param, &e->name))
		return -EINVAL;
	return ccs_update_acl(sizeof(*e), param);
}

/**
 * ccs_update_execute_acl - Update execute entry.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_update_execute_acl(struct ccs_acl_param *param)
{
	struct ccs_execute_acl *e = &param->e.execute_acl;
	e->head.type = CCS_TYPE_EXECUTE_ACL;
	e->head.perm = 1;
	if (!ccs_parse_name_union(param, &e->program))
		return -EINVAL;
	param->data = ccs_get_transit_preference(param, e);
	if (!param->data)
		return -EINVAL;
	return ccs_update_acl(sizeof(*e), param);
}

/**
 * ccs_write_file - Update file related list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_file(struct ccs_acl_param *param)
{
	u16 perm = 0;
	u8 type;
	const char *operation = ccs_read_token(param);
	if (ccs_permstr(operation, ccs_mac_keywords[CCS_MAC_FILE_EXECUTE]))
		return ccs_update_execute_acl(param);
	for (type = 0; type < CCS_MAX_PATH_OPERATION; type++)
		if (ccs_permstr(operation, ccs_mac_keywords[ccs_p2mac[type]]))
			perm |= 1 << type;
	if (perm) {
		struct ccs_path_acl *e = &param->e.path_acl;
		e->head.type = CCS_TYPE_PATH_ACL;
		e->head.perm = perm;
		if (!ccs_parse_name_union(param, &e->name))
			return -EINVAL;
		return ccs_update_acl(sizeof(*e), param);
	}
	for (type = 0; type < CCS_MAX_PATH2_OPERATION; type++)
		if (ccs_permstr(operation, ccs_mac_keywords[ccs_pp2mac[type]]))
			perm |= 1 << type;
	if (perm) {
		struct ccs_path2_acl *e = &param->e.path2_acl;
		e->head.type = CCS_TYPE_PATH2_ACL;
		e->head.perm = perm;
		if (!ccs_parse_name_union(param, &e->name1) ||
		    !ccs_parse_name_union(param, &e->name2))
			return -EINVAL;
		return ccs_update_acl(sizeof(*e), param);
	}
	for (type = 0; type < CCS_MAX_PATH_NUMBER_OPERATION; type++)
		if (ccs_permstr(operation, ccs_mac_keywords[ccs_pn2mac[type]]))
			perm |= 1 << type;
	if (perm) {
		struct ccs_path_number_acl *e = &param->e.path_number_acl;
		e->head.type = CCS_TYPE_PATH_NUMBER_ACL;
		e->head.perm = perm;
		if (!ccs_parse_name_union(param, &e->name) ||
		    !ccs_parse_number_union(param, &e->number))
			return -EINVAL;
		return ccs_update_acl(sizeof(*e), param);
	}
	for (type = 0; type < CCS_MAX_MKDEV_OPERATION; type++)
		if (ccs_permstr(operation,
				ccs_mac_keywords[ccs_pnnn2mac[type]]))
			perm |= 1 << type;
	if (perm) {
		struct ccs_mkdev_acl *e = &param->e.mkdev_acl;
		e->head.type = CCS_TYPE_MKDEV_ACL;
		e->head.perm = perm;
		if (!ccs_parse_name_union(param, &e->name) ||
		    !ccs_parse_number_union(param, &e->mode) ||
		    !ccs_parse_number_union(param, &e->major) ||
		    !ccs_parse_number_union(param, &e->minor))
			return -EINVAL;
		return ccs_update_acl(sizeof(*e), param);
	}
	if (ccs_permstr(operation, ccs_mac_keywords[CCS_MAC_FILE_MOUNT])) {
		struct ccs_mount_acl *e = &param->e.mount_acl;
		e->head.type = CCS_TYPE_MOUNT_ACL;
		if (!ccs_parse_name_union(param, &e->dev_name) ||
		    !ccs_parse_name_union(param, &e->dir_name) ||
		    !ccs_parse_name_union(param, &e->fs_type) ||
		    !ccs_parse_number_union(param, &e->flags))
			return -EINVAL;
		return ccs_update_acl(sizeof(*e), param);
	}
	return -EINVAL;
}

/**
 * ccs_write_misc - Update environment variable list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_misc(struct ccs_acl_param *param)
{
	if (ccs_str_starts2(&param->data, "env ")) {
		struct ccs_env_acl *e = &param->e.env_acl;
		e->head.type = CCS_TYPE_ENV_ACL;
		if (!ccs_parse_name_union(param, &e->env))
			return -EINVAL;
		return ccs_update_acl(sizeof(*e), param);
	}
	return -EINVAL;
}

/**
 * ccs_write_ipc - Update "struct ccs_ptrace_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_ipc(struct ccs_acl_param *param)
{
	struct ccs_ptrace_acl *e = &param->e.ptrace_acl;
	e->head.type = CCS_TYPE_PTRACE_ACL;
	if (!ccs_parse_number_union(param, &e->request))
		return -EINVAL;
	e->domainname = ccs_get_domainname(param);
	if (!e->domainname)
		return -EINVAL;
	return ccs_update_acl(sizeof(*e), param);
}

/**
 * ccs_write_capability - Write "struct ccs_capability_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_capability(struct ccs_acl_param *param)
{
	struct ccs_capability_acl *e = &param->e.capability_acl;
	const char *operation = ccs_read_token(param);
	u8 type;
	e->head.type = CCS_TYPE_CAPABILITY_ACL;
	for (type = 0; type < CCS_MAX_CAPABILITY_INDEX; type++) {
		if (strcmp(operation, ccs_mac_keywords[ccs_c2mac[type]]))
			continue;
		e->operation = type;
		return ccs_update_acl(sizeof(*e), param);
	}
	return -EINVAL;
}

/**
 * ccs_write_use_group_acl - Write "struct ccs_use_group_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_use_group_acl(struct ccs_acl_param *param)
{
	struct ccs_use_group_acl *e = &param->e.use_group_acl;
	e->head.type = CCS_TYPE_USE_GROUP_ACL;
	switch (ccs_group_type(&param->data)) {
	case 2:
		e->is_not = true;
		/* fall through */
	case 1:
		e->group = ccs_get_group(param, CCS_ACL_GROUP);
		if (e->group)
			return ccs_update_acl(sizeof(*e), param);
	}
	return -EINVAL;
}

/**
 * ccs_write_acl - Write "struct ccs_acl_info" list.
 *
 * @ns:        Pointer to "struct ccs_policy_namespace".
 * @list:      Pointer to "struct list_head".
 * @data:      Policy to be interpreted.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_acl(struct ccs_policy_namespace *ns,
			 struct list_head *list, char *data,
			 const _Bool is_delete)
{
	struct ccs_acl_param param = {
		.ns = ns,
		.list = list,
		.data = data,
		.is_delete = is_delete,
	};
	static const struct {
		const char *keyword;
		int (*write) (struct ccs_acl_param *);
	} ccs_callback[] = {
		{ "file ", ccs_write_file },
		{ "network inet ", ccs_write_inet_network },
		{ "network unix ", ccs_write_unix_network },
		{ "misc ", ccs_write_misc },
		{ "capability ", ccs_write_capability },
		{ "ipc ptrace ", ccs_write_ipc },
		{ "task ", ccs_write_task },
		{ "use_group ", ccs_write_use_group_acl },
	};
	u8 i;
	/* Forced zero clear for using memcmp() at ccs_update_acl(). */
	memset(&param.e, 0, sizeof(param.e));
	param.e.acl_info.perm = 1;
	for (i = 0; i < ARRAY_SIZE(ccs_callback); i++) {
		if (!ccs_str_starts2(&param.data, ccs_callback[i].keyword))
			continue;
		return ccs_callback[i].write(&param);
	}
	return -EINVAL;
}

/**
 * ccs_delete_domain4 - Delete a domain.
 *
 * @domainname: The name of domain.
 *
 * Returns nothing.
 */
static void ccs_delete_domain4(char *domainname)
{
	struct ccs_domain_info4 *domain;
	struct ccs_path_info name;
	name.name = domainname;
	ccs_fill_path_info(&name);
	/* Is there an active domain? */
	list_for_each_entry(domain, &ccs_domain_list, list) {
		/* Never delete ccs_kernel_domain. */
		if (domain == &ccs_kernel_domain)
			continue;
		if (domain->is_deleted ||
		    ccs_pathcmp(domain->domainname, &name))
			continue;
		domain->is_deleted = true;
		break;
	}
}

/**
 * ccs_write_domain - Write domain policy.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_write_domain(void)
{
	char *data = head.write_buf;
	struct ccs_policy_namespace *ns;
	struct ccs_domain_info4 *domain = head.domain;
	const _Bool is_delete = head.is_delete;
	const _Bool is_select = !is_delete &&
		ccs_str_starts2(&data, "select ");
	unsigned int profile;
	if (*data == '<') {
		domain = NULL;
		if (is_delete)
			ccs_delete_domain4(data);
		else if (is_select)
			domain = ccs_find_domain4(data);
		else
			domain = ccs_assign_domain4(data);
		head.domain = domain;
		return 0;
	}
	if (!domain)
		return -EINVAL;
	ns = domain->ns;
	if (sscanf(data, "use_profile %u\n", &profile) == 1
	    && profile < CCS_MAX_PROFILES) {
		if (ns->profile_ptr[(u8) profile])
			if (!is_delete)
				domain->profile = (u8) profile;
		return 0;
	}
	if (ccs_str_starts2(&data, "default_transition ")) {
		const struct ccs_path_info *new_transition = NULL;
		const struct ccs_path_info *old_transition;
		if (is_delete)
			return 0;
		if (ccs_correct_domain(data) || ccs_correct_path(data) ||
		    !strcmp(data, "keep") || !strcmp(data, "child"))
			new_transition = ccs_savename(data);
		if (!new_transition)
			return -EINVAL;
		old_transition = domain->default_transition;
		domain->default_transition = new_transition;
		ccs_put_name(old_transition);
		return 0;
	}
	if (!strncmp(data, CCS_QUOTA_EXCEEDED,
		     sizeof(CCS_QUOTA_EXCEEDED) - 2)) {
		domain->quota_exceeded = !is_delete;
		return 0;
	}
	return ccs_write_acl(ns, &domain->acl_info_list, data, is_delete);
}

/**
 * ccs_print_name_union - Print a ccs_name_union.
 *
 * @ptr: Pointer to "struct ccs_name_union".
 *
 * Returns nothing.
 */
static void ccs_print_name_union(const struct ccs_name_union *ptr)
{
	ccs_set_space();
	if (!ccs_print_group(ptr->is_not, ptr->group))
		cprint(ptr->filename->name);
}

/**
 * ccs_print_name_union_quoted - Print a ccs_name_union with a quote.
 *
 * @ptr:  Pointer to "struct ccs_name_union".
 *
 * Returns nothing.
 */
static void ccs_print_name_union_quoted(const struct ccs_name_union *ptr)
{
	if (!ccs_print_group(ptr->is_not, ptr->group)) {
		cprint("\"");
		cprint(ptr->filename->name);
		cprint("\"");
	}
}

/**
 * ccs_print_number_union_nospace - Print a ccs_number_union without a space.
 *
 * @ptr: Pointer to "struct ccs_number_union".
 *
 * Returns nothing.
 */
static void ccs_print_number_union_nospace(const struct ccs_number_union *ptr)
{
	if (!ccs_print_group(ptr->is_not, ptr->group)) {
		int i;
		unsigned long min = ptr->values[0];
		const unsigned long max = ptr->values[1];
		u8 min_type = ptr->value_type[0];
		const u8 max_type = ptr->value_type[1];
		for (i = 0; i < 2; i++) {
			switch (min_type) {
			case CCS_VALUE_TYPE_HEXADECIMAL:
				cprintf("0x%lX", min);
				break;
			case CCS_VALUE_TYPE_OCTAL:
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
 * ccs_print_number_union - Print a ccs_number_union.
 *
 * @ptr:  Pointer to "struct ccs_number_union".
 *
 * Returns nothing.
 */
static void ccs_print_number_union(const struct ccs_number_union *ptr)
{
	ccs_set_space();
	ccs_print_number_union_nospace(ptr);
}

/**
 * ccs_print_condition - Print condition part.
 *
 * @cond: Pointer to "struct ccs_condition".
 *
 * Returns nothing.
 */
static void ccs_print_condition(const struct ccs_condition *cond)
{
	u16 i;
	const u16 condc = cond->condc;
	const struct ccs_condition_element *condp = (typeof(condp)) (cond + 1);
	const struct ccs_number_union *numbers_p =
		(typeof(numbers_p)) (condp + condc);
	const struct ccs_name_union *names_p =
		(typeof(names_p)) (numbers_p + cond->numbers_count);
	const struct ccs_argv *argv =
		(typeof(argv)) (names_p + cond->names_count);
	const struct ccs_envp *envp = (typeof(envp)) (argv + cond->argc);
	for (i = 0; i < condc; i++) {
		const u8 match = condp->equals;
		const u8 left = condp->left;
		const u8 right = condp->right;
		condp++;
		ccs_set_space();
		switch (left) {
		case CCS_ARGV_ENTRY:
			cprintf("exec.argv[%lu]%s=\"%s\"", argv->index,
				argv->is_not ? "!" : "", argv->value->name);
			argv++;
			continue;
		case CCS_ENVP_ENTRY:
			cprintf("exec.envp[\"%s\"]%s=", envp->name->name,
				envp->is_not ? "!" : "");
			if (envp->value)
				cprintf("\"%s\"", envp->value->name);
			else
				cprint("NULL");
			envp++;
			continue;
		case CCS_NUMBER_UNION:
			ccs_print_number_union_nospace(numbers_p++);
			break;
		default:
			cprint(ccs_condition_keyword[left]);
			break;
		}
		cprint(match ? "=" : "!=");
		switch (right) {
		case CCS_NAME_UNION:
			ccs_print_name_union_quoted(names_p++);
			break;
		case CCS_NUMBER_UNION:
			ccs_print_number_union_nospace(numbers_p++);
			break;
		default:
			cprint(ccs_condition_keyword[right]);
			break;
		}
	}
	if (cond->grant_log != CCS_GRANTLOG_AUTO)
		cprintf(" grant_log=%s", ccs_yesno(cond->grant_log ==
						   CCS_GRANTLOG_YES));
}

/**
 * ccs_set_group - Print "acl_group " header keyword and category name.
 *
 * @category: Category name.
 *
 * Returns nothing.
 */
static void ccs_set_group(const char *category)
{
	if (head.type == CCS_EXCEPTION_POLICY) {
		ccs_print_namespace();
		cprint("acl_group ");
		cprint(head.acl_group_name->name);
		ccs_set_space();
	} else if (head.type == CCS_ACL_POLICY) {
		cprint("allow ");
	}
	cprint(category);
}

/**
 * ccs_print_entry - Print an ACL entry.
 *
 * @acl: Pointer to an ACL entry.
 *
 * Returns nothing.
 */
static void ccs_print_entry(const struct ccs_acl_info *acl)
{
	const u8 acl_type = acl->type;
	_Bool first = true;
	u8 bit;
	if (acl->is_deleted)
		return;
	else if (acl_type == CCS_TYPE_EXECUTE_ACL) {
		struct ccs_execute_acl *ptr
			= container_of(acl, typeof(*ptr), head);
		if (head.print_default_transition) {
			ccs_print_namespace();
			cprint("default_transition");
		} else {
			ccs_set_group("file ");
			cprint("execute");
		}
		ccs_print_name_union(&ptr->program);
		if (ptr->transit) {
			ccs_set_space();
			cprint(ptr->transit->name);
		}
	} else if (acl_type == CCS_TYPE_AUTO_EXECUTE_HANDLER ||
		   acl_type == CCS_TYPE_DENIED_EXECUTE_HANDLER) {
		struct ccs_handler_acl *ptr
			= container_of(acl, typeof(*ptr), head);
		ccs_set_group("task ");
		cprint(acl_type == CCS_TYPE_AUTO_EXECUTE_HANDLER
			       ? "auto_execute_handler " :
			       "denied_execute_handler ");
		cprint(ptr->handler->name);
		if (ptr->transit) {
			ccs_set_space();
			cprint(ptr->transit->name);
		}
	} else if (acl_type == CCS_TYPE_AUTO_TASK_ACL ||
		   acl_type == CCS_TYPE_MANUAL_TASK_ACL) {
		struct ccs_task_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group("task ");
		cprint(acl_type == CCS_TYPE_AUTO_TASK_ACL ?
			       "auto_domain_transition " :
			       "manual_domain_transition ");
		cprint(ptr->domainname->name);
	} else if (acl_type == CCS_TYPE_USE_GROUP_ACL) {
		struct ccs_use_group_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group("use_group ");
		ccs_print_group(ptr->is_not, ptr->group);
	} else if (head.print_transition_related_only) {
		return;
	} else if (acl_type == CCS_TYPE_PATH_ACL) {
		struct ccs_path_acl *ptr
			= container_of(acl, typeof(*ptr), head);
		for (bit = 0; bit < CCS_MAX_PATH_OPERATION; bit++) {
			if (!(acl->perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group("file ");
				first = false;
			} else {
				ccs_set_slash();
			}
			cprint(ccs_mac_keywords[ccs_p2mac[bit]]);
		}
		if (first)
			return;
		ccs_print_name_union(&ptr->name);
	} else if (acl_type == CCS_TYPE_MKDEV_ACL) {
		struct ccs_mkdev_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		for (bit = 0; bit < CCS_MAX_MKDEV_OPERATION; bit++) {
			if (!(acl->perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group("file ");
				first = false;
			} else {
				ccs_set_slash();
			}
			cprint(ccs_mac_keywords
				       [ccs_pnnn2mac[bit]]);
		}
		if (first)
			return;
		ccs_print_name_union(&ptr->name);
		ccs_print_number_union(&ptr->mode);
		ccs_print_number_union(&ptr->major);
		ccs_print_number_union(&ptr->minor);
	} else if (acl_type == CCS_TYPE_PATH2_ACL) {
		struct ccs_path2_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		for (bit = 0; bit < CCS_MAX_PATH2_OPERATION; bit++) {
			if (!(acl->perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group("file ");
				first = false;
			} else {
				ccs_set_slash();
			}
			cprint(ccs_mac_keywords
				       [ccs_pp2mac[bit]]);
		}
		if (first)
			return;
		ccs_print_name_union(&ptr->name1);
		ccs_print_name_union(&ptr->name2);
	} else if (acl_type == CCS_TYPE_PATH_NUMBER_ACL) {
		struct ccs_path_number_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		for (bit = 0; bit < CCS_MAX_PATH_NUMBER_OPERATION; bit++) {
			if (!(acl->perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group("file ");
				first = false;
			} else {
				ccs_set_slash();
			}
			cprint(ccs_mac_keywords
				       [ccs_pn2mac[bit]]);
		}
		if (first)
			return;
		ccs_print_name_union(&ptr->name);
		ccs_print_number_union(&ptr->number);
	} else if (acl_type == CCS_TYPE_ENV_ACL) {
		struct ccs_env_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group("misc env");
		ccs_print_name_union(&ptr->env);
	} else if (acl_type == CCS_TYPE_CAPABILITY_ACL) {
		struct ccs_capability_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group("capability ");
		cprint(ccs_mac_keywords
			       [ccs_c2mac[ptr->operation]]);
	} else if (acl_type == CCS_TYPE_INET_ACL) {
		struct ccs_inet_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		for (bit = 0; bit < CCS_MAX_NETWORK_OPERATION; bit++) {
			if (!(acl->perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group("network inet ");
				cprint(ccs_proto_keyword
					       [ptr->protocol]);
				ccs_set_space();
				first = false;
			} else {
				ccs_set_slash();
			}
			cprint(ccs_socket_keyword[bit]);
		}
		if (first)
			return;
		ccs_set_space();
		if (!ccs_print_group(ptr->address.is_not,
				     ptr->address.group))
			ccs_print_ip(&ptr->address);
		ccs_print_number_union(&ptr->port);
	} else if (acl_type == CCS_TYPE_UNIX_ACL) {
		struct ccs_unix_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		for (bit = 0; bit < CCS_MAX_NETWORK_OPERATION; bit++) {
			if (!(acl->perm & (1 << bit)))
				continue;
			if (first) {
				ccs_set_group("network unix ");
				cprint(ccs_proto_keyword[ptr->protocol]);
				ccs_set_space();
				first = false;
			} else {
				ccs_set_slash();
			}
			cprint(ccs_socket_keyword[bit]);
		}
		if (first)
			return;
		ccs_print_name_union(&ptr->name);
	} else if (acl_type == CCS_TYPE_PTRACE_ACL) {
		struct ccs_ptrace_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group("ipc ptrace ");
		ccs_print_number_union_nospace(&ptr->request);
		ccs_set_space();
		cprint(ptr->domainname->name);
	} else if (acl_type == CCS_TYPE_MOUNT_ACL) {
		struct ccs_mount_acl *ptr =
			container_of(acl, typeof(*ptr), head);
		ccs_set_group("file mount");
		ccs_print_name_union(&ptr->dev_name);
		ccs_print_name_union(&ptr->dir_name);
		ccs_print_name_union(&ptr->fs_type);
		ccs_print_number_union(&ptr->flags);
	}
	if (acl->cond)
		ccs_print_condition(acl->cond);
	ccs_set_lf();
}

/**
 * ccs_read_acl - Read "struct ccs_acl_info" list.
 *
 * @list: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_acl(struct list_head *list)
{
	struct ccs_acl_info *ptr;
	list_for_each_entry(ptr, list, list) {
		ccs_print_entry(ptr);
	}
}

/**
 * ccs_read_domain - Read domain policy.
 *
 * Returns nothing.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_domain(void)
{
	struct ccs_domain_info4 *domain;
	list_for_each_entry(domain, &ccs_domain_list, list) {
		if (domain->is_deleted &&
		    !head.print_this_domain_only)
			continue;
		/* Print domainname and flags. */
		cprint(domain->domainname->name);
		ccs_set_lf();
		cprintf("use_profile %u\n", domain->profile);
		cprintf("default_transition %s\n",
			domain->default_transition->name);
		if (domain->quota_exceeded)
			cprint(CCS_QUOTA_EXCEEDED);
		cprint("\n");
		ccs_read_acl(&domain->acl_info_list);
		ccs_set_lf();
		if (head.print_this_domain_only)
			break;
	}
}

/**
 * ccs_write_group - Write "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 * @type:  Type of this group.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_group(struct ccs_acl_param *param, const u8 type)
{
	int error = -EINVAL;
	struct ccs_group *group = ccs_get_group(param, type);
	if (!group || group == &ccs_group_any)
		return -ENOMEM;
	if (type != CCS_ACL_GROUP && ccs_group_type(&param->data))
		goto out;
	param->list = &group->member_list;
	if (type == CCS_PATH_GROUP) {
		struct ccs_path_group *e = &param->e.path_group;
		e->member_name = ccs_savename(ccs_read_token(param));
		if (!e->member_name) {
			error = -ENOMEM;
			goto out;
		}
		error = ccs_update_policy(sizeof(*e), param);
		ccs_put_name(e->member_name);
	} else if (type == CCS_NUMBER_GROUP) {
		struct ccs_number_group *e = &param->e.number_group;
		if (ccs_parse_number_union(param, &e->number))
			error = ccs_update_policy(sizeof(*e), param);
	} else if (type == CCS_ACL_GROUP) {
		error = ccs_write_acl(param->ns, param->list, param->data,
				      param->is_delete);
	} else {
		struct ccs_address_group *e = &param->e.address_group;
		if (ccs_parse_ipaddr_union(param, &e->address))
			error = ccs_update_policy(sizeof(*e), param);
	}
out:
	ccs_put_group(group);
	return error;
}

/**
 * ccs_write_transition_control - Write default domain transition rules.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_transition_control(struct ccs_acl_param *param)
{
	param->list = &param->ns->default_transition_list;
	return ccs_update_execute_acl(param);
}

/**
 * ccs_update_domain_in_acl - Update "struct ccs_domain_info4" in "struct ccs_acl_info".
 *
 * @acl:   Pointer to "struct ccs_acl_info".
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_domain_in_acl(struct ccs_acl_info *acl,
				    struct ccs_acl_param *param)
{
	struct ccs_domain_info4 *ptr;
	struct ccs_domain_info4 domain = { };
	int error = param->is_delete ? -ENOENT : -ENOMEM;
	domain.domainname = ccs_get_domainname(param);
	if (!domain.domainname)
		return error;
	if (param->data[0]) {
		domain.cond = ccs_get_condition(param);
		if (!domain.cond)
			goto out;
	}
	list_for_each_entry(ptr, &acl->domain_list, list) {
		if (ptr->cond != domain.cond ||
		    ptr->domainname != domain.domainname)
			continue;
		ptr->is_deleted = param->is_delete;
		error = 0;
		break;
	}
	if (!param->is_delete && error) {
		struct ccs_domain_info4 *entry =
			ccs_commit_ok(&domain, sizeof(domain));
		if (entry) {
			INIT_LIST_HEAD(&entry->acl_info_list);
			list_add_tail(&entry->list, &acl->domain_list);
			error = 0;
		}
	}
 out:
	ccs_put_name(domain.domainname);
	ccs_put_condition(domain.cond);
	return error;
}

/**
 * ccs_write_acl_policy - Write inverse mode policy.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_acl_policy(void)
{
	static const struct {
		const char *keyword;
		int (*write) (struct ccs_acl_param *);
	} ccs_callback[] = {
		{ "file ", ccs_write_file },
		{ "network inet ", ccs_write_inet_network },
		{ "network unix ", ccs_write_unix_network },
		{ "misc ", ccs_write_misc },
		{ "capability ", ccs_write_capability },
		{ "ipc ptrace ", ccs_write_ipc },
	};
	struct ccs_acl_param param = {
		.data = head.write_buf,
		.is_delete = head.is_delete,
		.e.acl_info.perm = 1,
	};
	u8 i;
	if (ccs_str_starts2(&param.data, "by ")) {
		if (!head.acl)
			return -EINVAL;
		return ccs_update_domain_in_acl(head.acl, &param);
	}
	if (ccs_str_starts2(&param.data, "mode ")) {
		u8 mode;
		if (!head.acl)
			return -EINVAL;
		for (mode = 0; mode < CCS_CONFIG_MAX_MODE; mode++)
			if (!strcmp(param.data, ccs_mode[mode])) {
				head.acl->mode = mode;
				return 0;
			}
		return -EINVAL;
	}
	head.acl = NULL;
	if (!ccs_str_starts2(&param.data, "allow "))
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(ccs_callback); i++) {
		int error;
		if (!ccs_str_starts2(&param.data, ccs_callback[i].keyword))
			continue;
		error = ccs_callback[i].write(&param);
		if (!error && !head.is_delete)
			head.acl = param.matched_entry;
		return error;
	}
	return -EINVAL;
}

/**
 * ccs_write_exception - Write exception policy.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_exception(void)
{
	const _Bool is_delete = head.is_delete;
	struct ccs_acl_param param = {
		.ns = head.ns,
		.is_delete = is_delete,
		.data = head.write_buf,
	};
	u8 i;
	/* Forced zero clear for using memcmp() at ccs_update_policy(). */
	memset(&param.e, 0, sizeof(param.e));
	param.e.acl_info.perm = 1;
	if (ccs_str_starts2(&param.data, "default_transition "))
		return ccs_write_transition_control(&param);
	for (i = 0; i < CCS_MAX_GROUP; i++)
		if (ccs_str_starts2(&param.data, ccs_group_name[i]))
			return ccs_write_group(&param, i);
	return -EINVAL;
}

/**
 * ccs_read_group - Read "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group" list.
 *
 * @idx: Index number.
 *
 * Returns nothing.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_group(const int idx)
{
	struct ccs_policy_namespace *ns = head.ns;
	struct ccs_group *group;
	if (idx == CCS_ACL_GROUP) {
		list_for_each_entry(group, &ccs_inversed_acl_list, head.list) {
			head.acl_group_name = group->group_name;
			ccs_read_acl(&group->member_list);
		}
		head.acl_group_name = NULL;
		return;
	}
	list_for_each_entry(group, &ns->group_list[idx], head.list) {
		struct ccs_acl_head *ptr;
		list_for_each_entry(ptr, &group->member_list, list) {
			if (ptr->is_deleted)
				continue;
			ccs_print_namespace();
			cprint(ccs_group_name[idx]);
			cprint(group->group_name->name);
			if (idx == CCS_PATH_GROUP) {
				ccs_set_space();
				cprint(container_of
				       (ptr, struct ccs_path_group,
					head)->member_name->name);
			} else if (idx == CCS_NUMBER_GROUP) {
				ccs_print_number_union(&container_of
					       (ptr, struct ccs_number_group,
						head)->number);
			} else if (idx == CCS_ADDRESS_GROUP) {
				struct ccs_address_group *member =
					container_of(ptr, typeof(*member),
							     head);
				cprint(" ");
				ccs_print_ip(&member->address);
			}
			ccs_set_lf();
		}
	}
}

/**
 * ccs_read_exception - Read exception policy.
 *
 * Returns nothing.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_exception(void)
{
	list_for_each_entry(head.ns, &ccs_namespace_list, namespace_list) {
		u8 i;
		for (i = 0; i < CCS_MAX_GROUP; i++)
			ccs_read_group(i);
		head.print_default_transition = true;
		ccs_read_acl(&head.ns->default_transition_list);
		head.print_default_transition = false;
	}
}

/**
 * ccs_read_stat - Read statistic data.
 *
 * Returns nothing.
 */
static void ccs_read_stat(void)
{
	u8 i;
	unsigned int total = 0;
	for (i = 0; i < CCS_MAX_MEMORY_STAT; i++) {
		unsigned int used = ccs_memory_used[i];
		total += used;
		cprintf("Memory used by %-22s %10u",
			ccs_memory_headers[i], used);
		used = ccs_memory_quota[i];
		if (used)
			cprintf(" (Quota: %10u)", used);
		ccs_set_lf();
	}
	cprintf("Total memory used:                    %10u\n", total);
}

/**
 * ccs_write_stat - Set memory quota.
 *
 * Returns 0.
 */
static int ccs_write_stat(void)
{
	char *data = head.write_buf;
	u8 i;
	if (ccs_str_starts2(&data, "Memory used by "))
		for (i = 0; i < CCS_MAX_MEMORY_STAT; i++)
			if (ccs_str_starts2(&data, ccs_memory_headers[i])) {
				if (*data == ' ')
					data++;
				ccs_memory_quota[i] = strtoul(data, NULL, 10);
			}
	return 0;
}

/**
 * ccs_find_namespace - Find specified namespace.
 *
 * @name: Name of namespace to find.
 * @len:  Length of @name.
 *
 * Returns pointer to "struct ccs_policy_namespace" if found, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static struct ccs_policy_namespace *ccs_find_namespace(const char *name,
						       const unsigned int len)
{
	struct ccs_policy_namespace *ns;
	list_for_each_entry(ns, &ccs_namespace_list, namespace_list) {
		if (strncmp(name, ns->name, len) ||
		    (name[len] && name[len] != ' '))
			continue;
		return ns;
	}
	return NULL;
}

/**
 * ccs_assign_namespace - Create a new namespace.
 *
 * @domainname: Name of namespace to create.
 *
 * Returns pointer to "struct ccs_policy_namespace" on success, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static struct ccs_policy_namespace *ccs_assign_namespace
(const char *domainname)
{
	struct ccs_policy_namespace *ptr;
	const char *cp = domainname;
	unsigned int len = 0;
	while (*cp && *cp++ != ' ')
		len++;
	ptr = ccs_find_namespace(domainname, len);
	if (ptr)
		return ptr;
	if (len >= 4096 - 10 || !ccs_domain_def(domainname))
		return NULL;
	ptr = ccs_malloc(sizeof(*ptr) + len + 1);
	{
		char *name = (char *) (ptr + 1);
		memmove(name, domainname, len);
		name[len] = '\0';
		ptr->name = name;
		ccs_init_policy_namespace(ptr);
	}
	return ptr;
}

/**
 * ccs_assign_domain4 - Create a domain or a namespace.
 *
 * @domainname: The name of domain.
 *
 * Returns pointer to "struct ccs_domain_info4" on success, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static struct ccs_domain_info4 *ccs_assign_domain4(const char *domainname)
{
	struct ccs_domain_info4 e = { };
	struct ccs_domain_info4 *entry = ccs_find_domain4(domainname);
	if (entry)
		return entry;
	/* Requested domain does not exist. */
	/* Don't create requested domain if domainname is invalid. */
	if (strlen(domainname) >= 4096 - 10 ||
	    !ccs_correct_domain(domainname))
		return NULL;
	e.ns = ccs_assign_namespace(domainname);
	if (!e.ns)
		return NULL;
	e.domainname = ccs_savename(domainname);
	if (!e.domainname)
		return NULL;
	e.default_transition = ccs_savename("child");
	if (!e.default_transition)
		goto out;
	entry = ccs_commit_ok(&e, sizeof(e));
	if (entry) {
		INIT_LIST_HEAD(&entry->acl_info_list);
		list_add_tail(&entry->list, &ccs_domain_list);
	}
out:
	ccs_put_name(e.domainname);
	ccs_put_name(e.default_transition);
	return entry;
}

/**
 * ccs_read_domain_in_acl - Read domainname and condition.
 *
 * @list: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_domain_in_acl(struct list_head *list)
{
	struct ccs_domain_info4 *domain;
	list_for_each_entry(domain, list, list) {
		if (domain->is_deleted)
			continue;
		cprintf("    by %s", domain->domainname->name);
		if (domain->cond)
			ccs_print_condition(domain->cond);
		ccs_set_lf();
	}
}

/**
 * ccs_read_inverse_policy - Read inversed mode policy.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_inverse_policy(void)
{
	struct ccs_acl_info *ptr;
	list_for_each_entry(ptr, &ccs_inversed_acl_list, list) {
		if (ptr->is_deleted)
			continue;
		ccs_print_entry(ptr);
		cprintf("    mode %s\n", ccs_mode[ptr->mode]);
		ccs_read_domain_in_acl(&ptr->domain_list);
		ccs_set_lf();
	}
}

/**
 * ccs_parse_policy - Parse a policy line.
 *
 * @line: Line to parse.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_parse_policy(char *line)
{
	/* Delete request? */
	head.is_delete = !strncmp(line, "delete ", 7);
	if (head.is_delete)
		memmove(line, line + 7, strlen(line + 7) + 1);
	/* Selecting namespace to update. */
	if (head.type == CCS_EXCEPTION_POLICY || head.type == CCS_PROFILE) {
		if (*line == '<') {
			char *cp = strchr(line, ' ');
			if (cp) {
				*cp++ = '\0';
				head.ns = ccs_assign_namespace(line);
				memmove(line, cp, strlen(cp) + 1);
			} else
				head.ns = NULL;
			/* Don't allow updating if namespace is invalid. */
			if (!head.ns)
				return -ENOENT;
		} else
			head.ns = &ccs_kernel_namespace;
	}
	/* Do the update. */
	switch (head.type) {
	case CCS_DOMAIN_POLICY:
		return ccs_write_domain();
	case CCS_ACL_POLICY:
		return ccs_write_acl_policy();
	case CCS_EXCEPTION_POLICY:
		return ccs_write_exception();
	case CCS_STAT:
		return ccs_write_stat();
	case CCS_PROFILE:
		return ccs_write_profile();
	case CCS_MANAGER:
		return ccs_write_manager();
	default:
		return -ENOSYS;
	}
}

/**
 * ccs_write_control - write() for /proc/ccs/ interface.
 *
 * @buffer:     Pointer to buffer to read from.
 * @buffer_len: Size of @buffer.
 *
 * Returns @buffer_len on success, negative value otherwise.
 */
static void ccs_write_control(char *buffer, const size_t buffer_len)
{
	static char *line = NULL;
	static int line_len = 0;
	size_t avail_len = buffer_len;
	while (avail_len > 0) {
		const char c = *buffer++;
		avail_len--;
		line = ccs_realloc(line, line_len + 1);
		line[line_len++] = c;
		if (c != '\n')
			continue;
		line[line_len - 1] = '\0';
		line_len = 0;
		head.write_buf = line;
		ccs_normalize_line(line);
		/* Don't allow updating policies by non manager programs. */
		switch (head.type) {
		case CCS_DOMAIN_POLICY:
			if (ccs_select_domain(line))
				continue;
			/* fall through */
		case CCS_EXCEPTION_POLICY:
			if (!strcmp(line, "select transition_only")) {
				head.print_transition_related_only = true;
				continue;
			}
		}
		ccs_parse_policy(line);
	}
}

/**
 * ccs_editpolicy_offline_init - Initialize variables for offline daemon.
 *
 * Returns nothing.
 */
static void ccs_editpolicy_offline_init(coid)
{
	static _Bool first = true;
	if (!first)
		return;
	first = false;
	memset(&head, 0, sizeof(head));
	memset(&ccs_kernel_domain, 0, sizeof(ccs_kernel_domain));
	memset(&ccs_kernel_namespace, 0, sizeof(ccs_kernel_namespace));
	{
		static struct ccs_path_info any;
		any.name = "any";
		ccs_fill_path_info(&any);
		ccs_group_any.group_name = &any;
		INIT_LIST_HEAD(&ccs_group_any.head.list);
		INIT_LIST_HEAD(&ccs_group_any.member_list);
	}
	ccs_kernel_namespace.name = "<kernel>";
	ccs_init_policy_namespace(&ccs_kernel_namespace);
	ccs_kernel_domain.ns = &ccs_kernel_namespace;
	INIT_LIST_HEAD(&ccs_kernel_domain.acl_info_list);
	ccs_kernel_domain.domainname = ccs_savename("<kernel>");
	ccs_kernel_domain.default_transition = ccs_savename("child");
	list_add_tail(&ccs_kernel_domain.list, &ccs_domain_list);
	memset(ccs_memory_quota, 0, sizeof(ccs_memory_quota));
}

/**
 * ccs_editpolicy_offline_main - Read request and handle policy I/O.
 *
 * @fd: Socket file descriptor. 
 *
 * Returns nothing.
 */
static void ccs_editpolicy_offline_main(const int fd)
{
	int i;
	static char buffer[4096];
	ccs_editpolicy_offline_init();
	/* Read filename. */
	for (i = 0; i < sizeof(buffer); i++) {
		if (read(fd, buffer + i, 1) != 1)
			return;
		if (!buffer[i])
			break;
	}
	if (!memchr(buffer, '\0', sizeof(buffer)))
		return;
	memset(&head, 0, sizeof(head));
	head.reset = true;
	if (!strcmp(buffer, CCS_PROC_POLICY_DOMAIN_POLICY))
		head.type = CCS_DOMAIN_POLICY;
	else if (!strcmp(buffer, CCS_PROC_POLICY_EXCEPTION_POLICY))
		head.type = CCS_EXCEPTION_POLICY;
	else if (!strcmp(buffer, CCS_PROC_POLICY_ACL_POLICY))
		head.type = CCS_ACL_POLICY;
	else if (!strcmp(buffer, CCS_PROC_POLICY_PROFILE))
		head.type = CCS_PROFILE;
	else if (!strcmp(buffer, CCS_PROC_POLICY_MANAGER))
		head.type = CCS_MANAGER;
	else if (!strcmp(buffer, CCS_PROC_POLICY_STAT))
		head.type = CCS_STAT;
	else
		return;
	/* Return \0 to indicate success. */
	if (write(fd, "", 1) != 1)
		return;
	client_fd = fd;
	while (1) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
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
			ccs_write_control(buffer, nonzero_len);
		} else {
			switch (head.type) {
			case CCS_DOMAIN_POLICY:
				ccs_read_domain();
				break;
			case CCS_ACL_POLICY:
				ccs_read_inverse_policy();
				break;
			case CCS_EXCEPTION_POLICY:
				ccs_read_exception();
				break;
			case CCS_STAT:
				ccs_read_stat();
				break;
			case CCS_PROFILE:
				ccs_read_profile();
				break;
			case CCS_MANAGER:
				ccs_read_manager();
				break;
			}
			/* Flush data. */
			cprintf("%s", "");
			/* Return \0 to indicate EOF. */
			if (write(fd, "", 1) != 1)
				return;
			nonzero_len = 1;
		}
		len -= nonzero_len;
		memmove(buffer, buffer + nonzero_len, len);
		if (len)
			goto restart;
	}
}

/**
 * ccs_editpolicy_offline_daemon - Emulate /proc/ccs/ interface.
 *
 * @listener: Listener fd. This is a listening PF_INET socket.
 * @notifier: Notifier fd. This is a pipe's reader side.
 *
 * This function does not return.
 */
void ccs_editpolicy_offline_daemon(const int listener, const int notifier)
{
	while (1) {
		struct pollfd pfd[2] = {
			{ .fd = listener, .events = POLLIN },
			{ .fd = notifier, .events = POLLIN }
		};
		struct sockaddr_in addr;
		socklen_t size = sizeof(addr);
		int fd;
		if (poll(pfd, 2, -1) == EOF ||
		    (pfd[1].revents & (POLLIN | POLLHUP)))
			_exit(1);
		fd = accept(listener, (struct sockaddr *) &addr, &size);
		if (fd == EOF)
			continue;
		ccs_editpolicy_offline_main(fd);
		close(fd);
	}
}
