/*
 * security/ccsecurity/internal.h
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_CCS_COMMON_H
#define _LINUX_CCS_COMMON_H

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#include <linux/smp_lock.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/binfmts.h>
#include <asm/uaccess.h>
#include <stdarg.h>
#include <linux/delay.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#include <linux/kmod.h>
#include <asm/hardirq.h>
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 9)
#include <asm/hardirq.h>
#else
#include <linux/hardirq.h>
#endif
#include <linux/in6.h>
#include <linux/ccsecurity.h>

struct dentry;
struct vfsmount;
struct in6_addr;
extern asmlinkage long sys_getpid(void);
extern asmlinkage long sys_getppid(void);

#include "compat.h"

/**
 * list_for_each_cookie - iterate over a list with cookie.
 * @pos:        the &struct list_head to use as a loop cursor.
 * @cookie:     the &struct list_head to use as a cookie.
 * @head:       the head for your list.
 *
 * Same with list_for_each_rcu() except that this primitive uses @cookie
 * so that we can continue iteration.
 * @cookie must be NULL when iteration starts, and @cookie will become
 * NULL when iteration finishes.
 */
#define list_for_each_cookie(pos, cookie, head)                       \
	for (({ if (!cookie)                                          \
				     cookie = head; }),               \
	     pos = rcu_dereference((cookie)->next);                   \
	     prefetch(pos->next), pos != (head) || ((cookie) = NULL); \
	     (cookie) = pos, pos = rcu_dereference(pos->next))

/* Subset of "struct stat". */
struct ccs_mini_stat {
	uid_t uid;
	gid_t gid;
	ino_t ino;
	mode_t mode;
	dev_t dev;
	dev_t rdev;
};

/* Structure for dumping argv[] and envp[] of "struct linux_binprm". */
struct ccs_page_dump {
	struct page *page;    /* Previously dumped page. */
	char *data;           /* Contents of "page". Size is PAGE_SIZE. */
};

/* Structure for attribute checks in addition to pathname checks. */
struct ccs_obj_info {
	bool validate_done;
	bool path1_valid;
	bool path1_parent_valid;
	bool path2_valid;
	bool path2_parent_valid;
	struct dentry *path1_dentry;
	struct vfsmount *path1_vfsmnt;
	struct dentry *path2_dentry;
	struct vfsmount *path2_vfsmnt;
	struct ccs_mini_stat path1_stat;
	/* I don't handle path2_stat for rename operation. */
	struct ccs_mini_stat path2_stat;
	struct ccs_mini_stat path1_parent_stat;
	struct ccs_mini_stat path2_parent_stat;
	struct ccs_path_info *symlink_target;
	unsigned int dev;
};

/* Value type definition. */
#define VALUE_TYPE_INVALID     0
#define VALUE_TYPE_DECIMAL     1
#define VALUE_TYPE_OCTAL       2
#define VALUE_TYPE_HEXADECIMAL 3

struct ccs_condition_element {
	/*
	 * Left hand operand. A "struct ccs_argv_entry" for ARGV_ENTRY, a
	 * "struct ccs_envp_entry" for ENVP_ENTRY is attached to the tail of
	 * the array of this struct.
	 */
	u8 left;
	/*
	 * Right hand operand.  An "unsigned long" for CONSTANT_VALUE,
	 * two "unsigned long" for CONSTANT_VALUE_RANGE,
	 * a "struct ccs_number_group *" for NUMBER_GROUP,
	 * a "struct ccs_path_info *" for PATH_INFO,
	 * a "struct ccs_group_info *" for PATH_GROUP is attached to the tail
	 * of the array of this struct.
	 */
	u8 right;
	/* Equation operator. 1 if equals or overlaps, 0 otherwise. */
	u8 equals;
	/*
	 * Radix types for constant value .
	 *
	 * Bit 3 and 2: Right hand operand's min value
	 * Bit 1 and 0: Right hand operand's max value
	 *
	 * 01 is for decimal, 10 is for octal, 11 is for hexadecimal,
	 * 00 is for invalid (i.e. not a value) expression.
	 */
	u8 type;
};

/* Structure for " if " and "; set" part. */
struct ccs_condition {
	struct list_head list;
	atomic_t users;
	u32 size;
	u16 condc;
	u16 ulong_count;
	u16 number_group_count;
	u16 path_info_count;
	u16 path_group_count;
	u16 argc;
	u16 envc;
	u8 post_state[4];
	/*
	 * struct ccs_condition_element condition[condc];
	 * unsigned long values[ulong_count];
	 * struct ccs_number_group *number_group[number_group_count];
	 * struct ccs_path_info *path_info[path_info_count];
	 * struct ccs_path_group *path_group[path_group_count];
	 * struct ccs_argv_entry argv[argc];
	 * struct ccs_envp_entry envp[envc];
	 */
};

struct ccs_execve_entry;

/* Structure for request info. */
struct ccs_request_info {
	struct ccs_domain_info *domain;
	struct ccs_obj_info *obj;
	struct ccs_execve_entry *ee;
	struct ccs_condition *cond;
	u16 retry;
	u8 profile;
	u8 mode;
};

/* Structure for holding a token. */
struct ccs_path_info {
	const char *name;
	u32 hash;          /* = full_name_hash(name, strlen(name)) */
	u16 total_len;     /* = strlen(name)                       */
	u16 const_len;     /* = ccs_const_part_length(name)        */
	bool is_dir;       /* = ccs_strendswith(name, "/")         */
	bool is_patterned; /* = const_len < total_len              */
	u16 depth;         /* = ccs_path_depth(name)               */
};

/*
 * This is the max length of a token.
 *
 * A token consists of only ASCII printable characters.
 * Non printable characters in a token is represented in \ooo style
 * octal string. Thus, \ itself is represented as \\.
 */
#define CCS_MAX_PATHNAME_LEN 4000

#define CCS_EXEC_TMPSIZE     4096

/* Structure for execve() operation. */
struct ccs_execve_entry {
	struct list_head list;
	struct task_struct *task; /* = current */
	struct ccs_request_info r;
	struct ccs_obj_info obj;
	struct linux_binprm *bprm;
	int reader_idx;
	/* For execute_handler */
	const struct ccs_path_info *handler;
	char *program_path; /* Size is CCS_MAX_PATHNAME_LEN bytes */
	/* For dumping argv[] and envp[]. */
	struct ccs_page_dump dump;
	/* For temporary use. */
	char *tmp; /* Size is CCS_EXEC_TMPSIZE bytes */
};

/* Structure for "path_group" directive. */
struct ccs_path_group_member {
	struct list_head list;
	const struct ccs_path_info *member_name;
	bool is_deleted;
};

/* Structure for "path_group" directive. */
struct ccs_path_group {
	struct list_head list;
	const struct ccs_path_info *group_name;
	struct list_head path_group_member_list;
	atomic_t users;
};

/* Structure for "number_group" directive. */
struct ccs_number_group_member {
	struct list_head list;
	unsigned long min;
	unsigned long max;
	bool is_deleted;
	u8 min_type;
	u8 max_type;
};

/* Structure for "number_group" directive. */
struct ccs_number_group {
	struct list_head list;
	const struct ccs_path_info *group_name;
	struct list_head number_group_member_list;
	atomic_t users;
};

/* Structure for "address_group" directive. */
struct ccs_address_group_member {
	struct list_head list;
	union {
		u32 ipv4;                    /* Host byte order    */
		const struct in6_addr *ipv6; /* Network byte order */
	} min, max;
	bool is_deleted;
	bool is_ipv6;
};

/* Structure for "address_group" directive. */
struct ccs_address_group_entry {
	struct list_head list;
	const struct ccs_path_info *group_name;
	struct list_head address_group_member_list;
	atomic_t users;
};

/* Structure for holding requested pathname. */
struct ccs_path_info_with_data {
	/* Keep "head" first, for this pointer is passed to ccs_free(). */
	struct ccs_path_info head;
	char barrier1[16]; /* Safeguard for overrun. */
	char body[CCS_MAX_PATHNAME_LEN];
	char barrier2[16]; /* Safeguard for overrun. */
};

/* Common header for holding ACL entries. */
struct ccs_acl_info {
	struct list_head list;
	struct ccs_condition *cond;
	/*
	 * Type of this ACL entry.
	 *
	 * MSB is is_deleted flag.
	 */
	u8 type;
} __attribute__((__packed__));

/* Index numbers for Access Controls. */
enum ccs_acl_entry_type_index {
	TYPE_SINGLE_PATH_ACL,
	TYPE_MKDEV_ACL,
	TYPE_DOUBLE_PATH_ACL,
	TYPE_IOCTL_ACL,
	TYPE_ARGV0_ACL,
	TYPE_ENV_ACL,
	TYPE_CAPABILITY_ACL,
	TYPE_IP_NETWORK_ACL,
	TYPE_SIGNAL_ACL,
	TYPE_MOUNT_ACL,
	TYPE_UMOUNT_ACL,
	TYPE_CHROOT_ACL,
	TYPE_PIVOT_ROOT_ACL,
	TYPE_EXECUTE_HANDLER,
	TYPE_DENIED_EXECUTE_HANDLER
};

/* This ACL entry is deleted.           */
#define ACL_DELETED        0x80

/* Structure for domain information. */
struct ccs_domain_info {
	struct list_head list;
	struct list_head acl_info_list;
	/* Name of this domain. Never NULL.          */
	const struct ccs_path_info *domainname;
	u8 profile;        /* Profile number to use. */
	bool is_deleted;   /* Delete flag.           */
	bool quota_warned; /* Quota warnning flag.   */
	/* Ignore "allow_read" directive in exception policy. */
	bool ignore_global_allow_read;
	/* Ignore "allow_env" directive in exception policy.  */
	bool ignore_global_allow_env;
	/*
	 * This domain was unable to create a new domain at
	 * ccs_find_next_domain() because the name of the domain to be created
	 * was too long or it could not allocate memory.
	 * More than one process continued execve() without domain transition.
	 */
	bool domain_transition_failed;
};

/* Profile number is an integer between 0 and 255. */
#define MAX_PROFILES 256

#define CCS_CHECK_READ_FOR_OPEN_EXEC     16
#define CCS_DONT_SLEEP_ON_ENFORCE_ERROR  32
#define CCS_TASK_IS_EXECUTE_HANDLER      64
#define CCS_TASK_IS_POLICY_MANAGER      128

/* Structure for "allow_read" keyword. */
struct ccs_globally_readable_file_entry {
	struct list_head list;
	const struct ccs_path_info *filename;
	bool is_deleted;
};

/* Structure for "file_pattern" keyword. */
struct ccs_pattern_entry {
	struct list_head list;
	const struct ccs_path_info *pattern;
	bool is_deleted;
};

/* Structure for "deny_rewrite" keyword. */
struct ccs_no_rewrite_entry {
	struct list_head list;
	const struct ccs_path_info *pattern;
	bool is_deleted;
};

/* Structure for "allow_env" keyword. */
struct ccs_globally_usable_env_entry {
	struct list_head list;
	const struct ccs_path_info *env;
	bool is_deleted;
};

/* Structure for "initialize_domain" and "no_initialize_domain" keyword. */
struct ccs_domain_initializer_entry {
	struct list_head list;
	const struct ccs_path_info *domainname;    /* This may be NULL */
	const struct ccs_path_info *program;
	bool is_deleted;
	bool is_not;       /* True if this entry is "no_initialize_domain".  */
	bool is_last_name; /* True if the domainname is ccs_get_last_name(). */
};

/* Structure for "keep_domain" and "no_keep_domain" keyword. */
struct ccs_domain_keeper_entry {
	struct list_head list;
	const struct ccs_path_info *domainname;
	const struct ccs_path_info *program;       /* This may be NULL */
	bool is_deleted;
	bool is_not;       /* True if this entry is "no_keep_domain".        */
	bool is_last_name; /* True if the domainname is ccs_get_last_name(). */
};

/* Structure for "aggregator" keyword. */
struct ccs_aggregator_entry {
	struct list_head list;
	const struct ccs_path_info *original_name;
	const struct ccs_path_info *aggregated_name;
	bool is_deleted;
};

/* Structure for "allow_unmount" keyword. */
struct ccs_umount_acl_record {
	struct ccs_acl_info head; /* type = TYPE_UMOUNT_ACL */
	const struct ccs_path_info *dir;
};

/* Structure for "allow_pivot_root" keyword. */
struct ccs_pivot_root_acl_record {
	struct ccs_acl_info head; /* type = TYPE_PIVOT_ROOT_ACL */
	const struct ccs_path_info *old_root;
	const struct ccs_path_info *new_root;
};

/* Structure for "allow_mount" keyword. */
struct ccs_mount_acl_record {
	struct ccs_acl_info head; /* type = TYPE_MOUNT_ACL */
	const struct ccs_path_info *dev_name;
	const struct ccs_path_info *dir_name;
	const struct ccs_path_info *fs_type;
	unsigned long flags;
};

/* Structure for "allow_chroot" keyword. */
struct ccs_chroot_acl_record {
	struct ccs_acl_info head; /* type = TYPE_CHROOT_ACL */
	const struct ccs_path_info *dir;
};

/* Structure for "deny_autobind" keyword. */
struct ccs_reserved_entry {
	struct list_head list;
	bool is_deleted;             /* Delete flag.                         */
	u16 min_port;                /* Start of port number range.          */
	u16 max_port;                /* End of port number range.            */
};

/* Structure for policy manager. */
struct ccs_policy_manager_entry {
	struct list_head list;
	/* A path to program or a domainname. */
	const struct ccs_path_info *manager;
	bool is_domain;  /* True if manager is a domainname. */
	bool is_deleted; /* True if this entry is deleted. */
};

/* Structure for argv[]. */
struct ccs_argv_entry {
	unsigned int index;
	const struct ccs_path_info *value;
	bool is_not;
};

/* Structure for envp[]. */
struct ccs_envp_entry {
	const struct ccs_path_info *name;
	const struct ccs_path_info *value;
	bool is_not;
};

/*
 * Structure for "execute_handler" and "denied_execute_handler" directive.
 * These directives can exist only one entry in a domain.
 *
 * If "execute_handler" directive exists and the current process is not
 * an execute handler, all execve() requests are replaced by execve() requests
 * of a program specified by "execute_handler" directive.
 * If the current process is an execute handler,
 * "execute_handler" and "denied_execute_handler" directives are ignored.
 * The program specified by "execute_handler" validates execve() parameters
 * and executes the original execve() requests if appropriate.
 *
 * "denied_execute_handler" directive is used only when execve() request was
 * rejected in enforcing mode (i.e. MAC_FOR_FILE=enforcing).
 * The program specified by "denied_execute_handler" does whatever it wants
 * to do (e.g. silently terminate, change firewall settings,
 * redirect the user to honey pot etc.).
 */
struct ccs_execute_handler_record {
	struct ccs_acl_info head;            /* type = TYPE_*EXECUTE_HANDLER */
	const struct ccs_path_info *handler; /* Pointer to single pathname.  */
};

union ccs_name_union {
	void *ptr;
	const struct ccs_path_info *filename;
	struct ccs_path_group *group;
};

union ccs_number_union {
	struct {
		unsigned int min;
		unsigned int max;
	} value;
	struct ccs_number_group *group;
};

/*
 * Structure for "allow_read/write", "allow_execute", "allow_read",
 * "allow_write", "allow_create", "allow_unlink", "allow_mkdir", "allow_rmdir",
 * "allow_mkfifo", "allow_mksock", "allow_truncate", "allow_symlink" and
 * "allow_rewrite" directive.
 */
struct ccs_single_path_acl_record {
	struct ccs_acl_info head; /* type = TYPE_SINGLE_PATH_ACL */
	/* True if name points to "path_group" directive. */
	bool name_is_group;
	u16 perm;
	union ccs_name_union name;
};

/* Structure for "allow_mkblock" and "allow_mkchar" directive. */
struct ccs_mkdev_acl_record {
	struct ccs_acl_info head; /* type = TYPE_MKDEV_ACL */
	u8 perm; /* mkblock and/or mkchar */
	/* True if name points to "path_group" directive. */
	bool name_is_group;
	/* True if major points to "number_group" directive. */
	bool major_is_group;
	/* True if minor points to "number_group" directive. */
	bool minor_is_group;
	union ccs_name_union name;
	union ccs_number_union major;
	union ccs_number_union minor;
};

/* Structure for "allow_rename" and "allow_link" directive. */
struct ccs_double_path_acl_record {
	struct ccs_acl_info head; /* type = TYPE_DOUBLE_PATH_ACL */
	u8 perm;
	/* True if name1 points to "path_group" directive. */
	bool name1_is_group;
	/* True if name2 points to "path_group" directive. */
	bool name2_is_group;
	union ccs_name_union name1;
	union ccs_name_union name2;
};

/* Structure for "allow_ioctl" directive. */
struct ccs_ioctl_acl_record {
	struct ccs_acl_info head; /* type = TYPE_IOCTL_ACL */
	/* True if name points to "path_group" directive. */
	bool name_is_group;
	/* True if cmd points to "number_group" directive. */
	bool cmd_is_group;
	union ccs_name_union name;
	union ccs_number_union cmd;
};

/* Structure for "allow_argv0" directive. */
struct ccs_argv0_acl_record {
	struct ccs_acl_info head;             /* type = TYPE_ARGV0_ACL       */
	const struct ccs_path_info *filename; /* Pointer to single pathname. */
	const struct ccs_path_info *argv0;    /* = strrchr(argv[0], '/') + 1 */
};

/* Structure for "allow_env" directive in domain policy. */
struct ccs_env_acl_record {
	struct ccs_acl_info head;        /* type = TYPE_ENV_ACL  */
	const struct ccs_path_info *env; /* environment variable */
};

/* Structure for "allow_capability" directive. */
struct ccs_capability_acl_record {
	struct ccs_acl_info head; /* type = TYPE_CAPABILITY_ACL */
	u8 operation;
};

/* Structure for "allow_signal" directive. */
struct ccs_signal_acl_record {
	struct ccs_acl_info head; /* type = TYPE_SIGNAL_ACL */
	u16 sig;
	/* Pointer to destination pattern. */
	const struct ccs_path_info *domainname;
};

struct ccs_ipv6addr_entry {
	struct list_head list;
	atomic_t users;
	struct in6_addr addr;
};

/* Structure for "allow_network" directive. */
struct ccs_ip_network_acl_record {
	struct ccs_acl_info head; /* type = TYPE_IP_NETWORK_ACL */
	/*
	 * operation_type takes one of the following constants.
	 *   NETWORK_ACL_UDP_BIND for UDP's bind() operation.
	 *   NETWORK_ACL_UDP_CONNECT for UDP's connect()/send()/recv()
	 *                               operation.
	 *   NETWORK_ACL_TCP_BIND for TCP's bind() operation.
	 *   NETWORK_ACL_TCP_LISTEN for TCP's listen() operation.
	 *   NETWORK_ACL_TCP_CONNECT for TCP's connect() operation.
	 *   NETWORK_ACL_TCP_ACCEPT for TCP's accept() operation.
	 *   NETWORK_ACL_RAW_BIND for IP's bind() operation.
	 *   NETWORK_ACL_RAW_CONNECT for IP's connect()/send()/recv()
	 *                               operation.
	 */
	u8 operation_type;
	/*
	 * record_type takes one of the following constants.
	 *   IP_RECORD_TYPE_ADDRESS_GROUP
	 *                if address points to "address_group" directive.
	 *   IP_RECORD_TYPE_IPv4
	 *                if address points to an IPv4 address.
	 *   IP_RECORD_TYPE_IPv6
	 *                if address points to an IPv6 address.
	 */
	u8 record_type;
	/* True if port points to "number_group" directive. */
	bool port_is_group;
	union {
		struct {
			/* Start of IPv4 address range. Host endian. */
			u32 min;
			/* End of IPv4 address range. Host endian.   */
			u32 max;
		} ipv4;
		struct {
			/* Start of IPv6 address range. Big endian.  */
			const struct in6_addr *min;
			/* End of IPv6 address range. Big endian.    */
			const struct in6_addr *max;
		} ipv6;
		/* Pointer to address group. */
		struct ccs_address_group_entry *group;
	} address;
	union ccs_number_union port;
};

/* Index numbers for File Controls. */

/*
 * TYPE_READ_WRITE_ACL is special. TYPE_READ_WRITE_ACL is automatically set
 * if both TYPE_READ_ACL and TYPE_WRITE_ACL are set. Both TYPE_READ_ACL and
 * TYPE_WRITE_ACL are automatically set if TYPE_READ_WRITE_ACL is set.
 * TYPE_READ_WRITE_ACL is automatically cleared if either TYPE_READ_ACL or
 * TYPE_WRITE_ACL is cleared. Both TYPE_READ_ACL and TYPE_WRITE_ACL are
 * automatically cleared if TYPE_READ_WRITE_ACL is cleared.
 */

enum ccs_single_path_acl_index {
	TYPE_READ_WRITE_ACL,
	TYPE_EXECUTE_ACL,
	TYPE_READ_ACL,
	TYPE_WRITE_ACL,
	TYPE_CREATE_ACL,
	TYPE_UNLINK_ACL,
	TYPE_MKDIR_ACL,
	TYPE_RMDIR_ACL,
	TYPE_MKFIFO_ACL,
	TYPE_MKSOCK_ACL,
	TYPE_TRUNCATE_ACL,
	TYPE_SYMLINK_ACL,
	TYPE_REWRITE_ACL,
	MAX_SINGLE_PATH_OPERATION
};

enum ccs_mkdev_acl_type {
	TYPE_MKBLOCK_ACL,
	TYPE_MKCHAR_ACL,
	MAX_MKDEV_OPERATION
};

enum ccs_double_path_acl_index {
	TYPE_LINK_ACL,
	TYPE_RENAME_ACL,
	MAX_DOUBLE_PATH_OPERATION
};

enum ccs_ip_record_type {
	IP_RECORD_TYPE_ADDRESS_GROUP,
	IP_RECORD_TYPE_IPv4,
	IP_RECORD_TYPE_IPv6
};

/* Keywords for ACLs. */
#define KEYWORD_ADDRESS_GROUP             "address_group "
#define KEYWORD_AGGREGATOR                "aggregator "
#define KEYWORD_ALLOW_ARGV0               "allow_argv0 "
#define KEYWORD_ALLOW_CAPABILITY          "allow_capability "
#define KEYWORD_ALLOW_CHROOT              "allow_chroot "
#define KEYWORD_ALLOW_ENV                 "allow_env "
#define KEYWORD_ALLOW_IOCTL               "allow_ioctl "
#define KEYWORD_ALLOW_MOUNT               "allow_mount "
#define KEYWORD_ALLOW_NETWORK             "allow_network "
#define KEYWORD_ALLOW_PIVOT_ROOT          "allow_pivot_root "
#define KEYWORD_ALLOW_READ                "allow_read "
#define KEYWORD_ALLOW_SIGNAL              "allow_signal "
#define KEYWORD_DELETE                    "delete "
#define KEYWORD_DENY_AUTOBIND             "deny_autobind "
#define KEYWORD_DENY_REWRITE              "deny_rewrite "
#define KEYWORD_ALLOW_UNMOUNT             "allow_unmount "
#define KEYWORD_FILE_PATTERN              "file_pattern "
#define KEYWORD_INITIALIZE_DOMAIN         "initialize_domain "
#define KEYWORD_KEEP_DOMAIN               "keep_domain "
#define KEYWORD_NO_INITIALIZE_DOMAIN      "no_initialize_domain "
#define KEYWORD_NO_KEEP_DOMAIN            "no_keep_domain "
#define KEYWORD_PATH_GROUP                "path_group "
#define KEYWORD_NUMBER_GROUP              "number_group "
#define KEYWORD_SELECT                    "select "
#define KEYWORD_USE_PROFILE               "use_profile "
#define KEYWORD_IGNORE_GLOBAL_ALLOW_READ  "ignore_global_allow_read"
#define KEYWORD_IGNORE_GLOBAL_ALLOW_ENV   "ignore_global_allow_env"
#define KEYWORD_EXECUTE_HANDLER           "execute_handler"
#define KEYWORD_DENIED_EXECUTE_HANDLER    "denied_execute_handler"
#define KEYWORD_MAC_FOR_CAPABILITY        "MAC_FOR_CAPABILITY::"
/* A domain definition starts with <kernel>. */
#define ROOT_NAME                         "<kernel>"
#define ROOT_NAME_LEN                     (sizeof(ROOT_NAME) - 1)

/* Index numbers for Access Controls. */
enum ccs_profile_index {
	CCS_MAC_FOR_FILE,          /* domain_policy.conf */
	CCS_MAC_FOR_IOCTL,         /* domain_policy.conf */
	CCS_MAC_FOR_ARGV0,         /* domain_policy.conf */
	CCS_MAC_FOR_ENV,           /* domain_policy.conf */
	CCS_MAC_FOR_NETWORK,       /* domain_policy.conf */
	CCS_MAC_FOR_SIGNAL,        /* domain_policy.conf */
	CCS_MAC_FOR_NAMESPACE,     /* domain_policy.conf */
	CCS_RESTRICT_AUTOBIND,     /* exception_policy.conf */
	CCS_MAX_ACCEPT_ENTRY,
#ifdef CONFIG_CCSECURITY_AUDIT
	CCS_MAX_GRANT_LOG,
	CCS_MAX_REJECT_LOG,
#endif
	CCS_VERBOSE,
	CCS_SLEEP_PERIOD,
	CCS_MAX_CONTROL_INDEX
};

/* Indexes for /proc/ccs/ interfaces. */
enum ccs_proc_interface_index {
	CCS_DOMAINPOLICY,
	CCS_EXCEPTIONPOLICY,
	CCS_SYSTEMPOLICY,
	CCS_DOMAIN_STATUS,
	CCS_PROCESS_STATUS,
	CCS_MEMINFO,
	CCS_GRANTLOG,
	CCS_REJECTLOG,
	CCS_SELFDOMAIN,
	CCS_VERSION,
	CCS_PROFILE,
	CCS_QUERY,
	CCS_MANAGER,
	CCS_UPDATESCOUNTER,
	CCS_EXECUTE_HANDLER
};

/* Structure for reading/writing policy via /proc interfaces. */
struct ccs_io_buffer {
	int (*read) (struct ccs_io_buffer *);
	int (*write) (struct ccs_io_buffer *);
	int (*poll) (struct file *file, poll_table *wait);
	/* Exclusive lock for this structure.   */
	struct mutex io_sem;
	/* Index returned by ccs_read_lock().   */
	int reader_idx;
	/* The position currently reading from. */
	struct list_head *read_var1;
	/* Extra variables for reading.         */
	struct list_head *read_var2;
	/* The position currently writing to.   */
	struct ccs_domain_info *write_var1;
	/* The step for reading.                */
	int read_step;
	/* Buffer for reading.                  */
	char *read_buf;
	/* EOF flag for reading.                */
	bool read_eof;
	/* Read domain ACL of specified PID?    */
	bool read_single_domain;
	/* Read allow_execute entry only?       */
	bool read_execute_only;
	/* Extra variable for reading.          */
	u8 read_bit;
	/* Bytes available for reading.         */
	int read_avail;
	/* Size of read buffer.                 */
	int readbuf_size;
	/* Buffer for writing.                  */
	char *write_buf;
	/* Bytes available for writing.         */
	int write_avail;
	/* Size of write buffer.                */
	int writebuf_size;
	/* Type of this interface.              */
	u8 type;
};

/* Prototype definition. */

bool ccs_can_sleep(void);
bool ccs_check_and_save_number(const char *filename, bool *is_group, union ccs_number_union *ptr);
bool ccs_check_condition(struct ccs_request_info *r, const struct ccs_acl_info *acl);
bool ccs_domain_quota_ok(struct ccs_request_info *r);
bool ccs_dump_page(struct linux_binprm *bprm, unsigned long pos, struct ccs_page_dump *dump);
bool ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));
bool ccs_is_correct_domain(const unsigned char *domainname);
bool ccs_is_correct_path(const char *filename, const s8 start_type, const s8 pattern_type, const s8 end_type);
bool ccs_is_domain_def(const unsigned char *buffer);
bool ccs_memory_ok(const void *ptr, const unsigned int size);
bool ccs_number_matches_group(const unsigned long min, const unsigned long max, const struct ccs_number_group *group);
bool ccs_path_matches_group(const struct ccs_path_info *pathname, const struct ccs_path_group *group, const bool may_use_pattern);
bool ccs_path_matches_pattern(const struct ccs_path_info *filename, const struct ccs_path_info *pattern);
bool ccs_print_condition(struct ccs_io_buffer *head, const struct ccs_condition *cond);
bool ccs_read_address_group_policy(struct ccs_io_buffer *head);
bool ccs_read_aggregator_policy(struct ccs_io_buffer *head);
bool ccs_read_domain_initializer_policy(struct ccs_io_buffer *head);
bool ccs_read_domain_keeper_policy(struct ccs_io_buffer *head);
bool ccs_read_file_pattern(struct ccs_io_buffer *head);
bool ccs_read_globally_readable_policy(struct ccs_io_buffer *head);
bool ccs_read_globally_usable_env_policy(struct ccs_io_buffer *head);
bool ccs_read_no_rewrite_policy(struct ccs_io_buffer *head);
bool ccs_read_number_group_policy(struct ccs_io_buffer *head);
bool ccs_read_path_group_policy(struct ccs_io_buffer *head);
bool ccs_read_reserved_port_policy(struct ccs_io_buffer *head);
bool ccs_str_starts(char **src, const char *find);
bool ccs_tokenize(char *buffer, char *w[], size_t size);
bool ccs_verbose_mode(const struct ccs_domain_info *domain);
char *ccs_encode(const char *str);
char *ccs_init_audit_log(int *len, struct ccs_request_info *r);
char *ccs_realpath(const char *pathname);
char *ccs_realpath_from_dentry(struct dentry *dentry, struct vfsmount *mnt);
const char *ccs_cap2keyword(const u8 operation);
const char *ccs_dp2keyword(const u8 operation);
const char *ccs_get_exe(void);
const char *ccs_get_last_name(const struct ccs_domain_info *domain);
const char *ccs_get_msg(const bool is_enforce);
const char *ccs_mkdev2keyword(const u8 operation);
const char *ccs_net2keyword(const u8 operation);
const char *ccs_sp2keyword(const u8 operation);
const struct ccs_path_info *ccs_get_name(const char *name);
const struct in6_addr *ccs_get_ipv6_address(const struct in6_addr *addr);
int ccs_add_domain_acl(struct ccs_domain_info *domain, struct ccs_acl_info *acl);
int ccs_check_argv0_perm(struct ccs_request_info *r, const struct ccs_path_info *filename, const char *argv0);
int ccs_check_env_perm(struct ccs_request_info *r, const char *env);
int ccs_check_exec_perm(struct ccs_request_info *r, const struct ccs_path_info *filename);
int ccs_check_supervisor(struct ccs_request_info *r, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));
int ccs_close_control(struct file *file);
int ccs_del_domain_acl(struct ccs_acl_info *acl);
int ccs_delete_domain(char *data);
int ccs_open_control(const u8 type, struct file *file);
int ccs_poll_control(struct file *file, poll_table *wait);
int ccs_poll_grant_log(struct file *file, poll_table *wait);
int ccs_poll_reject_log(struct file *file, poll_table *wait);
int ccs_read_control(struct file *file, char __user *buffer, const int buffer_len);
int ccs_read_grant_log(struct ccs_io_buffer *head);
int ccs_read_memory_counter(struct ccs_io_buffer *head);
int ccs_read_reject_log(struct ccs_io_buffer *head);
int ccs_symlink_path(const char *pathname, struct ccs_execve_entry *ee);
int ccs_write_address_group_policy(char *data, const bool is_delete);
int ccs_write_aggregator_policy(char *data, const bool is_delete);
int ccs_write_argv0_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
int ccs_write_audit_log(const bool is_granted, struct ccs_request_info *r, const char *fmt, ...) __attribute__ ((format(printf, 3, 4)));
int ccs_write_capability_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
int ccs_write_chroot_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
int ccs_write_control(struct file *file, const char __user *buffer, const int buffer_len);
int ccs_write_domain_initializer_policy(char *data, const bool is_not, const bool is_delete);
int ccs_write_domain_keeper_policy(char *data, const bool is_not, const bool is_delete);
int ccs_write_env_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
int ccs_write_file_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
int ccs_write_globally_readable_policy(char *data, const bool is_delete);
int ccs_write_globally_usable_env_policy(char *data, const bool is_delete);
int ccs_write_ioctl_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
int ccs_write_memory_quota(struct ccs_io_buffer *head);
int ccs_write_mount_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
int ccs_write_network_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
int ccs_write_no_rewrite_policy(char *data, const bool is_delete);
int ccs_write_number_group_policy(char *data, const bool is_delete);
int ccs_write_path_group_policy(char *data, const bool is_delete);
int ccs_write_pattern_policy(char *data, const bool is_delete);
int ccs_write_pivot_root_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
int ccs_write_reserved_port_policy(char *data, const bool is_delete);
int ccs_write_signal_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
int ccs_write_umount_policy(char *data, struct ccs_domain_info *domain, struct ccs_condition *condition, const bool is_delete);
struct ccs_condition *ccs_get_condition(char * const condition);
struct ccs_condition *ccs_handler_cond(void);
struct ccs_domain_info *ccs_fetch_next_domain(void);
struct ccs_domain_info *ccs_find_domain(const char *domainname);
struct ccs_domain_info *ccs_find_or_assign_new_domain(const char *domainname, const u8 profile);
struct ccs_number_group *ccs_get_number_group(const char *group_name);
struct ccs_path_group *ccs_get_path_group(const char *group_name);
struct ccs_profile *ccs_find_or_assign_new_profile(const unsigned int profile);
unsigned int ccs_check_flags(const struct ccs_domain_info *domain, const u8 index);
void ccs_fill_path_info(struct ccs_path_info *ptr);
void ccs_init_request_info(struct ccs_request_info *r, struct ccs_domain_info *domain, const u8 index);
void ccs_load_policy(const char *filename);
void ccs_memory_free(const void *ptr, size_t size);
void ccs_normalize_line(unsigned char *buffer);
void ccs_print_ipv6(char *buffer, const int buffer_len, const struct in6_addr *ip);
void ccs_put_address_group(struct ccs_address_group_entry *group);
void ccs_put_condition(struct ccs_condition *cond);
void ccs_put_ipv6_address(const struct in6_addr *addr);
void ccs_put_name(const struct ccs_path_info *name);
void ccs_put_number_group(struct ccs_number_group *group);
void ccs_put_path_group(struct ccs_path_group *group);
void ccs_run_gc(void);

/* strcmp() for "struct ccs_path_info" structure. */
static inline bool ccs_pathcmp(const struct ccs_path_info *a,
			       const struct ccs_path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}

/* Get type of an ACL entry. */
static inline u8 ccs_acl_type1(struct ccs_acl_info *ptr)
{
	return ptr->type & ~ACL_DELETED;
}

/* Get type of an ACL entry. */
static inline u8 ccs_acl_type2(struct ccs_acl_info *ptr)
{
	return ptr->type;
}

/* Lock for protecting policy. */
extern struct mutex ccs_policy_lock;
/* A linked list of domains. */
extern struct list_head ccs_domain_list;

extern struct list_head ccs_address_group_list;
extern struct list_head ccs_globally_readable_list;
extern struct list_head ccs_path_group_list;
extern struct list_head ccs_number_group_list;
extern struct list_head ccs_pattern_list;
extern struct list_head ccs_no_rewrite_list;
extern struct list_head ccs_globally_usable_env_list;
extern struct list_head ccs_domain_initializer_list;
extern struct list_head ccs_domain_keeper_list;
extern struct list_head ccs_aggregator_list;
extern struct list_head ccs_condition_list;
extern struct list_head ccs_reservedport_list;
extern struct list_head ccs_policy_manager_list;

/* Has /sbin/init started? */
extern bool ccs_policy_loaded;
/* The kernel's domain. */
extern struct ccs_domain_info ccs_kernel_domain;
/* Lock for GC. */
extern struct srcu_struct ccs_ss;

struct ccs_profile {
	unsigned int value[CCS_MAX_CONTROL_INDEX];
	const struct ccs_path_info *comment;
	unsigned char capability_value[CCS_MAX_CAPABILITY_INDEX];
};
extern struct ccs_profile *ccs_profile_ptr[MAX_PROFILES];

extern const char *ccs_capability_control_keyword[CCS_MAX_CAPABILITY_INDEX];

extern unsigned int ccs_audit_log_memory_size;
extern unsigned int ccs_quota_for_audit_log;
extern unsigned int ccs_query_memory_size;
extern unsigned int ccs_quota_for_query;

#include <linux/dcache.h>
extern spinlock_t vfsmount_lock;

#ifdef D_PATH_DISCONNECT

static inline void ccs_realpath_lock(void)
{
	spin_lock(&vfsmount_lock);
	spin_lock(&dcache_lock);
}
static inline void ccs_realpath_unlock(void)
{
	spin_unlock(&dcache_lock);
	spin_unlock(&vfsmount_lock);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)

static inline void ccs_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	spin_lock(&vfsmount_lock);
}
static inline void ccs_realpath_unlock(void)
{
	spin_unlock(&vfsmount_lock);
	spin_unlock(&dcache_lock);
}

#else

static inline void ccs_realpath_lock(void)
{
	spin_lock(&dcache_lock);
}
static inline void ccs_realpath_unlock(void)
{
	spin_unlock(&dcache_lock);
}

#endif

static inline struct ccs_domain_info *ccs_task_domain(struct task_struct *task)
{
	return task->ccs_domain_info ?
		task->ccs_domain_info : &ccs_kernel_domain;
}

static inline struct ccs_domain_info *ccs_current_domain(void)
{
	struct task_struct *task = current;
	if (!task->ccs_domain_info)
		task->ccs_domain_info = &ccs_kernel_domain;
	return task->ccs_domain_info;
}

#if 1

static inline int ccs_read_lock(void)
{
	struct task_struct *task = current;
	BUG_ON((task->ccs_flags & 15) == 15);
	task->ccs_flags++;
	return srcu_read_lock(&ccs_ss);
}

static inline void ccs_check_read_lock(void)
{
	if (ccs_policy_loaded)
		WARN_ON(!(current->ccs_flags & 15));
}

static inline void ccs_read_unlock(const int idx)
{
	struct task_struct *task = current;
	WARN_ON(!(task->ccs_flags & 15));
	task->ccs_flags--;
	srcu_read_unlock(&ccs_ss, idx);
}

#else

static inline int ccs_read_lock(void)
{
	return srcu_read_lock(&ccs_ss);
}

static inline void ccs_check_read_lock(void)
{
}

static inline void ccs_read_unlock(const int idx)
{
	srcu_read_unlock(&ccs_ss, idx);
}

#endif

#endif
