/*
 * security/ccsecurity/internal.h
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/24
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _SECURITY_CCSECURITY_INTERNAL_H
#define _SECURITY_CCSECURITY_INTERNAL_H

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
#endif
#include <linux/in6.h>
#include <linux/ccsecurity.h>
#include "compat.h"

/* Index numbers for Access Controls. */
enum ccs_acl_entry_type_index {
	CCS_TYPE_PATH_ACL,
	CCS_TYPE_PATH2_ACL,
	CCS_TYPE_PATH_NUMBER_ACL,
	CCS_TYPE_PATH_NUMBER3_ACL,
	CCS_TYPE_ENV_ACL,
	CCS_TYPE_CAPABILITY_ACL,
	CCS_TYPE_IP_NETWORK_ACL,
	CCS_TYPE_SIGNAL_ACL,
	CCS_TYPE_MOUNT_ACL,
	CCS_TYPE_UMOUNT_ACL,
	CCS_TYPE_CHROOT_ACL,
	CCS_TYPE_PIVOT_ROOT_ACL,
	CCS_TYPE_EXECUTE_HANDLER,
	CCS_TYPE_DENIED_EXECUTE_HANDLER
};

/*
 * CCS_TYPE_READ_WRITE is special. CCS_TYPE_READ_WRITE is automatically set if
 * both CCS_TYPE_READ and CCS_TYPE_WRITE are set. Both CCS_TYPE_READ and
 * CCS_TYPE_WRITE are automatically set if CCS_TYPE_READ_WRITE is set.
 * CCS_TYPE_READ_WRITE is automatically cleared if either CCS_TYPE_READ or
 * CCS_TYPE_WRITE is cleared. Both CCS_TYPE_READ and CCS_TYPE_WRITE are
 * automatically cleared if CCS_TYPE_READ_WRITE is cleared.
 */

enum ccs_path_acl_index {
	CCS_TYPE_READ_WRITE,
	CCS_TYPE_EXECUTE,
	CCS_TYPE_READ,
	CCS_TYPE_WRITE,
	CCS_TYPE_UNLINK,
	CCS_TYPE_RMDIR,
	CCS_TYPE_TRUNCATE,
	CCS_TYPE_SYMLINK,
	CCS_TYPE_REWRITE,
	CCS_MAX_PATH_OPERATION
};

enum ccs_path_number3_acl_index {
	CCS_TYPE_MKBLOCK,
	CCS_TYPE_MKCHAR,
	CCS_MAX_PATH_NUMBER3_OPERATION
};

enum ccs_path2_acl_index {
	CCS_TYPE_LINK,
	CCS_TYPE_RENAME,
	CCS_MAX_PATH2_OPERATION
};

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

enum ccs_network_acl_index {
	CCS_NETWORK_UDP_BIND,    /* UDP's bind() operation. */
	CCS_NETWORK_UDP_CONNECT, /* UDP's connect()/send()/recv() operation. */
	CCS_NETWORK_TCP_BIND,    /* TCP's bind() operation. */
	CCS_NETWORK_TCP_LISTEN,  /* TCP's listen() operation. */
	CCS_NETWORK_TCP_CONNECT, /* TCP's connect() operation. */
	CCS_NETWORK_TCP_ACCEPT,  /* TCP's accept() operation. */
	CCS_NETWORK_RAW_BIND,    /* IP's bind() operation. */
	CCS_NETWORK_RAW_CONNECT, /* IP's connect()/send()/recv() operation. */
	CCS_MAX_NETWORK_OPERATION
};

enum ccs_ip_address_type {
	CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP,
	CCS_IP_ADDRESS_TYPE_IPv4,
	CCS_IP_ADDRESS_TYPE_IPv6
};

/* Indexes for /proc/ccs/ interfaces. */
enum ccs_proc_interface_index {
	CCS_DOMAINPOLICY,
	CCS_EXCEPTIONPOLICY,
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
	CCS_EXECUTE_HANDLER
};

enum ccs_mac_index {
	CCS_MAC_FILE_EXECUTE,
	CCS_MAC_FILE_OPEN,
	CCS_MAC_FILE_CREATE,
	CCS_MAC_FILE_UNLINK,
	CCS_MAC_FILE_MKDIR,
	CCS_MAC_FILE_RMDIR,
	CCS_MAC_FILE_MKFIFO,
	CCS_MAC_FILE_MKSOCK,
	CCS_MAC_FILE_TRUNCATE,
	CCS_MAC_FILE_SYMLINK,
	CCS_MAC_FILE_REWRITE,
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
	CCS_MAC_NETWORK_UDP_BIND,
	CCS_MAC_NETWORK_UDP_CONNECT,
	CCS_MAC_NETWORK_TCP_BIND,
	CCS_MAC_NETWORK_TCP_LISTEN,
	CCS_MAC_NETWORK_TCP_CONNECT,
	CCS_MAC_NETWORK_TCP_ACCEPT,
	CCS_MAC_NETWORK_RAW_BIND,
	CCS_MAC_NETWORK_RAW_CONNECT,
	CCS_MAC_ENVIRON,
	CCS_MAC_SIGNAL,
	CCS_MAX_MAC_INDEX
};

enum ccs_mac_category_index {
	CCS_MAC_CATEGORY_FILE,
	CCS_MAC_CATEGORY_NETWORK,
	CCS_MAC_CATEGORY_MISC,
	CCS_MAC_CATEGORY_IPC,
	CCS_MAC_CATEGORY_CAPABILITY,
	CCS_MAX_MAC_CATEGORY_INDEX
};

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
	CCS_TASK_STATE_0,         /* (u8) (current->ccs_flags >> 24) */
	CCS_TASK_STATE_1,         /* (u8) (current->ccs_flags >> 16) */
	CCS_TASK_STATE_2,         /* (u8) (task->ccs_flags >> 8)     */
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
	CCS_SYMLINK_TARGET,
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
	CCS_ENVP_ENTRY
};

/* Keywords for ACLs. */
#define CCS_KEYWORD_ADDRESS_GROUP             "address_group "
#define CCS_KEYWORD_AGGREGATOR                "aggregator "
#define CCS_KEYWORD_ALLOW_CAPABILITY          "allow_capability "
#define CCS_KEYWORD_ALLOW_CHROOT              "allow_chroot "
#define CCS_KEYWORD_ALLOW_ENV                 "allow_env "
#define CCS_KEYWORD_ALLOW_IOCTL               "allow_ioctl "
#define CCS_KEYWORD_ALLOW_CHMOD               "allow_chmod "
#define CCS_KEYWORD_ALLOW_CHOWN               "allow_chown "
#define CCS_KEYWORD_ALLOW_CHGRP               "allow_chgrp "
#define CCS_KEYWORD_ALLOW_MOUNT               "allow_mount "
#define CCS_KEYWORD_ALLOW_NETWORK             "allow_network "
#define CCS_KEYWORD_ALLOW_PIVOT_ROOT          "allow_pivot_root "
#define CCS_KEYWORD_ALLOW_READ                "allow_read "
#define CCS_KEYWORD_ALLOW_SIGNAL              "allow_signal "
#define CCS_KEYWORD_DELETE                    "delete "
#define CCS_KEYWORD_DENY_AUTOBIND             "deny_autobind "
#define CCS_KEYWORD_DENY_REWRITE              "deny_rewrite "
#define CCS_KEYWORD_ALLOW_UNMOUNT             "allow_unmount "
#define CCS_KEYWORD_FILE_PATTERN              "file_pattern "
#define CCS_KEYWORD_INITIALIZE_DOMAIN         "initialize_domain "
#define CCS_KEYWORD_KEEP_DOMAIN               "keep_domain "
#define CCS_KEYWORD_NO_INITIALIZE_DOMAIN      "no_initialize_domain "
#define CCS_KEYWORD_NO_KEEP_DOMAIN            "no_keep_domain "
#define CCS_KEYWORD_PATH_GROUP                "path_group "
#define CCS_KEYWORD_NUMBER_GROUP              "number_group "
#define CCS_KEYWORD_SELECT                    "select "
#define CCS_KEYWORD_USE_PROFILE               "use_profile "
#define CCS_KEYWORD_IGNORE_GLOBAL_ALLOW_READ  "ignore_global_allow_read"
#define CCS_KEYWORD_IGNORE_GLOBAL_ALLOW_ENV   "ignore_global_allow_env"
#define CCS_KEYWORD_EXECUTE_HANDLER           "execute_handler"
#define CCS_KEYWORD_DENIED_EXECUTE_HANDLER    "denied_execute_handler"
#define CCS_KEYWORD_CAPABILITY                "capability::"

/* A domain definition starts with <kernel>. */
#define ROOT_NAME                         "<kernel>"
#define ROOT_NAME_LEN                     (sizeof(ROOT_NAME) - 1)

/* Value type definition. */
#define CCS_VALUE_TYPE_INVALID     0
#define CCS_VALUE_TYPE_DECIMAL     1
#define CCS_VALUE_TYPE_OCTAL       2
#define CCS_VALUE_TYPE_HEXADECIMAL 3

#define CCS_EXEC_TMPSIZE     4096

/* Profile number is an integer between 0 and 255. */
#define CCS_MAX_PROFILES 256

#define CCS_CONFIG_DISABLED          0
#define CCS_CONFIG_LEARNING          1
#define CCS_CONFIG_PERMISSIVE        2
#define CCS_CONFIG_ENFORCING         3
#define CCS_CONFIG_WANT_REJECT_LOG  64
#define CCS_CONFIG_WANT_GRANT_LOG  128
#define CCS_CONFIG_USE_DEFAULT     255

/* Lowest 2 bits are reserved for open() mode. */
#define CCS_USE_OPEN_MODE                 4
#define CCS_CHECK_READ_FOR_OPEN_EXEC     16
#define CCS_DONT_SLEEP_ON_ENFORCE_ERROR  32
#define CCS_TASK_IS_EXECUTE_HANDLER      64
#define CCS_TASK_IS_POLICY_MANAGER      128
/* Highest 24 bits are reserved for task.state[] conditions. */

struct dentry;
struct vfsmount;
struct in6_addr;
extern asmlinkage long sys_getpid(void);
extern asmlinkage long sys_getppid(void);

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
#define list_for_each_cookie(pos, cookie, head)				\
	for (({ if (!cookie)						\
				     cookie = head; }),			\
		     pos = rcu_dereference((cookie)->next);		\
	     prefetch(pos->next), pos != (head) || ((cookie) = NULL);	\
	     (cookie) = pos, pos = rcu_dereference(pos->next))

struct ccs_name_union {
	const struct ccs_path_info *filename;
	struct ccs_path_group *group;
	u8 is_group;
};

struct ccs_number_union {
	unsigned long values[2];
	struct ccs_number_group *group;
	u8 min_type;
	u8 max_type;
	u8 is_group;
};

/* Structure for "path_group" directive. */
struct ccs_path_group {
	struct list_head list;
	const struct ccs_path_info *group_name;
	struct list_head member_list;
	atomic_t users;
};

/* Structure for "number_group" directive. */
struct ccs_number_group {
	struct list_head list;
	const struct ccs_path_info *group_name;
	struct list_head member_list;
	atomic_t users;
};

/* Structure for "address_group" directive. */
struct ccs_address_group {
	struct list_head list;
	const struct ccs_path_info *group_name;
	struct list_head member_list;
	atomic_t users;
};

/* Structure for "path_group" directive. */
struct ccs_path_group_member {
	struct list_head list;
	bool is_deleted;
	const struct ccs_path_info *member_name;
};

/* Structure for "number_group" directive. */
struct ccs_number_group_member {
	struct list_head list;
	bool is_deleted;
	struct ccs_number_union number;
};

/* Structure for "address_group" directive. */
struct ccs_address_group_member {
	struct list_head list;
	bool is_deleted;
	bool is_ipv6;
	union {
		u32 ipv4;                    /* Host byte order    */
		const struct in6_addr *ipv6; /* Network byte order */
	} min, max;
};


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
	struct path path1;
	struct path path2;
	struct ccs_mini_stat path1_stat;
	/* I don't handle path2_stat for rename operation. */
	struct ccs_mini_stat path2_stat;
	struct ccs_mini_stat path1_parent_stat;
	struct ccs_mini_stat path2_parent_stat;
	struct ccs_path_info *symlink_target;
	unsigned int dev;
};

struct ccs_condition_element {
	/*
	 * Left hand operand. A "struct ccs_argv_entry" for CCS_ARGV_ENTRY, a
	 * "struct ccs_envp_entry" for CCS_ENVP_ENTRY is attached to the tail
	 * of the array of this struct.
	 */
	u8 left;
	/*
	 * Right hand operand. A "struct ccs_number_union" for
	 * CCS_NUMBER_UNION, a "struct ccs_name_union" for CCS_NAME_UNION is
	 * attached to the tail of the array of this struct.
	 */
	u8 right;
	/* Equation operator. true if equals or overlaps, false otherwise. */
	bool equals;
};

/* Structure for " if " and "; set" part. */
struct ccs_condition {
	struct list_head list;
	atomic_t users;
	u32 size;
	u16 condc;
	u16 numbers_count;
	u16 names_count;
	u16 argc;
	u16 envc;
	u8 post_state[4];
	/*
	 * struct ccs_condition_element condition[condc];
	 * struct ccs_number_union values[numbers_count];
	 * struct ccs_name_union names[names_count];
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
	u8 retry;
	u8 profile;
	u8 mode;
	u8 type;
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
	char *handler_path; /* = kstrdup(handler->name, GFP_KERNEL) */
	/* For dumping argv[] and envp[]. */
	struct ccs_page_dump dump;
	/* For temporary use. */
	char *tmp; /* Size is CCS_EXEC_TMPSIZE bytes */
};

/* Common header for holding ACL entries. */
struct ccs_acl_info {
	struct list_head list;
	struct ccs_condition *cond;
	bool is_deleted;
	u8 type; /* = one of values in "enum ccs_acl_entry_type_index" */
} __attribute__((__packed__));

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

/* Structure for "allow_read" keyword. */
struct ccs_globally_readable_file_entry {
	struct list_head list;
	bool is_deleted;
	const struct ccs_path_info *filename;
};

/* Structure for "file_pattern" keyword. */
struct ccs_pattern_entry {
	struct list_head list;
	bool is_deleted;
	const struct ccs_path_info *pattern;
};

/* Structure for "deny_rewrite" keyword. */
struct ccs_no_rewrite_entry {
	struct list_head list;
	bool is_deleted;
	const struct ccs_path_info *pattern;
};

/* Structure for "allow_env" keyword. */
struct ccs_globally_usable_env_entry {
	struct list_head list;
	bool is_deleted;
	const struct ccs_path_info *env;
};

/* Structure for "initialize_domain" and "no_initialize_domain" keyword. */
struct ccs_domain_initializer_entry {
	struct list_head list;
	bool is_deleted;
	bool is_not;       /* True if this entry is "no_initialize_domain". */
	bool is_last_name; /* True if the domainname is ccs_last_word(). */
	const struct ccs_path_info *domainname;    /* This may be NULL */
	const struct ccs_path_info *program;
};

/* Structure for "keep_domain" and "no_keep_domain" keyword. */
struct ccs_domain_keeper_entry {
	struct list_head list;
	bool is_deleted;
	bool is_not;       /* True if this entry is "no_keep_domain". */
	bool is_last_name; /* True if the domainname is ccs_last_word(). */
	const struct ccs_path_info *domainname;
	const struct ccs_path_info *program;       /* This may be NULL */
};

/* Structure for "aggregator" keyword. */
struct ccs_aggregator_entry {
	struct list_head list;
	bool is_deleted;
	const struct ccs_path_info *original_name;
	const struct ccs_path_info *aggregated_name;
};

/* Structure for "allow_unmount" keyword. */
struct ccs_umount_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_UMOUNT_ACL */
	struct ccs_name_union dir;
};

/* Structure for "allow_pivot_root" keyword. */
struct ccs_pivot_root_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PIVOT_ROOT_ACL */
	struct ccs_name_union old_root;
	struct ccs_name_union new_root;
};

/* Structure for "allow_mount" keyword. */
struct ccs_mount_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_MOUNT_ACL */
	struct ccs_name_union dev_name;
	struct ccs_name_union dir_name;
	struct ccs_name_union fs_type;
	struct ccs_number_union flags;
};

/* Structure for "allow_chroot" keyword. */
struct ccs_chroot_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_CHROOT_ACL */
	struct ccs_name_union dir;
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
	bool is_deleted; /* True if this entry is deleted. */
	bool is_domain;  /* True if manager is a domainname. */
	/* A path to program or a domainname. */
	const struct ccs_path_info *manager;
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
	struct ccs_acl_info head;        /* type = CCS_TYPE_*EXECUTE_HANDLER */
	const struct ccs_path_info *handler; /* Pointer to single pathname.  */
};

/*
 * Structure for "allow_read/write", "allow_execute", "allow_read",
 * "allow_write", "allow_unlink", "allow_rmdir", "allow_truncate",
 * "allow_symlink" and "allow_rewrite" directive.
 */
struct ccs_path_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PATH_ACL */
	u16 perm;
	struct ccs_name_union name;
};

/* Structure for "allow_mkblock" and "allow_mkchar" directive. */
struct ccs_path_number3_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PATH_NUMBER3_ACL */
	u8 perm;
	struct ccs_name_union name;
	struct ccs_number_union mode;
	struct ccs_number_union major;
	struct ccs_number_union minor;
};

/* Structure for "allow_rename" and "allow_link" directive. */
struct ccs_path2_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PATH2_ACL */
	u8 perm;
	struct ccs_name_union name1;
	struct ccs_name_union name2;
};

/*
 * Structure for "allow_create", "allow_mkdir", "allow_mkfifo", "allow_mksock",
 * "allow_ioctl", "allow_chmod", "allow_chown" and "allow_chgrp" directive.
 */
struct ccs_path_number_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_PATH_NUMBER_ACL */
	u8 perm;
	struct ccs_name_union name;
	struct ccs_number_union number;
};

/* Structure for "allow_env" directive in domain policy. */
struct ccs_env_acl {
	struct ccs_acl_info head;        /* type = CCS_TYPE_ENV_ACL  */
	const struct ccs_path_info *env; /* environment variable */
};

/* Structure for "allow_capability" directive. */
struct ccs_capability_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_CAPABILITY_ACL */
	u8 operation;
};

/* Structure for "allow_signal" directive. */
struct ccs_signal_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_SIGNAL_ACL */
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
struct ccs_ip_network_acl {
	struct ccs_acl_info head; /* type = CCS_TYPE_IP_NETWORK_ACL */
	u16 perm;
	/*
	 * address_type takes one of the following constants.
	 *   CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP
	 *                if address points to "address_group" directive.
	 *   CCS_IP_ADDRESS_TYPE_IPv4
	 *                if address points to an IPv4 address.
	 *   CCS_IP_ADDRESS_TYPE_IPv6
	 *                if address points to an IPv6 address.
	 */
	u8 address_type;
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
		struct ccs_address_group *group;
	} address;
	struct ccs_number_union port;
};


/* Structure for reading/writing policy via /proc interfaces. */
struct ccs_io_buffer {
	void (*read) (struct ccs_io_buffer *);
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

struct ccs_profile {
	const struct ccs_path_info *comment;
	unsigned int audit_max_grant_log;
	unsigned int audit_max_reject_log;
	unsigned int enforcing_penalty;
	unsigned int learning_max_entry;
	bool enforcing_verbose;
	bool permissive_verbose;
	bool learning_verbose;
	bool learning_exec_realpath;
	bool learning_exec_argv0;
	u8 default_config;
	u8 config[CCS_MAX_MAC_INDEX + CCS_MAX_CAPABILITY_INDEX
		  + CCS_MAX_MAC_CATEGORY_INDEX];
};

/* Prototype definition. */

bool ccs_address_matches_group(const bool is_ipv6, const u32 *address,
			       const struct ccs_address_group *group);
bool ccs_commit_ok(void *ptr, void *data, const unsigned int size);
bool ccs_compare_name_union(const struct ccs_path_info *name,
			    const struct ccs_name_union *ptr);
bool ccs_compare_number_union(const unsigned long value,
			      const struct ccs_number_union *ptr);
bool ccs_condition(struct ccs_request_info *r, const struct ccs_acl_info *acl);
bool ccs_domain_quota_ok(struct ccs_request_info *r);
bool ccs_dump_page(struct linux_binprm *bprm, unsigned long pos,
		   struct ccs_page_dump *dump);
bool ccs_get_audit(const u8 profile, const u8 index, const bool is_granted);
bool ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...)
     __attribute__ ((format(printf, 2, 3)));
bool ccs_is_correct_domain(const unsigned char *domainname);
bool ccs_is_correct_path(const char *filename, const s8 start_type,
			 const s8 pattern_type, const s8 end_type);
bool ccs_is_domain_def(const unsigned char *buffer);
bool ccs_memory_ok(const void *ptr, const unsigned int size);
bool ccs_number_matches_group(const unsigned long min, const unsigned long max,
			      const struct ccs_number_group *group);
bool ccs_parse_name_union(const char *filename, struct ccs_name_union *ptr);
bool ccs_parse_number_union(char *data, struct ccs_number_union *num);
bool ccs_path_matches_group(const struct ccs_path_info *pathname,
			    const struct ccs_path_group *group,
			    const bool may_use_pattern);
bool ccs_path_matches_pattern(const struct ccs_path_info *filename,
			      const struct ccs_path_info *pattern);
bool ccs_print_number_union(struct ccs_io_buffer *head,
			    const struct ccs_number_union *ptr);
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
char *ccs_encode(const char *str);
char *ccs_init_audit_log(int *len, struct ccs_request_info *r);
char *ccs_realpath_from_path(struct path *path);
const char *ccs_cap2keyword(const u8 operation);
const char *ccs_file_pattern(const struct ccs_path_info *filename);
const char *ccs_get_exe(void);
const char *ccs_last_word(const char *name);
const char *ccs_net2keyword(const u8 operation);
const char *ccs_path22keyword(const u8 operation);
const char *ccs_path2keyword(const u8 operation);
const char *ccs_path_number2keyword(const u8 operation);
const char *ccs_path_number32keyword(const u8 operation);
const struct ccs_path_info *ccs_get_name(const char *name);
const struct in6_addr *ccs_get_ipv6_address(const struct in6_addr *addr);
int ccs_close_control(struct file *file);
int ccs_delete_domain(char *data);
int ccs_env_perm(struct ccs_request_info *r, const char *env);
int ccs_exec_perm(struct ccs_request_info *r,
		  const struct ccs_path_info *filename);
int ccs_get_mode(const u8 profile, const u8 index);
int ccs_get_path(const char *pathname, struct path *path);
int ccs_init_request_info(struct ccs_request_info *r,
			  struct ccs_domain_info *domain, const u8 index);
int ccs_open_control(const u8 type, struct file *file);
int ccs_parse_ip_address(char *address, u16 *min, u16 *max);
int ccs_poll_control(struct file *file, poll_table *wait);
int ccs_poll_grant_log(struct file *file, poll_table *wait);
int ccs_poll_reject_log(struct file *file, poll_table *wait);
int ccs_read_control(struct file *file, char __user *buffer,
		     const int buffer_len);
int ccs_read_lock(void);
int ccs_supervisor(struct ccs_request_info *r, const char *fmt, ...)
     __attribute__ ((format(printf, 2, 3)));
int ccs_symlink_path(const char *pathname, struct ccs_path_info *name);
int ccs_write_address_group_policy(char *data, const bool is_delete);
int ccs_write_aggregator_policy(char *data, const bool is_delete);
int ccs_write_audit_log(const bool is_granted, struct ccs_request_info *r,
			const char *fmt, ...)
     __attribute__ ((format(printf, 3, 4)));
int ccs_write_capability_policy(char *data, struct ccs_domain_info *domain,
				struct ccs_condition *condition,
				const bool is_delete);
int ccs_write_chroot_policy(char *data, struct ccs_domain_info *domain,
			    struct ccs_condition *condition,
			    const bool is_delete);
int ccs_write_control(struct file *file, const char __user *buffer,
		      const int buffer_len);
int ccs_write_domain_initializer_policy(char *data, const bool is_not,
					const bool is_delete);
int ccs_write_domain_keeper_policy(char *data, const bool is_not,
				   const bool is_delete);
int ccs_write_env_policy(char *data, struct ccs_domain_info *domain,
			 struct ccs_condition *condition,
			 const bool is_delete);
int ccs_write_file_policy(char *data, struct ccs_domain_info *domain,
			  struct ccs_condition *condition,
			  const bool is_delete);
int ccs_write_globally_readable_policy(char *data, const bool is_delete);
int ccs_write_globally_usable_env_policy(char *data, const bool is_delete);
int ccs_write_memory_quota(struct ccs_io_buffer *head);
int ccs_write_mount_policy(char *data, struct ccs_domain_info *domain,
			   struct ccs_condition *condition,
			   const bool is_delete);
int ccs_write_network_policy(char *data, struct ccs_domain_info *domain,
			     struct ccs_condition *condition,
			     const bool is_delete);
int ccs_write_no_rewrite_policy(char *data, const bool is_delete);
int ccs_write_number_group_policy(char *data, const bool is_delete);
int ccs_write_path_group_policy(char *data, const bool is_delete);
int ccs_write_pattern_policy(char *data, const bool is_delete);
int ccs_write_pivot_root_policy(char *data, struct ccs_domain_info *domain,
				struct ccs_condition *condition,
				const bool is_delete);
int ccs_write_reserved_port_policy(char *data, const bool is_delete);
int ccs_write_signal_policy(char *data, struct ccs_domain_info *domain,
			    struct ccs_condition *condition,
			    const bool is_delete);
int ccs_write_umount_policy(char *data, struct ccs_domain_info *domain,
			    struct ccs_condition *condition,
			    const bool is_delete);
struct ccs_address_group *ccs_get_address_group(const char *group_name);
struct ccs_condition *ccs_get_condition(char * const condition);
struct ccs_domain_info *ccs_fetch_next_domain(void);
struct ccs_domain_info *ccs_find_domain(const char *domainname);
struct ccs_domain_info *ccs_find_or_assign_new_domain(const char *domainname,
						      const u8 profile);
struct ccs_number_group *ccs_get_number_group(const char *group_name);
struct ccs_path_group *ccs_get_path_group(const char *group_name);
struct ccs_profile *ccs_profile(const u8 profile);
u8 ccs_parse_ulong(unsigned long *result, char **str);
void ccs_fill_path_info(struct ccs_path_info *ptr);
void ccs_load_policy(const char *filename);
void ccs_memory_free(const void *ptr, size_t size);
void ccs_normalize_line(unsigned char *buffer);
void ccs_print_ipv6(char *buffer, const int buffer_len,
		    const struct in6_addr *ip);
void ccs_print_ulong(char *buffer, const int buffer_len,
		     const unsigned long value, const u8 type);
void ccs_put_address_group(struct ccs_address_group *group);
void ccs_put_condition(struct ccs_condition *cond);
void ccs_put_ipv6_address(const struct in6_addr *addr);
void ccs_put_name(const struct ccs_path_info *name);
void ccs_put_name_union(struct ccs_name_union *ptr);
void ccs_put_number_group(struct ccs_number_group *group);
void ccs_put_number_union(struct ccs_number_union *ptr);
void ccs_put_path_group(struct ccs_path_group *group);
void ccs_read_grant_log(struct ccs_io_buffer *head);
void ccs_read_memory_counter(struct ccs_io_buffer *head);
void ccs_read_reject_log(struct ccs_io_buffer *head);
void ccs_read_unlock(const int idx);
void ccs_run_gc(void);
void ccs_warn_log(struct ccs_request_info *r, const char *fmt, ...)
     __attribute__ ((format(printf, 2, 3)));
void ccs_warn_oom(const char *function);

/* strcmp() for "struct ccs_path_info" structure. */
static inline bool ccs_pathcmp(const struct ccs_path_info *a,
			       const struct ccs_path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}

static inline int ccs_memcmp(void *a, void *b, const u8 offset, const u8 size)
{
	return memcmp(((char *) a) + offset, ((char *) b) + offset,
		      size - offset);
}

extern struct mutex ccs_policy_lock;
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
extern struct list_head ccs_reservedport_list;
extern struct list_head ccs_policy_manager_list;

extern bool ccs_policy_loaded;
extern struct ccs_domain_info ccs_kernel_domain;

extern const char *ccs_condition_keyword[CCS_MAX_CONDITION_KEYWORD];

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

static inline void ccs_add_domain_acl(struct ccs_domain_info *domain,
				      struct ccs_acl_info *acl)
{
	if (acl->cond)
		atomic_inc(&acl->cond->users);
	list_add_tail_rcu(&acl->list, &domain->acl_info_list);
}

#if defined(CONFIG_SLOB)
static inline int ccs_round2(size_t size)
{
	return size;
}
#else
static inline int ccs_round2(size_t size)
{
#if PAGE_SIZE == 4096
	size_t bsize = 32;
#else
	size_t bsize = 64;
#endif
	if (!size)
		return 0;
	while (size > bsize)
		bsize <<= 1;
	return bsize;
}
#endif

#endif
