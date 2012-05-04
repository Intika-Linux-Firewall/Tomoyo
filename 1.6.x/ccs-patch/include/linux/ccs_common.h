/*
 * include/linux/ccs_common.h
 *
 * Common functions for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/05/05
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

struct dentry;
struct vfsmount;
struct in6_addr;
extern asmlinkage long sys_getpid(void);
extern asmlinkage long sys_getppid(void);

#include <linux/ccs_compat.h>

/*
 * Singly linked list.
 *
 * This list holds ACL entries used for access control.
 * Since TOMOYO Linux performs string pattern matching which takes long time,
 * I don't want to take any locks which disable preemption.
 * Threfore, I use singly linked list that cannot delete an element
 * but can make the code read-lock free.
 * This is OK because ACL entries in this list are seldom deleted.
 * You don't append garbage ACL entries without reasons, do you?
 */
struct list1_head {
	struct list1_head *next;
};

#define LIST1_HEAD_INIT(name) { &(name) }
#define LIST1_HEAD(name) struct list1_head name = LIST1_HEAD_INIT(name)

static inline void INIT_LIST1_HEAD(struct list1_head *list)
{
	list->next = list;
}

/* Reuse list_entry because it doesn't use "->prev" pointer. */
#define list1_entry list_entry

/* Reuse list_for_each_rcu because it doesn't use "->prev" pointer. */
#define list1_for_each list_for_each_rcu

/* Reuse list_for_each_entry_rcu because it doesn't use "->prev" pointer. */
#define list1_for_each_entry list_for_each_entry_rcu

/**
 * list1_for_each_cookie - iterate over a list with cookie.
 * @pos:        the &struct list1_head to use as a loop cursor.
 * @cookie:     the &struct list1_head to use as a cookie.
 * @head:       the head for your list.
 *
 * Same with list_for_each_rcu() except that this primitive uses @cookie
 * so that we can continue iteration.
 * @cookie must be NULL when iteration starts, and @cookie will become
 * NULL when iteration finishes.
 *
 * Since list elements are never removed, we don't need to get a lock
 * or a reference count.
 */
#define list1_for_each_cookie(pos, cookie, head)                      \
	for (({ if (!cookie)                                          \
				     cookie = head; }),               \
	     pos = rcu_dereference((cookie)->next);                   \
	     prefetch(pos->next), pos != (head) || ((cookie) = NULL); \
	     (cookie) = pos, pos = rcu_dereference(pos->next))

/**
 * list_add_tail_mb - add a new entry with memory barrier.
 * @new: new entry to be added.
 * @head: list head to add it before.
 *
 * Same with list_add_tail_rcu() except that this primitive uses mb()
 * so that we can traverse forwards using list1_for_each() and
 * list1_for_each_cookie().
 */
static inline void list1_add_tail_mb(struct list1_head *new,
				     struct list1_head *head)
{
	struct list1_head *prev = head;
	new->next = head;
	while (prev->next != head)
		prev = prev->next;
	rcu_assign_pointer(prev->next, new);
}

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
	bool path2_parent_valid;
	struct dentry *path1_dentry;
	struct vfsmount *path1_vfsmnt;
	struct dentry *path2_dentry;
	struct vfsmount *path2_vfsmnt;
	struct ccs_mini_stat path1_stat;
	/* I don't handle path2_stat for rename operation. */
	struct ccs_mini_stat path1_parent_stat;
	struct ccs_mini_stat path2_parent_stat;
	struct ccs_path_info *symlink_target;
};

/* Structure for " if " and "; set" part. */
struct ccs_condition_list {
	struct list1_head list;
	u16 condc;
	u16 argc;
	u16 envc;
	u16 symlinkc;
	u8 post_state[4];
	/* "unsigned long condition[condc]" follows here. */
	/* "struct ccs_argv_entry argv[argc]" follows here. */
	/* "struct ccs_envp_entry envp[envc]" follows here. */
	/* "struct ccs_symlinkp_entry symlinkp[symlinkc]" follows here. */
};

struct ccs_execve_entry;

/* Structure for request info. */
struct ccs_request_info {
	struct ccs_domain_info *domain;
	struct ccs_obj_info *obj;
	struct ccs_execve_entry *ee;
	const struct ccs_condition_list *cond;
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
	/* For execute_handler */
	const struct ccs_path_info *handler;
	/* For calculating domain to transit to. */
	struct ccs_domain_info *next_domain; /* Initialized to NULL. */
	char *program_path; /* Size is CCS_MAX_PATHNAME_LEN bytes */
	/* For dumping argv[] and envp[]. */
	struct ccs_page_dump dump;
	/* For temporary use. */
	char *tmp; /* Size is CCS_EXEC_TMPSIZE bytes */
};

/* Structure for "path_group" directive. */
struct ccs_path_group_member {
	struct list1_head list;
	const struct ccs_path_info *member_name;
	bool is_deleted;
};

/* Structure for "path_group" directive. */
struct ccs_path_group_entry {
	struct list1_head list;
	const struct ccs_path_info *group_name;
	struct list1_head path_group_member_list;
};

/* Structure for "address_group" directive. */
struct ccs_address_group_member {
	struct list1_head list;
	union {
		u32 ipv4;                    /* Host byte order    */
		const struct in6_addr *ipv6; /* Network byte order */
	} min, max;
	bool is_deleted;
	bool is_ipv6;
};

/* Structure for "address_group" directive. */
struct ccs_address_group_entry {
	struct list1_head list;
	const struct ccs_path_info *group_name;
	struct list1_head address_group_member_list;
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
	/*
	 * Keep "access_me_via_ccs_get_condition_part" first, for
	 * memory for this filed is not allocated if
	 * (type & ACL_WITH_CONDITION) == 0.
	 */
	const struct ccs_condition_list *access_me_via_ccs_get_condition_part;
	struct list1_head list;
	/*
	 * Type of this ACL entry.
	 *
	 * MSB is is_deleted flag.
	 * Next bit is with_condition flag.
	 */
	u8 type;
} __attribute__((__packed__));

/* Index numbers for Access Controls. */
enum ccs_acl_entry_type_index {
	TYPE_SINGLE_PATH_ACL,
	TYPE_DOUBLE_PATH_ACL,
	TYPE_IOCTL_ACL,
	TYPE_ARGV0_ACL,
	TYPE_ENV_ACL,
	TYPE_CAPABILITY_ACL,
	TYPE_IP_NETWORK_ACL,
	TYPE_SIGNAL_ACL,
	TYPE_EXECUTE_HANDLER,
	TYPE_DENIED_EXECUTE_HANDLER
};

/* This ACL entry is deleted.           */
#define ACL_DELETED        0x80
/* This ACL entry has conditional part. */
#define ACL_WITH_CONDITION 0x40

/* Structure for domain information. */
struct ccs_domain_info {
	struct list1_head list;
	struct list1_head acl_info_list;
	/* Name of this domain. Never NULL.          */
	const struct ccs_path_info *domainname;
	u8 profile;        /* Profile number to use. */
	bool is_deleted;   /* Delete flag.           */
	bool quota_warned; /* Quota warnning flag.   */
	/* DOMAIN_FLAGS_*. Use ccs_set_domain_flag() to modify. */
	u8 flags;
};

/* Profile number is an integer between 0 and 255. */
#define MAX_PROFILES 256

/* Ignore "allow_read" directive in exception policy. */
#define DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_READ 1
/* Ignore "allow_env" directive in exception policy.  */
#define DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_ENV  2
/*
 * This domain was unable to create a new domain at ccs_find_next_domain()
 * because the name of the domain to be created was too long or
 * it could not allocate memory.
 * More than one process continued execve() without domain transition.
 */
#define DOMAIN_FLAGS_TRANSITION_FAILED        4

#define CCS_CHECK_READ_FOR_OPEN_EXEC    1
#define CCS_DONT_SLEEP_ON_ENFORCE_ERROR 2
#define CCS_TASK_IS_EXECUTE_HANDLER     4
#define CCS_TASK_IS_POLICY_MANAGER      8

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

/*
 * Structure for "allow_read/write", "allow_execute", "allow_read",
 * "allow_write", "allow_create", "allow_unlink", "allow_mkdir", "allow_rmdir",
 * "allow_mkfifo", "allow_mksock", "allow_mkblock", "allow_mkchar",
 * "allow_truncate", "allow_symlink" and "allow_rewrite" directive.
 */
struct ccs_single_path_acl_record {
	struct ccs_acl_info head; /* type = TYPE_SINGLE_PATH_ACL */
	bool u_is_group; /* True if u points to "path_group" directive. */
	u16 perm;
	union {
		/* Pointer to single pathname. */
		const struct ccs_path_info *filename;
		/* Pointer to pathname group. */
		const struct ccs_path_group_entry *group;
	} u;
};

/* Structure for "allow_rename" and "allow_link" directive. */
struct ccs_double_path_acl_record {
	struct ccs_acl_info head; /* type = TYPE_DOUBLE_PATH_ACL */
	u8 perm;
	bool u1_is_group; /* True if u1 points to "path_group" directive. */
	bool u2_is_group; /* True if u2 points to "path_group" directive. */
	union {
		/* Pointer to single pathname. */
		const struct ccs_path_info *filename1;
		/* Pointer to pathname group. */
		const struct ccs_path_group_entry *group1;
	} u1;
	union {
		/* Pointer to single pathname. */
		const struct ccs_path_info *filename2;
		/* Pointer to pathname group. */
		const struct ccs_path_group_entry *group2;
	} u2;
};

/* Structure for "allow_ioctl" directive. */
struct ccs_ioctl_acl_record {
	struct ccs_acl_info head; /* type = TYPE_IOCTL_ACL */
	unsigned int cmd_min;
	unsigned int cmd_max;
	bool u_is_group; /* True if u points to "path_group" directive. */
	union {
		/* Pointer to single pathname. */
		const struct ccs_path_info *filename;
		/* Pointer to pathname group. */
		const struct ccs_path_group_entry *group;
	} u;
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
	 *                if u points to "address_group" directive.
	 *   IP_RECORD_TYPE_IPv4
	 *                if u points to an IPv4 address.
	 *   IP_RECORD_TYPE_IPv6
	 *                if u points to an IPv6 address.
	 */
	u8 record_type;
	/* Start of port number range. */
	u16 min_port;
	/* End of port number range.   */
	u16 max_port;
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
		const struct ccs_address_group_entry *group;
	} u;
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
	TYPE_MKBLOCK_ACL,
	TYPE_MKCHAR_ACL,
	TYPE_TRUNCATE_ACL,
	TYPE_SYMLINK_ACL,
	TYPE_REWRITE_ACL,
	MAX_SINGLE_PATH_OPERATION
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
#define KEYWORD_ALIAS                     "alias "
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
#define KEYWORD_DENY_UNMOUNT              "deny_unmount "
#define KEYWORD_FILE_PATTERN              "file_pattern "
#define KEYWORD_INITIALIZE_DOMAIN         "initialize_domain "
#define KEYWORD_KEEP_DOMAIN               "keep_domain "
#define KEYWORD_NO_INITIALIZE_DOMAIN      "no_initialize_domain "
#define KEYWORD_NO_KEEP_DOMAIN            "no_keep_domain "
#define KEYWORD_PATH_GROUP                "path_group "
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
	CCS_DENY_CONCEAL_MOUNT,
	CCS_RESTRICT_CHROOT,       /* system_policy.conf */
	CCS_RESTRICT_MOUNT,        /* system_policy.conf */
	CCS_RESTRICT_UNMOUNT,      /* system_policy.conf */
	CCS_RESTRICT_PIVOT_ROOT,   /* system_policy.conf */
	CCS_RESTRICT_AUTOBIND,     /* system_policy.conf */
	CCS_MAX_ACCEPT_ENTRY,
#ifdef CONFIG_TOMOYO_AUDIT
	CCS_MAX_GRANT_LOG,
	CCS_MAX_REJECT_LOG,
#endif
	CCS_VERBOSE,
	CCS_SLEEP_PERIOD,
	CCS_MAX_CONTROL_INDEX
};

/* Index numbers for updates counter. */
enum ccs_update_counter_index {
	CCS_UPDATES_COUNTER_SYSTEM_POLICY,
	CCS_UPDATES_COUNTER_DOMAIN_POLICY,
	CCS_UPDATES_COUNTER_EXCEPTION_POLICY,
	CCS_UPDATES_COUNTER_PROFILE,
	CCS_UPDATES_COUNTER_QUERY,
	CCS_UPDATES_COUNTER_MANAGER,
#ifdef CONFIG_TOMOYO_AUDIT
	CCS_UPDATES_COUNTER_GRANT_LOG,
	CCS_UPDATES_COUNTER_REJECT_LOG,
#endif
	MAX_CCS_UPDATES_COUNTER
};

/* Structure for reading/writing policy via /proc interfaces. */
struct ccs_io_buffer {
	int (*read) (struct ccs_io_buffer *);
	int (*write) (struct ccs_io_buffer *);
	unsigned int (*poll) (struct file *file, poll_table *wait);
	/* Exclusive lock for this structure.   */
	struct mutex io_sem;
	/* The position currently reading from. */
	struct list1_head *read_var1;
	/* Extra variables for reading.         */
	struct list1_head *read_var2;
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
};

/* Prototype definition. */
struct ccs_condition_list;

/* Check conditional part of an ACL entry. */
bool ccs_check_condition(struct ccs_request_info *r,
			 const struct ccs_acl_info *acl);
/* Check whether the domain has too many ACL entries to hold. */
bool ccs_domain_quota_ok(struct ccs_domain_info * const domain);
/* Dump a page to buffer. */
bool ccs_dump_page(struct linux_binprm *bprm, unsigned long pos,
		   struct ccs_page_dump *dump);
/* Transactional sprintf() for policy dump. */
bool ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...)
     __attribute__ ((format(printf, 2, 3)));
/* Check whether the domainname is correct. */
bool ccs_is_correct_domain(const unsigned char *domainname,
			   const char *function);
/* Check whether the token is correct. */
bool ccs_is_correct_path(const char *filename, const s8 start_type,
			 const s8 pattern_type, const s8 end_type,
			 const char *function);
/* Check whether the token can be a domainname. */
bool ccs_is_domain_def(const unsigned char *buffer);
/* Format string. */
void ccs_normalize_line(unsigned char *buffer);
/* Check whether the given filename matches the given pattern. */
bool ccs_path_matches_pattern(const struct ccs_path_info *filename,
			      const struct ccs_path_info *pattern);
/* Print conditional part of an ACL entry. */
bool ccs_print_condition(struct ccs_io_buffer *head,
			 const struct ccs_condition_list *cond);
/* Read "address_group" entry in exception policy. */
bool ccs_read_address_group_policy(struct ccs_io_buffer *head);
/* Read "aggregator" entry in exception policy. */
bool ccs_read_aggregator_policy(struct ccs_io_buffer *head);
/* Read "alias" entry in exception policy. */
bool ccs_read_alias_policy(struct ccs_io_buffer *head);
/* Read "allow_chroot" entry in system policy. */
bool ccs_read_chroot_policy(struct ccs_io_buffer *head);
/*
 * Read "initialize_domain" and "no_initialize_domain" entry
 * in exception policy.
 */
bool ccs_read_domain_initializer_policy(struct ccs_io_buffer *head);
/* Read "keep_domain" and "no_keep_domain" entry in exception policy. */
bool ccs_read_domain_keeper_policy(struct ccs_io_buffer *head);
/* Read "file_pattern" entry in exception policy. */
bool ccs_read_file_pattern(struct ccs_io_buffer *head);
/* Read "allow_read" entry in exception policy. */
bool ccs_read_globally_readable_policy(struct ccs_io_buffer *head);
/* Read "allow_env" entry in exception policy. */
bool ccs_read_globally_usable_env_policy(struct ccs_io_buffer *head);
/* Read "allow_mount" entry in system policy. */
bool ccs_read_mount_policy(struct ccs_io_buffer *head);
/* Read "deny_rewrite" entry in exception policy. */
bool ccs_read_no_rewrite_policy(struct ccs_io_buffer *head);
/* Read "deny_unmount" entry in system policy. */
bool ccs_read_no_umount_policy(struct ccs_io_buffer *head);
/* Read "path_group" entry in exception policy. */
bool ccs_read_path_group_policy(struct ccs_io_buffer *head);
/* Read "allow_pivot_root" entry in system policy. */
bool ccs_read_pivot_root_policy(struct ccs_io_buffer *head);
/* Read "deny_autobind" entry in system policy. */
bool ccs_read_reserved_port_policy(struct ccs_io_buffer *head);
/* Write domain policy violation warning message to console? */
bool ccs_verbose_mode(const struct ccs_domain_info *domain);
/* Allocate buffer for domain policy auditing. */
char *ccs_init_audit_log(int *len, struct ccs_request_info *r);
/* Convert capability index to capability name. */
const char *ccs_cap2keyword(const u8 operation);
/* Convert double path operation to operation name. */
const char *ccs_dp2keyword(const u8 operation);
/* Get the pathname of current process. */
const char *ccs_get_exe(void);
/* Get the last component of the given domainname. */
const char *ccs_get_last_name(const struct ccs_domain_info *domain);
/* Get warning message. */
const char *ccs_get_msg(const bool is_enforce);
/* Convert network operation index to operation name. */
const char *ccs_net2keyword(const u8 operation);
/* Convert single path operation to operation name. */
const char *ccs_sp2keyword(const u8 operation);
/* Fetch next_domain from the list. */
struct ccs_domain_info *ccs_fetch_next_domain(void);
/* Create conditional part of an ACL entry. */
const struct ccs_condition_list *
ccs_find_or_assign_new_condition(char * const condition);
/* Create conditional part for execute_handler process. */
const struct ccs_condition_list *ccs_handler_cond(void);
/* Add an ACL entry to domain's ACL list. */
int ccs_add_domain_acl(struct ccs_domain_info *domain,
		       struct ccs_acl_info *acl);
/* Ask supervisor's opinion. */
int ccs_check_supervisor(struct ccs_request_info *r,
			 const char *fmt, ...)
     __attribute__ ((format(printf, 2, 3)));
/* Close /proc/ccs/ interface. */
int ccs_close_control(struct file *file);
/* Delete an ACL entry from domain's ACL list. */
int ccs_del_domain_acl(struct ccs_acl_info *acl);
/* Delete a domain. */
int ccs_delete_domain(char *data);
/* Open operation for /proc/ccs/ interface. */
int ccs_open_control(const u8 type, struct file *file);
/* Poll operation for /proc/ccs/ interface. */
unsigned int ccs_poll_control(struct file *file, poll_table *wait);
/* Check whether there is a grant log. */
unsigned int ccs_poll_grant_log(struct file *file, poll_table *wait);
/* Check whether there is a reject log. */
unsigned int ccs_poll_reject_log(struct file *file, poll_table *wait);
/* Read operation for /proc/ccs/ interface. */
int ccs_read_control(struct file *file, char __user *buffer,
		     const int buffer_len);
/* Read a grant log. */
int ccs_read_grant_log(struct ccs_io_buffer *head);
/* Read a reject log. */
int ccs_read_reject_log(struct ccs_io_buffer *head);
/* Add "address_group" entry in exception policy. */
int ccs_write_address_group_policy(char *data, const bool is_delete);
/* Create "aggregator" entry in exception policy. */
int ccs_write_aggregator_policy(char *data, const bool is_delete);
/* Create "alias" entry in exception policy. */
int ccs_write_alias_policy(char *data, const bool is_delete);
/* Create "allow_argv0" entry in domain policy. */
int ccs_write_argv0_policy(char *data, struct ccs_domain_info *domain,
			   const struct ccs_condition_list *condition,
			   const bool is_delete);
/* Write an audit log. */
int ccs_write_audit_log(const bool is_granted, struct ccs_request_info *r,
			const char *fmt, ...)
     __attribute__ ((format(printf, 3, 4)));
/* Create "allow_capability" entry in domain policy. */
int ccs_write_capability_policy(char *data, struct ccs_domain_info *domain,
				const struct ccs_condition_list *condition,
				const bool is_delete);
/* Create "allow_chroot" entry in system policy. */
int ccs_write_chroot_policy(char *data, const bool is_delete);
/*
 * Create "initialize_domain" and "no_initialize_domain" entry
 * in exception policy.
 */
int ccs_write_domain_initializer_policy(char *data, const bool is_not,
					const bool is_delete);
/* Create "keep_domain" and "no_keep_domain" entry in exception policy. */
int ccs_write_domain_keeper_policy(char *data, const bool is_not,
				   const bool is_delete);
/* Create "allow_env" entry in domain policy. */
int ccs_write_env_policy(char *data, struct ccs_domain_info *domain,
			 const struct ccs_condition_list *condition,
			 const bool is_delete);
/*
 * Create "allow_read/write", "allow_execute", "allow_read", "allow_write",
 * "allow_create", "allow_unlink", "allow_mkdir", "allow_rmdir",
 * "allow_mkfifo", "allow_mksock", "allow_mkblock", "allow_mkchar",
 * "allow_truncate", "allow_symlink", "allow_rewrite", "allow_rename",
 * "allow_link", "execute_handler" and "denied_execute_handler"
 * entry in domain policy.
 */
int ccs_write_file_policy(char *data, struct ccs_domain_info *domain,
			  const struct ccs_condition_list *condition,
			  const bool is_delete);
/* Create "allow_read" entry in exception policy. */
int ccs_write_globally_readable_policy(char *data, const bool is_delete);
/* Create "allow_env" entry in exception policy. */
int ccs_write_globally_usable_env_policy(char *data, const bool is_delete);
/* Create "allow_ioctl" entry in domain policy. */
int ccs_write_ioctl_policy(char *data, struct ccs_domain_info *domain,
			   const struct ccs_condition_list *condition,
			   const bool is_delete);
/* Create "allow_mount" entry in system policy. */
int ccs_write_mount_policy(char *data, const bool is_delete);
/* Create "allow_network" entry in domain policy. */
int ccs_write_network_policy(char *data, struct ccs_domain_info *domain,
			     const struct ccs_condition_list *condition,
			     const bool is_delete);
/* Create "deny_rewrite" entry in exception policy. */
int ccs_write_no_rewrite_policy(char *data, const bool is_delete);
/* Create "deny_unmount" entry in system policy. */
int ccs_write_no_umount_policy(char *data, const bool is_delete);
/* Create "path_group" entry in exception policy. */
int ccs_write_path_group_policy(char *data, const bool is_delete);
/* Create "file_pattern" entry in exception policy. */
int ccs_write_pattern_policy(char *data, const bool is_delete);
/* Create "allow_pivot_root" entry in system policy. */
int ccs_write_pivot_root_policy(char *data, const bool is_delete);
/* Create "deny_autobind" entry in system policy. */
int ccs_write_reserved_port_policy(char *data, const bool is_delete);
/* Create "allow_signal" entry in domain policy. */
int ccs_write_signal_policy(char *data, struct ccs_domain_info *domain,
			    const struct ccs_condition_list *condition,
			    const bool is_delete);
/* Write operation for /proc/ccs/ interface. */
int ccs_write_control(struct file *file, const char __user *buffer,
		      const int buffer_len);
/* Find a domain by the given name. */
struct ccs_domain_info *ccs_find_domain(const char *domainname);
/* Find or create a domain by the given name. */
struct ccs_domain_info *ccs_find_or_assign_new_domain(const char *domainname,
						  const u8 profile);
/* Check mode for specified functionality. */
unsigned int ccs_check_flags(const struct ccs_domain_info *domain,
			     const u8 index);
/* Check whether it is safe to sleep. */
bool ccs_can_sleep(void);
/* Allocate memory for structures. */
void *ccs_alloc_acl_element(const u8 acl_type,
			    const struct ccs_condition_list *condition);
/* Fill in "struct ccs_path_info" members. */
void ccs_fill_path_info(struct ccs_path_info *ptr);
/* Fill in "struct ccs_request_info" members. */
void ccs_init_request_info(struct ccs_request_info *r,
			   struct ccs_domain_info *domain, const u8 index);
/* Run policy loader when /sbin/init starts. */
void ccs_load_policy(const char *filename);
/* Print an IPv6 address. */
void ccs_print_ipv6(char *buffer, const int buffer_len,
		    const struct in6_addr *ip);
/* Change "struct ccs_domain_info"->flags. */
void ccs_set_domain_flag(struct ccs_domain_info *domain, const bool is_delete,
			 const u8 flags);
/* Update the policy change counter. */
void ccs_update_counter(const unsigned char index);

/* Check whether the basename of program and argv0 is allowed to differ. */
int ccs_check_argv0_perm(struct ccs_request_info *r,
			 const struct ccs_path_info *filename,
			 const char *argv0);
/* Check whether the given environment is allowed to be received. */
int ccs_check_env_perm(struct ccs_request_info *r, const char *env);
/* Check whether the given pathname is allowed to be executed. */
int ccs_check_exec_perm(struct ccs_request_info *r,
			const struct ccs_path_info *filename);

/* strcmp() for "struct ccs_path_info" structure. */
static inline bool ccs_pathcmp(const struct ccs_path_info *a,
			       const struct ccs_path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}

/* Get type of an ACL entry. */
static inline u8 ccs_acl_type1(struct ccs_acl_info *ptr)
{
	return ptr->type & ~(ACL_DELETED | ACL_WITH_CONDITION);
}

/* Get type of an ACL entry. */
static inline u8 ccs_acl_type2(struct ccs_acl_info *ptr)
{
	return ptr->type & ~ACL_WITH_CONDITION;
}

/**
 * ccs_get_condition_part - Get condition part of the given ACL entry.
 *
 * @acl: Pointer to "struct ccs_acl_info".
 *
 * Returns pointer to the condition part if the ACL has it, NULL otherwise.
 */
static inline const struct ccs_condition_list *
ccs_get_condition_part(const struct ccs_acl_info *acl)
{
	return (acl->type & ACL_WITH_CONDITION) ?
		acl->access_me_via_ccs_get_condition_part : NULL;
}

/* A linked list of domains. */
extern struct list1_head ccs_domain_list;
/* Has /sbin/init started? */
extern bool ccs_policy_loaded;
/* Log level for printk(). */
extern const char *ccs_log_level;
/* The kernel's domain. */
extern struct ccs_domain_info ccs_kernel_domain;

#include <linux/dcache.h>
extern spinlock_t vfsmount_lock;

#if defined(D_PATH_DISCONNECT) && !defined(CONFIG_SUSE_KERNEL)

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

static inline void ccs_tasklist_lock(void)
{
	rcu_read_lock();
}
static inline void ccs_tasklist_unlock(void)
{
	rcu_read_unlock();
}

#else

static inline void ccs_tasklist_lock(void)
{
	read_lock(&tasklist_lock);
}
static inline void ccs_tasklist_unlock(void)
{
	read_unlock(&tasklist_lock);
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

#endif
