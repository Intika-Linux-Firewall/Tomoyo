/*
 * include/linux/ccs_common.h
 *
 * Common functions for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.0   2008/04/20
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
extern asmlinkage long sys_getppid(void);

#define false 0
#define true 1

#ifndef __user
#define __user
#endif

#ifndef WARN_ON
#define WARN_ON(x) do { } while (0)
#endif

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
typedef _Bool bool;
#endif


#ifndef KERN_CONT
#define KERN_CONT ""
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
#define mutex semaphore
#define mutex_init(mutex) init_MUTEX(mutex)
#define mutex_lock(mutex) down(mutex)
#define mutex_unlock(mutex) up(mutex)
#define mutex_lock_interruptible(mutex) down_interruptible(mutex)
#define DEFINE_MUTEX(mutexname) DECLARE_MUTEX(mutexname)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({				\
			const typeof(((type *)0)->member) *__mptr = (ptr); \
			(type *)((char *)__mptr - offsetof(type, member)); })
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14)
#define kzalloc(size, flags) ({						\
			void *ret = kmalloc((size), (flags));		\
			if (ret)					\
				memset(ret, 0, (size));			\
			ret; })
#endif

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

/**
 * list1_entry - get the struct for this entry
 * @ptr:        the &struct list1_head pointer.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list1_struct within the struct.
 */
#define list1_entry(ptr, type, member) container_of(ptr, type, member)

/**
 * list1_for_each        -       iterate over a list
 * @pos:        the &struct list1_head to use as a loop cursor.
 * @head:       the head for your list.
 */
#define list1_for_each(pos, head)					\
	for (pos = (head)->next; prefetch(pos->next), pos != (head);	\
	     pos = pos->next)

/**
 * list1_for_each_entry  -       iterate over list of given type
 * @pos:        the type * to use as a loop cursor.
 * @head:       the head for your list.
 * @member:     the name of the list1_struct within the struct.
 */
#define list1_for_each_entry(pos, head, member)				\
	for (pos = list1_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head);        \
	     pos = list1_entry(pos->member.next, typeof(*pos), member))

/**
 * list1_for_each_cookie - iterate over a list with cookie.
 * @pos:        the &struct list1_head to use as a loop cursor.
 * @cookie:     the &struct list1_head to use as a cookie.
 * @head:       the head for your list.
 *
 * Same with list_for_each except that this primitive uses cookie
 * so that we can continue iteration.
 */
#define list1_for_each_cookie(pos, cookie, head)			\
	for (({ if (!cookie)						\
				     cookie = head; }), pos = (cookie)->next; \
	     prefetch(pos->next), pos != (head) || ((cookie) = NULL);	\
	     (cookie) = pos, pos = pos->next)

/**
 * list_add_tail_mb - add a new entry with memory barrier.
 * @new: new entry to be added.
 * @head: list head to add it before.
 *
 * Same with list_add_tail_rcu() except that this primitive uses mb()
 * so that we can traverse forwards using list_for_each() and
 * list_for_each_cookie().
 */
static inline void list1_add_tail_mb(struct list1_head *new,
				     struct list1_head *head)
{
	struct list1_head *pos = head;
	new->next = head;
	mb(); /* Avoid out-of-order execution. */
	while (pos->next != head)
		pos = pos->next;
	pos->next = new;
}

/* Temporary buffer for holding pathnames. */
struct ccs_page_buffer {
	char buffer[4096];
};

/* Subset of "struct stat". */
struct mini_stat {
	uid_t uid;
	gid_t gid;
	ino_t ino;
};

/* Structure for attribute checks in addition to pathname checks. */
struct obj_info {
	bool validate_done;
	bool path1_valid;
	bool path1_parent_valid;
	bool path2_parent_valid;
	struct dentry *path1_dentry;
	struct vfsmount *path1_vfsmnt;
	struct dentry *path2_dentry;
	struct vfsmount *path2_vfsmnt;
	struct mini_stat path1_stat;
	/* I don't handle path2_stat for rename operation. */
	struct mini_stat path1_parent_stat;
	struct mini_stat path2_parent_stat;
	struct linux_binprm *bprm;
	struct ccs_page_buffer *tmp;
};

/* Structure for holding a token. */
struct path_info {
	const char *name;
	u32 hash;          /* = full_name_hash(name, strlen(name)) */
	u16 total_len;     /* = strlen(name)                       */
	u16 const_len;     /* = const_part_length(name)            */
	bool is_dir;       /* = strendswith(name, "/")             */
	bool is_patterned; /* = path_contains_pattern(name)        */
	u16 depth;         /* = path_depth(name)                   */
};

/*
 * This is the max length of a token.
 *
 * A token consists of only ASCII printable characters.
 * Non printable characters in a token is represented in \ooo style
 * octal string. Thus, \ itself is represented as \\.
 */
#define CCS_MAX_PATHNAME_LEN 4000

/* Structure for "path_group" directive. */
struct path_group_member {
	struct list1_head list;
	const struct path_info *member_name;
	bool is_deleted;
};

/* Structure for "path_group" directive. */
struct path_group_entry {
	struct list1_head list;
	const struct path_info *group_name;
	struct list1_head path_group_member_list;
};

/* Structure for "address_group" directive. */
struct address_group_member {
	struct list1_head list;
	union {
		u32 ipv4;                    /* Host byte order    */
		const struct in6_addr *ipv6; /* Network byte order */
	} min, max;
	bool is_deleted;
	bool is_ipv6;
};

/* Structure for "address_group" directive. */
struct address_group_entry {
	struct list1_head list;
	const struct path_info *group_name;
	struct list1_head address_group_member_list;
};

/* Structure for holding requested pathname. */
struct path_info_with_data {
	/* Keep "head" first, for this pointer is passed to ccs_free(). */
	struct path_info head;
	char bariier1[16]; /* Safeguard for overrun. */
	char body[CCS_MAX_PATHNAME_LEN];
	char barrier2[16]; /* Safeguard for overrun. */
};

/* Common header for holding ACL entries. */
struct acl_info {
	/*
	 * Keep "access_me_via_ccs_get_condition_part" first, for
	 * memory for this filed is not allocated if
	 * (type & ACL_WITH_CONDITION) == 0.
	 */
	const struct condition_list *access_me_via_ccs_get_condition_part;
	struct list1_head list;
	/*
	 * Type of this ACL entry.
	 *
	 * MSB is is_deleted flag.
	 * Next bit is with_condition flag.
	 */
	u8 type;
} __attribute__((__packed__));

/* This ACL entry is deleted.           */
#define ACL_DELETED        0x80
/* This ACL entry has conditional part. */
#define ACL_WITH_CONDITION 0x40

/* Structure for domain information. */
struct domain_info {
	struct list1_head list;
	struct list1_head acl_info_list;
	/* Name of this domain. Never NULL.          */
	const struct path_info *domainname;
	u8 profile;        /* Profile number to use. */
	u8 is_deleted;     /* Delete flag.           */
	bool quota_warned; /* Quota warnning flag.   */
	/* DOMAIN_FLAGS_IGNORE_*. Use ccs_set_domain_flag() to modify. */
	u8 flags;
};

/* Profile number is an integer between 0 and 255. */
#define MAX_PROFILES 256

/* Ignore "allow_read" directive in exception policy. */
#define DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_READ 1
/* Ignore "allow_env" directive in exception policy.  */
#define DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_ENV  2

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
struct execute_handler_record {
	struct acl_info head;            /* type = TYPE_*EXECUTE_HANDLER */
	const struct path_info *handler; /* Pointer to single pathname.  */
};

/*
 * Structure for "allow_read/write", "allow_execute", "allow_read",
 * "allow_write", "allow_create", "allow_unlink", "allow_mkdir", "allow_rmdir",
 * "allow_mkfifo", "allow_mksock", "allow_mkblock", "allow_mkchar",
 * "allow_truncate", "allow_symlink" and "allow_rewrite" directive.
 */
struct single_path_acl_record {
	struct acl_info head; /* type = TYPE_SINGLE_PATH_ACL */
	bool u_is_group; /* True if u points to "path_group" directive. */
	u16 perm;
	union {
		/* Pointer to single pathname. */
		const struct path_info *filename;
		/* Pointer to pathname group. */
		const struct path_group_entry *group;
	} u;
};

/* Structure for "allow_rename" and "allow_link" directive. */
struct double_path_acl_record {
	struct acl_info head; /* type = TYPE_DOUBLE_PATH_ACL */
	u8 perm;
	bool u1_is_group; /* True if u1 points to "path_group" directive. */
	bool u2_is_group; /* True if u2 points to "path_group" directive. */
	union {
		/* Pointer to single pathname. */
		const struct path_info *filename1;
		/* Pointer to pathname group. */
		const struct path_group_entry *group1;
	} u1;
	union {
		/* Pointer to single pathname. */
		const struct path_info *filename2;
		/* Pointer to pathname group. */
		const struct path_group_entry *group2;
	} u2;
};

/* Structure for "allow_argv0" directive. */
struct argv0_acl_record {
	struct acl_info head;             /* type = TYPE_ARGV0_ACL       */
	const struct path_info *filename; /* Pointer to single pathname. */
	const struct path_info *argv0;    /* = strrchr(argv[0], '/') + 1 */
};

/* Structure for "allow_env" directive in domain policy. */
struct env_acl_record {
	struct acl_info head;        /* type = TYPE_ENV_ACL  */
	const struct path_info *env; /* environment variable */
};

/* Structure for "allow_capability" directive. */
struct capability_acl_record {
	struct acl_info head; /* type = TYPE_CAPABILITY_ACL */
	u8 operation;
};

/* Structure for "allow_signal" directive. */
struct signal_acl_record {
	struct acl_info head; /* type = TYPE_SIGNAL_ACL */
	u16 sig;
	/* Pointer to destination pattern. */
	const struct path_info *domainname;
};

/* Structure for "allow_network" directive. */
struct ip_network_acl_record {
	struct acl_info head; /* type = TYPE_IP_NETWORK_ACL */
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
		const struct address_group_entry *group;
	} u;
};

#define IP_RECORD_TYPE_ADDRESS_GROUP 0
#define IP_RECORD_TYPE_IPv4          1
#define IP_RECORD_TYPE_IPv6          2

/* Keywords for ACLs. */
#define KEYWORD_ADDRESS_GROUP             "address_group "
#define KEYWORD_AGGREGATOR                "aggregator "
#define KEYWORD_ALIAS                     "alias "
#define KEYWORD_ALLOW_ARGV0               "allow_argv0 "
#define KEYWORD_ALLOW_CAPABILITY          "allow_capability "
#define KEYWORD_ALLOW_CHROOT              "allow_chroot "
#define KEYWORD_ALLOW_ENV                 "allow_env "
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
#define KEYWORD_UNDELETE                  "undelete "
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
#define CCS_TOMOYO_MAC_FOR_FILE                  0  /* domain_policy.conf */
#define CCS_TOMOYO_MAC_FOR_ARGV0                 1  /* domain_policy.conf */
#define CCS_TOMOYO_MAC_FOR_ENV                   2  /* domain_policy.conf */
#define CCS_TOMOYO_MAC_FOR_NETWORK               3  /* domain_policy.conf */
#define CCS_TOMOYO_MAC_FOR_SIGNAL                4  /* domain_policy.conf */
#define CCS_SAKURA_DENY_CONCEAL_MOUNT            5
#define CCS_SAKURA_RESTRICT_CHROOT               6  /* system_policy.conf */
#define CCS_SAKURA_RESTRICT_MOUNT                7  /* system_policy.conf */
#define CCS_SAKURA_RESTRICT_UNMOUNT              8  /* system_policy.conf */
#define CCS_SAKURA_RESTRICT_PIVOT_ROOT           9  /* system_policy.conf */
#define CCS_SAKURA_RESTRICT_AUTOBIND            10  /* system_policy.conf */
#define CCS_TOMOYO_MAX_ACCEPT_ENTRY             11
#define CCS_TOMOYO_MAX_GRANT_LOG                12
#define CCS_TOMOYO_MAX_REJECT_LOG               13
#define CCS_TOMOYO_VERBOSE                      14
#define CCS_ALLOW_ENFORCE_GRACE                 15
#define CCS_SLEEP_PERIOD                        16  /* profile.conf       */
#define CCS_MAX_CONTROL_INDEX                   17

/* Index numbers for updates counter. */
#define CCS_UPDATES_COUNTER_SYSTEM_POLICY    0
#define CCS_UPDATES_COUNTER_DOMAIN_POLICY    1
#define CCS_UPDATES_COUNTER_EXCEPTION_POLICY 2
#define CCS_UPDATES_COUNTER_PROFILE          3
#define CCS_UPDATES_COUNTER_QUERY            4
#define CCS_UPDATES_COUNTER_MANAGER          5
#define CCS_UPDATES_COUNTER_GRANT_LOG        6
#define CCS_UPDATES_COUNTER_REJECT_LOG       7
#define MAX_CCS_UPDATES_COUNTER              8

/* Structure for reading/writing policy via /proc interfaces. */
struct ccs_io_buffer {
	int (*read) (struct ccs_io_buffer *);
	int (*write) (struct ccs_io_buffer *);
	int (*poll) (struct file *file, poll_table *wait);
	/* Exclusive lock for read_buf.         */
	struct mutex read_sem;
	/* Exclusive lock for write_buf.        */
	struct mutex write_sem;
	/* The position currently reading from. */
	struct list1_head *read_var1;
	/* Extra variables for reading.         */
	struct list1_head *read_var2;
	/* The position currently writing to.   */
	struct domain_info *write_var1;
	/* The step for reading.                */
	int read_step;
	/* Buffer for reading.                  */
	char *read_buf;
	/* EOF flag for reading.                */
	bool read_eof;
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
struct condition_list;

/* Check conditional part of an ACL entry. */
bool ccs_check_condition(const struct acl_info *acl,
			 struct obj_info *obj_info);
/* Check whether the domain has too many ACL entries to hold. */
bool ccs_check_domain_quota(struct domain_info * const domain);
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
/* Check whether the given filename matches the given pattern. */
bool ccs_path_matches_pattern(const struct path_info *filename,
			      const struct path_info *pattern);
/* Print conditional part of an ACL entry. */
bool ccs_print_condition(struct ccs_io_buffer *head,
			const struct condition_list *cond);
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
bool ccs_verbose_mode(void);
/* Allocate buffer for domain policy auditing. */
char *ccs_init_audit_log(int *len, const u8 profile, const u8 mode,
			 struct linux_binprm *bprm);
/* Convert capability index to capability name. */
const char *ccs_cap2keyword(const u8 operation);
/* Convert double path operation to operation name. */
const char *ccs_dp2keyword(const u8 operation);
/* Get the pathname of current process. */
const char *ccs_get_exe(void);
/* Get the last component of the given domainname. */
const char *ccs_get_last_name(const struct domain_info *domain);
/* Get warning message. */
const char *ccs_get_msg(const bool is_enforce);
/* Convert network operation index to operation name. */
const char *ccs_net2keyword(const u8 operation);
/* Convert single path operation to operation name. */
const char *ccs_sp2keyword(const u8 operation);
/* Create conditional part of an ACL entry. */
const struct condition_list *
ccs_find_or_assign_new_condition(char * const condition);
/* Read conditional part of an ACL entry. */
const struct condition_list *
ccs_get_condition_part(const struct acl_info *acl);
/* Add an ACL entry to domain's ACL list. */
int ccs_add_domain_acl(struct domain_info *domain, struct acl_info *acl);
/* Check whether there is space for audit logs. */
int ccs_can_save_audit_log(const bool is_granted);
/* Ask supervisor's opinion. */
int ccs_check_supervisor(const char *fmt, ...)
	__attribute__ ((format(printf, 1, 2)));
/* Close /proc/ccs/ interface. */
int ccs_close_control(struct file *file);
/* Delete an ACL entry from domain's ACL list. */
int ccs_del_domain_acl(struct acl_info *acl);
/* Delete a domain. */
int ccs_delete_domain(char *data);
/* Open operation for /proc/ccs/ interface. */
int ccs_open_control(const u8 type, struct file *file);
/* Poll operation for /proc/ccs/ interface. */
int ccs_poll_control(struct file *file, poll_table *wait);
/* Check whether there is a grant log. */
int ccs_poll_grant_log(struct file *file, poll_table *wait);
/* Check whether there is a reject log. */
int ccs_poll_reject_log(struct file *file, poll_table *wait);
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
int ccs_write_argv0_policy(char *data, struct domain_info *domain,
			   const struct condition_list *condition,
			   const bool is_delete);
/* Write an audit log. */
int ccs_write_audit_log(char *log, const bool is_granted);
/* Create "allow_capability" entry in domain policy. */
int ccs_write_capability_policy(char *data, struct domain_info *domain,
				const struct condition_list *condition,
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
int ccs_write_env_policy(char *data, struct domain_info *domain,
			 const struct condition_list *condition,
			 const bool is_delete);
/*
 * Create "allow_read/write", "allow_execute", "allow_read", "allow_write",
 * "allow_create", "allow_unlink", "allow_mkdir", "allow_rmdir",
 * "allow_mkfifo", "allow_mksock", "allow_mkblock", "allow_mkchar",
 * "allow_truncate", "allow_symlink", "allow_rewrite", "allow_rename",
 * "allow_link", "execute_handler" and "denied_execute_handler"
 * entry in domain policy.
 */
int ccs_write_file_policy(char *data, struct domain_info *domain,
			  const struct condition_list *condition,
			  const bool is_delete);
/* Create "allow_read" entry in exception policy. */
int ccs_write_globally_readable_policy(char *data, const bool is_delete);
/* Create "allow_env" entry in exception policy. */
int ccs_write_globally_usable_env_policy(char *data, const bool is_delete);
/* Create "allow_mount" entry in system policy. */
int ccs_write_mount_policy(char *data, const bool is_delete);
/* Create "allow_network" entry in domain policy. */
int ccs_write_network_policy(char *data, struct domain_info *domain,
			     const struct condition_list *condition,
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
int ccs_write_signal_policy(char *data, struct domain_info *domain,
			    const struct condition_list *condition,
			    const bool is_delete);
/* Write operation for /proc/ccs/ interface. */
int ccs_write_control(struct file *file, const char __user *buffer,
		      const int buffer_len);
/* Find a domain by the given name. */
struct domain_info *ccs_find_domain(const char *domainname);
/* Find or create a domain by the given name. */
struct domain_info *ccs_find_or_assign_new_domain(const char *domainname,
						  const u8 profile);
/* Undelete a domain. */
struct domain_info *ccs_undelete_domain(const char *domainname);
/* Write a grant log. */
u8 ccs_check_capability_flags(const u8 index);
/* Check mode for specified functionality. */
unsigned int ccs_check_flags(const u8 index);
/* Same with ccs_check_flags() except that it doesn't check might_sleep(). */
unsigned int ccs_check_flags_no_sleep_check(const u8 index);
/* Allocate memory for structures. */
void *ccs_alloc_acl_element(const u8 acl_type,
			    const struct condition_list *condition);
/* Fill in "struct path_info" members. */
void ccs_fill_path_info(struct path_info *ptr);
/* Run policy loader when /sbin/init starts. */
void ccs_load_policy(const char *filename);
/* Print an IPv6 address. */
void ccs_print_ipv6(char *buffer, const int buffer_len,
		    const struct in6_addr *ip);
/* Change "struct domain_info"->flags. */
void ccs_set_domain_flag(struct domain_info *domain, const bool is_delete,
			 const u8 flags);
/* Update the process's state. */
void ccs_update_condition(const struct acl_info *acl);
/* Update the policy change counter. */
void ccs_update_counter(const unsigned char index);

/* strcmp() for "struct path_info" structure. */
static inline bool ccs_pathcmp(const struct path_info *a,
			       const struct path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}

/* Get type of an ACL entry. */
static inline u8 ccs_acl_type1(struct acl_info *ptr)
{
	return (ptr->type & ~(ACL_DELETED | ACL_WITH_CONDITION));
}

/* Get type of an ACL entry. */
static inline u8 ccs_acl_type2(struct acl_info *ptr)
{
	return (ptr->type & ~ACL_WITH_CONDITION);
}

/* A linked list of domains. */
extern struct list1_head domain_list;
/* Has /sbin/init started? */
extern bool sbin_init_started;
/* Log level for printk(). */
extern const char *ccs_log_level;
/* The kernel's domain. */
extern struct domain_info KERNEL_DOMAIN;
/* Exclusive lock for updating domain policy. */
extern struct mutex domain_acl_lock;

#endif
