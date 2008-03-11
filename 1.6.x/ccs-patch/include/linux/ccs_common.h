/*
 * include/linux/ccs_common.h
 *
 * Common functions for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.0-pre   2008/03/11
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#include <linux/kmod.h>
#include <asm/hardirq.h>
#else
#include <linux/hardirq.h>
#endif

#ifndef __user
#define __user
#endif

#ifndef WARN_ON
#define WARN_ON(x) do { } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
typedef _Bool bool;
#endif

#define false 0
#define true 1

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
#define mutex semaphore
#define mutex_init(mutex) init_MUTEX(mutex)
#define mutex_lock(mutex) down(mutex)
#define mutex_unlock(mutex) up(mutex)
#define mutex_lock_interruptible(mutex) down_interruptible(mutex)
#define DEFINE_MUTEX(mutexname) DECLARE_MUTEX(mutexname)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#if 0

#define list1_head list_head
#define LIST1_HEAD_INIT LIST_HEAD_INIT
#define LIST1_HEAD LIST_HEAD
#define INIT_LIST1_HEAD INIT_LIST_HEAD
#define list1_entry list_entry
#define list1_for_each list_for_each
#define list1_for_each_entry list_for_each_entry
#define list1_for_each_cookie(pos, cookie, head) \
	for (({if (!cookie) cookie = head;}), pos = (cookie)->next; \
		prefetch(pos->next), pos != (head) || ((cookie) = NULL); \
		(cookie) = pos, pos = pos->next)
static inline void list1_add_tail_mb(struct list1_head *new,
				     struct list1_head *head)
{
	struct list_head *prev = head->prev;
	struct list_head *next = head;
	new->next = next;
	new->prev = prev;
	mb(); /* Avoid out-of-order execution. */
	next->prev = new;
	prev->next = new;
}

#else /////////////////////////////////////////////////////////////////////////

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
#define list1_for_each(pos, head) \
	for (pos = (head)->next; prefetch(pos->next), pos != (head); \
		pos = pos->next)

/**
 * list1_for_each_entry  -       iterate over list of given type
 * @pos:        the type * to use as a loop cursor.
 * @head:       the head for your list.
 * @member:     the name of the list1_struct within the struct.
 */
#define list1_for_each_entry(pos, head, member)                          \
	for (pos = list1_entry((head)->next, typeof(*pos), member);      \
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
#define list1_for_each_cookie(pos, cookie, head) \
	for (({if (!cookie) cookie = head;}), pos = (cookie)->next; \
		prefetch(pos->next), pos != (head) || ((cookie) = NULL); \
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

#endif

struct ccs_page_buffer {
	char buffer[4096];
};

struct mini_stat {
	uid_t uid;
	gid_t gid;
	ino_t ino;
};
struct dentry;
struct vfsmount;
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

struct path_info {
	const char *name;
	u32 hash;        /* = full_name_hash(name, strlen(name)) */
	u16 total_len;   /* = strlen(name)                       */
	u16 const_len;   /* = const_part_length(name)            */
	bool is_dir;       /* = strendswith(name, "/")             */
	bool is_patterned; /* = PathContainsPattern(name)          */
	u16 depth;       /* = PathDepth(name)                    */
};

#define CCS_MAX_PATHNAME_LEN 4000

struct path_group_member {
	struct list1_head list;
	const struct path_info *member_name;
	bool is_deleted;
};

struct path_group_entry {
	struct list1_head list;
	const struct path_info *group_name;
	struct list1_head path_group_member_list;
};

struct in6_addr;
struct address_group_member {
	struct list1_head list;
	union {
		u32 ipv4;                    /* Host byte order    */
		const struct in6_addr *ipv6; /* Network byte order */
	} min, max;
	bool is_deleted;
	bool is_ipv6;
};

struct address_group_entry {
	struct list1_head list;
	const struct path_info *group_name;
	struct list1_head address_group_member_list;
};

struct path_info_with_data {
	struct path_info head; /* Keep this first, for this pointer is passed to ccs_free(). */
	char bariier1[16];
	char body[CCS_MAX_PATHNAME_LEN];
	char barrier2[16];
};
	
/*
 *  TOMOYO uses the following structures.
 *  Memory allocated for these structures are never kfree()ed.
 *  Since no locks are used for reading, assignment must be performed atomically.
 */

/*************************  The structure for domains.  *************************/

#define ACL_DELETED        0x80
#define ACL_WITH_CONDITION 0x40

struct acl_info {
	const struct condition_list *cond; /* Use GetConditionPart() to read me. */
	struct list1_head list;
	u8 type; /* MSB is is_deleted flag. Next bit is with_condition flag. */
} __attribute__((__packed__));

struct domain_info {
	struct list1_head list;
	struct list1_head acl_info_list;
	const struct path_info *domainname; /* Name of this domain. Never NULL.      */
	u8 profile;                         /* Profile to use.                       */
	u8 is_deleted;                      /* Delete flag.                          */
	bool quota_warned;                  /* Quota warnning done flag.             */
	u8 flags;                           /* Ignore default?                       */
};

#define MAX_PROFILES 256

#define DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_READ 1 /* Ignore "allow_read" in exception_policy */
#define DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_ENV  2 /* Ignore "allow_env" in exception_policy  */

struct execute_handler_record {
	struct acl_info head;                         /* type = TYPE_*_EXECUTE_HANDLER */
	const struct path_info *handler;              /* Pointer to single pathname.   */
};

struct single_path_acl_record {
	struct acl_info head;                         /* type = TYPE_SINGLE_PATH_ACL */
	bool u_is_group;
	u16 perm;
	union {
		const struct path_info *filename;     /* Pointer to single pathname. */
		const struct path_group_entry *group; /* Pointer to pathname group.  */
	} u;
};

struct double_path_acl_record {
	struct acl_info head;                          /* type = TYPE_DOUBLE_PATH_ACL */
	u8 perm;
	bool u1_is_group;
	bool u2_is_group;
	union {
		const struct path_info *filename1;     /* Pointer to single pathname. */
		const struct path_group_entry *group1; /* Pointer to pathname group.  */
	} u1;
	union {
		const struct path_info *filename2;     /* Pointer to single pathname. */
		const struct path_group_entry *group2; /* Pointer to pathname group.  */
	} u2;
};

struct argv0_acl_record {
	struct acl_info head;             /* type = TYPE_ARGV0_ACL       */
	const struct path_info *filename; /* Pointer to single pathname. */
	const struct path_info *argv0;    /* strrchr(argv[0], '/') + 1   */
};

struct env_acl_record {
	struct acl_info head;           /* type = TYPE_ENV_ACL  */
	const struct path_info *env;    /* environment variable */
};

struct capability_acl_record {
	struct acl_info head; /* type = TYPE_CAPABILITY_ACL */
	u8 operation;
};

struct signal_acl_record {
	struct acl_info head;               /* type = TYPE_SIGNAL_ACL          */
	u16 sig;
	const struct path_info *domainname; /* Pointer to destination pattern. */
};

#define IP_RECORD_TYPE_ADDRESS_GROUP 0
#define IP_RECORD_TYPE_IPv4          1
#define IP_RECORD_TYPE_IPv6          2

struct ip_network_acl_record {
	struct acl_info head;   /* type = TYPE_IP_NETWORK_ACL */
	u8 operation_type;
	u8 record_type;         /* IP_RECORD_TYPE_*           */
	u16 min_port;           /* Start of port number range.                   */
	u16 max_port;           /* End of port number range.                     */
	union {
		struct {
			u32 min; /* Start of IPv4 address range. Host endian. */
			u32 max; /* End of IPv4 address range. Host endian.   */
		} ipv4;
		struct {
			const struct in6_addr *min; /* Start of IPv6 address range. Big endian.      */
			const struct in6_addr *max; /* End of IPv6 address range. Big endian.        */
		} ipv6;
		const struct address_group_entry *group; /* Pointer to address group. */
	} u;
};

/*************************  Keywords for ACLs.  *************************/

#define KEYWORD_ADDRESS_GROUP            "address_group "
#define KEYWORD_ADDRESS_GROUP_LEN        (sizeof(KEYWORD_ADDRESS_GROUP) - 1)
#define KEYWORD_AGGREGATOR               "aggregator "
#define KEYWORD_AGGREGATOR_LEN           (sizeof(KEYWORD_AGGREGATOR) - 1)
#define KEYWORD_ALIAS                    "alias "
#define KEYWORD_ALIAS_LEN                (sizeof(KEYWORD_ALIAS) - 1)
#define KEYWORD_ALLOW_ARGV0              "allow_argv0 "
#define KEYWORD_ALLOW_ARGV0_LEN          (sizeof(KEYWORD_ALLOW_ARGV0) - 1)
#define KEYWORD_ALLOW_CAPABILITY         "allow_capability "
#define KEYWORD_ALLOW_CAPABILITY_LEN     (sizeof(KEYWORD_ALLOW_CAPABILITY) - 1)
#define KEYWORD_ALLOW_CHROOT             "allow_chroot "
#define KEYWORD_ALLOW_CHROOT_LEN         (sizeof(KEYWORD_ALLOW_CHROOT) - 1)
#define KEYWORD_ALLOW_ENV                "allow_env "
#define KEYWORD_ALLOW_ENV_LEN            (sizeof(KEYWORD_ALLOW_ENV) - 1)
#define KEYWORD_ALLOW_MOUNT              "allow_mount "
#define KEYWORD_ALLOW_MOUNT_LEN          (sizeof(KEYWORD_ALLOW_MOUNT) - 1)
#define KEYWORD_ALLOW_NETWORK            "allow_network "
#define KEYWORD_ALLOW_NETWORK_LEN        (sizeof(KEYWORD_ALLOW_NETWORK) - 1)
#define KEYWORD_ALLOW_PIVOT_ROOT         "allow_pivot_root "
#define KEYWORD_ALLOW_PIVOT_ROOT_LEN     (sizeof(KEYWORD_ALLOW_PIVOT_ROOT) - 1)
#define KEYWORD_ALLOW_READ               "allow_read "
#define KEYWORD_ALLOW_READ_LEN           (sizeof(KEYWORD_ALLOW_READ) - 1)
#define KEYWORD_ALLOW_SIGNAL             "allow_signal "
#define KEYWORD_ALLOW_SIGNAL_LEN         (sizeof(KEYWORD_ALLOW_SIGNAL) - 1)
#define KEYWORD_DELETE                   "delete "
#define KEYWORD_DELETE_LEN               (sizeof(KEYWORD_DELETE) - 1)
#define KEYWORD_DENY_AUTOBIND            "deny_autobind "
#define KEYWORD_DENY_AUTOBIND_LEN        (sizeof(KEYWORD_DENY_AUTOBIND) - 1)
#define KEYWORD_DENY_REWRITE             "deny_rewrite "
#define KEYWORD_DENY_REWRITE_LEN         (sizeof(KEYWORD_DENY_REWRITE) - 1)
#define KEYWORD_DENY_UNMOUNT             "deny_unmount "
#define KEYWORD_DENY_UNMOUNT_LEN         (sizeof(KEYWORD_DENY_UNMOUNT) - 1)
#define KEYWORD_FILE_PATTERN             "file_pattern "
#define KEYWORD_FILE_PATTERN_LEN         (sizeof(KEYWORD_FILE_PATTERN) - 1)
#define KEYWORD_INITIALIZE_DOMAIN        "initialize_domain "
#define KEYWORD_INITIALIZE_DOMAIN_LEN    (sizeof(KEYWORD_INITIALIZE_DOMAIN) - 1)
#define KEYWORD_KEEP_DOMAIN              "keep_domain "
#define KEYWORD_KEEP_DOMAIN_LEN          (sizeof(KEYWORD_KEEP_DOMAIN) - 1)
#define KEYWORD_NO_INITIALIZE_DOMAIN     "no_initialize_domain "
#define KEYWORD_NO_INITIALIZE_DOMAIN_LEN (sizeof(KEYWORD_NO_INITIALIZE_DOMAIN) - 1)
#define KEYWORD_NO_KEEP_DOMAIN           "no_keep_domain "
#define KEYWORD_NO_KEEP_DOMAIN_LEN       (sizeof(KEYWORD_NO_KEEP_DOMAIN) - 1)
#define KEYWORD_PATH_GROUP               "path_group "
#define KEYWORD_PATH_GROUP_LEN           (sizeof(KEYWORD_PATH_GROUP) - 1)
#define KEYWORD_SELECT                   "select "
#define KEYWORD_SELECT_LEN               (sizeof(KEYWORD_SELECT) - 1)
#define KEYWORD_UNDELETE                 "undelete "
#define KEYWORD_UNDELETE_LEN             (sizeof(KEYWORD_UNDELETE) - 1)

#define KEYWORD_USE_PROFILE              "use_profile "
#define KEYWORD_IGNORE_GLOBAL_ALLOW_READ "ignore_global_allow_read"
#define KEYWORD_IGNORE_GLOBAL_ALLOW_ENV  "ignore_global_allow_env"
#define KEYWORD_PREFERRED_EXECUTE_HANDLER "preferred_execute_handler"
#define KEYWORD_DEFAULT_EXECUTE_HANDLER   "default_execute_handler"

#define KEYWORD_MAC_FOR_CAPABILITY       "MAC_FOR_CAPABILITY::"
#define KEYWORD_MAC_FOR_CAPABILITY_LEN   (sizeof(KEYWORD_MAC_FOR_CAPABILITY) - 1)

#define ROOT_NAME "<kernel>"             /* A domain definition starts with <kernel> . */
#define ROOT_NAME_LEN (sizeof(ROOT_NAME) - 1)

/*************************  Index numbers for Access Controls.  *************************/

#define CCS_PROFILE_COMMENT                      0  /* profile.conf            */
#define CCS_TOMOYO_MAC_FOR_FILE                  1  /* domain_policy.conf      */
#define CCS_TOMOYO_MAC_FOR_ARGV0                 2  /* domain_policy.conf      */
#define CCS_TOMOYO_MAC_FOR_ENV                   3  /* domain_policy.conf      */
#define CCS_TOMOYO_MAC_FOR_NETWORK               4  /* domain_policy.conf      */
#define CCS_TOMOYO_MAC_FOR_SIGNAL                5  /* domain_policy.conf      */
#define CCS_SAKURA_DENY_CONCEAL_MOUNT            6
#define CCS_SAKURA_RESTRICT_CHROOT               7  /* system_policy.conf      */
#define CCS_SAKURA_RESTRICT_MOUNT                8  /* system_policy.conf      */
#define CCS_SAKURA_RESTRICT_UNMOUNT              9  /* system_policy.conf      */
#define CCS_SAKURA_RESTRICT_PIVOT_ROOT          10  /* system_policy.conf      */
#define CCS_SAKURA_RESTRICT_AUTOBIND            11  /* system_policy.conf      */
#define CCS_TOMOYO_MAX_ACCEPT_ENTRY             12
#define CCS_TOMOYO_MAX_GRANT_LOG                13
#define CCS_TOMOYO_MAX_REJECT_LOG               14
#define CCS_TOMOYO_VERBOSE                      15
#define CCS_ALLOW_ENFORCE_GRACE                 16
#define CCS_SLEEP_PERIOD                        17  /* profile.conf            */
#define CCS_MAX_CONTROL_INDEX                   18

/*************************  Index numbers for updates counter.  *************************/

#define CCS_UPDATES_COUNTER_SYSTEM_POLICY    0
#define CCS_UPDATES_COUNTER_DOMAIN_POLICY    1
#define CCS_UPDATES_COUNTER_EXCEPTION_POLICY 2
#define CCS_UPDATES_COUNTER_PROFILE          3
#define CCS_UPDATES_COUNTER_QUERY            4
#define CCS_UPDATES_COUNTER_MANAGER          5
#define CCS_UPDATES_COUNTER_GRANT_LOG        6
#define CCS_UPDATES_COUNTER_REJECT_LOG       7
#define MAX_CCS_UPDATES_COUNTER              8

/*************************  The structure for /proc interfaces.  *************************/

struct io_buffer {
	int (*read) (struct io_buffer *);
	struct mutex read_sem;
	int (*write) (struct io_buffer *);
	struct mutex write_sem;
	int (*poll) (struct file *file, poll_table *wait);
	struct list1_head *read_var1;     /* The position currently reading from. */
	struct list1_head *read_var2;     /* Extra variables for reading.         */
	struct domain_info *write_var1;   /* The position currently writing to.   */
	int read_step;                    /* The step for reading.                */
	char *read_buf;                   /* Buffer for reading.                  */
	bool read_eof;                    /* EOF flag for reading.                */
	u8 read_bit;                      /* Extra variable for reading.          */
	int read_avail;                   /* Bytes available for reading.         */
	int readbuf_size;                 /* Size of read buffer.                 */
	char *write_buf;                  /* Buffer for writing.                  */
	int write_avail;                  /* Bytes available for writing.         */
	int writebuf_size;                /* Size of write buffer.                */
};

/*************************  PROTOTYPES  *************************/

struct condition_list;

char *InitAuditLog(int *len, const u8 profile, const u8 mode, struct linux_binprm *bprm);
void *ccs_alloc(const size_t size);
char *print_ipv6(char *buffer, const int buffer_len, const struct in6_addr *ip);
const char *GetEXE(void);
const char *GetLastName(const struct domain_info *domain);
const char *GetMSG(const bool is_enforce);
const char *cap_operation2keyword(const u8 operation);
const char *dp_operation2keyword(const u8 operation);
const char *sp_operation2keyword(const u8 operation);
const char *net_operation2keyword(const u8 operation);
const struct condition_list *FindOrAssignNewCondition(char *condition);
int AddAddressGroupPolicy(char *data, const bool is_delete);
int AddAggregatorPolicy(char *data, const bool is_delete);
int AddAliasPolicy(char *data, const bool is_delete);
int AddArgv0Policy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete);
int AddCapabilityPolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete);
int AddChrootPolicy(char *data, const bool is_delete);
int AddDomainACL(struct domain_info *domain, struct acl_info *acl);
int AddDomainInitializerPolicy(char *data, const bool is_not, const bool is_delete);
int AddDomainKeeperPolicy(char *data, const bool is_not, const bool is_delete);
int AddEnvPolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete);
int AddFilePolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete);
int AddGloballyReadablePolicy(char *data, const bool is_delete);
int AddGloballyUsableEnvPolicy(char *env, const bool is_delete);
int AddFilePatternPolicy(char *data, const bool is_delete);
int AddMountPolicy(char *data, const bool is_delete);
int AddNetworkPolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete);
int AddNoRewritePolicy(char *pattern, const bool is_delete);
int AddNoUmountPolicy(char *data, const bool is_delete);
int AddPathGroupPolicy(char *data, const bool is_delete);
int AddPivotRootPolicy(char *data, const bool is_delete);
int AddReservedPortPolicy(char *data, const bool is_delete);
int AddSignalPolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete);
int CCS_CloseControl(struct file *file);
int CCS_OpenControl(const u8 type, struct file *file);
int CCS_PollControl(struct file *file, poll_table *wait);
int CCS_ReadControl(struct file *file, char __user *buffer, const int buffer_len);
int CCS_WriteControl(struct file *file, const char __user *buffer, const int buffer_len);
int CanSaveAuditLog(const bool is_granted);
int CheckSupervisor(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));
int DelDomainACL(struct acl_info *acl);
int DeleteDomain(char *data);
int DumpCondition(struct io_buffer *head, const struct condition_list *ptr);
bool CheckCondition(const struct acl_info *acl, struct obj_info *obj_info);
bool IsCorrectDomain(const unsigned char *domainname, const char *function);
bool IsCorrectPath(const char *filename, const s8 start_type, const s8 pattern_type, const s8 end_type, const char *function);
bool IsDomainDef(const unsigned char *buffer);
bool PathMatchesToPattern(const struct path_info *pathname0, const struct path_info *pattern0);
int PollGrantLog(struct file *file, poll_table *wait);
int PollRejectLog(struct file *file, poll_table *wait);
int ReadAddressGroupPolicy(struct io_buffer *head);
int ReadAggregatorPolicy(struct io_buffer *head);
int ReadAliasPolicy(struct io_buffer *head);
int ReadChrootPolicy(struct io_buffer *head);
int ReadDomainInitializerPolicy(struct io_buffer *head);
int ReadDomainKeeperPolicy(struct io_buffer *head);
int ReadGloballyReadablePolicy(struct io_buffer *head);
int ReadGloballyUsableEnvPolicy(struct io_buffer *head);
int ReadGrantLog(struct io_buffer *head);
int ReadFilePatternPolicy(struct io_buffer *head);
int ReadMountPolicy(struct io_buffer *head);
int ReadNoRewritePolicy(struct io_buffer *head);
int ReadNoUmountPolicy(struct io_buffer *head);
int ReadPathGroupPolicy(struct io_buffer *head);
int ReadPivotRootPolicy(struct io_buffer *head);
int ReadRejectLog(struct io_buffer *head);
int ReadReservedPortPolicy(struct io_buffer *head);
int WriteAuditLog(char *log, const bool is_granted);
int io_printf(struct io_buffer *head, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));
struct domain_info *FindDomain(const char *domainname);
struct domain_info *FindOrAssignNewDomain(const char *domainname, const u8 profile);
struct domain_info *UndeleteDomain(const char *domainname0);
bool CheckCCSQuota(struct domain_info * const domain);
unsigned int CheckCCSFlags(const u8 index);
unsigned int CheckCCSFlags_NoSleepCheck(const u8 index);
u8 CheckCapabilityFlags(const u8 index);
bool CheckDomainQuota(struct domain_info * const domain);
bool TomoyoVerboseMode(void);
void *alloc_acl_element(const u8 acl_type, const struct condition_list *condition);
const struct condition_list *GetConditionPart(const struct acl_info *acl);
void CCS_LoadPolicy(const char *filename);
void UpdateCounter(const unsigned char index);
void ccs_free(const void *p);
void fill_path_info(struct path_info *ptr);
void UpdateCondition(const struct acl_info *acl);
void SetDomainFlag(struct domain_info *domain, const bool is_delete, const u8 flags);

static inline bool pathcmp(const struct path_info *a, const struct path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}

extern struct list1_head domain_list;
extern asmlinkage long sys_getppid(void);
extern bool sbin_init_started;
extern const char *ccs_log_level;
extern struct domain_info KERNEL_DOMAIN;
extern struct mutex domain_acl_lock;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
static inline void *kzalloc(int size, int flags)
{
	void *p = kmalloc(size, flags);
	if (p) memset(p, 0, size);
	return p;
}
#endif 

#endif
