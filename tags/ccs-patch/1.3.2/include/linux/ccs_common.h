/*
 * include/linux/ccs_common.h
 *
 * Common functions for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.3.2   2007/02/14
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
#endif

#ifndef __user
#define __user
#endif

struct mini_stat {
	uid_t uid;
	gid_t gid;
	ino_t ino;
};
struct dentry;
struct vfsmount;
struct obj_info {
	u8 validate_done;
	u8 path1_valid;
	u8 path1_parent_valid;
	u8 path2_parent_valid;
	struct dentry *path1_dentry;
	struct vfsmount *path1_vfsmnt;
	struct dentry *path2_dentry;
	struct vfsmount *path2_vfsmnt;
	struct mini_stat path1_stat;
	/* I don't handle path2_stat for rename operation. */
	struct mini_stat path1_parent_stat;
	struct mini_stat path2_parent_stat;
};

struct path_info {
	const char *name;
	u32 hash;        /* = full_name_hash(name, strlen(name)) */
	u16 total_len;   /* = strlen(name)                       */
	u16 const_len;   /* = const_part_length(name)            */
	u8 is_dir;       /* = strendswith(name, "/")             */
	u8 is_patterned; /* = PathContainsPattern(name)          */
	u16 depth;       /* = PathDepth(name)                    */
};

#define CCS_MAX_PATHNAME_LEN 4000

typedef struct group_member {
	struct group_member *next;
	const struct path_info *member_name;
	int is_deleted;
} GROUP_MEMBER;

typedef struct group_entry {
	struct group_entry *next;
	const struct path_info *group_name;
	GROUP_MEMBER *first_member;
} GROUP_ENTRY;

/*
 *  TOMOYO uses the following structures.
 *  Memory allocated for these structures are never kfree()ed.
 *  Since no locks are used for reading, assignment must be performed atomically.
 */

/*************************  The structure for domains.  *************************/

struct condition_list;

struct acl_info {
	struct acl_info *next;
	const struct condition_list *cond;
	u8 type;
	u8 is_deleted;
	union {
		u16 w;
		u8 b[2];
	} u;
};

struct domain_info {
	struct domain_info *next;           /* Pointer to next record. NULL if none. */
	struct acl_info *first_acl_ptr;     /* Pointer to first acl. NULL if none.   */
	const struct path_info *domainname; /* Name of this domain. Never NULL.      */
	u8 profile;                         /* Profile to use.                       */
	u8 is_deleted;                      /* Delete flag.                          */
	u8 quota_warned;                    /* Quota warnning done flag.             */
};

#define MAX_PROFILES 256

typedef struct {
	struct acl_info head;                   /* type = TYPE_FILE_ACL, b[0] = perm, b[1] = u_is_group */
	union {
		const struct path_info *filename;   /* Pointer to single pathname. */
		const struct group_entry *group;    /* Pointer to pathname group.  */
	} u;
} FILE_ACL_RECORD;

typedef struct {
	struct acl_info head;             /* type = TYPE_ARGV0_ACL       */
	const struct path_info *filename; /* Pointer to single pathname. */
	const struct path_info *argv0;    /* strrchr(argv[0], '/') + 1   */
} ARGV0_ACL_RECORD;

typedef struct {
	struct acl_info head;   /* type = TYPE_CAPABILITY_ACL, w = capability index. */
} CAPABILITY_ACL_RECORD;

typedef struct {
	struct acl_info head;               /* type = TYPE_SIGNAL_ACL, w = signal_number. */
	const struct path_info *domainname; /* Pointer to destination pattern.            */
} SIGNAL_ACL_RECORD;

typedef struct {
	struct acl_info head;   /* type = TYPE_CONNECT_ACL or TYPE_BIND_ACL, w = is_tcp */
	u16 min_port;           /* Start of port number range.                          */
	u16 max_port;           /* End of port number range.                            */
} PORT_ACL_RECORD;

typedef struct {
	struct acl_info head;                 /* type = TYPE_*, w = u_is_group */
	union {
		const struct path_info *filename; /* Pointer to single pathname. */
		const struct group_entry *group;  /* Pointer to pathname group.  */
	} u;
} SINGLE_ACL_RECORD;

typedef struct {
	struct acl_info head;                   /* type = TYPE_RENAME_ACL or TYPE_LINK_ACL, b[0] = u1_is_group, b[1] = u2_is_group */
	union {
		const struct path_info *filename1;  /* Pointer to single pathname. */
		const struct group_entry *group1;   /* Pointer to pathname group.  */
	} u1;
	union {
		const struct path_info *filename2;  /* Pointer to single pathname. */
		const struct group_entry *group2;   /* Pointer to pathname group.  */
	} u2;
} DOUBLE_ACL_RECORD;

typedef struct {
	struct acl_info head;   /* type = TYPE_IPv4_NETWORK_ACL, w = socket_type */
	u32 min_address;        /* Start of IPv4 address range.                  */
	u32 max_address;        /* End of IPv4 address range.                    */
	u16 min_port;           /* Start of port number range.                   */
	u16 max_port;           /* End of port number range.                     */
} IPv4_NETWORK_ACL_RECORD;

typedef struct {
	struct acl_info head;   /* type = TYPE_IPv6_NETWORK_ACL, w = socket_type */
	u8 min_address[16];     /* Start of IPv6 address range. Big endian.      */
	u8 max_address[16];     /* End of IPv6 address range. Big endian.        */
	u16 min_port;           /* Start of port number range.                   */
	u16 max_port;           /* End of port number range.                     */
} IPv6_NETWORK_ACL_RECORD;

/*************************  Keywords for ACLs.  *************************/

#define KEYWORD_AGGREGATOR               "aggregator "
#define KEYWORD_AGGREGATOR_LEN           (sizeof(KEYWORD_AGGREGATOR) - 1)
#define KEYWORD_ALIAS                    "alias "
#define KEYWORD_ALIAS_LEN                (sizeof(KEYWORD_ALIAS) - 1)
#define KEYWORD_ALLOW_ARGV0              "allow_argv0 "
#define KEYWORD_ALLOW_ARGV0_LEN          (sizeof(KEYWORD_ALLOW_ARGV0) - 1)
#define KEYWORD_ALLOW_BIND               "allow_bind "
#define KEYWORD_ALLOW_BIND_LEN           (sizeof(KEYWORD_ALLOW_BIND) - 1)
#define KEYWORD_ALLOW_CAPABILITY         "allow_capability "
#define KEYWORD_ALLOW_CAPABILITY_LEN     (sizeof(KEYWORD_ALLOW_CAPABILITY) - 1)
#define KEYWORD_ALLOW_CHROOT             "allow_chroot "
#define KEYWORD_ALLOW_CHROOT_LEN         (sizeof(KEYWORD_ALLOW_CHROOT) - 1)
#define KEYWORD_ALLOW_CONNECT            "allow_connect "
#define KEYWORD_ALLOW_CONNECT_LEN        (sizeof(KEYWORD_ALLOW_CONNECT) - 1)
#define KEYWORD_ALLOW_MOUNT              "allow_mount "
#define KEYWORD_ALLOW_MOUNT_LEN          (sizeof(KEYWORD_ALLOW_MOUNT) - 1)
#define KEYWORD_ALLOW_NETWORK            "allow_network "
#define KEYWORD_ALLOW_NETWORK_LEN        (sizeof(KEYWORD_ALLOW_NETWORK) - 1)
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
#define KEYWORD_INITIALIZER              "initializer "
#define KEYWORD_INITIALIZER_LEN          (sizeof(KEYWORD_INITIALIZER) - 1)
#define KEYWORD_INITIALIZE_DOMAIN        "initialize_domain "
#define KEYWORD_INITIALIZE_DOMAIN_LEN    (sizeof(KEYWORD_INITIALIZE_DOMAIN) - 1)
#define KEYWORD_KEEP_DOMAIN              "keep_domain "
#define KEYWORD_KEEP_DOMAIN_LEN          (sizeof(KEYWORD_KEEP_DOMAIN) - 1)
#define KEYWORD_NO_INITIALIZER           "no_initializer "
#define KEYWORD_NO_INITIALIZER_LEN       (sizeof(KEYWORD_NO_INITIALIZER) - 1)
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

#define KEYWORD_MAC_FOR_CAPABILITY       "MAC_FOR_CAPABILITY::"
#define KEYWORD_MAC_FOR_CAPABILITY_LEN   (sizeof(KEYWORD_MAC_FOR_CAPABILITY) - 1)

#define ROOT_NAME "<kernel>"             /* A domain definition starts with <kernel> . */
#define ROOT_NAME_LEN (sizeof(ROOT_NAME) - 1)

/*************************  Index numbers for Access Controls.  *************************/

#define CCS_PROFILE_COMMENT                      0  /* status.txt             */
#define CCS_TOMOYO_MAC_FOR_FILE                  1  /* domain_policy.txt      */
#define CCS_TOMOYO_MAC_FOR_ARGV0                 2  /* domain_policy.txt      */
#define CCS_TOMOYO_MAC_FOR_NETWORK               3  /* domain_policy.txt      */
#define CCS_TOMOYO_MAC_FOR_BINDPORT              4  /* domain_policy.txt      */
#define CCS_TOMOYO_MAC_FOR_CONNECTPORT           5  /* domain_policy.txt      */
#define CCS_TOMOYO_MAC_FOR_SIGNAL                6  /* domain_policy.txt      */
#define CCS_SAKURA_DENY_CONCEAL_MOUNT            7
#define CCS_SAKURA_RESTRICT_CHROOT               8  /* system_policy.txt      */
#define CCS_SAKURA_RESTRICT_MOUNT                9  /* system_policy.txt      */
#define CCS_SAKURA_RESTRICT_UNMOUNT             10  /* system_policy.txt      */
#define CCS_SAKURA_DENY_PIVOT_ROOT              11
#define CCS_SAKURA_TRACE_READONLY               12
#define CCS_SAKURA_RESTRICT_AUTOBIND            13  /* system_policy.txt      */
#define CCS_TOMOYO_MAX_ACCEPT_FILES             14
#define CCS_TOMOYO_MAX_GRANT_LOG                15
#define CCS_TOMOYO_MAX_REJECT_LOG               16
#define CCS_TOMOYO_VERBOSE                      17
#define CCS_ALLOW_ENFORCE_GRACE                 18
#define CCS_MAX_CONTROL_INDEX                   19

/*************************  Index numbers for updates counter.  *************************/

#define CCS_UPDATES_COUNTER_SYSTEM_POLICY    0
#define CCS_UPDATES_COUNTER_DOMAIN_POLICY    1
#define CCS_UPDATES_COUNTER_EXCEPTION_POLICY 2
#define CCS_UPDATES_COUNTER_STATUS           3
#define CCS_UPDATES_COUNTER_QUERY            4
#define CCS_UPDATES_COUNTER_MANAGER          5
#define CCS_UPDATES_COUNTER_GRANT_LOG        6
#define CCS_UPDATES_COUNTER_REJECT_LOG       7
#define MAX_CCS_UPDATES_COUNTER              8

/*************************  The structure for /proc interfaces.  *************************/

typedef struct io_buffer {
	int (*read) (struct io_buffer *);
	struct semaphore read_sem;
	int (*write) (struct io_buffer *);
	struct semaphore write_sem;
	int (*poll) (struct file *file, poll_table *wait);
	struct domain_info *read_var1;    /* The position currently reading from. */
	void *read_var2;                  /* Extra variables for reading.         */
	struct domain_info *write_var1;   /* The position currently writing to.   */
	int read_step;                    /* The step for reading.                */
	char *read_buf;                   /* Buffer for reading.                  */
	int read_eof;                     /* EOF flag for reading.                */
	int read_avail;                   /* Bytes available for reading.         */
	int readbuf_size;                 /* Size of read buffer.                 */
	char *write_buf;                  /* Buffer for writing.                  */
	int write_avail;                  /* Bytes available for writing.         */
	int writebuf_size;                /* Size of write buffer.                */
} IO_BUFFER;

/*************************  PROTOTYPES  *************************/

char *FindConditionPart(char *data);
char *InitAuditLog(int *len);
char *ccs_alloc(const size_t size);
char *print_ipv6(char *buffer, const int buffer_len, const u16 *ip);
const char *GetEXE(void);
const char *GetLastName(const struct domain_info *domain);
const char *GetMSG(const int is_enforce);
const char *acltype2keyword(const unsigned int acl_type);
const char *capability2keyword(const unsigned int capability);
const char *network2keyword(const unsigned int operation);
const struct condition_list *FindOrAssignNewCondition(const char *condition);
int AddAggregatorPolicy(char *data, const int is_delete);
int AddAliasPolicy(char *data, const int is_delete);
int AddArgv0Policy(char *data, struct domain_info *domain, const int is_delete);
int AddCapabilityPolicy(char *data, struct domain_info *domain, const int is_delete);
int AddChrootPolicy(char *data, const int is_delete);
int AddDomainACL(struct acl_info *ptr, struct domain_info *domain, struct acl_info *new_ptr);
int AddDomainInitializerPolicy(char *data, const int is_not, const int is_delete, const int is_oldstyle);
int AddDomainKeeperPolicy(char *data, const int is_not, const int is_delete);
int AddFilePolicy(char *data, struct domain_info *domain, const int is_delete);
int AddGloballyReadablePolicy(char *data, const int is_delete);
int AddGroupPolicy(char *data, const int is_delete);
int AddMountPolicy(char *data, const int is_delete);
int AddNetworkPolicy(char *data, struct domain_info *domain, const int is_delete);
int AddNoRewritePolicy(char *pattern, const int is_delete);
int AddNoUmountPolicy(char *data, const int is_delete);
int AddPatternPolicy(char *data, const int is_delete);
int AddPortPolicy(char *data, struct domain_info *domain, const int is_delete);
int AddReservedPortPolicy(char *data, const int is_delete);
int AddSignalPolicy(char *data, struct domain_info *domain, const int is_delete);
int CCS_CloseControl(struct file *file);
int CCS_OpenControl(const int type, struct file *file);
int CCS_PollControl(struct file *file, poll_table *wait);
int CCS_ReadControl(struct file *file, char __user *buffer, const int buffer_len);
int CCS_WriteControl(struct file *file, const char __user *buffer, const int buffer_len);
int CanSaveAuditLog(const int is_granted);
int CheckCondition(const struct condition_list *condition, struct obj_info *obj_info);
int CheckSupervisor(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));
int DelDomainACL(struct acl_info *ptr);
int DeleteDomain(char *data);
int DumpCondition(IO_BUFFER *head, const struct condition_list *ptr);
int IsCorrectDomain(const unsigned char *domainname, const char *function);
int IsCorrectPath(const char *filename, const int start_type, const int pattern_type, const int end_type, const char *function);
int IsDomainDef(const unsigned char *buffer);
int PathMatchesToPattern(const struct path_info *pathname0, const struct path_info *pattern0);
int PollGrantLog(struct file *file, poll_table *wait);
int PollRejectLog(struct file *file, poll_table *wait);
int ReadAggregatorPolicy(IO_BUFFER *head);
int ReadAliasPolicy(IO_BUFFER *head);
int ReadCapabilityStatus(IO_BUFFER *head);
int ReadChrootPolicy(IO_BUFFER *head);
int ReadDomainInitializerPolicy(IO_BUFFER *head);
int ReadDomainKeeperPolicy(IO_BUFFER *head);
int ReadGloballyReadablePolicy(IO_BUFFER *head);
int ReadGrantLog(IO_BUFFER *head);
int ReadGroupPolicy(IO_BUFFER *head);
int ReadMountPolicy(IO_BUFFER *head);
int ReadNoRewritePolicy(IO_BUFFER *head);
int ReadNoUmountPolicy(IO_BUFFER *head);
int ReadPatternPolicy(IO_BUFFER *head);
int ReadPermissionMapping(IO_BUFFER *head);
int ReadRejectLog(IO_BUFFER *head);
int ReadReservedPortPolicy(IO_BUFFER *head);
int ReadSelfDomain(IO_BUFFER *head);
int SetCapabilityStatus(const char *data, unsigned int value, const unsigned int profile);
int SetPermissionMapping(IO_BUFFER *head);
int WriteAuditLog(char *log, const int is_granted);
int acltype2paths(const unsigned int acl_type);
int io_printf(IO_BUFFER *head, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));
struct domain_info *FindDomain(const char *domainname);
struct domain_info *FindOrAssignNewDomain(const char *domainname, const u8 profile);
struct domain_info *UndeleteDomain(const char *domainname0);
unsigned int CheckCCSAccept(const unsigned int index);
unsigned int CheckCCSEnforce(const unsigned int index);
unsigned int CheckCCSFlags(const unsigned int index);
unsigned int TomoyoVerboseMode(void);
void UpdateCounter(const unsigned char index);
void ccs_free(const void *p);
void fill_path_info(struct path_info *ptr);

static inline int pathcmp(const struct path_info *a, const struct path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}
#endif
