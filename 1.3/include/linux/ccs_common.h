/*
 * include/linux/ccs_common.h
 *
 * Common functions for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.3   2006/11/11
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
#ifndef for_each_process
#define for_each_process for_each_task
#endif
#endif

#ifndef __user
#define __user
#endif

#ifdef CONFIG_TOMOYO_MAX_ACCEPT_FILES
#define MAX_ACCEPT_FILES (CONFIG_TOMOYO_MAX_ACCEPT_FILES)
#else
#define MAX_ACCEPT_FILES 2048
#endif
#ifdef CONFIG_TOMOYO_MAX_GRANT_LOG
#define MAX_GRANT_LOG (CONFIG_TOMOYO_MAX_GRANT_LOG)
#else
#define MAX_GRANT_LOG 1024
#endif
#ifdef CONFIG_TOMOYO_MAX_REJECT_LOG
#define MAX_REJECT_LOG (CONFIG_TOMOYO_MAX_REJECT_LOG)
#else
#define MAX_REJECT_LOG 1024
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
	/* path2_stat isn't needed because it doesn't exist at this time. */
	struct mini_stat path1_parent_stat;
	struct mini_stat path2_parent_stat;
};

/*
 *  TOMOYO uses the following structures.
 *  Memory allocated for these structures are never kfree()ed.
 *  Since no locks are used for reading, assignment must be performed atomically.
 */

/*************************  The structure for domains.  *************************/

struct condition_list;

struct acl_info {
	struct acl_info *next;
	unsigned int type_hash;
	const struct condition_list *cond;
};

typedef struct domain_info {
	struct domain_info *next;       /* Pointer to next record. NULL if none. */
	struct acl_info *first_acl_ptr; /* Pointer to first acl. NULL if none.   */
	const char *domainname;         /* Name of this domain. Never NULL.      */
	u8 profile;                     /* Profile to use.                       */
	u8 attributes;                  /* Domain attributes.                    */
	u16 hash;                       /* full_name_hash(domainname)            */
} DOMAIN_INFO;

#define MAX_PROFILES 256

#define DOMAIN_ATTRIBUTE_TRUSTED       1 /* This domain is trusted. (No domain mandatory access controlls are applied.) */
#define DOMAIN_ATTRIBUTE_DELETED       2 /* This domain is deleted.                                                     */
#define DOMAIN_ATTRIBUTE_QUOTA_WARNED  4 /* This domain has too many FILE_ACL_RECORDs to keep.                          */
#define DOMAIN_ATTRIBUTE_UNTRUSTED     8 /* This domain is no longer trusted.                                           */

typedef struct {
	struct acl_info head;   /* = TYPE_FILE_ACL | PathDepth(filename).  */
	const char *filename;   /* Absolute pathname. Never NULL.          */
	u16 perm;               /* Permissions. Between 0(---) and 7(rwx). */
	u16 extra_hash;         /* (full_name_hash(filename) << 1) if !PathContainsPattern(filename), 0xFFFF otherwise. */
} FILE_ACL_RECORD;

typedef struct argv0_map_entry {
	struct acl_info head;   /* = TYPE_ARGV0_ACL | PathDepth(filename). */
	const char *filename;   /* Absolute pathname. Never NULL.          */
	const char *argv0;      /* argv0. Never NULL.                      */
} ARGV0_ACL_RECORD;

typedef struct {
	struct acl_info head;   /* = TYPE_CAPABILITY_ACL | capability index. */
} CAPABILITY_ACL_RECORD;

typedef struct {
	struct acl_info head;   /* = TYPE_SIGNAL_ACL | signal_number.          */
	const char *domainname; /* Pointer to destination pattern. Never NULL. */
} SIGNAL_ACL_RECORD;

typedef struct {
	struct acl_info head;   /* = TYPE_CONNECT_ACL or TYPE_BIND_ACL | boolean TCP. */
	u16 min_port;           /* Start of port number range.                        */
	u16 max_port;           /* End of port number range.                          */
} NETWORK_ACL_RECORD;

typedef struct {
	struct acl_info head;
	const char *filename;   /* Absolute pathname. Never NULL.        */
} SINGLE_ACL_RECORD;

typedef struct {
	struct acl_info head;
	const char *filename1;  /* Absolute pathname. Never NULL.        */
	const char *filename2;  /* Absolute pathname. Never NULL.        */
} DOUBLE_ACL_RECORD;

typedef struct {
	struct acl_info head;   /* = TYPE_IPv4_NETWORK_ACL | type.       */
	u32 min_address;        /* Start of IPv4 address range.          */
	u32 max_address;        /* End of IPv4 address range.            */
	u16 min_port;           /* Start of port number range.           */
	u16 max_port;           /* End of port number range.             */
} IPv4_NETWORK_ACL_RECORD;

typedef struct {
	struct acl_info head;   /* = TYPE_IPv6_NETWORK_ACL | type.          */
	u8 min_address[16];     /* Start of IPv6 address range. Big endian. */
	u8 max_address[16];     /* End of IPv6 address range. Big endian.   */
	u16 min_port;           /* Start of port number range.              */
	u16 max_port;           /* End of port number range.                */
} IPv6_NETWORK_ACL_RECORD;

/*************************  Keywords for ACLs.  *************************/

#define KEYWORD_DELETE                   "delete "
#define KEYWORD_SELECT                   "select "
#define KEYWORD_ALLOW_MOUNT              "allow_mount "
#define KEYWORD_DENY_UNMOUNT             "deny_unmount "
#define KEYWORD_ALLOW_CHROOT             "allow_chroot "
#define KEYWORD_DENY_AUTOBIND            "deny_autobind "
#define KEYWORD_ALLOW_CAPABILITY         "allow_capability "
#define KEYWORD_ALLOW_BIND               "allow_bind "
#define KEYWORD_ALLOW_CONNECT            "allow_connect "
#define KEYWORD_ALLOW_NETWORK            "allow_network "
#define KEYWORD_ALLOW_SIGNAL             "allow_signal "
#define KEYWORD_TRUST_DOMAIN             "trust_domain "
#define KEYWORD_ALLOW_READ               "allow_read "
#define KEYWORD_INITIALIZER              "initializer "
#define KEYWORD_ALIAS                    "alias "
#define KEYWORD_AGGREGATOR               "aggregator "
#define KEYWORD_FILE_PATTERN             "file_pattern "
#define KEYWORD_ALLOW_ARGV0              "allow_argv0 "
#define KEYWORD_USE_PROFILE              "use_profile "
#define KEYWORD_DENY_REWRITE             "deny_rewrite "
#define KEYWORD_DELETE_LEN             (sizeof(KEYWORD_DELETE) - 1)
#define KEYWORD_SELECT_LEN             (sizeof(KEYWORD_SELECT) - 1)
#define KEYWORD_ALLOW_MOUNT_LEN        (sizeof(KEYWORD_ALLOW_MOUNT) - 1)
#define KEYWORD_DENY_UNMOUNT_LEN       (sizeof(KEYWORD_DENY_UNMOUNT) - 1)
#define KEYWORD_ALLOW_CHROOT_LEN       (sizeof(KEYWORD_ALLOW_CHROOT) - 1)
#define KEYWORD_DENY_AUTOBIND_LEN      (sizeof(KEYWORD_DENY_AUTOBIND) - 1)
#define KEYWORD_ALLOW_CAPABILITY_LEN   (sizeof(KEYWORD_ALLOW_CAPABILITY) - 1)
#define KEYWORD_ALLOW_BIND_LEN         (sizeof(KEYWORD_ALLOW_BIND) - 1)
#define KEYWORD_ALLOW_CONNECT_LEN      (sizeof(KEYWORD_ALLOW_CONNECT) - 1)
#define KEYWORD_ALLOW_NETWORK_LEN      (sizeof(KEYWORD_ALLOW_NETWORK) - 1)
#define KEYWORD_ALLOW_SIGNAL_LEN       (sizeof(KEYWORD_ALLOW_SIGNAL) - 1)
#define KEYWORD_TRUST_DOMAIN_LEN       (sizeof(KEYWORD_TRUST_DOMAIN) - 1)
#define KEYWORD_ALLOW_READ_LEN         (sizeof(KEYWORD_ALLOW_READ) - 1)
#define KEYWORD_INITIALIZER_LEN        (sizeof(KEYWORD_INITIALIZER) - 1)
#define KEYWORD_ALIAS_LEN              (sizeof(KEYWORD_ALIAS) - 1)
#define KEYWORD_AGGREGATOR_LEN         (sizeof(KEYWORD_AGGREGATOR) - 1)
#define KEYWORD_FILE_PATTERN_LEN       (sizeof(KEYWORD_FILE_PATTERN) - 1)
#define KEYWORD_ALLOW_ARGV0_LEN        (sizeof(KEYWORD_ALLOW_ARGV0) - 1)
#define KEYWORD_DENY_REWRITE_LEN       (sizeof(KEYWORD_DENY_REWRITE) - 1)

#define KEYWORD_MAC_FOR_CAPABILITY      "MAC_FOR_CAPABILITY::"
#define KEYWORD_MAC_FOR_CAPABILITY_LEN  (sizeof(KEYWORD_MAC_FOR_CAPABILITY) - 1)

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

const char *GetEXE(void);
const char *GetLastName(const struct domain_info *domain);
const char *GetMSG(const int is_enforce);
const char *acltype2keyword(const unsigned int acl_type);
const char *capability2keyword(const unsigned int capability);
const char *network2keyword(const unsigned int operation);
char *print_ipv6(char *buffer, const int buffer_len, const u16 *ip);
char *InitAuditLog(int *len);
int AddDomainACL(struct acl_info *ptr, struct domain_info *domain, struct acl_info *new_ptr);
int DelDomainACL(struct acl_info *prev, struct domain_info *domain, struct acl_info *ptr);
int AddAliasPolicy(char *data, const int is_delete);
int AddAggregatorPolicy(char *data, const int is_delete);
int AddArgv0Policy(char *data, struct domain_info *domain, const int is_delete);
int AddCapabilityPolicy(char *data, struct domain_info *domain, const int is_delete);
int AddChrootPolicy(char *data, const int is_delete);
int AddPortPolicy(char *data, struct domain_info *domain, const int is_delete);
int AddFilePolicy(char *data, struct domain_info *domain, const int is_delete);
int AddGloballyReadablePolicy(char *data, const int is_delete);
int AddInitializerPolicy(char *data, const int is_delete);
int AddMountPolicy(char *data, const int is_delete);
int AddNetworkPolicy(char *data, struct domain_info *domain, const int is_delete);
int AddNoRewritePolicy(char *pattern, const int is_delete);
int AddNoUmountPolicy(char *data, const int is_delete);
int AddPatternPolicy(char *data, const int is_delete);
int AddReservedPortPolicy(char *data, const int is_delete);
int AddSignalPolicy(char *data, struct domain_info *domain, const int is_delete);
int AddTrustedPatternPolicy(char *data, const int is_delete);
int CCS_CloseControl(struct file *file);
int CCS_OpenControl(const int type, struct file *file);
int CCS_PollControl(struct file *file, poll_table *wait);
int CCS_ReadControl(struct file *file, char __user *buffer, const int buffer_len);
int CCS_WriteControl(struct file *file, const char __user *buffer, const int buffer_len);
int CanSaveAuditLog(const int is_granted);
int CheckSupervisor(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));
int DeleteDomain(char *data);
int IsCorrectPath(const char *filename, const int start_type, const int pattern_type, const int end_type, const char *function);
int IsDomainDef(const unsigned char *buffer);
int PathMatchesToPattern(const char *pathname, const char *pattern);
int PollGrantLog(struct file *file, poll_table *wait);
int PollRejectLog(struct file *file, poll_table *wait);
int ReadAliasPolicy(IO_BUFFER *head);
int ReadAggregatorPolicy(IO_BUFFER *head);
int ReadCapabilityStatus(IO_BUFFER *head);
int ReadChrootPolicy(IO_BUFFER *head);
int ReadGloballyReadablePolicy(IO_BUFFER *head);
int ReadGrantLog(IO_BUFFER *head);
int ReadInitializerPolicy(IO_BUFFER *head);
int ReadMountPolicy(IO_BUFFER *head);
int ReadNoRewritePolicy(IO_BUFFER *head);
int ReadNoUmountPolicy(IO_BUFFER *head);
int ReadPatternPolicy(IO_BUFFER *head);
int ReadPermissionMapping(IO_BUFFER *head);
int ReadRejectLog(IO_BUFFER *head);
int ReadReservedPortPolicy(IO_BUFFER *head);
int ReadSelfDomain(IO_BUFFER *head);
int ReadTrustedPIDs(IO_BUFFER *head);
int ReadTrustedPatternPolicy(IO_BUFFER *head);
int SetCapabilityStatus(const char *data, unsigned int value, const unsigned int profile);
int SetPermissionMapping(IO_BUFFER *head);
int WriteAuditLog(char *log, const int is_granted);
int acltype2paths(const unsigned int acl_type);
int io_printf(IO_BUFFER *head, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));
int PathDepth(const char *pathname);
char *ccs_alloc(const size_t size);
void ccs_free(const void *p);
int strendswith(const char *name, const char *tail);
struct domain_info *FindDomain(const char *domainname);
struct domain_info *FindOrAssignNewDomain(const char *domainname, const u8 profile);
unsigned int CheckCCSAccept(const unsigned int index);
unsigned int CheckCCSEnforce(const unsigned int index);
unsigned int CheckCCSFlags(const unsigned int index);
unsigned int GetMaxAutoAppendFiles(void);
unsigned int GetMaxGrantLog(void);
unsigned int GetMaxRejectLog(void);
unsigned int TomoyoVerboseMode(void);
void SetDomainAttribute(struct domain_info *domain, const u16 attribute);
u16 GetDomainAttribute(const struct domain_info *domain);
char *FindConditionPart(char *data);
const struct condition_list *FindOrAssignNewCondition(const char *condition);
int DumpCondition(IO_BUFFER *head, const struct condition_list *ptr);
int CheckCondition(const struct condition_list *condition, struct obj_info *obj_info);
void UpdateCounter(const unsigned char index);
int IsCorrectDomain(const unsigned char *domainname);

#endif
