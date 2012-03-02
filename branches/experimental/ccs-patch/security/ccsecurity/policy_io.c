/*
 * security/ccsecurity/policy_io.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.8.3+   2012/02/29
 */

#include "internal.h"

/***** SECTION1: Constants definition *****/

/* Define this to enable debug mode. */
/* #define DEBUG_CONDITION */

#ifdef DEBUG_CONDITION
#define dprintk printk
#else
#define dprintk(...) do { } while (0)
#endif

/* Mapping table from "enum ccs_mac_index" to "enum ccs_mac_category_index". */
static const u8 ccs_index2category[CCS_MAX_MAC_INDEX] = {
	/* file group */
	[CCS_MAC_FILE_EXECUTE]    = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_READ]       = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_WRITE]      = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_APPEND]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_CREATE]     = CCS_MAC_CATEGORY_FILE,
	[CCS_MAC_FILE_UNLINK]     = CCS_MAC_CATEGORY_FILE,
#ifdef CONFIG_CCSECURITY_FILE_GETATTR
	[CCS_MAC_FILE_GETATTR]    = CCS_MAC_CATEGORY_FILE,
#endif
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
	/* misc group */
#ifdef CONFIG_CCSECURITY_MISC
	[CCS_MAC_ENVIRON]         = CCS_MAC_CATEGORY_MISC,
#endif
	/* network group */
#ifdef CONFIG_CCSECURITY_NETWORK
	[CCS_MAC_NETWORK_INET_STREAM_BIND]       = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_STREAM_LISTEN]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_STREAM_CONNECT]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_STREAM_ACCEPT]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_DGRAM_BIND]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_DGRAM_SEND]        = CCS_MAC_CATEGORY_NETWORK,
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	[CCS_MAC_NETWORK_INET_DGRAM_RECV]        = CCS_MAC_CATEGORY_NETWORK,
#endif
	[CCS_MAC_NETWORK_INET_RAW_BIND]          = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_INET_RAW_SEND]          = CCS_MAC_CATEGORY_NETWORK,
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	[CCS_MAC_NETWORK_INET_RAW_RECV]          = CCS_MAC_CATEGORY_NETWORK,
#endif
	[CCS_MAC_NETWORK_UNIX_STREAM_BIND]       = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_LISTEN]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_CONNECT]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT]     = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_DGRAM_BIND]        = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_DGRAM_SEND]        = CCS_MAC_CATEGORY_NETWORK,
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	[CCS_MAC_NETWORK_UNIX_DGRAM_RECV]        = CCS_MAC_CATEGORY_NETWORK,
#endif
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND]    = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN]  = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT] = CCS_MAC_CATEGORY_NETWORK,
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT]  = CCS_MAC_CATEGORY_NETWORK,
#endif
	/* ipc group */
#ifdef CONFIG_CCSECURITY_IPC
	[CCS_MAC_PTRACE]          = CCS_MAC_CATEGORY_IPC,
#endif
	/* capability group */
	[CCS_MAC_CAPABILITY_MODIFY_POLICY]     = CCS_MAC_CATEGORY_CAPABILITY,
#ifdef CONFIG_CCSECURITY_CAPABILITY
	[CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET]  = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_USE_PACKET_SOCKET] = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_REBOOT]        = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_VHANGUP]       = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_SETTIME]       = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_NICE]          = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_SETHOSTNAME]   = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_USE_KERNEL_MODULE] = CCS_MAC_CATEGORY_CAPABILITY,
	[CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD]    = CCS_MAC_CATEGORY_CAPABILITY,
#endif
#ifdef CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION
	[CCS_MAC_AUTO_TASK_TRANSITION]   = CCS_MAC_CATEGORY_TASK,
	[CCS_MAC_MANUAL_TASK_TRANSITION] = CCS_MAC_CATEGORY_TASK,
#endif
};

/* String table for operation. */
static const char * const ccs_mac_keywords[CCS_MAX_MAC_INDEX] = {
	/* file group */
	[CCS_MAC_FILE_EXECUTE]    = "execute",
	[CCS_MAC_FILE_READ]       = "read",
	[CCS_MAC_FILE_WRITE]      = "write",
	[CCS_MAC_FILE_APPEND]     = "append",
	[CCS_MAC_FILE_CREATE]     = "create",
	[CCS_MAC_FILE_UNLINK]     = "unlink",
#ifdef CONFIG_CCSECURITY_FILE_GETATTR
	[CCS_MAC_FILE_GETATTR]    = "getattr",
#endif
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
	/* misc group */
#ifdef CONFIG_CCSECURITY_MISC
	[CCS_MAC_ENVIRON] = "env",
#endif
	/* network group */
#ifdef CONFIG_CCSECURITY_NETWORK
	[CCS_MAC_NETWORK_INET_STREAM_BIND]       = "inet_stream_bind",
	[CCS_MAC_NETWORK_INET_STREAM_LISTEN]     = "inet_stream_listen",
	[CCS_MAC_NETWORK_INET_STREAM_CONNECT]    = "inet_stream_connect",
	[CCS_MAC_NETWORK_INET_STREAM_ACCEPT]     = "inet_stream_accept",
	[CCS_MAC_NETWORK_INET_DGRAM_BIND]        = "inet_dgram_bind",
	[CCS_MAC_NETWORK_INET_DGRAM_SEND]        = "inet_dgram_send",
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	[CCS_MAC_NETWORK_INET_DGRAM_RECV]        = "inet_dgram_recv",
#endif
	[CCS_MAC_NETWORK_INET_RAW_BIND]          = "inet_raw_bind",
	[CCS_MAC_NETWORK_INET_RAW_SEND]          = "inet_raw_send",
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	[CCS_MAC_NETWORK_INET_RAW_RECV]          = "inet_raw_recv",
#endif
	[CCS_MAC_NETWORK_UNIX_STREAM_BIND]       = "unix_stream_bind",
	[CCS_MAC_NETWORK_UNIX_STREAM_LISTEN]     = "unix_stream_listen",
	[CCS_MAC_NETWORK_UNIX_STREAM_CONNECT]    = "unix_stream_connect",
	[CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT]     = "unix_stream_accept",
	[CCS_MAC_NETWORK_UNIX_DGRAM_BIND]        = "unix_dgram_bind",
	[CCS_MAC_NETWORK_UNIX_DGRAM_SEND]        = "unix_dgram_send",
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	[CCS_MAC_NETWORK_UNIX_DGRAM_RECV]        = "unix_dgram_recv",
#endif
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND]    = "unix_seqpacket_bind",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN]  = "unix_seqpacket_listen",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT] = "unix_seqpacket_connect",
	[CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT]  = "unix_seqpacket_accept",
#endif
	/* ipc group */
#ifdef CONFIG_CCSECURITY_IPC
	[CCS_MAC_PTRACE] = "ptrace",
#endif
	/* capability group */
	[CCS_MAC_CAPABILITY_MODIFY_POLICY]     = "modify_policy",
#ifdef CONFIG_CCSECURITY_CAPABILITY
	[CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET]  = "use_route",
	[CCS_MAC_CAPABILITY_USE_PACKET_SOCKET] = "use_packet",
	[CCS_MAC_CAPABILITY_SYS_REBOOT]        = "SYS_REBOOT",
	[CCS_MAC_CAPABILITY_SYS_VHANGUP]       = "SYS_VHANGUP",
	[CCS_MAC_CAPABILITY_SYS_SETTIME]       = "SYS_TIME",
	[CCS_MAC_CAPABILITY_SYS_NICE]          = "SYS_NICE",
	[CCS_MAC_CAPABILITY_SYS_SETHOSTNAME]   = "SYS_SETHOSTNAME",
	[CCS_MAC_CAPABILITY_USE_KERNEL_MODULE] = "use_kernel_module",
	[CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD]    = "SYS_KEXEC_LOAD",
#endif
	/* task group */
#ifdef CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION
	[CCS_MAC_AUTO_TASK_TRANSITION]   = "auto_domain_transition",
	[CCS_MAC_MANUAL_TASK_TRANSITION] = "manual_domain_transition",
#endif
};

/* String table for categories. */
static const char * const ccs_category_keywords[CCS_MAX_MAC_CATEGORY_INDEX] = {
	[CCS_MAC_CATEGORY_FILE]       = "file",
#ifdef CONFIG_CCSECURITY_NETWORK
	[CCS_MAC_CATEGORY_NETWORK]    = "network",
#endif
#ifdef CONFIG_CCSECURITY_MISC
	[CCS_MAC_CATEGORY_MISC]       = "misc",
#endif
#ifdef CONFIG_CCSECURITY_IPC
	[CCS_MAC_CATEGORY_IPC]        = "ipc",
#endif
	[CCS_MAC_CATEGORY_CAPABILITY] = "capability",
#ifdef CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION
	[CCS_MAC_CATEGORY_TASK]       = "task",
#endif
	[CCS_MAC_CATEGORY_NONE]       = "",
};

/* String table for conditions. */
static const char *const ccs_condition_keyword[CCS_MAX_CONDITION_KEYWORD] = {
	[CCS_SELF_UID]             = "uid",
	[CCS_SELF_EUID]            = "euid",
	[CCS_SELF_SUID]            = "suid",
	[CCS_SELF_FSUID]           = "fsuid",
	[CCS_SELF_GID]             = "gid",
	[CCS_SELF_EGID]            = "egid",
	[CCS_SELF_SGID]            = "sgid",
	[CCS_SELF_FSGID]           = "fsgid",
	[CCS_SELF_PID]             = "pid",
	[CCS_SELF_PPID]            = "ppid",
	[CCS_TASK_TYPE]            = "type",
	[CCS_SELF_DOMAIN]          = "domain",
	[CCS_SELF_EXE]             = "exe",
	[CCS_EXEC_ARGC]            = "argc",
	[CCS_EXEC_ENVC]            = "envc",
	[CCS_OBJ_IS_SOCKET]        = "socket",
	[CCS_OBJ_IS_SYMLINK]       = "symlink",
	[CCS_OBJ_IS_FILE]          = "file",
	[CCS_OBJ_IS_BLOCK_DEV]     = "block",
	[CCS_OBJ_IS_DIRECTORY]     = "directory",
	[CCS_OBJ_IS_CHAR_DEV]      = "char",
	[CCS_OBJ_IS_FIFO]          = "fifo",
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
	[CCS_TASK_EXECUTE_HANDLER] = "execute_handler",
	[CCS_HANDLER_PATH]         = "handler",
	[CCS_TRANSIT_DOMAIN]       = "transition",
};

/* String table for file attributes. */
static const char *const ccs_path_attribute[CCS_MAX_PATH_ATTRIBUTE] = {
	[CCS_PATH_ATTRIBUTE_UID]       = "uid",
	[CCS_PATH_ATTRIBUTE_GID]       = "gid",
	[CCS_PATH_ATTRIBUTE_INO]       = "ino",
	[CCS_PATH_ATTRIBUTE_MAJOR]     = "major",
	[CCS_PATH_ATTRIBUTE_MINOR]     = "minor",
	[CCS_PATH_ATTRIBUTE_PERM]      = "perm",
	[CCS_PATH_ATTRIBUTE_TYPE]      = "type",
	[CCS_PATH_ATTRIBUTE_DEV_MAJOR] = "dev_major",
	[CCS_PATH_ATTRIBUTE_DEV_MINOR] = "dev_minor",
	[CCS_PATH_ATTRIBUTE_FSMAGIC]   = "fsmagic",
};

/* String table for grouping keywords. */
static const char * const ccs_group_name[CCS_MAX_GROUP] = {
	[CCS_PATH_GROUP]    = "path_group",
	[CCS_DOMAIN_GROUP]  = "domain_group",
	[CCS_NUMBER_GROUP]  = "number_group",
#ifdef CONFIG_CCSECURITY_NETWORK
	[CCS_ADDRESS_GROUP] = "address_group",
#endif
};

/* String table for stat info. */
static const char * const ccs_memory_headers[CCS_MAX_MEMORY_STAT] = {
	[CCS_MEMORY_POLICY]     = "policy",
	[CCS_MEMORY_AUDIT]      = "audit",
	[CCS_MEMORY_QUERY]      = "query",
};

/***** SECTION2: Structure definition *****/

struct iattr;

/* Structure for query. */
struct ccs_query {
	struct list_head list;
	struct ccs_acl_info *acl;
	char *query;
	size_t query_len;
	unsigned int serial;
	u8 timer;
	u8 answer;
	u8 retry;
};

/* Structure for audit log. */
struct ccs_log {
	struct list_head list;
	char *log;
	int size;
	enum ccs_matching_result result;
};

/***** SECTION3: Prototype definition section *****/

int ccs_audit_log(struct ccs_request_info *r);
bool ccs_manager(void);
struct ccs_domain_info *ccs_assign_domain(const char *domainname);

static bool ccs_correct_domain(const unsigned char *domainname);
static bool ccs_correct_word(const char *string);
static bool ccs_correct_word2(const char *string, size_t len);
static bool ccs_flush(struct ccs_io_buffer *head);
static bool ccs_print_condition(struct ccs_io_buffer *head,
				const struct ccs_condition *cond);
static bool ccs_read_acl(struct ccs_io_buffer *head,
			 const struct ccs_acl_info *acl);
static bool ccs_read_group(struct ccs_io_buffer *head);
static bool ccs_select_acl(struct ccs_io_buffer *head, const char *data);
static bool ccs_set_lf(struct ccs_io_buffer *head);
static bool ccs_str_starts(char **src, const char *find);
static char *ccs_init_log(struct ccs_request_info *r);
static char *ccs_print_bprm(struct linux_binprm *bprm,
			    struct ccs_page_dump *dump);
static char *ccs_print_trailer(struct ccs_request_info *r);
static char *ccs_read_token(struct ccs_io_buffer *head);
static const char *ccs_yesno(const unsigned int value);
static const struct ccs_path_info *ccs_get_dqword(char *start);
static int __init ccs_init_module(void);
static int ccs_open(struct inode *inode, struct file *file);
static int ccs_parse_policy(struct ccs_io_buffer *head, char *line);
static int ccs_poll_log(struct file *file, poll_table *wait);
static int ccs_poll_query(struct file *file, poll_table *wait);
static int ccs_release(struct inode *inode, struct file *file);
static int ccs_supervisor(struct ccs_request_info *r);
static int ccs_update_group(struct ccs_io_buffer *head,
			    const enum ccs_group_id type);
static int ccs_write_answer(struct ccs_io_buffer *head);
static int ccs_write_audit_quota(char *data);
static int ccs_write_memory_quota(char *data);
static int ccs_write_pid(struct ccs_io_buffer *head);
static int ccs_write_policy(struct ccs_io_buffer *head);
static ssize_t ccs_read(struct file *file, char __user *buf, size_t count,
			loff_t *ppos);
static ssize_t ccs_read_self(struct file *file, char __user *buf, size_t count,
			     loff_t *ppos);
static ssize_t ccs_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos);
static struct ccs_condition *ccs_get_condition(struct ccs_io_buffer *head);
static struct ccs_domain_info *ccs_find_domain(const char *domainname);
static struct ccs_acl_info *ccs_find_acl_by_qid(unsigned int serial);
static struct ccs_group *ccs_get_group(struct ccs_io_buffer *head,
				       const enum ccs_group_id idx);
static u8 ccs_make_byte(const u8 c1, const u8 c2, const u8 c3);
static enum ccs_value_type ccs_parse_ulong(unsigned long *result, char **str);
static unsigned int ccs_poll(struct file *file, poll_table *wait);
static void __init ccs_create_entry(const char *name, const umode_t mode,
				    struct proc_dir_entry *parent,
				    const u8 key);
static void __init ccs_load_builtin_policy(void);
static void __init ccs_policy_io_init(void);
static void __init ccs_proc_init(void);
static void ccs_check_profile(void);
static void ccs_convert_time(time_t time, struct ccs_time *stamp);
static void ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...)
	__printf(2, 3);
static void ccs_normalize_line(unsigned char *buffer);
static void ccs_read_log(struct ccs_io_buffer *head);
static void ccs_read_pid(struct ccs_io_buffer *head);
static void ccs_read_policy(struct ccs_io_buffer *head);
static void ccs_read_query(struct ccs_io_buffer *head);
static bool ccs_read_quota(struct ccs_io_buffer *head);
static bool ccs_read_stat(struct ccs_io_buffer *head);
static void ccs_read_version(struct ccs_io_buffer *head);
static void ccs_set_space(struct ccs_io_buffer *head);
static void ccs_set_string(struct ccs_io_buffer *head, const char *string);
static void ccs_update_stat(const u8 index);
static void ccs_write_log(struct ccs_request_info *r);


#ifdef CONFIG_CCSECURITY_NETWORK
static int ccs_print_ipv4(char *buffer, const unsigned int buffer_len,
			  const u8 *ip);
static int ccs_print_ipv6(char *buffer, const unsigned int buffer_len,
			  const struct in6_addr *ip);
static void ccs_print_ip(struct ccs_io_buffer *head,
			 struct ccs_address_group *member);
#endif

#ifdef CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION
static ssize_t ccs_write_self(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos);
#endif

/***** SECTION4: Standalone functions section *****/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)

/**
 * fatal_signal_pending - Check whether SIGKILL is pending or not.
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns true if SIGKILL is pending on @p, false otherwise.
 *
 * This is for compatibility with older kernels.
 */
#define fatal_signal_pending(p) (signal_pending(p) &&			\
				 sigismember(&p->pending.signal, SIGKILL))

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

/**
 * __wait_event_interruptible_timeout - Sleep until a condition gets true or a timeout elapses.
 *
 * @wq:        The waitqueue to wait on.
 * @condition: A C expression for the event to wait for.
 * @ret:       Timeout, in jiffies.
 *
 * Returns 0 if the @timeout elapsed, -ERESTARTSYS if it was interrupted by a
 * signal, and the remaining jiffies otherwise if the condition evaluated to
 * true before the timeout elapsed.
 *
 * This is for compatibility with older kernels.
 */
#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	wait_queue_t __wait;						\
	init_waitqueue_entry(&__wait, current);				\
									\
	add_wait_queue(&wq, &__wait);					\
	for (;;) {							\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)

/**
 * wait_event_interruptible_timeout - Sleep until a condition gets true or a timeout elapses.
 *
 * @wq:        The waitqueue to wait on.
 * @condition: A C expression for the event to wait for.
 * @timeout:   Timeout, in jiffies.
 *
 * Returns 0 if the @timeout elapsed, -ERESTARTSYS if it was interrupted by a
 * signal, and the remaining jiffies otherwise if the condition evaluated to
 * true before the timeout elapsed.
 *
 * This is for compatibility with older kernels.
 */
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})

#endif

/**
 * ccs_convert_time - Convert time_t to YYYY/MM/DD hh/mm/ss.
 *
 * @time:  Seconds since 1970/01/01 00:00:00.
 * @stamp: Pointer to "struct ccs_time".
 *
 * Returns nothing.
 *
 * This function does not handle Y2038 problem.
 */
static void ccs_convert_time(time_t time, struct ccs_time *stamp)
{
	static const u16 ccs_eom[2][12] = {
		{ 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
		{ 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
	};
	u16 y;
	u8 m;
	bool r;
	stamp->sec = time % 60;
	time /= 60;
	stamp->min = time % 60;
	time /= 60;
	stamp->hour = time % 24;
	time /= 24;
	for (y = 1970; ; y++) {
		const unsigned short days = (y & 3) ? 365 : 366;
		if (time < days)
			break;
		time -= days;
	}
	r = (y & 3) == 0;
	for (m = 0; m < 11 && time >= ccs_eom[r][m]; m++);
	if (m)
		time -= ccs_eom[r][m - 1];
	stamp->year = y;
	stamp->month = ++m;
	stamp->day = ++time;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 23)
#if !defined(RHEL_VERSION) || RHEL_VERSION != 3

/**
 * PDE - Get "struct proc_dir_entry".
 *
 * @inode: Pointer to "struct inode".
 *
 * Returns pointer to "struct proc_dir_entry".
 *
 * This is for compatibility with older kernels.
 */
static inline struct proc_dir_entry *PDE(const struct inode *inode)
{
	return (struct proc_dir_entry *) inode->u.generic_ip;
}

#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

/**
 * proc_notify_change - Update inode's attributes and reflect to the dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @iattr:  Pointer to "struct iattr".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * The 2.4 kernels don't allow chmod()/chown() for files in /proc,
 * while the 2.6 kernels allow.
 * To permit management of /proc/ccs/ interface by non-root user,
 * I modified to allow chmod()/chown() of /proc/ccs/ interface like 2.6 kernels
 * by adding "struct inode_operations"->setattr hook.
 */
static int proc_notify_change(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	struct proc_dir_entry *de = PDE(inode);
	int error;

	error = inode_change_ok(inode, iattr);
	if (error)
		goto out;

	error = inode_setattr(inode, iattr);
	if (error)
		goto out;

	de->uid = inode->i_uid;
	de->gid = inode->i_gid;
	de->mode = inode->i_mode;
out:
	return error;
}

#endif

#ifdef CONFIG_CCSECURITY_NETWORK

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19) && defined(CONFIG_NET)
#define ccs_in4_pton in4_pton
#define ccs_in6_pton in6_pton
#else
/*
 * Routines for parsing IPv4 or IPv6 address.
 * These are copied from lib/hexdump.c net/core/utils.c .
 */
#include <linux/ctype.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
static int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}
#endif

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
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)

/*
 * Routines for printing IPv4 or IPv6 address.
 * These are copied from include/linux/kernel.h include/net/ipv6.h
 * include/net/addrconf.h lib/hexdump.c lib/vsprintf.c and simplified.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
static const char hex_asc[] = "0123456789abcdef";
#define hex_asc_lo(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)   hex_asc[((x) & 0xf0) >> 4]

static inline char *pack_hex_byte(char *buf, u8 byte)
{
	*buf++ = hex_asc_hi(byte);
	*buf++ = hex_asc_lo(byte);
	return buf;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
static inline int ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return (a->s6_addr32[0] | a->s6_addr32[1] |
		(a->s6_addr32[2] ^ htonl(0x0000ffff))) == 0;
}
#endif

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
	bool needcolon = false;
	bool useIPv4;
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
#endif

/**
 * ccs_print_ipv4 - Print an IPv4 address.
 *
 * @buffer:     Buffer to write to.
 * @buffer_len: Size of @buffer.
 * @ip:         Pointer to "u8" in network byte order.
 *
 * Returns written length.
 */
static int ccs_print_ipv4(char *buffer, const unsigned int buffer_len,
			  const u8 *ip)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	return snprintf(buffer, buffer_len, "%pI4", ip);
#else
	char addr[sizeof("255.255.255.255")];
	ip4_string(addr, ip);
	return snprintf(buffer, buffer_len, "%s", addr);
#endif
}

/**
 * ccs_print_ipv6 - Print an IPv6 address.
 *
 * @buffer:     Buffer to write to.
 * @buffer_len: Size of @buffer.
 * @ip:         Pointer to "struct in6_addr".
 *
 * Returns written length.
 */
static int ccs_print_ipv6(char *buffer, const unsigned int buffer_len,
			  const struct in6_addr *ip)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	return snprintf(buffer, buffer_len, "%pI6c", ip);
#else
	char addr[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];
	ip6_compressed_string(addr, (const u8 *) ip);
	return snprintf(buffer, buffer_len, "%s", addr);
#endif
}

/**
 * ccs_print_ip - Print an IP address.
 *
 * @head:   Pointer to "struct ccs_io_buffer".
 * @member: Pointer to "struct ccs_address_group".
 *
 * Returns nothing.
 */
static void ccs_print_ip(struct ccs_io_buffer *head,
			 struct ccs_address_group *member)
{
	char addr[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];
	u8 i;
	for (i = 0; i < 2; i++) {
		if (member->is_ipv6)
			ccs_print_ipv6(addr, sizeof(addr), &member->ip[i]);
		else
			ccs_print_ipv4(addr, sizeof(addr),
				       member->ip[i].s6_addr);
		ccs_io_printf(head, "%s", addr);
		if (i)
			break;
		if (!memcmp(&member->ip[0], &member->ip[1], 16))
			break;
		ccs_set_string(head, "-");
	}
}

#endif

/**
 * ccs_get_sarg - Get attribute name of CCS_SARG argument.
 *
 * @type:  One of values in "enum ccs_mac_index".
 * @index: Index to return.
 *
 * Returns attribute name.
 */
static const char *ccs_get_sarg(const enum ccs_mac_index type, const u8 index)
{
	switch (type) {
	case CCS_MAC_FILE_LINK:
	case CCS_MAC_FILE_RENAME:
		if (index == 0)
			return "old_path";
		if (index == 1)
			return "new_path";
		break;
	case CCS_MAC_FILE_MOUNT:
		if (index == 0)
			return "source";
		if (index == 1)
			return "target";
		if (index == 2)
			return "fstype";
		break;
	case CCS_MAC_FILE_PIVOT_ROOT:
		if (index == 0)
			return "new_root";
		if (index == 1)
			return "put_old";
		break;
#ifdef CONFIG_CCSECURITY_MISC
	case CCS_MAC_ENVIRON:
		if (index == 2)
			return "name";
		if (index == 3)
			return "value";
		/* fall through */
#endif
	case CCS_MAC_FILE_EXECUTE:
		if (index == 0)
			return "path";
		if (index == 1)
			return "exec";
		break;
	case CCS_MAC_FILE_SYMLINK:
		if (index == 0)
			return "path";
		if (index == 1)
			return "target";
		break;
	case CCS_MAC_FILE_READ:
	case CCS_MAC_FILE_WRITE:
	case CCS_MAC_FILE_APPEND:
	case CCS_MAC_FILE_UNLINK:
#ifdef CONFIG_CCSECURITY_FILE_GETATTR
	case CCS_MAC_FILE_GETATTR:
#endif
	case CCS_MAC_FILE_RMDIR:
	case CCS_MAC_FILE_TRUNCATE:
	case CCS_MAC_FILE_CHROOT:
	case CCS_MAC_FILE_CHMOD:
	case CCS_MAC_FILE_CHOWN:
	case CCS_MAC_FILE_CHGRP:
	case CCS_MAC_FILE_IOCTL:
	case CCS_MAC_FILE_MKDIR:
	case CCS_MAC_FILE_CREATE:
	case CCS_MAC_FILE_MKFIFO:
	case CCS_MAC_FILE_MKSOCK:
	case CCS_MAC_FILE_MKBLOCK:
	case CCS_MAC_FILE_MKCHAR:
	case CCS_MAC_FILE_UMOUNT:
		if (index == 0)
			return "path";
		break;
	case CCS_MAC_CAPABILITY_MODIFY_POLICY:
#ifdef CONFIG_CCSECURITY_CAPABILITY
	case CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET:
	case CCS_MAC_CAPABILITY_USE_PACKET_SOCKET:
	case CCS_MAC_CAPABILITY_SYS_REBOOT:
	case CCS_MAC_CAPABILITY_SYS_VHANGUP:
	case CCS_MAC_CAPABILITY_SYS_SETTIME:
	case CCS_MAC_CAPABILITY_SYS_NICE:
	case CCS_MAC_CAPABILITY_SYS_SETHOSTNAME:
	case CCS_MAC_CAPABILITY_USE_KERNEL_MODULE:
	case CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD:
#endif
		break;
#ifdef CONFIG_CCSECURITY_NETWORK
	case CCS_MAC_NETWORK_INET_STREAM_BIND:
	case CCS_MAC_NETWORK_INET_STREAM_LISTEN:
	case CCS_MAC_NETWORK_INET_STREAM_CONNECT:
	case CCS_MAC_NETWORK_INET_STREAM_ACCEPT:
	case CCS_MAC_NETWORK_INET_DGRAM_BIND:
	case CCS_MAC_NETWORK_INET_DGRAM_SEND:
	case CCS_MAC_NETWORK_INET_DGRAM_RECV:
	case CCS_MAC_NETWORK_INET_RAW_BIND:
	case CCS_MAC_NETWORK_INET_RAW_SEND:
	case CCS_MAC_NETWORK_INET_RAW_RECV:
		if (index == 0)
			return "ip";
		break;
	case CCS_MAC_NETWORK_UNIX_STREAM_BIND:
	case CCS_MAC_NETWORK_UNIX_STREAM_LISTEN:
	case CCS_MAC_NETWORK_UNIX_STREAM_CONNECT:
	case CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT:
	case CCS_MAC_NETWORK_UNIX_DGRAM_BIND:
	case CCS_MAC_NETWORK_UNIX_DGRAM_SEND:
	case CCS_MAC_NETWORK_UNIX_DGRAM_RECV:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT:
		if (index == 0)
			return "addr";
		break;
#endif
#ifdef CONFIG_CCSECURITY_IPC
	case CCS_MAC_PTRACE:
		if (index == 0)
			return "domain";
		break;
#endif
	default:
		break;
	}
	return "unknown"; /* This should not happen. */
}

/**
 * ccs_get_narg - Get attribute name of CCS_NARG argument.
 *
 * @type:  One of values in "enum ccs_mac_index".
 * @index: Index to return.
 *
 * Returns attribute name.
 */
static const char *ccs_get_narg(const enum ccs_mac_index type, const u8 index)
{
	switch (type) {
	case CCS_MAC_FILE_MOUNT:
	case CCS_MAC_FILE_UMOUNT:
		if (index == 0)
			return "flags";
		break;
	case CCS_MAC_FILE_CHMOD:
		if (index == 0)
			return "perm";
		break;
	case CCS_MAC_FILE_CHOWN:
		if (index == 0)
			return "uid";
		break;
	case CCS_MAC_FILE_CHGRP:
		if (index == 0)
			return "gid";
		break;
	case CCS_MAC_FILE_IOCTL:
		if (index == 0)
			return "cmd";
		break;
	case CCS_MAC_FILE_MKDIR:
	case CCS_MAC_FILE_CREATE:
	case CCS_MAC_FILE_MKFIFO:
	case CCS_MAC_FILE_MKSOCK:
		if (index == 0)
			return "perm";
		break;
	case CCS_MAC_FILE_MKBLOCK:
	case CCS_MAC_FILE_MKCHAR:
		if (index == 0)
			return "perm";
		if (index == 1)
			return "dev_major";
		if (index == 2)
			return "dev_minor";
		break;
#ifdef CONFIG_CCSECURITY_NETWORK
	case CCS_MAC_NETWORK_INET_STREAM_BIND:
	case CCS_MAC_NETWORK_INET_STREAM_LISTEN:
	case CCS_MAC_NETWORK_INET_STREAM_CONNECT:
	case CCS_MAC_NETWORK_INET_STREAM_ACCEPT:
	case CCS_MAC_NETWORK_INET_DGRAM_BIND:
	case CCS_MAC_NETWORK_INET_DGRAM_SEND:
	case CCS_MAC_NETWORK_INET_DGRAM_RECV:
		if (index == 0)
			return "port";
		break;
	case CCS_MAC_NETWORK_INET_RAW_BIND:
	case CCS_MAC_NETWORK_INET_RAW_SEND:
	case CCS_MAC_NETWORK_INET_RAW_RECV:
		if (index == 0)
			return "proto";
		break;
#endif
#ifdef CONFIG_CCSECURITY_IPC
	case CCS_MAC_PTRACE:
		if (index == 0)
			return "cmd";
		break;
#endif
	default:
		break;
	}
	return "unknown"; /* This should not happen. */
}

/***** SECTION5: Variables definition section *****/

/* Lock for protecting policy. */
DEFINE_MUTEX(ccs_policy_lock);

/* Has /sbin/init started? */
bool ccs_policy_loaded;

/* List of "struct ccs_group". */
struct list_head ccs_group_list[CCS_MAX_GROUP];
/* Policy version. Currently only 20100903 is defined. */
static unsigned int ccs_policy_version = 20100903;

/* List of "struct ccs_condition". */
LIST_HEAD(ccs_condition_list);

/* Wait queue for kernel -> userspace notification. */
static DECLARE_WAIT_QUEUE_HEAD(ccs_query_wait);
/* Wait queue for userspace -> kernel notification. */
static DECLARE_WAIT_QUEUE_HEAD(ccs_answer_wait);

/* The list for "struct ccs_query". */
static LIST_HEAD(ccs_query_list);

/* Lock for manipulating ccs_query_list. */
static DEFINE_SPINLOCK(ccs_query_list_lock);

/* Number of "struct file" referring /proc/ccs/query interface. */
static atomic_t ccs_query_observers = ATOMIC_INIT(0);

/* Wait queue for /proc/ccs/audit. */
static DECLARE_WAIT_QUEUE_HEAD(ccs_log_wait);

/* The list for "struct ccs_log". */
static LIST_HEAD(ccs_log);

/* Lock for "struct list_head ccs_log". */
static DEFINE_SPINLOCK(ccs_log_lock);

/* Length of "stuct list_head ccs_log". */
static unsigned int ccs_log_count[CCS_MAX_MATCHING];
/* Quota for audit logs. */
static unsigned int ccs_log_quota[CCS_MAX_LOG_QUOTA][CCS_MAX_MATCHING];

/* Timestamp counter for last updated. */
static unsigned int ccs_stat_updated[CCS_MAX_POLICY_STAT];

/* Counter for number of updates. */
static unsigned int ccs_stat_modified[CCS_MAX_POLICY_STAT];

/* Operations for /proc/ccs/self_domain interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations ccs_self_operations = {
#ifdef CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION
	.write = ccs_write_self,
#endif
	.read  = ccs_read_self,
};

/* Operations for /proc/ccs/ interface. */
static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
const
#endif
struct file_operations ccs_operations = {
	.open    = ccs_open,
	.release = ccs_release,
	.poll    = ccs_poll,
	.read    = ccs_read,
	.write   = ccs_write,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

/* The inode operations for /proc/ccs/ directory. */
static struct inode_operations ccs_dir_inode_operations;

/* The inode operations for files under /proc/ccs/ directory. */
static struct inode_operations ccs_file_inode_operations;

#endif

/***** SECTION6: Dependent functions section *****/

/**
 * list_for_each_cookie - iterate over a list with cookie.
 *
 * @pos:  Pointer to "struct list_head".
 * @head: Pointer to "struct list_head".
 */
#define list_for_each_cookie(pos, head)					\
	for (pos = pos ? pos : srcu_dereference((head)->next, &ccs_ss); \
	     pos != (head); pos = srcu_dereference(pos->next, &ccs_ss))

/**
 * ccs_read_token - Read a word from a line.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns a word on success, "" otherwise.
 *
 * To allow the caller to skip NULL check, this function returns "" rather than
 * NULL if there is no more words to read.
 */
static char *ccs_read_token(struct ccs_io_buffer *head)
{
	char *pos = head->w.data;
	char *del = strchr(pos, ' ');
	if (del)
		*del++ = '\0';
	else
		del = pos + strlen(pos);
	head->w.data = del;
	return pos;
}

/**
 * ccs_make_byte - Make byte value from three octal characters.
 *
 * @c1: The first character.
 * @c2: The second character.
 * @c3: The third character.
 *
 * Returns byte value.
 */
static u8 ccs_make_byte(const u8 c1, const u8 c2, const u8 c3)
{
	return ((c1 - '0') << 6) + ((c2 - '0') << 3) + (c3 - '0');
}

/**
 * ccs_correct_word2 - Check whether the given string follows the naming rules.
 *
 * @string: The byte sequence to check. Not '\0'-terminated.
 * @len:    Length of @string.
 *
 * Returns true if @string follows the naming rules, false otherwise.
 */
static bool ccs_correct_word2(const char *string, size_t len)
{
	const char *const start = string;
	bool in_repetition = false;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	if (!len)
		goto out;
	while (len--) {
		c = *string++;
		if (c == '\\') {
			if (!len--)
				goto out;
			c = *string++;
			switch (c) {
			case '$':   /* "\$" */
			case '+':   /* "\+" */
			case '?':   /* "\?" */
			case '*':   /* "\*" */
			case '@':   /* "\@" */
			case 'x':   /* "\x" */
			case 'X':   /* "\X" */
			case 'a':   /* "\a" */
			case 'A':   /* "\A" */
			case '-':   /* "\-" */
				continue;
			case '{':   /* "/\{" */
				if (string - 3 < start || *(string - 3) != '/')
					break;
				in_repetition = true;
				continue;
			case '}':   /* "\}/" */
				if (*string != '/')
					break;
				if (!in_repetition)
					break;
				in_repetition = false;
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				if (!len-- || !len--)
					break;
				d = *string++;
				e = *string++;
				if (d < '0' || d > '7' || e < '0' || e > '7')
					break;
				c = ccs_make_byte(c, d, e);
				if (c <= ' ' || c >= 127 || c == '\\')
					continue;
			}
			goto out;
		} else if (in_repetition && c == '/') {
			goto out;
		} else if (c <= ' ' || c >= 127) {
			goto out;
		}
	}
	if (in_repetition)
		goto out;
	return true;
out:
	return false;
}

/**
 * ccs_correct_word - Check whether the given string follows the naming rules.
 *
 * @string: The string to check.
 *
 * Returns true if @string follows the naming rules, false otherwise.
 */
static bool ccs_correct_word(const char *string)
{
	return ccs_correct_word2(string, strlen(string));
}

/**
 * ccs_get_group - Allocate memory for "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group".
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @idx:  Index number.
 *
 * Returns pointer to "struct ccs_group" on success, NULL otherwise.
 */
static struct ccs_group *ccs_get_group(struct ccs_io_buffer *head,
				       const enum ccs_group_id idx)
{
	struct ccs_group e = { };
	struct ccs_group *group = NULL;
	struct list_head *list;
	const char *group_name = ccs_read_token(head);
	bool found = false;
	if (!ccs_correct_word(group_name) || idx >= CCS_MAX_GROUP)
		return NULL;
	e.group_name = ccs_get_name(group_name);
	if (!e.group_name)
		return NULL;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list = &ccs_group_list[idx];
	list_for_each_entry(group, list, head.list) {
		if (e.group_name != group->group_name ||
		    atomic_read(&group->head.users) == CCS_GC_IN_PROGRESS)
			continue;
		atomic_inc(&group->head.users);
		found = true;
		break;
	}
	if (!found) {
		struct ccs_group *entry = ccs_commit_ok(&e, sizeof(e));
		if (entry) {
			INIT_LIST_HEAD(&entry->member_list);
			atomic_set(&entry->head.users, 1);
			list_add_tail_rcu(&entry->head.list, list);
			group = entry;
			found = true;
		}
	}
	mutex_unlock(&ccs_policy_lock);
out:
	ccs_put_name(e.group_name);
	return found ? group : NULL;
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
static enum ccs_value_type ccs_parse_ulong(unsigned long *result, char **str)
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
	*result = simple_strtoul(cp, &ep, base);
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
 * ccs_get_dqword - ccs_get_name() for a quoted string.
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
	return ccs_get_name(start);
}

/**
 * ccs_same_condition - Check for duplicated "struct ccs_condition" entry.
 *
 * @a: Pointer to "struct ccs_condition".
 * @b: Pointer to "struct ccs_condition".
 *
 * Returns true if @a == @b, false otherwise.
 */
static bool ccs_same_condition(const struct ccs_condition *a,
			       const struct ccs_condition *b)
{
	return a->size == b->size &&
		!memcmp(a + 1, b + 1, a->size - sizeof(*a));
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
	bool found = false;
	if (mutex_lock_interruptible(&ccs_policy_lock)) {
		dprintk(KERN_WARNING "%u: %s failed\n", __LINE__, __func__);
		ptr = NULL;
		found = true;
		goto out;
	}
	list_for_each_entry(ptr, &ccs_condition_list, head.list) {
		if (!ccs_same_condition(ptr, entry) ||
		    atomic_read(&ptr->head.users) == CCS_GC_IN_PROGRESS)
			continue;
		/* Same entry found. Share this entry. */
		atomic_inc(&ptr->head.users);
		found = true;
		break;
	}
	if (!found) {
		if (ccs_memory_ok(entry, entry->size)) {
			atomic_set(&entry->head.users, 1);
			list_add(&entry->head.list, &ccs_condition_list);
		} else {
			found = true;
			ptr = NULL;
		}
	}
	mutex_unlock(&ccs_policy_lock);
out:
	if (found) {
		ccs_del_condition(&entry->head.list);
		kfree(entry);
		entry = ptr;
	}
	return entry;
}

/**
 * ccs_correct_domain - Check whether the given domainname follows the naming rules.
 *
 * @domainname: The domainname to check.
 *
 * Returns true if @domainname follows the naming rules, false otherwise.
 */
static bool ccs_correct_domain(const unsigned char *domainname)
{
	if (!*domainname || !ccs_correct_word(domainname))
		return false;
	while (*domainname) {
		if (*domainname++ != '\\')
			continue;
		if (*domainname < '0' || *domainname++ > '3')
			return false;
	}
	return true;
}


/**
 * ccs_normalize_line - Format string.
 *
 * @buffer: The line to normalize.
 *
 * Returns nothing.
 *
 * Leading and trailing whitespaces are removed.
 * Multiple whitespaces are packed into single space.
 */
static void ccs_normalize_line(unsigned char *buffer)
{
	unsigned char *sp = buffer;
	unsigned char *dp = buffer;
	bool first = true;
	while (*sp && (*sp <= ' ' || *sp >= 127))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (*sp > ' ' && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || *sp >= 127))
			sp++;
	}
	*dp = '\0';
}

struct ccs_cond_tmp {
	u8 left;
	u8 right;
	bool is_not;
	u8 radix;
	struct ccs_group *group;
	const struct ccs_path_info *path;
	struct in6_addr ipv6[2];
	unsigned long value[2];
	unsigned long argv;
	const struct ccs_path_info *envp;
};

static u8 ccs_parse_values(char *value, unsigned long v[2])
{
	enum ccs_value_type radix1 = ccs_parse_ulong(&v[0], &value);
	enum ccs_value_type radix2;
	if (radix1 == CCS_VALUE_TYPE_INVALID)
		return CCS_VALUE_TYPE_INVALID;
	if (!*value) {
		v[1] = v[0];
		return radix1;
	}
	if (*value++ != '-')
		return CCS_VALUE_TYPE_INVALID;
	radix2 = ccs_parse_ulong(&v[1], &value);
	if (radix2 == CCS_VALUE_TYPE_INVALID || *value || v[0] > v[1])
		return CCS_VALUE_TYPE_INVALID;
	return radix1 | (radix2 << 2);
}

#ifdef CONFIG_CCSECURITY_NETWORK

static u8 ccs_parse_ipaddr(char *address, struct in6_addr ipv6[2])
{
	const char *end;
	if (!strchr(address, ':') &&
	    ccs_in4_pton(address, -1, ipv6[0].s6_addr, '-', &end) > 0) {
		if (!*end) {
			ipv6[0].s6_addr32[0] = ipv6[0].s6_addr32[0];
			ipv6[1].s6_addr32[0] = ipv6[0].s6_addr32[0];
			return 1;
		}
		if (*end++ != '-' ||
		    ccs_in4_pton(end, -1, ipv6[1].s6_addr, '\0', &end) <= 0 ||
		    *end || memcmp(&ipv6[0], &ipv6[1], 4) >= 0)
			return 0;
		return 2;
	}
	if (ccs_in6_pton(address, -1, ipv6[0].s6_addr, '-', &end) > 0) {
		if (!*end) {
			ipv6[1] = ipv6[0];
			return 3;
		}
		if (*end++ != '-' ||
		    ccs_in6_pton(end, -1, ipv6[1].s6_addr, '\0', &end) <= 0 ||
		    *end || memcmp(&ipv6[0], &ipv6[1], 16) >= 0)
			return 0;
		return 4;
	}
	return 0;
}

#endif

static enum ccs_conditions_index ccs_parse_task_cond(const char *word)
{
	if (!strncmp(word, "task.", 5)) {
		word += 5;
		if (!strcmp(word, "uid"))
			return CCS_SELF_UID;
		if (!strcmp(word, "euid"))
			return  CCS_SELF_EUID;
		if (!strcmp(word, "suid"))
			return CCS_SELF_SUID;
		if (!strcmp(word, "fsuid"))
			return  CCS_SELF_FSUID;
		if (!strcmp(word, "gid"))
			return CCS_SELF_GID;
		if (!strcmp(word, "egid"))
			return CCS_SELF_EGID;
		if (!strcmp(word, "sgid"))
			return CCS_SELF_SGID;
		if (!strcmp(word, "fsgid"))
			return CCS_SELF_FSGID;
		if (!strcmp(word, "pid"))
			return CCS_SELF_PID;
		if (!strcmp(word, "ppid"))
			return CCS_SELF_PPID;
		if (!strcmp(word, "type"))
			return CCS_TASK_TYPE;
		if (!strcmp(word, "domain"))
			return CCS_SELF_DOMAIN;
		if (!strcmp(word, "exe"))
			return CCS_SELF_EXE;
	}
	return CCS_MAX_CONDITION_KEYWORD;
}

static enum ccs_conditions_index ccs_parse_syscall_arg
(const char *word, const enum ccs_mac_index type)
{
	switch (type) {
	case CCS_MAC_FILE_READ:
	case CCS_MAC_FILE_WRITE:
	case CCS_MAC_FILE_APPEND:
	case CCS_MAC_FILE_UNLINK:
#ifdef CONFIG_CCSECURITY_FILE_GETATTR
	case CCS_MAC_FILE_GETATTR:
#endif
	case CCS_MAC_FILE_RMDIR:
	case CCS_MAC_FILE_TRUNCATE:
	case CCS_MAC_FILE_CHROOT:
	case CCS_MAC_FILE_CHOWN:
	case CCS_MAC_FILE_CHGRP:
	case CCS_MAC_FILE_IOCTL:
	case CCS_MAC_FILE_EXECUTE:
	case CCS_MAC_FILE_SYMLINK:
		if (!strcmp(word, "path"))
			return CCS_COND_SARG0;
		if (type == CCS_MAC_FILE_CHOWN && !strcmp(word, "uid"))
			return CCS_COND_NARG0;
		if (type == CCS_MAC_FILE_CHGRP && !strcmp(word, "gid"))
			return CCS_COND_NARG0;
		if (type == CCS_MAC_FILE_IOCTL && !strcmp(word, "cmd"))
			return CCS_COND_NARG0;
		if (type == CCS_MAC_FILE_EXECUTE && !strcmp(word, "exec"))
			return CCS_COND_SARG1;
		if (type == CCS_MAC_FILE_SYMLINK && !strcmp(word, "target"))
			return CCS_COND_SARG1;
		break;
	case CCS_MAC_FILE_CHMOD:
	case CCS_MAC_FILE_MKDIR:
	case CCS_MAC_FILE_CREATE:
	case CCS_MAC_FILE_MKFIFO:
	case CCS_MAC_FILE_MKSOCK:
	case CCS_MAC_FILE_MKBLOCK:
	case CCS_MAC_FILE_MKCHAR:
		if (!strcmp(word, "path"))
			return CCS_COND_SARG0;
		if (!strcmp(word, "perm"))
			return CCS_COND_NARG0;
		if (type == CCS_MAC_FILE_MKBLOCK ||
		    type == CCS_MAC_FILE_MKCHAR) {
			if (!strcmp(word, "dev_major"))
				return CCS_COND_NARG1;
			if (!strcmp(word, "dev_minor"))
				return CCS_COND_NARG2;
		}
		break;
	case CCS_MAC_FILE_LINK:
	case CCS_MAC_FILE_RENAME:
		if (!strcmp(word, "old_path"))
			return CCS_COND_SARG0;
		if (!strcmp(word, "new_path"))
			return CCS_COND_SARG1;
		break;
	case CCS_MAC_FILE_MOUNT:
		if (!strcmp(word, "source"))
			return CCS_COND_SARG0;
		if (!strcmp(word, "target"))
			return CCS_COND_SARG1;
		if (!strcmp(word, "fstype"))
			return CCS_COND_SARG2;
		if (!strcmp(word, "flags"))
			return CCS_COND_NARG0;
		break;
	case CCS_MAC_FILE_UMOUNT:
		if (!strcmp(word, "path"))
			return CCS_COND_SARG0;
		if (!strcmp(word, "flags"))
			return CCS_COND_NARG0;
		break;
	case CCS_MAC_FILE_PIVOT_ROOT:
		if (!strcmp(word, "new_root"))
			return CCS_COND_SARG0;
		if (!strcmp(word, "put_old"))
			return CCS_COND_SARG1;
		break;
#ifdef CONFIG_CCSECURITY_NETWORK
	case CCS_MAC_NETWORK_INET_STREAM_BIND:
	case CCS_MAC_NETWORK_INET_STREAM_LISTEN:
	case CCS_MAC_NETWORK_INET_STREAM_CONNECT:
	case CCS_MAC_NETWORK_INET_STREAM_ACCEPT:
	case CCS_MAC_NETWORK_INET_DGRAM_BIND:
	case CCS_MAC_NETWORK_INET_DGRAM_SEND:
	case CCS_MAC_NETWORK_INET_DGRAM_RECV:
		if (!strcmp(word, "ip"))
			return CCS_COND_IPARG;
		if (!strcmp(word, "port"))
			return CCS_COND_NARG0;
		break;
	case CCS_MAC_NETWORK_INET_RAW_BIND:
	case CCS_MAC_NETWORK_INET_RAW_SEND:
	case CCS_MAC_NETWORK_INET_RAW_RECV:
		if (!strcmp(word, "ip"))
			return CCS_COND_IPARG;
		if (!strcmp(word, "proto"))
			return CCS_COND_NARG0;
		break;
	case CCS_MAC_NETWORK_UNIX_STREAM_BIND:
	case CCS_MAC_NETWORK_UNIX_STREAM_LISTEN:
	case CCS_MAC_NETWORK_UNIX_STREAM_CONNECT:
	case CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT:
	case CCS_MAC_NETWORK_UNIX_DGRAM_BIND:
	case CCS_MAC_NETWORK_UNIX_DGRAM_SEND:
	case CCS_MAC_NETWORK_UNIX_DGRAM_RECV:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT:
		if (!strcmp(word, "addr"))
			return CCS_COND_SARG0;
		break;
#endif
#ifdef CONFIG_CCSECURITY_MISC
	case CCS_MAC_ENVIRON:
		if (!strcmp(word, "name"))
			return CCS_COND_SARG2;
		if (!strcmp(word, "value"))
			return CCS_COND_SARG3;
		break;
#endif
#ifdef CONFIG_CCSECURITY_IPC
	case CCS_MAC_PTRACE:
		if (!strcmp(word, "domain"))
			return CCS_COND_DOMAIN;
		if (!strcmp(word, "cmd"))
			return CCS_COND_NARG0;
		break;
#endif
	case CCS_MAC_CAPABILITY_MODIFY_POLICY:
#ifdef CONFIG_CCSECURITY_CAPABILITY
	case CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET:
	case CCS_MAC_CAPABILITY_USE_PACKET_SOCKET:
	case CCS_MAC_CAPABILITY_SYS_REBOOT:
	case CCS_MAC_CAPABILITY_SYS_VHANGUP:
	case CCS_MAC_CAPABILITY_SYS_SETTIME:
	case CCS_MAC_CAPABILITY_SYS_NICE:
	case CCS_MAC_CAPABILITY_SYS_SETHOSTNAME:
	case CCS_MAC_CAPABILITY_USE_KERNEL_MODULE:
	case CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD:
#endif
		break;
	case CCS_MAX_MAC_INDEX:
#ifdef CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION
	case CCS_MAC_AUTO_TASK_TRANSITION:
	case CCS_MAC_MANUAL_TASK_TRANSITION:
#endif
		break;
	}
	return CCS_MAX_CONDITION_KEYWORD;
}

static enum ccs_conditions_index ccs_parse_path_attribute
(char *word, const enum ccs_mac_index type)
{
	u8 i;
	enum ccs_conditions_index start;
	switch (type) {
	case CCS_MAC_FILE_READ:
	case CCS_MAC_FILE_WRITE:
	case CCS_MAC_FILE_APPEND:
	case CCS_MAC_FILE_UNLINK:
#ifdef CONFIG_CCSECURITY_FILE_GETATTR
	case CCS_MAC_FILE_GETATTR:
#endif
	case CCS_MAC_FILE_RMDIR:
	case CCS_MAC_FILE_TRUNCATE:
	case CCS_MAC_FILE_CHROOT:
	case CCS_MAC_FILE_CHMOD:
	case CCS_MAC_FILE_CHOWN:
	case CCS_MAC_FILE_CHGRP:
	case CCS_MAC_FILE_IOCTL:
	case CCS_MAC_FILE_EXECUTE:
	case CCS_MAC_FILE_UMOUNT:
		if (ccs_str_starts(&word, "path"))
			goto path1;
		if (type == CCS_MAC_FILE_EXECUTE &&
		    ccs_str_starts(&word, "exec"))
			goto path2;
		break;
	case CCS_MAC_FILE_MKDIR:
	case CCS_MAC_FILE_CREATE:
	case CCS_MAC_FILE_MKFIFO:
	case CCS_MAC_FILE_MKSOCK:
	case CCS_MAC_FILE_MKBLOCK:
	case CCS_MAC_FILE_MKCHAR:
	case CCS_MAC_FILE_SYMLINK:
		if (ccs_str_starts(&word, "path"))
			goto path1_parent;
		break;
	case CCS_MAC_FILE_LINK:
	case CCS_MAC_FILE_RENAME:
		if (ccs_str_starts(&word, "old_path"))
			goto path1;
		if (ccs_str_starts(&word, "new_path"))
			goto path2_parent;
		break;
	case CCS_MAC_FILE_MOUNT:
		if (ccs_str_starts(&word, "source"))
			goto path1;
		if (ccs_str_starts(&word, "target"))
			goto path2;
		break;
	case CCS_MAC_FILE_PIVOT_ROOT:
		if (ccs_str_starts(&word, "new_root"))
			goto path1;
		if (ccs_str_starts(&word, "put_old"))
			goto path2;
		break;
	default:
		break;
	}
	goto out;
path1_parent:
	if (strncmp(word, ".parent", 7))
		goto out;
path1:
	start = CCS_PATH_ATTRIBUTE_START;
	goto check;
path2_parent:
	if (strncmp(word, ".parent", 7))
		goto out;
path2:
	start = CCS_PATH_ATTRIBUTE_START + 32;
check:
	if (ccs_str_starts(&word, ".parent"))
		start += 16;
	if (*word++ == '.')
		for (i = 0; i < CCS_MAX_PATH_ATTRIBUTE; i++)
			if (!strcmp(word, ccs_path_attribute[i]))
				return start + i;
out:
	return CCS_MAX_CONDITION_KEYWORD;
}

static enum ccs_conditions_index ccs_find_path_type(const char *word)
{
	if (!strcmp(word, "socket"))
		return CCS_OBJ_IS_SOCKET;
	if (!strcmp(word, "symlink"))
		return CCS_OBJ_IS_SYMLINK;
	if (!strcmp(word, "file"))
		return CCS_OBJ_IS_FILE;
	if (!strcmp(word, "block"))
		return CCS_OBJ_IS_BLOCK_DEV;
	if (!strcmp(word, "directory"))
		return CCS_OBJ_IS_DIRECTORY;
	if (!strcmp(word, "char"))
		return CCS_OBJ_IS_CHAR_DEV;
	if (!strcmp(word, "fifo"))
		return CCS_OBJ_IS_FIFO;
	return CCS_MAX_CONDITION_KEYWORD;
}

static enum ccs_conditions_index ccs_find_path_perm(const char *word)
{
	if (!strcmp(word, "setuid"))
		return CCS_MODE_SETUID;
	if (!strcmp(word, "setgid"))
		return CCS_MODE_SETGID;
	if (!strcmp(word, "sticky"))
		return CCS_MODE_STICKY;
	if (!strcmp(word, "owner_read"))
		return CCS_MODE_OWNER_READ;
	if (!strcmp(word, "owner_write"))
		return CCS_MODE_OWNER_WRITE;
	if (!strcmp(word, "owner_execute"))
		return CCS_MODE_OWNER_EXECUTE;
	if (!strcmp(word, "group_read"))
		return CCS_MODE_GROUP_READ;
	if (!strcmp(word, "group_write"))
		return CCS_MODE_GROUP_WRITE;
	if (!strcmp(word, "group_execute"))
		return CCS_MODE_GROUP_EXECUTE;
	if (!strcmp(word, "others_read"))
		return CCS_MODE_OTHERS_READ;
	if (!strcmp(word, "others_write"))
		return CCS_MODE_OTHERS_WRITE;
	if (!strcmp(word, "others_execute"))
		return CCS_MODE_OTHERS_EXECUTE;
	return CCS_MAX_CONDITION_KEYWORD;
}

static const struct ccs_path_info *ccs_get_dqdomain(char *start)
{
	const struct ccs_path_info *domain = ccs_get_dqword(start);
	if (domain && !ccs_correct_domain(domain->name)) {
		ccs_put_name(domain);
		return NULL;
	}
	return domain;
}

static bool ccs_parse_cond(struct ccs_cond_tmp *tmp,
			   struct ccs_io_buffer *head)
{
	enum ccs_group_id g;
	char *left = head->w.data;
	char *right;
	const enum ccs_mac_index type = head->w.acl_index;
	right = strchr(left, '=');
	if (!right || right == left)
		return false;
	*right++ = '\0';
	tmp->is_not = (*(right - 2) == '!');
	if (tmp->is_not)
		*(right - 2) = '\0';
	if (!*left || !*right)
		return false;
	if (type == CCS_MAC_FILE_EXECUTE
#ifdef CONFIG_CCSECURITY_MISC
	    || type == CCS_MAC_ENVIRON
#endif
	    ) {
		if (ccs_str_starts(&left, "argv[")) {
			tmp->left = CCS_ARGV_ENTRY;
			if (ccs_parse_ulong(&tmp->argv, &left) !=
			    CCS_VALUE_TYPE_DECIMAL || *left++ != ']' || *left)
				return false;
		} else if (ccs_str_starts(&left, "envp[")) {
			char *cp = left + strlen(left) - 1;
			tmp->left = CCS_ENVP_ENTRY;
			if (*cp != ']')
				return false;
			*cp = '\0';
			tmp->envp = ccs_get_dqword(left);
			if (!tmp->envp)
				return false;
		} else if (!strcmp(left, "argc"))
			tmp->left = CCS_EXEC_ARGC;
		else if (!strcmp(left, "envc"))
			tmp->left = CCS_EXEC_ENVC;
	}
	if (tmp->left == CCS_MAX_CONDITION_KEYWORD)
		tmp->left = ccs_parse_syscall_arg(left, type);
	if (tmp->left == CCS_MAX_CONDITION_KEYWORD)
		tmp->left = ccs_parse_task_cond(left);
	if (tmp->left == CCS_MAX_CONDITION_KEYWORD)
		tmp->left = ccs_parse_path_attribute(left, type);
	if (tmp->left == CCS_MAX_CONDITION_KEYWORD) {
		/*
		 * CCS_HANDLER_PATH and CCS_TRANSIT_DOMAIN are not for
		 * comparison.
		 */
		if (tmp->is_not)
			return false;
		if (!strcmp(left, "handler")) {
			tmp->left = CCS_HANDLER_PATH;
			tmp->right = CCS_IMM_NAME_ENTRY;
			tmp->path = ccs_get_dqword(right);
			if (!tmp->path || tmp->path->is_patterned)
				return false;
			return true;
		}
		if (!strcmp(left, "transition")) {
			tmp->left = CCS_TRANSIT_DOMAIN;
			tmp->right = CCS_IMM_DOMAINNAME_ENTRY;
			tmp->path = ccs_get_dqdomain(right);
			return tmp->path != NULL;
		}
	}
	if (tmp->left == CCS_MAX_CONDITION_KEYWORD)
		return false;
	switch (tmp->left) {
	case CCS_COND_DOMAIN:
	case CCS_SELF_DOMAIN:
		if (*right == '@') {
			g = CCS_DOMAIN_GROUP;
			break;
		}
		tmp->right = CCS_IMM_DOMAINNAME_ENTRY;
		tmp->path = ccs_get_dqdomain(right);
		return tmp->path != NULL;
	case CCS_ARGV_ENTRY:
	case CCS_ENVP_ENTRY:
	case CCS_COND_SARG0:
	case CCS_COND_SARG1:
	case CCS_COND_SARG2:
	case CCS_COND_SARG3:
	case CCS_SELF_EXE:
		g = CCS_PATH_GROUP;
		break;
#ifdef CONFIG_CCSECURITY_NETWORK
	case CCS_COND_IPARG:
		g = CCS_ADDRESS_GROUP;
		break;
#endif
	case CCS_TASK_TYPE:
		tmp->right = CCS_TASK_EXECUTE_HANDLER;
		return !strcmp(right, "execute_handler");
	case CCS_PATH_ATTRIBUTE_START + CCS_PATH_ATTRIBUTE_TYPE:
	case CCS_PATH_ATTRIBUTE_START + 16 + CCS_PATH_ATTRIBUTE_TYPE:
	case CCS_PATH_ATTRIBUTE_START + 32 + CCS_PATH_ATTRIBUTE_TYPE:
	case CCS_PATH_ATTRIBUTE_START + 48 + CCS_PATH_ATTRIBUTE_TYPE:
		tmp->right = ccs_find_path_type(right);
		return tmp->right != CCS_MAX_CONDITION_KEYWORD;
	case CCS_PATH_ATTRIBUTE_START + CCS_PATH_ATTRIBUTE_PERM:
	case CCS_PATH_ATTRIBUTE_START + 16 + CCS_PATH_ATTRIBUTE_PERM:
	case CCS_PATH_ATTRIBUTE_START + 32 + CCS_PATH_ATTRIBUTE_PERM:
	case CCS_PATH_ATTRIBUTE_START + 48 + CCS_PATH_ATTRIBUTE_PERM:
		tmp->right = ccs_find_path_perm(right);
		if (tmp->right != CCS_MAX_CONDITION_KEYWORD)
			return true;
		/* fall through */
	default:
		g = CCS_NUMBER_GROUP;
	}
	if (*right == '@') {
		tmp->right = CCS_IMM_GROUP;
		head->w.data = ++right;
		tmp->group = ccs_get_group(head, g);
		return tmp->group != NULL;
	}
	if (*right == '"') {
		if (g != CCS_PATH_GROUP)
			return false;
		tmp->right = CCS_IMM_NAME_ENTRY;
		tmp->path = ccs_get_dqword(right);
		return tmp->path != NULL;
	}
	if (tmp->left == CCS_ENVP_ENTRY) {
		tmp->right = CCS_IMM_NAME_ENTRY;
		tmp->path = &ccs_null_name;
		return !strcmp(right, "NULL");
	}
	if (g == CCS_NUMBER_GROUP) {
		tmp->right = ccs_parse_task_cond(right);
		if (tmp->right == CCS_SELF_DOMAIN ||
		    tmp->right == CCS_SELF_EXE)
			return false;
		if (tmp->right == CCS_MAX_CONDITION_KEYWORD)
			tmp->right = ccs_parse_path_attribute(right, type);
		if (tmp->right != CCS_MAX_CONDITION_KEYWORD)
			return true;
		tmp->radix = ccs_parse_values(right, tmp->value);
		if (tmp->radix == CCS_VALUE_TYPE_INVALID)
			return false;
		if (tmp->radix >> 2)
			tmp->right = CCS_IMM_NUMBER_ENTRY2;
		else
			tmp->right = CCS_IMM_NUMBER_ENTRY1;
		return true;
	}
#ifdef CONFIG_CCSECURITY_NETWORK
	if (g == CCS_ADDRESS_GROUP) {
		switch (ccs_parse_ipaddr(right, tmp->ipv6)) {
		case 1:
			tmp->right = CCS_IMM_IPV4ADDR_ENTRY1;
			break;
		case 2:
			tmp->right = CCS_IMM_IPV4ADDR_ENTRY2;
			break;
		case 3:
			tmp->right = CCS_IMM_IPV6ADDR_ENTRY1;
			break;
		case 4:
			tmp->right = CCS_IMM_IPV6ADDR_ENTRY2;
			break;
		default:
			return false;
		}
		return true;
	}
#endif
	return false;
}

/**
 * ccs_get_condition - Parse condition part.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns pointer to "struct ccs_condition" on success, NULL otherwise.
 */
struct ccs_condition *ccs_get_condition(struct ccs_io_buffer *head)
{
	struct ccs_condition *entry = kmalloc(PAGE_SIZE, CCS_GFP_FLAGS);
	union ccs_condition_element *condp;
	struct ccs_cond_tmp tmp;
	const enum ccs_mac_index type = head->w.acl_index;
#ifdef CONFIG_CCSECURITY_TASK_EXECUTE_HANDLER
	bool handler_path_done = head->w.is_deny ||
		type != CCS_MAC_FILE_EXECUTE;
#else
	bool handler_path_done = true;
#endif
	bool transit_domain_done = head->w.is_deny ||
		(type != CCS_MAC_FILE_EXECUTE
#ifdef CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION
		 && type != CCS_MAC_MANUAL_TASK_TRANSITION
		 && type != CCS_MAC_AUTO_TASK_TRANSITION
#endif
		 );
	char *pos = head->w.data;
	if (!entry)
		return NULL;
	condp = (union ccs_condition_element *) (entry + 1);
	while (1) {
		memset(&tmp, 0, sizeof(tmp));
		tmp.left = CCS_MAX_CONDITION_KEYWORD;
		tmp.right = CCS_MAX_CONDITION_KEYWORD;
		while (*pos == ' ')
			pos++;
		if (!*pos)
			break;
		if ((u8 *) condp >= ((u8 *) entry) + PAGE_SIZE
		    - (sizeof(*condp) + sizeof(struct in6_addr) * 2))
			goto out;
		{
			char *next = strchr(pos, ' ');
			if (next)
				*next++ = '\0';
			else
				next = "";
			head->w.data = pos;
			pos = next;
		}
		if (!ccs_parse_cond(&tmp, head))
			goto out;
		if (tmp.left == CCS_HANDLER_PATH) {
			if (handler_path_done)
				goto out;
			handler_path_done = true;
		}
		if (tmp.left == CCS_TRANSIT_DOMAIN) {
			if (transit_domain_done)
				goto out;
			transit_domain_done = true;
		}
		condp->is_not = tmp.is_not;
		condp->left = tmp.left;
		condp->right = tmp.right;
		condp->radix = tmp.radix;
		condp++;
		if (tmp.left == CCS_ARGV_ENTRY) {
			condp->value = tmp.argv;
			condp++;
			WARN_ON(tmp.right != CCS_IMM_NAME_ENTRY &&
				tmp.right != CCS_IMM_GROUP);
			WARN_ON(!tmp.group && !tmp.path);
		} else if (tmp.left == CCS_ENVP_ENTRY) {
			condp->path = tmp.envp;
			condp++;
			WARN_ON(tmp.right != CCS_IMM_NAME_ENTRY &&
				tmp.right != CCS_IMM_GROUP);
			WARN_ON(!tmp.group && !tmp.path);
		}
		if (tmp.right == CCS_IMM_GROUP) {
			condp->group = tmp.group;
			condp++;
		} else if (tmp.right == CCS_IMM_NAME_ENTRY ||
			   tmp.right == CCS_IMM_DOMAINNAME_ENTRY) {
			condp->path = tmp.path;
			condp++;
		} else if (tmp.right == CCS_IMM_NUMBER_ENTRY1 ||
			   tmp.right == CCS_IMM_NUMBER_ENTRY2) {
			condp->value = tmp.value[0];
			condp++;
			if (tmp.right == CCS_IMM_NUMBER_ENTRY2) {
				condp->value = tmp.value[1];
				condp++;
			}
		} else if (tmp.right == CCS_IMM_IPV4ADDR_ENTRY1 ||
			   tmp.right == CCS_IMM_IPV4ADDR_ENTRY2) {
			condp->ip = * (u32 *) &tmp.ipv6[0];
			condp++;
			if (tmp.right == CCS_IMM_IPV4ADDR_ENTRY2) {
				condp->ip = * (u32 *) &tmp.ipv6[1];
				condp++;
			}
		} else if (tmp.right == CCS_IMM_IPV6ADDR_ENTRY1 ||
			   tmp.right == CCS_IMM_IPV6ADDR_ENTRY2) {
			* (struct in6_addr *) condp = tmp.ipv6[0];
			condp = (void *) (((u8 *) condp) +
					  sizeof(struct in6_addr));
			if (tmp.right == CCS_IMM_IPV6ADDR_ENTRY2) {
				* (struct in6_addr *) condp = tmp.ipv6[1];
				condp = (void *) (((u8 *) condp) +
						  sizeof(struct in6_addr));
			}
		}
	}
#ifdef CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION
	if (!transit_domain_done &&
	    (type == CCS_MAC_MANUAL_TASK_TRANSITION ||
	     type == CCS_MAC_AUTO_TASK_TRANSITION))
		goto out;
#endif
	entry->size = (void *) condp - (void *) entry;
	return ccs_commit_condition(entry);
out:
	printk(KERN_WARNING "%u: type=%u env='%s' path='%s' group='%s'\n",
	       __LINE__, type, tmp.envp ? tmp.envp->name : "",
	       tmp.path ? tmp.path->name : "",
	       tmp.group ? tmp.group->group_name->name : "");
	ccs_put_name(tmp.envp);
	if (tmp.path != &ccs_null_name)
		ccs_put_name(tmp.path);
	ccs_put_group(tmp.group);
	entry->size = (void *) condp - (void *) entry;
	ccs_del_condition(&entry->head.list);
	kfree(entry);
	return NULL;
}

/**
 * ccs_yesno - Return "yes" or "no".
 *
 * @value: Bool value.
 *
 * Returns "yes" if @value is not 0, "no" otherwise.
 */
static const char *ccs_yesno(const unsigned int value)
{
	return value ? "yes" : "no";
}

/**
 * ccs_flush - Flush queued string to userspace's buffer.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true if all data was flushed, false otherwise.
 */
static bool ccs_flush(struct ccs_io_buffer *head)
{
	while (head->r.w_pos) {
		const char *w = head->r.w[0];
		size_t len = strlen(w);
		if (len) {
			if (len > head->read_user_buf_avail)
				len = head->read_user_buf_avail;
			if (!len)
				return false;
			if (copy_to_user(head->read_user_buf, w, len))
				return false;
			head->read_user_buf_avail -= len;
			head->read_user_buf += len;
			w += len;
		}
		head->r.w[0] = w;
		if (*w)
			return false;
		/* Add '\0' for audit logs and query. */
		if (head->type == CCS_AUDIT || head->type == CCS_QUERY) {
			if (!head->read_user_buf_avail ||
			    copy_to_user(head->read_user_buf, "", 1))
				return false;
			head->read_user_buf_avail--;
			head->read_user_buf++;
		}
		head->r.w_pos--;
		for (len = 0; len < head->r.w_pos; len++)
			head->r.w[len] = head->r.w[len + 1];
	}
	head->r.avail = 0;
	return true;
}

/**
 * ccs_set_string - Queue string to "struct ccs_io_buffer" structure.
 *
 * @head:   Pointer to "struct ccs_io_buffer".
 * @string: String to print.
 *
 * Returns nothing.
 *
 * Note that @string has to be kept valid until @head is kfree()d.
 * This means that char[] allocated on stack memory cannot be passed to
 * this function. Use ccs_io_printf() for char[] allocated on stack memory.
 */
static void ccs_set_string(struct ccs_io_buffer *head, const char *string)
{
	if (head->r.w_pos < CCS_MAX_IO_READ_QUEUE) {
		head->r.w[head->r.w_pos++] = string;
		ccs_flush(head);
	} else
		printk(KERN_WARNING "Too many words in a line.\n");
}

/**
 * ccs_io_printf - printf() to "struct ccs_io_buffer" structure.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @fmt:  The printf()'s format string, followed by parameters.
 *
 * Returns nothing.
 */
static void ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...)
{
	va_list args;
	size_t len;
	size_t pos = head->r.avail;
	int size = head->readbuf_size - pos;
	if (size <= 0)
		return;
	va_start(args, fmt);
	len = vsnprintf(head->read_buf + pos, size, fmt, args) + 1;
	va_end(args);
	if (pos + len >= head->readbuf_size) {
		printk(KERN_WARNING "Too many words in a line.\n");
		return;
	}
	head->r.avail += len;
	ccs_set_string(head, head->read_buf + pos);
}

/**
 * ccs_set_space - Put a space to "struct ccs_io_buffer" structure.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_set_space(struct ccs_io_buffer *head)
{
	ccs_set_string(head, " ");
}

/**
 * ccs_set_lf - Put a line feed to "struct ccs_io_buffer" structure.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static bool ccs_set_lf(struct ccs_io_buffer *head)
{
	ccs_set_string(head, "\n");
	return !head->r.w_pos;
}

/**
 * ccs_check_profile - Check all profiles currently assigned to domains are defined.
 *
 * Returns nothing.
 */
static void ccs_check_profile(void)
{
	ccs_policy_loaded = true;
	printk(KERN_INFO "CCSecurity: 1.8.3+   2012/02/29\n");
	if (ccs_policy_version == 20100903) {
		printk(KERN_INFO "Mandatory Access Control activated.\n");
		return;
	}
	printk(KERN_ERR "Policy version %u is not supported.\n",
	       ccs_policy_version);
	printk(KERN_ERR "Userland tools for TOMOYO 1.8 must be installed and "
	       "policy must be initialized.\n");
	printk(KERN_ERR "Please see http://tomoyo.sourceforge.jp/1.8/ "
	       "for more information.\n");
	panic("STOP!");
}

/**
 * ccs_str_starts - Check whether the given string starts with the given keyword.
 *
 * @src:  Pointer to pointer to the string.
 * @find: Pointer to the keyword.
 *
 * Returns true if @src starts with @find, false otherwise.
 *
 * The @src is updated to point the first character after the @find
 * if @src starts with @find.
 */
static bool ccs_str_starts(char **src, const char *find)
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
 * ccs_find_domain - Find a domain by the given name.
 *
 * @domainname: The domainname to find.
 *
 * Returns pointer to "struct ccs_domain_info" if found, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static struct ccs_domain_info *ccs_find_domain(const char *domainname)
{
	struct ccs_domain_info *domain;
	struct ccs_path_info name;
	name.name = domainname;
	ccs_fill_path_info(&name);
	list_for_each_entry_srcu(domain, &ccs_domain_list, list, &ccs_ss) {
		if (!domain->is_deleted &&
		    !ccs_pathcmp(&name, domain->domainname))
			return domain;
	}
	return NULL;
}

/**
 * ccs_select_acl - Parse select command.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @data: String to parse.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_select_acl(struct ccs_io_buffer *head, const char *data)
{
	unsigned int qid;
	struct ccs_acl_info *acl;
	if (sscanf(data, "Q=%u", &qid) != 1)
		return false;
	acl = ccs_find_acl_by_qid(qid);
	head->w.acl = acl;
	/* Accessing read_buf is safe because head->io_sem is held. */
	if (!head->read_buf)
		return true; /* Do nothing if open(O_WRONLY). */
	memset(&head->r, 0, sizeof(head->r));
	head->r.print_this_acl_only = true;
	if (acl)
		head->r.acl = &acl->list;
	else
		head->r.eof = true;
	ccs_io_printf(head, "# Q=%u\n", qid);
	return true;
}

/**
 * ccs_update_acl - Update "struct ccs_acl_info" entry.
 *
 * @list:   Pointer to "struct list_head".
 * @head:   Pointer to "struct ccs_io_buffer".
 * @update: True to store matching entry, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_update_acl(struct list_head * const list,
			  struct ccs_io_buffer *head, const bool update)
{
	struct ccs_acl_info *ptr;
	struct ccs_acl_info new_entry = { };
	const bool is_delete = head->w.is_delete;
	int error = is_delete ? -ENOENT : -ENOMEM;
	new_entry.priority = head->w.priority;
	new_entry.priority = head->w.priority;
	new_entry.is_deny = head->w.is_deny;
	if (head->w.data[0]) {
		new_entry.cond = ccs_get_condition(head);
		if (!new_entry.cond)
			return -EINVAL;
	}
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	list_for_each_entry_srcu(ptr, list, list, &ccs_ss) {
		if (ptr->priority > new_entry.priority)
			break;
		/*
		 * We cannot reuse deleted "struct ccs_acl_info" entry because
		 * somebody might be referencing children of this deleted entry
		 * from srcu section. We cannot delete children of this deleted
		 * entry until all children are no longer referenced. Thus, let
		 * the garbage collector wait and delete rather than trying to
		 * reuse this deleted entry.
		 */
		if (ptr->is_deleted || ptr->cond != new_entry.cond ||
		    ptr->priority != new_entry.priority ||
		    ptr->is_deny != new_entry.is_deny)
			continue;
		ptr->is_deleted = is_delete;
		if (!is_delete && update)
			head->w.acl = ptr;
		error = 0;
		break;
	}
	if (error && !is_delete) {
		struct ccs_acl_info *entry =
			ccs_commit_ok(&new_entry, sizeof(new_entry));
		if (entry) {
			INIT_LIST_HEAD(&entry->acl_info_list);
			list_add_tail_rcu(&entry->list, &ptr->list);
			if (update)
				head->w.acl = entry;
		}
	}
	mutex_unlock(&ccs_policy_lock);
out:
	ccs_put_condition(new_entry.cond);
	return error;
}

/**
 * ccs_parse_entry - Update ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_parse_entry(struct ccs_io_buffer *head)
{
	enum ccs_mac_index type;
	const char *category = ccs_read_token(head);
	const char *operation = ccs_read_token(head);
	for (type = CCS_MAC_FILE_EXECUTE; type < CCS_MAX_MAC_INDEX; type++) {
		if (!ccs_category_keywords[ccs_index2category[type]]) {
			printk(KERN_INFO
			       "ccs_category_keywords[ccs_index2category[%u]]"
			       "==NULL\n", type);
			continue;
		}
		if (!ccs_mac_keywords[type]) {
			printk(KERN_INFO "ccs_mac_keywords[%u]==NULL\n", type);
			continue;
		}
		if (strcmp(category, ccs_category_keywords
			   [ccs_index2category[type]]) ||
		    strcmp(operation, ccs_mac_keywords[type]))
			continue;
		head->w.acl_index = type;
		return ccs_update_acl(&ccs_acl_list[type], head, true);
	}
	return -EINVAL;
}

static void ccs_print_number(struct ccs_io_buffer *head,
			     const enum ccs_value_type radix,
			     const unsigned long value)
{
	switch (radix) {
	case CCS_VALUE_TYPE_HEXADECIMAL:
		ccs_io_printf(head, "0x%lX", value);
		break;
	case CCS_VALUE_TYPE_OCTAL:
		ccs_io_printf(head, "0%lo", value);
		break;
	default:
		ccs_io_printf(head, "%lu", value);
	}
}

static void ccs_print_misc_attribute(struct ccs_io_buffer *head,
				     const enum ccs_mac_index type,
				     const enum ccs_conditions_index cond)
{
	if (cond >= CCS_PATH_ATTRIBUTE_START) {
		const u8 pos = cond - CCS_PATH_ATTRIBUTE_START;
		ccs_io_printf(head, "%s.%s%s", ccs_get_sarg(type, pos >= 32),
			      pos % 32 >= 16 ? "parent." : "",
			      ccs_path_attribute[pos % 16]);
		return;
	}
	if (cond == CCS_COND_DOMAIN) {
		ccs_set_string(head, "domain");
		return;
	}
	switch (cond) {
	case CCS_SELF_UID:
	case CCS_SELF_EUID:
	case CCS_SELF_SUID:
	case CCS_SELF_FSUID:
	case CCS_SELF_GID:
	case CCS_SELF_EGID:
	case CCS_SELF_SGID:
	case CCS_SELF_FSGID:
	case CCS_SELF_PID:
	case CCS_SELF_PPID:
	case CCS_TASK_TYPE:
	case CCS_SELF_DOMAIN:
	case CCS_SELF_EXE:
		ccs_set_string(head, "task.");
		/* fall through */
	default:
		if (cond < CCS_MAX_CONDITION_KEYWORD)
			ccs_set_string(head, ccs_condition_keyword[cond]);
		else
			ccs_io_printf(head, "unknown(%u)", cond);
	}
}

static void ccs_print_ipv4_address(struct ccs_io_buffer *head,
				   const u32 *ip)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	ccs_io_printf(head, "%pI4", ip);
#else
	char addr[sizeof("255.255.255.255")];
	ip4_string(addr, (const u8 *) ip);
	ccs_io_printf(head, "%s", addr);
#endif
}

static void ccs_print_ipv6_address(struct ccs_io_buffer *head,
				   const struct in6_addr *ip)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	ccs_io_printf(head, "%pI6c", ip);
#else
	char addr[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:"
			 "255.255.255.255")];
	ip6_compressed_string(addr, (const u8 *) ip);
	ccs_io_printf(head, "%s", addr);
#endif
}

/**
 * ccs_print_condition_loop - Print condition part.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @type: One of values in "enum ccs_mac_index".
 * @cond: Pointer to "struct ccs_condition".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_condition_loop(struct ccs_io_buffer *head,
				     const struct ccs_condition *cond)
{
	const enum ccs_mac_index type = head->r.acl_index;
	const union ccs_condition_element *condp = head->r.cond;
	while ((void *) condp < (void *) ((u8 *) cond) + cond->size) {
		const bool is_not = condp->is_not;
		const enum ccs_conditions_index left = condp->left;
		const enum ccs_conditions_index right = condp->right;
		const u8 radix = condp->radix;
		if (!ccs_flush(head)) {
			head->r.cond = condp;
			return false;
		}
		condp++;
		ccs_set_space(head);
		switch (left) {
		case CCS_ARGV_ENTRY:
			ccs_io_printf(head, "argv[%lu]", condp->value);
			condp++;
			break;
		case CCS_ENVP_ENTRY:
			ccs_set_string(head, "envp[\"");
			ccs_set_string(head, condp->path->name);
			condp++;
			ccs_set_string(head, "\"]");
			break;
		case CCS_COND_SARG0:
			ccs_set_string(head, ccs_get_sarg(type, 0));
			break;
		case CCS_COND_SARG1:
			ccs_set_string(head, ccs_get_sarg(type, 1));
			break;
		case CCS_COND_SARG2:
			ccs_set_string(head, ccs_get_sarg(type, 2));
			break;
		case CCS_COND_SARG3:
			ccs_set_string(head, ccs_get_sarg(type, 3));
			break;
		case CCS_COND_NARG0:
			ccs_set_string(head, ccs_get_narg(type, 0));
			break;
		case CCS_COND_NARG1:
			ccs_set_string(head, ccs_get_narg(type, 1));
			break;
		case CCS_COND_NARG2:
			ccs_set_string(head, ccs_get_narg(type, 2));
			break;
		case CCS_COND_IPARG:
			ccs_set_string(head, "ip");
			break;
		default:
			ccs_print_misc_attribute(head, type, left);
		}
		ccs_set_string(head, is_not ? "!=" : "=");
		switch (right) {
		case CCS_IMM_GROUP:
			ccs_set_string(head, "@");
			ccs_set_string(head, condp->group->group_name->name);
			condp++;
			break;
		case CCS_IMM_NAME_ENTRY:
		case CCS_IMM_DOMAINNAME_ENTRY:
			if (condp->path != &ccs_null_name) {
				ccs_set_string(head, "\"");
				ccs_set_string(head, condp->path->name);
				ccs_set_string(head, "\"");
			} else {
				ccs_set_string(head, "NULL");
			}
			condp++;
			break;
		case CCS_IMM_NUMBER_ENTRY1:
		case CCS_IMM_NUMBER_ENTRY2:
			ccs_print_number(head, radix & 3, condp->value);
			condp++;
			if (right == CCS_IMM_NUMBER_ENTRY1)
				break;
			ccs_set_string(head, "-");
			ccs_print_number(head, (radix >> 2) & 3, condp->value);
			condp++;
			break;
		case CCS_IMM_IPV4ADDR_ENTRY1:
		case CCS_IMM_IPV4ADDR_ENTRY2:
			ccs_print_ipv4_address(head, &condp->ip);
			condp++;
			if (right == CCS_IMM_IPV4ADDR_ENTRY1)
				break;
			ccs_set_string(head, "-");
			ccs_print_ipv4_address(head, &condp->ip);
			condp++;
			break;
		case CCS_IMM_IPV6ADDR_ENTRY1:
		case CCS_IMM_IPV6ADDR_ENTRY2:
			ccs_print_ipv6_address(head, (const struct in6_addr *)
					       condp);
			condp = (void *)
				((u8 *) condp) + sizeof(struct in6_addr);
			if (right == CCS_IMM_IPV6ADDR_ENTRY1)
				break;
			ccs_set_string(head, "-");
			ccs_print_ipv6_address(head, (const struct in6_addr *)
					       condp);
			condp = (void *)
				((u8 *) condp) + sizeof(struct in6_addr);
			break;
		default:
			ccs_print_misc_attribute(head, type, right);
		}
	}
	head->r.cond = NULL;
	return true;
}

/**
 * ccs_print_condition - Print condition part.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @cond: Pointer to "struct ccs_condition".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_condition(struct ccs_io_buffer *head,
				const struct ccs_condition *cond)
{
	switch (head->r.cond_step) {
	case 0:
		head->r.cond = (const union ccs_condition_element *)
			(cond + 1);
		head->r.cond_step++;
		/* fall through */
	case 1:
		if (!ccs_print_condition_loop(head, cond))
			return false;
		head->r.cond_step++;
		/* fall through */
	case 2:
		head->r.cond = NULL;
		return true;
	}
	return false;
}

/**
 * ccs_read_acl - Print an ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @acl:  Pointer to an ACL entry.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_read_acl(struct ccs_io_buffer *head,
			 const struct ccs_acl_info *acl)
{
	const enum ccs_mac_index type = head->r.acl_index;
	if (head->r.cond)
		goto print_cond_part;
	if (acl->is_deleted)
		return true;
	if (!ccs_flush(head))
		return false;
	BUG_ON(type >= CCS_MAX_MAC_INDEX);
	ccs_io_printf(head, "%u ", acl->priority);
	ccs_set_string(head, "acl ");
	ccs_set_string(head, ccs_category_keywords[ccs_index2category[type]]);
	ccs_set_space(head);
	ccs_set_string(head, ccs_mac_keywords[type]);
	if (acl->cond) {
		head->r.cond_step = 0;
print_cond_part:
		if (!ccs_print_condition(head, acl->cond))
			return false;
	}
	ccs_set_lf(head);
	return true;
}

/**
 * ccs_write_pid - Specify PID to obtain domainname.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
static int ccs_write_pid(struct ccs_io_buffer *head)
{
	head->r.eof = false;
	return 0;
}

/**
 * ccs_read_pid - Read information of a process.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns the domainname which the specified PID is in or
 * process information of the specified PID on success,
 * empty string otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_pid(struct ccs_io_buffer *head)
{
	char *buf = head->write_buf;
	bool task_info = false;
	bool global_pid = false;
	unsigned int pid;
	struct task_struct *p;
	struct ccs_domain_info *domain = NULL;
	u32 ccs_flags = 0;
	/* Accessing write_buf is safe because head->io_sem is held. */
	if (!buf) {
		head->r.eof = true;
		return; /* Do nothing if open(O_RDONLY). */
	}
	if (head->r.w_pos || head->r.eof)
		return;
	head->r.eof = true;
	if (ccs_str_starts(&buf, "info "))
		task_info = true;
	if (ccs_str_starts(&buf, "global-pid "))
		global_pid = true;
	pid = (unsigned int) simple_strtoul(buf, NULL, 10);
	ccs_tasklist_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	if (global_pid)
		p = ccsecurity_exports.find_task_by_pid_ns(pid, &init_pid_ns);
	else
		p = ccsecurity_exports.find_task_by_vpid(pid);
#else
	p = find_task_by_pid(pid);
#endif
	if (p) {
		domain = ccs_task_domain(p);
		ccs_flags = ccs_task_flags(p);
	}
	ccs_tasklist_unlock();
	if (!domain)
		return;
	if (!task_info) {
		ccs_io_printf(head, "%u ", pid);
		ccs_set_string(head, domain->domainname->name);
	} else {
		ccs_io_printf(head, "%u manager=%s execute_handler=%s ", pid,
			      ccs_yesno(ccs_flags &
					CCS_TASK_IS_MANAGER),
			      ccs_yesno(ccs_flags &
					CCS_TASK_IS_EXECUTE_HANDLER));
	}
}

/**
 * ccs_update_group - Update "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @type: Type of this group.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_group(struct ccs_io_buffer *head,
			    const enum ccs_group_id type)
{
	u8 size;
	const bool is_delete = head->w.is_delete;
	int error = is_delete ? -ENOENT : -ENOMEM;
	struct ccs_group *group = ccs_get_group(head, type);
	char *word = ccs_read_token(head);
	union {
		struct ccs_acl_head head;
		struct ccs_path_group path;
		struct ccs_number_group number;
		struct ccs_address_group address;
	} e = { };
	if (!group)
		return -ENOMEM;
	if (!*word)
		return -EINVAL;
	if (type == CCS_PATH_GROUP || type == CCS_DOMAIN_GROUP) {
		if ((type == CCS_PATH_GROUP && !ccs_correct_word(word)) ||
		    (type == CCS_DOMAIN_GROUP && !ccs_correct_domain(word))) {
			error = -EINVAL;
			goto out;
		}
		e.path.member_name = ccs_get_name(word);
		if (!e.path.member_name) {
			error = -ENOMEM;
			goto out;
		}
		size = sizeof(e.path);
	} else if (type == CCS_NUMBER_GROUP) {
		e.number.radix = ccs_parse_values(word, e.number.value);
		if (e.number.radix == CCS_VALUE_TYPE_INVALID)
			goto out;
		size = sizeof(e.number);
#ifdef CONFIG_CCSECURITY_NETWORK
	} else {
		switch (ccs_parse_ipaddr(word, e.address.ip)) {
		case 1:
		case 2:
			e.address.is_ipv6 = false;
			break;
		case 3:
		case 4:
			e.address.is_ipv6 = true;
			break;
		default:
			goto out;
		}
		size = sizeof(e.address);
#endif
	}
	if (mutex_lock_interruptible(&ccs_policy_lock) == 0) {
		struct ccs_acl_head *entry;
		list_for_each_entry_srcu(entry, &group->member_list,
					 list, &ccs_ss) {
			if (entry->is_deleted == CCS_GC_IN_PROGRESS ||
			    memcmp(entry + 1, &e.head + 1,
				   size - sizeof(*entry)))
				continue;
			entry->is_deleted = is_delete;
			error = 0;
			break;
		}
		if (error && !is_delete) {
			entry = ccs_commit_ok(&e, size);
			if (entry) {
				list_add_tail_rcu(&entry->list,
						  &group->member_list);
				error = 0;
			}
		}
		mutex_unlock(&ccs_policy_lock);
	}
	if (type == CCS_PATH_GROUP || type == CCS_DOMAIN_GROUP)
		ccs_put_name(e.path.member_name);
out:
	ccs_put_group(group);
	return error;
}

/**
 * ccs_write_policy - Write policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_policy(struct ccs_io_buffer *head)
{
	enum ccs_group_id i;
	unsigned int priority;
	char *word = ccs_read_token(head);
	if (sscanf(word, "%u", &priority) == 1)
		word = ccs_read_token(head);
	else
		priority = 1000;
	if (priority >= 65536 || !*word)
		return -EINVAL;
	head->w.priority = priority;
	if (!head->w.acl)
		goto no_acl_selected;
	head->w.is_deny = !strcmp(word, "deny");
	if (head->w.is_deny || !strcmp(word, "allow"))
		return ccs_update_acl(&head->w.acl->acl_info_list, head,
				      false);
	if (!strcmp(word, "audit")) {
		head->w.acl->audit = simple_strtoul(head->w.data, NULL, 10);
		return 0;
	}
	head->w.acl = NULL;
no_acl_selected:
	if (ccs_select_acl(head, word))
		return 0;
	if (!strcmp(word, "acl"))
		return ccs_parse_entry(head);
	for (i = 0; i < CCS_MAX_GROUP; i++)
		if (!strcmp(word, ccs_group_name[i]))
			return ccs_update_group(head, i);
	if (sscanf(word, "POLICY_VERSION=%u", &ccs_policy_version) == 1)
		return 0;
	if (strcmp(word, "quota"))
		return -EINVAL;
	if (ccs_str_starts(&head->w.data, "memory "))
		return ccs_write_memory_quota(head->w.data);
	return ccs_write_audit_quota(head->w.data);
}


/**
 * ccs_read_subgroup - Read "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group" list.
 *
 * @head:  Pointer to "struct ccs_io_buffer".
 * @group: Pointer to "struct ccs_group".
 * @idx:   One of values in "enum ccs_group_id".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_read_subgroup(struct ccs_io_buffer *head,
			      struct ccs_group *group,
			      const enum ccs_group_id idx)
{
	list_for_each_cookie(head->r.acl, &group->member_list) {
		struct ccs_acl_head *ptr =
			list_entry(head->r.acl, typeof(*ptr), list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_flush(head))
			return false;
		ccs_set_string(head, ccs_group_name[idx]);
		ccs_set_space(head);
		ccs_set_string(head, group->group_name->name);
		ccs_set_space(head);
		if (idx == CCS_PATH_GROUP || idx == CCS_DOMAIN_GROUP) {
			ccs_set_string(head, container_of
				       (ptr, struct ccs_path_group,
					head)->member_name->name);
		} else if (idx == CCS_NUMBER_GROUP) {
			struct ccs_number_group *e =
				container_of(ptr, typeof(*e), head);
			ccs_print_number(head, e->radix & 3, e->value[0]);
			if (e->radix >> 2) {
				ccs_set_string(head, "-");
				ccs_print_number(head, (e->radix >> 2) & 3,
						 e->value[1]);
			}
#ifdef CONFIG_CCSECURITY_NETWORK
		} else if (idx == CCS_ADDRESS_GROUP) {
			ccs_print_ip(head, container_of
				     (ptr, struct ccs_address_group, head));
#endif
		}
		ccs_set_lf(head);
	}
	head->r.acl = NULL;
	return true;
}

/**
 * ccs_read_group - Read "struct ccs_path_group"/"struct ccs_number_group"/"struct ccs_address_group" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_read_group(struct ccs_io_buffer *head)
{
	while (head->r.step < CCS_MAX_GROUP) {
		const enum ccs_group_id idx = head->r.step;
		struct list_head *list = &ccs_group_list[idx];
		list_for_each_cookie(head->r.group, list) {
			struct ccs_group *group =
				list_entry(head->r.group, typeof(*group),
					   head.list);
			if (!ccs_read_subgroup(head, group, idx))
				return false;
		}
		head->r.group = NULL;
		head->r.step++;
	}
	head->r.step = 0;
	return true;
}

/**
 * ccs_supervisor - Ask for the supervisor's decision.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 if the supervisor decided to permit the access request which
 * violated the policy in enforcing mode, CCS_RETRY_REQUEST if the supervisor
 * decided to retry the access request which violated the policy in enforcing
 * mode, 0 if it is not in enforcing mode, -EPERM otherwise.
 */
static int ccs_supervisor(struct ccs_request_info *r)
{
	int error = -EPERM;
	int len;
	static unsigned int ccs_serial;
	struct ccs_query entry = { };
	bool quota_exceeded = false;
	if (WARN_ON(!r->matched_acl))
		return -EPERM;
	/* Get message. */
	entry.query = ccs_init_log(r);
	if (!entry.query)
		return -EPERM;
	entry.query_len = strlen(entry.query) + 1;
	len = ccs_round2(entry.query_len);
	entry.acl = r->matched_acl;
	spin_lock(&ccs_query_list_lock);
	if (ccs_memory_quota[CCS_MEMORY_QUERY] &&
	    ccs_memory_used[CCS_MEMORY_QUERY] + len
	    >= ccs_memory_quota[CCS_MEMORY_QUERY]) {
		quota_exceeded = true;
	} else {
		entry.serial = ccs_serial++;
		entry.retry = r->retry;
		ccs_memory_used[CCS_MEMORY_QUERY] += len;
		list_add_tail(&entry.list, &ccs_query_list);
	}
	spin_unlock(&ccs_query_list_lock);
	if (quota_exceeded)
		goto out;
	/* Give 10 seconds for supervisor's opinion. */
	while (entry.timer < 10) {
		wake_up_all(&ccs_query_wait);
		if (wait_event_interruptible_timeout
		    (ccs_answer_wait, entry.answer ||
		     !atomic_read(&ccs_query_observers), HZ))
			break;
		else
			entry.timer++;
	}
	spin_lock(&ccs_query_list_lock);
	list_del(&entry.list);
	ccs_memory_used[CCS_MEMORY_QUERY] -= len;
	spin_unlock(&ccs_query_list_lock);
	switch (entry.answer) {
	case 3: /* Asked to retry by administrator. */
		error = CCS_RETRY_REQUEST;
		r->retry++;
		break;
	case 1:
		/* Granted by administrator. */
		error = 0;
		break;
	default:
		/* Timed out or rejected by administrator. */
		break;
	}
out:
	kfree(entry.query);
	return error;
}

/**
 * ccs_audit_log - Audit permission check log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 to grant the request, CCS_RETRY_REQUEST to retry the permission
 * check, -EPERM otherwise.
 */
int ccs_audit_log(struct ccs_request_info *r)
{
	/* Do not reject if not yet activated. */
	if (!ccs_policy_loaded)
		return 0;
	/* Write /proc/ccs/audit unless quota exceeded. */
	if (ccs_log_count[r->result] < ccs_log_quota[r->audit][r->result])
		ccs_write_log(r);
	/* Nothing more to do unless denied. */
	if (r->result != CCS_MATCHING_DENIED)
		return 0;
	/* Update policy violation counter if denied. */
	ccs_update_stat(CCS_STAT_REQUEST_DENIED);
	/* Nothing more to do unless ccs-queryd is running. */
	if (!atomic_read(&ccs_query_observers))
		return -EPERM;
	/* Ask the ccs-queryd for decision. */
	return ccs_supervisor(r);
}

/**
 * ccs_find_acl_by_qid - Get ACL by query id.
 *
 * @serial: Query ID assigned by ccs_supervisor().
 *
 * Returns pointer to "struct ccs_ack_info" if found, NULL otherwise.
 */
static struct ccs_acl_info *ccs_find_acl_by_qid(unsigned int serial)
{
	struct ccs_query *ptr;
	struct ccs_acl_info *acl = NULL;
	spin_lock(&ccs_query_list_lock);
	list_for_each_entry(ptr, &ccs_query_list, list) {
		if (ptr->serial != serial || ptr->answer)
			continue;
		acl = ptr->acl;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	return acl;
}

/**
 * ccs_poll_query - poll() for /proc/ccs/query.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns POLLIN | POLLRDNORM when ready to read, 0 otherwise.
 *
 * Waits for access requests which violated policy in enforcing mode.
 */
static int ccs_poll_query(struct file *file, poll_table *wait)
{
	struct list_head *tmp;
	bool found = false;
	u8 i;
	for (i = 0; i < 2; i++) {
		spin_lock(&ccs_query_list_lock);
		list_for_each(tmp, &ccs_query_list) {
			struct ccs_query *ptr =
				list_entry(tmp, typeof(*ptr), list);
			if (ptr->answer)
				continue;
			found = true;
			break;
		}
		spin_unlock(&ccs_query_list_lock);
		if (found)
			return POLLIN | POLLRDNORM;
		if (i)
			break;
		poll_wait(file, &ccs_query_wait, wait);
	}
	return 0;
}

/**
 * ccs_read_query - Read access requests which violated policy in enforcing mode.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_read_query(struct ccs_io_buffer *head)
{
	struct list_head *tmp;
	unsigned int pos = 0;
	size_t len = 0;
	char *buf;
	if (head->r.w_pos)
		return;
	kfree(head->read_buf);
	head->read_buf = NULL;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		if (ptr->answer)
			continue;
		if (pos++ != head->r.query_index)
			continue;
		len = ptr->query_len;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	if (!len) {
		head->r.query_index = 0;
		return;
	}
	buf = kzalloc(len + 32, CCS_GFP_FLAGS);
	if (!buf)
		return;
	pos = 0;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		if (ptr->answer)
			continue;
		if (pos++ != head->r.query_index)
			continue;
		/*
		 * Some query can be skipped because ccs_query_list
		 * can change, but I don't care.
		 */
		if (len == ptr->query_len)
			snprintf(buf, len + 31, "Q%u-%hu\n%s", ptr->serial,
				 ptr->retry, ptr->query);
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	if (buf[0]) {
		head->read_buf = buf;
		head->r.w[head->r.w_pos++] = buf;
		head->r.query_index++;
	} else {
		kfree(buf);
	}
}

/**
 * ccs_write_answer - Write the supervisor's decision.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int ccs_write_answer(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	struct list_head *tmp;
	unsigned int serial;
	unsigned int answer;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		ptr->timer = 0;
	}
	spin_unlock(&ccs_query_list_lock);
	if (sscanf(data, "A%u=%u", &serial, &answer) != 2)
		return -EINVAL;
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query *ptr = list_entry(tmp, typeof(*ptr), list);
		if (ptr->serial != serial)
			continue;
		if (!ptr->answer)
			ptr->answer = (u8) answer;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	wake_up_all(&ccs_answer_wait);
	return 0;
}

/**
 * ccs_read_version - Get version.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_read_version(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	ccs_set_string(head, "1.8.3");
	head->r.eof = true;
}

/**
 * ccs_update_stat - Update statistic counters.
 *
 * @index: Index for policy type.
 *
 * Returns nothing.
 */
static void ccs_update_stat(const u8 index)
{
	struct timeval tv;
	do_gettimeofday(&tv);
	/*
	 * I don't use atomic operations because race condition is not fatal.
	 */
	ccs_stat_updated[index]++;
	ccs_stat_modified[index] = tv.tv_sec;
}

/**
 * ccs_read_stat - Read statistic data.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_read_stat(struct ccs_io_buffer *head)
{
	u8 i;
	for (i = 0; i < CCS_MAX_POLICY_STAT; i++) {
		static const char * const k[CCS_MAX_POLICY_STAT] = {
			[CCS_STAT_POLICY_UPDATES] = "Policy update:",
			[CCS_STAT_REQUEST_DENIED]  = "Requests denied:",
		};
		ccs_io_printf(head, "stat %s %u", k[i], ccs_stat_updated[i]);
		if (ccs_stat_modified[i]) {
			struct ccs_time stamp;
			ccs_convert_time(ccs_stat_modified[i], &stamp);
			ccs_io_printf(head, " (Last: %04u/%02u/%02u "
				      "%02u:%02u:%02u)",
				      stamp.year, stamp.month, stamp.day,
				      stamp.hour, stamp.min, stamp.sec);
		}
		ccs_set_lf(head);
	}
	for (i = 0; i < CCS_MAX_MEMORY_STAT; i++)
		ccs_io_printf(head, "stat Memory used by %s: %u\n",
			      ccs_memory_headers[i], ccs_memory_used[i]);
	return true;
}

/**
 * ccs_read_quota - Read quota data.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_read_quota(struct ccs_io_buffer *head)
{
	unsigned int i;
	while (head->r.step < CCS_MAX_MEMORY_STAT) {
		i = head->r.step++;
		if (!ccs_memory_quota[i])
			continue;
		ccs_io_printf(head, "quota memory %s %u\n",
			      ccs_memory_headers[i], ccs_memory_quota[i]);
	}
	while (head->r.step < CCS_MAX_GROUP + CCS_MAX_MEMORY_STAT) {
		unsigned int a;
		unsigned int d;
		unsigned int u;
		if (!ccs_flush(head))
			return false;
		i = head->r.step - CCS_MAX_MEMORY_STAT;
		a = ccs_log_quota[i][CCS_MATCHING_ALLOWED];
		d = ccs_log_quota[i][CCS_MATCHING_DENIED];
		u = ccs_log_quota[i][CCS_MATCHING_UNMATCHED];
		if (a || d || u)
			ccs_io_printf(head, "quota audit[%u] allowed=%u"
				      " denied=%u unmatched=%u\n", i, a, d, u);
		head->r.step++;
	}
	head->r.step = 0;
	return true;
}

/**
 * ccs_write_memory_quota - Set memory quota.
 *
 * @data: Line to parse.
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int ccs_write_memory_quota(char *data)
{
	u8 i;
	for (i = 0; i < CCS_MAX_MEMORY_STAT; i++)
		if (ccs_str_starts(&data, ccs_memory_headers[i])) {
			if (*data == ' ')
				data++;
			ccs_memory_quota[i] =
				simple_strtoul(data, NULL, 10);
			return 0;
		}
	return -EINVAL;
}

/**
 * ccs_write_audit_quota - Set audit log quota.
 *
 * @data: Line to parse.
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int ccs_write_audit_quota(char *data)
{
	unsigned int i;
	if (sscanf(data, "audit[%u]", &i) != 1 || i >= CCS_MAX_LOG_QUOTA)
		return -EINVAL;
	data = strchr(data, ' ');
	if (!data++)
		return -EINVAL;
	while (1) {
		unsigned int logs;
		char *cp = strchr(data, ' ');
		if (cp)
			*cp++ = '\0';
		if (sscanf(data, "allowed=%u", &logs) == 1)
			ccs_log_quota[i][CCS_MATCHING_ALLOWED] = logs;
		else if (sscanf(data, "denied=%u", &logs) == 1)
			ccs_log_quota[i][CCS_MATCHING_DENIED] = logs;
		else if (sscanf(data, "unmatched=%u", &logs) == 1)
			ccs_log_quota[i][CCS_MATCHING_UNMATCHED] = logs;
		if (!cp)
			break;
		data = cp;
	}
	return 0;
}

/**
 * ccs_print_bprm - Print "struct linux_binprm" for auditing.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @dump: Pointer to "struct ccs_page_dump".
 *
 * Returns the contents of @bprm on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *ccs_print_bprm(struct linux_binprm *bprm,
			    struct ccs_page_dump *dump)
{
	static const int ccs_buffer_len = 4096 * 2;
	char *buffer = kzalloc(ccs_buffer_len, CCS_GFP_FLAGS);
	char *cp;
	char *last_start;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	bool skip = false;
	bool env_value = false;
	if (!buffer)
		return NULL;
	cp = buffer + snprintf(buffer, ccs_buffer_len - 1, " argc=%d envc=%d",
			       argv_count, envp_count);
	last_start = cp;
	while (argv_count || envp_count) {
		if (!ccs_dump_page(bprm, pos, dump)) {
			kfree(buffer);
			return NULL;
		}
		pos += PAGE_SIZE - offset;
		/* Read. */
		while (offset < PAGE_SIZE) {
			const char *kaddr = dump->data;
			const unsigned char c = kaddr[offset++];
			int len;
			/* Check for end of buffer. */
			if (skip) {
				if (c)
					continue;
				goto reset;
			}
			len = buffer + ccs_buffer_len - cp - 1;
			if (len <= 32 && c) {
				cp = last_start;
				skip = true;
				continue;
			}
			/* Print argv[$index]=" or envp[" part. */
			if (cp == last_start) {
				int l;
				if (argv_count)
					l = snprintf(cp, len, " argv[%u]=\"",
						     bprm->argc - argv_count);
				else
					l = snprintf(cp, len, " envp[\"");
				cp += l;
				len -= l;
			}
			if (c > ' ' && c < 127 && c != '\\') {
				/* Print "]=" part if printing environ. */
				if (c == '=' && !argv_count && !env_value) {
					cp += snprintf(cp, len, "\"]=\"");
					env_value = true;
				} else
					*cp++ = c;
				continue;
			}
			if (c) {
				*cp++ = '\\';
				*cp++ = (c >> 6) + '0';
				*cp++ = ((c >> 3) & 7) + '0';
				*cp++ = (c & 7) + '0';
				continue;
			}
			/* Ignore malformed $name=$value entry. */
			if (!argv_count && !env_value)
				cp = last_start;
			else
				*cp++ = '"';
			last_start = cp;
reset:
			skip = false;
			env_value = false;
			if (argv_count)
				argv_count--;
			else if (envp_count)
				envp_count--;
			else
				break;
		}
		offset = 0;
	}
	*cp = '\0';
	return buffer;
}

/**
 * ccs_filetype - Get string representation of file type.
 *
 * @mode: Mode value for stat().
 *
 * Returns file type string.
 */
static inline const char *ccs_filetype(const umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case 0:
		return "file";
	case S_IFDIR:
		return "directory";
	case S_IFLNK:
		return "symlink";
	case S_IFIFO:
		return "fifo";
	case S_IFSOCK:
		return "socket";
	case S_IFBLK:
		return "block";
	case S_IFCHR:
		return "char";
	}
	return "unknown"; /* This should not happen. */
}

/**
 * ccs_print_trailer - Get misc info of audit log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns string representation.
 *
 * This function uses kmalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *ccs_print_trailer(struct ccs_request_info *r)
{
	const char *handler =
		ccs_current_flags() & CCS_TASK_IS_EXECUTE_HANDLER ? "" : "!";
	const char *exe = r->exename.name;
	const char *domain = ccs_current_domain()->domainname->name;
	const int ccs_buffer_len = 2000 + strlen(exe) + strlen(domain);
	char *buffer = kmalloc(ccs_buffer_len, CCS_GFP_FLAGS);
	int pos;
	u8 i;
	if (!buffer)
		return NULL;
	pos = snprintf(buffer, ccs_buffer_len - 1, " task.pid=%u task.ppid=%u"
		       " task.uid=%u task.gid=%u task.euid=%u task.egid=%u"
		       " task.suid=%u task.sgid=%u task.fsuid=%u task.fsgid=%u"
		       " task.type%s=execute_handler task.exe=\"%s\""
		       " task.domain=\"%s\"", ccs_sys_getpid(),
		       ccs_sys_getppid(), current_uid(), current_gid(),
		       current_euid(), current_egid(), current_suid(),
		       current_sgid(), current_fsuid(), current_fsgid(),
		       handler, exe, domain);
	if (!r->obj.path[0].dentry && !r->obj.path[1].dentry)
		goto no_obj_info;
	ccs_get_attributes(r);
	for (i = 0; i < CCS_MAX_PATH_STAT; i++) {
		char objname[32];
		struct ccs_mini_stat *stat;
		unsigned int dev;
		umode_t mode;
		if (!r->obj.stat_valid[i])
			continue;
		stat = &r->obj.stat[i];
		dev = stat->dev;
		mode = stat->mode;
		memset(objname, 0, sizeof(objname));
		snprintf(objname, sizeof(objname) - 1, "%s%s.",
			 ccs_get_sarg(r->type, (i >> 1)),
			 i & 1 ? ".parent" : "");
		pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
				" %suid=%u %sgid=%u %sino=%lu %smajor=%u"
				" %sminor=%u %sperm=0%o %stype=%s"
				" %sfsmagic=0x%lX", objname, stat->uid,
				objname, stat->gid, objname, (unsigned long)
				stat->ino, objname, MAJOR(dev), objname,
				MINOR(dev), objname, mode & S_IALLUGO, objname,
				ccs_filetype(mode), objname, stat->fsmagic);
		if (S_ISCHR(mode) || S_ISBLK(mode)) {
			dev = stat->rdev;
			pos += snprintf(buffer + pos, ccs_buffer_len - 1 - pos,
					" %sdev_major=%u %sdev_minor=%u",
					objname, MAJOR(dev), objname,
					MINOR(dev));
		}
	}
no_obj_info:
	if (pos < ccs_buffer_len - 1)
		return buffer;
	kfree(buffer);
	return NULL;
}

/**
 * ccs_print_param -  Get arg info of audit log.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @buf: Buffer to write.
 * @len: Size of @buf in bytes.
 */
static int ccs_print_param(struct ccs_request_info *r, char *buf, int len)
{
#ifdef CONFIG_CCSECURITY_NETWORK
	/* Make sure that IP address argument is ready. */
	char ip[48];
	switch (r->type) {
	case CCS_MAC_NETWORK_INET_STREAM_BIND:
	case CCS_MAC_NETWORK_INET_STREAM_LISTEN:
	case CCS_MAC_NETWORK_INET_STREAM_CONNECT:
	case CCS_MAC_NETWORK_INET_STREAM_ACCEPT:
	case CCS_MAC_NETWORK_INET_DGRAM_BIND:
	case CCS_MAC_NETWORK_INET_DGRAM_SEND:
	case CCS_MAC_NETWORK_INET_RAW_BIND:
	case CCS_MAC_NETWORK_INET_RAW_SEND:
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	case CCS_MAC_NETWORK_INET_DGRAM_RECV:
	case CCS_MAC_NETWORK_INET_RAW_RECV:
#endif
		if (WARN_ON(!r->param.ip))
			return 0;
		if (r->param.is_ipv6)
			ccs_print_ipv6(ip, sizeof(ip),
				       (const struct in6_addr *) r->param.ip);
		else
			ccs_print_ipv4(ip, sizeof(ip), r->param.ip);
		break;
	default:
		//ip[0] = '\0';
		break;
	}
#endif
	/* Make sure that string arguments are ready. */
	if (!r->param.s[0])
		ccs_populate_patharg(r, true);
	if (!r->param.s[1])
		ccs_populate_patharg(r, false);
	switch (r->type) {
	case CCS_MAC_FILE_EXECUTE:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		if (WARN_ON(!r->param.s[1]))
			return 0;
		if (WARN_ON(!r->param.s[1]->name))
			return 0;
		return snprintf(buf, len, " exec=\"%s\" path=\"%s\"",
				r->param.s[1]->name, r->param.s[0]->name);
	case CCS_MAC_FILE_READ:
	case CCS_MAC_FILE_WRITE:
	case CCS_MAC_FILE_APPEND:
	case CCS_MAC_FILE_UNLINK:
#ifdef CONFIG_CCSECURITY_FILE_GETATTR
	case CCS_MAC_FILE_GETATTR:
#endif
	case CCS_MAC_FILE_RMDIR:
	case CCS_MAC_FILE_TRUNCATE:
	case CCS_MAC_FILE_CHROOT:
	case CCS_MAC_FILE_UMOUNT:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		return snprintf(buf, len, " path=\"%s\"", r->param.s[0]->name);
	case CCS_MAC_FILE_CREATE:
	case CCS_MAC_FILE_MKDIR:
	case CCS_MAC_FILE_MKFIFO:
	case CCS_MAC_FILE_MKSOCK:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		return snprintf(buf, len, " path=\"%s\" perm=0%lo",
				r->param.s[0]->name, r->param.i[0]);
	case CCS_MAC_FILE_SYMLINK:
		return snprintf(buf, len, " path=\"%s\" target=\"%s\"",
				r->param.s[0]->name, r->param.s[1]->name);
	case CCS_MAC_FILE_MKBLOCK:
	case CCS_MAC_FILE_MKCHAR:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		return snprintf(buf, len, " path=\"%s\" perm=0%lo "
				"dev_major=%lu dev_minor=%lu",
				r->param.s[0]->name, r->param.i[0],
				r->param.i[1], r->param.i[2]);
	case CCS_MAC_FILE_LINK:
	case CCS_MAC_FILE_RENAME:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		if (WARN_ON(!r->param.s[1]))
			return 0;
		if (WARN_ON(!r->param.s[1]->name))
			return 0;
		return snprintf(buf, len, " old_path=\"%s\" new_path=\"%s\"",
				r->param.s[0]->name, r->param.s[1]->name);
	case CCS_MAC_FILE_CHMOD:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		return snprintf(buf, len, " path=\"%s\" perm=0%lo",
				r->param.s[0]->name, r->param.i[0]);
	case CCS_MAC_FILE_CHOWN:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		return snprintf(buf, len, " path=\"%s\" uid=%lu",
				r->param.s[0]->name, r->param.i[0]);
	case CCS_MAC_FILE_CHGRP:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		return snprintf(buf, len, " path=\"%s\" gid=%lu",
				r->param.s[0]->name, r->param.i[0]);
	case CCS_MAC_FILE_IOCTL:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		return snprintf(buf, len, " path=\"%s\" cmd=0x%lX",
				r->param.s[0]->name, r->param.i[0]);
	case CCS_MAC_FILE_MOUNT:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		if (WARN_ON(!r->param.s[1]))
			return 0;
		if (WARN_ON(!r->param.s[1]->name))
			return 0;
		if (WARN_ON(!r->param.s[2]))
			return 0;
		if (WARN_ON(!r->param.s[2]->name))
			return 0;
		return snprintf(buf, len, " source=\"%s\" target=\"%s\""
				" fstype=\"%s\" flags=0x%lX",
				r->param.s[0]->name, r->param.s[1]->name,
				r->param.s[2]->name, r->param.i[0]);
	case CCS_MAC_FILE_PIVOT_ROOT:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		if (WARN_ON(!r->param.s[1]))
			return 0;
		if (WARN_ON(!r->param.s[1]->name))
			return 0;
		return snprintf(buf, len, " new_root=\"%s\" put_old=\"%s\"",
				r->param.s[0]->name, r->param.s[1]->name);
#ifdef CONFIG_CCSECURITY_MISC
	case CCS_MAC_ENVIRON:
		if (WARN_ON(!r->param.s[2]))
			return 0;
		if (WARN_ON(!r->param.s[2]->name))
			return 0;
		if (WARN_ON(!r->param.s[3]))
			return 0;
		if (WARN_ON(!r->param.s[3]->name))
			return 0;
		return snprintf(buf, len, " name=\"%s\" value=\"%s\"",
				r->param.s[2]->name, r->param.s[3]->name);
#endif
	case CCS_MAC_CAPABILITY_MODIFY_POLICY:
#ifdef CONFIG_CCSECURITY_CAPABILITY
	case CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET:
	case CCS_MAC_CAPABILITY_USE_PACKET_SOCKET:
	case CCS_MAC_CAPABILITY_SYS_REBOOT:
	case CCS_MAC_CAPABILITY_SYS_VHANGUP:
	case CCS_MAC_CAPABILITY_SYS_SETTIME:
	case CCS_MAC_CAPABILITY_SYS_NICE:
	case CCS_MAC_CAPABILITY_SYS_SETHOSTNAME:
	case CCS_MAC_CAPABILITY_USE_KERNEL_MODULE:
	case CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD:
#endif
		return 0;
#ifdef CONFIG_CCSECURITY_NETWORK
	case CCS_MAC_NETWORK_INET_STREAM_BIND:
	case CCS_MAC_NETWORK_INET_STREAM_LISTEN:
	case CCS_MAC_NETWORK_INET_STREAM_CONNECT:
	case CCS_MAC_NETWORK_INET_STREAM_ACCEPT:
	case CCS_MAC_NETWORK_INET_DGRAM_BIND:
	case CCS_MAC_NETWORK_INET_DGRAM_SEND:
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	case CCS_MAC_NETWORK_INET_DGRAM_RECV:
#endif
		return snprintf(buf, len, " ip=%s port=%lu", ip,
				r->param.i[0]);
	case CCS_MAC_NETWORK_INET_RAW_BIND:
	case CCS_MAC_NETWORK_INET_RAW_SEND:
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	case CCS_MAC_NETWORK_INET_RAW_RECV:
#endif
		return snprintf(buf, len, " ip=%s proto=%lu", ip,
				r->param.i[0]);
	case CCS_MAC_NETWORK_UNIX_STREAM_BIND:
	case CCS_MAC_NETWORK_UNIX_STREAM_LISTEN:
	case CCS_MAC_NETWORK_UNIX_STREAM_CONNECT:
	case CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT:
	case CCS_MAC_NETWORK_UNIX_DGRAM_BIND:
	case CCS_MAC_NETWORK_UNIX_DGRAM_SEND:
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	case CCS_MAC_NETWORK_UNIX_DGRAM_RECV:
#endif
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT:
	case CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		return snprintf(buf, len, " addr=\"%s\"", r->param.s[0]->name);
#endif
#ifdef CONFIG_CCSECURITY_IPC
	case CCS_MAC_PTRACE:
		if (WARN_ON(!r->param.s[0]))
			return 0;
		if (WARN_ON(!r->param.s[0]->name))
			return 0;
		return snprintf(buf, len, " cmd=%lu domain=\"%s\"",
				r->param.i[0], r->param.s[0]->name);
#endif
	default:
		break;
	}
	return 0;
}


/**
 * ccs_init_log - Allocate buffer for audit logs.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns pointer to allocated memory.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *ccs_init_log(struct ccs_request_info *r)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	const pid_t gpid = ccs_sys_getpid();
#else
	const pid_t gpid = task_pid_nr(current);
#endif
	struct timeval tv;
	struct ccs_time stamp;
	static const char * const k[CCS_MAX_MATCHING] = {
		[CCS_MATCHING_UNMATCHED] = "unmatched",
		[CCS_MATCHING_ALLOWED] = "allowed",
		[CCS_MATCHING_DENIED] = "denied",
	};
	char *buf;
	const char *bprm_info;
	const char *trailer;
	int len;
	if (!r->exename.name && !ccs_get_exename(&r->exename))
		return NULL;
	do_gettimeofday(&tv);
	ccs_convert_time(tv.tv_sec, &stamp);
	trailer = ccs_print_trailer(r);
	if (r->bprm)
		bprm_info = ccs_print_bprm(r->bprm, &r->dump);
	else
		bprm_info = NULL;
	len = 0;
	while (1) {
		int pos;
		buf = kzalloc(len, CCS_GFP_FLAGS);
		if (!buf)
			break;
		pos = snprintf(buf, len, "#%04u/%02u/%02u %02u:%02u:%02u# "
			       "global-pid=%u result=%s / %s %s", stamp.year,
			       stamp.month, stamp.day, stamp.hour, stamp.min,
			       stamp.sec, gpid, k[r->result],
			       ccs_category_keywords[ccs_index2category
						     [r->type]],
			       ccs_mac_keywords[r->type]);
		pos += ccs_print_param(r, buf + pos,
				       pos < len ? len - pos : 0);
		if (bprm_info)
			pos += snprintf(buf + pos, pos < len ? len - pos : 0,
					"%s", bprm_info);
		if (trailer)
			pos += snprintf(buf + pos, pos < len ? len - pos : 0,
					"%s", trailer);
		pos += snprintf(buf + pos, pos < len ? len - pos : 0,
				"\n") + 1;
		if (pos <= len)
			break;
		kfree(buf);
		len = pos;
	}
	kfree(bprm_info);
	kfree(trailer);
	return buf;
}

/**
 * ccs_write_log - Write an audit log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns nothing.
 */
static void ccs_write_log(struct ccs_request_info *r)
{
	struct ccs_log *entry;
	bool quota_exceeded = false;
	int len;
	char *buf = ccs_init_log(r);
	if (!buf)
		return;
	entry = kzalloc(sizeof(*entry), CCS_GFP_FLAGS);
	if (!entry) {
		kfree(buf);
		return;
	}
	entry->log = buf;
	len = ccs_round2(strlen(buf) + 1);
	/*
	 * The entry->size is used for memory quota checks.
	 * Don't go beyond strlen(entry->log).
	 */
	entry->size = len + ccs_round2(sizeof(*entry));
	entry->result = r->result;
	spin_lock(&ccs_log_lock);
	if (ccs_memory_quota[CCS_MEMORY_AUDIT] &&
	    ccs_memory_used[CCS_MEMORY_AUDIT] + entry->size >=
	    ccs_memory_quota[CCS_MEMORY_AUDIT]) {
		quota_exceeded = true;
	} else {
		ccs_memory_used[CCS_MEMORY_AUDIT] += entry->size;
		list_add_tail(&entry->list, &ccs_log);
		ccs_log_count[entry->result]++;
	}
	spin_unlock(&ccs_log_lock);
	if (quota_exceeded) {
		kfree(buf);
		kfree(entry);
		return;
	}
	wake_up(&ccs_log_wait);
}

/**
 * ccs_read_log - Read an audit log.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns nothing.
 */
static void ccs_read_log(struct ccs_io_buffer *head)
{
	struct ccs_log *ptr = NULL;
	if (head->r.w_pos)
		return;
	kfree(head->read_buf);
	head->read_buf = NULL;
	spin_lock(&ccs_log_lock);
	if (!list_empty(&ccs_log)) {
		ptr = list_entry(ccs_log.next, typeof(*ptr), list);
		list_del(&ptr->list);
		ccs_log_count[ptr->result]--;
		ccs_memory_used[CCS_MEMORY_AUDIT] -= ptr->size;
	}
	spin_unlock(&ccs_log_lock);
	if (ptr) {
		head->read_buf = ptr->log;
		head->r.w[head->r.w_pos++] = head->read_buf;
		kfree(ptr);
	}
}

/**
 * ccs_poll_log - Wait for an audit log.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns POLLIN | POLLRDNORM when ready to read an audit log.
 */
static int ccs_poll_log(struct file *file, poll_table *wait)
{
	enum ccs_matching_result i;
	for (i = 0; i < CCS_MAX_MATCHING; i++)
		if (ccs_log_count[i])
			return POLLIN | POLLRDNORM;
	poll_wait(file, &ccs_log_wait, wait);
	for (i = 0; i < CCS_MAX_MATCHING; i++)
		if (ccs_log_count[i])
			return POLLIN | POLLRDNORM;
	return 0;
}

/**
 * ccs_assign_domain - Create a domain.
 *
 * @domainname: The name of domain.
 *
 * Returns pointer to "struct ccs_domain_info" on success, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
struct ccs_domain_info *ccs_assign_domain(const char *domainname)
{
	struct ccs_security *security = ccs_current_security();
	struct ccs_domain_info e = { };
	struct ccs_domain_info *entry = ccs_find_domain(domainname);
	if (entry) {
		security->ccs_domain_info = entry;
		return entry;
	}
	/* Requested domain does not exist. */
	/* Don't create requested domain if domainname is invalid. */
	if (!ccs_correct_domain(domainname))
		return NULL;
	e.domainname = ccs_get_name(domainname);
	if (!e.domainname)
		return NULL;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	entry = ccs_find_domain(domainname);
	if (entry)
		goto done;
	entry = ccs_commit_ok(&e, sizeof(e));
	if (!entry)
		goto done;
	list_add_tail_rcu(&entry->list, &ccs_domain_list);
done:
	mutex_unlock(&ccs_policy_lock);
out:
	ccs_put_name(e.domainname);
	if (entry)
		security->ccs_domain_info = entry;
	return entry;
}

/**
 * ccs_parse_policy - Parse a policy line.
 *
 * @head: Poiter to "struct ccs_io_buffer".
 * @line: Line to parse.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_parse_policy(struct ccs_io_buffer *head, char *line)
{
	/* Set current line's content. */
	head->w.data = line;
	head->w.is_deny = false;
	head->w.priority = 0;
	/* Delete request? */
	head->w.is_delete = !strncmp(line, "delete ", 7);
	if (head->w.is_delete)
		memmove(line, line + 7, strlen(line + 7) + 1);
	/* Do the update. */
	switch (head->type) {
#ifdef CONFIG_CCSECURITY_TASK_EXECUTE_HANDLER
	case CCS_EXECUTE_HANDLER:
#endif
	case CCS_PROCESS_STATUS:
		return ccs_write_pid(head);
	case CCS_QUERY:
		return ccs_write_answer(head);
	case CCS_POLICY:
		return ccs_write_policy(head);
	default:
		return -ENOSYS;
	}
}

/**
 * ccs_policy_io_init - Register hooks for policy I/O.
 *
 * Returns nothing.
 */
static void __init ccs_policy_io_init(void)
{
	ccsecurity_ops.check_profile = ccs_check_profile;
}

/**
 * ccs_load_builtin_policy - Load built-in policy.
 *
 * Returns nothing.
 */
static void __init ccs_load_builtin_policy(void)
{
	/*
	 * This include file is manually created and contains built-in policy.
	 *
	 * static char [] __initdata ccs_builtin_policy = { ... };
	 */
#include "builtin-policy.h"
	const int idx = ccs_read_lock();
	struct ccs_io_buffer head = { };
	char *start = ccs_builtin_policy;
	head.type = CCS_POLICY;
	while (1) {
		char *end = strchr(start, '\n');
		if (!end)
			break;
		*end = '\0';
		ccs_normalize_line(start);
		head.write_buf = start;
		ccs_parse_policy(&head, start);
		start = end + 1;
	}
	ccs_read_unlock(idx);
#ifdef CONFIG_CCSECURITY_OMIT_USERSPACE_LOADER
	ccs_check_profile();
#endif
}

/**
 * ccs_read_self - read() for /proc/ccs/self_domain interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Domainname which current thread belongs to.
 * @count: Size of @buf.
 * @ppos:  Bytes read by now.
 *
 * Returns read size on success, negative value otherwise.
 */
static ssize_t ccs_read_self(struct file *file, char __user *buf, size_t count,
			     loff_t *ppos)
{
	const char *domain = ccs_current_domain()->domainname->name;
	loff_t len = strlen(domain);
	loff_t pos = *ppos;
	if (pos >= len || !count)
		return 0;
	len -= pos;
	if (count < len)
		len = count;
	if (copy_to_user(buf, domain + pos, len))
		return -EFAULT;
	*ppos += len;
	return len;
}

/**
 * ccs_read_subacl - Read sub ACL in ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @list: Pointer to "struct list_head".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_read_subacl(struct ccs_io_buffer *head,
			    const struct list_head *list)
{
	list_for_each_cookie(head->r.subacl, list) {
		struct ccs_acl_info *acl =
			list_entry(head->r.subacl, typeof(*acl), list);
		switch (head->r.step) {
		case 3:
			if (acl->is_deleted)
				continue;
			if (!ccs_flush(head))
				return false;
			ccs_io_printf(head, "    %u ", acl->priority);
			if (acl->is_deny)
				ccs_set_string(head, "deny");
			else
				ccs_set_string(head, "allow");
			head->r.cond_step = 0;
			head->r.step++;
			/* fall through */
		case 4:
			if (!ccs_flush(head))
				return false;
			if (acl->cond &&
			    !ccs_print_condition(head, acl->cond))
				return false;
			ccs_set_lf(head);
			head->r.step--;
		}
	}
	head->r.subacl = NULL;
	return true;
}

/**
 * ccs_read_policy - Read policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Caller holds ccs_read_lock().
 */
static void ccs_read_policy(struct ccs_io_buffer *head)
{
	if (head->r.eof)
		return;
	if (head->r.print_this_acl_only)
		goto skip;
	if (!head->r.version_done) {
		ccs_io_printf(head, "POLICY_VERSION=%u\n", ccs_policy_version);
		head->r.version_done = true;
	}
	if (!head->r.stat_done) {
		ccs_read_stat(head);
		head->r.stat_done = true;
	}
	if (!head->r.quota_done) {
		if (!ccs_read_quota(head))
			return;
		head->r.quota_done = true;
	}
	if (!head->r.group_done) {
		if (!ccs_read_group(head))
			return;
		head->r.group_done = true;
		ccs_set_lf(head);
	}
	while (head->r.acl_index < CCS_MAX_MAC_INDEX) {
		struct list_head * const list =
			&ccs_acl_list[head->r.acl_index];
		list_for_each_cookie(head->r.acl, list) {
			struct ccs_acl_info *ptr;
skip:
			ptr = list_entry(head->r.acl, typeof(*ptr), list);
			switch (head->r.step) {
			case 0:
				if (ptr->is_deleted &&
				    !head->r.print_this_acl_only)
					continue;
				head->r.step++;
				/* fall through */
			case 1:
				if (!ccs_read_acl(head, ptr))
					return;
				head->r.step++;
				/* fall through */
			case 2:
				if (!ccs_flush(head))
					return;
				ccs_io_printf(head, "    audit %u\n",
					      ptr->audit);
				head->r.step++;
				/* fall through */
			case 3:
			case 4:
				if (!ccs_read_subacl(head,
						     &ptr->acl_info_list))
					return;
				head->r.step = 5;
				/* fall through */
			case 5:
				if (!ccs_flush(head))
					return;
				ccs_set_lf(head);
				head->r.step = 0;
				if (head->r.print_this_acl_only)
					goto done;
			}
		}
		head->r.acl = NULL;
		head->r.acl_index++;
	}
done:
	head->r.eof = true;
}

/**
 * ccs_open - open() for /proc/ccs/ interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_open(struct inode *inode, struct file *file)
{
	const u8 type = (unsigned long) PDE(inode)->data;
	struct ccs_io_buffer *head = kzalloc(sizeof(*head), CCS_GFP_FLAGS);
	if (!head)
		return -ENOMEM;
	mutex_init(&head->io_sem);
	head->type = type;
#ifdef CONFIG_CCSECURITY_TASK_EXECUTE_HANDLER
	if (type == CCS_EXECUTE_HANDLER) {
		/* Allow execute_handler to read process's status. */
		if (!(ccs_current_flags() & CCS_TASK_IS_EXECUTE_HANDLER)) {
			kfree(head);
			return -EPERM;
		}
	}
#endif
	if ((file->f_mode & FMODE_READ) && type != CCS_AUDIT &&
	    type != CCS_QUERY) {
		/* Don't allocate read_buf for poll() access. */
		head->readbuf_size = 4096;
		head->read_buf = kzalloc(head->readbuf_size, CCS_GFP_FLAGS);
		if (!head->read_buf) {
			kfree(head);
			return -ENOMEM;
		}
	}
	if (file->f_mode & FMODE_WRITE) {
		head->writebuf_size = 4096;
		head->write_buf = kzalloc(head->writebuf_size, CCS_GFP_FLAGS);
		if (!head->write_buf) {
			kfree(head->read_buf);
			kfree(head);
			return -ENOMEM;
		}
	}
	/*
	 * If the file is /proc/ccs/query, increment the observer counter.
	 * The obserber counter is used by ccs_supervisor() to see if
	 * there is some process monitoring /proc/ccs/query.
	 */
	if (type == CCS_QUERY)
		atomic_inc(&ccs_query_observers);
	file->private_data = head;
	ccs_notify_gc(head, true);
	return 0;
}

/**
 * ccs_release - close() for /proc/ccs/ interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0.
 */
static int ccs_release(struct inode *inode, struct file *file)
{
	struct ccs_io_buffer *head = file->private_data;
	/*
	 * If the file is /proc/ccs/query, decrement the observer counter.
	 */
	if (head->type == CCS_QUERY &&
	    atomic_dec_and_test(&ccs_query_observers))
		wake_up_all(&ccs_answer_wait);
	ccs_notify_gc(head, false);
	return 0;
}

/**
 * ccs_poll - poll() for /proc/ccs/ interface.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns 0 on success, negative value otherwise.
 */
static unsigned int ccs_poll(struct file *file, poll_table *wait)
{
	struct ccs_io_buffer *head = file->private_data;
	switch (head->type) {
	case CCS_AUDIT:
		return ccs_poll_log(file, wait);
	case CCS_QUERY:
		return ccs_poll_query(file, wait);
	default:
		return -ENOSYS;
	}
}

/**
 * ccs_read - read() for /proc/ccs/ interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns bytes read on success, negative value otherwise.
 */
static ssize_t ccs_read(struct file *file, char __user *buf, size_t count,
			loff_t *ppos)
{
	struct ccs_io_buffer *head = file->private_data;
	int len;
	int idx;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	head->read_user_buf = buf;
	head->read_user_buf_avail = count;
	idx = ccs_read_lock();
	if (ccs_flush(head)) {
		/* Call the policy handler. */
		switch (head->type) {
		case CCS_AUDIT:
			ccs_read_log(head);
			break;
#ifdef CONFIG_CCSECURITY_TASK_EXECUTE_HANDLER
		case CCS_EXECUTE_HANDLER:
#endif
		case CCS_PROCESS_STATUS:
			ccs_read_pid(head);
			break;
		case CCS_VERSION:
			ccs_read_version(head);
			break;
		case CCS_QUERY:
			ccs_read_query(head);
			break;
		case CCS_POLICY:
			ccs_read_policy(head);
			break;
		}
		ccs_flush(head);
	}
	ccs_read_unlock(idx);
	len = head->read_user_buf - buf;
	mutex_unlock(&head->io_sem);
	return len;
}

#ifdef CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION

/**
 * ccs_write_self - write() for /proc/ccs/self_domain interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Domainname to transit to.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns @count on success, negative value otherwise.
 *
 * If domain transition was permitted but the domain transition failed, this
 * function returns error rather than terminating current thread with SIGKILL.
 */
static ssize_t ccs_write_self(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char *data;
	int error;
	if (!count || count >= CCS_EXEC_TMPSIZE - 10)
		return -ENOMEM;
	data = kzalloc(count + 1, CCS_GFP_FLAGS);
	if (!data)
		return -ENOMEM;
	if (copy_from_user(data, buf, count)) {
		error = -EFAULT;
		goto out;
	}
	ccs_normalize_line(data);
	if (ccs_correct_domain(data)) {
		const int idx = ccs_read_lock();
		struct ccs_path_info name;
		struct ccs_request_info r = { };
		name.name = data;
		ccs_fill_path_info(&name);
		/* Check "task manual_domain_transition" permission. */
		r.type = CCS_MAC_MANUAL_TASK_TRANSITION;
		r.param.s[0] = &name;
		ccs_check_acl(&r, true);
		if (r.result != CCS_MATCHING_ALLOWED)
			error = -EPERM;
		else
			error = ccs_assign_domain(data) ? 0 : -ENOENT;
		ccs_read_unlock(idx);
	} else
		error = -EINVAL;
out:
	kfree(data);
	return error ? error : count;
}

#endif

/**
 * ccs_write - write() for /proc/ccs/ interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns @count on success, negative value otherwise.
 */
static ssize_t ccs_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	struct ccs_io_buffer *head = file->private_data;
	int error = count;
	char *cp0 = head->write_buf;
	int idx;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	head->read_user_buf_avail = 0;
	idx = ccs_read_lock();
	/* Read a line and dispatch it to the policy handler. */
	while (count) {
		char c;
		if (head->w.avail >= head->writebuf_size - 1) {
			const int len = head->writebuf_size * 2;
			char *cp = kzalloc(len, CCS_GFP_FLAGS);
			if (!cp) {
				error = -ENOMEM;
				break;
			}
			memmove(cp, cp0, head->w.avail);
			kfree(cp0);
			head->write_buf = cp;
			cp0 = cp;
			head->writebuf_size = len;
		}
		if (get_user(c, buf)) {
			error = -EFAULT;
			break;
		}
		buf++;
		count--;
		cp0[head->w.avail++] = c;
		if (c != '\n')
			continue;
		cp0[head->w.avail - 1] = '\0';
		head->w.avail = 0;
		ccs_normalize_line(cp0);
		/* Don't allow updating policies by non manager programs. */
		if (head->type != CCS_PROCESS_STATUS && !ccs_manager()) {
			error = -EPERM;
			goto out;
		}
		switch (ccs_parse_policy(head, cp0)) {
		case -EPERM:
			error = -EPERM;
			goto out;
		case 0:
			/* Update statistics. */
			if (head->type == CCS_POLICY)
				ccs_update_stat(CCS_STAT_POLICY_UPDATES);
			break;
		}
	}
out:
	ccs_read_unlock(idx);
	mutex_unlock(&head->io_sem);
	return error;
}

/**
 * ccs_create_entry - Create interface files under /proc/ccs/ directory.
 *
 * @name:   The name of the interface file.
 * @mode:   The permission of the interface file.
 * @parent: The parent directory.
 * @key:    Type of interface.
 *
 * Returns nothing.
 */
static void __init ccs_create_entry(const char *name, const umode_t mode,
				    struct proc_dir_entry *parent,
				    const u8 key)
{
	struct proc_dir_entry *entry = create_proc_entry(name, mode, parent);
	if (entry) {
		entry->proc_fops = &ccs_operations;
		entry->data = ((u8 *) NULL) + key;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
		if (entry->proc_iops)
			ccs_file_inode_operations = *entry->proc_iops;
		if (!ccs_file_inode_operations.setattr)
			ccs_file_inode_operations.setattr = proc_notify_change;
		entry->proc_iops = &ccs_file_inode_operations;
#endif
	}
}

/**
 * ccs_proc_init - Initialize /proc/ccs/ interface.
 *
 * Returns 0.
 */
static void __init ccs_proc_init(void)
{
	struct proc_dir_entry *ccs_dir = proc_mkdir("ccs", NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
	if (ccs_dir->proc_iops)
		ccs_dir_inode_operations = *ccs_dir->proc_iops;
	if (!ccs_dir_inode_operations.setattr)
		ccs_dir_inode_operations.setattr = proc_notify_change;
	ccs_dir->proc_iops = &ccs_dir_inode_operations;
#endif
	ccs_create_entry("query",            0600, ccs_dir, CCS_QUERY);
	ccs_create_entry("audit",            0400, ccs_dir, CCS_AUDIT);
	ccs_create_entry(".process_status",  0600, ccs_dir,
			 CCS_PROCESS_STATUS);
	ccs_create_entry("version",          0400, ccs_dir, CCS_VERSION);
#ifdef CONFIG_CCSECURITY_TASK_EXECUTE_HANDLER
	ccs_create_entry(".execute_handler", 0666, ccs_dir,
			 CCS_EXECUTE_HANDLER);
#endif
	ccs_create_entry("policy",           0600, ccs_dir, CCS_POLICY);
	{
		struct proc_dir_entry *e = create_proc_entry("self_domain",
							     0666, ccs_dir);
		if (e)
			e->proc_fops = &ccs_self_operations;
	}
}

/**
 * ccs_init_module - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __init ccs_init_module(void)
{
	u8 idx;
	if (ccsecurity_ops.disabled)
		return -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
	MOD_INC_USE_COUNT;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
	if (init_srcu_struct(&ccs_ss))
		panic("Out of memory.");
#endif
	for (idx = 0; idx < CCS_MAX_MAC_INDEX; idx++)
		INIT_LIST_HEAD(&ccs_acl_list[idx]);
	for (idx = 0; idx < CCS_MAX_GROUP; idx++)
		INIT_LIST_HEAD(&ccs_group_list[idx]);
	ccs_mm_init();
	ccs_policy_io_init();
	ccs_permission_init();
	ccs_proc_init();
	ccs_load_builtin_policy();
	return 0;
}

MODULE_LICENSE("GPL");
module_init(ccs_init_module);
