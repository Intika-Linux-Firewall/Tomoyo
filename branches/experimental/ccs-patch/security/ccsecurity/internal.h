/*
 * security/ccsecurity/internal.h
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.8.3+   2011/11/11
 */

#ifndef _SECURITY_CCSECURITY_INTERNAL_H
#define _SECURITY_CCSECURITY_INTERNAL_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 38)
#include <linux/smp_lock.h>
#endif
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/poll.h>
#include <linux/binfmts.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#include <linux/fs.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
#include <linux/fs_struct.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#include <linux/namespace.h>
#endif
#include <linux/proc_fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0) || defined(RHEL_MAJOR)
#include <linux/hash.h>
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18) || (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33) && defined(CONFIG_SYSCTL_SYSCALL))
#include <linux/sysctl.h>
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 6)
#include <linux/kthread.h>
#endif
#include <stdarg.h>
#include <asm/uaccess.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define sk_family family
#define sk_protocol protocol
#define sk_type type
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)

/* Structure for holding "struct vfsmount *" and "struct dentry *". */
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

#endif

#ifndef __printf
#define __printf(a,b) __attribute__((format(printf,a,b)))
#endif
#ifndef __packed
#define __packed __attribute__((__packed__))
#endif
#ifndef bool
#define bool _Bool
#endif
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif

#ifndef __user
#define __user
#endif

#ifndef current_uid
#define current_uid()   (current->uid)
#endif
#ifndef current_gid
#define current_gid()   (current->gid)
#endif
#ifndef current_euid
#define current_euid()  (current->euid)
#endif
#ifndef current_egid
#define current_egid()  (current->egid)
#endif
#ifndef current_suid
#define current_suid()  (current->suid)
#endif
#ifndef current_sgid
#define current_sgid()  (current->sgid)
#endif
#ifndef current_fsuid
#define current_fsuid() (current->fsuid)
#endif
#ifndef current_fsgid
#define current_fsgid() (current->fsgid)
#endif

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
#define mutex semaphore
#define mutex_init(mutex) init_MUTEX(mutex)
#define mutex_unlock(mutex) up(mutex)
#define mutex_lock(mutex) down(mutex)
#define mutex_lock_interruptible(mutex) down_interruptible(mutex)
#define mutex_trylock(mutex) (!down_trylock(mutex))
#define DEFINE_MUTEX(mutexname) DECLARE_MUTEX(mutexname)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
#define MS_UNBINDABLE	(1<<17)	/* change to unbindable */
#define MS_PRIVATE	(1<<18)	/* change to private */
#define MS_SLAVE	(1<<19)	/* change to slave */
#define MS_SHARED	(1<<20)	/* change to shared */
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({				\
			const typeof(((type *)0)->member) *__mptr = (ptr); \
			(type *)((char *)__mptr - offsetof(type, member)); })
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
#define smp_read_barrier_depends smp_rmb
#endif

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#ifndef rcu_dereference
#define rcu_dereference(p)     ({					\
			typeof(p) _________p1 = ACCESS_ONCE(p);		\
			smp_read_barrier_depends(); /* see RCU */	\
			(_________p1);					\
		})
#endif

#ifndef rcu_assign_pointer
#define rcu_assign_pointer(p, v)			\
	({						\
		if (!__builtin_constant_p(v) ||		\
		    ((v) != NULL))			\
			smp_wmb(); /* see RCU */	\
		(p) = (v);				\
	})
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14)

/**
 * kzalloc() - Allocate memory. The memory is set to zero.
 *
 * @size:  Size to allocate.
 * @flags: GFP flags.
 *
 * Returns pointer to allocated memory on success, NULL otherwise.
 *
 * This is for compatibility with older kernels.
 *
 * Since several distributions backported kzalloc(), I define it as a macro
 * rather than an inlined function in order to avoid multiple definition error.
 */
#define kzalloc(size, flags) ({					\
			void *ret = kmalloc((size), (flags));	\
			if (ret)				\
				memset(ret, 0, (size));		\
			ret; })

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)

/**
 * path_put - Drop reference on "struct path".
 *
 * @path: Pointer to "struct path".
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 */
static inline void path_put(struct path *path)
{
	dput(path->dentry);
	mntput(path->mnt);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)

/**
 * __list_add_rcu - Insert a new entry between two known consecutive entries.
 *
 * @new:  Pointer to "struct list_head".
 * @prev: Pointer to "struct list_head".
 * @next: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 */
static inline void __list_add_rcu(struct list_head *new,
				  struct list_head *prev,
				  struct list_head *next)
{
	new->next = next;
	new->prev = prev;
	rcu_assign_pointer(prev->next, new);
	next->prev = new;
}

/**
 * list_add_tail_rcu - Add a new entry to rcu-protected list.
 *
 * @new:  Pointer to "struct list_head".
 * @head: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 */
static inline void list_add_tail_rcu(struct list_head *new,
				     struct list_head *head)
{
	__list_add_rcu(new, head->prev, head);
}

/**
 * list_add_rcu - Add a new entry to rcu-protected list.
 *
 * @new:  Pointer to "struct list_head".
 * @head: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 */
static inline void list_add_rcu(struct list_head *new, struct list_head *head)
{
	__list_add_rcu(new, head, head->next);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)

/**
 * __list_del_entry - Deletes entry from list without re-initialization.
 *
 * @entry: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 */
static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

#endif

#ifndef list_for_each_entry_safe

/**
 * list_for_each_entry_safe - Iterate over list of given type safe against removal of list entry.
 *
 * @pos:    The "type *" to use as a loop cursor.
 * @n:      Another "type *" to use as temporary storage.
 * @head:   Pointer to "struct list_head".
 * @member: The name of the list_struct within the struct.
 *
 * This is for compatibility with older kernels.
 */
#define list_for_each_entry_safe(pos, n, head, member)                  \
	for (pos = list_entry((head)->next, typeof(*pos), member),      \
		     n = list_entry(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#endif

#ifndef srcu_dereference

/**
 * srcu_dereference - Fetch SRCU-protected pointer with checking.
 *
 * @p:  The pointer to read, prior to dereferencing.
 * @ss: Pointer to "struct srcu_struct".
 *
 * Returns @p.
 *
 * This is for compatibility with older kernels.
 */
#define srcu_dereference(p, ss) rcu_dereference(p)

#endif

#ifndef list_for_each_entry_srcu

/**
 * list_for_each_entry_srcu - Iterate over rcu list of given type.
 *
 * @pos:    The type * to use as a loop cursor.
 * @head:   The head for your list.
 * @member: The name of the list_struct within the struct.
 * @ss:     Pointer to "struct srcu_struct".
 *
 * As of 2.6.36, this macro is not provided because only TOMOYO wants it.
 */
#define list_for_each_entry_srcu(pos, head, member, ss)		      \
	for (pos = list_entry(srcu_dereference((head)->next, ss),     \
			      typeof(*pos), member);		      \
	     prefetch(pos->member.next), &pos->member != (head);      \
	     pos = list_entry(srcu_dereference(pos->member.next, ss), \
			      typeof(*pos), member))

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 30) || (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 9))

#ifndef ssleep

/**
 * ssleep - Sleep for specified seconds.
 *
 * @secs: Seconds to sleep.
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 *
 * Since several distributions backported ssleep(), I define it as a macro
 * rather than an inlined function in order to avoid multiple definition error.
 */
#define ssleep(secs) {						\
		set_current_state(TASK_UNINTERRUPTIBLE);	\
		schedule_timeout((HZ * secs) + 1);		\
	}

#endif

#endif

/*
 * TOMOYO specific part start.
 */

#include <linux/ccsecurity.h>

/* Enumeration definition for internal use. */

/* Index numbers for "struct ccs_condition". */
enum ccs_conditions_index {
	/* 0 */
	CCS_SELF_UID,             /* current_uid()   */
	CCS_SELF_EUID,            /* current_euid()  */
	CCS_SELF_SUID,            /* current_suid()  */
	CCS_SELF_FSUID,           /* current_fsuid() */
	CCS_SELF_GID,             /* current_gid()   */
	CCS_SELF_EGID,            /* current_egid()  */
	CCS_SELF_SGID,            /* current_sgid()  */
	CCS_SELF_FSGID,           /* current_fsgid() */
	CCS_SELF_PID,             /* sys_getpid()   */
	CCS_SELF_PPID,            /* sys_getppid()  */
	/* 10 */
	CCS_TASK_TYPE,            /* ((u8) task->ccs_flags) &
				     CCS_TASK_IS_EXECUTE_HANDLER */
	CCS_SELF_DOMAIN,
	CCS_SELF_EXE,
	CCS_EXEC_ARGC,            /* "struct linux_binprm *"->argc */
	CCS_EXEC_ENVC,            /* "struct linux_binprm *"->envc */
	CCS_OBJ_IS_SOCKET,        /* S_IFSOCK */
	CCS_OBJ_IS_SYMLINK,       /* S_IFLNK */
	CCS_OBJ_IS_FILE,          /* S_IFREG */
	CCS_OBJ_IS_BLOCK_DEV,     /* S_IFBLK */
	CCS_OBJ_IS_DIRECTORY,     /* S_IFDIR */
	/* 20 */
	CCS_OBJ_IS_CHAR_DEV,      /* S_IFCHR */
	CCS_OBJ_IS_FIFO,          /* S_IFIFO */
	CCS_MODE_SETUID,          /* S_ISUID */
	CCS_MODE_SETGID,          /* S_ISGID */
	CCS_MODE_STICKY,          /* S_ISVTX */
	CCS_MODE_OWNER_READ,      /* S_IRUSR */
	CCS_MODE_OWNER_WRITE,     /* S_IWUSR */
	CCS_MODE_OWNER_EXECUTE,   /* S_IXUSR */
	CCS_MODE_GROUP_READ,      /* S_IRGRP */
	CCS_MODE_GROUP_WRITE,     /* S_IWGRP */
	/* 30 */
	CCS_MODE_GROUP_EXECUTE,   /* S_IXGRP */
	CCS_MODE_OTHERS_READ,     /* S_IROTH */
	CCS_MODE_OTHERS_WRITE,    /* S_IWOTH */
	CCS_MODE_OTHERS_EXECUTE,  /* S_IXOTH */
	CCS_TASK_EXECUTE_HANDLER, /* CCS_TASK_IS_EXECUTE_HANDLER */
	CCS_HANDLER_PATH,
	CCS_TRANSIT_DOMAIN,
	CCS_MAX_CONDITION_KEYWORD,
	CCS_COND_SARG0,
	CCS_COND_SARG1,
	/* 40 */
	CCS_COND_SARG2,
	CCS_COND_NARG0,
	CCS_COND_NARG1,
	CCS_COND_NARG2,
	CCS_COND_IPARG,
	CCS_COND_DOMAIN,
	CCS_IMM_GROUP,
	CCS_IMM_NAME_ENTRY,
	CCS_IMM_DOMAINNAME_ENTRY,
	CCS_IMM_NUMBER_ENTRY1,
	/* 50 */
	CCS_IMM_NUMBER_ENTRY2,
	CCS_IMM_IPV4ADDR_ENTRY1,
	CCS_IMM_IPV4ADDR_ENTRY2,
	CCS_IMM_IPV6ADDR_ENTRY1,
	CCS_IMM_IPV6ADDR_ENTRY2,
	CCS_ARGV_ENTRY,
	CCS_ENVP_ENTRY,
	CCS_PATH_ATTRIBUTE_START = 192,
	CCS_PATH_ATTRIBUTE_END = 255
} __packed;

enum ccs_path_attribute_index {
	CCS_PATH_ATTRIBUTE_UID,
	CCS_PATH_ATTRIBUTE_GID,
	CCS_PATH_ATTRIBUTE_INO,
	CCS_PATH_ATTRIBUTE_TYPE,
	CCS_PATH_ATTRIBUTE_MAJOR,
	CCS_PATH_ATTRIBUTE_MINOR,
	CCS_PATH_ATTRIBUTE_PERM,
	CCS_PATH_ATTRIBUTE_DEV_MAJOR,
	CCS_PATH_ATTRIBUTE_DEV_MINOR,
	CCS_PATH_ATTRIBUTE_FSMAGIC,
	CCS_MAX_PATH_ATTRIBUTE
};

/* Index numbers for group entries. */
enum ccs_group_id {
	CCS_PATH_GROUP,
	CCS_DOMAIN_GROUP,
	CCS_NUMBER_GROUP,
#ifdef CONFIG_CCSECURITY_NETWORK
	CCS_ADDRESS_GROUP,
#endif
	CCS_MAX_GROUP
} __packed;

/* Index numbers for category of functionality. */
enum ccs_mac_category_index {
	CCS_MAC_CATEGORY_FILE,
#ifdef CONFIG_CCSECURITY_NETWORK
	CCS_MAC_CATEGORY_NETWORK,
#endif
#ifdef CONFIG_CCSECURITY_MISC
	CCS_MAC_CATEGORY_MISC,
#endif
#ifdef CONFIG_CCSECURITY_IPC
	CCS_MAC_CATEGORY_IPC,
#endif
	CCS_MAC_CATEGORY_CAPABILITY,
#if defined(CONFIG_CCSECURITY_TASK_EXECUTE_HANDLER) || defined(CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION)
	CCS_MAC_CATEGORY_TASK,
#endif
	CCS_MAC_CATEGORY_NONE,
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
#ifdef CONFIG_CCSECURITY_FILE_GETATTR
	CCS_MAC_FILE_GETATTR,
#endif
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
#ifdef CONFIG_CCSECURITY_NETWORK
	CCS_MAC_NETWORK_INET_STREAM_BIND,
	CCS_MAC_NETWORK_INET_STREAM_LISTEN,
	CCS_MAC_NETWORK_INET_STREAM_CONNECT,
	CCS_MAC_NETWORK_INET_STREAM_ACCEPT,
	CCS_MAC_NETWORK_INET_DGRAM_BIND,
	CCS_MAC_NETWORK_INET_DGRAM_SEND,
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	CCS_MAC_NETWORK_INET_DGRAM_RECV,
#endif
	CCS_MAC_NETWORK_INET_RAW_BIND,
	CCS_MAC_NETWORK_INET_RAW_SEND,
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	CCS_MAC_NETWORK_INET_RAW_RECV,
#endif
	CCS_MAC_NETWORK_UNIX_STREAM_BIND,
	CCS_MAC_NETWORK_UNIX_STREAM_LISTEN,
	CCS_MAC_NETWORK_UNIX_STREAM_CONNECT,
	CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT,
	CCS_MAC_NETWORK_UNIX_DGRAM_BIND,
	CCS_MAC_NETWORK_UNIX_DGRAM_SEND,
#ifdef CONFIG_CCSECURITY_NETWORK_RECVMSG
	CCS_MAC_NETWORK_UNIX_DGRAM_RECV,
#endif
	CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT,
	CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT,
#endif
#ifdef CONFIG_CCSECURITY_MISC
	CCS_MAC_ENVIRON,
#endif
#ifdef CONFIG_CCSECURITY_IPC
	CCS_MAC_PTRACE,
#endif
	CCS_MAC_CAPABILITY_MODIFY_POLICY,
#ifdef CONFIG_CCSECURITY_CAPABILITY
	CCS_MAC_CAPABILITY_USE_ROUTE_SOCKET,
	CCS_MAC_CAPABILITY_USE_PACKET_SOCKET,
	CCS_MAC_CAPABILITY_SYS_REBOOT,
	CCS_MAC_CAPABILITY_SYS_VHANGUP,
	CCS_MAC_CAPABILITY_SYS_SETTIME,
	CCS_MAC_CAPABILITY_SYS_NICE,
	CCS_MAC_CAPABILITY_SYS_SETHOSTNAME,
	CCS_MAC_CAPABILITY_USE_KERNEL_MODULE,
	CCS_MAC_CAPABILITY_SYS_KEXEC_LOAD,
#endif
#ifdef CONFIG_CCSECURITY_TASK_EXECUTE_HANDLER
	CCS_MAC_AUTO_EXECUTE_HANDLER,
	CCS_MAC_DENIED_EXECUTE_HANDLER,
#endif
#ifdef CONFIG_CCSECURITY_TASK_DOMAIN_TRANSITION
	CCS_MAC_AUTO_TASK_TRANSITION,
	CCS_MAC_MANUAL_TASK_TRANSITION,
#endif
	CCS_MAX_MAC_INDEX
};

/* Index numbers for statistic information. */
enum ccs_memory_stat_type {
	CCS_MEMORY_POLICY,
	CCS_MEMORY_AUDIT,
	CCS_MEMORY_QUERY,
	CCS_MAX_MEMORY_STAT
};

enum ccs_matching_result {
	CCS_MATCHING_UNMATCHED,
	CCS_MATCHING_ALLOWED,
	CCS_MATCHING_DENIED,
	CCS_MAX_MATCHING
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
#ifdef CONFIG_CCSECURITY_NETWORK
	CCS_ID_ADDRESS_GROUP,
#endif
	CCS_ID_PATH_GROUP,
	CCS_ID_NUMBER_GROUP,
	CCS_ID_CONDITION,
	CCS_ID_NAME,
	CCS_ID_ACL,
	CCS_ID_DOMAIN,
	CCS_MAX_POLICY
};

/* Index numbers for statistic information. */
enum ccs_policy_stat_type {
	CCS_STAT_POLICY_UPDATES,
	CCS_STAT_REQUEST_DENIED,
	CCS_MAX_POLICY_STAT
};

/* Index numbers for /proc/ccs/ interfaces. */
enum ccs_proc_interface_index {
	CCS_POLICY,
	CCS_PROCESS_STATUS,
	CCS_AUDIT,
	CCS_VERSION,
	CCS_QUERY,
#ifdef CONFIG_CCSECURITY_TASK_EXECUTE_HANDLER
	CCS_EXECUTE_HANDLER,
#endif
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
} __packed;

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

/* Garbage collector is trying to kfree() this element. */
#define CCS_GC_IN_PROGRESS -1

/* Current thread is doing open(O_RDONLY | O_TRUNC) ? */
#define CCS_OPEN_FOR_READ_TRUNCATE        1
/* Current thread is doing open(3) ? */
#define CCS_OPEN_FOR_IOCTL_ONLY           2
/* Current thread is doing do_execve() ? */
#define CCS_TASK_IS_IN_EXECVE             4
/* Current thread is running as an execute handler program? */
#define CCS_TASK_IS_EXECUTE_HANDLER       8
/* Current thread is allowed to modify policy via /proc/ccs/ interface? */
#define CCS_TASK_IS_MANAGER              16

/*
 * Retry this request. Returned by ccs_supervisor() if policy violation has
 * occurred in enforcing mode and the userspace daemon decided to retry.
 *
 * We must choose a positive value in order to distinguish "granted" (which is
 * 0) and "rejected" (which is a negative value) and "retry".
 */
#define CCS_RETRY_REQUEST 1

/* Ignore gfp flags which are not supported. */
#ifndef __GFP_HIGHIO
#define __GFP_HIGHIO 0
#endif
#ifndef __GFP_NOWARN
#define __GFP_NOWARN 0
#endif
#ifndef __GFP_NORETRY
#define __GFP_NORETRY 0
#endif
#ifndef __GFP_NOMEMALLOC
#define __GFP_NOMEMALLOC 0
#endif

/* The gfp flags used by TOMOYO. */
#define CCS_GFP_FLAGS (__GFP_WAIT | __GFP_IO | __GFP_HIGHIO | __GFP_NOWARN | \
		       __GFP_NORETRY | __GFP_NOMEMALLOC)

/* Size of read buffer for /proc/ccs/ interface. */
#define CCS_MAX_IO_READ_QUEUE 64

/* Structure definition for internal use. */

/* Common header for holding ACL entries. */
struct ccs_acl_head {
	struct list_head list;
	s8 is_deleted; /* true or false or CCS_GC_IN_PROGRESS */
} __packed;

/* Common header for shared entries. */
struct ccs_shared_acl_head {
	struct list_head list;
	atomic_t users;
} __packed;

/* Common header for individual entries. */
struct ccs_acl_info {
	struct list_head list;
	struct list_head acl_info_list;
	struct ccs_condition *cond; /* Maybe NULL. */
	s8 is_deleted; /* true or false or CCS_GC_IN_PROGRESS */
	bool is_deny;
	u16 priority;
	u16 max_log[CCS_MAX_MATCHING];
};

/*
 * Structure for "path_group"/"domain_group"/"number_group"/"address_group"
 * directive.
 */
struct ccs_group {
	struct ccs_shared_acl_head head;
	/* Name of group (without leading "@"). */
	const struct ccs_path_info *group_name;
	/*
	 * List of "struct ccs_path_group" or "struct ccs_number_group" or
	 * "struct ccs_address_group".
	 */
	struct list_head member_list;
};

/* Structure for "path_group"/"domain_group" directive. */
struct ccs_path_group {
	struct ccs_acl_head head;
	const struct ccs_path_info *member_name;
};

/* Structure for "number_group" directive. */
struct ccs_number_group {
	struct ccs_acl_head head;
	u8 radix;
	unsigned long value[2];
};

/* Structure for "address_group" directive. */
struct ccs_address_group {
	struct ccs_acl_head head;
	bool is_ipv6;
	/* Structure for holding an IP address. */
	struct in6_addr ip[2]; /* Big endian. */
};

/* Subset of "struct stat". Used by conditional ACL and audit logs. */
struct ccs_mini_stat {
	uid_t uid;
	gid_t gid;
	ino_t ino;
	umode_t mode;
	dev_t dev;
	dev_t rdev;
	unsigned long fsmagic;
};

/* Structure for dumping argv[] and envp[] of "struct linux_binprm". */
struct ccs_page_dump {
	struct page *page;    /* Previously dumped page. */
	char *data;           /* Contents of "page". Size is PAGE_SIZE. */
};

/* Structure for entries which follows "struct ccs_condition". */
union ccs_condition_element {
	struct {
		enum ccs_conditions_index left;
		enum ccs_conditions_index right;
		bool is_not;
		u8 radix;
	};
	struct ccs_group *group;
	const struct ccs_path_info *path;
	u32 ip; /* Repeat 4 times if IPv6 address. */
	unsigned long value;
};

/* Structure for optional arguments. */
struct ccs_condition {
	struct ccs_shared_acl_head head;
	u32 size; /* Memory size allocated for this entry. */
	/* union ccs_condition_element condition[]; */
};

/* Structure for holding a token. */
struct ccs_path_info {
	const char *name;
	u32 hash;          /* = full_name_hash(name, strlen(name)) */
	u16 total_len;     /* = strlen(name)                       */
	u16 const_len;     /* = ccs_const_part_length(name)        */
	bool is_dir;       /* = ccs_strendswith(name, "/")         */
	bool is_patterned; /* = const_len < total_len              */
};

/* Structure for request info. */
struct ccs_request_info {
	/* For holding parameters. */
	struct ccs_request_param {
		const struct ccs_path_info *s[3];
		unsigned long i[3];
#ifdef CONFIG_CCSECURITY_NETWORK
		const u8 *ip; /* Big endian. */
		bool is_ipv6;
#endif
	} param;
	/* For holding pathnames and attributes. */
	struct {
		/*
		 * True if ccs_get_attributes() was already called, false
		 * otherwise.
		 */
		bool validate_done;
		/* True if @stat[] is valid. */
		bool stat_valid[CCS_MAX_PATH_STAT];
		struct path path[2];
		/*
		 * Information on @path[0], @path[0]'s parent directory,
		 * @path[1] and @path[1]'s parent directory.
		 */
		struct ccs_mini_stat stat[CCS_MAX_PATH_STAT];
		/*
		 * Name of @path[0] and @path[1].
		 * Cleared by ccs_crear_request_info().
		 */
		struct ccs_path_info pathname[2];
	} obj;
	struct {
		struct linux_binprm *bprm;
		struct ccs_domain_info *previous_domain;
		/* For execute_handler. */
		char *handler; /* kstrdup(handler_path->name, CCS_GFP_FLAGS) */
		/* For dumping argv[] and envp[]. */
		struct ccs_page_dump dump;
		/* For temporary use. Size is CCS_EXEC_TMPSIZE bytes. */
		char *tmp;
	};
	/*
	 * Name of current thread's executable.
	 * Cleared by ccs_crear_request_info().
	 */
	struct ccs_path_info exename;
	/*
	 * Matching "struct ccs_acl_info" is copied. Used for ccs-queryd.
	 * Valid until ccs_read_unlock().
	 */
	struct ccs_acl_info *matched_acl;
	/*
	 * Matching handler and domain transition are copied.
	 * Valid until ccs_read_unlock().
	 */
	const struct ccs_path_info *handler_path;
	const struct ccs_path_info *transition;
	/*
	 * For holding operation index used for this request.
	 * One of values in "enum ccs_mac_index".
	 */
	enum ccs_mac_index type;
	/* For holding matching result. */
	enum ccs_matching_result result;
	/*
	 * For counting number of retries made for this request.
	 * This counter is incremented whenever ccs_supervisor() returned
	 * CCS_RETRY_REQUEST.
	 */
	u8 retry;
	/* For holding max audit log count for this matching entry. */
	u16 max_log;
};

/* Structure for domain information. */
struct ccs_domain_info {
	struct list_head list;
	/* Name of this domain. Never NULL.          */
	const struct ccs_path_info *domainname;
	s8 is_deleted;     /* Delete flag.           */
};

/* Structure for holding string data. */
struct ccs_name {
	struct ccs_shared_acl_head head;
	int size; /* Memory size allocated for this entry. */
	struct ccs_path_info entry;
};

/* Structure for reading/writing policy via /proc/ccs/ interfaces. */
struct ccs_io_buffer {
	/* Exclusive lock for this structure.   */
	struct mutex io_sem;
	char __user *read_user_buf;
	size_t read_user_buf_avail;
	struct {
		struct list_head *group;
		struct list_head *acl;
		struct list_head *subacl;
		const union ccs_condition_element *cond;
		size_t avail;
		unsigned int step;
		unsigned int query_index;
		u16 index;
		u8 cond_step;
		u8 w_pos;
		enum ccs_mac_index acl_index;
		bool eof;
		bool print_this_acl_only;
		bool version_done;
		bool stat_done;
		bool group_done;
		const char *w[CCS_MAX_IO_READ_QUEUE];
	} r;
	struct {
		char *data;
		struct ccs_acl_info *acl;
		size_t avail;
		enum ccs_mac_index acl_index;
		bool is_delete;
		bool is_deny;
		u16 priority;
	} w;
	/* Buffer for reading.                  */
	char *read_buf;
	/* Size of read buffer.                 */
	size_t readbuf_size;
	/* Buffer for writing.                  */
	char *write_buf;
	/* Size of write buffer.                */
	size_t writebuf_size;
	/* Type of interface. */
	enum ccs_proc_interface_index type;
	/* Users counter protected by ccs_io_buffer_list_lock. */
	u8 users;
	/* List for telling GC not to kfree() elements. */
	struct list_head list;
};

/* Structure for representing YYYY/MM/DD hh/mm/ss. */
struct ccs_time {
	u16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 min;
	u8 sec;
};

/* Prototype definition for "struct ccsecurity_operations". */

void __init ccs_permission_init(void);
void __init ccs_mm_init(void);

/* Prototype definition for internal use. */

bool ccs_dump_page(struct linux_binprm *bprm, unsigned long pos,
		   struct ccs_page_dump *dump);
bool ccs_get_exename(struct ccs_path_info *buf);
bool ccs_manager(void);
bool ccs_memory_ok(const void *ptr, const unsigned int size);
char *ccs_encode(const char *str);
char *ccs_encode2(const char *str, int str_len);
char *ccs_realpath(struct path *path);
const char *ccs_get_exe(void);
const struct ccs_path_info *ccs_get_name(const char *name);
int ccs_audit_log(struct ccs_request_info *r);
int ccs_check_acl(struct ccs_request_info *r, const bool clear);
struct ccs_domain_info *ccs_assign_domain(const char *domainname);
void *ccs_commit_ok(void *data, const unsigned int size);
void ccs_del_condition(struct list_head *element);
void ccs_fill_path_info(struct ccs_path_info *ptr);
void ccs_get_attributes(struct ccs_request_info *r);
void ccs_notify_gc(struct ccs_io_buffer *head, const bool is_register);
void ccs_populate_patharg(struct ccs_request_info *r, const bool first);
void ccs_transition_failed(const char *domainname);
void ccs_warn_oom(const char *function);

/* Variable definition for internal use. */

extern bool ccs_policy_loaded;
extern struct ccs_domain_info ccs_kernel_domain;
extern struct ccs_path_info ccs_null_name;
extern struct list_head ccs_acl_list[CCS_MAX_MAC_INDEX];
extern struct list_head ccs_condition_list;
extern struct list_head ccs_domain_list;
extern struct list_head ccs_group_list[CCS_MAX_GROUP];
extern struct list_head ccs_name_list[CCS_MAX_HASH];
extern struct mutex ccs_policy_lock;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
extern struct srcu_struct ccs_ss;
#endif
extern unsigned int ccs_memory_quota[CCS_MAX_MEMORY_STAT];
extern unsigned int ccs_memory_used[CCS_MAX_MEMORY_STAT];

/* Inlined functions for internal use. */

/**
 * ccs_pathcmp - strcmp() for "struct ccs_path_info" structure.
 *
 * @a: Pointer to "struct ccs_path_info".
 * @b: Pointer to "struct ccs_path_info".
 *
 * Returns true if @a != @b, false otherwise.
 */
static inline bool ccs_pathcmp(const struct ccs_path_info *a,
			       const struct ccs_path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)

/**
 * ccs_read_lock - Take lock for protecting policy.
 *
 * Returns index number for ccs_read_unlock().
 */
static inline int ccs_read_lock(void)
{
	return srcu_read_lock(&ccs_ss);
}

/**
 * ccs_read_unlock - Release lock for protecting policy.
 *
 * @idx: Index number returned by ccs_read_lock().
 *
 * Returns nothing.
 */
static inline void ccs_read_unlock(const int idx)
{
	srcu_read_unlock(&ccs_ss, idx);
}

#else

int ccs_lock(void);
void ccs_unlock(const int idx);

/**
 * ccs_read_lock - Take lock for protecting policy.
 *
 * Returns index number for ccs_read_unlock().
 */
static inline int ccs_read_lock(void)
{
	return ccs_lock();
}

/**
 * ccs_read_unlock - Release lock for protecting policy.
 *
 * @idx: Index number returned by ccs_read_lock().
 *
 * Returns nothing.
 */
static inline void ccs_read_unlock(const int idx)
{
	ccs_unlock(idx);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)

/**
 * ccs_tasklist_lock - Take lock for reading list of "struct task_struct".
 *
 * Returns nothing.
 */
static inline void ccs_tasklist_lock(void)
{
	rcu_read_lock();
}

/**
 * ccs_tasklist_unlock - Release lock for reading list of "struct task_struct".
 *
 * Returns nothing.
 */
static inline void ccs_tasklist_unlock(void)
{
	rcu_read_unlock();
}

#else

/**
 * ccs_tasklist_lock - Take lock for reading list of "struct task_struct".
 *
 * Returns nothing.
 */
static inline void ccs_tasklist_lock(void)
{
	read_lock(&tasklist_lock);
}

/**
 * ccs_tasklist_unlock - Release lock for reading list of "struct task_struct".
 *
 * Returns nothing.
 */
static inline void ccs_tasklist_unlock(void)
{
	read_unlock(&tasklist_lock);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/**
 * ccs_sys_getppid - Copy of getppid().
 *
 * Returns parent process's PID.
 *
 * Alpha does not have getppid() defined. To be able to build this module on
 * Alpha, I have to copy getppid() from kernel/timer.c.
 */
static inline pid_t ccs_sys_getppid(void)
{
	pid_t pid;
	rcu_read_lock();
	pid = task_tgid_vnr(rcu_dereference(current->real_parent));
	rcu_read_unlock();
	return pid;
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)

/**
 * ccs_sys_getppid - Copy of getppid().
 *
 * Returns parent process's PID.
 *
 * This function was rewritten to use RCU in 2.6.16.34. However, distributors
 * which use earlier kernels (e.g. 2.6.8/2.6.9) did not backport the bugfix.
 * Therefore, I'm using code for 2.6.16.34 for earlier kernels.
 */
static inline pid_t ccs_sys_getppid(void)
{
	pid_t pid;
	rcu_read_lock();
#if (defined(RHEL_MAJOR) && RHEL_MAJOR == 5) || (defined(AX_MAJOR) && AX_MAJOR == 3)
	pid = rcu_dereference(current->parent)->tgid;
#else
	pid = rcu_dereference(current->real_parent)->tgid;
#endif
	rcu_read_unlock();
	return pid;
}

#else

/**
 * ccs_sys_getppid - Copy of getppid().
 *
 * Returns parent process's PID.
 *
 * I can't use code for 2.6.16.34 for 2.4 kernels because 2.4 kernels does not
 * have RCU. Therefore, I'm using pessimistic lock (i.e. tasklist_lock
 * spinlock).
 */
static inline pid_t ccs_sys_getppid(void)
{
	pid_t pid;
	read_lock(&tasklist_lock);
#ifdef TASK_DEAD
	pid = current->group_leader->real_parent->tgid;
#else
	pid = current->p_opptr->pid;
#endif
	read_unlock(&tasklist_lock);
	return pid;
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/**
 * ccs_sys_getpid - Copy of getpid().
 *
 * Returns current thread's PID.
 *
 * Alpha does not have getpid() defined. To be able to build this module on
 * Alpha, I have to copy getpid() from kernel/timer.c.
 */
static inline pid_t ccs_sys_getpid(void)
{
	return task_tgid_vnr(current);
}

#else

/**
 * ccs_sys_getpid - Copy of getpid().
 *
 * Returns current thread's PID.
 */
static inline pid_t ccs_sys_getpid(void)
{
	return current->tgid;
}

#endif

#if defined(CONFIG_SLOB)

/**
 * ccs_round2 - Round up to power of 2 for calculating memory usage.
 *
 * @size: Size to be rounded up.
 *
 * Returns @size.
 *
 * Since SLOB does not round up, this function simply returns @size.
 */
static inline int ccs_round2(size_t size)
{
	return size;
}

#else

/**
 * ccs_round2 - Round up to power of 2 for calculating memory usage.
 *
 * @size: Size to be rounded up.
 *
 * Returns rounded size.
 *
 * Strictly speaking, SLAB may be able to allocate (e.g.) 96 bytes instead of
 * (e.g.) 128 bytes.
 */
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

/**
 * ccs_put_condition - Drop reference on "struct ccs_condition".
 *
 * @cond: Pointer to "struct ccs_condition". Maybe NULL.
 *
 * Returns nothing.
 */
static inline void ccs_put_condition(struct ccs_condition *cond)
{
	if (cond)
		atomic_dec(&cond->head.users);
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
	if (group)
		atomic_dec(&group->head.users);
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
	if (name)
		atomic_dec(&container_of(name, struct ccs_name, entry)->
			   head.users);
}

/* For importing variables and functions. */
extern const struct ccsecurity_exports ccsecurity_exports;

#ifdef CONFIG_CCSECURITY_USE_EXTERNAL_TASK_SECURITY

/*
 * Structure for holding "struct ccs_domain_info *" and "u32 ccs_flags" for
 * each "struct task_struct".
 *
 * "struct ccs_domain_info *" and "u32 ccs_flags" for each "struct task_struct"
 * are maintained outside that "struct task_struct". Therefore, ccs_security
 * != task_struct . This keeps KABI for distributor's prebuilt kernels but
 * entails slow access.
 *
 * Memory for this structure is allocated when current thread tries to access
 * it. Therefore, if memory allocation failed, current thread will be killed by
 * SIGKILL. Note that if current->pid == 1, sending SIGKILL won't work.
 */
struct ccs_security {
	struct list_head list;
	const struct task_struct *task;
	struct ccs_domain_info *ccs_domain_info;
	u32 ccs_flags;
	struct rcu_head rcu;
};

#define CCS_TASK_SECURITY_HASH_BITS 12
#define CCS_MAX_TASK_SECURITY_HASH (1u << CCS_TASK_SECURITY_HASH_BITS)
extern struct list_head ccs_task_security_list[CCS_MAX_TASK_SECURITY_HASH];

struct ccs_security *ccs_find_task_security(const struct task_struct *task);

/**
 * ccs_current_security - Get "struct ccs_security" for current thread.
 *
 * Returns pointer to "struct ccs_security" for current thread.
 */
static inline struct ccs_security *ccs_current_security(void)
{
	return ccs_find_task_security(current);
}

/**
 * ccs_task_domain - Get "struct ccs_domain_info" for specified thread.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct ccs_security" for specified thread.
 */
static inline struct ccs_domain_info *ccs_task_domain(struct task_struct *task)
{
	struct ccs_domain_info *domain;
	rcu_read_lock();
	domain = ccs_find_task_security(task)->ccs_domain_info;
	rcu_read_unlock();
	return domain;
}

/**
 * ccs_current_domain - Get "struct ccs_domain_info" for current thread.
 *
 * Returns pointer to "struct ccs_domain_info" for current thread.
 */
static inline struct ccs_domain_info *ccs_current_domain(void)
{
	return ccs_find_task_security(current)->ccs_domain_info;
}

/**
 * ccs_task_flags - Get flags for specified thread.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns flags for specified thread.
 */
static inline u32 ccs_task_flags(struct task_struct *task)
{
	u32 ccs_flags;
	rcu_read_lock();
	ccs_flags = ccs_find_task_security(task)->ccs_flags;
	rcu_read_unlock();
	return ccs_flags;
}

/**
 * ccs_current_flags - Get flags for current thread.
 *
 * Returns flags for current thread.
 */
static inline u32 ccs_current_flags(void)
{
	return ccs_find_task_security(current)->ccs_flags;
}

#else

/*
 * "struct ccs_domain_info *" and "u32 ccs_flags" for each "struct task_struct"
 * are maintained inside that "struct task_struct". Therefore, ccs_security ==
 * task_struct . This allows fast access but breaks KABI checks for
 * distributor's prebuilt kernels due to changes in "struct task_struct".
 */
#define ccs_security task_struct

/**
 * ccs_find_task_security - Find "struct ccs_security" for given task.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct ccs_security".
 */
static inline struct ccs_security *ccs_find_task_security(struct task_struct *
							  task)
{
	return task;
}

/**
 * ccs_current_security - Get "struct ccs_security" for current thread.
 *
 * Returns pointer to "struct ccs_security" for current thread.
 */
static inline struct ccs_security *ccs_current_security(void)
{
	return ccs_find_task_security(current);
}

/**
 * ccs_task_domain - Get "struct ccs_domain_info" for specified thread.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct ccs_security" for specified thread.
 */
static inline struct ccs_domain_info *ccs_task_domain(struct task_struct *task)
{
	struct ccs_domain_info *domain = task->ccs_domain_info;
	return domain ? domain : &ccs_kernel_domain;
}

/**
 * ccs_current_domain - Get "struct ccs_domain_info" for current thread.
 *
 * Returns pointer to "struct ccs_domain_info" for current thread.
 *
 * If current thread does not belong to a domain (which is true for initial
 * init_task in order to hide ccs_kernel_domain from this module),
 * current thread enters into ccs_kernel_domain.
 */
static inline struct ccs_domain_info *ccs_current_domain(void)
{
	struct task_struct *task = current;
	if (!task->ccs_domain_info)
		task->ccs_domain_info = &ccs_kernel_domain;
	return task->ccs_domain_info;
}

/**
 * ccs_task_flags - Get flags for specified thread.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns flags for specified thread.
 */
static inline u32 ccs_task_flags(struct task_struct *task)
{
	return ccs_find_task_security(task)->ccs_flags;
}

/**
 * ccs_current_flags - Get flags for current thread.
 *
 * Returns flags for current thread.
 */
static inline u32 ccs_current_flags(void)
{
	return ccs_find_task_security(current)->ccs_flags;
}

#endif

#endif
