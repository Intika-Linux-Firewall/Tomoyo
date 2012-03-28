/*
 * include/linux/ccs_compat.h
 *
 * For compatibility for older kernels.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#define false 0
#define true 1

#ifndef __user
#define __user
#endif

#ifndef current_uid
#define current_uid()           (current->uid)
#endif
#ifndef current_gid
#define current_gid()           (current->gid)
#endif
#ifndef current_euid
#define current_euid()          (current->euid)
#endif
#ifndef current_egid
#define current_egid()          (current->egid)
#endif
#ifndef current_suid
#define current_suid()          (current->suid)
#endif
#ifndef current_sgid
#define current_sgid()          (current->sgid)
#endif
#ifndef current_fsuid
#define current_fsuid()         (current->fsuid)
#endif
#ifndef current_fsgid
#define current_fsgid()         (current->fsgid)
#endif

#ifndef WARN_ON
#define WARN_ON(x) do { } while (0)
#endif

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#define bool _Bool
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
#define smp_read_barrier_depends smp_rmb
#endif

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#ifndef rcu_dereference
#define rcu_dereference(p)     ({ \
				typeof(p) _________p1 = ACCESS_ONCE(p); \
				smp_read_barrier_depends(); /* see RCU */ \
				(_________p1); \
				})
#endif

#ifndef rcu_assign_pointer
#define rcu_assign_pointer(p, v) \
	({ \
		if (!__builtin_constant_p(v) || \
		    ((v) != NULL)) \
			smp_wmb(); /* see RCU */ \
		(p) = (v); \
	})
#endif

#ifndef list_for_each_rcu
#define list_for_each_rcu(pos, head) \
	for (pos = rcu_dereference((head)->next); \
		prefetch(pos->next), pos != (head); \
		pos = rcu_dereference(pos->next))
#endif

#ifndef list_for_each_entry_rcu
#define list_for_each_entry_rcu(pos, head, member) \
	for (pos = list_entry(rcu_dereference((head)->next), typeof(*pos), \
		member); \
		prefetch(pos->member.next), &pos->member != (head); \
		pos = list_entry(rcu_dereference(pos->member.next), \
		typeof(*pos), member))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define s_fs_info u.generic_sbp
#else
#include <linux/audit.h>
#ifdef AUDIT_APPARMOR_AUDIT
/* AppArmor patch adds "struct vfsmount" to VFS helper functions. */
#define HAVE_VFSMOUNT_IN_VFS_HELPER
#endif
#endif

#if defined(RHEL_MAJOR) && RHEL_MAJOR == 5
#define HAVE_NO_I_BLKSIZE_IN_INODE
#elif defined(AX_MAJOR) && AX_MAJOR == 3
#define HAVE_NO_I_BLKSIZE_IN_INODE
#endif

#ifndef list_for_each_entry_safe
#define list_for_each_entry_safe(pos, n, head, member)                  \
	for (pos = list_entry((head)->next, typeof(*pos), member),      \
		     n = list_entry(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define sk_family family
#define sk_protocol protocol
#define sk_type type
#define sk_receive_queue receive_queue
static inline struct socket *SOCKET_I(struct inode *inode)
{
	return inode->i_sock ? &inode->u.socket_i : NULL;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD NIPQUAD
#else
#error "Please fix asm/byteorder.h"
#endif /* __LITTLE_ENDIAN */
#endif
