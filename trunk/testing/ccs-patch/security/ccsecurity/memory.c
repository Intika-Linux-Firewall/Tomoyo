/*
 * security/ccsecurity/memory.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.8.3+   2011/11/11
 */

#include "internal.h"

#ifdef CONFIG_CCSECURITY_USE_EXTERNAL_TASK_SECURITY

/***** SECTION1: Constants definition *****/

/***** SECTION2: Structure definition *****/

/***** SECTION3: Prototype definition section *****/

struct ccs_security *ccs_find_task_security(const struct task_struct *task);
void __init ccs_mm_init(void);

static int __ccs_alloc_task_security(const struct task_struct *task);
static void __ccs_free_task_security(const struct task_struct *task);
static void ccs_add_task_security(struct ccs_security *ptr,
				  struct list_head *list);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
static void ccs_rcu_free(struct rcu_head *rcu);
#else
static void ccs_rcu_free(void *arg);
#endif

/***** SECTION4: Standalone functions section *****/

/***** SECTION5: Variables definition section *****/

/* Dummy security context for avoiding NULL pointer dereference. */
static struct ccs_security ccs_oom_security = {
	.ccs_domain_info = &ccs_kernel_domain
};

/* Dummy security context for avoiding NULL pointer dereference. */
static struct ccs_security ccs_default_security = {
	.ccs_domain_info = &ccs_kernel_domain
};

/* List of "struct ccs_security". */
struct list_head ccs_task_security_list[CCS_MAX_TASK_SECURITY_HASH];
/* Lock for protecting ccs_task_security_list[]. */
static DEFINE_SPINLOCK(ccs_task_security_list_lock);

/***** SECTION6: Dependent functions section *****/

/**
 * ccs_add_task_security - Add "struct ccs_security" to list.
 *
 * @ptr:  Pointer to "struct ccs_security".
 * @list: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static void ccs_add_task_security(struct ccs_security *ptr,
				  struct list_head *list)
{
	unsigned long flags;
	spin_lock_irqsave(&ccs_task_security_list_lock, flags);
	list_add_rcu(&ptr->list, list);
	spin_unlock_irqrestore(&ccs_task_security_list_lock, flags);
}

/**
 * __ccs_alloc_task_security - Allocate memory for new tasks.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __ccs_alloc_task_security(const struct task_struct *task)
{
	struct ccs_security *old_security = ccs_current_security();
	struct ccs_security *new_security = kzalloc(sizeof(*new_security),
						    GFP_KERNEL);
	struct list_head *list = &ccs_task_security_list
		[hash_ptr((void *) task, CCS_TASK_SECURITY_HASH_BITS)];
	if (!new_security)
		return -ENOMEM;
	*new_security = *old_security;
	new_security->task = task;
	ccs_add_task_security(new_security, list);
	return 0;
}

/**
 * ccs_find_task_security - Find "struct ccs_security" for given task.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct ccs_security" on success, &ccs_oom_security on
 * out of memory, &ccs_default_security otherwise.
 *
 * If @task is current thread and "struct ccs_security" for current thread was
 * not found, I try to allocate it. But if allocation failed, current thread
 * will be killed by SIGKILL. Note that if current->pid == 1, sending SIGKILL
 * won't work.
 */
struct ccs_security *ccs_find_task_security(const struct task_struct *task)
{
	struct ccs_security *ptr;
	struct list_head *list = &ccs_task_security_list
		[hash_ptr((void *) task, CCS_TASK_SECURITY_HASH_BITS)];
	/* Make sure INIT_LIST_HEAD() in ccs_mm_init() takes effect. */
	while (!list->next);
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, list, list) {
		if (ptr->task != task)
			continue;
		rcu_read_unlock();
		return ptr;
	}
	rcu_read_unlock();
	if (task != current)
		return &ccs_default_security;
	/* Use GFP_ATOMIC because caller may have called rcu_read_lock(). */
	ptr = kzalloc(sizeof(*ptr), GFP_ATOMIC);
	if (!ptr) {
		printk(KERN_WARNING "Unable to allocate memory for pid=%u\n",
		       task->pid);
		send_sig(SIGKILL, current, 0);
		return &ccs_oom_security;
	}
	*ptr = ccs_default_security;
	ptr->task = task;
	ccs_add_task_security(ptr, list);
	return ptr;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)

/**
 * ccs_rcu_free - RCU callback for releasing "struct ccs_security".
 *
 * @rcu: Pointer to "struct rcu_head".
 *
 * Returns nothing.
 */
static void ccs_rcu_free(struct rcu_head *rcu)
{
	struct ccs_security *ptr = container_of(rcu, typeof(*ptr), rcu);
	kfree(ptr);
}

#else

/**
 * ccs_rcu_free - RCU callback for releasing "struct ccs_security".
 *
 * @arg: Pointer to "void".
 *
 * Returns nothing.
 */
static void ccs_rcu_free(void *arg)
{
	struct ccs_security *ptr = arg;
	kfree(ptr);
}

#endif

/**
 * __ccs_free_task_security - Release memory associated with "struct task_struct".
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void __ccs_free_task_security(const struct task_struct *task)
{
	unsigned long flags;
	struct ccs_security *ptr = ccs_find_task_security(task);
	if (ptr == &ccs_default_security || ptr == &ccs_oom_security)
		return;
	spin_lock_irqsave(&ccs_task_security_list_lock, flags);
	list_del_rcu(&ptr->list);
	spin_unlock_irqrestore(&ccs_task_security_list_lock, flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
	call_rcu(&ptr->rcu, ccs_rcu_free);
#else
	call_rcu(&ptr->rcu, ccs_rcu_free, ptr);
#endif
}

/**
 * ccs_mm_init - Initialize mm related code.
 *
 * Returns nothing.
 */
void __init ccs_mm_init(void)
{
	int idx;
	for (idx = 0; idx < CCS_MAX_TASK_SECURITY_HASH; idx++)
		INIT_LIST_HEAD(&ccs_task_security_list[idx]);
	smp_wmb(); /* Avoid out of order execution. */
	ccsecurity_ops.alloc_task_security = __ccs_alloc_task_security;
	ccsecurity_ops.free_task_security = __ccs_free_task_security;
}

#endif
