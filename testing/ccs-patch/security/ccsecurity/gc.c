/*
 * security/ccsecurity/gc.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.8.3+   2012/03/15
 */

#include "internal.h"

/***** SECTION1: Constants definition *****/

/* For compatibility with older kernels. */
#ifndef for_each_process
#define for_each_process for_each_task
#endif

/* The list for "struct ccs_io_buffer". */
static LIST_HEAD(ccs_io_buffer_list);
/* Lock for protecting ccs_io_buffer_list. */
static DEFINE_SPINLOCK(ccs_io_buffer_list_lock);

/***** SECTION2: Structure definition *****/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)

/*
 * Lock for syscall users.
 *
 * This lock is used for protecting single SRCU section for 2.6.18 and
 * earlier kernels because they don't have SRCU support.
 */
struct ccs_lock_struct {
	int counter_idx; /* Currently active index (0 or 1). */
	int counter[2];  /* Current users. Protected by ccs_counter_lock. */
};

#endif

/***** SECTION3: Prototype definition section *****/

static bool ccs_domain_used_by_task(struct ccs_domain_info *domain);
static bool ccs_name_used_by_io_buffer(const char *string, const size_t size);
static bool ccs_struct_used_by_io_buffer(const struct list_head *element);
static int ccs_gc_thread(void *unused);
static void ccs_collect_acl(struct list_head *list);
static void ccs_collect_entry(void);
static void ccs_collect_member(const enum ccs_policy_id id,
			       struct list_head *member_list);
static void ccs_memory_free(const void *ptr, const enum ccs_policy_id type);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static void ccs_synchronize_counter(void);
#endif
static void ccs_try_to_gc(const enum ccs_policy_id type,
			  struct list_head *element);

/***** SECTION4: Standalone functions section *****/

/***** SECTION5: Variables definition section *****/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)

/*
 * Lock for syscall users.
 *
 * This lock is held for only protecting single SRCU section.
 */
struct srcu_struct ccs_ss;

#else

static struct ccs_lock_struct ccs_counter;
/* Lock for protecting ccs_counter. */
static DEFINE_SPINLOCK(ccs_counter_lock);

#endif

/***** SECTION6: Dependent functions section *****/

/**
 * ccs_memory_free - Free memory for elements.
 *
 * @ptr:  Pointer to allocated memory.
 * @type: One of values in "enum ccs_policy_id".
 *
 * Returns nothing.
 *
 * Caller holds ccs_policy_lock mutex.
 */
static void ccs_memory_free(const void *ptr, const enum ccs_policy_id type)
{
	/* Size of an element. */
	static const u8 e[CCS_MAX_POLICY] = {
		[CCS_ID_GROUP] = sizeof(struct ccs_group),
#ifdef CONFIG_CCSECURITY_NETWORK
		[CCS_ID_IP_GROUP] = sizeof(struct ccs_ip_group),
#endif
		[CCS_ID_STRING_GROUP] = sizeof(struct ccs_string_group),
		[CCS_ID_NUMBER_GROUP] = sizeof(struct ccs_number_group),
		/* [CCS_ID_CONDITION] = "struct ccs_condition"->size, */
		/* [CCS_ID_NAME] = "struct ccs_name"->size, */
		/* [CCS_ID_ACL] = sizeof(struct ccs_acl_info), */
		[CCS_ID_DOMAIN] = sizeof(struct ccs_domain_info),
	};
	size_t size;
	if (type == CCS_ID_ACL)
		size = sizeof(struct ccs_acl_info);
	else if (type == CCS_ID_NAME)
		size = container_of(ptr, typeof(struct ccs_name),
				    head.list)->size;
	else if (type == CCS_ID_CONDITION)
		size = container_of(ptr, typeof(struct ccs_condition),
				    head.list)->size;
	else
		size = e[type];
	ccs_memory_used[CCS_MEMORY_POLICY] -= ccs_round2(size);
	kfree(ptr);
}

/**
 * ccs_struct_used_by_io_buffer - Check whether the list element is used by /proc/ccs/ users or not.
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns true if @element is used by /proc/ccs/ users, false otherwise.
 */
static bool ccs_struct_used_by_io_buffer(const struct list_head *element)
{
	struct ccs_io_buffer *head;
	bool in_use = false;
	spin_lock(&ccs_io_buffer_list_lock);
	list_for_each_entry(head, &ccs_io_buffer_list, list) {
		head->users++;
		spin_unlock(&ccs_io_buffer_list_lock);
		mutex_lock(&head->io_sem);
		if (head->r.acl == element || head->r.subacl == element ||
		    head->r.group == element || &head->w.acl->list == element)
			in_use = true;
		mutex_unlock(&head->io_sem);
		spin_lock(&ccs_io_buffer_list_lock);
		head->users--;
		if (in_use)
			break;
	}
	spin_unlock(&ccs_io_buffer_list_lock);
	return in_use;
}

/**
 * ccs_name_used_by_io_buffer - Check whether the string is used by /proc/ccs/ users or not.
 *
 * @string: String to check.
 * @size:   Memory allocated for @string .
 *
 * Returns true if @string is used by /proc/ccs/ users, false otherwise.
 */
static bool ccs_name_used_by_io_buffer(const char *string, const size_t size)
{
	struct ccs_io_buffer *head;
	bool in_use = false;
	spin_lock(&ccs_io_buffer_list_lock);
	list_for_each_entry(head, &ccs_io_buffer_list, list) {
		int i;
		head->users++;
		spin_unlock(&ccs_io_buffer_list_lock);
		mutex_lock(&head->io_sem);
		for (i = 0; i < CCS_MAX_IO_READ_QUEUE; i++) {
			const char *w = head->r.w[i];
			if (w < string || w > string + size)
				continue;
			in_use = true;
			break;
		}
		mutex_unlock(&head->io_sem);
		spin_lock(&ccs_io_buffer_list_lock);
		head->users--;
		if (in_use)
			break;
	}
	spin_unlock(&ccs_io_buffer_list_lock);
	return in_use;
}

/**
 * ccs_domain_used_by_task - Check whether the given pointer is referenced by a task.
 *
 * @domain: Pointer to "struct ccs_domain_info".
 *
 * Returns true if @domain is in use, false otherwise.
 */
static bool ccs_domain_used_by_task(struct ccs_domain_info *domain)
{
	bool in_use = false;
	/*
	 * Don't delete this domain if somebody is doing execve().
	 *
	 * Since ccs_finish_execve() first reverts ccs_domain_info and then
	 * updates ccs_flags, we need smp_rmb() to make sure that GC first
	 * checks ccs_flags and then checks ccs_domain_info.
	 */
#ifdef CONFIG_CCSECURITY_USE_EXTERNAL_TASK_SECURITY
	int idx;
	rcu_read_lock();
	for (idx = 0; idx < CCS_MAX_TASK_SECURITY_HASH; idx++) {
		struct ccs_security *ptr;
		struct list_head *list = &ccs_task_security_list[idx];
		list_for_each_entry_rcu(ptr, list, list) {
			if (!(ptr->ccs_flags & CCS_TASK_IS_IN_EXECVE)) {
				smp_rmb(); /* Avoid out of order execution. */
				if (ptr->ccs_domain_info != domain)
					continue;
			}
			in_use = true;
			goto out;
		}
	}
out:
	rcu_read_unlock();
#else
	struct task_struct *g;
	struct task_struct *t;
	ccs_tasklist_lock();
	do_each_thread(g, t) {
		if (!(t->ccs_flags & CCS_TASK_IS_IN_EXECVE)) {
			smp_rmb(); /* Avoid out of order execution. */
			if (t->ccs_domain_info != domain)
				continue;
		}
		in_use = true;
		goto out;
	} while_each_thread(g, t);
out:
	ccs_tasklist_unlock();
#endif
	return in_use;
}

/**
 * ccs_del_acl - Delete members in "struct ccs_acl_info".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_acl(struct list_head *element)
{
	struct ccs_acl_info *acl = container_of(element, typeof(*acl), list);
	ccs_put_condition(acl->cond);
}

/**
 * ccs_del_domain - Delete members in "struct ccs_domain_info".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * Caller holds ccs_policy_lock mutex.
 */
static inline void ccs_del_domain(struct list_head *element)
{
	struct ccs_domain_info *domain =
		container_of(element, typeof(*domain), list);
	ccs_put_name(domain->domainname);
}

/**
 * ccs_del_string_group - Delete members in "struct ccs_string_group".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_string_group(struct list_head *element)
{
	struct ccs_string_group *member =
		container_of(element, typeof(*member), head.list);
	ccs_put_name(member->member_name);
}

/**
 * ccs_del_group - Delete "struct ccs_group".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static inline void ccs_del_group(struct list_head *element)
{
	struct ccs_group *group =
		container_of(element, typeof(*group), head.list);
	ccs_put_name(group->group_name);
}

/**
 * ccs_del_condition - Delete members in "struct ccs_condition".
 *
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
void ccs_del_condition(struct list_head *element)
{
	struct ccs_condition *cond = container_of(element, typeof(*cond),
						  head.list);
	const union ccs_condition_element *condp = (typeof(condp)) (cond + 1);
	while ((void *) condp < (void *) ((u8 *) cond) + cond->size) {
		const enum ccs_conditions_index left = condp->left;
		const enum ccs_conditions_index right = condp->right;
		condp++;
		if (left == CCS_ARGV_ENTRY)
			condp++;
		else if (left == CCS_ENVP_ENTRY) {
			ccs_put_name(condp->path);
			condp++;
		}
		if (right == CCS_IMM_GROUP) {
			ccs_put_group(condp->group);
			condp++;
		} else if (right == CCS_IMM_NAME_ENTRY) {
			if (condp->path != &ccs_null_name)
				ccs_put_name(condp->path);
			condp++;
		} else if (right == CCS_IMM_NUMBER_ENTRY1)
			condp++;
		else if (right == CCS_IMM_NUMBER_ENTRY2)
			condp += 2;
#ifdef CONFIG_CCSECURITY_NETWORK
		else if (right == CCS_IMM_IPV6ADDR_ENTRY1)
			condp = (void *)
				(((u8 *) condp) + sizeof(struct in6_addr));
		else if (right == CCS_IMM_IPV6ADDR_ENTRY2)
			condp = (void *)
				(((u8 *) condp) + sizeof(struct in6_addr) * 2);
#endif
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)

/**
 * ccs_lock - Alternative for srcu_read_lock().
 *
 * Returns index number which has to be passed to ccs_unlock().
 */
int ccs_lock(void)
{
	int idx;
	spin_lock(&ccs_counter_lock);
	idx = ccs_counter.counter_idx;
	ccs_counter.counter[idx]++;
	spin_unlock(&ccs_counter_lock);
	return idx;
}

/**
 * ccs_unlock - Alternative for srcu_read_unlock().
 *
 * @idx: Index number returned by ccs_lock().
 *
 * Returns nothing.
 */
void ccs_unlock(const int idx)
{
	spin_lock(&ccs_counter_lock);
	ccs_counter.counter[idx]--;
	spin_unlock(&ccs_counter_lock);
}

/**
 * ccs_synchronize_counter - Alternative for synchronize_srcu().
 *
 * Returns nothing.
 */
static void ccs_synchronize_counter(void)
{
	int idx;
	int v;
	/*
	 * Change currently active counter's index. Make it visible to other
	 * threads by doing it with ccs_counter_lock held.
	 * This function is called by garbage collector thread, and the garbage
	 * collector thread is exclusive. Therefore, it is guaranteed that
	 * SRCU grace period has expired when returning from this function.
	 */
	spin_lock(&ccs_counter_lock);
	idx = ccs_counter.counter_idx;
	ccs_counter.counter_idx ^= 1;
	v = ccs_counter.counter[idx];
	spin_unlock(&ccs_counter_lock);
	/* Wait for previously active counter to become 0. */
	while (v) {
		ssleep(1);
		spin_lock(&ccs_counter_lock);
		v = ccs_counter.counter[idx];
		spin_unlock(&ccs_counter_lock);
	}
}

#endif

/**
 * ccs_try_to_gc - Try to kfree() an entry.
 *
 * @type:    One of values in "enum ccs_policy_id".
 * @element: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * Caller holds ccs_policy_lock mutex.
 */
static void ccs_try_to_gc(const enum ccs_policy_id type,
			  struct list_head *element)
{
	/*
	 * __list_del_entry() guarantees that the list element became no longer
	 * reachable from the list which the element was originally on (e.g.
	 * ccs_domain_list). Also, synchronize_srcu() guarantees that the list
	 * element became no longer referenced by syscall users.
	 */
	__list_del_entry(element);
	mutex_unlock(&ccs_policy_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
	synchronize_srcu(&ccs_ss);
#else
	ccs_synchronize_counter();
#endif
	/*
	 * However, there are two users which may still be using the list
	 * element. We need to defer until both users forget this element.
	 *
	 * Don't kfree() until "struct ccs_io_buffer"->r.{group,acl,subacl} and
	 * "struct ccs_io_buffer"->w.acl forget this element.
	 */
	if (ccs_struct_used_by_io_buffer(element))
		goto reinject;
	switch (type) {
	case CCS_ID_GROUP:
		ccs_del_group(element);
		break;
	case CCS_ID_STRING_GROUP:
		ccs_del_string_group(element);
		break;
	case CCS_ID_CONDITION:
		ccs_del_condition(element);
		break;
	case CCS_ID_NAME:
		/*
		 * Don't kfree() until all "struct ccs_io_buffer"->r.w[] forget
		 * this element.
		 */
		if (ccs_name_used_by_io_buffer
		    (container_of(element, typeof(struct ccs_name),
				  head.list)->entry.name,
		     container_of(element, typeof(struct ccs_name),
				  head.list)->size))
			goto reinject;
		break;
	case CCS_ID_ACL:
		ccs_del_acl(element);
		break;
	case CCS_ID_DOMAIN:
		/*
		 * Don't kfree() until all "struct task_struct" forget this
		 * element.
		 */
		if (ccs_domain_used_by_task
		    (container_of(element, typeof(struct ccs_domain_info),
				  list)))
			goto reinject;
		ccs_del_domain(element);
		break;
	default:
		break;
	}
	mutex_lock(&ccs_policy_lock);
	ccs_memory_free(element, type);
	return;
reinject:
	/*
	 * We can safely reinject this element here bacause
	 * (1) Appending list elements and removing list elements are protected
	 *     by ccs_policy_lock mutex.
	 * (2) Only this function removes list elements and this function is
	 *     exclusively executed by ccs_gc_mutex mutex.
	 * are true.
	 */
	mutex_lock(&ccs_policy_lock);
	list_add_rcu(element, element->prev);
}

/**
 * ccs_collect_member - Delete elements with "struct ccs_acl_head".
 *
 * @id:          One of values in "enum ccs_policy_id".
 * @member_list: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * Caller holds ccs_policy_lock mutex.
 */
static void ccs_collect_member(const enum ccs_policy_id id,
			       struct list_head *member_list)
{
	struct ccs_acl_head *member;
	struct ccs_acl_head *tmp;
	list_for_each_entry_safe(member, tmp, member_list, list) {
		if (!member->is_deleted)
			continue;
		member->is_deleted = CCS_GC_IN_PROGRESS;
		ccs_try_to_gc(id, &member->list);
	}
}

/**
 * ccs_collect_acl - Delete elements in "struct ccs_acl_info".
 *
 * @list: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * Caller holds ccs_policy_lock mutex.
 */
static void ccs_collect_acl(struct list_head *list)
{
	struct ccs_acl_info *acl;
	struct ccs_acl_info *tmp;
	list_for_each_entry_safe(acl, tmp, list, list) {
		if (!acl->is_deleted)
			continue;
		ccs_try_to_gc(CCS_ID_ACL, &acl->list);
	}
}

/**
 * ccs_collect_entry - Try to kfree() deleted elements.
 *
 * Returns nothing.
 */
static void ccs_collect_entry(void)
{
	int i;
	mutex_lock(&ccs_policy_lock);
	{
		struct ccs_domain_info *domain;
		struct ccs_domain_info *tmp;
		list_for_each_entry_safe(domain, tmp, &ccs_domain_list, list) {
			if (ccs_domain_used_by_task(domain))
				continue;
			ccs_try_to_gc(CCS_ID_DOMAIN, &domain->list);
		}
	}
	for (i = 0; i < CCS_MAX_MAC_INDEX; i++) {
		struct ccs_acl_info *ptr;
		struct ccs_acl_info *tmp;
		struct list_head * const list = &ccs_acl_list[i];
		list_for_each_entry_safe(ptr, tmp, list, list) {
			ccs_collect_acl(&ptr->acl_info_list);
			if (!ptr->is_deleted ||
			    !list_empty(&ptr->acl_info_list))
				continue;
			/* ptr->is_deleted = CCS_GC_IN_PROGRESS; */
			ccs_try_to_gc(CCS_ID_ACL, &ptr->list);
		}
	}
	{
		struct ccs_shared_acl_head *ptr;
		struct ccs_shared_acl_head *tmp;
		list_for_each_entry_safe(ptr, tmp, &ccs_condition_list, list) {
			if (atomic_read(&ptr->users) > 0)
				continue;
			atomic_set(&ptr->users, CCS_GC_IN_PROGRESS);
			ccs_try_to_gc(CCS_ID_CONDITION, &ptr->list);
		}
	}
	for (i = 0; i < CCS_MAX_GROUP; i++) {
		struct list_head *list = &ccs_group_list[i];
		struct ccs_group *group;
		struct ccs_group *tmp;
		enum ccs_policy_id id = CCS_ID_STRING_GROUP;
		if (i == CCS_NUMBER_GROUP)
			id = CCS_ID_NUMBER_GROUP;
#ifdef CONFIG_CCSECURITY_NETWORK
		else if (i == CCS_IP_GROUP)
			id = CCS_ID_IP_GROUP;
#endif
		list_for_each_entry_safe(group, tmp, list, head.list) {
			ccs_collect_member(id, &group->member_list);
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->head.users) > 0)
				continue;
			atomic_set(&group->head.users, CCS_GC_IN_PROGRESS);
			ccs_try_to_gc(CCS_ID_GROUP, &group->head.list);
		}
	}
	for (i = 0; i < CCS_MAX_HASH; i++) {
		struct list_head *list = &ccs_name_list[i];
		struct ccs_shared_acl_head *ptr;
		struct ccs_shared_acl_head *tmp;
		list_for_each_entry_safe(ptr, tmp, list, list) {
			if (atomic_read(&ptr->users) > 0)
				continue;
			atomic_set(&ptr->users, CCS_GC_IN_PROGRESS);
			ccs_try_to_gc(CCS_ID_NAME, &ptr->list);
		}
	}
	mutex_unlock(&ccs_policy_lock);
}

/**
 * ccs_gc_thread - Garbage collector thread function.
 *
 * @unused: Unused.
 *
 * Returns 0.
 */
static int ccs_gc_thread(void *unused)
{
	/* Garbage collector thread is exclusive. */
	static DEFINE_MUTEX(ccs_gc_mutex);
	if (!mutex_trylock(&ccs_gc_mutex))
		goto out;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 6)
	/* daemonize() not needed. */
#else
	daemonize("GC for CCS");
#endif
	ccs_collect_entry();
	{
		struct ccs_io_buffer *head;
		struct ccs_io_buffer *tmp;
		spin_lock(&ccs_io_buffer_list_lock);
		list_for_each_entry_safe(head, tmp, &ccs_io_buffer_list,
					 list) {
			if (head->users)
				continue;
			list_del(&head->list);
			kfree(head->read_buf);
			kfree(head->write_buf);
			kfree(head);
		}
		spin_unlock(&ccs_io_buffer_list_lock);
	}
	mutex_unlock(&ccs_gc_mutex);
out:
	/* This acts as do_exit(0). */
	return 0;
}

/**
 * ccs_notify_gc - Register/unregister /proc/ccs/ users.
 *
 * @head:        Pointer to "struct ccs_io_buffer".
 * @is_register: True if register, false if unregister.
 *
 * Returns nothing.
 */
void ccs_notify_gc(struct ccs_io_buffer *head, const bool is_register)
{
	bool is_write = false;
	spin_lock(&ccs_io_buffer_list_lock);
	if (is_register) {
		head->users = 1;
		list_add(&head->list, &ccs_io_buffer_list);
	} else {
		is_write = head->write_buf != NULL;
		if (!--head->users) {
			list_del(&head->list);
			kfree(head->read_buf);
			kfree(head->write_buf);
			kfree(head);
		}
	}
	spin_unlock(&ccs_io_buffer_list_lock);
	if (is_write) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 6)
		struct task_struct *task = kthread_create(ccs_gc_thread, NULL,
							  "GC for CCS");
		if (!IS_ERR(task))
			wake_up_process(task);
#else
		kernel_thread(ccs_gc_thread, NULL, 0);
#endif
	}
}
