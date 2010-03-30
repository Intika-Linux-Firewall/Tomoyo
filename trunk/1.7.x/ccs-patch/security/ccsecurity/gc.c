/*
 * security/ccsecurity/gc.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2-pre   2010/03/21
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/version.h>
#include "internal.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/kthread.h>
#endif

LIST_HEAD(ccs_io_buffer_list);
DEFINE_SPINLOCK(ccs_io_buffer_list_lock);

enum ccs_gc_id {
	CCS_ID_RESERVEDPORT,
	CCS_ID_ADDRESS_GROUP,
	CCS_ID_ADDRESS_GROUP_MEMBER,
	CCS_ID_PATH_GROUP,
	CCS_ID_PATH_GROUP_MEMBER,
	CCS_ID_NUMBER_GROUP,
	CCS_ID_NUMBER_GROUP_MEMBER,
	CCS_ID_GLOBAL_ENV,
	CCS_ID_AGGREGATOR,
	CCS_ID_DOMAIN_INITIALIZER,
	CCS_ID_DOMAIN_KEEPER,
	CCS_ID_GLOBALLY_READABLE,
	CCS_ID_PATTERN,
	CCS_ID_NO_REWRITE,
	CCS_ID_MANAGER,
	CCS_ID_IPV6_ADDRESS,
	CCS_ID_CONDITION,
	CCS_ID_NAME,
	CCS_ID_ACL,
	CCS_ID_DOMAIN
};

#define CCS_MAX_GC_ELEMENTS 128
static u8 ccs_gc_elements_type[CCS_MAX_GC_ELEMENTS];
static struct list_head *ccs_gc_elements[CCS_MAX_GC_ELEMENTS];
static unsigned int ccs_gc_count;

/**
 * ccs_used_by_io_buffer - Check whether the given pointer is referenced by ccs_io_buffer.
 *
 * @ptr: Pointer to scan.
 *
 * Returns true if @ptr is referenced by ccs_io_buffer, false otherwise.
 */
static bool ccs_used_by_io_buffer(struct list_head *ptr)
{
	bool in_use = false;
	struct ccs_io_buffer *entry;
	spin_lock(&ccs_io_buffer_list_lock);
	list_for_each_entry(entry, &ccs_io_buffer_list, list) {
		if (entry->read_var1 == ptr || entry->read_var2 == ptr ||
		    &entry->write_var1->list == ptr) {
			in_use = true;
			break;
		}
	}
	spin_unlock(&ccs_io_buffer_list_lock);
	return in_use;
}

/* Caller holds ccs_policy_lock mutex. */
static bool ccs_add_to_gc(const int type, struct list_head *element)
{
	if (ccs_gc_count == CCS_MAX_GC_ELEMENTS)
		return false;
	if (!ccs_used_by_io_buffer(element)) {
		ccs_gc_elements_type[ccs_gc_count] = type;
		ccs_gc_elements[ccs_gc_count++] = element;
		list_del_rcu(element);
	}
	return true;
}

static size_t ccs_del_allow_read(struct list_head *element)
{
	struct ccs_globally_readable_file_entry *ptr =
		container_of(element, typeof(*ptr), list);
	ccs_put_name(ptr->filename);
	return sizeof(*ptr);
}

static size_t ccs_del_allow_env(struct list_head *element)
{
	struct ccs_globally_usable_env_entry *ptr =
		container_of(element, typeof(*ptr), list);
	ccs_put_name(ptr->env);
	return sizeof(*ptr);
}

static size_t ccs_del_file_pattern(struct list_head *element)
{
	struct ccs_pattern_entry *ptr =
		container_of(element, typeof(*ptr), list);
	ccs_put_name(ptr->pattern);
	return sizeof(*ptr);
}

static size_t ccs_del_no_rewrite(struct list_head *element)
{
	struct ccs_no_rewrite_entry *ptr =
		container_of(element, typeof(*ptr), list);
	ccs_put_name(ptr->pattern);
	return sizeof(*ptr);
}

static size_t ccs_del_domain_initializer(struct list_head *element)
{
	struct ccs_domain_initializer_entry *ptr =
		container_of(element, typeof(*ptr), list);
	ccs_put_name(ptr->domainname);
	ccs_put_name(ptr->program);
	return sizeof(*ptr);
}

static size_t ccs_del_domain_keeper(struct list_head *element)
{
	struct ccs_domain_keeper_entry *ptr =
		container_of(element, typeof(*ptr), list);
	ccs_put_name(ptr->domainname);
	ccs_put_name(ptr->program);
	return sizeof(*ptr);
}

static size_t ccs_del_aggregator(struct list_head *element)
{
	struct ccs_aggregator_entry *ptr =
		container_of(element, typeof(*ptr), list);
	ccs_put_name(ptr->original_name);
	ccs_put_name(ptr->aggregated_name);
	return sizeof(*ptr);
}

static size_t ccs_del_manager(struct list_head *element)
{
	struct ccs_policy_manager_entry *ptr =
		container_of(element, typeof(*ptr), list);
	ccs_put_name(ptr->manager);
	return sizeof(*ptr);
}

/* For compatibility with older kernels. */
#ifndef for_each_process
#define for_each_process for_each_task
#endif

/**
 * ccs_used_by_task - Check whether the given pointer is referenced by a task.
 *
 * @domain: Pointer to "struct ccs_domain_info".
 *
 * Returns true if @domain is in use, false otherwise.
 */
static bool ccs_used_by_task(struct ccs_domain_info *domain)
{
	bool in_use = false;
	/*
	 * Don't delete this domain if somebody is doing execve().
	 *
	 * Since ccs_finish_execve() first reverts ccs_domain_info and then
	 * updates ccs_flags , we need smp_mb() to make sure that GC first
	 * checks ccs_flags and then checks ccs_domain_info .
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
	struct task_struct *g;
	struct task_struct *t;
	ccs_tasklist_lock();
	do_each_thread(g, t) {
		if (!(t->ccs_flags & CCS_TASK_IS_IN_EXECVE)) {
			smp_mb(); /* Avoid out of order execution. */
			if (t->ccs_domain_info != domain)
				continue;
		}
		in_use = true;
		goto out;
	} while_each_thread(g, t);
 out:
	ccs_tasklist_unlock();
#else
	struct task_struct *p;
	ccs_tasklist_lock();
	for_each_process(p) {
		if (!(p->ccs_flags & CCS_TASK_IS_IN_EXECVE)) {
			smp_mb(); /* Avoid out of order execution. */
			if (p->ccs_domain_info != domain)
				continue;
		}
		in_use = true;
		break;
	}
	ccs_tasklist_unlock();
#endif
	return in_use;
}

static size_t ccs_del_acl(struct list_head *element)
{
	size_t size;
	struct ccs_acl_info *acl = container_of(element, typeof(*acl), list);
	ccs_put_condition(acl->cond);
	switch (acl->type) {
	case CCS_TYPE_PATH_ACL:
		{
			struct ccs_path_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->name);
		}
		break;
	case CCS_TYPE_PATH_NUMBER3_ACL:
		{
			struct ccs_path_number3_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->name);
			ccs_put_number_union(&entry->mode);
			ccs_put_number_union(&entry->major);
			ccs_put_number_union(&entry->minor);
		}
		break;
	case CCS_TYPE_PATH2_ACL:
		{
			struct ccs_path2_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->name1);
			ccs_put_name_union(&entry->name2);
		}
		break;
	case CCS_TYPE_IP_NETWORK_ACL:
		{
			struct ccs_ip_network_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			switch (entry->address_type) {
			case CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP:
				ccs_put_address_group(entry->address.group);
				break;
			case CCS_IP_ADDRESS_TYPE_IPv6:
				ccs_put_ipv6_address(entry->address.ipv6.min);
				ccs_put_ipv6_address(entry->address.ipv6.max);
				break;
			}
			ccs_put_number_union(&entry->port);
		}
		break;
	case CCS_TYPE_PATH_NUMBER_ACL:
		{
			struct ccs_path_number_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->name);
			ccs_put_number_union(&entry->number);
		}
		break;
	case CCS_TYPE_ENV_ACL:
		{
			struct ccs_env_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name(entry->env);
		}
		break;
	case CCS_TYPE_CAPABILITY_ACL:
		{
			struct ccs_capability_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
		}
		break;
	case CCS_TYPE_SIGNAL_ACL:
		{
			struct ccs_signal_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name(entry->domainname);
		}
		break;
	case CCS_TYPE_EXECUTE_HANDLER:
	case CCS_TYPE_DENIED_EXECUTE_HANDLER:
		{
			struct ccs_execute_handler_record *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name(entry->handler);
		}
		break;
	case CCS_TYPE_MOUNT_ACL:
		{
			struct ccs_mount_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->dev_name);
			ccs_put_name_union(&entry->dir_name);
			ccs_put_name_union(&entry->fs_type);
			ccs_put_number_union(&entry->flags);
		}
		break;
	default:
		size = 0;
		break;
	}
	return size;
}

static size_t ccs_del_domain(struct list_head *element)
{
	struct ccs_acl_info *acl;
	struct ccs_domain_info *domain =
		container_of(element, typeof(*domain), list);
	int idx;
	if (ccs_used_by_task(domain))
		goto out;
	if (domain->gc_in_progress)
		goto check;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		goto out;
	/*
	 * Mark all elements in this domain as deleted. Also, suppress callback
	 * until all elements in this domain are deleted. Elements marked as
	 * deleted will be collected by ccs_collect_entry() and deleted by
	 * ccs_del_acl().
	 */
	idx = ccs_read_lock();
	list_for_each_entry_rcu(acl, &domain->acl_info_list, list)
		acl->is_deleted = true;
	ccs_read_unlock(idx);
	domain->gc_in_progress = true;
	mutex_unlock(&ccs_policy_lock);
 out:
	/* Push this domain back to ccs_domain_list for later callback. */
	return 0;
 check:
	/*
	 * Elements which could not be deleted are pushed back to this domain.
	 * Since ccs_gc_elements is a FIFO, ccs_del_acl() for this domain is
	 * processed before ccs_del_domain() for this domain is processed.
	 * Therefore, pushing back to this domain is safe and list_empty() will
	 * return false when an element was pushed back.
	 */
	if (!list_empty(&domain->acl_info_list))
		goto out;
	/*
	 * All elements in this domain were deleted. Thus, ready to delete
	 * this domain.
	 */
	ccs_put_name(domain->domainname);
	return sizeof(*domain);
}

static size_t ccs_del_path_group_member(struct list_head *element)
{
	struct ccs_path_group_member *member =
		container_of(element, typeof(*member), list);
	ccs_put_name(member->member_name);
	return sizeof(*member);
}

static size_t ccs_del_path_group(struct list_head *element)
{
	struct ccs_path_group *group =
		container_of(element, typeof(*group), list);
	ccs_put_name(group->group_name);
	return sizeof(*group);
}

static size_t ccs_del_address_group_member(struct list_head *element)
{
	struct ccs_address_group_member *member =
		container_of(element, typeof(*member), list);
	if (member->is_ipv6) {
		ccs_put_ipv6_address(member->min.ipv6);
		ccs_put_ipv6_address(member->max.ipv6);
	}
	return sizeof(*member);
}

static size_t ccs_del_address_group(struct list_head *element)
{
	struct ccs_address_group *group =
		container_of(element, typeof(*group), list);
	ccs_put_name(group->group_name);
	return sizeof(*group);
}

static size_t ccs_del_number_group_member(struct list_head *element)
{
	struct ccs_number_group_member *member =
		container_of(element, typeof(*member), list);
	return sizeof(*member);
}

static size_t ccs_del_number_group(struct list_head *element)
{
	struct ccs_number_group *group =
		container_of(element, typeof(*group), list);
	ccs_put_name(group->group_name);
	return sizeof(*group);
}

static size_t ccs_del_reservedport(struct list_head *element)
{
	struct ccs_reserved_entry *ptr =
		container_of(element, typeof(*ptr), list);
	return sizeof(*ptr);
}

static size_t ccs_del_ipv6_address(struct list_head *element)
{
	struct ccs_ipv6addr_entry *ptr =
		container_of(element, typeof(*ptr), list);
	return sizeof(*ptr);
}

/**
 * ccs_del_conditiopn - Delete condition part.
 *
 * @cond: Pointer to "struct ccs_condition".
 *
 * Returns size of condition in bytes.
 */
size_t ccs_del_condition(struct ccs_condition *cond)
{
	const u16 condc = cond->condc;
	const u16 numbers_count = cond->numbers_count;
	const u16 names_count = cond->names_count;
	const u16 argc = cond->argc;
	const u16 envc = cond->envc;
	unsigned int i;
	const struct ccs_condition_element *condp
		= (const struct ccs_condition_element *) (cond + 1);
	struct ccs_number_union *numbers_p
		= (struct ccs_number_union *) (condp + condc);
	struct ccs_name_union *names_p
		= (struct ccs_name_union *) (numbers_p + numbers_count);
	const struct ccs_argv_entry *argv
		= (const struct ccs_argv_entry *) (names_p + names_count);
	const struct ccs_envp_entry *envp
		= (const struct ccs_envp_entry *) (argv + argc);
	for (i = 0; i < numbers_count; i++)
		ccs_put_number_union(numbers_p++);
	for (i = 0; i < names_count; i++)
		ccs_put_name_union(names_p++);
	for (i = 0; i < argc; argv++, i++)
		ccs_put_name(argv->value);
	for (i = 0; i < envc; envp++, i++) {
		ccs_put_name(envp->name);
		ccs_put_name(envp->value);
	}
	return cond->size;
}

static size_t ccs_del_name(struct list_head *element)
{
	const struct ccs_name_entry *ptr =
		container_of(element, typeof(*ptr), list);
	return ptr->size;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)

/* Lock for GC. */
struct srcu_struct ccs_ss;

static inline void ccs_synchronize_srcu(void)
{
	synchronize_srcu(&ccs_ss);
}

#else

/* Lock for GC. */
static struct {
	int counter_idx;
	int counter[2];
} ccs_gc;
static DEFINE_SPINLOCK(ccs_counter_lock);

int ccs_read_lock(void)
{
	int idx;
	spin_lock(&ccs_counter_lock);
	idx = ccs_gc.counter_idx;
	ccs_gc.counter[idx]++;
	spin_unlock(&ccs_counter_lock);
	return idx;
}

void ccs_read_unlock(const int idx)
{
	spin_lock(&ccs_counter_lock);
	ccs_gc.counter[idx]--;
	spin_unlock(&ccs_counter_lock);
}

static void ccs_synchronize_srcu(void)
{
	int idx;
	int v;
	spin_lock(&ccs_counter_lock);
	idx = ccs_gc.counter_idx;
	ccs_gc.counter_idx ^= 1;
	v = ccs_gc.counter[idx];
	spin_unlock(&ccs_counter_lock);
	while (v) {
		ssleep(1);
		spin_lock(&ccs_counter_lock);
		v = ccs_gc.counter[idx];
		spin_unlock(&ccs_counter_lock);
	}
}

#endif

static bool ccs_collect_entry(void)
{
	int i;
	int idx;
	if (mutex_lock_interruptible(&ccs_policy_lock))
		return false;
	idx = ccs_read_lock();
	{
		struct ccs_globally_readable_file_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_globally_readable_list,
					list) {
			if (!ptr->is_deleted)
				continue;
			if (!ccs_add_to_gc(CCS_ID_GLOBALLY_READABLE,
					   &ptr->list))
				goto unlock;
		}
	}
	{
		struct ccs_globally_usable_env_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_globally_usable_env_list,
					list) {
			if (!ptr->is_deleted)
				continue;
			if (!ccs_add_to_gc(CCS_ID_GLOBAL_ENV, &ptr->list))
				goto unlock;
		}
	}
	{
		struct ccs_pattern_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_pattern_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (!ccs_add_to_gc(CCS_ID_PATTERN, &ptr->list))
				goto unlock;
		}
	}
	{
		struct ccs_no_rewrite_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_no_rewrite_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (!ccs_add_to_gc(CCS_ID_NO_REWRITE, &ptr->list))
				goto unlock;
		}
	}
	{
		struct ccs_domain_initializer_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_domain_initializer_list,
					list) {
			if (!ptr->is_deleted)
				continue;
			if (!ccs_add_to_gc(CCS_ID_DOMAIN_INITIALIZER,
					   &ptr->list))
				goto unlock;
		}
	}
	{
		struct ccs_domain_keeper_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_domain_keeper_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (!ccs_add_to_gc(CCS_ID_DOMAIN_KEEPER, &ptr->list))
				goto unlock;
		}
	}
	{
		struct ccs_policy_manager_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_policy_manager_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (!ccs_add_to_gc(CCS_ID_MANAGER, &ptr->list))
				goto unlock;
		}
	}
	{
		struct ccs_aggregator_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_aggregator_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (!ccs_add_to_gc(CCS_ID_AGGREGATOR, &ptr->list))
				goto unlock;
		}
	}
	{
		struct ccs_domain_info *domain;
		list_for_each_entry_rcu(domain, &ccs_domain_list, list) {
			struct ccs_acl_info *acl;
			list_for_each_entry_rcu(acl, &domain->acl_info_list,
						list) {
				if (!acl->is_deleted)
					continue;
				if (!ccs_add_to_gc(CCS_ID_ACL, &acl->list))
					goto unlock;
			}
			if (domain->gc_in_progress &&
			    !list_empty(&domain->acl_info_list))
				continue;
			if (!domain->is_deleted || ccs_used_by_task(domain))
				continue;
			if (!ccs_add_to_gc(CCS_ID_DOMAIN, &domain->list))
				goto unlock;
		}
	}
	{
		struct ccs_path_group *group;
		list_for_each_entry_rcu(group, &ccs_path_group_list, list) {
			struct ccs_path_group_member *member;
			list_for_each_entry_rcu(member, &group->member_list,
						list) {
				if (!member->is_deleted)
					continue;
				if (!ccs_add_to_gc(CCS_ID_PATH_GROUP_MEMBER,
						   &member->list))
					goto unlock;
			}
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->users))
				continue;
			if (!ccs_add_to_gc(CCS_ID_PATH_GROUP, &group->list))
				goto unlock;
		}
	}
	{
		struct ccs_address_group *group;
		list_for_each_entry_rcu(group, &ccs_address_group_list, list) {
			struct ccs_address_group_member *member;
			list_for_each_entry_rcu(member, &group->member_list,
						list) {
				if (!member->is_deleted)
					continue;
				if (!ccs_add_to_gc(CCS_ID_ADDRESS_GROUP_MEMBER,
						   &member->list))
					goto unlock;
			}
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->users))
				continue;
			if (!ccs_add_to_gc(CCS_ID_ADDRESS_GROUP, &group->list))
				goto unlock;
		}
	}
	{
		struct ccs_number_group *group;
		list_for_each_entry_rcu(group, &ccs_number_group_list, list) {
			struct ccs_number_group_member *member;
			list_for_each_entry_rcu(member, &group->member_list,
						list) {
				if (!member->is_deleted)
					continue;
				if (!ccs_add_to_gc(CCS_ID_NUMBER_GROUP_MEMBER,
						   &member->list))
					goto unlock;
			}
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->users))
				continue;
			if (!ccs_add_to_gc(CCS_ID_NUMBER_GROUP, &group->list))
				goto unlock;
		}
	}
	{
		struct ccs_reserved_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_reservedport_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (!ccs_add_to_gc(CCS_ID_RESERVEDPORT, &ptr->list))
				goto unlock;
		}
	}
	{
		struct ccs_ipv6addr_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_address_list, list) {
			if (atomic_read(&ptr->users))
				continue;
			if (!ccs_add_to_gc(CCS_ID_IPV6_ADDRESS, &ptr->list))
				goto unlock;
		}
	}
	{
		struct ccs_condition *ptr;
		list_for_each_entry_rcu(ptr, &ccs_condition_list, list) {
			if (atomic_read(&ptr->users))
				continue;
			if (!ccs_add_to_gc(CCS_ID_CONDITION, &ptr->list))
				goto unlock;
		}
	}
	for (i = 0; i < CCS_MAX_HASH; i++) {
		struct ccs_name_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_name_list[i], list) {
			if (atomic_read(&ptr->users))
				continue;
			if (!ccs_add_to_gc(CCS_ID_NAME, &ptr->list))
				goto unlock;
		}
	}
 unlock:
	ccs_read_unlock(idx);
	/*
	 * The order of kfree() by ccs_kfree_entry() is not sequential.
	 * Thus, if ccs_gc_elements[i]->next points ccs_gc_elements[j] ,
	 * reader will trigger oops by reaching already kfree()d element.
	 * To avoid oops, make sure that ccs_gc_elements[i]->next never points
	 * ccs_gc_elements[j] before waiting for SRCU grace period. After SRCU
	 * grace period, it is safe to push ccs_gc_elements[i] back to between
	 * ccs_gc_elements[i]->next->prev and ccs_gc_elements[i]->next if
	 * ccs_gc_elements[i] is still used by "struct ccs_io_buffer" or
	 * "struct task_struct".
	 */
 restart:
	for (i = 0; i < ccs_gc_count; i++) {
		int j;
		for (j = 0; j < ccs_gc_count; j++) {
			if (ccs_gc_elements_type[i] != ccs_gc_elements_type[j])
				continue;
			if (ccs_gc_elements[i]->next == ccs_gc_elements[j]) {
				rcu_assign_pointer(ccs_gc_elements[i]->next,
						   ccs_gc_elements[j]->next);
				goto restart;
			}
			if (ccs_gc_elements[j]->next == ccs_gc_elements[i]) {
				rcu_assign_pointer(ccs_gc_elements[j]->next,
						   ccs_gc_elements[i]->next);
				goto restart;
			}
		}
	}
	mutex_unlock(&ccs_policy_lock);
	return ccs_gc_count != 0;
}

static void ccs_kfree_entry(void)
{
	size_t size = 0;
	int i;
	for (i = 0; i < ccs_gc_count; i++) {
		struct list_head *element = ccs_gc_elements[i];
		if (ccs_used_by_io_buffer(element)) {
			/* Push back to list. */
			list_add_tail_rcu(element, element->next);
			continue;
		}
		switch (ccs_gc_elements_type[i]) {
		case CCS_ID_DOMAIN_INITIALIZER:
			size = ccs_del_domain_initializer(element);
			break;
		case CCS_ID_DOMAIN_KEEPER:
			size = ccs_del_domain_keeper(element);
			break;
		case CCS_ID_GLOBALLY_READABLE:
			size = ccs_del_allow_read(element);
			break;
		case CCS_ID_PATTERN:
			size = ccs_del_file_pattern(element);
			break;
		case CCS_ID_NO_REWRITE:
			size = ccs_del_no_rewrite(element);
			break;
		case CCS_ID_MANAGER:
			size = ccs_del_manager(element);
			break;
		case CCS_ID_GLOBAL_ENV:
			size = ccs_del_allow_env(element);
			break;
		case CCS_ID_AGGREGATOR:
			size = ccs_del_aggregator(element);
			break;
		case CCS_ID_PATH_GROUP_MEMBER:
			size = ccs_del_path_group_member(element);
			break;
		case CCS_ID_PATH_GROUP:
			size = ccs_del_path_group(element);
			break;
		case CCS_ID_ADDRESS_GROUP_MEMBER:
			size = ccs_del_address_group_member(element);
			break;
		case CCS_ID_ADDRESS_GROUP:
			size = ccs_del_address_group(element);
			break;
		case CCS_ID_NUMBER_GROUP_MEMBER:
			size = ccs_del_number_group_member(element);
			break;
		case CCS_ID_NUMBER_GROUP:
			size = ccs_del_number_group(element);
			break;
		case CCS_ID_RESERVEDPORT:
			size = ccs_del_reservedport(element);
			break;
		case CCS_ID_IPV6_ADDRESS:
			size = ccs_del_ipv6_address(element);
			break;
		case CCS_ID_CONDITION:
			size = ccs_del_condition(container_of(element,
							      struct
							      ccs_condition,
							      list));
			break;
		case CCS_ID_NAME:
			size = ccs_del_name(element);
			break;
		case CCS_ID_ACL:
			size = ccs_del_acl(element);
			break;
		case CCS_ID_DOMAIN:
			size = ccs_del_domain(element);
			if (size)
				break;
			/* Push back to list. */
			list_add_tail_rcu(element, element->next);
			continue;
		default:
			size = 0;
			break;
		}
		ccs_memory_free(element, size);
	}
	ccs_gc_count = 0;
}

static int ccs_gc_thread(void *unused)
{
	static DEFINE_MUTEX(ccs_gc_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	daemonize("GC for CCS");
#else
	daemonize();
	reparent_to_init();
#if defined(TASK_DEAD)
	{
		struct task_struct *task = current;
		spin_lock_irq(&task->sighand->siglock);
		siginitsetinv(&task->blocked, 0);
		recalc_sigpending();
		spin_unlock_irq(&task->sighand->siglock);
	}
#else
	{
		struct task_struct *task = current;
		spin_lock_irq(&task->sigmask_lock);
		siginitsetinv(&task->blocked, 0);
		recalc_sigpending(task);
		spin_unlock_irq(&task->sigmask_lock);
	}
#endif
	snprintf(current->comm, sizeof(current->comm) - 1, "GC for CCS");
#endif
	if (mutex_trylock(&ccs_gc_mutex)) {
		while (ccs_collect_entry()) {
			ccs_synchronize_srcu();
			ccs_kfree_entry();
		}
		mutex_unlock(&ccs_gc_mutex);
	}
	return 0;
}

void ccs_run_gc(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	struct task_struct *task = kthread_create(ccs_gc_thread, NULL,
						  "GC for CCS");
	if (!IS_ERR(task))
		wake_up_process(task);
#else
	kernel_thread(ccs_gc_thread, NULL, 0);
#endif
}
