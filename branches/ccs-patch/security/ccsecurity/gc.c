/*
 * security/ccsecurity/gc.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
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
	CCS_ID_ACL,
	CCS_ID_DOMAIN
};

struct ccs_gc_entry {
	struct list_head list;
	int type;
	void *element;
};

/* Caller holds ccs_policy_lock mutex. */
static bool ccs_add_to_gc(const int type, void *element, struct list_head *head)
{
	struct ccs_gc_entry *entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return false;
	entry->type = type;
	entry->element = element;
	list_add(&entry->list, head);
	return true;
}

static size_t ccs_del_allow_read(struct ccs_globally_readable_file_entry *ptr)
{
	ccs_put_name(ptr->filename);
	return sizeof(*ptr);
}

static size_t ccs_del_allow_env(struct ccs_globally_usable_env_entry *ptr)
{
	ccs_put_name(ptr->env);
	return sizeof(*ptr);
}

static size_t ccs_del_file_pattern(struct ccs_pattern_entry *ptr)
{
	ccs_put_name(ptr->pattern);
	return sizeof(*ptr);
}

static size_t ccs_del_no_rewrite(struct ccs_no_rewrite_entry *ptr)
{
	ccs_put_name(ptr->pattern);
	return sizeof(*ptr);
}

static size_t ccs_del_domain_initializer(struct ccs_domain_initializer_entry *
					 ptr)
{
	ccs_put_name(ptr->domainname);
	ccs_put_name(ptr->program);
	return sizeof(*ptr);
}

static size_t ccs_del_domain_keeper(struct ccs_domain_keeper_entry *ptr)
{
	ccs_put_name(ptr->domainname);
	ccs_put_name(ptr->program);
	return sizeof(*ptr);
}

static size_t ccs_del_aggregator(struct ccs_aggregator_entry *ptr)
{
	ccs_put_name(ptr->original_name);
	ccs_put_name(ptr->aggregated_name);
	return sizeof(*ptr);
}

static size_t ccs_del_manager(struct ccs_policy_manager_entry *ptr)
{
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
 * Returns true if @ptr is in use, false otherwise.
 */
static bool ccs_used_by_task(struct ccs_domain_info *domain)
{
	bool in_use = false;
	struct task_struct *p;
	/***** CRITICAL SECTION START *****/
	read_lock(&tasklist_lock);
	for_each_process(p) {
		if (p->ccs_domain_info != domain)
			continue;
		in_use = true;
		break;
	}
	read_unlock(&tasklist_lock);
	/***** CRITICAL SECTION END *****/
	return in_use;
}

static size_t ccs_del_acl(struct ccs_acl_info *acl)
{
	size_t size;
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
	case CCS_TYPE_PATH_NUMBER_NUMBER_ACL:
		{
			struct ccs_path_number_number_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->name);
			ccs_put_number_union(&entry->major);
			ccs_put_number_union(&entry->minor);
		}
		break;
	case CCS_TYPE_PATH_PATH_ACL:
		{
			struct ccs_path_path_acl *entry;
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
			switch (entry->record_type) {
			case CCS_IP_RECORD_TYPE_ADDRESS_GROUP:
				ccs_put_address_group(entry->address.group);
				break;
			case CCS_IP_RECORD_TYPE_IPv6:
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
	case CCS_TYPE_UMOUNT_ACL:
		{
			struct ccs_umount_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->dir);
		}
		break;
	case CCS_TYPE_CHROOT_ACL:
		{
			struct ccs_chroot_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->dir);
		}
		break;
	case CCS_TYPE_PIVOT_ROOT_ACL:
		{
			struct ccs_pivot_root_acl *entry;
			size = sizeof(*entry);
			entry = container_of(acl, typeof(*entry), head);
			ccs_put_name_union(&entry->old_root);
			ccs_put_name_union(&entry->new_root);
		}
		break;
	default:
		size = 0;
		printk(KERN_WARNING "Unknown type\n");
		break;
	}
	return size;
}

static size_t ccs_del_domain(struct ccs_domain_info *domain)
{
	struct ccs_acl_info *acl;
	struct ccs_acl_info *tmp;
	if (ccs_used_by_task(domain))
		return 0;
	list_for_each_entry_safe(acl, tmp, &domain->acl_info_list, list) {
		size_t size = ccs_del_acl(acl);
		ccs_memory_free(acl, size);
	}
	ccs_put_name(domain->domainname);
	return sizeof(*domain);
}

static size_t ccs_del_path_group_member(struct ccs_path_group_member *member)
{
	ccs_put_name(member->member_name);
	return sizeof(*member);
}

static size_t ccs_del_path_group(struct ccs_path_group *group)
{
	ccs_put_name(group->group_name);
	return sizeof(*group);
}

static size_t ccs_del_address_group_member
(struct ccs_address_group_member *member)
{
	if (member->is_ipv6) {
		ccs_put_ipv6_address(member->min.ipv6);
		ccs_put_ipv6_address(member->max.ipv6);
	}
	return sizeof(*member);
}

static size_t ccs_del_address_group(struct ccs_address_group *group)
{
	ccs_put_name(group->group_name);
	return sizeof(*group);
}

static size_t ccs_del_number_group_member
(struct ccs_number_group_member *member)
{
	return sizeof(*member);
}

static size_t ccs_del_number_group(struct ccs_number_group *group)
{
	ccs_put_name(group->group_name);
	return sizeof(*group);
}

static size_t ccs_del_reservedport(struct ccs_reserved_entry *ptr)
{
	return sizeof(*ptr);
}

static int ccs_gc_thread(void *unused)
{
	static DEFINE_MUTEX(ccs_gc_mutex);
	static LIST_HEAD(ccs_gc_queue);
	if (!mutex_trylock(&ccs_gc_mutex))
		goto out;
	mutex_lock(&ccs_policy_lock);
	{
		struct ccs_globally_readable_file_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_globally_readable_list,
					list) {
			if (!ptr->is_deleted)
				continue;
			if (ccs_add_to_gc(CCS_ID_GLOBALLY_READABLE, ptr,
					  &ccs_gc_queue))
				list_del_rcu(&ptr->list);
			else
				break;
		}
	}
	{
		struct ccs_globally_usable_env_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_globally_usable_env_list,
					list) {
			if (!ptr->is_deleted)
				continue;
			if (ccs_add_to_gc(CCS_ID_GLOBAL_ENV, ptr,
					  &ccs_gc_queue))
				list_del_rcu(&ptr->list);
			else
				break;
		}
	}
	{
		struct ccs_pattern_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_pattern_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (ccs_add_to_gc(CCS_ID_PATTERN, ptr,
					  &ccs_gc_queue))
				list_del_rcu(&ptr->list);
			else
				break;
		}
	}
	{
		struct ccs_no_rewrite_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_no_rewrite_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (ccs_add_to_gc(CCS_ID_NO_REWRITE, ptr,
					  &ccs_gc_queue))
				list_del_rcu(&ptr->list);
			else
				break;
		}
	}
	{
		struct ccs_domain_initializer_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_domain_initializer_list,
					list) {
			if (!ptr->is_deleted)
				continue;
			if (ccs_add_to_gc(CCS_ID_DOMAIN_INITIALIZER,
					  ptr, &ccs_gc_queue))
				list_del_rcu(&ptr->list);
			else
				break;
		}
	}
	{
		struct ccs_domain_keeper_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_domain_keeper_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (ccs_add_to_gc(CCS_ID_DOMAIN_KEEPER, ptr,
					  &ccs_gc_queue))
				list_del_rcu(&ptr->list);
			else
				break;
		}
	}
	{
		struct ccs_policy_manager_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_policy_manager_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (ccs_add_to_gc(CCS_ID_MANAGER, ptr, &ccs_gc_queue))
				list_del_rcu(&ptr->list);
			else
				break;
		}
	}
	{
		struct ccs_aggregator_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_aggregator_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (ccs_add_to_gc(CCS_ID_AGGREGATOR, ptr,
					  &ccs_gc_queue))
				list_del_rcu(&ptr->list);
			else
				break;
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
				if (ccs_add_to_gc(CCS_ID_ACL, acl,
						  &ccs_gc_queue))
					list_del_rcu(&acl->list);
				else
					break;
			}
			if (!domain->is_deleted ||
			    ccs_used_by_task(domain))
				continue;
			if (ccs_add_to_gc(CCS_ID_DOMAIN, domain, &ccs_gc_queue))
				list_del_rcu(&domain->list);
			else
				break;
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
				if (ccs_add_to_gc(CCS_ID_PATH_GROUP_MEMBER,
						  member, &ccs_gc_queue))
					list_del_rcu(&member->list);
				else
					break;
			}
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->users))
				continue;
			if (ccs_add_to_gc(CCS_ID_PATH_GROUP, group,
					  &ccs_gc_queue))
				list_del_rcu(&group->list);
			else
				break;
		}
	}
	{
		struct ccs_address_group *group;
		list_for_each_entry_rcu(group, &ccs_address_group_list, list) {
			struct ccs_address_group_member *member;
			list_for_each_entry_rcu(member, &group->member_list,
						list) {
				if (!member->is_deleted)
					break;
				if (ccs_add_to_gc(CCS_ID_ADDRESS_GROUP_MEMBER,
						  member, &ccs_gc_queue))
					list_del_rcu(&member->list);
				else
					break;
			}
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->users))
				continue;
			if (ccs_add_to_gc(CCS_ID_ADDRESS_GROUP, group,
					  &ccs_gc_queue))
				list_del_rcu(&group->list);
			else
				break;
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
				if (ccs_add_to_gc(CCS_ID_NUMBER_GROUP_MEMBER,
						  member, &ccs_gc_queue))
					list_del_rcu(&member->list);
				else
					break;
			}
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->users))
				continue;
			if (ccs_add_to_gc(CCS_ID_NUMBER_GROUP, group,
					  &ccs_gc_queue))
				list_del_rcu(&group->list);
			else
				break;
		}
	}
	{
		struct ccs_reserved_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_reservedport_list, list) {
			if (!ptr->is_deleted)
				continue;
			if (ccs_add_to_gc(CCS_ID_RESERVEDPORT, ptr,
					  &ccs_gc_queue))
				list_del_rcu(&ptr->list);
			else
				break;
		}
	}
	mutex_unlock(&ccs_policy_lock);
	if (list_empty(&ccs_gc_queue))
		goto done;
	synchronize_srcu(&ccs_ss);
	{
		struct ccs_gc_entry *p;
		struct ccs_gc_entry *tmp;
		size_t size = 0;
		list_for_each_entry_safe(p, tmp, &ccs_gc_queue, list) {
			switch (p->type) {
			case CCS_ID_DOMAIN_INITIALIZER:
				size = ccs_del_domain_initializer(p->element);
				break;
			case CCS_ID_DOMAIN_KEEPER:
				size = ccs_del_domain_keeper(p->element);
				break;
			case CCS_ID_GLOBALLY_READABLE:
				size = ccs_del_allow_read(p->element);
				break;
			case CCS_ID_PATTERN:
				size = ccs_del_file_pattern(p->element);
				break;
			case CCS_ID_NO_REWRITE:
				size = ccs_del_no_rewrite(p->element);
				break;
			case CCS_ID_MANAGER:
				size = ccs_del_manager(p->element);
				break;
			case CCS_ID_GLOBAL_ENV:
				size = ccs_del_allow_env(p->element);
				break;
			case CCS_ID_AGGREGATOR:
				size = ccs_del_aggregator(p->element);
				break;
			case CCS_ID_PATH_GROUP_MEMBER:
				size = ccs_del_path_group_member(p->element);
				break;
			case CCS_ID_PATH_GROUP:
				size = ccs_del_path_group(p->element);
				break;
			case CCS_ID_ADDRESS_GROUP_MEMBER:
				size = ccs_del_address_group_member(p->element);
				break;
			case CCS_ID_ADDRESS_GROUP:
				size = ccs_del_address_group(p->element);
				break;
			case CCS_ID_NUMBER_GROUP_MEMBER:
				size = ccs_del_number_group_member(p->element);
				break;
			case CCS_ID_NUMBER_GROUP:
				size = ccs_del_number_group(p->element);
				break;
			case CCS_ID_RESERVEDPORT:
				size = ccs_del_reservedport(p->element);
				break;
			case CCS_ID_ACL:
				size = ccs_del_acl(p->element);
				break;
			case CCS_ID_DOMAIN:
				size = ccs_del_domain(p->element);
				if (!size)
					continue;
				break;
			default:
				size = 0;
				printk(KERN_WARNING "Unknown type\n");
				break;
			}
			ccs_memory_free(p->element, size);
			list_del(&p->list);
			kfree(p);
		}
	}
 done:
	mutex_unlock(&ccs_gc_mutex);
 out:
	do_exit(0);
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

#ifndef _LINUX_SRCU_H

static DEFINE_SPINLOCK(ccs_counter_lock);

int srcu_read_lock(struct srcu_struct *sp)
{
	int idx;
	spin_lock(&ccs_counter_lock);
	idx = sp->counter_idx;
	sp->counter[idx]++;
	spin_unlock(&ccs_counter_lock);
	return idx;
}

void srcu_read_unlock(struct srcu_struct *sp, const int idx)
{
	spin_lock(&ccs_counter_lock);
	sp->counter[idx]--;
	spin_unlock(&ccs_counter_lock);
}

void synchronize_srcu(struct srcu_struct *sp)
{
	int idx;
	int v;
	spin_lock(&ccs_counter_lock);
	idx = sp->counter_idx;
	sp->counter_idx ^= 1;
	v = sp->counter[idx];
	spin_unlock(&ccs_counter_lock);
	while (v) {
		ssleep(1);
		spin_lock(&ccs_counter_lock);
		v = sp->counter[idx];
		spin_unlock(&ccs_counter_lock);
	}
}

#endif
