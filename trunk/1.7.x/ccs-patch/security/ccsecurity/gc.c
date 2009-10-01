/*
 * security/ccsecurity/gc.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0   2009/10/01
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
static LIST_HEAD(ccs_gc_queue);
static DEFINE_MUTEX(ccs_gc_mutex);

/* Caller holds ccs_policy_lock mutex. */
static bool ccs_add_to_gc(const int type, void *element)
{
	struct ccs_gc_entry *entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return false;
	entry->type = type;
	entry->element = element;
	list_add(&entry->list, &ccs_gc_queue);
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
	read_lock(&tasklist_lock);
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
	read_unlock(&tasklist_lock);
#else
	struct task_struct *p;
	read_lock(&tasklist_lock);
	for_each_process(p) {
		if (!(p->ccs_flags & CCS_TASK_IS_IN_EXECVE)) {
			smp_mb(); /* Avoid out of order execution. */
			if (p->ccs_domain_info != domain)
				continue;
		}
		in_use = true;
		break;
	}
	read_unlock(&tasklist_lock);
#endif
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

/*
 * 2.6.19 has SRCU support but it triggers general protection fault in my
 * environment. Thus, I use SRCU for 2.6.20 and later.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)

/* Lock for GC. */
static struct srcu_struct ccs_ss;

/**
 * ccs_gc_init - Initialize garbage collector.
 *
 * Returns 0.
 */
static int __init ccs_gc_init(void)
{
	if (init_srcu_struct(&ccs_ss))
		panic("Out of memory.");
	return 0;
}
core_initcall(ccs_gc_init);

int ccs_read_lock(void)
{
	return srcu_read_lock(&ccs_ss);
}

void ccs_read_unlock(const int idx)
{
	srcu_read_unlock(&ccs_ss, idx);
}

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

static int ccs_gc_thread(void *unused)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	daemonize("GC for CCS");
#else
	daemonize();
	reparent_to_init();
#endif
	if (!mutex_trylock(&ccs_gc_mutex))
		goto out;
	mutex_lock(&ccs_policy_lock);
	{
		struct ccs_globally_readable_file_entry *ptr;
		list_for_each_entry_rcu(ptr, &ccs_globally_readable_list,
					list) {
			if (!ptr->is_deleted)
				continue;
			if (ccs_add_to_gc(CCS_ID_GLOBALLY_READABLE, ptr))
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
			if (ccs_add_to_gc(CCS_ID_GLOBAL_ENV, ptr))
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
			if (ccs_add_to_gc(CCS_ID_PATTERN, ptr))
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
			if (ccs_add_to_gc(CCS_ID_NO_REWRITE, ptr))
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
			if (ccs_add_to_gc(CCS_ID_DOMAIN_INITIALIZER, ptr))
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
			if (ccs_add_to_gc(CCS_ID_DOMAIN_KEEPER, ptr))
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
			if (ccs_add_to_gc(CCS_ID_MANAGER, ptr))
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
			if (ccs_add_to_gc(CCS_ID_AGGREGATOR, ptr))
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
				if (ccs_add_to_gc(CCS_ID_ACL, acl))
					list_del_rcu(&acl->list);
				else
					break;
			}
			if (!domain->is_deleted ||
			    ccs_used_by_task(domain))
				continue;
			if (ccs_add_to_gc(CCS_ID_DOMAIN, domain))
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
						  member))
					list_del_rcu(&member->list);
				else
					break;
			}
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->users))
				continue;
			if (ccs_add_to_gc(CCS_ID_PATH_GROUP, group))
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
						  member))
					list_del_rcu(&member->list);
				else
					break;
			}
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->users))
				continue;
			if (ccs_add_to_gc(CCS_ID_ADDRESS_GROUP, group))
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
						  member))
					list_del_rcu(&member->list);
				else
					break;
			}
			if (!list_empty(&group->member_list) ||
			    atomic_read(&group->users))
				continue;
			if (ccs_add_to_gc(CCS_ID_NUMBER_GROUP, group))
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
			if (ccs_add_to_gc(CCS_ID_RESERVEDPORT, ptr))
				list_del_rcu(&ptr->list);
			else
				break;
		}
	}
	mutex_unlock(&ccs_policy_lock);
	if (list_empty(&ccs_gc_queue))
		goto done;
	ccs_synchronize_srcu();
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
