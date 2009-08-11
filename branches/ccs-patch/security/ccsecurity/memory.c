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

#include "internal.h"

static atomic_t ccs_non_string_memory_size;
static unsigned int ccs_quota_for_non_string;

/**
 * ccs_memory_ok - Check memory quota.
 *
 * @ptr:  Pointer to allocated memory.
 * @size: Size in byte.
 *
 * Returns true if @ptr is not NULL and quota not exceeded, false otehrwise.
 */
bool ccs_memory_ok(const void *ptr, const unsigned int size)
{
	atomic_add(size, &ccs_non_string_memory_size);
	if (ptr && (!ccs_quota_for_non_string ||
		    atomic_read(&ccs_non_string_memory_size)
		    <= ccs_quota_for_non_string))
		return true;
	atomic_sub(size, &ccs_non_string_memory_size);
	printk(KERN_WARNING "ERROR: Out of memory. (%s)\n", __func__);
	if (!ccs_policy_loaded)
		panic("MAC Initialization failed.\n");
	return false;
}

/**
 * ccs_memory_free - Free memory for elements.
 *
 * @ptr:  Pointer to allocated memory.
 * @size: Size in byte.
 */
void ccs_memory_free(const void *ptr, size_t size)
{
	atomic_sub(size, &ccs_non_string_memory_size);
	kfree(ptr);
}

/**
 * ccs_put_path_group - Delete memory for "struct ccs_path_group".
 *
 * @group: Pointer to "struct ccs_path_group".
 */
void ccs_put_path_group(struct ccs_path_group *group)
{
	struct ccs_path_group_member *member;
	struct ccs_path_group_member *next_member;
	LIST_HEAD(q);
	bool can_delete_group = false;
	if (!group)
		return;
	mutex_lock(&ccs_policy_lock);
	if (atomic_dec_and_test(&group->users)) {
		list_for_each_entry_safe(member, next_member,
					 &group->path_group_member_list,
					 list) {
			if (!member->is_deleted)
				break;
			list_del(&member->list);
			list_add(&member->list, &q);
		}
		if (list_empty(&group->path_group_member_list)) {
			list_del(&group->list);
			can_delete_group = true;
		}
	}
	mutex_unlock(&ccs_policy_lock);
	list_for_each_entry_safe(member, next_member, &q, list) {
		list_del(&member->list);
		ccs_put_name(member->member_name);
		ccs_memory_free(member, sizeof(*member));
	}
	if (can_delete_group) {
		ccs_put_name(group->group_name);
		ccs_memory_free(group, sizeof(*group));
	}
}

/**
 * ccs_put_address_group - Delete memory for "struct ccs_address_group_entry".
 *
 * @group: Pointer to "struct ccs_address_group_entry".
 */
void ccs_put_address_group(struct ccs_address_group_entry *group)
{
	struct ccs_address_group_member *member;
	struct ccs_address_group_member *next_member;
	LIST_HEAD(q);
	bool can_delete_group = false;
	if (!group)
		return;
	mutex_lock(&ccs_policy_lock);
	if (atomic_dec_and_test(&group->users)) {
		list_for_each_entry_safe(member, next_member,
					 &group->address_group_member_list,
					 list) {
			if (!member->is_deleted)
				break;
			list_del(&member->list);
			list_add(&member->list, &q);
		}
		if (list_empty(&group->address_group_member_list)) {
			list_del(&group->list);
			can_delete_group = true;
		}
	}
	mutex_unlock(&ccs_policy_lock);
	list_for_each_entry_safe(member, next_member, &q, list) {
		list_del(&member->list);
		if (member->is_ipv6) {
			ccs_put_ipv6_address(member->min.ipv6);
			ccs_put_ipv6_address(member->max.ipv6);
		}
		ccs_memory_free(member, sizeof(*member));
	}
	if (can_delete_group) {
		ccs_put_name(group->group_name);
		ccs_memory_free(group, sizeof(*group));
	}
}

/**
 * ccs_put_number_group - Delete memory for "struct ccs_number_group".
 *
 * @group: Pointer to "struct ccs_number_group".
 */
void ccs_put_number_group(struct ccs_number_group *group)
{
	struct ccs_number_group_member *member;
	struct ccs_number_group_member *next_member;
	LIST_HEAD(q);
	bool can_delete_group = false;
	if (!group)
		return;
	mutex_lock(&ccs_policy_lock);
	if (atomic_dec_and_test(&group->users)) {
		list_for_each_entry_safe(member, next_member,
					 &group->number_group_member_list,
					 list) {
			if (!member->is_deleted)
				break;
			list_del(&member->list);
			list_add(&member->list, &q);
		}
		if (list_empty(&group->number_group_member_list)) {
			list_del(&group->list);
			can_delete_group = true;
		}
	}
	mutex_unlock(&ccs_policy_lock);
	list_for_each_entry_safe(member, next_member, &q, list) {
		list_del(&member->list);
		ccs_memory_free(member, sizeof(*member));
	}
	if (can_delete_group) {
		ccs_put_name(group->group_name);
		ccs_memory_free(group, sizeof(*group));
	}
}

static LIST_HEAD(ccs_address_list);

/**
 * ccs_get_ipv6_address - Keep the given IPv6 address on the RAM.
 *
 * @addr: Pointer to "struct in6_addr".
 *
 * Returns pointer to "struct in6_addr" on success, NULL otherwise.
 *
 * The RAM is shared, so NEVER try to modify or kfree() the returned address.
 */
const struct in6_addr *ccs_get_ipv6_address(const struct in6_addr *addr)
{
	struct ccs_ipv6addr_entry *entry;
	struct ccs_ipv6addr_entry *ptr;
	int error = -ENOMEM;
	if (!addr)
		return NULL;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry(ptr, &ccs_address_list, list) {
		if (memcmp(&ptr->addr, addr, sizeof(*addr)))
			continue;
		atomic_inc(&ptr->users);
		error = 0;
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		ptr = entry;
		ptr->addr = *addr;
		atomic_set(&ptr->users, 1);
		list_add_tail(&ptr->list, &ccs_address_list);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	kfree(entry);
	return ptr ? &ptr->addr : NULL;
}

/**
 * ccs_put_ipv6_address - Delete the given IPv6 address on the RAM.
 *
 * @addr: Pointer to "struct in6_addr".
 */
void ccs_put_ipv6_address(const struct in6_addr *addr)
{
	struct ccs_ipv6addr_entry *ptr;
	bool can_delete = false;
	if (!addr)
		return;
	ptr = container_of(addr, struct ccs_ipv6addr_entry, addr);
	mutex_lock(&ccs_policy_lock);
	if (atomic_dec_and_test(&ptr->users)) {
		list_del(&ptr->list);
		can_delete = true;
	}
	mutex_unlock(&ccs_policy_lock);
	if (can_delete)
		ccs_memory_free(ptr, sizeof(*ptr));
}

/**
 * ccs_put_condition - Delete memory for "struct ccs_condition".
 *
 * @cond: Pointer to "struct ccs_condition".
 */
void ccs_put_condition(struct ccs_condition *cond)
{
	const struct ccs_condition_element *condp;
	struct ccs_number_union *numbers_p;
	struct ccs_name_union *names_p;
	const struct ccs_argv_entry *argv;
	const struct ccs_envp_entry *envp;
	u16 condc;
	u16 numbers_count;
	u16 names_count;
	u16 argc;
	u16 envc;
	u16 i;
	bool can_delete = false;
	if (!cond)
		return;
	mutex_lock(&ccs_policy_lock);
	if (atomic_dec_and_test(&cond->users)) {
		list_del(&cond->list);
		can_delete = true;
	}
	mutex_unlock(&ccs_policy_lock);
	if (!can_delete)
		return;
	condc = cond->condc;
	numbers_count = cond->numbers_count;
	names_count = cond->names_count;
	argc = cond->argc;
	envc = cond->envc;
	condp = (const struct ccs_condition_element *) (cond + 1);
	numbers_p = (struct ccs_number_union *) (condp + condc);
	names_p = (struct ccs_name_union *) (numbers_p + numbers_count);
	argv = (const struct ccs_argv_entry *) (names_p + names_count);
	envp = (const struct ccs_envp_entry *) (argv + argc);
	for (i = 0; i < cond->numbers_count; i++)
		ccs_put_number_union(numbers_p++);
	for (i = 0; i < cond->names_count; i++)
		ccs_put_name_union(names_p++);
	for (i = 0; i < argc; argv++, i++)
		ccs_put_name(argv->value);
	for (i = 0; i < envc; envp++, i++) {
		ccs_put_name(envp->name);
		ccs_put_name(envp->value);
	}
	ccs_memory_free(cond, cond->size);
}

static unsigned int ccs_string_memory_size;
static unsigned int ccs_quota_for_string;

#define CCS_MAX_HASH 256

/* Structure for string data. */
struct ccs_name_entry {
	struct list_head list;
	atomic_t users;
	int size;
	struct ccs_path_info entry;
};

/* The list for "struct ccs_name_entry". */
static struct list_head ccs_name_list[CCS_MAX_HASH];
static DEFINE_MUTEX(ccs_name_list_lock);

/**
 * ccs_get_name - Allocate memory for string data.
 *
 * @name: The string to store into the permernent memory.
 *
 * Returns pointer to "struct ccs_path_info" on success, NULL otherwise.
 */
const struct ccs_path_info *ccs_get_name(const char *name)
{
	struct ccs_name_entry *ptr;
	unsigned int hash;
	int len;
	int allocated_len;

	if (!name)
		return NULL;
	len = strlen(name) + 1;
	if (len > CCS_MAX_PATHNAME_LEN) {
		printk(KERN_WARNING "ERROR: Name too long. (%s)\n", __func__);
		return NULL;
	}
	hash = full_name_hash((const unsigned char *) name, len - 1);
	/***** EXCLUSIVE SECTION START *****/
	mutex_lock(&ccs_name_list_lock);
	list_for_each_entry(ptr, &ccs_name_list[hash % CCS_MAX_HASH], list) {
		if (hash != ptr->entry.hash || strcmp(name, ptr->entry.name))
			continue;
		atomic_inc(&ptr->users);
		goto out;
	}
	ptr = kzalloc(sizeof(*ptr) + len, GFP_KERNEL);
	allocated_len = ptr ? sizeof(*ptr) + len : 0;
	ccs_string_memory_size += allocated_len;
	if (!allocated_len ||
	    (ccs_quota_for_string &&
	     ccs_string_memory_size > ccs_quota_for_string)) {
		ccs_string_memory_size -= allocated_len;
		kfree(ptr);
		ptr = NULL;
		printk(KERN_WARNING "ERROR: Out of memory. (%s)\n", __func__);
		if (!ccs_policy_loaded)
			panic("MAC Initialization failed.\n");
		goto out;
	}
	ptr->entry.name = ((char *) ptr) + sizeof(*ptr);
	memmove((char *) ptr->entry.name, name, len);
	atomic_set(&ptr->users, 1);
	ccs_fill_path_info(&ptr->entry);
	ptr->size = allocated_len;
	list_add_tail(&ptr->list, &ccs_name_list[hash % CCS_MAX_HASH]);
 out:
	mutex_unlock(&ccs_name_list_lock);
	/***** EXCLUSIVE SECTION END *****/
	return ptr ? &ptr->entry : NULL;
}

/**
 * ccs_put_name - Delete shared memory for string data.
 *
 * @name: Pointer to "struct ccs_path_info".
 */
void ccs_put_name(const struct ccs_path_info *name)
{
	struct ccs_name_entry *ptr;
	bool can_delete = false;
	if (!name)
		return;
	ptr = container_of(name, struct ccs_name_entry, entry);
	/***** EXCLUSIVE SECTION START *****/
	mutex_lock(&ccs_name_list_lock);
	if (atomic_dec_and_test(&ptr->users)) {
		list_del(&ptr->list);
		ccs_string_memory_size -= ptr->size;
		can_delete = true;
	}
	mutex_unlock(&ccs_name_list_lock);
	/***** EXCLUSIVE SECTION END *****/
	if (can_delete)
		kfree(ptr);
}

struct srcu_struct ccs_ss;

/**
 * ccs_realpath_init - Initialize realpath related code.
 *
 * Returns 0.
 */
static int __init ccs_realpath_init(void)
{
	int i;
	/* Constraint for ccs_get_name(). */
	if (CCS_MAX_PATHNAME_LEN > PAGE_SIZE)
		panic("Bad size.");
	/* Constraint for "struct ccs_execve_entry"->tmp users. */
	if (CCS_MAX_PATHNAME_LEN > CCS_EXEC_TMPSIZE)
		panic("Bad size.");
	if (init_srcu_struct(&ccs_ss))
		panic("Out of memory.");
	for (i = 0; i < CCS_MAX_HASH; i++)
		INIT_LIST_HEAD(&ccs_name_list[i]);
	INIT_LIST_HEAD(&ccs_kernel_domain.acl_info_list);
	ccs_kernel_domain.domainname = ccs_get_name(ROOT_NAME);
	list_add_tail_rcu(&ccs_kernel_domain.list, &ccs_domain_list);
	if (ccs_find_domain(ROOT_NAME) != &ccs_kernel_domain)
		panic("Can't register ccs_kernel_domain");
#ifdef CONFIG_CCSECURITY_BUILTIN_INITIALIZERS
	{
		/* Load built-in policy. */
		static char ccs_builtin_initializers[] __initdata
			= CONFIG_CCSECURITY_BUILTIN_INITIALIZERS;
		char *cp = ccs_builtin_initializers;
		ccs_normalize_line(cp);
		while (cp && *cp) {
			char *cp2 = strchr(cp, ' ');
			if (cp2)
				*cp2++ = '\0';
			ccs_write_domain_initializer_policy(cp, false, false);
			cp = cp2;
		}
	}
#endif
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
__initcall(ccs_realpath_init);
#else
core_initcall(ccs_realpath_init);
#endif

unsigned int ccs_audit_log_memory_size;
unsigned int ccs_quota_for_audit_log;

unsigned int ccs_query_memory_size;
unsigned int ccs_quota_for_query;

/**
 * ccs_read_memory_counter - Check for memory usage.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns memory usage.
 */
int ccs_read_memory_counter(struct ccs_io_buffer *head)
{
	if (!head->read_eof) {
		const unsigned int string = ccs_string_memory_size;
		const unsigned int nonstring
			= atomic_read(&ccs_non_string_memory_size);
		const unsigned int audit_log = ccs_audit_log_memory_size;
		const unsigned int query = ccs_query_memory_size;
		char buffer[64];
		memset(buffer, 0, sizeof(buffer));
		if (ccs_quota_for_string)
			snprintf(buffer, sizeof(buffer) - 1,
				 "   (Quota: %10u)", ccs_quota_for_string);
		else
			buffer[0] = '\0';
		ccs_io_printf(head, "Policy (string):         %10u%s\n",
			      string, buffer);
		if (ccs_quota_for_non_string)
			snprintf(buffer, sizeof(buffer) - 1,
				 "   (Quota: %10u)", ccs_quota_for_non_string);
		else
			buffer[0] = '\0';
		ccs_io_printf(head, "Policy (non-string):     %10u%s\n",
			      nonstring, buffer);
		if (ccs_quota_for_audit_log)
			snprintf(buffer, sizeof(buffer) - 1,
				 "   (Quota: %10u)", ccs_quota_for_audit_log);
		else
			buffer[0] = '\0';
		ccs_io_printf(head, "Audit logs:              %10u%s\n",
			      audit_log, buffer);
		if (ccs_quota_for_query)
			snprintf(buffer, sizeof(buffer) - 1,
				 "   (Quota: %10u)", ccs_quota_for_query);
		else
			buffer[0] = '\0';
		ccs_io_printf(head, "Interactive enforcement: %10u%s\n",
			      query, buffer);
		ccs_io_printf(head, "Total:                   %10u\n",
			      string + nonstring + audit_log + query);
		head->read_eof = true;
	}
	return 0;
}

/**
 * ccs_write_memory_quota - Set memory quota.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
int ccs_write_memory_quota(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	unsigned int size;
	if (sscanf(data, "Policy (string): %u", &size) == 1)
		ccs_quota_for_string = size;
	else if (sscanf(data, "Policy (non-string): %u", &size) == 1)
		ccs_quota_for_non_string = size;
	else if (sscanf(data, "Audit logs: %u", &size) == 1)
		ccs_quota_for_audit_log = size;
	else if (sscanf(data, "Interactive enforcement: %u", &size) == 1)
		ccs_quota_for_query = size;
	return 0;
}
