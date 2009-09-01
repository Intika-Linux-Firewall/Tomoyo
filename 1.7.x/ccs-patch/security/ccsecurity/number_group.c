/*
 * security/ccsecurity/number_group.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-rc   2009/09/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/slab.h>
#include "internal.h"

/* The list for "struct ccs_number_group". */
LIST_HEAD(ccs_number_group_list);

/**
 * ccs_get_number_group - Allocate memory for "struct ccs_number_group".
 *
 * @group_name: The name of number group.
 *
 * Returns pointer to "struct ccs_number_group" on success,
 * NULL otherwise.
 */
struct ccs_number_group *ccs_get_number_group(const char *group_name)
{
	struct ccs_number_group *entry = NULL;
	struct ccs_number_group *group;
	const struct ccs_path_info *saved_group_name;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(group_name, 0, 0, 0) ||
	    !group_name[0])
		return NULL;
	saved_group_name = ccs_get_name(group_name);
	if (!saved_group_name)
		return NULL;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(group, &ccs_number_group_list, list) {
		if (saved_group_name != group->group_name)
			continue;
		atomic_inc(&group->users);
		error = 0;
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		INIT_LIST_HEAD(&entry->member_list);
		entry->group_name = saved_group_name;
		saved_group_name = NULL;
		atomic_set(&entry->users, 1);
		list_add_tail_rcu(&entry->list, &ccs_number_group_list);
		group = entry;
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(saved_group_name);
	kfree(entry);
	return !error ? group : NULL;
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
					 &group->member_list, list) {
			if (!member->is_deleted)
				break;
			list_del(&member->list);
			list_add(&member->list, &q);
		}
		if (list_empty(&group->member_list)) {
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

/**
 * ccs_write_number_group_policy - Write "struct ccs_number_group" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, nagative value otherwise.
 */
int ccs_write_number_group_policy(char *data, const bool is_delete)
{
	struct ccs_number_group *group;
	struct ccs_number_group_member *entry = NULL;
	struct ccs_number_group_member e = { };
	struct ccs_number_group_member *member;
	int error = is_delete ? -ENOENT : -ENOMEM;
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)))
		return -EINVAL;
	if (!ccs_parse_number_union(w[1], &e.number))
		return -EINVAL;
	if (e.number.is_group || e.number.values[0] > e.number.values[1]) {
		ccs_put_number_union(&e.number);
		return -EINVAL;
	}
	group = ccs_get_number_group(w[0]);
	if (!group)
		return -ENOMEM;
	if (!is_delete)
		entry = kmalloc(sizeof(e), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(member, &group->member_list, list) {
		if (memcmp(&member->number, &e.number, sizeof(e.number)))
			continue;
		member->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_commit_ok(entry, &e, sizeof(e))) {
		list_add_tail_rcu(&entry->list, &group->member_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_number_group(group);
	kfree(entry);
	return error;
}

/**
 * ccs_read_number_group_policy - Read "struct ccs_number_group" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_number_group_policy(struct ccs_io_buffer *head)
{
	struct list_head *gpos;
	struct list_head *mpos;
	bool done = true;
	list_for_each_cookie(gpos, head->read_var1, &ccs_number_group_list) {
		struct ccs_number_group *group;
		const char *name;
		group = list_entry(gpos, struct ccs_number_group, list);
		name = group->group_name->name;
		list_for_each_cookie(mpos, head->read_var2,
				     &group->member_list) {
			int pos;
			const struct ccs_number_group_member *member
				= list_entry(mpos,
					     struct ccs_number_group_member,
					     list);
			if (member->is_deleted)
				continue;
			pos = head->read_avail;
			if (!ccs_io_printf(head, CCS_KEYWORD_NUMBER_GROUP "%s",
					   name) ||
			    !ccs_print_number_union(head, &member->number) ||
			    !ccs_io_printf(head, "\n")) {
				head->read_avail = pos;
				done = false;
				break;
			}
		}
	}
	return done;
}

/**
 * ccs_number_matches_group - Check whether the given number matches members of the given number group.
 *
 * @min:   Min number.
 * @max:   Max number.
 * @group: Pointer to "struct ccs_number_group".
 *
 * Returns true if @min and @max partially overlaps @group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_number_matches_group(const unsigned long min, const unsigned long max,
			      const struct ccs_number_group *group)
{
	struct ccs_number_group_member *member;
	bool matched = false;
	list_for_each_entry_rcu(member, &group->member_list, list) {
		if (member->is_deleted)
			continue;
		if (min > member->number.values[1] ||
		    max < member->number.values[0])
			continue;
		matched = true;
		break;
	}
	return matched;
}
