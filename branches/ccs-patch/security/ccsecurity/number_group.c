/*
 * security/ccsecurity/number_group.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2   2010/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/slab.h>
#include "internal.h"

static bool ccs_is_same_number_group(const struct ccs_acl_head *a,
				     const struct ccs_acl_head *b)
{
	return !memcmp(&container_of(a, struct ccs_number_group, head)->number,
		       &container_of(b, struct ccs_number_group, head)->number,
		       sizeof(container_of(a, struct ccs_number_group, head)
			      ->number));
}

/**
 * ccs_write_number_group_policy - Write "struct ccs_number_group" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, nagative value otherwise.
 */
int ccs_write_number_group_policy(char *data, const bool is_delete, const u8 flags)
{
	struct ccs_group *group;
	struct ccs_number_group e = { };
	int error;
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)))
		return -EINVAL;
	if (!ccs_parse_number_union(w[1], &e.number))
		return -EINVAL;
	if (e.number.is_group || e.number.values[0] > e.number.values[1]) {
		ccs_put_number_union(&e.number);
		return -EINVAL;
	}
	group = ccs_get_group(w[0], CCS_NUMBER_GROUP);
	if (!group)
		return -ENOMEM;
	error = ccs_update_group(&e.head, sizeof(e), is_delete, group,
				 ccs_is_same_number_group);
	ccs_put_group(group);
	return error;
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
			      const struct ccs_group *group)
{
	struct ccs_number_group *member;
	bool matched = false;
	list_for_each_entry_rcu(member, &group->member_list, head.list) {
		if (member->head.is_deleted)
			continue;
		if (min > member->number.values[1] ||
		    max < member->number.values[0])
			continue;
		matched = true;
		break;
	}
	return matched;
}
