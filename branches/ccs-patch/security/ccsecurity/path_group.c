/*
 * security/ccsecurity/path_group.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2   2010/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

static bool ccs_is_same_path_group(const struct ccs_acl_head *a,
				   const struct ccs_acl_head *b)
{
	return container_of(a, struct ccs_path_group, head)->member_name ==
		container_of(b, struct ccs_path_group, head)->member_name;
}

/**
 * ccs_write_path_group_policy - Write "struct ccs_path_group" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, nagative value otherwise.
 */
int ccs_write_path_group_policy(char *data, const bool is_delete, const u8 flags)
{
	struct ccs_group *group;
	struct ccs_path_group e = { };
	int error;
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	group = ccs_get_group(w[0], CCS_PATH_GROUP);
	if (!group)
		return -ENOMEM;
	e.member_name = ccs_get_name(w[1]);
	if (e.member_name)
		error = ccs_update_group(&e.head, sizeof(e), is_delete, group,
					 ccs_is_same_path_group);
	else
		error = -ENOMEM;
 	ccs_put_name(e.member_name);
	ccs_put_group(group);
	return error;
}

/**
 * ccs_path_matches_group - Check whether the given pathname matches members of the given pathname group.
 *
 * @pathname:        The name of pathname.
 * @group:           Pointer to "struct ccs_path_group".
 * @may_use_pattern: True if wild card is permitted.
 *
 * Returns true if @pathname matches pathnames in @group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_path_matches_group(const struct ccs_path_info *pathname,
			    const struct ccs_group *group,
			    const bool may_use_pattern)
{
	struct ccs_path_group *member;
	bool matched = false;
	list_for_each_entry_rcu(member, &group->member_list, head.list) {
		if (member->head.is_deleted)
			continue;
		if (!member->member_name->is_patterned) {
			if (ccs_pathcmp(pathname, member->member_name))
				continue;
		} else if (may_use_pattern) {
			if (!ccs_path_matches_pattern(pathname,
						      member->member_name))
				continue;
		} else
			continue;
		matched = true;
		break;
	}
	return matched;
}
