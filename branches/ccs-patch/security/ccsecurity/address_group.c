/*
 * security/ccsecurity/address_group.c
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

static bool ccs_is_same_address_group(const struct ccs_acl_head *a,
				      const struct ccs_acl_head *b)
{
	const struct ccs_address_group *p1 = container_of(a, typeof(*p1),
							  head);
	const struct ccs_address_group *p2 = container_of(b, typeof(*p2),
							  head);
	return p1->is_ipv6 == p2->is_ipv6 &&
		p1->min.ipv4 == p2->min.ipv4 && p1->min.ipv6 == p2->min.ipv6 &&
		p1->max.ipv4 == p2->max.ipv4 && p1->max.ipv6 == p2->max.ipv6;
}

/**
 * ccs_write_address_group_policy - Write "struct ccs_address_group" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_address_group_policy(char *data, const bool is_delete)
{
	struct ccs_group *group;
	struct ccs_address_group e = { };
	int error = -ENOMEM;
	u16 min_address[8];
	u16 max_address[8];
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	group = ccs_get_address_group(w[0]);
	if (!group)
		return -ENOMEM;
	switch (ccs_parse_ip_address(w[1], min_address, max_address)) {
	case CCS_IP_ADDRESS_TYPE_IPv6:
		e.is_ipv6 = true;
		e.min.ipv6 = ccs_get_ipv6_address((struct in6_addr *)
						  min_address);
		e.max.ipv6 = ccs_get_ipv6_address((struct in6_addr *)
						  max_address);
		if (!e.min.ipv6 || !e.max.ipv6)
			goto out;
		break;
	case CCS_IP_ADDRESS_TYPE_IPv4:
		e.min.ipv4 = ntohl(*(u32 *) min_address);
		e.max.ipv4 = ntohl(*(u32 *) max_address);
		break;
	default:
		goto out;
	}
	error = ccs_update_group(&e.head, sizeof(e), is_delete, group,
				 ccs_is_same_address_group);
 out:
	if (e.is_ipv6) {
		ccs_put_ipv6_address(e.min.ipv6);
		ccs_put_ipv6_address(e.max.ipv6);
	}
	ccs_put_group(group);
	return error;
}

/**
 * ccs_address_matches_group - Check whether the given address matches members of the given address group.
 *
 * @is_ipv6: True if @address is an IPv6 address.
 * @address: An IPv4 or IPv6 address.
 * @group:   Pointer to "struct ccs_address_group".
 *
 * Returns true if @address matches addresses in @group group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_address_matches_group(const bool is_ipv6, const u32 *address,
			       const struct ccs_group *group)
{
	struct ccs_address_group *member;
	const u32 ip = ntohl(*address);
	bool matched = false;
	list_for_each_entry_rcu(member, &group->member_list, head.list) {
		if (member->head.is_deleted)
			continue;
		if (member->is_ipv6) {
			if (is_ipv6 &&
			    memcmp(member->min.ipv6, address, 16) <= 0 &&
			    memcmp(address, member->max.ipv6, 16) <= 0) {
				matched = true;
				break;
			}
		} else {
			if (!is_ipv6 &&
			    member->min.ipv4 <= ip && ip <= member->max.ipv4) {
				matched = true;
				break;
			}
		}
	}
	return matched;
}
