/*
 * security/ccsecurity/network.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include "internal.h"

/* Index numbers for Network Controls. */
enum ccs_network_acl_index {
	CCS_NETWORK_ACL_UDP_BIND,
	CCS_NETWORK_ACL_UDP_CONNECT,
	CCS_NETWORK_ACL_TCP_BIND,
	CCS_NETWORK_ACL_TCP_LISTEN,
	CCS_NETWORK_ACL_TCP_CONNECT,
	CCS_NETWORK_ACL_TCP_ACCEPT,
	CCS_NETWORK_ACL_RAW_BIND,
	CCS_NETWORK_ACL_RAW_CONNECT
};

/**
 * ccs_audit_network_log - Audit network log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @address:    An IPv4 or IPv6 address.
 * @port:       Port number.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_network_log(struct ccs_request_info *r,
				 const char *operation, const char *address,
				 const u16 port, const bool is_granted)
{
	if (!is_granted && ccs_verbose_mode(r->domain))
		printk(KERN_WARNING "TOMOYO-%s: %s to %s %u denied for %s\n",
		       ccs_get_msg(r->mode == 3), operation, address, port,
		       ccs_get_last_name(r->domain));
	return ccs_write_audit_log(is_granted, r, CCS_KEYWORD_ALLOW_NETWORK
				   "%s %s %u\n", operation, address, port);
}

/* The list for "struct ccs_address_group_entry". */
LIST_HEAD(ccs_address_group_list);

/**
 * ccs_get_address_group - Allocate memory for "struct ccs_address_group_entry".
 *
 * @group_name: The name of address group.
 *
 * Returns pointer to "struct ccs_address_group_entry" on success,
 * NULL otherwise.
 */
static struct ccs_address_group_entry *ccs_get_address_group(const char *
							     group_name)
{
	struct ccs_address_group_entry *entry = NULL;
	struct ccs_address_group_entry *group;
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
	list_for_each_entry_rcu(group, &ccs_address_group_list, list) {
		if (saved_group_name != group->group_name)
			continue;
		atomic_inc(&group->users);
		error = 0;
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		INIT_LIST_HEAD(&entry->address_group_member_list);
		entry->group_name = saved_group_name;
		saved_group_name = NULL;
		atomic_set(&entry->users, 1);
		list_add_tail_rcu(&entry->list, &ccs_address_group_list);
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
 * ccs_parse_ip_address - Parse an IP address.
 *
 * @address: String to parse.
 * @min:     Pointer to store min address.
 * @max:     Pointer to store max address.
 *
 * Returns 2 if @address is an IPv6, 1 if @address is an IPv4, 0 otherwise.
 */
static int ccs_parse_ip_address(char *address, u16 *min, u16 *max)
{
	int count = sscanf(address, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx"
			   "-%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
			   &min[0], &min[1], &min[2], &min[3],
			   &min[4], &min[5], &min[6], &min[7],
			   &max[0], &max[1], &max[2], &max[3],
			   &max[4], &max[5], &max[6], &max[7]);
	if (count == 8 || count == 16) {
		u8 i;
		if (count == 8)
			memmove(max, min, sizeof(u16) * 8);
		for (i = 0; i < 8; i++) {
			min[i] = htons(min[i]);
			max[i] = htons(max[i]);
		}
		return 2;
	}
	count = sscanf(address, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
		       &min[0], &min[1], &min[2], &min[3],
		       &max[0], &max[1], &max[2], &max[3]);
	if (count == 4 || count == 8) {
		u32 ip = htonl((((u8) min[0]) << 24) + (((u8) min[1]) << 16)
			       + (((u8) min[2]) << 8) + (u8) min[3]);
		memmove(min, &ip, sizeof(ip));
		if (count == 8)
			ip = htonl((((u8) max[0]) << 24) + (((u8) max[1]) << 16)
				   + (((u8) max[2]) << 8) + (u8) max[3]);
		memmove(max, &ip, sizeof(ip));
		return 1;
	}
	return 0;
}

/**
 * ccs_update_address_group_entry - Update "struct ccs_address_group_entry" list.
 *
 * @group_name:  The name of address group.
 * @address:     IP address.
 * @is_delete:   True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_address_group_entry(const char *group_name,
					  char *address, const bool is_delete)
{
	struct ccs_address_group_entry *group;
	struct ccs_address_group_member *entry = NULL;
	struct ccs_address_group_member *member;
	const struct in6_addr *saved_min_address = NULL;
	const struct in6_addr *saved_max_address = NULL;
	int error = is_delete ? -ENOENT : -ENOMEM;
	u32 min_ipv4_address = 0;
	u32 max_ipv4_address = 0;
	u16 min_address[8];
	u16 max_address[8];
	bool is_ipv6 = false;
	group = ccs_get_address_group(group_name);
	if (!group)
		return -ENOMEM;
	switch (ccs_parse_ip_address(address, min_address, max_address)) {
	case 2:
		is_ipv6 = true;
		saved_min_address
			= ccs_get_ipv6_address((struct in6_addr *)
					       min_address);
		saved_max_address
			= ccs_get_ipv6_address((struct in6_addr *)
					       max_address);
		if (!saved_min_address || !saved_max_address)
			goto out;
		break;
	case 1:
		min_ipv4_address = ntohl(*(u32 *) min_address);
		max_ipv4_address = ntohl(*(u32 *) max_address);
		break;
	default:
		goto out;
	}
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(member, &group->address_group_member_list,
				list) {
		if (member->is_ipv6 != is_ipv6)
			continue;
		if (is_ipv6) {
			if (member->min.ipv6 != saved_min_address ||
			    member->max.ipv6 != saved_max_address)
				continue;
		} else {
			if (member->min.ipv4 != min_ipv4_address ||
			    member->max.ipv4 != max_ipv4_address)
				continue;
		}
		member->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->is_ipv6 = is_ipv6;
		if (is_ipv6) {
			entry->min.ipv6 = saved_min_address;
			saved_min_address = NULL;
			entry->max.ipv6 = saved_max_address;
			saved_max_address = NULL;
		} else {
			entry->min.ipv4 = min_ipv4_address;
			entry->max.ipv4 = max_ipv4_address;
		}
		list_add_tail_rcu(&entry->list,
				  &group->address_group_member_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	ccs_put_ipv6_address(saved_min_address);
	ccs_put_ipv6_address(saved_max_address);
	ccs_put_address_group(group);
	return error;
}

/**
 * ccs_write_address_group_policy - Write "struct ccs_address_group_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_address_group_policy(char *data, const bool is_delete)
{
	char *w[2];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[1][0])
		return -EINVAL;
	return ccs_update_address_group_entry(w[0], w[1], is_delete);
}

/**
 * ccs_address_matches_group - Check whether the given address matches members of the given address group.
 *
 * @is_ipv6: True if @address is an IPv6 address.
 * @address: An IPv4 or IPv6 address.
 * @group:   Pointer to "struct ccs_address_group_entry".
 *
 * Returns true if @address matches addresses in @group group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static bool ccs_address_matches_group(const bool is_ipv6, const u32 *address,
				      const struct ccs_address_group_entry *
				      group)
{
	struct ccs_address_group_member *member;
	const u32 ip = ntohl(*address);
	bool matched = false;
	ccs_check_read_lock();
	list_for_each_entry_rcu(member, &group->address_group_member_list,
				list) {
		if (member->is_deleted)
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

/**
 * ccs_read_address_group_policy - Read "struct ccs_address_group_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_address_group_policy(struct ccs_io_buffer *head)
{
	struct list_head *gpos;
	struct list_head *mpos;
	bool done = true;
	ccs_check_read_lock();
	list_for_each_cookie(gpos, head->read_var1, &ccs_address_group_list) {
		struct ccs_address_group_entry *group;
		group = list_entry(gpos, struct ccs_address_group_entry, list);
		list_for_each_cookie(mpos, head->read_var2,
				     &group->address_group_member_list) {
			char buf[128];
			struct ccs_address_group_member *member;
			member = list_entry(mpos,
					     struct ccs_address_group_member,
					     list);
			if (member->is_deleted)
				continue;
			if (member->is_ipv6) {
				const struct in6_addr *min_address
					= member->min.ipv6;
				const struct in6_addr *max_address
					= member->max.ipv6;
				ccs_print_ipv6(buf, sizeof(buf), min_address);
				if (min_address != max_address) {
					int len;
					char *cp = buf + strlen(buf);
					*cp++ = '-';
					len = strlen(buf);
					ccs_print_ipv6(cp, sizeof(buf) - len,
						       max_address);
				}
			} else {
				const u32 min_address = member->min.ipv4;
				const u32 max_address = member->max.ipv4;
				memset(buf, 0, sizeof(buf));
				snprintf(buf, sizeof(buf) - 1, "%u.%u.%u.%u",
					 HIPQUAD(min_address));
				if (min_address != max_address) {
					const int len = strlen(buf);
					snprintf(buf + len,
						 sizeof(buf) - 1 - len,
						 "-%u.%u.%u.%u",
						 HIPQUAD(max_address));
				}
			}
			done = ccs_io_printf(head, CCS_KEYWORD_ADDRESS_GROUP
					     "%s %s\n", group->group_name->name,
					     buf);
			if (!done)
				break;
		}
		if (!done)
			break;
	}
	return done;
}

#if !defined(NIP6)
#define NIP6(addr)	\
	ntohs((addr).s6_addr16[0]), ntohs((addr).s6_addr16[1]), \
	ntohs((addr).s6_addr16[2]), ntohs((addr).s6_addr16[3]), \
	ntohs((addr).s6_addr16[4]), ntohs((addr).s6_addr16[5]), \
	ntohs((addr).s6_addr16[6]), ntohs((addr).s6_addr16[7])
#endif

/**
 * ccs_print_ipv6 - Print an IPv6 address.
 *
 * @buffer:     Buffer to write to.
 * @buffer_len: Size of @buffer.
 * @ip:         Pointer to "struct in6_addr".
 *
 * Returns nothing.
 */
void ccs_print_ipv6(char *buffer, const int buffer_len,
		    const struct in6_addr *ip)
{
	memset(buffer, 0, buffer_len);
	snprintf(buffer, buffer_len - 1, "%x:%x:%x:%x:%x:%x:%x:%x", NIP6(*ip));
}

/**
 * ccs_net2keyword - Convert network operation index to network operation name.
 *
 * @operation: Type of operation.
 *
 * Returns the name of operation.
 */
const char *ccs_net2keyword(const u8 operation)
{
	const char *keyword = "unknown";
	switch (operation) {
	case CCS_NETWORK_ACL_UDP_BIND:
		keyword = "UDP bind";
		break;
	case CCS_NETWORK_ACL_UDP_CONNECT:
		keyword = "UDP connect";
		break;
	case CCS_NETWORK_ACL_TCP_BIND:
		keyword = "TCP bind";
		break;
	case CCS_NETWORK_ACL_TCP_LISTEN:
		keyword = "TCP listen";
		break;
	case CCS_NETWORK_ACL_TCP_CONNECT:
		keyword = "TCP connect";
		break;
	case CCS_NETWORK_ACL_TCP_ACCEPT:
		keyword = "TCP accept";
		break;
	case CCS_NETWORK_ACL_RAW_BIND:
		keyword = "RAW bind";
		break;
	case CCS_NETWORK_ACL_RAW_CONNECT:
		keyword = "RAW connect";
		break;
	}
	return keyword;
}

/**
 * ccs_update_network_entry - Update "struct ccs_ip_network_acl_record" list.
 *
 * @protocol:    Protocol name.
 * @operation:   Type of operation.
 * @address:     Address.
 * @port:        Port number.
 * @domain:      Pointer to "struct ccs_domain_info".
 * @condition:   Pointer to "struct ccs_condition". May be NULL.
 * @is_delete:   True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_network_entry(const char *protocol,
				    const char *operation, char *address,
				    char *port, struct ccs_domain_info *domain,
				    struct ccs_condition *condition,
				    const bool is_delete)
{
	static const u8 offset = offsetof(struct ccs_ip_network_acl_record,
					  head.cond);
	struct ccs_acl_info *ptr;
	struct ccs_ip_network_acl_record e;
	struct ccs_ip_network_acl_record *entry = NULL;
	u16 min_address[8];
	u16 max_address[8];
	int error = is_delete ? -ENOENT : -ENOMEM;
	u8 sock_type;
	memset(&e, 0, sizeof(e));
	e.head.type = CCS_TYPE_IP_NETWORK_ACL;
	e.head.cond = condition;
	if (!domain)
		return -EINVAL;
	if (!strcmp(protocol, "TCP"))
		sock_type = SOCK_STREAM;
	else if (!strcmp(protocol, "UDP"))
		sock_type = SOCK_DGRAM;
	else if (!strcmp(protocol, "RAW"))
		sock_type = SOCK_RAW;
	else
		return -EINVAL;
	if (!strcmp(operation, "bind"))
		switch (sock_type) {
		case SOCK_STREAM:
			e.operation_type = CCS_NETWORK_ACL_TCP_BIND;
			break;
		case SOCK_DGRAM:
			e.operation_type = CCS_NETWORK_ACL_UDP_BIND;
			break;
		default:
			e.operation_type = CCS_NETWORK_ACL_RAW_BIND;
			break;
		}
	else if (!strcmp(operation, "connect"))
		switch (sock_type) {
		case SOCK_STREAM:
			e.operation_type = CCS_NETWORK_ACL_TCP_CONNECT;
			break;
		case SOCK_DGRAM:
			e.operation_type = CCS_NETWORK_ACL_UDP_CONNECT;
			break;
		default:
			e.operation_type = CCS_NETWORK_ACL_RAW_CONNECT;
			break;
		}
	else if (sock_type == SOCK_STREAM && !strcmp(operation, "listen"))
		e.operation_type = CCS_NETWORK_ACL_TCP_LISTEN;
	else if (sock_type == SOCK_STREAM && !strcmp(operation, "accept"))
		e.operation_type = CCS_NETWORK_ACL_TCP_ACCEPT;
	else
		return -EINVAL;
	switch (ccs_parse_ip_address(address, min_address, max_address)) {
	case 2:
		e.record_type = CCS_IP_RECORD_TYPE_IPv6;
		e.address.ipv6.min = ccs_get_ipv6_address((struct in6_addr *)
							  min_address);
		e.address.ipv6.max = ccs_get_ipv6_address((struct in6_addr *)
							  max_address);
		if (!e.address.ipv6.min || !e.address.ipv6.max)
			goto out;
		break;
	case 1:
		e.record_type = CCS_IP_RECORD_TYPE_IPv4;
		/* use host byte order to allow u32 comparison.*/
		e.address.ipv4.min = ntohl(* (u32 *) min_address);
		e.address.ipv4.max = ntohl(* (u32 *) max_address);
		break;
	default:
		if (address[0] != '@')
			return -EINVAL;
		e.record_type = CCS_IP_RECORD_TYPE_ADDRESS_GROUP;
		e.address.group = ccs_get_address_group(address + 1);
		if (!e.address.group)
			return -ENOMEM;
		break;
	}
	if (!ccs_parse_number_union(port, &e.port))
		goto out;
	if (is_delete)
		goto delete;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_ip_network_acl_record *acl;
		if (ccs_acl_type1(ptr) != CCS_TYPE_IP_NETWORK_ACL)
			continue;
		//if (ptr->cond != condition)
		//continue;
		acl = container_of(ptr, struct ccs_ip_network_acl_record, head);
		if (memcmp(((char *) acl) + offset, ((char *) &e) + offset,
			   sizeof(e) - offset))
			continue;
		error = ccs_add_domain_acl(NULL, ptr);
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		memmove(entry, &e, sizeof(e));
		memset(&e, 0, sizeof(e));
		error = ccs_add_domain_acl(domain, &entry->head);
		entry = NULL;
	}
	mutex_unlock(&ccs_policy_lock);
	goto out;
 delete:
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		struct ccs_ip_network_acl_record *acl;
		if (ccs_acl_type2(ptr) != CCS_TYPE_IP_NETWORK_ACL)
			continue;
		//if (ptr->cond != condition)
		//continue;
		acl = container_of(ptr, struct ccs_ip_network_acl_record, head);
		if (memcmp(((char *) acl) + offset, ((char *) &e) + offset,
			   sizeof(e) - offset))
			continue;
		error = ccs_del_domain_acl(ptr);
		break;
	}
	mutex_unlock(&ccs_policy_lock);
 out:
	if (address[0] == '@')
		ccs_put_address_group(e.address.group);
	else if (e.record_type == CCS_IP_RECORD_TYPE_IPv6) {
		ccs_put_ipv6_address(e.address.ipv6.min);
		ccs_put_ipv6_address(e.address.ipv6.max);
	}
	ccs_put_number_union(&e.port);
	kfree(entry);
	return error;
}

/**
 * ccs_check_network_entry2 - Check permission for network operation.
 *
 * @is_ipv6:   True if @address is an IPv6 address.
 * @operation: Type of operation.
 * @address:   An IPv4 or IPv6 address.
 * @port:      Port number.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds ccs_read_lock().
 */
static int ccs_check_network_entry2(const bool is_ipv6, const u8 operation,
				    const u32 *address, const u16 port)
{
	struct ccs_request_info r;
	struct ccs_acl_info *ptr;
	const char *keyword = ccs_net2keyword(operation);
	bool is_enforce;
	/* using host byte order to allow u32 comparison than memcmp().*/
	const u32 ip = ntohl(*address);
	bool found = false;
	char buf[64];
	ccs_check_read_lock();
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_NETWORK);
	is_enforce = (r.mode == 3);
	if (!r.mode)
		return 0;
 retry:
	list_for_each_entry_rcu(ptr, &r.domain->acl_info_list, list) {
		struct ccs_ip_network_acl_record *acl;
		if (ccs_acl_type2(ptr) != CCS_TYPE_IP_NETWORK_ACL)
			continue;
		acl = container_of(ptr, struct ccs_ip_network_acl_record, head);
		if (acl->operation_type != operation)
			continue;
		if (!ccs_compare_number_union(port, &acl->port) ||
		    !ccs_check_condition(&r, ptr))
			continue;
		if (acl->record_type == CCS_IP_RECORD_TYPE_ADDRESS_GROUP) {
			if (!ccs_address_matches_group(is_ipv6, address,
						       acl->address.group))
				continue;
		} else if (acl->record_type == CCS_IP_RECORD_TYPE_IPv4) {
			if (is_ipv6 ||
			    ip < acl->address.ipv4.min ||
			    acl->address.ipv4.max < ip)
				continue;
		} else {
			if (!is_ipv6 ||
			    memcmp(acl->address.ipv6.min, address, 16) > 0 ||
			    memcmp(address, acl->address.ipv6.max, 16) > 0)
				continue;
		}
		r.cond = ptr->cond;
		found = true;
		break;
	}
	memset(buf, 0, sizeof(buf));
	if (is_ipv6)
		ccs_print_ipv6(buf, sizeof(buf),
			       (const struct in6_addr *) address);
	else
		snprintf(buf, sizeof(buf) - 1, "%u.%u.%u.%u", HIPQUAD(ip));
	ccs_audit_network_log(&r, keyword, buf, port, found);
	if (found)
		return 0;
	if (is_enforce) {
		int err = ccs_check_supervisor(&r, CCS_KEYWORD_ALLOW_NETWORK
					       "%s %s %u\n", keyword, buf,
					       port);
		if (err == 1)
			goto retry;
		return err;
	} else if (ccs_domain_quota_ok(&r)) {
		char *tmp = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (tmp) {
			struct ccs_condition *cond = ccs_handler_cond();
			snprintf(tmp, PAGE_SIZE - 1, "%s %s %u", keyword, buf,
				 port);
			ccs_write_network_policy(tmp, r.domain, cond, false);
			ccs_put_condition(cond);
			kfree(tmp);
		}
	}
	return 0;
}

/**
 * ccs_check_network_entry - Check permission for network operation.
 *
 * @is_ipv6:   True if @address is an IPv6 address.
 * @operation: Type of operation.
 * @address:   An IPv4 or IPv6 address.
 * @port:      Port number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_network_entry(const bool is_ipv6, const u8 operation,
				   const u32 *address, const u16 port)
{
	const int idx = ccs_read_lock();
	const int error = ccs_check_network_entry2(is_ipv6, operation,
						   address, port);
	ccs_read_unlock(idx);
	return error;
}

/**
 * ccs_write_network_policy - Write "struct ccs_ip_network_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_network_policy(char *data, struct ccs_domain_info *domain,
			     struct ccs_condition *condition,
			     const bool is_delete)
{
	char *w[4];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[3][0])
		return -EINVAL;
	return ccs_update_network_entry(w[0], w[1], w[2], w[3], domain,
					condition, is_delete);
}

/**
 * ccs_check_network_listen_acl - Check permission for listen() operation.
 *
 * @is_ipv6: True if @address is an IPv6 address.
 * @address: An IPv4 or IPv6 address.
 * @port:    Port number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_check_network_listen_acl(const bool is_ipv6,
					       const u8 *address,
					       const u16 port)
{
	return ccs_check_network_entry(is_ipv6, CCS_NETWORK_ACL_TCP_LISTEN,
				       (const u32 *) address, ntohs(port));
}

/**
 * ccs_check_network_connect_acl - Check permission for connect() operation.
 *
 * @is_ipv6:   True if @address is an IPv6 address.
 * @sock_type: Type of socket. (TCP or UDP or RAW)
 * @address:   An IPv4 or IPv6 address.
 * @port:      Port number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_check_network_connect_acl(const bool is_ipv6,
						const int sock_type,
						const u8 *address,
						const u16 port)
{
	u8 operation;
	switch (sock_type) {
	case SOCK_STREAM:
		operation = CCS_NETWORK_ACL_TCP_CONNECT;
		break;
	case SOCK_DGRAM:
		operation = CCS_NETWORK_ACL_UDP_CONNECT;
		break;
	default:
		operation = CCS_NETWORK_ACL_RAW_CONNECT;
	}
	return ccs_check_network_entry(is_ipv6, operation,
				       (const u32 *) address, ntohs(port));
}

/**
 * ccs_check_network_bind_acl - Check permission for bind() operation.
 *
 * @is_ipv6:   True if @address is an IPv6 address.
 * @sock_type: Type of socket. (TCP or UDP or RAW)
 * @address:   An IPv4 or IPv6 address.
 * @port:      Port number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_check_network_bind_acl(const bool is_ipv6, const int sock_type,
				      const u8 *address, const u16 port)
{
	u8 operation;
	switch (sock_type) {
	case SOCK_STREAM:
		operation = CCS_NETWORK_ACL_TCP_BIND;
		break;
	case SOCK_DGRAM:
		operation = CCS_NETWORK_ACL_UDP_BIND;
		break;
	default:
		operation = CCS_NETWORK_ACL_RAW_BIND;
	}
	return ccs_check_network_entry(is_ipv6, operation,
				       (const u32 *) address, ntohs(port));
}

/**
 * ccs_check_network_accept_acl - Check permission for accept() operation.
 *
 * @is_ipv6: True if @address is an IPv6 address.
 * @address: An IPv4 or IPv6 address.
 * @port:    Port number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_check_network_accept_acl(const bool is_ipv6,
					       const u8 *address,
					       const u16 port)
{
	int retval;
	current->ccs_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	retval = ccs_check_network_entry(is_ipv6, CCS_NETWORK_ACL_TCP_ACCEPT,
					 (const u32 *) address, ntohs(port));
	current->ccs_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	return retval;
}

/**
 * ccs_check_network_sendmsg_acl - Check permission for sendmsg() operation.
 *
 * @is_ipv6:   True if @address is an IPv6 address.
 * @sock_type: Type of socket. (UDP or RAW)
 * @address:   An IPv4 or IPv6 address.
 * @port:      Port number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_check_network_sendmsg_acl(const bool is_ipv6,
						const int sock_type,
						const u8 *address,
						const u16 port)
{
	u8 operation;
	if (sock_type == SOCK_DGRAM)
		operation = CCS_NETWORK_ACL_UDP_CONNECT;
	else
		operation = CCS_NETWORK_ACL_RAW_CONNECT;
	return ccs_check_network_entry(is_ipv6, operation,
				       (const u32 *) address, ntohs(port));
}

/**
 * ccs_check_network_recvmsg_acl - Check permission for recvmsg() operation.
 *
 * @is_ipv6:   True if @address is an IPv6 address.
 * @sock_type: Type of socket. (UDP or RAW)
 * @address:   An IPv4 or IPv6 address.
 * @port:      Port number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static inline int ccs_check_network_recvmsg_acl(const bool is_ipv6,
						const int sock_type,
						const u8 *address,
						const u16 port)
{
	int retval;
	const u8 operation
		= (sock_type == SOCK_DGRAM) ?
		CCS_NETWORK_ACL_UDP_CONNECT : CCS_NETWORK_ACL_RAW_CONNECT;
	current->ccs_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	retval = ccs_check_network_entry(is_ipv6, operation,
					 (const u32 *) address, ntohs(port));
	current->ccs_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	return retval;
}

#define MAX_SOCK_ADDR 128 /* net/socket.c */

/* Check permission for creating a socket. */
int ccs_socket_create_permission(int family, int type, int protocol)
{
	int error = 0;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	if (family == PF_PACKET && !ccs_capable(CCS_USE_PACKET_SOCKET))
		return -EPERM;
	if (family == PF_ROUTE && !ccs_capable(CCS_USE_ROUTE_SOCKET))
		return -EPERM;
	if (family != PF_INET && family != PF_INET6)
		return 0;
	switch (type) {
	case SOCK_STREAM:
		if (!ccs_capable(CCS_INET_STREAM_SOCKET_CREATE))
			error = -EPERM;
		break;
	case SOCK_DGRAM:
		if (!ccs_capable(CCS_USE_INET_DGRAM_SOCKET))
			error = -EPERM;
		break;
	case SOCK_RAW:
		if (!ccs_capable(CCS_USE_INET_RAW_SOCKET))
			error = -EPERM;
		break;
	}
	return error;
}

/* Check permission for listening a TCP socket. */
int ccs_socket_listen_permission(struct socket *sock)
{
	int error = 0;
	char addr[MAX_SOCK_ADDR];
	int addr_len;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	if (sock->type != SOCK_STREAM)
		return 0;
	switch (sock->sk->sk_family) {
	case PF_INET:
	case PF_INET6:
		break;
	default:
		return 0;
	}
	if (!ccs_capable(CCS_INET_STREAM_SOCKET_LISTEN))
		return -EPERM;
	if (sock->ops->getname(sock, (struct sockaddr *) addr, &addr_len, 0))
		return -EPERM;
	switch (((struct sockaddr *) addr)->sa_family) {
		struct sockaddr_in6 *addr6;
		struct sockaddr_in *addr4;
	case AF_INET6:
		addr6 = (struct sockaddr_in6 *) addr;
		error = ccs_check_network_listen_acl(true,
						     addr6->sin6_addr.s6_addr,
						     addr6->sin6_port);
		break;
	case AF_INET:
		addr4 = (struct sockaddr_in *) addr;
		error = ccs_check_network_listen_acl(false,
						     (u8 *) &addr4->sin_addr,
						     addr4->sin_port);
		break;
	}
	return error;
}

/* Check permission for setting the remote IP address/port pair of a socket. */
int ccs_socket_connect_permission(struct socket *sock, struct sockaddr *addr,
				  int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (type) {
	case SOCK_STREAM:
	case SOCK_DGRAM:
	case SOCK_RAW:
		break;
	default:
		return 0;
	}
	switch (addr->sa_family) {
		struct sockaddr_in6 *addr6;
		struct sockaddr_in *addr4;
		u16 port;
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			break;
		addr6 = (struct sockaddr_in6 *) addr;
		if (type != SOCK_RAW)
			port = addr6->sin6_port;
		else
			port = htons(sock->sk->sk_protocol);
		error = ccs_check_network_connect_acl(true, type,
						      addr6->sin6_addr.s6_addr,
						      port);
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			break;
		addr4 = (struct sockaddr_in *) addr;
		if (type != SOCK_RAW)
			port = addr4->sin_port;
		else
			port = htons(sock->sk->sk_protocol);
		error = ccs_check_network_connect_acl(false, type,
						      (u8 *) &addr4->sin_addr,
						      port);
		break;
	}
	if (type != SOCK_STREAM)
		return error;
	switch (sock->sk->sk_family) {
	case PF_INET:
	case PF_INET6:
		if (!ccs_capable(CCS_INET_STREAM_SOCKET_CONNECT))
			error = -EPERM;
		break;
	}
	return error;
}

/* Check permission for setting the local IP address/port pair of a socket. */
int ccs_socket_bind_permission(struct socket *sock, struct sockaddr *addr,
			       int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (type) {
	case SOCK_STREAM:
	case SOCK_DGRAM:
	case SOCK_RAW:
		break;
	default:
		return 0;
	}
	switch (addr->sa_family) {
		struct sockaddr_in6 *addr6;
		struct sockaddr_in *addr4;
		u16 port;
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			break;
		addr6 = (struct sockaddr_in6 *) addr;
		if (type != SOCK_RAW)
			port = addr6->sin6_port;
		else
			port = htons(sock->sk->sk_protocol);
		error = ccs_check_network_bind_acl(true, type,
						   addr6->sin6_addr.s6_addr,
						   port);
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			break;
		addr4 = (struct sockaddr_in *) addr;
		if (type != SOCK_RAW)
			port = addr4->sin_port;
		else
			port = htons(sock->sk->sk_protocol);
		error = ccs_check_network_bind_acl(false, type,
						   (u8 *) &addr4->sin_addr,
						   port);
		break;
	}
	return error;
}

/*
 * Check permission for accepting a TCP socket.
 *
 * Currently, the LSM hook for this purpose is not provided.
 */
int ccs_socket_accept_permission(struct socket *sock, struct sockaddr *addr)
{
	int error = 0;
	int addr_len;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (sock->sk->sk_family) {
	case PF_INET:
	case PF_INET6:
		break;
	default:
		return 0;
	}
	error = sock->ops->getname(sock, addr, &addr_len, 2);
	if (error)
		return error;
	switch (addr->sa_family) {
		struct sockaddr_in6 *addr6;
		struct sockaddr_in *addr4;
	case AF_INET6:
		addr6 = (struct sockaddr_in6 *) addr;
		error = ccs_check_network_accept_acl(true,
						     addr6->sin6_addr.s6_addr,
						     addr6->sin6_port);
		break;
	case AF_INET:
		addr4 = (struct sockaddr_in *) addr;
		error = ccs_check_network_accept_acl(false,
						     (u8 *) &addr4->sin_addr,
						     addr4->sin_port);
		break;
	}
	return error;
}

/* Check permission for sending a datagram via a UDP or RAW socket. */
int ccs_socket_sendmsg_permission(struct socket *sock, struct sockaddr *addr,
				  int addr_len)
{
	int error = 0;
	const int type = sock->type;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	if (!addr || (type != SOCK_DGRAM && type != SOCK_RAW))
		return 0;
	switch (addr->sa_family) {
		struct sockaddr_in6 *addr6;
		struct sockaddr_in *addr4;
		u16 port;
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			break;
		addr6 = (struct sockaddr_in6 *) addr;
		if (type == SOCK_DGRAM)
			port = addr6->sin6_port;
		else
			port = htons(sock->sk->sk_protocol);
		error = ccs_check_network_sendmsg_acl(true, type,
						      addr6->sin6_addr.s6_addr,
						      port);
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			break;
		addr4 = (struct sockaddr_in *) addr;
		if (type == SOCK_DGRAM)
			port = addr4->sin_port;
		else
			port = htons(sock->sk->sk_protocol);
		error = ccs_check_network_sendmsg_acl(false, type,
						      (u8 *) &addr4->sin_addr,
						      port);
		break;
	}
	return error;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
#if !defined(RHEL_MAJOR) || RHEL_MAJOR != 5

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return skb->nh.iph;
}

static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
	return skb->h.uh;
}

static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return skb->nh.ipv6h;
}

#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 12)
static void skb_kill_datagram(struct sock *sk, struct sk_buff *skb,
			      unsigned int flags)
{
	/* Clear queue. */
	if (flags & MSG_PEEK) {
		int clear = 0;
		spin_lock_irq(&sk->sk_receive_queue.lock);
		if (skb == skb_peek(&sk->sk_receive_queue)) {
			__skb_unlink(skb, &sk->sk_receive_queue);
			clear = 1;
		}
		spin_unlock_irq(&sk->sk_receive_queue.lock);
		if (clear)
			kfree_skb(skb);
	}
	skb_free_datagram(sk, skb);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
static void skb_kill_datagram(struct sock *sk, struct sk_buff *skb,
			      unsigned int flags)
{
	/* Clear queue. */
	if (flags & MSG_PEEK) {
		int clear = 0;
		spin_lock_bh(&sk->sk_receive_queue.lock);
		if (skb == skb_peek(&sk->sk_receive_queue)) {
			__skb_unlink(skb, &sk->sk_receive_queue);
			clear = 1;
		}
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		if (clear)
			kfree_skb(skb);
	}
	skb_free_datagram(sk, skb);
}
#endif

/*
 * Check permission for receiving a datagram via a UDP or RAW socket.
 *
 * Currently, the LSM hook for this purpose is not provided.
 */
int ccs_socket_recvmsg_permission(struct sock *sk, struct sk_buff *skb,
				  const unsigned int flags)
{
	int error = 0;
	const unsigned int type = sk->sk_type;
	if (type != SOCK_DGRAM && type != SOCK_RAW)
		return 0;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;

	switch (sk->sk_family) {
		struct in6_addr sin6;
		struct in_addr sin4;
		u16 port;
	case PF_INET6:
		if (type == SOCK_DGRAM) { /* UDP IPv6 */
			if (skb->protocol == htons(ETH_P_IP)) {
				ipv6_addr_set(&sin6, 0, 0, htonl(0xffff),
					      ip_hdr(skb)->saddr);
			} else {
				ipv6_addr_copy(&sin6, &ipv6_hdr(skb)->saddr);
			}
			port = udp_hdr(skb)->source;
		} else { /* RAW IPv6 */
			ipv6_addr_copy(&sin6, &ipv6_hdr(skb)->saddr);
			port = htons(sk->sk_protocol);
		}
		error = ccs_check_network_recvmsg_acl(true, type,
						      (u8 *) &sin6, port);
		break;
	case PF_INET:
		if (type == SOCK_DGRAM) { /* UDP IPv4 */
			sin4.s_addr = ip_hdr(skb)->saddr;
			port = udp_hdr(skb)->source;
		} else { /* RAW IPv4 */
			sin4.s_addr = ip_hdr(skb)->saddr;
			port = htons(sk->sk_protocol);
		}
		error = ccs_check_network_recvmsg_acl(false, type,
						      (u8 *) &sin4, port);
		break;
	}
	if (!error)
		return 0;
	/*
	 * Remove from queue if MSG_PEEK is used so that
	 * the head message from unwanted source in receive queue will not
	 * prevent the caller from picking up next message from wanted source
	 * when the caller is using MSG_PEEK flag for picking up.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	if (type == SOCK_DGRAM)
		lock_sock(sk);
#endif
	skb_kill_datagram(sk, skb, flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	if (type == SOCK_DGRAM)
		release_sock(sk);
#endif
	/* Hope less harmful than -EPERM. */
	return -ENOMEM;
}
EXPORT_SYMBOL(ccs_socket_recvmsg_permission);
