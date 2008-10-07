/*
 * fs/tomoyo_network.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.5-pre   2008/10/07
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>

/**
 * audit_network_log - Audit network log.
 *
 * @r:          Pointer to "struct ccs_request_info".
 * @operation:  The name of operation.
 * @address:    An IPv4 or IPv6 address.
 * @port:       Port number.
 * @is_granted: True if this is a granted log.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int audit_network_log(struct ccs_request_info *r, const char *operation,
			     const char *address, const u16 port,
			     const bool is_granted)
{
	return ccs_write_audit_log(is_granted, r, KEYWORD_ALLOW_NETWORK
				   "%s %s %u\n", operation, address, port);
}

/**
 * save_ipv6_address - Keep the given IPv6 address on the RAM.
 *
 * @addr: Pointer to "struct in6_addr".
 *
 * Returns pointer to "struct in6_addr" on success, NULL otherwise.
 *
 * The RAM is shared, so NEVER try to modify or kfree() the returned address.
 */
static const struct in6_addr *save_ipv6_address(const struct in6_addr *addr)
{
	static const u8 block_size = 16;
	struct addr_list {
		/* Workaround for gcc 4.3's bug. */
		struct in6_addr addr[16]; /* = block_size */
		struct list1_head list;
		u32 in_use_count;
	};
	static LIST1_HEAD(address_list);
	struct addr_list *ptr;
	static DEFINE_MUTEX(lock);
	u8 i = block_size;
	if (!addr)
		return NULL;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &address_list, list) {
		for (i = 0; i < ptr->in_use_count; i++) {
			if (!memcmp(&ptr->addr[i], addr, sizeof(*addr)))
				goto ok;
		}
		if (i < block_size)
			break;
	}
	if (i == block_size) {
		ptr = ccs_alloc_element(sizeof(*ptr));
		if (!ptr)
			goto ok;
		list1_add_tail_mb(&ptr->list, &address_list);
		i = 0;
	}
	ptr->addr[ptr->in_use_count++] = *addr;
 ok:
	mutex_unlock(&lock);
	return ptr ? &ptr->addr[i] : NULL;
}

/* The list for "struct address_group_entry". */
static LIST1_HEAD(address_group_list);

/**
 * update_address_group_entry - Update "struct address_group_entry" list.
 *
 * @group_name:  The name of address group.
 * @is_ipv6:     True if @min_address and @max_address are IPv6 addresses.
 * @min_address: Start of IPv4 or IPv6 address range.
 * @max_address: End of IPv4 or IPv6 address range.
 * @is_delete:   True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_address_group_entry(const char *group_name,
				      const bool is_ipv6,
				      const u16 *min_address,
				      const u16 *max_address,
				      const bool is_delete)
{
	static DEFINE_MUTEX(lock);
	struct address_group_entry *new_group;
	struct address_group_entry *group;
	struct address_group_member *new_member;
	struct address_group_member *member;
	const struct path_info *saved_group_name;
	const struct in6_addr *saved_min_address = NULL;
	const struct in6_addr *saved_max_address = NULL;
	int error = -ENOMEM;
	bool found = false;
	if (!ccs_is_correct_path(group_name, 0, 0, 0, __func__) ||
	    !group_name[0])
		return -EINVAL;
	saved_group_name = ccs_save_name(group_name);
	if (!saved_group_name)
		return -ENOMEM;
	if (!is_ipv6)
		goto not_ipv6;
	saved_min_address
		= save_ipv6_address((struct in6_addr *) min_address);
	saved_max_address
		= save_ipv6_address((struct in6_addr *) max_address);
	if (!saved_min_address || !saved_max_address)
		return -ENOMEM;
 not_ipv6:
	mutex_lock(&lock);
	list1_for_each_entry(group, &address_group_list, list) {
		if (saved_group_name != group->group_name)
			continue;
		list1_for_each_entry(member, &group->address_group_member_list,
				     list) {
			if (member->is_ipv6 != is_ipv6)
				continue;
			if (is_ipv6) {
				if (member->min.ipv6 != saved_min_address ||
				    member->max.ipv6 != saved_max_address)
					continue;
			} else {
				if (member->min.ipv4 != *(u32 *) min_address ||
				    member->max.ipv4 != *(u32 *) max_address)
					continue;
			}
			member->is_deleted = is_delete;
			error = 0;
			goto out;
		}
		found = true;
		break;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if (!found) {
		new_group = ccs_alloc_element(sizeof(*new_group));
		if (!new_group)
			goto out;
		INIT_LIST1_HEAD(&new_group->address_group_member_list);
		new_group->group_name = saved_group_name;
		list1_add_tail_mb(&new_group->list, &address_group_list);
		group = new_group;
	}
	new_member = ccs_alloc_element(sizeof(*new_member));
	if (!new_member)
		goto out;
	new_member->is_ipv6 = is_ipv6;
	if (is_ipv6) {
		new_member->min.ipv6 = saved_min_address;
		new_member->max.ipv6 = saved_max_address;
	} else {
		new_member->min.ipv4 = *(u32 *) min_address;
		new_member->max.ipv4 = *(u32 *) max_address;
	}
	list1_add_tail_mb(&new_member->list, &group->address_group_member_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
}

/**
 * parse_ip_address - Parse an IP address.
 *
 * @address: String to parse.
 * @min:     Pointer to store min address.
 * @max:     Pointer to store max address.
 *
 * Returns 2 if @address is an IPv6, 1 if @address is an IPv4, 0 otherwise.
 */
static int parse_ip_address(char *address, u16 *min, u16 *max)
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
		u8 *p = (void *) min;
		*p++ = min[0];
		*p++ = min[1];
		*p++ = min[2];
		*p = min[3];
		if (count == 4)
			memmove(max, min, sizeof(u16) * 4);
		p = (void *) max;
		*p++ = max[0];
		*p++ = max[1];
		*p++ = max[2];
		*p = max[3];
		return 1;
	}
	return 0;
}

/**
 * ccs_write_address_group_policy - Write "struct address_group_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_address_group_policy(char *data, const bool is_delete)
{
	bool is_ipv6;
	u16 min_address[8];
	u16 max_address[8];
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	switch (parse_ip_address(cp, min_address, max_address)) {
	case 2:
		is_ipv6 = true;
		break;
	case 1:
		is_ipv6 = false;
		break;
	default:
		return -EINVAL;
	}
	return update_address_group_entry(data, is_ipv6,
					  min_address, max_address, is_delete);
}

/**
 * find_or_assign_new_address_group - Create address group.
 *
 * @group_name: The name of address group.
 *
 * Returns pointer to "struct address_group_entry" on success, NULL otherwise.
 */
static struct address_group_entry *
find_or_assign_new_address_group(const char *group_name)
{
	u8 i;
	struct address_group_entry *group;
	for (i = 0; i <= 1; i++) {
		list1_for_each_entry(group, &address_group_list, list) {
			if (!strcmp(group_name, group->group_name->name))
				return group;
		}
		if (!i) {
			const u16 dummy[2] = { 0, 0 };
			update_address_group_entry(group_name, false,
						   dummy, dummy, false);
			update_address_group_entry(group_name, false,
						   dummy, dummy, true);
		}
	}
	return NULL;
}

/**
 * address_matches_to_group - Check whether the given address matches members of the given address group.
 *
 * @is_ipv6: True if @address is an IPv6 address.
 * @address: An IPv4 or IPv6 address.
 * @group:   Pointer to "struct address_group_entry".
 *
 * Returns true if @address matches addresses in @group group, false otherwise.
 */
static bool address_matches_to_group(const bool is_ipv6, const u32 *address,
				     const struct address_group_entry *group)
{
	struct address_group_member *member;
	const u32 ip = ntohl(*address);
	list1_for_each_entry(member, &group->address_group_member_list, list) {
		if (member->is_deleted)
			continue;
		if (member->is_ipv6) {
			if (is_ipv6 &&
			    memcmp(member->min.ipv6, address, 16) <= 0 &&
			    memcmp(address, member->max.ipv6, 16) <= 0)
				return true;
		} else {
			if (!is_ipv6 &&
			    member->min.ipv4 <= ip && ip <= member->max.ipv4)
				return true;
		}
	}
	return false;
}

/**
 * ccs_read_address_group_policy - Read "struct address_group_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_address_group_policy(struct ccs_io_buffer *head)
{
	struct list1_head *gpos;
	struct list1_head *mpos;
	list1_for_each_cookie(gpos, head->read_var1, &address_group_list) {
		struct address_group_entry *group;
		group = list1_entry(gpos, struct address_group_entry, list);
		list1_for_each_cookie(mpos, head->read_var2,
				      &group->address_group_member_list) {
			char buf[128];
			struct address_group_member *member;
			member = list1_entry(mpos, struct address_group_member,
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
					char *cp = strchr(buf, '\0');
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
			if (!ccs_io_printf(head, KEYWORD_ADDRESS_GROUP
					   "%s %s\n", group->group_name->name,
					   buf))
				goto out;
		}
	}
	return true;
 out:
	return false;
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
	case NETWORK_ACL_UDP_BIND:
		keyword = "UDP bind";
		break;
	case NETWORK_ACL_UDP_CONNECT:
		keyword = "UDP connect";
		break;
	case NETWORK_ACL_TCP_BIND:
		keyword = "TCP bind";
		break;
	case NETWORK_ACL_TCP_LISTEN:
		keyword = "TCP listen";
		break;
	case NETWORK_ACL_TCP_CONNECT:
		keyword = "TCP connect";
		break;
	case NETWORK_ACL_TCP_ACCEPT:
		keyword = "TCP accept";
		break;
	case NETWORK_ACL_RAW_BIND:
		keyword = "RAW bind";
		break;
	case NETWORK_ACL_RAW_CONNECT:
		keyword = "RAW connect";
		break;
	}
	return keyword;
}

/**
 * update_network_entry - Update "struct ip_network_acl_record" list.
 *
 * @operation:   Type of operation.
 * @record_type: Type of address.
 * @group:       Pointer to "struct address_group_entry". May be NULL.
 * @min_address: Start of IPv4 or IPv6 address range.
 * @max_address: End of IPv4 or IPv6 address range.
 * @min_port:    Start of port number range.
 * @max_port:    End of port number range.
 * @domain:      Pointer to "struct domain_info".
 * @condition:   Pointer to "struct condition_list". May be NULL.
 * @is_delete:   True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int update_network_entry(const u8 operation, const u8 record_type,
				const struct address_group_entry *group,
				const u32 *min_address, const u32 *max_address,
				const u16 min_port, const u16 max_port,
				struct domain_info *domain,
				const struct condition_list *condition,
				const bool is_delete)
{
	struct acl_info *ptr;
	struct ip_network_acl_record *acl;
	int error = -ENOMEM;
	/* using host byte order to allow u32 comparison than memcmp().*/
	const u32 min_ip = ntohl(*min_address);
	const u32 max_ip = ntohl(*max_address);
	const struct in6_addr *saved_min_address = NULL;
	const struct in6_addr *saved_max_address = NULL;
	if (!domain)
		return -EINVAL;
	if (record_type != IP_RECORD_TYPE_IPv6)
		goto not_ipv6;
	saved_min_address = save_ipv6_address((struct in6_addr *) min_address);
	saved_max_address = save_ipv6_address((struct in6_addr *) max_address);
	if (!saved_min_address || !saved_max_address)
		return -ENOMEM;
 not_ipv6:
	mutex_lock(&domain_acl_lock);
	if (is_delete)
		goto delete;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != TYPE_IP_NETWORK_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ip_network_acl_record, head);
		if (acl->operation_type != operation ||
		    acl->record_type != record_type ||
		    acl->min_port != min_port || max_port != acl->max_port)
			continue;
		if (record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
			if (acl->u.group != group)
				continue;
		} else if (record_type == IP_RECORD_TYPE_IPv4) {
			if (acl->u.ipv4.min != min_ip ||
			    max_ip != acl->u.ipv4.max)
				continue;
		} else if (record_type == IP_RECORD_TYPE_IPv6) {
			if (acl->u.ipv6.min != saved_min_address ||
			    saved_max_address != acl->u.ipv6.max)
				continue;
		}
		error = ccs_add_domain_acl(NULL, ptr);
		goto out;
	}
	/* Not found. Append it to the tail. */
	acl = ccs_alloc_acl_element(TYPE_IP_NETWORK_ACL, condition);
	if (!acl)
		goto out;
	acl->operation_type = operation;
	acl->record_type = record_type;
	if (record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
		acl->u.group = group;
	} else if (record_type == IP_RECORD_TYPE_IPv4) {
		acl->u.ipv4.min = min_ip;
		acl->u.ipv4.max = max_ip;
	} else {
		acl->u.ipv6.min = saved_min_address;
		acl->u.ipv6.max = saved_max_address;
	}
	acl->min_port = min_port;
	acl->max_port = max_port;
	error = ccs_add_domain_acl(domain, &acl->head);
	goto out;
 delete:
	error = -ENOENT;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type2(ptr) != TYPE_IP_NETWORK_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ip_network_acl_record, head);
		if (acl->operation_type != operation ||
		    acl->record_type != record_type ||
		    acl->min_port != min_port || max_port != acl->max_port)
			continue;
		if (record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
			if (acl->u.group != group)
				continue;
		} else if (record_type == IP_RECORD_TYPE_IPv4) {
			if (acl->u.ipv4.min != min_ip ||
			    max_ip != acl->u.ipv4.max)
				continue;
		} else if (record_type == IP_RECORD_TYPE_IPv6) {
			if (acl->u.ipv6.min != saved_min_address ||
			    saved_max_address != acl->u.ipv6.max)
				continue;
		}
		error = ccs_del_domain_acl(ptr);
		break;
	}
 out:
	mutex_unlock(&domain_acl_lock);
	return error;
}

/**
 * check_network_entry - Check permission for network operation.
 *
 * @is_ipv6:   True if @address is an IPv6 address.
 * @operation: Type of operation.
 * @address:   An IPv4 or IPv6 address.
 * @port:      Port number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int check_network_entry(const bool is_ipv6, const u8 operation,
			       const u32 *address, const u16 port)
{
	struct ccs_request_info r;
	struct acl_info *ptr;
	const char *keyword = ccs_net2keyword(operation);
	bool is_enforce;
	/* using host byte order to allow u32 comparison than memcmp().*/
	const u32 ip = ntohl(*address);
	bool found = false;
	char buf[64];
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_TOMOYO_MAC_FOR_NETWORK);
	is_enforce = (r.mode == 3);
	if (!r.mode)
		return 0;
retry:
	list1_for_each_entry(ptr, &r.domain->acl_info_list, list) {
		struct ip_network_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_IP_NETWORK_ACL)
			continue;
		acl = container_of(ptr, struct ip_network_acl_record, head);
		if (acl->operation_type != operation || port < acl->min_port ||
		    acl->max_port < port || !ccs_check_condition(&r, ptr))
			continue;
		if (acl->record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
			if (!address_matches_to_group(is_ipv6, address,
						      acl->u.group))
				continue;
		} else if (acl->record_type == IP_RECORD_TYPE_IPv4) {
			if (is_ipv6 ||
			    ip < acl->u.ipv4.min || acl->u.ipv4.max < ip)
				continue;
		} else {
			if (!is_ipv6 ||
			    memcmp(acl->u.ipv6.min, address, 16) > 0 ||
			    memcmp(address, acl->u.ipv6.max, 16) > 0)
				continue;
		}
		ccs_update_condition(ptr);
		found = true;
		break;
	}
	memset(buf, 0, sizeof(buf));
	if (is_ipv6)
		ccs_print_ipv6(buf, sizeof(buf),
			       (const struct in6_addr *) address);
	else
		snprintf(buf, sizeof(buf) - 1, "%u.%u.%u.%u", HIPQUAD(ip));
	audit_network_log(&r, keyword, buf, port, found);
	if (found)
		return 0;
	if (ccs_verbose_mode(r.domain))
		printk(KERN_WARNING "TOMOYO-%s: %s to %s %u denied for %s\n",
		       ccs_get_msg(is_enforce), keyword, buf, port,
		       ccs_get_last_name(r.domain));
	if (is_enforce) {
		int error = ccs_check_supervisor(&r, KEYWORD_ALLOW_NETWORK
						 "%s %s %u\n", keyword, buf,
						 port);
		if (error == 1) {
			r.retry++;
			goto retry;
		}
		return error;
	}
	if (r.mode == 1 && ccs_check_domain_quota(r.domain))
		update_network_entry(operation, is_ipv6 ?
				     IP_RECORD_TYPE_IPv6 : IP_RECORD_TYPE_IPv4,
				     NULL, address, address, port, port,
				     r.domain, NULL, 0);
	return 0;
}

/**
 * ccs_write_network_policy - Write "struct ip_network_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct domain_info".
 * @condition: Pointer to "struct condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_network_policy(char *data, struct domain_info *domain,
			     const struct condition_list *condition,
			     const bool is_delete)
{
	u8 sock_type;
	u8 operation;
	u8 record_type;
	u16 min_address[8];
	u16 max_address[8];
	struct address_group_entry *group = NULL;
	u16 min_port;
	u16 max_port;
	u8 count;
	char *cp1 = strchr(data, ' ');
	char *cp2;
	if (!cp1)
		goto out;
	cp1++;
	if (!strncmp(data, "TCP ", 4))
		sock_type = SOCK_STREAM;
	else if (!strncmp(data, "UDP ", 4))
		sock_type = SOCK_DGRAM;
	else if (!strncmp(data, "RAW ", 4))
		sock_type = SOCK_RAW;
	else
		goto out;
	cp2 = strchr(cp1, ' ');
	if (!cp2)
		goto out;
	cp2++;
	if (!strncmp(cp1, "bind ", 5))
		switch (sock_type) {
		case SOCK_STREAM:
			operation = NETWORK_ACL_TCP_BIND;
			break;
		case SOCK_DGRAM:
			operation = NETWORK_ACL_UDP_BIND;
			break;
		default:
			operation = NETWORK_ACL_RAW_BIND;
		}
	else if (!strncmp(cp1, "connect ", 8))
		switch (sock_type) {
		case SOCK_STREAM:
			operation = NETWORK_ACL_TCP_CONNECT;
			break;
		case SOCK_DGRAM:
			operation = NETWORK_ACL_UDP_CONNECT;
			break;
		default:
			operation = NETWORK_ACL_RAW_CONNECT;
		}
	else if (sock_type == SOCK_STREAM && !strncmp(cp1, "listen ", 7))
		operation = NETWORK_ACL_TCP_LISTEN;
	else if (sock_type == SOCK_STREAM && !strncmp(cp1, "accept ", 7))
		operation = NETWORK_ACL_TCP_ACCEPT;
	else
		goto out;
	cp1 = strchr(cp2, ' ');
	if (!cp1)
		goto out;
	*cp1++ = '\0';
	switch (parse_ip_address(cp2, min_address, max_address)) {
	case 2:
		record_type = IP_RECORD_TYPE_IPv6;
		break;
	case 1:
		record_type = IP_RECORD_TYPE_IPv4;
		break;
	default:
		if (*cp2 != '@')
			goto out;
		group = find_or_assign_new_address_group(cp2 + 1);
		if (!group)
			return -ENOMEM;
		record_type = IP_RECORD_TYPE_ADDRESS_GROUP;
		break;
	}
	if (strchr(cp1, ' '))
		goto out;
	count = sscanf(cp1, "%hu-%hu", &min_port, &max_port);
	if (count != 1 && count != 2)
		goto out;
	if (count == 1)
		max_port = min_port;
	return update_network_entry(operation, record_type, group,
				    (u32 *) min_address, (u32 *) max_address,
				    min_port, max_port, domain, condition,
				    is_delete);
 out:
	return -EINVAL;
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
int ccs_check_network_listen_acl(const _Bool is_ipv6, const u8 *address,
				 const u16 port)
{
	return check_network_entry(is_ipv6, NETWORK_ACL_TCP_LISTEN,
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
int ccs_check_network_connect_acl(const _Bool is_ipv6, const int sock_type,
				  const u8 *address, const u16 port)
{
	u8 operation;
	switch (sock_type) {
	case SOCK_STREAM:
		operation = NETWORK_ACL_TCP_CONNECT;
		break;
	case SOCK_DGRAM:
		operation = NETWORK_ACL_UDP_CONNECT;
		break;
	default:
		operation = NETWORK_ACL_RAW_CONNECT;
	}
	return check_network_entry(is_ipv6, operation, (const u32 *) address,
				   ntohs(port));
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
int ccs_check_network_bind_acl(const _Bool is_ipv6, const int sock_type,
			       const u8 *address, const u16 port)
{
	u8 operation;
	switch (sock_type) {
	case SOCK_STREAM:
		operation = NETWORK_ACL_TCP_BIND;
		break;
	case SOCK_DGRAM:
		operation = NETWORK_ACL_UDP_BIND;
		break;
	default:
		operation = NETWORK_ACL_RAW_BIND;
	}
	return check_network_entry(is_ipv6, operation, (const u32 *) address,
				   ntohs(port));
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
int ccs_check_network_accept_acl(const _Bool is_ipv6, const u8 *address,
				 const u16 port)
{
	int retval;
	current->tomoyo_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	retval = check_network_entry(is_ipv6, NETWORK_ACL_TCP_ACCEPT,
				     (const u32 *) address, ntohs(port));
	current->tomoyo_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
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
int ccs_check_network_sendmsg_acl(const _Bool is_ipv6, const int sock_type,
				  const u8 *address, const u16 port)
{
	u8 operation;
	if (sock_type == SOCK_DGRAM)
		operation = NETWORK_ACL_UDP_CONNECT;
	else
		operation = NETWORK_ACL_RAW_CONNECT;
	return check_network_entry(is_ipv6, operation, (const u32 *) address,
				   ntohs(port));
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
int ccs_check_network_recvmsg_acl(const _Bool is_ipv6, const int sock_type,
				  const u8 *address, const u16 port)
{
	int retval;
	const u8 operation
		= (sock_type == SOCK_DGRAM) ?
		NETWORK_ACL_UDP_CONNECT : NETWORK_ACL_RAW_CONNECT;
	current->tomoyo_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	retval = check_network_entry(is_ipv6, operation, (const u32 *) address,
				     ntohs(port));
	current->tomoyo_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	return retval;
}
