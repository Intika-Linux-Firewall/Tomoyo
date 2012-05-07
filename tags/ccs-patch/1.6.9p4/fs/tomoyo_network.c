/*
 * fs/tomoyo_network.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/05/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/tomoyo_socket.h>
#include <linux/realpath.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>

/* Index numbers for Network Controls. */
enum ccs_network_acl_index {
	NETWORK_ACL_UDP_BIND,
	NETWORK_ACL_UDP_CONNECT,
	NETWORK_ACL_TCP_BIND,
	NETWORK_ACL_TCP_LISTEN,
	NETWORK_ACL_TCP_CONNECT,
	NETWORK_ACL_TCP_ACCEPT,
	NETWORK_ACL_RAW_BIND,
	NETWORK_ACL_RAW_CONNECT
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
	return ccs_write_audit_log(is_granted, r, KEYWORD_ALLOW_NETWORK
				   "%s %s %u\n", operation, address, port);
}

/**
 * ccs_save_ipv6_address - Keep the given IPv6 address on the RAM.
 *
 * @addr: Pointer to "struct in6_addr".
 *
 * Returns pointer to "struct in6_addr" on success, NULL otherwise.
 *
 * The RAM is shared, so NEVER try to modify or kfree() the returned address.
 */
static const struct in6_addr *ccs_save_ipv6_address(const struct in6_addr *addr)
{
	static const u8 ccs_block_size = 16;
	struct ccs_addr_list {
		/* Workaround for gcc 4.3's bug. */
		struct in6_addr addr[16]; /* = ccs_block_size */
		struct list1_head list;
		u32 in_use_count;
	};
	static LIST1_HEAD(ccs_address_list);
	struct ccs_addr_list *ptr;
	static DEFINE_MUTEX(lock);
	u8 i = ccs_block_size;
	if (!addr)
		return NULL;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_address_list, list) {
		for (i = 0; i < ptr->in_use_count; i++) {
			if (!memcmp(&ptr->addr[i], addr, sizeof(*addr)))
				goto ok;
		}
		if (i < ccs_block_size)
			break;
	}
	if (i == ccs_block_size) {
		ptr = ccs_alloc_element(sizeof(*ptr));
		if (!ptr)
			goto ok;
		list1_add_tail_mb(&ptr->list, &ccs_address_list);
		i = 0;
	}
	ptr->addr[ptr->in_use_count++] = *addr;
 ok:
	mutex_unlock(&lock);
	return ptr ? &ptr->addr[i] : NULL;
}

/* The list for "struct ccs_address_group_entry". */
static LIST1_HEAD(ccs_address_group_list);

/**
 * ccs_update_address_group_entry - Update "struct ccs_address_group_entry" list.
 *
 * @group_name:  The name of address group.
 * @is_ipv6:     True if @min_address and @max_address are IPv6 addresses.
 * @min_address: Start of IPv4 or IPv6 address range.
 * @max_address: End of IPv4 or IPv6 address range.
 * @is_delete:   True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_address_group_entry(const char *group_name,
					  const bool is_ipv6,
					  const u16 *min_address,
					  const u16 *max_address,
					  const bool is_delete)
{
	static DEFINE_MUTEX(lock);
	struct ccs_address_group_entry *new_group;
	struct ccs_address_group_entry *group;
	struct ccs_address_group_member *new_member;
	struct ccs_address_group_member *member;
	const struct ccs_path_info *saved_group_name;
	const struct in6_addr *saved_min_address = NULL;
	const struct in6_addr *saved_max_address = NULL;
	int error = -ENOMEM;
	bool found = false;
	const u32 min_ipv4_address = ntohl(*(u32 *) min_address);
	const u32 max_ipv4_address = ntohl(*(u32 *) max_address);
	if (!ccs_is_correct_path(group_name, 0, 0, 0, __func__) ||
	    !group_name[0])
		return -EINVAL;
	saved_group_name = ccs_save_name(group_name);
	if (!saved_group_name)
		return -ENOMEM;
	if (!is_ipv6)
		goto not_ipv6;
	saved_min_address
		= ccs_save_ipv6_address((struct in6_addr *) min_address);
	saved_max_address
		= ccs_save_ipv6_address((struct in6_addr *) max_address);
	if (!saved_min_address || !saved_max_address)
		return -ENOMEM;
 not_ipv6:
	mutex_lock(&lock);
	list1_for_each_entry(group, &ccs_address_group_list, list) {
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
				if (member->min.ipv4 != min_ipv4_address ||
				    member->max.ipv4 != max_ipv4_address)
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
		list1_add_tail_mb(&new_group->list, &ccs_address_group_list);
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
		new_member->min.ipv4 = min_ipv4_address;
		new_member->max.ipv4 = max_ipv4_address;
	}
	list1_add_tail_mb(&new_member->list, &group->address_group_member_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	ccs_update_counter(CCS_UPDATES_COUNTER_EXCEPTION_POLICY);
	return error;
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
 * ccs_write_address_group_policy - Write "struct ccs_address_group_entry" list.
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
	switch (ccs_parse_ip_address(cp, min_address, max_address)) {
	case 2:
		is_ipv6 = true;
		break;
	case 1:
		is_ipv6 = false;
		break;
	default:
		return -EINVAL;
	}
	return ccs_update_address_group_entry(data, is_ipv6, min_address,
					      max_address, is_delete);
}

/**
 * ccs_find_or_assign_new_address_group - Create address group.
 *
 * @group_name: The name of address group.
 *
 * Returns pointer to "struct ccs_address_group_entry" on success,
 * NULL otherwise.
 */
static struct ccs_address_group_entry *
ccs_find_or_assign_new_address_group(const char *group_name)
{
	u8 i;
	struct ccs_address_group_entry *group;
	for (i = 0; i <= 1; i++) {
		list1_for_each_entry(group, &ccs_address_group_list, list) {
			if (!strcmp(group_name, group->group_name->name))
				return group;
		}
		if (!i) {
			const u16 dummy[2] = { 0, 0 };
			ccs_update_address_group_entry(group_name, false,
						       dummy, dummy, false);
			ccs_update_address_group_entry(group_name, false,
						       dummy, dummy, true);
		}
	}
	return NULL;
}

/**
 * ccs_address_matches_group - Check whether the given address matches members of the given address group.
 *
 * @is_ipv6: True if @address is an IPv6 address.
 * @address: An IPv4 or IPv6 address.
 * @group:   Pointer to "struct ccs_address_group_entry".
 *
 * Returns true if @address matches addresses in @group group, false otherwise.
 */
static bool ccs_address_matches_group(const bool is_ipv6, const u32 *address,
				      const struct ccs_address_group_entry *
				      group)
{
	struct ccs_address_group_member *member;
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
 * ccs_read_address_group_policy - Read "struct ccs_address_group_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_read_address_group_policy(struct ccs_io_buffer *head)
{
	struct list1_head *gpos;
	struct list1_head *mpos;
	list1_for_each_cookie(gpos, head->read_var1, &ccs_address_group_list) {
		struct ccs_address_group_entry *group;
		group = list1_entry(gpos, struct ccs_address_group_entry, list);
		list1_for_each_cookie(mpos, head->read_var2,
				      &group->address_group_member_list) {
			char buf[128];
			struct ccs_address_group_member *member;
			member = list1_entry(mpos,
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
 * ccs_update_network_entry - Update "struct ccs_ip_network_acl_record" list.
 *
 * @operation:   Type of operation.
 * @record_type: Type of address.
 * @group:       Pointer to "struct ccs_address_group_entry". May be NULL.
 * @min_address: Start of IPv4 or IPv6 address range.
 * @max_address: End of IPv4 or IPv6 address range.
 * @min_port:    Start of port number range.
 * @max_port:    End of port number range.
 * @domain:      Pointer to "struct ccs_domain_info".
 * @condition:   Pointer to "struct ccs_condition_list". May be NULL.
 * @is_delete:   True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_network_entry(const u8 operation, const u8 record_type,
				    const struct ccs_address_group_entry *group,
				    const u32 *min_address,
				    const u32 *max_address,
				    const u16 min_port, const u16 max_port,
				    struct ccs_domain_info *domain,
				    const struct ccs_condition_list *condition,
				    const bool is_delete)
{
	static DEFINE_MUTEX(lock);
	struct ccs_acl_info *ptr;
	struct ccs_ip_network_acl_record *acl;
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
	saved_min_address = ccs_save_ipv6_address((struct in6_addr *)
						  min_address);
	saved_max_address = ccs_save_ipv6_address((struct in6_addr *)
						  max_address);
	if (!saved_min_address || !saved_max_address)
		return -ENOMEM;
 not_ipv6:
	mutex_lock(&lock);
	if (is_delete)
		goto delete;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		if (ccs_acl_type1(ptr) != TYPE_IP_NETWORK_ACL)
			continue;
		if (ccs_get_condition_part(ptr) != condition)
			continue;
		acl = container_of(ptr, struct ccs_ip_network_acl_record, head);
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
		acl = container_of(ptr, struct ccs_ip_network_acl_record, head);
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
	mutex_unlock(&lock);
	return error;
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
	struct ccs_request_info r;
	struct ccs_acl_info *ptr;
	const char *keyword = ccs_net2keyword(operation);
	bool is_enforce;
	/* using host byte order to allow u32 comparison than memcmp().*/
	const u32 ip = ntohl(*address);
	bool found = false;
	char buf[64];
	if (!ccs_can_sleep())
		return 0;
	ccs_init_request_info(&r, NULL, CCS_MAC_FOR_NETWORK);
	is_enforce = (r.mode == 3);
	if (!r.mode)
		return 0;
 retry:
	list1_for_each_entry(ptr, &r.domain->acl_info_list, list) {
		struct ccs_ip_network_acl_record *acl;
		if (ccs_acl_type2(ptr) != TYPE_IP_NETWORK_ACL)
			continue;
		acl = container_of(ptr, struct ccs_ip_network_acl_record, head);
		if (acl->operation_type != operation || port < acl->min_port ||
		    acl->max_port < port || !ccs_check_condition(&r, ptr))
			continue;
		if (acl->record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
			if (!ccs_address_matches_group(is_ipv6, address,
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
		r.cond = ccs_get_condition_part(ptr);
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
	if (ccs_verbose_mode(r.domain))
		printk(KERN_WARNING "TOMOYO-%s: %s to %s %u denied for %s\n",
		       ccs_get_msg(is_enforce), keyword, buf, port,
		       ccs_get_last_name(r.domain));
	if (is_enforce) {
		int error = ccs_check_supervisor(&r, KEYWORD_ALLOW_NETWORK
						 "%s %s %u\n", keyword, buf,
						 port);
		if (error == 1)
			goto retry;
		return error;
	}
	if (r.mode == 1 && ccs_domain_quota_ok(r.domain))
		ccs_update_network_entry(operation, is_ipv6 ?
					 IP_RECORD_TYPE_IPv6 :
					 IP_RECORD_TYPE_IPv4,
					 NULL, address, address, port, port,
					 r.domain, ccs_handler_cond(), 0);
	return 0;
}

/**
 * ccs_write_network_policy - Write "struct ccs_ip_network_acl_record" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition_list". May be NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_network_policy(char *data, struct ccs_domain_info *domain,
			     const struct ccs_condition_list *condition,
			     const bool is_delete)
{
	u8 sock_type;
	u8 operation;
	u8 record_type;
	u16 min_address[8];
	u16 max_address[8];
	struct ccs_address_group_entry *group = NULL;
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
	switch (ccs_parse_ip_address(cp2, min_address, max_address)) {
	case 2:
		record_type = IP_RECORD_TYPE_IPv6;
		break;
	case 1:
		record_type = IP_RECORD_TYPE_IPv4;
		break;
	default:
		if (*cp2 != '@')
			goto out;
		group = ccs_find_or_assign_new_address_group(cp2 + 1);
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
	return ccs_update_network_entry(operation, record_type, group,
					(u32 *) min_address,
					(u32 *) max_address,
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
static inline int ccs_check_network_listen_acl(const bool is_ipv6,
					       const u8 *address,
					       const u16 port)
{
	return ccs_check_network_entry(is_ipv6, NETWORK_ACL_TCP_LISTEN,
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
		operation = NETWORK_ACL_TCP_CONNECT;
		break;
	case SOCK_DGRAM:
		operation = NETWORK_ACL_UDP_CONNECT;
		break;
	default:
		operation = NETWORK_ACL_RAW_CONNECT;
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
		operation = NETWORK_ACL_TCP_BIND;
		break;
	case SOCK_DGRAM:
		operation = NETWORK_ACL_UDP_BIND;
		break;
	default:
		operation = NETWORK_ACL_RAW_BIND;
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
	retval = ccs_check_network_entry(is_ipv6, NETWORK_ACL_TCP_ACCEPT,
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
		operation = NETWORK_ACL_UDP_CONNECT;
	else
		operation = NETWORK_ACL_RAW_CONNECT;
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
		NETWORK_ACL_UDP_CONNECT : NETWORK_ACL_RAW_CONNECT;
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
#if !defined(AX_MAJOR) || AX_MAJOR != 3 || !defined(AX_MINOR) || AX_MINOR < 2

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
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
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
#elif defined(RHEL_MAJOR) && RHEL_MAJOR == 5 && defined(RHEL_MINOR) && RHEL_MINOR >= 2
	if (type == SOCK_DGRAM)
		lock_sock(sk);
#endif
	skb_kill_datagram(sk, skb, flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	if (type == SOCK_DGRAM)
		release_sock(sk);
#elif defined(RHEL_MAJOR) && RHEL_MAJOR == 5 && defined(RHEL_MINOR) && RHEL_MINOR >= 2
	if (type == SOCK_DGRAM)
		release_sock(sk);
#endif
	/* Hope less harmful than -EPERM. */
	return -ENOMEM;
}
EXPORT_SYMBOL(ccs_socket_recvmsg_permission);
