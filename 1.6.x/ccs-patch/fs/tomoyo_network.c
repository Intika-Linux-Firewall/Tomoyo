/*
 * fs/tomoyo_network.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.0-pre   2008/03/04
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */
/***** TOMOYO Linux start. *****/

#include <linux/ccs_common.h>
#include <linux/tomoyo.h>
#include <linux/realpath.h>
#include <net/ip.h>

/*************************  AUDIT FUNCTIONS  *************************/

static int AuditNetworkLog(const bool is_ipv6, const char *operation, const u32 *address, const u16 port, const bool is_granted, const u8 profile, const u8 mode)
{
	char *buf;
	int len = 256;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	if ((buf = InitAuditLog(&len, profile, mode, NULL)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_NETWORK "%s ", operation);
	if (is_ipv6) {
		print_ipv6(buf + strlen(buf), len - strlen(buf), (const struct in6_addr *) address);
	} else {
		u32 ip = *address;
		snprintf(buf + strlen(buf), len - strlen(buf) - 1, "%u.%u.%u.%u", NIPQUAD(ip));
	}
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, " %u\n", port);
	return WriteAuditLog(buf, is_granted);
}

/*************************  UTILITY FUNCTIONS  *************************/

/* Keep the given IPv6 address on the RAM. The RAM is shared, so NEVER try to modify or kfree() the returned address. */
static const struct in6_addr *SaveIPv6Address(const struct in6_addr *addr)
{
	static const u8 block_size = 16;
	struct addr_list {
		struct in6_addr addr[block_size];
		struct list1_head list;
		u32 in_use_count;
	};
	static LIST1_HEAD(address_list);
	struct addr_list *ptr;
	static DEFINE_MUTEX(lock);
	u8 i = block_size;
	if (!addr) return NULL;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &address_list, list) {
		for (i = 0; i < ptr->in_use_count; i++) {
			if (memcmp(&ptr->addr[i], addr, sizeof(*addr)) == 0) goto ok;
		}
		if (i < block_size) break;
	}
	if (i == block_size) {
		ptr = alloc_element(sizeof(*ptr));
		if (!ptr) goto ok;
		list1_add_tail_mb(&ptr->list, &address_list);
		i = 0;
	}
	ptr->addr[ptr->in_use_count++] = *addr;
ok:
	mutex_unlock(&lock);
	return ptr ? &ptr->addr[i] : NULL;
}

/*************************  ADDRESS GROUP HANDLER  *************************/

static LIST1_HEAD(address_group_list);

static int AddAddressGroupEntry(const char *group_name, const bool is_ipv6, const u16 *min_address, const u16 *max_address, const bool is_delete)
{
	static DEFINE_MUTEX(lock);
	struct address_group_entry *new_group, *group;
	struct address_group_member *new_member, *member;
	const struct path_info *saved_group_name;
	const struct in6_addr *saved_min_address = NULL, *saved_max_address = NULL;
	int error = -ENOMEM;
	bool found = 0;
	if (!IsCorrectPath(group_name, 0, 0, 0, __FUNCTION__) || !group_name[0]) return -EINVAL;
	if ((saved_group_name = SaveName(group_name)) == NULL) return -ENOMEM;
	if (is_ipv6) {
		if ((saved_min_address = SaveIPv6Address((struct in6_addr *) min_address)) == NULL
		    || (saved_max_address = SaveIPv6Address((struct in6_addr *) max_address)) == NULL) return -ENOMEM;
	}
	mutex_lock(&lock);
	list1_for_each_entry(group, &address_group_list, list) {
		if (saved_group_name != group->group_name) continue;
		list1_for_each_entry(member, &group->address_group_member_list, list) {
			if (member->is_ipv6 != is_ipv6) continue;
			if (is_ipv6) {
				if (member->min.ipv6 != saved_min_address || member->max.ipv6 != saved_max_address) continue;
			} else {
				if (member->min.ipv4 != * (u32 *) min_address || member->max.ipv4 != * (u32 *) max_address) continue;
			}
			member->is_deleted = is_delete;
			error = 0;
			goto out;
		}
		found = 1;
		break;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if (!found) {
		if ((new_group = alloc_element(sizeof(*new_group))) == NULL) goto out;
		INIT_LIST1_HEAD(&new_group->address_group_member_list);
		new_group->group_name = saved_group_name;
		list1_add_tail_mb(&new_group->list, &address_group_list);
		group = new_group;
	}
	if ((new_member = alloc_element(sizeof(*new_member))) == NULL) goto out;
	new_member->is_ipv6 = is_ipv6;
	if (is_ipv6) {
		new_member->min.ipv6 = saved_min_address;
		new_member->max.ipv6 = saved_max_address;
	} else {
		new_member->min.ipv4 = * (u32 *) min_address;
		new_member->max.ipv4 = * (u32 *) max_address;
	}
	list1_add_tail_mb(&new_member->list, &group->address_group_member_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	return error;
}

int AddAddressGroupPolicy(char *data, const bool is_delete)
{
	u8 count;
	bool is_ipv6;
	u16 min_address[8], max_address[8];
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp++ = '\0';
	if ((count = sscanf(cp, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx-%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
			    &min_address[0], &min_address[1], &min_address[2], &min_address[3],
			    &min_address[4], &min_address[5], &min_address[6], &min_address[7],
			    &max_address[0], &max_address[1], &max_address[2], &max_address[3],
			    &max_address[4], &max_address[5], &max_address[6], &max_address[7])) == 8 || count == 16) {
		u8 i;
		for (i = 0; i < 8; i++) {
			min_address[i] = htons(min_address[i]);
			max_address[i] = htons(max_address[i]);
		}
		if (count == 8) memmove(max_address, min_address, sizeof(min_address));
		is_ipv6 = 1;
	} else if ((count = sscanf(cp, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
				   &min_address[0], &min_address[1], &min_address[2], &min_address[3],
				   &max_address[0], &max_address[1], &max_address[2], &max_address[3])) == 4 || count == 8) {
		u32 ip = ((((u8) min_address[0]) << 24) + (((u8) min_address[1]) << 16) + (((u8) min_address[2]) << 8) + (u8) min_address[3]);
		* (u32 *) min_address = ip;
		if (count == 8) ip = ((((u8) max_address[0]) << 24) + (((u8) max_address[1]) << 16) + (((u8) max_address[2]) << 8) + (u8) max_address[3]);
		* (u32 *) max_address = ip;
		is_ipv6 = 0;
	} else {
		return -EINVAL;
	}
	return AddAddressGroupEntry(data, is_ipv6, min_address, max_address, is_delete);
}

static struct address_group_entry *FindOrAssignNewAddressGroup(const char *group_name)
{
	u8 i;
	struct address_group_entry *group;
	for (i = 0; i <= 1; i++) {
		list1_for_each_entry(group, &address_group_list, list) {
			if (strcmp(group_name, group->group_name->name) == 0) return group;
		}
		if (i == 0) {
			const u16 dummy[2] = { 0, 0 };
			AddAddressGroupEntry(group_name, 0, dummy, dummy, 0);
			AddAddressGroupEntry(group_name, 0, dummy, dummy, 1);
		}
	}
	return NULL;
}

static bool AddressMatchesToGroup(const bool is_ipv6, const u32 *address, const struct address_group_entry *group)
{
	struct address_group_member *member;
	const u32 ip = ntohl(*address);
	list1_for_each_entry(member, &group->address_group_member_list, list) {
		if (member->is_deleted) continue;
		if (member->is_ipv6) {
			if (is_ipv6 && memcmp(member->min.ipv6, address, 16) <= 0 && memcmp(address, member->max.ipv6, 16) <= 0) return 1;
		} else {
			if (!is_ipv6 && member->min.ipv4 <= ip && ip <= member->max.ipv4) return 1;
		}
	}
	return 0;
}

int ReadAddressGroupPolicy(struct io_buffer *head)
{
	struct list1_head *gpos;
	struct list1_head *mpos;
	list1_for_each_cookie(gpos, head->read_var1, &address_group_list) {
		struct address_group_entry *group;
		group = list1_entry(gpos, struct address_group_entry, list);
		list1_for_each_cookie(mpos, head->read_var2, &group->address_group_member_list) {
			char buf[128];
			struct address_group_member *member;
			member = list1_entry(mpos, struct address_group_member, list);
			if (member->is_deleted) continue;
			if (member->is_ipv6) {
				const struct in6_addr *min_address = member->min.ipv6, *max_address = member->max.ipv6;
				print_ipv6(buf, sizeof(buf), min_address);
				if (min_address != max_address) {
					char *cp = strchr(buf, '\0');
					*cp++ = '-';
					print_ipv6(cp, sizeof(buf) - strlen(buf), max_address);
				}
			} else {
				const u32 min_address = member->min.ipv4, max_address = member->max.ipv4;
				memset(buf, 0, sizeof(buf));
				snprintf(buf, sizeof(buf) - 1, "%u.%u.%u.%u", HIPQUAD(min_address));
				if (min_address != max_address) {
					const int len = strlen(buf);
					snprintf(buf + len, sizeof(buf) - 1 - len, "-%u.%u.%u.%u", HIPQUAD(max_address));
				}
			}
			if (io_printf(head, KEYWORD_ADDRESS_GROUP "%s %s\n", group->group_name->name, buf)) return -ENOMEM;
		}
	}
	return 0;
}

/*************************  NETWORK NETWORK ACL HANDLER  *************************/

#if !defined(NIP6)
#define NIP6(addr) \
        ntohs((addr).s6_addr16[0]), \
        ntohs((addr).s6_addr16[1]), \
        ntohs((addr).s6_addr16[2]), \
        ntohs((addr).s6_addr16[3]), \
        ntohs((addr).s6_addr16[4]), \
        ntohs((addr).s6_addr16[5]), \
        ntohs((addr).s6_addr16[6]), \
        ntohs((addr).s6_addr16[7])
#endif

char *print_ipv6(char *buffer, const int buffer_len, const struct in6_addr *ip)
{
	memset(buffer, 0, buffer_len);
	snprintf(buffer, buffer_len - 1, "%x:%x:%x:%x:%x:%x:%x:%x", NIP6(*ip));
	return buffer;
}

const char *net_operation2keyword(const u8 operation)
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

static int AddNetworkEntry(const u8 operation, const u8 record_type, const struct address_group_entry *group, const u32 *min_address, const u32 *max_address, const u16 min_port, const u16 max_port, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	struct acl_info *ptr;
	struct ip_network_acl_record *acl;
	int error = -ENOMEM;
	const u32 min_ip = ntohl(*min_address), max_ip = ntohl(*max_address); /* using host byte order to allow u32 comparison than memcmp().*/
	const struct in6_addr *saved_min_address = NULL, *saved_max_address = NULL;
	if (!domain) return -EINVAL;
	if (record_type == IP_RECORD_TYPE_IPv6) {
		if ((saved_min_address = SaveIPv6Address((struct in6_addr *) min_address)) == NULL
		    || (saved_max_address = SaveIPv6Address((struct in6_addr *) max_address)) == NULL) return -ENOMEM;
	}
	mutex_lock(&domain_acl_lock);
	if (!is_delete) {
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			if ((ptr->type & ~(ACL_DELETED | ACL_WITH_CONDITION)) != TYPE_IP_NETWORK_ACL) continue;
			if (GetConditionPart(ptr) != condition) continue;
			acl = container_of(ptr, struct ip_network_acl_record, head);
			if (acl->operation_type != operation || acl->record_type != record_type || acl->min_port != min_port || max_port != acl->max_port) continue;
			if (record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
				if (acl->u.group != group) continue;
			} else if (record_type == IP_RECORD_TYPE_IPv4) {
				if (acl->u.ipv4.min != min_ip || max_ip != acl->u.ipv4.max) continue;
			} else if (record_type == IP_RECORD_TYPE_IPv6) {
				if (acl->u.ipv6.min != saved_min_address || saved_max_address != acl->u.ipv6.max) continue;
			}
			error = AddDomainACL(NULL, ptr);
			goto out;
		}
		/* Not found. Append it to the tail. */
		if ((acl = alloc_acl_element(TYPE_IP_NETWORK_ACL, condition)) == NULL) goto out;
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
		error = AddDomainACL(domain, &acl->head);
	} else {
		error = -ENOENT;
		list1_for_each_entry(ptr, &domain->acl_info_list, list) {
			if ((ptr->type & ~ACL_WITH_CONDITION) != TYPE_IP_NETWORK_ACL) continue;
			if (GetConditionPart(ptr) != condition) continue;
			acl = container_of(ptr, struct ip_network_acl_record, head);
			if (acl->operation_type != operation || acl->record_type != record_type || acl->min_port != min_port || max_port != acl->max_port) continue;
			if (record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
				if (acl->u.group != group) continue;
			} else if (record_type == IP_RECORD_TYPE_IPv4) {
				if (acl->u.ipv4.min != min_ip || max_ip != acl->u.ipv4.max) continue;
			} else if (record_type == IP_RECORD_TYPE_IPv6) {
				if (acl->u.ipv6.min != saved_min_address || saved_max_address != acl->u.ipv6.max) continue;
			}
			error = DelDomainACL(ptr);
			break;
		}
	}
 out: ;
	mutex_unlock(&domain_acl_lock);
	return error;
}

static int CheckNetworkEntry(const bool is_ipv6, const u8 operation, const u32 *address, const u16 port)
{
	struct domain_info * const domain = current->domain_info;
	struct acl_info *ptr;
	const char *keyword = net_operation2keyword(operation);
	const u8 profile = current->domain_info->profile;
	const u8 mode = CheckCCSFlags(CCS_TOMOYO_MAC_FOR_NETWORK);
	const bool is_enforce = (mode == 3);
	const u32 ip = ntohl(*address); /* using host byte order to allow u32 comparison than memcmp().*/
	bool found = 0;
	if (!mode) return 0;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
		struct ip_network_acl_record *acl;
		if ((ptr->type & ~ACL_WITH_CONDITION) != TYPE_IP_NETWORK_ACL) continue;
		acl = container_of(ptr, struct ip_network_acl_record, head);
		if (acl->operation_type != operation || port < acl->min_port || acl->max_port < port || !CheckCondition(ptr, NULL)) continue;
		if (acl->record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
			if (!AddressMatchesToGroup(is_ipv6, address, acl->u.group)) continue;
		} else if (acl->record_type == IP_RECORD_TYPE_IPv4) {
			if (is_ipv6 || ip < acl->u.ipv4.min || acl->u.ipv4.max < ip) continue;
		} else {
			if (!is_ipv6 || memcmp(acl->u.ipv6.min, address, 16) > 0 || memcmp(address, acl->u.ipv6.max, 16) > 0) continue;
		}
		UpdateCondition(ptr);
		found = 1;
		break;
	}
	AuditNetworkLog(is_ipv6, keyword, address, port, found, profile, mode);
	if (found) return 0;
	if (TomoyoVerboseMode()) {
		if (is_ipv6) {
			char buf[64];
			print_ipv6(buf, sizeof(buf), (const struct in6_addr *) address);
			printk("TOMOYO-%s: %s to %s %u denied for %s\n", GetMSG(is_enforce), keyword, buf, port, GetLastName(domain));
		} else {
			printk("TOMOYO-%s: %s to %u.%u.%u.%u %u denied for %s\n", GetMSG(is_enforce), keyword, HIPQUAD(ip), port, GetLastName(domain));
		}
	}
	if (is_enforce) {
		if (is_ipv6) {
			char buf[64];
			print_ipv6(buf, sizeof(buf), (const struct in6_addr *) address);
			return CheckSupervisor("%s\n" KEYWORD_ALLOW_NETWORK "%s %s %u\n", domain->domainname->name, keyword, buf, port);
		}
		return CheckSupervisor("%s\n" KEYWORD_ALLOW_NETWORK "%s %u.%u.%u.%u %u\n", domain->domainname->name, keyword, HIPQUAD(ip), port);
	}
	else if (mode == 1 && CheckDomainQuota(domain)) AddNetworkEntry(operation, is_ipv6 ? IP_RECORD_TYPE_IPv6 : IP_RECORD_TYPE_IPv4, NULL, address, address, port, port, domain, NULL, 0);
	return 0;
}

int AddNetworkPolicy(char *data, struct domain_info *domain, const struct condition_list *condition, const bool is_delete)
{
	u8 sock_type, operation, record_type;
	u16 min_address[8], max_address[8];
	struct address_group_entry *group = NULL;
	u16 min_port, max_port;
	u8 count;
	char *cp1 = NULL, *cp2 = NULL;
	if ((cp1 = strchr(data, ' ')) == NULL) goto out; cp1++;
	if (strncmp(data, "TCP ", 4) == 0) sock_type = SOCK_STREAM;
	else if (strncmp(data, "UDP ", 4) == 0) sock_type = SOCK_DGRAM;
	else if (strncmp(data, "RAW ", 4) == 0) sock_type = SOCK_RAW;
	else goto out;
	if ((cp2 = strchr(cp1, ' ')) == NULL) goto out; cp2++;
	if (strncmp(cp1, "bind ", 5) == 0) {
		operation = (sock_type == SOCK_STREAM) ? NETWORK_ACL_TCP_BIND : (sock_type == SOCK_DGRAM) ? NETWORK_ACL_UDP_BIND : NETWORK_ACL_RAW_BIND;
	} else if (strncmp(cp1, "connect ", 8) == 0) {
		operation = (sock_type == SOCK_STREAM) ? NETWORK_ACL_TCP_CONNECT : (sock_type == SOCK_DGRAM) ? NETWORK_ACL_UDP_CONNECT : NETWORK_ACL_RAW_CONNECT;
	} else if (sock_type == SOCK_STREAM && strncmp(cp1, "listen ", 7) == 0) {
		operation = NETWORK_ACL_TCP_LISTEN;
	} else if (sock_type == SOCK_STREAM && strncmp(cp1, "accept ", 7) == 0) {
		operation = NETWORK_ACL_TCP_ACCEPT;
	} else {
		goto out;
	}
	if ((cp1 = strchr(cp2, ' ')) == NULL) goto out; *cp1++ = '\0';
	if ((count = sscanf(cp2, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx-%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
			    &min_address[0], &min_address[1], &min_address[2], &min_address[3],
			    &min_address[4], &min_address[5], &min_address[6], &min_address[7],
			    &max_address[0], &max_address[1], &max_address[2], &max_address[3],
			    &max_address[4], &max_address[5], &max_address[6], &max_address[7])) == 8 || count == 16) {
		u8 i;
		for (i = 0; i < 8; i++) {
			min_address[i] = htons(min_address[i]);
			max_address[i] = htons(max_address[i]);
		}
		if (count == 8) memmove(max_address, min_address, sizeof(min_address));
		record_type = IP_RECORD_TYPE_IPv6;
	} else if ((count = sscanf(cp2, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
				   &min_address[0], &min_address[1], &min_address[2], &min_address[3],
				   &max_address[0], &max_address[1], &max_address[2], &max_address[3])) == 4 || count == 8) {
		u32 ip = htonl((((u8) min_address[0]) << 24) + (((u8) min_address[1]) << 16) + (((u8) min_address[2]) << 8) + (u8) min_address[3]);
		* (u32 *) min_address = ip;
		if (count == 8) ip = htonl((((u8) max_address[0]) << 24) + (((u8) max_address[1]) << 16) + (((u8) max_address[2]) << 8) + (u8) max_address[3]);
		* (u32 *) max_address = ip;
		record_type = IP_RECORD_TYPE_IPv4;
	} else if (*cp2 == '@') {
		if ((group = FindOrAssignNewAddressGroup(cp2 + 1)) == NULL) return -ENOMEM;
		record_type = IP_RECORD_TYPE_ADDRESS_GROUP;
	} else {
		goto out;
	}
	if (strchr(cp1, ' ')) goto out;
	if ((count = sscanf(cp1, "%hu-%hu", &min_port, &max_port)) == 1 || count == 2) {
		if (count == 1) max_port = min_port;
		return AddNetworkEntry(operation, record_type, group, (u32 *) min_address, (u32 *) max_address, min_port, max_port, domain, condition, is_delete);
	}
 out: ;
	return -EINVAL;
}

int CheckNetworkListenACL(const _Bool is_ipv6, const u8 *address, const u16 port)
{
	return CheckNetworkEntry(is_ipv6, NETWORK_ACL_TCP_LISTEN, (const u32 *) address, ntohs(port));
}

int CheckNetworkConnectACL(const _Bool is_ipv6, const int sock_type, const u8 *address, const u16 port)
{
	return CheckNetworkEntry(is_ipv6, sock_type == SOCK_STREAM ? NETWORK_ACL_TCP_CONNECT : (sock_type == SOCK_DGRAM ? NETWORK_ACL_UDP_CONNECT : NETWORK_ACL_RAW_CONNECT), (const u32 *) address, ntohs(port));
}

int CheckNetworkBindACL(const _Bool is_ipv6, const int sock_type, const u8 *address, const u16 port)
{
	return CheckNetworkEntry(is_ipv6, sock_type == SOCK_STREAM ? NETWORK_ACL_TCP_BIND : (sock_type == SOCK_DGRAM ? NETWORK_ACL_UDP_BIND : NETWORK_ACL_RAW_BIND), (const u32 *) address, ntohs(port));
}

int CheckNetworkAcceptACL(const _Bool is_ipv6, const u8 *address, const u16 port)
{
	int retval;
	current->tomoyo_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	retval = CheckNetworkEntry(is_ipv6, NETWORK_ACL_TCP_ACCEPT, (const u32 *) address, ntohs(port));
	current->tomoyo_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	return retval;
}

int CheckNetworkSendMsgACL(const _Bool is_ipv6, const int sock_type, const u8 *address, const u16 port)
{
	return CheckNetworkEntry(is_ipv6, sock_type == SOCK_DGRAM ? NETWORK_ACL_UDP_CONNECT : NETWORK_ACL_RAW_CONNECT, (const u32 *) address, ntohs(port));
}

int CheckNetworkRecvMsgACL(const _Bool is_ipv6, const int sock_type, const u8 *address, const u16 port)
{
	int retval;
	current->tomoyo_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	retval = CheckNetworkEntry(is_ipv6, sock_type == SOCK_DGRAM ? NETWORK_ACL_UDP_CONNECT : NETWORK_ACL_RAW_CONNECT, (const u32 *) address, ntohs(port));
	current->tomoyo_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	return retval;
}

/***** TOMOYO Linux end. *****/
