/*
 * fs/tomoyo_network.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.4   2007/04/01
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

/*************************  VARIABLES  *************************/

extern struct semaphore domain_acl_lock;

/*************************  AUDIT FUNCTIONS  *************************/

#ifdef CONFIG_TOMOYO_AUDIT
static int AuditNetworkLog(const int is_ipv6, const char *operation, const u32 *address, const u16 port, const int is_granted)
{
	char *buf;
	int len = 256;
	if (CanSaveAuditLog(is_granted) < 0) return -ENOMEM;
	if ((buf = InitAuditLog(&len)) == NULL) return -ENOMEM;
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, KEYWORD_ALLOW_NETWORK "%s ", operation);
	if (is_ipv6) {
		print_ipv6(buf + strlen(buf), len - strlen(buf), (const u16 *) address);
	} else {
		u32 ip = *address;
		snprintf(buf + strlen(buf), len - strlen(buf) - 1, "%u.%u.%u.%u", NIPQUAD(ip));
	}
	snprintf(buf + strlen(buf), len - strlen(buf) - 1, " %u\n", port);
	return WriteAuditLog(buf, is_granted);
}
#else
static inline void AuditNetworkLog(const int is_ipv6, const char *operation, const u32 *address, const u16 port, const int is_granted) {}
#endif

/*************************  ADDRESS GROUP HANDLER  *************************/

static ADDRESS_GROUP_ENTRY *group_list = NULL;

static int AddAddressGroupEntry(const char *group_name, const u8 is_ipv6, const u16 *min_address, const u16 *max_address, const int is_delete)
{
	static DECLARE_MUTEX(lock);
	ADDRESS_GROUP_ENTRY *new_group, *group;
	ADDRESS_GROUP_MEMBER *new_member, *member;
	const struct path_info *saved_group_name;
	int error = -ENOMEM;
	if (!IsCorrectPath(group_name, 0, 0, 0, __FUNCTION__) || !group_name[0]) return -EINVAL;
	if ((saved_group_name = SaveName(group_name)) == NULL) return -ENOMEM;
	down(&lock);
	for (group = group_list; group; group = group->next) {
		if (saved_group_name != group->group_name) continue;
		for (member = group->first_member; member; member = member->next) {
			if (member->is_ipv6 != is_ipv6) continue;
			if (is_ipv6) {
				if (memcmp(member->min.ipv6, min_address, 16) || memcmp(member->max.ipv6, max_address, 16)) continue;
			} else {
				if (member->min.ipv4 != * (u32 *) min_address || member->max.ipv4 != * (u32 *) max_address) continue;
			}
			member->is_deleted = is_delete;
			error = 0;
			goto out;
		}
		break;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	if (!group) {
		if ((new_group = (ADDRESS_GROUP_ENTRY *) alloc_element(sizeof(ADDRESS_GROUP_ENTRY))) == NULL) goto out;
		new_group->group_name = saved_group_name;
		mb(); /* Instead of using spinlock. */
		if ((group = group_list) != NULL) {
			while (group->next) group = group->next; group->next = new_group;
		} else {
			group_list= new_group;
		}
		group = new_group;
	}
	if ((new_member = (ADDRESS_GROUP_MEMBER *) alloc_element(sizeof(ADDRESS_GROUP_MEMBER))) == NULL) goto out;
	new_member->is_ipv6 = is_ipv6;
	if (is_ipv6) {
		memmove(new_member->min.ipv6, min_address, 16);
		memmove(new_member->max.ipv6, max_address, 16);
	} else {
		new_member->min.ipv4 = * (u32 *) min_address;
		new_member->max.ipv4 = * (u32 *) max_address;
	}
	mb(); /* Instead of using spinlock. */
	if ((member = group->first_member) != NULL) {
		while (member->next) member = member->next; member->next = new_member;
	} else {
		group->first_member = new_member;
	}
	error = 0;
 out:
	up(&lock);
	return error;
}

int AddAddressGroupPolicy(char *data, const int is_delete)
{
	int count, is_ipv6;
	u16 min_address[8], max_address[8];
	char *cp = strchr(data, ' ');
	if (!cp) return -EINVAL;
	*cp++ = '\0';
	if ((count = sscanf(cp, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx-%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
						&min_address[0], &min_address[1], &min_address[2], &min_address[3],
						&min_address[4], &min_address[5], &min_address[6], &min_address[7],
						&max_address[0], &max_address[1], &max_address[2], &max_address[3],
						&max_address[4], &max_address[5], &max_address[6], &max_address[7])) == 8 || count == 16) {
		int i;
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

static ADDRESS_GROUP_ENTRY *FindOrAssignNewAddressGroup(const char *group_name)
{
	int i;
	ADDRESS_GROUP_ENTRY *group;
	for (i = 0; i <= 1; i++) {
		for (group = group_list; group; group = group->next) {
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

static int AddressMatchesToGroup(const u8 is_ipv6, const u32 *address, const ADDRESS_GROUP_ENTRY *group)
{
	ADDRESS_GROUP_MEMBER *member;
	const u32 ip = ntohl(*address);
	for (member = group->first_member; member; member = member->next) {
		if (member->is_deleted) continue;
		if (member->is_ipv6) {
			if (is_ipv6 && memcmp(member->min.ipv6, address, 16) <= 0 && memcmp(address, member->max.ipv6, 16) <= 0) return 1;
		} else {
			if (!is_ipv6 && member->min.ipv4 <= ip && ip <= member->max.ipv4) return 1;
		}
	}
	return 0;
}

int ReadAddressGroupPolicy(IO_BUFFER *head)
{
	ADDRESS_GROUP_ENTRY *group = (ADDRESS_GROUP_ENTRY *) head->read_var1;
	ADDRESS_GROUP_MEMBER *member = (ADDRESS_GROUP_MEMBER *) head->read_var2;
	if (!group) group = group_list;
	while (group) {
		head->read_var1 = (struct domain_info *) group;
		if (!member) member = group->first_member;
		while (member) {
			head->read_var2 = (void *) member;
			if (!member->is_deleted) {
				char buf[128];
				if (member->is_ipv6) {
					const u16 *min_address = member->min.ipv6, *max_address = member->max.ipv6;
					print_ipv6(buf, sizeof(buf), min_address);
					if (memcmp(min_address, max_address, 16)) {
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
				if (io_printf(head, KEYWORD_ADDRESS_GROUP "%s %s\n", group->group_name->name, buf)) break;
			}
			member = member->next;
		}
		if (member) break;
		head->read_var2 = NULL;
		group = group->next;
	}
	return group ? -ENOMEM : 0;
}

/*************************  NETWORK NETWORK ACL HANDLER  *************************/

char *print_ipv6(char *buffer, const int buffer_len, const u16 *ip)
{
	memset(buffer, 0, buffer_len);
	snprintf(buffer, buffer_len - 1, "%x:%x:%x:%x:%x:%x:%x:%x", ntohs(ip[0]), ntohs(ip[1]), ntohs(ip[2]), ntohs(ip[3]), ntohs(ip[4]), ntohs(ip[5]), ntohs(ip[6]), ntohs(ip[7]));
	return buffer;
}

const char *network2keyword(const unsigned int operation)
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

static int AddNetworkEntry(const u8 operation, const u8 record_type, const struct address_group_entry *group, const u32 *min_address, const u32 *max_address, const u16 min_port, const u16 max_port, struct domain_info *domain, const u8 is_add, const struct condition_list *condition)
{
	struct acl_info *ptr;
	int error = -ENOMEM;
	const u32 min_ip = ntohl(*min_address), max_ip = ntohl(*max_address); /* using host byte order to allow u32 comparison than memcmp().*/
	if (!domain) return -EINVAL;
	down(&domain_acl_lock);
	if (is_add) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			IP_NETWORK_ACL_RECORD *new_ptr;
			if (ptr->type == TYPE_IP_NETWORK_ACL && ptr->u.b[0] == operation && ptr->u.b[1] == record_type && ptr->cond == condition && ((IP_NETWORK_ACL_RECORD *) ptr)->min_port == min_port && max_port == ((IP_NETWORK_ACL_RECORD *) ptr)->max_port) {
				if (record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
					if (((IP_NETWORK_ACL_RECORD *) ptr)->u.group == group) {
						ptr->is_deleted = 0;
						/* Found. Nothing to do. */
						error = 0;
						break;
					}
				} else if (record_type == IP_RECORD_TYPE_IPv4) {
					if (((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv4.min == min_ip && max_ip == ((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv4.max) {
						ptr->is_deleted = 0;
						/* Found. Nothing to do. */
						error = 0;
						break;
					}
				} else if (record_type == IP_RECORD_TYPE_IPv6) {
					if (memcmp(((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv6.min, min_address, 16) == 0 && memcmp(max_address, ((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv6.max, 16) == 0) {
						ptr->is_deleted = 0;
						/* Found. Nothing to do. */
						error = 0;
						break;
					}
				}
			}
			if (ptr->next) {
				ptr = ptr->next;
				continue;
			}
		first_entry: ;
			if (is_add == 1 && TooManyDomainACL(domain)) break;
			/* Not found. Append it to the tail. */
			if ((new_ptr = (IP_NETWORK_ACL_RECORD *) alloc_element(sizeof(IP_NETWORK_ACL_RECORD))) == NULL) break;
			new_ptr->head.type = TYPE_IP_NETWORK_ACL;
			new_ptr->head.u.b[0] = operation;
			new_ptr->head.u.b[1] = record_type;
			new_ptr->head.cond = condition;
			if (record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
				new_ptr->u.group = group;
			} else if (record_type == IP_RECORD_TYPE_IPv4) {
				new_ptr->u.ipv4.min = min_ip;
				new_ptr->u.ipv4.max = max_ip;
			} else {
				memmove(new_ptr->u.ipv6.min, min_address, 16);
				memmove(new_ptr->u.ipv6.max, max_address, 16);
			}
			new_ptr->min_port = min_port;
			new_ptr->max_port = max_port;
			error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			break;
		}
	} else {
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
			if (ptr->type != TYPE_IP_NETWORK_ACL || ptr->is_deleted || ptr->u.b[0] != operation || ptr->u.b[1] != record_type || ptr->cond != condition || ((IP_NETWORK_ACL_RECORD *) ptr)->min_port != min_port || ((IP_NETWORK_ACL_RECORD *) ptr)->max_port != max_port) continue;
			if (record_type == IP_RECORD_TYPE_ADDRESS_GROUP) {
				if (((IP_NETWORK_ACL_RECORD *) ptr)->u.group != group) continue;
			} else if (record_type == IP_RECORD_TYPE_IPv4) {
				if (((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv4.min != min_ip || max_ip != ((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv4.max) continue;
			} else if (record_type == IP_RECORD_TYPE_IPv6) {
				if (memcmp(((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv6.min, min_address, 16) || memcmp(max_address, ((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv6.max, 16)) continue;
			}
			error = DelDomainACL(ptr);
			break;
		}
	}
	up(&domain_acl_lock);
	return error;
}

static int CheckNetworkEntry(const int is_ipv6, const int operation, const u32 *address, const u16 port)
{
	struct domain_info * const domain = current->domain_info;
	struct acl_info *ptr;
	const char *keyword = network2keyword(operation);
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_NETWORK);
	const u32 ip = ntohl(*address); /* using host byte order to allow u32 comparison than memcmp().*/
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_NETWORK)) return 0;
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (ptr->type != TYPE_IP_NETWORK_ACL || ptr->is_deleted || ptr->u.b[0] != operation || port < ((IP_NETWORK_ACL_RECORD *) ptr)->min_port || ((IP_NETWORK_ACL_RECORD *) ptr)->max_port < port || CheckCondition(ptr->cond, NULL)) continue;
		if (ptr->u.b[1] == IP_RECORD_TYPE_ADDRESS_GROUP) {
			if (AddressMatchesToGroup(is_ipv6, address, ((IP_NETWORK_ACL_RECORD *) ptr)->u.group)) break;
		} else if (ptr->u.b[1] == IP_RECORD_TYPE_IPv4) {
			if (!is_ipv6 && ((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv4.min <= ip && ip <= ((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv4.max) break;
		} else {
			if (is_ipv6 && memcmp(((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv6.min, address, 16) <= 0 && memcmp(address, ((IP_NETWORK_ACL_RECORD *) ptr)->u.ipv6.max, 16) <= 0) break;
		}
	}
	if (ptr) {
		AuditNetworkLog(is_ipv6, keyword, address, port, 1);
		return 0;
	}
	if (TomoyoVerboseMode()) {
		if (is_ipv6) {
			char buf[64];
			print_ipv6(buf, sizeof(buf), (const u16 *) address);
			printk("TOMOYO-%s: %s to %s %u denied for %s\n", GetMSG(is_enforce), keyword, buf, port, GetLastName(domain));
		} else {
			printk("TOMOYO-%s: %s to %u.%u.%u.%u %u denied for %s\n", GetMSG(is_enforce), keyword, HIPQUAD(ip), port, GetLastName(domain));
		}
	}
	AuditNetworkLog(is_ipv6, keyword, address, port, 0);
	if (is_enforce) {
		if (is_ipv6) {
			char buf[64];
			print_ipv6(buf, sizeof(buf), (const u16 *) address);
			return CheckSupervisor("%s\n" KEYWORD_ALLOW_NETWORK "%s %s %u\n", domain->domainname->name, keyword, buf, port);
		}
		return CheckSupervisor("%s\n" KEYWORD_ALLOW_NETWORK "%s %u.%u.%u.%u %u\n", domain->domainname->name, keyword, HIPQUAD(ip), port);
	}
	if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_NETWORK)) AddNetworkEntry(operation, is_ipv6 ? IP_RECORD_TYPE_IPv6: IP_RECORD_TYPE_IPv4, NULL, address, address, port, port, domain, 1, NULL);
	return 0;
}

int AddNetworkPolicy(char *data, struct domain_info *domain, const int is_delete)
{
	u8 sock_type, operation, record_type;
	u16 min_address[8], max_address[8];
	struct address_group_entry *group = NULL;
	u16 min_port, max_port;
	int count;
	char *cp1 = NULL, *cp2 = NULL;
	const struct condition_list *condition = NULL;
	cp1 = FindConditionPart(data);
	if (cp1 && (condition = FindOrAssignNewCondition(cp1)) == NULL) goto out;
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
		int i;
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
		return AddNetworkEntry(operation, record_type, group, (u32 *) min_address, (u32 *) max_address, min_port, max_port, domain, is_delete ? 0 : -1, condition);
	}
 out: ;
	return -EINVAL;
}

int CheckNetworkListenACL(const int is_ipv6, const u8 *address, const u16 port)
{
	return CheckNetworkEntry(is_ipv6, NETWORK_ACL_TCP_LISTEN, (const u32 *) address, ntohs(port));
}

int CheckNetworkConnectACL(const int is_ipv6, const int sock_type, const u8 *address, const u16 port)
{
	return CheckNetworkEntry(is_ipv6, sock_type == SOCK_STREAM ? NETWORK_ACL_TCP_CONNECT : (sock_type == SOCK_DGRAM ? NETWORK_ACL_UDP_CONNECT : NETWORK_ACL_RAW_CONNECT), (const u32 *) address, ntohs(port));
}

int CheckNetworkBindACL(const int is_ipv6, const int sock_type, const u8 *address, const u16 port)
{
	return CheckNetworkEntry(is_ipv6, sock_type == SOCK_STREAM ? NETWORK_ACL_TCP_BIND : (sock_type == SOCK_DGRAM ? NETWORK_ACL_UDP_BIND : NETWORK_ACL_RAW_BIND), (const u32 *) address, ntohs(port));
}

int CheckNetworkAcceptACL(const int is_ipv6, const u8 *address, const u16 port)
{
	return CheckNetworkEntry(is_ipv6, NETWORK_ACL_TCP_ACCEPT, (const u32 *) address, ntohs(port));
}

int CheckNetworkSendMsgACL(const int is_ipv6, const int sock_type, const u8 *address, const u16 port)
{
	return CheckNetworkEntry(is_ipv6, sock_type == SOCK_DGRAM ? NETWORK_ACL_UDP_CONNECT : NETWORK_ACL_RAW_CONNECT, (const u32 *) address, ntohs(port));
}

int CheckNetworkRecvMsgACL(const int is_ipv6, const int sock_type, const u8 *address, const u16 port)
{
	return CheckNetworkEntry(is_ipv6, sock_type == SOCK_DGRAM ? NETWORK_ACL_UDP_CONNECT : NETWORK_ACL_RAW_CONNECT, (const u32 *) address, ntohs(port));
}

EXPORT_SYMBOL(CheckNetworkListenACL);
EXPORT_SYMBOL(CheckNetworkConnectACL);
EXPORT_SYMBOL(CheckNetworkBindACL);
EXPORT_SYMBOL(CheckNetworkAcceptACL);
EXPORT_SYMBOL(CheckNetworkSendMsgACL);
EXPORT_SYMBOL(CheckNetworkRecvMsgACL);

/***** TOMOYO Linux end. *****/
