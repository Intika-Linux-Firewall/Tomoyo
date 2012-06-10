/*
 * fs/tomoyo_network.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.3.1   2006/12/08
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

static int AddNetworkEntry(const int is_ipv6, const int operation, const u32 *min_address, const u32 *max_address, const u16 min_port, const u16 max_port, struct domain_info *domain, const int is_delete, const struct condition_list *condition)
{
	struct acl_info *ptr;
	int error = -ENOMEM;
	const unsigned int type_hash = MAKE_ACL_TYPE(is_ipv6 ? TYPE_IPv6_NETWORK_ACL : TYPE_IPv4_NETWORK_ACL) + MAKE_ACL_HASH(operation);
	const u32 min_ip = ntohl(*min_address), max_ip = ntohl(*max_address); /* using host byte order to allow u32 comparison than memcmp().*/
	if (!domain) return -EINVAL;
	down(&domain_acl_lock);
	if (!is_delete) {
		if ((ptr = domain->first_acl_ptr) == NULL) goto first_entry;
		while (1) {
			if (ptr->type_hash == type_hash && ptr->cond == condition) {
				if (is_ipv6) {
					if (((IPv6_NETWORK_ACL_RECORD *) ptr)->min_port == min_port && max_port == ((IPv6_NETWORK_ACL_RECORD *) ptr)->max_port &&  memcmp(((IPv6_NETWORK_ACL_RECORD *) ptr)->min_address, min_address, 16) == 0 && memcmp(max_address, ((IPv6_NETWORK_ACL_RECORD *) ptr)->max_address, 16) == 0) {
						/* Found. Nothing to do. */
						error = 0;
						break;
					}
				} else {
					if (((IPv4_NETWORK_ACL_RECORD *) ptr)->min_port == min_port && max_port == ((IPv4_NETWORK_ACL_RECORD *) ptr)->max_port &&  ((IPv4_NETWORK_ACL_RECORD *) ptr)->min_address == min_ip && max_ip == ((IPv4_NETWORK_ACL_RECORD *) ptr)->max_address) {
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
			/* Not found. Append it to the tail. */
			if (is_ipv6) {
				IPv6_NETWORK_ACL_RECORD *new_ptr;
				if ((new_ptr = (IPv6_NETWORK_ACL_RECORD *) alloc_element(sizeof(IPv6_NETWORK_ACL_RECORD))) == NULL) break;
				new_ptr->head.type_hash = type_hash;
				new_ptr->head.cond = condition;
				memmove(new_ptr->min_address, min_address, 16);
				memmove(new_ptr->max_address, max_address, 16);
				new_ptr->min_port = min_port;
				new_ptr->max_port = max_port;
				error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			} else {
				IPv4_NETWORK_ACL_RECORD *new_ptr;
				if ((new_ptr = (IPv4_NETWORK_ACL_RECORD *) alloc_element(sizeof(IPv4_NETWORK_ACL_RECORD))) == NULL) break;
				new_ptr->head.type_hash = type_hash;
				new_ptr->head.cond = condition;
				new_ptr->min_address = min_ip;
				new_ptr->max_address = max_ip;
				new_ptr->min_port = min_port;
				new_ptr->max_port = max_port;
				error = AddDomainACL(ptr, domain, (struct acl_info *) new_ptr);
			}
			break;
		}
	} else {
		struct acl_info *prev = NULL;
		error = -ENOENT;
		for (ptr = domain->first_acl_ptr; ptr; prev = ptr, ptr = ptr->next) {
			if (ptr->type_hash != type_hash || ptr->cond != condition) continue;
			if (is_ipv6) {
				if (((IPv6_NETWORK_ACL_RECORD *) ptr)->min_port != min_port || ((IPv6_NETWORK_ACL_RECORD *) ptr)->max_port != max_port || memcmp(((IPv6_NETWORK_ACL_RECORD *) ptr)->min_address, min_address, 16) || memcmp(max_address, ((IPv6_NETWORK_ACL_RECORD *) ptr)->max_address, 16)) continue;
			} else {
				if (((IPv4_NETWORK_ACL_RECORD *) ptr)->min_port != min_port || ((IPv4_NETWORK_ACL_RECORD *) ptr)->max_port != max_port || ((IPv4_NETWORK_ACL_RECORD *) ptr)->min_address != min_ip || max_ip != ((IPv4_NETWORK_ACL_RECORD *) ptr)->max_address) continue;
			}
			error = DelDomainACL(prev, domain, ptr);
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
	const unsigned int type_hash = MAKE_ACL_TYPE(is_ipv6 ? TYPE_IPv6_NETWORK_ACL : TYPE_IPv4_NETWORK_ACL) + MAKE_ACL_HASH(operation);
	const int is_enforce = CheckCCSEnforce(CCS_TOMOYO_MAC_FOR_NETWORK);
	const u32 ip = ntohl(*address); /* using host byte order to allow u32 comparison than memcmp().*/
	if (!CheckCCSFlags(CCS_TOMOYO_MAC_FOR_NETWORK)) return 0;
	for (ptr = domain->first_acl_ptr; ptr; ptr = ptr->next) {
		if (is_ipv6) {
			if (ptr->type_hash == type_hash && ((IPv6_NETWORK_ACL_RECORD *) ptr)->min_port <= port && port <= ((IPv6_NETWORK_ACL_RECORD *) ptr)->max_port && memcmp(((IPv6_NETWORK_ACL_RECORD *) ptr)->min_address, address, 16) <= 0 && memcmp(address, ((IPv6_NETWORK_ACL_RECORD *) ptr)->max_address, 16) <= 0 && CheckCondition(ptr->cond, NULL) == 0) break;
		} else {
			if (ptr->type_hash == type_hash && ((IPv4_NETWORK_ACL_RECORD *) ptr)->min_port <= port && port <= ((IPv4_NETWORK_ACL_RECORD *) ptr)->max_port && ((IPv4_NETWORK_ACL_RECORD *) ptr)->min_address <= ip && ip <= ((IPv4_NETWORK_ACL_RECORD *) ptr)->max_address && CheckCondition(ptr->cond, NULL) == 0) break;
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
			return CheckSupervisor("%s\n" KEYWORD_ALLOW_NETWORK "%s %s %u\n", domain->domainname, keyword, buf, port);
		}
		return CheckSupervisor("%s\n" KEYWORD_ALLOW_NETWORK "%s %u.%u.%u.%u %u\n", domain->domainname, keyword, HIPQUAD(ip), port);
	}
	if (CheckCCSAccept(CCS_TOMOYO_MAC_FOR_NETWORK)) AddNetworkEntry(is_ipv6, operation, address, address, port, port, domain, 0, NULL);
	return 0;
}

int AddNetworkPolicy(char *data, struct domain_info *domain, const int is_delete)
{
	int sock_type, operation, is_ipv6;
	u16 min_address[8], max_address[8];
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
	if ((cp1 = strchr(cp2, ' ')) == NULL) goto out; cp1++;
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
		is_ipv6 = 1;
	} else if ((count = sscanf(cp2, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
							   &min_address[0], &min_address[1], &min_address[2], &min_address[3],
 							   &max_address[0], &max_address[1], &max_address[2], &max_address[3])) == 4 || count == 8) {
		u32 ip = htonl((((u8) min_address[0]) << 24) + (((u8) min_address[1]) << 16) + (((u8) min_address[2]) << 8) + (u8) min_address[3]);
		* (u32 *) min_address = ip;
		if (count == 8) ip = htonl((((u8) max_address[0]) << 24) + (((u8) max_address[1]) << 16) + (((u8) max_address[2]) << 8) + (u8) max_address[3]);
		* (u32 *) max_address = ip;
		is_ipv6 = 0;
	} else {
		goto out;
	}
	if (strchr(cp1, ' ')) goto out;
	if ((count = sscanf(cp1, "%hu-%hu", &min_port, &max_port)) == 1 || count == 2) {
		if (count == 1) max_port = min_port;
		return AddNetworkEntry(is_ipv6, operation, (u32 *) min_address, (u32 *) max_address, min_port, max_port, domain, is_delete, condition);
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
