/*
 * security/ccsecurity/network.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/09/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include "internal.h"

struct ccs_inet_addr_info {
	u16 port;           /* In network byte order. */
	const u32 *address; /* In network byte order. */
	bool is_ipv6;
};

struct ccs_unix_addr_info {
	u8 *addr;
	unsigned int addr_len;
};

struct ccs_addr_info {
	u8 protocol;
	u8 operation;
	struct ccs_inet_addr_info inet;
	struct ccs_unix_addr_info unix0;
};

const char *ccs_proto_keyword[CCS_SOCK_MAX] = {
	[SOCK_STREAM]    = "stream",
	[SOCK_DGRAM]     = "dgram",
	[SOCK_RAW]       = "raw",
	[SOCK_SEQPACKET] = "seqpacket",
};

const char *ccs_socket_keyword[CCS_MAX_NETWORK_OPERATION] = {
	[CCS_NETWORK_BIND]    = "bind",
	[CCS_NETWORK_LISTEN]  = "listen",
	[CCS_NETWORK_CONNECT] = "connect",
	[CCS_NETWORK_ACCEPT]  = "accept",
	[CCS_NETWORK_SEND]    = "send",
	[CCS_NETWORK_RECV]    = "recv",
};

static int ccs_audit_net_log(struct ccs_request_info *r, const char *family,
			     const u8 proto, const u8 ope, const char *address)
{
	const char *protocol = ccs_proto_keyword[proto];
	const char *operation = ccs_socket_keyword[ope];
	ccs_write_log(r, "network %s %s %s %s\n", family,
		      protocol, operation, address);
	if (r->granted)
		return 0;
	ccs_warn_log(r, "network %s %s %s %s", family, protocol, operation,
		     address);
	return ccs_supervisor(r, "network %s %s %s %s\n", family, protocol,
			      operation, address);
}

/**
 * ccs_audit_inet_log - Audit INET network log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_inet_log(struct ccs_request_info *r)
{
	char buf[128];
	int len;
	const u32 *address = r->param.inet_network.address;
	if (r->param.inet_network.is_ipv6)
		ccs_print_ipv6(buf, sizeof(buf), (const struct in6_addr *)
			       address, (const struct in6_addr *) address);
	else
		ccs_print_ipv4(buf, sizeof(buf), r->param.inet_network.ip,
			       r->param.inet_network.ip);
	len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, " %u",
		 r->param.inet_network.port); 
	return ccs_audit_net_log(r, "inet", r->param.inet_network.protocol,
				 r->param.inet_network.operation, buf);
}

/**
 * ccs_audit_unix_log - Audit UNIX network log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_unix_log(struct ccs_request_info *r)
{
	return ccs_audit_net_log(r, "unix", r->param.unix_network.protocol,
				 r->param.unix_network.operation,
				 r->param.unix_network.address->name);
}

/**
 * ccs_parse_ip_address - Parse an IP address.
 *
 * @address: String to parse.
 * @min:     Pointer to store min address.
 * @max:     Pointer to store max address.
 *
 * Returns CCS_IP_ADDRESS_TYPE_IPv6 if @address is an IPv6,
 * CCS_IP_ADDRESS_TYPE_IPv4 if @address is an IPv4,
 * CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP otherwise.
 */
int ccs_parse_ip_address(char *address, u16 *min, u16 *max)
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
		return CCS_IP_ADDRESS_TYPE_IPv6;
	}
	count = sscanf(address, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
		       &min[0], &min[1], &min[2], &min[3],
		       &max[0], &max[1], &max[2], &max[3]);
	if (count == 4 || count == 8) {
		u32 ip = htonl((((u8) min[0]) << 24) + (((u8) min[1]) << 16)
			       + (((u8) min[2]) << 8) + (u8) min[3]);
		memmove(min, &ip, sizeof(ip));
		if (count == 8)
			ip = htonl((((u8) max[0]) << 24)
				   + (((u8) max[1]) << 16)
				   + (((u8) max[2]) << 8) + (u8) max[3]);
		memmove(max, &ip, sizeof(ip));
		return CCS_IP_ADDRESS_TYPE_IPv4;
	}
	return CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP;
}

/**
 * ccs_print_ipv4 - Print an IPv4 address.
 *
 * @buffer:     Buffer to write to.
 * @buffer_len: Size of @buffer.
 * @min_ip:     Min address in host byte order.
 * @max_ip:     Max address in host byte order.
 *
 * Returns nothing.
 */
void ccs_print_ipv4(char *buffer, const int buffer_len,
		    const u32 min_ip, const u32 max_ip)
{
	memset(buffer, 0, buffer_len);
	snprintf(buffer, buffer_len - 1, "%u.%u.%u.%u%c%u.%u.%u.%u",
		 HIPQUAD(min_ip), min_ip == max_ip ? '\0' : '-',
		 HIPQUAD(max_ip));
}

#if !defined(NIP6)
#define NIP6(addr)							\
	ntohs((addr).s6_addr16[0]), ntohs((addr).s6_addr16[1]),		\
		ntohs((addr).s6_addr16[2]), ntohs((addr).s6_addr16[3]), \
		ntohs((addr).s6_addr16[4]), ntohs((addr).s6_addr16[5]), \
		ntohs((addr).s6_addr16[6]), ntohs((addr).s6_addr16[7])
#endif

/**
 * ccs_print_ipv6 - Print an IPv6 address.
 *
 * @buffer:     Buffer to write to.
 * @buffer_len: Size of @buffer.
 * @min_ip:     Pointer to "struct in6_addr".
 * @max_ip:     Pointer to "struct in6_addr".
 *
 * Returns nothing.
 */
void ccs_print_ipv6(char *buffer, const int buffer_len,
		    const struct in6_addr *min_ip,
		    const struct in6_addr *max_ip)
{
	memset(buffer, 0, buffer_len);
	snprintf(buffer, buffer_len - 1,
		 "%x:%x:%x:%x:%x:%x:%x:%x%c%x:%x:%x:%x:%x:%x:%x:%x",
		 NIP6(*min_ip), min_ip == max_ip ? '\0' : '-',
		 NIP6(*max_ip));
}

static bool ccs_check_inet_acl(struct ccs_request_info *r,
			       const struct ccs_acl_info *ptr)
{
	const struct ccs_inet_acl *acl = container_of(ptr, typeof(*acl), head);
	bool ret;
	if (!(acl->perm & (1 << r->param.inet_network.operation)) ||
	    !ccs_compare_number_union(r->param.inet_network.port, &acl->port))
		return false;
	switch (acl->address_type) {
	case CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP:
		ret = ccs_address_matches_group(r->param.inet_network.is_ipv6,
						r->param.inet_network.address,
						acl->address.group);
		break;
	case CCS_IP_ADDRESS_TYPE_IPv4:
		ret = !r->param.inet_network.is_ipv6 &&
			acl->address.ipv4.min <= r->param.inet_network.ip &&
			r->param.inet_network.ip <= acl->address.ipv4.max;
		break;
	default:
		ret = r->param.inet_network.is_ipv6 &&
			memcmp(acl->address.ipv6.min,
			       r->param.inet_network.address, 16) <= 0 &&
			memcmp(r->param.inet_network.address,
			       acl->address.ipv6.max, 16) <= 0;
		break;
	}
	return ret;
}

static bool ccs_check_unix_acl(struct ccs_request_info *r,
			       const struct ccs_acl_info *ptr)
{
	const struct ccs_unix_acl *acl = container_of(ptr, typeof(*acl), head);
	return (acl->perm & (1 << r->param.unix_network.operation)) &&
		ccs_compare_name_union(r->param.unix_network.address,
				       &acl->name);
}

static const u8
ccs_inet2mac[CCS_SOCK_MAX][CCS_MAX_NETWORK_OPERATION] = {
	[SOCK_STREAM] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_INET_STREAM_BIND,
		[CCS_NETWORK_LISTEN]  = CCS_MAC_NETWORK_INET_STREAM_LISTEN,
		[CCS_NETWORK_CONNECT] = CCS_MAC_NETWORK_INET_STREAM_CONNECT,
		[CCS_NETWORK_ACCEPT]  = CCS_MAC_NETWORK_INET_STREAM_ACCEPT,
	},
	[SOCK_DGRAM] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_INET_DGRAM_BIND,
		[CCS_NETWORK_SEND]    = CCS_MAC_NETWORK_INET_DGRAM_SEND,
		[CCS_NETWORK_RECV]    = CCS_MAC_NETWORK_INET_DGRAM_RECV,
	},
	[SOCK_RAW]    = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_INET_RAW_BIND,
		[CCS_NETWORK_SEND]    = CCS_MAC_NETWORK_INET_RAW_SEND,
		[CCS_NETWORK_RECV]    = CCS_MAC_NETWORK_INET_RAW_RECV,
	},
};

static const u8
ccs_unix2mac[CCS_SOCK_MAX][CCS_MAX_NETWORK_OPERATION] = {
	[SOCK_STREAM] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_UNIX_STREAM_BIND,
		[CCS_NETWORK_LISTEN]  = CCS_MAC_NETWORK_UNIX_STREAM_LISTEN,
		[CCS_NETWORK_CONNECT] = CCS_MAC_NETWORK_UNIX_STREAM_CONNECT,
		[CCS_NETWORK_ACCEPT]  = CCS_MAC_NETWORK_UNIX_STREAM_ACCEPT,
	},
	[SOCK_DGRAM] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_UNIX_DGRAM_BIND,
		[CCS_NETWORK_SEND]    = CCS_MAC_NETWORK_UNIX_DGRAM_SEND,
		[CCS_NETWORK_RECV]    = CCS_MAC_NETWORK_UNIX_DGRAM_RECV,
	},
	[SOCK_SEQPACKET] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_UNIX_SEQPACKET_BIND,
		[CCS_NETWORK_LISTEN]  = CCS_MAC_NETWORK_UNIX_SEQPACKET_LISTEN,
		[CCS_NETWORK_CONNECT] = CCS_MAC_NETWORK_UNIX_SEQPACKET_CONNECT,
		[CCS_NETWORK_ACCEPT]  = CCS_MAC_NETWORK_UNIX_SEQPACKET_ACCEPT,
	},
};

static bool ccs_same_inet_acl(const struct ccs_acl_info *a,
				      const struct ccs_acl_info *b)
{
	const struct ccs_inet_acl *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_inet_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->protocol == p2->protocol &&
		p1->address_type == p2->address_type &&
		p1->address.ipv4.min == p2->address.ipv4.min &&
		p1->address.ipv6.min == p2->address.ipv6.min &&
		p1->address.ipv4.max == p2->address.ipv4.max &&
		p1->address.ipv6.max == p2->address.ipv6.max &&
		p1->address.group == p2->address.group &&
		ccs_same_number_union(&p1->port, &p2->port);
}

static bool ccs_same_unix_acl(const struct ccs_acl_info *a,
				      const struct ccs_acl_info *b)
{
	const struct ccs_unix_acl *p1 = container_of(a, typeof(*p1), head);
	const struct ccs_unix_acl *p2 = container_of(b, typeof(*p2), head);
	return p1->protocol == p2->protocol &&
		ccs_same_name_union(&p1->name, &p2->name);
}

static bool ccs_merge_inet_acl(struct ccs_acl_info *a, struct ccs_acl_info *b,
			       const bool is_delete)
{
	u8 * const a_perm = &container_of(a, struct ccs_inet_acl, head)->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct ccs_inet_acl, head)->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

static bool ccs_merge_unix_acl(struct ccs_acl_info *a, struct ccs_acl_info *b,
			       const bool is_delete)
{
	u8 * const a_perm = &container_of(a, struct ccs_unix_acl, head)->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct ccs_unix_acl, head)->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * ccs_write_inet_network - Write "struct ccs_inet_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_inet_network(struct ccs_acl_param *param)
{
	struct ccs_inet_acl e = { .head.type = CCS_TYPE_INET_ACL };
	u16 min_address[8];
	u16 max_address[8];
	int error = -EINVAL;
	u8 type;
	const char *protocol = ccs_read_token(param);
	const char *operation = ccs_read_token(param);
	char *address = ccs_read_token(param);
	for (e.protocol = 0; e.protocol < CCS_SOCK_MAX; e.protocol++)
		if (!strcmp(protocol, ccs_proto_keyword[e.protocol]))
			break;
	for (type = 0; type < CCS_MAX_NETWORK_OPERATION; type++)
		if (ccs_permstr(operation, ccs_socket_keyword[type]))
			e.perm |= 1 << type;
	if (e.protocol == CCS_SOCK_MAX || !e.perm)
		return -EINVAL;
	switch (ccs_parse_ip_address(address, min_address, max_address)) {
	case CCS_IP_ADDRESS_TYPE_IPv6:
		e.address_type = CCS_IP_ADDRESS_TYPE_IPv6;
		e.address.ipv6.min = ccs_get_ipv6_address((struct in6_addr *)
							    min_address);
		e.address.ipv6.max = ccs_get_ipv6_address((struct in6_addr *)
							    max_address);
		if (!e.address.ipv6.min || !e.address.ipv6.max)
			goto out;
		break;
	case CCS_IP_ADDRESS_TYPE_IPv4:
		e.address_type = CCS_IP_ADDRESS_TYPE_IPv4;
		/* use host byte order to allow u32 comparison.*/
		e.address.ipv4.min = ntohl(*(u32 *) min_address);
		e.address.ipv4.max = ntohl(*(u32 *) max_address);
		break;
	default:
		if (address[0] != '@')
			return -EINVAL;
		e.address_type = CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP;
		e.address.group = ccs_get_group(address + 1,
						CCS_ADDRESS_GROUP);
		if (!e.address.group)
			return -ENOMEM;
		break;
	}
	if (!ccs_parse_number_union(ccs_read_token(param), &e.port))
		goto out;
	error = ccs_update_domain(&e.head, sizeof(e), param, ccs_same_inet_acl,
				  ccs_merge_inet_acl);
 out:
	if (e.address_type == CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP)
		ccs_put_group(e.address.group);
	else if (e.address_type == CCS_IP_ADDRESS_TYPE_IPv6) {
		ccs_put_ipv6_address(e.address.ipv6.min);
		ccs_put_ipv6_address(e.address.ipv6.max);
	}
	ccs_put_number_union(&e.port);
	return error;
}

/**
 * ccs_write_unix_network - Write "struct ccs_unix_acl" list.
 *
 * @param: Pointer to "struct ccs_acl_param".
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_unix_network(struct ccs_acl_param *param)
{
	struct ccs_unix_acl e = { .head.type = CCS_TYPE_UNIX_ACL };
	int error;
	u8 type;
	const char *protocol = ccs_read_token(param);
	const char *operation = ccs_read_token(param);
	for (e.protocol = 0; e.protocol < CCS_SOCK_MAX; e.protocol++)
		if (!strcmp(protocol, ccs_proto_keyword[e.protocol]))
			break;
	for (type = 0; type < CCS_MAX_NETWORK_OPERATION; type++)
		if (ccs_permstr(operation, ccs_socket_keyword[type]))
			e.perm |= 1 << type;
	if (e.protocol == CCS_SOCK_MAX || !e.perm)
		return -EINVAL;
	if (!ccs_parse_name_union(ccs_read_token(param), &e.name))
                return -EINVAL;
	error = ccs_update_domain(&e.head, sizeof(e), param, ccs_same_unix_acl,
				  ccs_merge_unix_acl);
	ccs_put_name_union(&e.name);
	return error;
}

#ifndef CONFIG_NET

void __init ccs_network_init(void)
{
	u8 i;
	for (i = 0; i < CCS_SOCK_MAX; i++)
		if (!ccs_proto_keyword[i])
			ccs_proto_keyword[i] = "unknown";
}

#else

/**
 * ccs_inet_entry - Check permission for INET network operation.
 *
 * @address: Pointer to "struct ccs_addr_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inet_entry(const struct ccs_addr_info *address)
{
	const int idx = ccs_read_lock();
	struct ccs_request_info r;
	int error = 0;
	const u8 type = ccs_inet2mac[address->protocol][address->operation];
	if (type && ccs_init_request_info(&r, type) != CCS_CONFIG_DISABLED) {
		struct task_struct * const task = current;
		const bool no_sleep = address->operation == CCS_NETWORK_ACCEPT
			|| address->operation == CCS_NETWORK_RECV;
		r.param_type = CCS_TYPE_INET_ACL;
		r.param.inet_network.protocol = address->protocol;
		r.param.inet_network.operation = address->operation;
		r.param.inet_network.is_ipv6 = address->inet.is_ipv6;
		r.param.inet_network.address = address->inet.address;
		r.param.inet_network.port = ntohs(address->inet.port);
		/* use host byte order to allow u32 comparison than memcmp().*/
		r.param.inet_network.ip = ntohl(*address->inet.address);
		if (no_sleep)
			task->ccs_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
		do {
			ccs_check_acl(&r, ccs_check_inet_acl);
			error = ccs_audit_inet_log(&r);
		} while (error == CCS_RETRY_REQUEST);
		if (no_sleep)
			task->ccs_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	}
	ccs_read_unlock(idx);
	return error;
}

static int ccs_check_inet_address(const struct sockaddr *addr,
				  const unsigned int addr_len, const u16 port,
				  struct ccs_addr_info *address)
{
	struct ccs_inet_addr_info *i = &address->inet;
	switch (addr->sa_family) {
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			goto skip;
		i->is_ipv6 = true;
		i->address = (u32 *)
			((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr;
		i->port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			goto skip;
		i->is_ipv6 = false;
		i->address = (u32 *) &((struct sockaddr_in *) addr)->sin_addr;
		i->port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	default:
		goto skip;
	}
	if (address->protocol == SOCK_RAW)
		i->port = htons(port);
	return ccs_inet_entry(address);
 skip:
	return 0;
}

/**
 * ccs_unix_entry - Check permission for UNIX network operation.
 *
 * @address: Pointer to "struct ccs_addr_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_unix_entry(const struct ccs_addr_info *address)
{
	const int idx = ccs_read_lock();
	struct ccs_request_info r;
	int error = 0;
	const u8 type = ccs_unix2mac[address->protocol][address->operation];
	if (type && ccs_init_request_info(&r, type) != CCS_CONFIG_DISABLED) {
		char *buf;
		if (address->unix0.addr_len <= sizeof(sa_family_t))
			buf = ccs_encode2("anonymous", 9);			
		else if (address->unix0.addr[0])
			buf = ccs_encode(address->unix0.addr);
		else
			buf = ccs_encode2(address->unix0.addr,
					  address->unix0.addr_len
					  - sizeof(sa_family_t));
		if (buf) {
			struct task_struct * const task = current;
			const bool no_sleep =
				address->operation == CCS_NETWORK_ACCEPT ||
				address->operation == CCS_NETWORK_RECV;
			struct ccs_path_info addr;
			addr.name = buf;
			ccs_fill_path_info(&addr);
			r.param_type = CCS_TYPE_UNIX_ACL;
			r.param.unix_network.protocol = address->protocol;
			r.param.unix_network.operation = address->operation;
			r.param.unix_network.address = &addr;
			if (no_sleep)
				task->ccs_flags |=
					CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
		
			do {
				ccs_check_acl(&r, ccs_check_unix_acl);
				error = ccs_audit_unix_log(&r);
			} while (error == CCS_RETRY_REQUEST);
			if (no_sleep)
				task->ccs_flags &=
					~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
			kfree(buf);
		} else
			error = -ENOMEM;
	}
	ccs_read_unlock(idx);
	return error;
}

static int ccs_check_unix_address(struct sockaddr *addr,
				  const unsigned int addr_len,
				  struct ccs_addr_info *address)
{
	struct ccs_unix_addr_info *u = &address->unix0;
	if (addr->sa_family != AF_UNIX)
		return 0;
	u->addr = ((struct sockaddr_un *) addr)->sun_path;
	u->addr_len = addr_len;
	/*
	 * Terminate pathname with '\0' like unix_mkname() does.
	 * This is needed because pathname was copied by move_addr_to_kernel()
	 * but not yet terminated by unix_mkname().
	 */
	if (u->addr[0] && addr_len > sizeof(short) &&
	    addr_len <= sizeof(struct sockaddr_un))
                ((char *) u->addr)[addr_len] = '\0';
	return ccs_unix_entry(address);
}

static bool ccs_kernel_service(void)
{
	/* Nothing to do if I am a kernel service. */
	return segment_eq(get_fs(), KERNEL_DS);
}

static u8 ccs_sock_family(struct sock *sk)
{
	u8 family;
	if (ccs_kernel_service())
		return 0;
	family = sk->sk_family;
	switch (family) {
	case PF_INET:
	case PF_INET6:
	case PF_UNIX:
		return family;
	default:
		return 0;
	}
}

/* Check permission for creating a socket. */
static int __ccs_socket_create_permission(int family, int type, int protocol)
{
	if (ccs_kernel_service())
		return 0;
	if (family == PF_PACKET && !ccs_capable(CCS_USE_PACKET_SOCKET))
		return -EPERM;
	if (family == PF_ROUTE && !ccs_capable(CCS_USE_ROUTE_SOCKET))
		return -EPERM;
	return 0;
}

/* Check permission for listening a socket. */
static int __ccs_socket_listen_permission(struct socket *sock)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	struct sockaddr_storage addr;
	int addr_len;
	if (!family || (type != SOCK_STREAM && type != SOCK_SEQPACKET))
		return 0;
	{
		const int error = sock->ops->getname(sock, (struct sockaddr *)
						     &addr, &addr_len, 0);
		if (error)
			return error;
	}
	address.protocol = type;
	address.operation = CCS_NETWORK_LISTEN;
	if (family == PF_UNIX)
		return ccs_check_unix_address((struct sockaddr *) &addr,
					      addr_len, &address);
	return ccs_check_inet_address((struct sockaddr *) &addr, addr_len, 0,
				      &address);
}

/* Check permission for setting the remote address of a socket. */
static int __ccs_socket_connect_permission(struct socket *sock,
					   struct sockaddr *addr, int addr_len)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	if (!family)
		return 0;
	address.protocol = type;
	switch (type) {
	case SOCK_DGRAM:
	case SOCK_RAW:
		address.operation = CCS_NETWORK_SEND;
		break;
	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		address.operation = CCS_NETWORK_CONNECT;
		break;
	default:
		return 0;
	}
	if (family == PF_UNIX)
		return ccs_check_unix_address(addr, addr_len, &address);
	return ccs_check_inet_address(addr, addr_len, sock->sk->sk_protocol,
				      &address);
}

/* Check permission for setting the local address of a socket. */
static int __ccs_socket_bind_permission(struct socket *sock,
					struct sockaddr *addr, int addr_len)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	if (!family)
		return 0;
	switch (type) {
	case SOCK_STREAM:
	case SOCK_DGRAM:
	case SOCK_RAW:
	case SOCK_SEQPACKET:
		address.protocol = type;
		address.operation = CCS_NETWORK_BIND;
		break;
	default:
		return 0;
	}
	if (family == PF_UNIX)
		return ccs_check_unix_address(addr, addr_len, &address);
	return ccs_check_inet_address(addr, addr_len, sock->sk->sk_protocol,
				      &address);
}

/* Check permission for sending a datagram. */
static int __ccs_socket_sendmsg_permission(struct socket *sock,
					   struct msghdr *msg, int size)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	if (!msg->msg_name || !family ||
	    (type != SOCK_DGRAM && type != SOCK_RAW))
		return 0;
	address.protocol = type;
	address.operation = CCS_NETWORK_SEND;
	if (family == PF_UNIX)
		return ccs_check_unix_address((struct sockaddr *)
					      msg->msg_name, msg->msg_namelen,
					      &address);
	return ccs_check_inet_address((struct sockaddr *) msg->msg_name,
				      msg->msg_namelen, sock->sk->sk_protocol,
				      &address);
}

/* Check permission for accepting a socket. */
static int __ccs_socket_post_accept_permission(struct socket *sock,
					       struct socket *newsock)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sock->sk);
	const unsigned int type = sock->type;
	struct sockaddr_storage addr;
	int addr_len;
	if (!family || (type != SOCK_STREAM && type != SOCK_SEQPACKET))
		return 0;
	{
		const int error = newsock->ops->getname(newsock,
							(struct sockaddr *)
							&addr, &addr_len, 2);
		if (error)
			return error;
	}
	address.protocol = type;
	address.operation = CCS_NETWORK_ACCEPT;
	if (family == PF_UNIX)
		return ccs_check_unix_address((struct sockaddr *) &addr,
					      addr_len, &address);
	return ccs_check_inet_address((struct sockaddr *) &addr, addr_len, 0,
				      &address);
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

/* Check permission for receiving a datagram. */
static int __ccs_socket_post_recvmsg_permission(struct sock *sk,
						struct sk_buff *skb)
{
	struct ccs_addr_info address;
	const u8 family = ccs_sock_family(sk);
	const unsigned int type = sk->sk_type;
	struct sockaddr_storage addr;
	if (!family)
		return 0;
	switch (type) {
	case SOCK_DGRAM:
	case SOCK_RAW:
		address.protocol = type;
		break;
	default:
		return 0;
	}
	address.operation = CCS_NETWORK_RECV;
	switch (family) {
	case PF_INET6:
		{
			struct in6_addr *sin6 = (struct in6_addr *) &addr;
			address.inet.is_ipv6 = true;
			if (type == SOCK_DGRAM &&
			    skb->protocol == htons(ETH_P_IP))
				ipv6_addr_set(sin6, 0, 0, htonl(0xffff),
					      ip_hdr(skb)->saddr);
			else
				ipv6_addr_copy(sin6, &ipv6_hdr(skb)->saddr);
			break;
		}
	case PF_INET:
		{
			struct in_addr *sin4 = (struct in_addr *) &addr;
			address.inet.is_ipv6 = false; 
			sin4->s_addr = ip_hdr(skb)->saddr;
			break;
		}
	default: /* == PF_UNIX */
		{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
			struct unix_address *u = unix_sk(skb->sk)->addr;
#else
			struct unix_address *u = skb->sk->protinfo.af_unix.addr;
#endif
			unsigned int addr_len;
			if (!u)
				return 0;
			addr_len = u->len;
			if (addr_len >= sizeof(addr))
				return 0;
			memcpy(&addr, u->name, addr_len);
			return ccs_check_unix_address((struct sockaddr *) &addr,
						      addr_len, &address);
		}
	}
	address.inet.address = (u32 *) &addr;
	if (type == SOCK_DGRAM)
		address.inet.port = udp_hdr(skb)->source;
	else
		address.inet.port = htons(sk->sk_protocol);
	return ccs_inet_entry(&address);
}

void __init ccs_network_init(void)
{
	u8 i;
	for (i = 0; i < CCS_SOCK_MAX; i++)
		if (!ccs_proto_keyword[i])
			ccs_proto_keyword[i] = "unknown";
	ccsecurity_ops.socket_create_permission =
		__ccs_socket_create_permission;
	ccsecurity_ops.socket_listen_permission =
		__ccs_socket_listen_permission;
	ccsecurity_ops.socket_connect_permission =
		__ccs_socket_connect_permission;
	ccsecurity_ops.socket_bind_permission = __ccs_socket_bind_permission;
	ccsecurity_ops.socket_post_accept_permission =
		__ccs_socket_post_accept_permission;
	ccsecurity_ops.socket_sendmsg_permission =
		__ccs_socket_sendmsg_permission;
	ccsecurity_ops.socket_post_recvmsg_permission =
		__ccs_socket_post_recvmsg_permission;
}

#endif
