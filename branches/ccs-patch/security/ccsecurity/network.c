/*
 * security/ccsecurity/network.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/07/21
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

struct ccs_addr_info {
	u8 protocol;
	u8 operation;
	u16 port;           /* In network byte order. */
	const u32 *address; /* In network byte order. */
	bool is_ipv6;
};

const char *ccs_net_protocol_keyword[CCS_MAX_NETWORK_PROTOCOL] = {
	[CCS_NETWORK_TCP_PROTOCOL] = "TCP",
	[CCS_NETWORK_UDP_PROTOCOL] = "UDP",
	[CCS_NETWORK_RAW_PROTOCOL] = "RAW",
};

const char *ccs_net_keyword[CCS_MAX_NETWORK_OPERATION] = {
	[CCS_NETWORK_BIND]    = "bind",
	[CCS_NETWORK_LISTEN]  = "listen",
	[CCS_NETWORK_CONNECT] = "connect",
	[CCS_NETWORK_ACCEPT]  = "accept",
	[CCS_NETWORK_SEND]    = "send",
	[CCS_NETWORK_RECV]    = "recv",
};

/**
 * ccs_audit_network_log - Audit network log.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_audit_network_log(struct ccs_request_info *r)
{
	char buf[128];
	const char *protocol =
		ccs_net_protocol_keyword[r->param.network.protocol];
	const char *operation = ccs_net_keyword[r->param.network.operation];
	const u32 *address = r->param.network.address;
	const u16 port = r->param.network.port;
	if (r->param.network.is_ipv6)
		ccs_print_ipv6(buf, sizeof(buf), (const struct in6_addr *)
			       address, (const struct in6_addr *) address);
	else
		ccs_print_ipv4(buf, sizeof(buf), r->param.network.ip,
			       r->param.network.ip);
	ccs_write_log(r, "network %s %s %s %u\n", protocol, operation, buf,
		      port);
	if (r->granted)
		return 0;
	ccs_warn_log(r, "network %s %s %s %u", protocol, operation, buf, port);
	return ccs_supervisor(r, "network %s %s %s %u\n", protocol, operation,
			      buf, port);
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

static bool ccs_check_network_acl(struct ccs_request_info *r,
				  const struct ccs_acl_info *ptr)
{
	const struct ccs_ip_network_acl *acl =
		container_of(ptr, typeof(*acl), head);
	bool ret;
	if (!(acl->perm & (1 << r->param.network.operation)) ||
	    !ccs_compare_number_union(r->param.network.port, &acl->port))
		return false;
	switch (acl->address_type) {
	case CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP:
		ret = ccs_address_matches_group(r->param.network.is_ipv6,
						r->param.network.address,
						acl->address.group);
		break;
	case CCS_IP_ADDRESS_TYPE_IPv4:
		ret = !r->param.network.is_ipv6 &&
			acl->address.ipv4.min <= r->param.network.ip &&
			r->param.network.ip <= acl->address.ipv4.max;
		break;
	default:
		ret = r->param.network.is_ipv6 &&
			memcmp(acl->address.ipv6.min, r->param.network.address,
			       16) <= 0 &&
			memcmp(r->param.network.address, acl->address.ipv6.max,
			       16) <= 0;
		break;
	}
	return ret;
}

static const u8
ccs_net2mac[CCS_MAX_NETWORK_PROTOCOL][CCS_MAX_NETWORK_OPERATION] = {
	[CCS_NETWORK_TCP_PROTOCOL] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_TCP_BIND,
		[CCS_NETWORK_LISTEN]  = CCS_MAC_NETWORK_TCP_LISTEN,
		[CCS_NETWORK_CONNECT] = CCS_MAC_NETWORK_TCP_CONNECT,
		[CCS_NETWORK_ACCEPT]  = CCS_MAC_NETWORK_TCP_ACCEPT,
	},
	[CCS_NETWORK_UDP_PROTOCOL] = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_UDP_BIND,
		[CCS_NETWORK_CONNECT] = CCS_MAC_NETWORK_UDP_SEND,
		[CCS_NETWORK_SEND]    = CCS_MAC_NETWORK_UDP_SEND,
		[CCS_NETWORK_RECV]    = CCS_MAC_NETWORK_UDP_RECV,
	},
	[CCS_NETWORK_RAW_PROTOCOL]    = {
		[CCS_NETWORK_BIND]    = CCS_MAC_NETWORK_RAW_BIND,
		[CCS_NETWORK_CONNECT] = CCS_MAC_NETWORK_RAW_SEND,
		[CCS_NETWORK_SEND]    = CCS_MAC_NETWORK_RAW_SEND,
		[CCS_NETWORK_RECV]    = CCS_MAC_NETWORK_RAW_RECV,
	},
};

/**
 * ccs_network_entry - Check permission for network operation.
 *
 * @address: Pointer to "struct ccs_ip_address".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_network_entry(const struct ccs_addr_info *address)
{
	const int idx = ccs_read_lock();
	struct ccs_request_info r;
	int error = 0;
	const u8 type = ccs_net2mac[address->protocol][address->operation];
	if (!type || ccs_init_request_info(&r, type) != CCS_CONFIG_DISABLED) {
		r.param_type = CCS_TYPE_IP_NETWORK_ACL;
		r.param.network.protocol = address->protocol;
		r.param.network.operation = address->operation;
		r.param.network.is_ipv6 = address->is_ipv6;
		r.param.network.address = address->address;
		r.param.network.port = ntohs(address->port);
		/* use host byte order to allow u32 comparison than memcmp().*/
		r.param.network.ip = ntohl(*address->address);
		do {
			ccs_check_acl(&r, ccs_check_network_acl);
			error = ccs_audit_network_log(&r);
		} while (error == CCS_RETRY_REQUEST);
	}
	ccs_read_unlock(idx);
	return error;
}

static bool ccs_same_ip_network_acl(const struct ccs_acl_info *a,
				    const struct ccs_acl_info *b)
{
	const struct ccs_ip_network_acl *p1 = container_of(a, typeof(*p1),
							   head);
	const struct ccs_ip_network_acl *p2 = container_of(b, typeof(*p2),
							   head);
	return ccs_same_acl_head(&p1->head, &p2->head)
		&& p1->protocol == p2->protocol
		&& p1->address_type == p2->address_type &&
		p1->address.ipv4.min == p2->address.ipv4.min &&
		p1->address.ipv6.min == p2->address.ipv6.min &&
		p1->address.ipv4.max == p2->address.ipv4.max &&
		p1->address.ipv6.max == p2->address.ipv6.max &&
		p1->address.group == p2->address.group &&
		ccs_same_number_union(&p1->port, &p2->port);
}

static bool ccs_merge_ip_network_acl(struct ccs_acl_info *a,
				     struct ccs_acl_info *b,
				     const bool is_delete)
{
	u8 * const a_perm = &container_of(a, struct ccs_ip_network_acl, head)
		->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct ccs_ip_network_acl, head)
		->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * ccs_write_network - Write "struct ccs_ip_network_acl" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct ccs_domain_info".
 * @condition: Pointer to "struct ccs_condition". Maybe NULL.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_write_network(char *data, struct ccs_domain_info *domain,
		      struct ccs_condition *condition, const bool is_delete)
{
	struct ccs_ip_network_acl e = {
		.head.type = CCS_TYPE_IP_NETWORK_ACL,
		.head.cond = condition,
	};
	u16 min_address[8];
	u16 max_address[8];
	int error = is_delete ? -ENOENT : -ENOMEM;
	u8 type;
	char *w[4];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[3][0])
		return -EINVAL;
	for (e.protocol = 0; e.protocol < CCS_MAX_NETWORK_PROTOCOL;
	     e.protocol++)
		if (!strcmp(w[0], ccs_net_protocol_keyword[e.protocol]))
			break;
	for (type = 0; type < CCS_MAX_NETWORK_OPERATION; type++)
		if (ccs_permstr(w[1], ccs_net_keyword[type]))
			e.perm |= 1 << type;
	if (e.protocol == CCS_MAX_NETWORK_PROTOCOL || !e.perm)
		return -EINVAL;
	switch (ccs_parse_ip_address(w[2], min_address, max_address)) {
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
		if (w[2][0] != '@')
			return -EINVAL;
		e.address_type = CCS_IP_ADDRESS_TYPE_ADDRESS_GROUP;
		e.address.group = ccs_get_group(w[2] + 1, CCS_ADDRESS_GROUP);
		if (!e.address.group)
			return -ENOMEM;
		break;
	}
	if (!ccs_parse_number_union(w[3], &e.port))
		goto out;
	error = ccs_update_domain(&e.head, sizeof(e), is_delete, domain,
				  ccs_same_ip_network_acl,
				  ccs_merge_ip_network_acl);
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

#ifndef CONFIG_NET

void __init ccs_network_init(void)
{
}

#else

static bool ccs_check_address(const struct sockaddr *addr,
			      const unsigned int addr_len,
			      struct ccs_addr_info *address)
{
	switch (addr->sa_family) {
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			goto skip;
		address->is_ipv6 = true;
		address->address = (u32 *)
			((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr;
		address->port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			goto skip;
		address->is_ipv6 = false;
		address->address = (u32 *)
			&((struct sockaddr_in *) addr)->sin_addr;
		address->port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	default:
		goto skip;
	}
	return true;
 skip:
	return false;
}

/* Check permission for creating a socket. */
static int __ccs_socket_create_permission(int family, int type, int protocol)
{
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	if (family == PF_PACKET && !ccs_capable(CCS_USE_PACKET_SOCKET))
		return -EPERM;
	if (family == PF_ROUTE && !ccs_capable(CCS_USE_ROUTE_SOCKET))
		return -EPERM;
	return 0;
}

/* Check permission for listening a TCP socket. */
static int __ccs_socket_listen_permission(struct socket *sock)
{
	struct sockaddr_storage addr;
	int error = 0;
	int addr_len;
	struct ccs_addr_info address;
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
	if (sock->ops->getname(sock, (struct sockaddr *) &addr, &addr_len, 0))
		return -EPERM;
	address.protocol = CCS_NETWORK_TCP_PROTOCOL;
	address.operation = CCS_NETWORK_LISTEN;
	if (ccs_check_address((struct sockaddr *) &addr, addr_len, &address))
		error = ccs_network_entry(&address);
 	return error;
}

/* Check permission for setting the remote IP address/port pair of a socket. */
static int __ccs_socket_connect_permission(struct socket *sock,
					   struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	struct ccs_addr_info address;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (type) {
	case SOCK_STREAM:
		address.protocol = CCS_NETWORK_TCP_PROTOCOL;
		break;
	case SOCK_DGRAM:
		address.protocol = CCS_NETWORK_UDP_PROTOCOL;
		break;
	case SOCK_RAW:
		address.protocol = CCS_NETWORK_RAW_PROTOCOL;
		break;
	default:
		return 0;
	}
	address.operation = CCS_NETWORK_CONNECT;
	if (!ccs_check_address(addr, addr_len, &address))
		goto skip;
	if (type == SOCK_RAW)
		address.port = htons(sock->sk->sk_protocol);
	error = ccs_network_entry(&address);
 skip:
	return error;
}

/* Check permission for setting the local IP address/port pair of a socket. */
static int __ccs_socket_bind_permission(struct socket *sock,
					struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	struct ccs_addr_info address;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (type) {
	case SOCK_STREAM:
		address.protocol = CCS_NETWORK_TCP_PROTOCOL;
		break;
	case SOCK_DGRAM:
		address.protocol = CCS_NETWORK_UDP_PROTOCOL;
		break;
	case SOCK_RAW:
		address.protocol = CCS_NETWORK_RAW_PROTOCOL;
		break;
	default:
		return 0;
	}
	address.operation = CCS_NETWORK_BIND;
	if (!ccs_check_address(addr, addr_len, &address))
		goto skip;
	if (type == SOCK_RAW)
		address.port = htons(sock->sk->sk_protocol);
	error = ccs_network_entry(&address);
 skip:
	return error;
}

/* Check permission for accepting a TCP socket. */
static int __ccs_socket_post_accept_permission(struct socket *sock,
					       struct socket *newsock)
{
	struct sockaddr_storage addr;
	struct task_struct * const task = current;
	int error = 0;
	int addr_len;
	struct ccs_addr_info address;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (newsock->sk->sk_family) {
	case PF_INET:
	case PF_INET6:
		break;
	default:
		return 0;
	}
	error = newsock->ops->getname(newsock, (struct sockaddr *) &addr,
				      &addr_len, 2);
	if (error)
		return error;
	if (!ccs_check_address((struct sockaddr *) &addr, addr_len,
			       &address))
		goto skip;
	address.protocol = CCS_NETWORK_TCP_PROTOCOL;
	address.operation = CCS_NETWORK_ACCEPT;
	task->ccs_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	error = ccs_network_entry(&address);
	task->ccs_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
 skip:
	return error;
}

/* Check permission for sending a datagram via a UDP or RAW socket. */
static int __ccs_socket_sendmsg_permission(struct socket *sock,
					   struct msghdr *msg, int size)
{
	int error = 0;
	const int type = sock->type;
	struct ccs_addr_info address;
	if (!msg->msg_name)
		return 0;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (type) {
	case SOCK_DGRAM:
		address.protocol = CCS_NETWORK_UDP_PROTOCOL;
		break;
	case SOCK_RAW:
		address.protocol = CCS_NETWORK_RAW_PROTOCOL;
		break;
	default:
		return 0;
	}
	address.operation = CCS_NETWORK_SEND;
	if (!ccs_check_address((struct sockaddr *) msg->msg_name,
			       msg->msg_namelen, &address))
		goto skip;
	if (type == SOCK_RAW)
		address.port = htons(sock->sk->sk_protocol);
	error = ccs_network_entry(&address);
 skip:
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

/* Check permission for receiving a datagram via a UDP or RAW socket. */
static int __ccs_socket_post_recvmsg_permission(struct sock *sk,
						struct sk_buff *skb)
{
	struct task_struct * const task = current;
	int error = 0;
	const unsigned int type = sk->sk_type;
	struct ccs_addr_info address;
	union {
		struct in6_addr sin6;
		struct in_addr sin4;
	} ip_address;
	switch (type) {
	case SOCK_DGRAM:
		address.protocol = CCS_NETWORK_UDP_PROTOCOL;
		break;
	case SOCK_RAW:
		address.protocol = CCS_NETWORK_RAW_PROTOCOL;
		break;
	default:
		return 0;
	}
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (sk->sk_family) {
	case PF_INET6:
		address.is_ipv6 = true;
		if (type == SOCK_DGRAM && skb->protocol == htons(ETH_P_IP))
			ipv6_addr_set(&ip_address.sin6, 0, 0, htonl(0xffff),
				      ip_hdr(skb)->saddr);
		else
			ipv6_addr_copy(&ip_address.sin6, &ipv6_hdr(skb)->saddr);
		break;
	case PF_INET:
		address.is_ipv6 = false; 
		ip_address.sin4.s_addr = ip_hdr(skb)->saddr;
		break;
	default:
		goto skip;
	}
	address.address = (u32 *) &ip_address;
	if (type == SOCK_DGRAM)
		address.port = udp_hdr(skb)->source;
	else
		address.port = htons(sk->sk_protocol);
	address.operation = CCS_NETWORK_RECV;
	task->ccs_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	error = ccs_network_entry(&address);
	task->ccs_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
 skip:
	return error;
}

void __init ccs_network_init(void)
{
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
