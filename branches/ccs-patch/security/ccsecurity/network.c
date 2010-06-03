/*
 * security/ccsecurity/network.c
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2   2010/04/01
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
	const char *operation = ccs_net2keyword(r->param.network.operation);
	const u32 *address = r->param.network.address;
	const u16 port = r->param.network.port;
	if (r->param.network.is_ipv6)
		ccs_print_ipv6(buf, sizeof(buf), (const struct in6_addr *)
			       address, (const struct in6_addr *) address);
	else
		ccs_print_ipv4(buf, sizeof(buf), r->param.network.ip,
			       r->param.network.ip);
	ccs_write_log(r, CCS_KEYWORD_ALLOW_NETWORK "%s %s %u\n", operation,
		      buf, port);
	if (r->granted)
		return 0;
	ccs_warn_log(r, "%s %s %u", operation, buf, port);
	return ccs_supervisor(r, CCS_KEYWORD_ALLOW_NETWORK "%s %s %u\n",
			      operation, buf, port);
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
	case CCS_NETWORK_UDP_BIND:
		keyword = "UDP bind";
		break;
	case CCS_NETWORK_UDP_CONNECT:
		keyword = "UDP connect";
		break;
	case CCS_NETWORK_TCP_BIND:
		keyword = "TCP bind";
		break;
	case CCS_NETWORK_TCP_LISTEN:
		keyword = "TCP listen";
		break;
	case CCS_NETWORK_TCP_CONNECT:
		keyword = "TCP connect";
		break;
	case CCS_NETWORK_TCP_ACCEPT:
		keyword = "TCP accept";
		break;
	case CCS_NETWORK_RAW_BIND:
		keyword = "RAW bind";
		break;
	case CCS_NETWORK_RAW_CONNECT:
		keyword = "RAW connect";
		break;
	}
	return keyword;
}

static bool ccs_check_network_acl(const struct ccs_request_info *r,
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

/**
 * ccs_network_entry - Check permission for network operation.
 *
 * @is_ipv6:   True if @address is an IPv6 address.
 * @operation: Type of operation.
 * @address:   An IPv4 or IPv6 address in network byte order.
 * @port:      Port number in network byte order.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_network_entry(const bool is_ipv6, const u8 operation,
			     const u32 *address, const u16 port)
{
	const int idx = ccs_read_lock();
	struct ccs_request_info r;
	int error = 0;
	if (ccs_init_request_info(&r, CCS_MAC_NETWORK_UDP_BIND + operation)
	    != CCS_CONFIG_DISABLED) {
		r.param_type = CCS_TYPE_IP_NETWORK_ACL;
		r.param.network.operation = operation;
		r.param.network.is_ipv6 = is_ipv6;
		r.param.network.address = address;
		r.param.network.port = ntohs(port);
		/* use host byte order to allow u32 comparison than memcmp().*/
		r.param.network.ip = ntohl(*address);
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
 * @condition: Pointer to "struct ccs_condition". May be NULL.
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
	u8 sock_type;
	u8 operation;
	char *w[4];
	if (!ccs_tokenize(data, w, sizeof(w)) || !w[3][0])
		return -EINVAL;
	if (!strcmp(w[0], "TCP"))
		sock_type = SOCK_STREAM;
	else if (!strcmp(w[0], "UDP"))
		sock_type = SOCK_DGRAM;
	else if (!strcmp(w[0], "RAW"))
		sock_type = SOCK_RAW;
	else
		return -EINVAL;
	if (!strcmp(w[1], "bind"))
		switch (sock_type) {
		case SOCK_STREAM:
			operation = CCS_NETWORK_TCP_BIND;
			break;
		case SOCK_DGRAM:
			operation = CCS_NETWORK_UDP_BIND;
			break;
		default:
			operation = CCS_NETWORK_RAW_BIND;
			break;
		}
	else if (!strcmp(w[1], "connect"))
		switch (sock_type) {
		case SOCK_STREAM:
			operation = CCS_NETWORK_TCP_CONNECT;
			break;
		case SOCK_DGRAM:
			operation = CCS_NETWORK_UDP_CONNECT;
			break;
		default:
			operation = CCS_NETWORK_RAW_CONNECT;
			break;
		}
	else if (sock_type == SOCK_STREAM && !strcmp(w[1], "listen"))
		operation = CCS_NETWORK_TCP_LISTEN;
	else if (sock_type == SOCK_STREAM && !strcmp(w[1], "accept"))
		operation = CCS_NETWORK_TCP_ACCEPT;
	else
		return -EINVAL;
	e.perm = 1 << operation;			
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

#define MAX_SOCK_ADDR 128 /* net/socket.c */

/* Check permission for creating a socket. */
static int __ccs_socket_create_permission(int family, int type, int protocol)
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
static int __ccs_socket_listen_permission(struct socket *sock)
{
	int error = 0;
	char addr[MAX_SOCK_ADDR];
	int addr_len;
	u32 *address;
	u16 port;
	bool is_ipv6;
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
	case AF_INET6:
		is_ipv6 = true;
		address = (u32 *) ((struct sockaddr_in6 *) addr)->sin6_addr
			.s6_addr;
		port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	case AF_INET:
		is_ipv6 = false;
		address = (u32 *) &((struct sockaddr_in *) addr)->sin_addr;
		port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	default:
		goto skip;
	}
	error = ccs_network_entry(is_ipv6, CCS_NETWORK_TCP_LISTEN, address,
				  port);
 skip:
	return error;
}

/* Check permission for setting the remote IP address/port pair of a socket. */
static int __ccs_socket_connect_permission(struct socket *sock,
					   struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	u32 *address;
	u16 port;
	u8 operation;
	bool is_ipv6; 
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (type) {
	case SOCK_STREAM:
		operation = CCS_NETWORK_TCP_CONNECT;
		break;
	case SOCK_DGRAM:
		operation = CCS_NETWORK_UDP_CONNECT;
		break;
	case SOCK_RAW:
		operation = CCS_NETWORK_RAW_CONNECT;
		break;
	default:
		return 0;
	}
	switch (addr->sa_family) {
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			goto skip;
		is_ipv6 = true;
		address = (u32 *) ((struct sockaddr_in6 *) addr)->sin6_addr
			.s6_addr;
		port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			goto skip;
		is_ipv6 = false;
		address = (u32 *) &((struct sockaddr_in *) addr)->sin_addr;
		port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	default:
		goto skip;
	}
	if (type == SOCK_RAW)
		port = htons(sock->sk->sk_protocol);
	error = ccs_network_entry(is_ipv6, operation, address, port);
 skip:
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
static int __ccs_socket_bind_permission(struct socket *sock,
					struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	const u32 *address;
	u16 port;
	u8 operation;
	bool is_ipv6;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (type) {
	case SOCK_STREAM:
		operation = CCS_NETWORK_TCP_BIND;
		break;
	case SOCK_DGRAM:
		operation = CCS_NETWORK_UDP_BIND;
		break;
	case SOCK_RAW:
		operation = CCS_NETWORK_RAW_BIND;
		break;
	default:
		return 0;
	}
	switch (addr->sa_family) {
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			goto skip;
		is_ipv6 = true;
		address = (u32 *) ((struct sockaddr_in6 *) addr)->sin6_addr
			.s6_addr;
		port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			goto skip;
		is_ipv6 = false;
		address = (u32 *) &((struct sockaddr_in *) addr)->sin_addr;
		port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	default:
		goto skip;
	}
	if (type == SOCK_RAW)
		port = htons(sock->sk->sk_protocol);
	error = ccs_network_entry(is_ipv6, operation, address, port);
 skip:
	return error;
}

/*
 * Check permission for accepting a TCP socket.
 *
 * Currently, the LSM hook for this purpose is not provided.
 */
static int __ccs_socket_accept_permission(struct socket *sock,
					  struct sockaddr *addr)
{
	struct task_struct * const task = current;
	int error = 0;
	int addr_len;
	u32 *address;
	u16 port;
	bool is_ipv6;
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
	case AF_INET6:
		is_ipv6 = true;
		address = (u32 *) ((struct sockaddr_in6 *) addr)->sin6_addr
			.s6_addr;
		port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	case AF_INET:
		is_ipv6 = false;
		address = (u32 *) &((struct sockaddr_in *) addr)->sin_addr;
		port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	default:
		goto skip;
	}
	task->ccs_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	error = ccs_network_entry(is_ipv6, CCS_NETWORK_TCP_ACCEPT, address,
				  port);
	task->ccs_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
 skip:
	return error;
}

/* Check permission for sending a datagram via a UDP or RAW socket. */
static int __ccs_socket_sendmsg_permission(struct socket *sock,
					   struct msghdr *msg, int size)
{
	struct sockaddr *addr = (struct sockaddr *) msg->msg_name;
	const int addr_len = msg->msg_namelen;
	int error = 0;
	const int type = sock->type;
	u32 *address;
	u16 port;
	bool is_ipv6;
	u8 operation;
	if (!addr)
		return 0;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (type) {
	case SOCK_DGRAM:
		operation = CCS_NETWORK_UDP_CONNECT;
		break;
	case SOCK_RAW:
		operation = CCS_NETWORK_RAW_CONNECT;
		break;
	default:
		return 0;
	}
	switch (addr->sa_family) {
	case AF_INET6:
		if (addr_len < SIN6_LEN_RFC2133)
			goto skip;
		is_ipv6 = true;
		address = (u32 *) ((struct sockaddr_in6 *) addr)->sin6_addr
			.s6_addr;
		port = ((struct sockaddr_in6 *) addr)->sin6_port;
		break;
	case AF_INET:
		if (addr_len < sizeof(struct sockaddr_in))
			goto skip;
		is_ipv6 = false;
		address = (u32 *) &((struct sockaddr_in *) addr)->sin_addr;
		port = ((struct sockaddr_in *) addr)->sin_port;
		break;
	default:
		goto skip;
	}
	if (type == SOCK_RAW)
		port = htons(sock->sk->sk_protocol);
	error = ccs_network_entry(is_ipv6, operation, address, port);
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
static int __ccs_socket_recvmsg_permission(struct sock *sk,
					   struct sk_buff *skb,
					   const unsigned int flags)
{
	struct task_struct * const task = current;
	int error = 0;
	const unsigned int type = sk->sk_type;
	u16 port;
	bool is_ipv6;
	u8 operation;
	union {
		struct in6_addr sin6;
		struct in_addr sin4;
	} address;
	switch (type) {
	case SOCK_DGRAM:
		operation = CCS_NETWORK_UDP_CONNECT;
		break;
	case SOCK_RAW:
		operation = CCS_NETWORK_RAW_CONNECT;
		break;
	default:
		return 0;
	}
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	switch (sk->sk_family) {
	case PF_INET6:
		is_ipv6 = true;
		if (type == SOCK_DGRAM && skb->protocol == htons(ETH_P_IP))
			ipv6_addr_set(&address.sin6, 0, 0, htonl(0xffff),
				      ip_hdr(skb)->saddr);
		else
			ipv6_addr_copy(&address.sin6, &ipv6_hdr(skb)->saddr);
		break;
	case PF_INET:
		is_ipv6 = false; 
		address.sin4.s_addr = ip_hdr(skb)->saddr;
		break;
	default:
		goto skip;
	}
	if (type == SOCK_DGRAM)
		port = udp_hdr(skb)->source;
	else
		port = htons(sk->sk_protocol);
	task->ccs_flags |= CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
	error = ccs_network_entry(is_ipv6, operation, (u32 *) &address, port);
	task->ccs_flags &= ~CCS_DONT_SLEEP_ON_ENFORCE_ERROR;
 skip:
	if (!error)
		return 0;
	/*
	 * Remove from queue if MSG_PEEK is used so that
	 * the head message from unwanted source in receive queue will not
	 * prevent the caller from picking up next message from wanted source
	 * when the caller is using MSG_PEEK flag for picking up.
	 */
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
		bool slow = false;
		if (type == SOCK_DGRAM)
			slow = lock_sock_fast(sk);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		if (type == SOCK_DGRAM)
			lock_sock(sk);
#endif
		skb_kill_datagram(sk, skb, flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
		if (type == SOCK_DGRAM)
			unlock_sock_fast(sk, slow);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		if (type == SOCK_DGRAM)
			release_sock(sk);
#endif
	}
	/* Hope less harmful than -EPERM. */
	return -ENOMEM;
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
	ccsecurity_ops.socket_accept_permission =
		__ccs_socket_accept_permission;
	ccsecurity_ops.socket_sendmsg_permission =
		__ccs_socket_sendmsg_permission;
	ccsecurity_ops.socket_recvmsg_permission =
		__ccs_socket_recvmsg_permission;
}

#endif
