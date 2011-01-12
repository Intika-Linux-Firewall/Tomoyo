/*
 * security/tomoyo/network.c
 *
 * Network restriction functions.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 */

#include "common.h"
#include <linux/slab.h>

const char *tomoyo_net_keyword[TOMOYO_MAX_NETWORK_OPERATION] = {
	[TOMOYO_NETWORK_UDP_BIND] = "UDP bind",
	[TOMOYO_NETWORK_UDP_CONNECT] = "UDP connect",
	[TOMOYO_NETWORK_TCP_BIND] = "TCP bind",
	[TOMOYO_NETWORK_TCP_LISTEN] = "TCP listen",
	[TOMOYO_NETWORK_TCP_CONNECT] = "TCP connect",
	[TOMOYO_NETWORK_TCP_ACCEPT] = "TCP accept",
	[TOMOYO_NETWORK_RAW_BIND] = "RAW bind",
	[TOMOYO_NETWORK_RAW_CONNECT] = "RAW connect"
};

/**
 * tomoyo_audit_network_log - Audit network log.
 *
 * @r: Pointer to "struct tomoyo_request_info".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_audit_network_log(struct tomoyo_request_info *r)
{
	char buf[128];
	const char *operation = tomoyo_net_keyword[r->param.network.operation];
	const u32 *address = r->param.network.address;
	const u16 port = r->param.network.port;
	if (r->granted)
		return 0;
	if (r->param.network.is_ipv6)
		tomoyo_print_ipv6(buf, sizeof(buf), (const struct in6_addr *)
				  address, (const struct in6_addr *) address);
	else
		tomoyo_print_ipv4(buf, sizeof(buf), r->param.network.ip,
				  r->param.network.ip);
	tomoyo_warn_log(r, "network %s %s %u", operation, buf, port);
	return tomoyo_supervisor(r, "allow_network %s %s %u\n", operation, buf, port);
}

/**
 * tomoyo_parse_ip_address - Parse an IP address.
 *
 * @address: String to parse.
 * @min:     Pointer to store min address.
 * @max:     Pointer to store max address.
 *
 * Returns TOMOYO_IP_ADDRESS_TYPE_IPv6 if @address is an IPv6,
 * TOMOYO_IP_ADDRESS_TYPE_IPv4 if @address is an IPv4,
 * TOMOYO_IP_ADDRESS_TYPE_ADDRESS_GROUP otherwise.
 */
int tomoyo_parse_ip_address(char *address, u16 *min, u16 *max)
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
		return TOMOYO_IP_ADDRESS_TYPE_IPv6;
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
		return TOMOYO_IP_ADDRESS_TYPE_IPv4;
	}
	return TOMOYO_IP_ADDRESS_TYPE_ADDRESS_GROUP;
}

#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr)				\
	((unsigned char *)&addr)[3],		\
		((unsigned char *)&addr)[2],	\
		((unsigned char *)&addr)[1],	\
		((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD NIPQUAD
#else
#error "Please fix asm/byteorder.h"
#endif

/**
 * tomoyo_print_ipv4 - Print an IPv4 address.
 *
 * @buffer:     Buffer to write to.
 * @buffer_len: Size of @buffer.
 * @min_ip:     Min address in host byte order.
 * @max_ip:     Max address in host byte order.
 *
 * Returns nothing.
 */
void tomoyo_print_ipv4(char *buffer, const int buffer_len,
		       const u32 min_ip, const u32 max_ip)
{
	memset(buffer, 0, buffer_len);
	snprintf(buffer, buffer_len - 1, "%u.%u.%u.%u%c%u.%u.%u.%u",
		 HIPQUAD(min_ip), min_ip == max_ip ? '\0' : '-',
		 HIPQUAD(max_ip));
}

#define NIP6(addr)							\
	ntohs((addr).s6_addr16[0]), ntohs((addr).s6_addr16[1]),		\
		ntohs((addr).s6_addr16[2]), ntohs((addr).s6_addr16[3]), \
		ntohs((addr).s6_addr16[4]), ntohs((addr).s6_addr16[5]), \
		ntohs((addr).s6_addr16[6]), ntohs((addr).s6_addr16[7])

/**
 * tomoyo_print_ipv6 - Print an IPv6 address.
 *
 * @buffer:     Buffer to write to.
 * @buffer_len: Size of @buffer.
 * @min_ip:     Pointer to "struct in6_addr".
 * @max_ip:     Pointer to "struct in6_addr".
 *
 * Returns nothing.
 */
void tomoyo_print_ipv6(char *buffer, const int buffer_len,
		       const struct in6_addr *min_ip,
		       const struct in6_addr *max_ip)
{
	memset(buffer, 0, buffer_len);
	snprintf(buffer, buffer_len - 1,
		 "%x:%x:%x:%x:%x:%x:%x:%x%c%x:%x:%x:%x:%x:%x:%x:%x",
		 NIP6(*min_ip), min_ip == max_ip ? '\0' : '-',
		 NIP6(*max_ip));
}

static bool tomoyo_check_network_acl(const struct tomoyo_request_info *r,
				     const struct tomoyo_acl_info *ptr)
{
	const struct tomoyo_ip_network_acl *acl =
		container_of(ptr, typeof(*acl), head);
	bool ret;
	if (!(acl->perm & (1 << r->param.network.operation)) ||
	    !tomoyo_compare_number_union(r->param.network.port, &acl->port))
		return false;
	switch (acl->address_type) {
	case TOMOYO_IP_ADDRESS_TYPE_ADDRESS_GROUP:
		ret = tomoyo_address_matches_group(r->param.network.is_ipv6,
						   r->param.network.address,
						   acl->address.group);
		break;
	case TOMOYO_IP_ADDRESS_TYPE_IPv4:
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
 * tomoyo_network_entry - Check permission for network operation.
 *
 * @is_ipv6:   True if @address is an IPv6 address.
 * @operation: Type of operation.
 * @address:   An IPv4 or IPv6 address in network byte order.
 * @port:      Port number in network byte order.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_network_entry(const bool is_ipv6, const u8 operation,
				const u32 *address, const u16 port)
{
	const int idx = tomoyo_read_lock();
	struct tomoyo_request_info r;
	int error = 0;
	if (tomoyo_init_request_info(&r, NULL,
				     TOMOYO_MAC_NETWORK_UDP_BIND + operation)
	    != TOMOYO_CONFIG_DISABLED) {
		r.param_type = TOMOYO_TYPE_IP_NETWORK_ACL;
		r.param.network.operation = operation;
		r.param.network.is_ipv6 = is_ipv6;
		r.param.network.address = address;
		r.param.network.port = ntohs(port);
		/* use host byte order to allow u32 comparison than memcmp().*/
		r.param.network.ip = ntohl(*address);
		do {
			tomoyo_check_acl(&r, tomoyo_check_network_acl);
			error = tomoyo_audit_network_log(&r);
		} while (error == TOMOYO_RETRY_REQUEST);
	}
	tomoyo_read_unlock(idx);
	return error;
}

static bool tomoyo_same_ip_network_acl(const struct tomoyo_acl_info *a,
				       const struct tomoyo_acl_info *b)
{
	const struct tomoyo_ip_network_acl *p1 = container_of(a, typeof(*p1),
							      head);
	const struct tomoyo_ip_network_acl *p2 = container_of(b, typeof(*p2),
							      head);
	return tomoyo_same_acl_head(&p1->head, &p2->head)
		&& p1->address_type == p2->address_type &&
		p1->address.ipv4.min == p2->address.ipv4.min &&
		p1->address.ipv6.min == p2->address.ipv6.min &&
		p1->address.ipv4.max == p2->address.ipv4.max &&
		p1->address.ipv6.max == p2->address.ipv6.max &&
		p1->address.group == p2->address.group &&
		tomoyo_same_number_union(&p1->port, &p2->port);
}

static bool tomoyo_merge_ip_network_acl(struct tomoyo_acl_info *a,
					struct tomoyo_acl_info *b,
					const bool is_delete)
{
	u8 * const a_perm = &container_of(a, struct tomoyo_ip_network_acl, head)
		->perm;
	u8 perm = *a_perm;
	const u8 b_perm = container_of(b, struct tomoyo_ip_network_acl, head)
		->perm;
	if (is_delete)
		perm &= ~b_perm;
	else
		perm |= b_perm;
	*a_perm = perm;
	return !perm;
}

/**
 * tomoyo_write_network - Write "struct tomoyo_ip_network_acl" list.
 *
 * @data:      String to parse.
 * @domain:    Pointer to "struct tomoyo_domain_info".
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
int tomoyo_write_network(char *data, struct tomoyo_domain_info *domain,
			 const bool is_delete)
{
	struct tomoyo_ip_network_acl e = {
		.head.type = TOMOYO_TYPE_IP_NETWORK_ACL,
	};
	u16 min_address[8];
	u16 max_address[8];
	int error = is_delete ? -ENOENT : -ENOMEM;
	u8 sock_type;
	u8 operation;
	char *w[4];
	if (!tomoyo_tokenize(data, w, sizeof(w)) || !w[3][0])
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
			operation = TOMOYO_NETWORK_TCP_BIND;
			break;
		case SOCK_DGRAM:
			operation = TOMOYO_NETWORK_UDP_BIND;
			break;
		default:
			operation = TOMOYO_NETWORK_RAW_BIND;
			break;
		}
	else if (!strcmp(w[1], "connect"))
		switch (sock_type) {
		case SOCK_STREAM:
			operation = TOMOYO_NETWORK_TCP_CONNECT;
			break;
		case SOCK_DGRAM:
			operation = TOMOYO_NETWORK_UDP_CONNECT;
			break;
		default:
			operation = TOMOYO_NETWORK_RAW_CONNECT;
			break;
		}
	else if (sock_type == SOCK_STREAM && !strcmp(w[1], "listen"))
		operation = TOMOYO_NETWORK_TCP_LISTEN;
	else if (sock_type == SOCK_STREAM && !strcmp(w[1], "accept"))
		operation = TOMOYO_NETWORK_TCP_ACCEPT;
	else
		return -EINVAL;
	e.perm = 1 << operation;			
	switch (tomoyo_parse_ip_address(w[2], min_address, max_address)) {
	case TOMOYO_IP_ADDRESS_TYPE_IPv6:
		e.address_type = TOMOYO_IP_ADDRESS_TYPE_IPv6;
		e.address.ipv6.min = tomoyo_get_ipv6_address((struct in6_addr *)
							     min_address);
		e.address.ipv6.max = tomoyo_get_ipv6_address((struct in6_addr *)
							     max_address);
		if (!e.address.ipv6.min || !e.address.ipv6.max)
			goto out;
		break;
	case TOMOYO_IP_ADDRESS_TYPE_IPv4:
		e.address_type = TOMOYO_IP_ADDRESS_TYPE_IPv4;
		/* use host byte order to allow u32 comparison.*/
		e.address.ipv4.min = ntohl(*(u32 *) min_address);
		e.address.ipv4.max = ntohl(*(u32 *) max_address);
		break;
	default:
		if (w[2][0] != '@')
			return -EINVAL;
		e.address_type = TOMOYO_IP_ADDRESS_TYPE_ADDRESS_GROUP;
		e.address.group = tomoyo_get_group(w[2] + 1,
						   TOMOYO_ADDRESS_GROUP);
		if (!e.address.group)
			return -ENOMEM;
		break;
	}
	if (!tomoyo_parse_number_union(w[3], &e.port))
		goto out;
	error = tomoyo_update_domain(&e.head, sizeof(e), is_delete, domain,
				     tomoyo_same_ip_network_acl,
				     tomoyo_merge_ip_network_acl);
 out:
	if (e.address_type == TOMOYO_IP_ADDRESS_TYPE_ADDRESS_GROUP)
		tomoyo_put_group(e.address.group);
	else if (e.address_type == TOMOYO_IP_ADDRESS_TYPE_IPv6) {
		tomoyo_put_ipv6_address(e.address.ipv6.min);
		tomoyo_put_ipv6_address(e.address.ipv6.max);
	}
	tomoyo_put_number_union(&e.port);
	return error;
}

/* Check permission for listening a TCP socket. */
int tomoyo_socket_listen_permission(struct socket *sock)
{
	int error = 0;
	struct sockaddr_storage addr;
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
	if (sock->ops->getname(sock, (struct sockaddr *) &addr, &addr_len, 0))
		return -EPERM;
	switch (((struct sockaddr *) &addr)->sa_family) {
	case AF_INET6:
		is_ipv6 = true;
		address = (u32 *) ((struct sockaddr_in6 *) &addr)->sin6_addr
			.s6_addr;
		port = ((struct sockaddr_in6 *) &addr)->sin6_port;
		break;
	case AF_INET:
		is_ipv6 = false;
		address = (u32 *) &((struct sockaddr_in *) &addr)->sin_addr;
		port = ((struct sockaddr_in *) &addr)->sin_port;
		break;
	default:
		goto skip;
	}
	error = tomoyo_network_entry(is_ipv6, TOMOYO_NETWORK_TCP_LISTEN,
				     address, port);
 skip:
	return error;
}

/* Check permission for setting the remote IP address/port pair of a socket. */
int tomoyo_socket_connect_permission(struct socket *sock, struct sockaddr *addr,
				     int addr_len)
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
		operation = TOMOYO_NETWORK_TCP_CONNECT;
		break;
	case SOCK_DGRAM:
		operation = TOMOYO_NETWORK_UDP_CONNECT;
		break;
	case SOCK_RAW:
		operation = TOMOYO_NETWORK_RAW_CONNECT;
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
	error = tomoyo_network_entry(is_ipv6, operation, address, port);
 skip:
	return error;
}

/* Check permission for setting the local IP address/port pair of a socket. */
int tomoyo_socket_bind_permission(struct socket *sock, struct sockaddr *addr,
				  int addr_len)
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
		operation = TOMOYO_NETWORK_TCP_BIND;
		break;
	case SOCK_DGRAM:
		operation = TOMOYO_NETWORK_UDP_BIND;
		break;
	case SOCK_RAW:
		operation = TOMOYO_NETWORK_RAW_BIND;
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
	error = tomoyo_network_entry(is_ipv6, operation, address, port);
 skip:
	return error;
}

/* Check permission for accepting a TCP socket. */
int tomoyo_socket_accept_permission(struct socket *sock)
{
	struct sockaddr_storage addr;
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
	error = sock->ops->getname(sock, (struct sockaddr *) &addr, &addr_len,
				   2);
	if (error)
		return error;
	switch (((struct sockaddr *) &addr)->sa_family) {
		case AF_INET6:
		is_ipv6 = true;
		address = (u32 *) ((struct sockaddr_in6 *) &addr)->sin6_addr
			.s6_addr;
		port = ((struct sockaddr_in6 *) &addr)->sin6_port;
		break;
	case AF_INET:
		is_ipv6 = false;
		address = (u32 *) &((struct sockaddr_in *) &addr)->sin_addr;
		port = ((struct sockaddr_in *) &addr)->sin_port;
		break;
	default:
		goto skip;
	}
	error = tomoyo_network_entry(is_ipv6, TOMOYO_NETWORK_TCP_ACCEPT,
				     address, port);
 skip:
	return error;
}

/* Check permission for sending a datagram via a UDP or RAW socket. */
int tomoyo_socket_sendmsg_permission(struct socket *sock, struct msghdr *msg,
				     int size)
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
		operation = TOMOYO_NETWORK_UDP_CONNECT;
		break;
	case SOCK_RAW:
		operation = TOMOYO_NETWORK_RAW_CONNECT;
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
	error = tomoyo_network_entry(is_ipv6, operation, address, port);
 skip:
	return error;
}

/* Check permission for receiving a datagram via a UDP or RAW socket. */
int tomoyo_socket_recvmsg_permission(struct sock *sk, struct sk_buff *skb)
{
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
		operation = TOMOYO_NETWORK_UDP_CONNECT;
		break;
	case SOCK_RAW:
		operation = TOMOYO_NETWORK_RAW_CONNECT;
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
	error = tomoyo_network_entry(is_ipv6, operation, (u32 *) &address,
				     port);
 skip:
	return error;
}