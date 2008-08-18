/*
 * include/linux/tomoyo_socket.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2008  NTT DATA CORPORATION
 *
 * Version: 1.6.3+   2008/08/18
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_TOMOYO_SOCKET_H
#define _LINUX_TOMOYO_SOCKET_H

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include <asm/uaccess.h>
#include <linux/version.h>

#if defined(CONFIG_TOMOYO)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define sk_family family
#define sk_protocol protocol
#define sk_type type
#define sk_receive_queue receive_queue
#endif

#define false 0
#define true 1

#define MAX_SOCK_ADDR 128 /* net/socket.c */

/* Check permission for creating a socket. */
static inline int ccs_socket_create_permission(int family, int type,
					       int protocol)
{
	int error = 0;
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	if (family == PF_PACKET && !ccs_capable(TOMOYO_USE_PACKET_SOCKET))
		return -EPERM;
	if (family == PF_ROUTE && !ccs_capable(TOMOYO_USE_ROUTE_SOCKET))
		return -EPERM;
	if (family != PF_INET && family != PF_INET6)
		return 0;
	switch (type) {
	case SOCK_STREAM:
		if (!ccs_capable(TOMOYO_INET_STREAM_SOCKET_CREATE))
			error = -EPERM;
		break;
	case SOCK_DGRAM:
		if (!ccs_capable(TOMOYO_USE_INET_DGRAM_SOCKET))
			error = -EPERM;
		break;
	case SOCK_RAW:
		if (!ccs_capable(TOMOYO_USE_INET_RAW_SOCKET))
			error = -EPERM;
		break;
	}
	return error;
}

/* Check permission for listening a TCP socket. */
static inline int ccs_socket_listen_permission(struct socket *sock)
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
	if (!ccs_capable(TOMOYO_INET_STREAM_SOCKET_LISTEN))
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
static inline int ccs_socket_connect_permission(struct socket *sock,
						struct sockaddr *addr,
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
		if (!ccs_capable(TOMOYO_INET_STREAM_SOCKET_CONNECT))
			error = -EPERM;
		break;
	}
	return error;
}

/* Check permission for setting the local IP address/port pair of a socket. */
static inline int ccs_socket_bind_permission(struct socket *sock,
					     struct sockaddr *addr,
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
static inline int ccs_socket_accept_permission(struct socket *sock,
					       struct sockaddr *addr)
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
static inline int ccs_socket_sendmsg_permission(struct socket *sock,
						struct sockaddr *addr,
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

#define ip_hdr(skb) ((skb)->nh.iph)
#define udp_hdr(skb) ((skb)->h.uh)
#define ipv6_hdr(skb) ((skb)->nh.ipv6h)

#endif

/*
 * Check permission for receiving a datagram via a UDP or RAW socket.
 *
 * Currently, the LSM hook for this purpose is not provided.
 */
static inline int ccs_socket_recv_datagram_permission(struct sock *sk,
						      struct sk_buff *skb,
						      const unsigned int flags)
{
	int error = 0;
	const unsigned int type = sk->sk_type;
	/* Nothing to do if I didn't receive a datagram. */
	if (!skb)
		return 0;
	/* Nothing to do if I can't sleep. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
	if (in_interrupt())
		return 0;
#else
	if (in_atomic())
		return 0;
#endif
	/* Nothing to do if I am a kernel service. */
	if (segment_eq(get_fs(), KERNEL_DS))
		return 0;
	if (type != SOCK_DGRAM && type != SOCK_RAW)
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	lock_sock(sk);
#endif
	/*
	 * Remove from queue if MSG_PEEK is used so that
	 * the head message from unwanted source in receive queue will not
	 * prevent the caller from picking up next message from wanted source
	 * when the caller is using MSG_PEEK flag for picking up.
	 */
	if (flags & MSG_PEEK) {
		unsigned long cpu_flags;
		/***** CRITICAL SECTION START *****/
		spin_lock_irqsave(&sk->sk_receive_queue.lock, cpu_flags);
		if (skb == skb_peek(&sk->sk_receive_queue)) {
			__skb_unlink(skb, &sk->sk_receive_queue);
			atomic_dec(&skb->users);
		}
		spin_unlock_irqrestore(&sk->sk_receive_queue.lock, cpu_flags);
		/***** CRITICAL SECTION END *****/
	}
	/* Drop reference count. */
	skb_free_datagram(sk, skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	release_sock(sk);
#endif
	/* Hope less harmful than -EPERM. */
	return -EAGAIN;
}

#else

static inline int ccs_socket_create_permission(int family, int type,
					       int protocol)
{
	return 0;
}
static inline int ccs_socket_listen_permission(struct socket *sock)
{
	return 0;
}
static inline int ccs_socket_connect_permission(struct socket *sock,
						struct sockaddr *addr,
						int addr_len)
{
	return 0;
}
static inline int ccs_socket_bind_permission(struct socket *sock,
					     struct sockaddr *addr,
					     int addr_len)
{
	return 0;
}
static inline int ccs_socket_accept_permission(struct socket *sock,
					       struct sockaddr *addr)
{
	return 0;
}
static inline int ccs_socket_sendmsg_permission(struct socket *sock,
						struct sockaddr *addr,
						int addr_len)
{
	return 0;
}
static inline int ccs_socket_recv_datagram_permission(struct sock *sk,
						      struct sk_buff *skb,
						      const unsigned int flags)
{
	return 0;
}

#endif

/* For compatibility with 1.4.x/1.5.x patches */
#define CheckSocketSendMsgPermission      ccs_socket_sendmsg_permission
#define CheckSocketCreatePermission       ccs_socket_create_permission
#define CheckSocketBindPermission         ccs_socket_bind_permission
#define CheckSocketListenPermission       ccs_socket_listen_permission
#define CheckSocketAcceptPermission       ccs_socket_accept_permission
#define CheckSocketConnectPermission      ccs_socket_connect_permission
#define CheckSocketRecvDatagramPermission ccs_socket_recv_datagram_permission

#endif
