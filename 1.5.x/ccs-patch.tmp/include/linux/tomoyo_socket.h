/*
 * include/linux/tomoyo_socket.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2007  NTT DATA CORPORATION
 *
 * Version: 1.5.3-pre   2007/12/03
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_TOMOYO_SOCKET_H
#define _LINUX_TOMOYO_SOCKET_H

/***** TOMOYO Linux start. *****/

#if defined(CONFIG_TOMOYO)

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include <asm/uaccess.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#define sk_family family
#define sk_protocol protocol
#define sk_type type
#define sk_receive_queue receive_queue
#endif

#define MAX_SOCK_ADDR 128 /* net/socket.c */

static inline int CheckSocketCreatePermission(int family, int type, int protocol)
{
	int error = 0;
	if (segment_eq(get_fs(), KERNEL_DS)) return 0;
	if (family == PF_INET || family == PF_INET6) {
		switch (type) {
		case SOCK_STREAM:
			error = CheckCapabilityACL(TOMOYO_INET_STREAM_SOCKET_CREATE);
			break;
		case SOCK_DGRAM:
			error = CheckCapabilityACL(TOMOYO_USE_INET_DGRAM_SOCKET);
			break;
		case SOCK_RAW:
			error = CheckCapabilityACL(TOMOYO_USE_INET_RAW_SOCKET);
			break;
		}
	} else if (family == PF_PACKET) {
		error = CheckCapabilityACL(TOMOYO_USE_PACKET_SOCKET);
	} else if (family == PF_ROUTE) {
		error = CheckCapabilityACL(TOMOYO_USE_ROUTE_SOCKET);
	}
	return error;
}

static inline int CheckSocketListenPermission(struct socket *sock)
{
	int error = 0;
	if (segment_eq(get_fs(), KERNEL_DS)) return 0;
	if (sock->type == SOCK_STREAM) {
		switch (sock->sk->sk_family) {
		case PF_INET:
		case PF_INET6:
			error = CheckCapabilityACL(TOMOYO_INET_STREAM_SOCKET_LISTEN);
			if (!error) {
				char addr[MAX_SOCK_ADDR];
				int addr_len;
				if (sock->ops->getname(sock, (struct sockaddr *) addr, &addr_len, 0) == 0) {
					switch (((struct sockaddr *) addr)->sa_family) {
					case AF_INET6:
						error = CheckNetworkListenACL(1, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, ((struct sockaddr_in6 *) addr)->sin6_port);
						break;
					case AF_INET:
						error = CheckNetworkListenACL(0, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, ((struct sockaddr_in *) addr)->sin_port);
						break;
					}
				} else {
					error = -EPERM;
				}
			}
			break;
		}
	}
	return error;
}

static inline int CheckSocketConnectPermission(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	if (segment_eq(get_fs(), KERNEL_DS)) return 0;
	if (type == SOCK_STREAM || type == SOCK_DGRAM || type == SOCK_RAW) {
		switch (addr->sa_family) {
		case AF_INET6:
			if (addr_len >= SIN6_LEN_RFC2133) {
				if (type != SOCK_RAW) {
					error = CheckNetworkConnectACL(1, type, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, ((struct sockaddr_in6 *) addr)->sin6_port);
				} else {
					error = CheckNetworkConnectACL(1, SOCK_RAW, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, htons(sock->sk->sk_protocol));
				}
			}
			break;
		case AF_INET:
			if (addr_len >= sizeof(struct sockaddr_in)) {
				if (type != SOCK_RAW) {
					error = CheckNetworkConnectACL(0, type, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, ((struct sockaddr_in *) addr)->sin_port);
				} else {
					error = CheckNetworkConnectACL(0, SOCK_RAW, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, htons(sock->sk->sk_protocol));
				}
			}
			break;
		}
	}
	if (type == SOCK_STREAM) {
		switch (sock->sk->sk_family) {
		case PF_INET:
		case PF_INET6:
			error = CheckCapabilityACL(TOMOYO_INET_STREAM_SOCKET_CONNECT) ? -EPERM : error;
			break;
		}
	}
	return error;
}

static inline int CheckSocketBindPermission(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	if (segment_eq(get_fs(), KERNEL_DS)) return 0;
	if (type == SOCK_STREAM || type == SOCK_DGRAM || type == SOCK_RAW) {
		switch (addr->sa_family) {
		case AF_INET6:
			if (addr_len >= SIN6_LEN_RFC2133) {
				if (type != SOCK_RAW) {
					error = CheckNetworkBindACL(1, type, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, ((struct sockaddr_in6 *) addr)->sin6_port);
				} else {
					error = CheckNetworkBindACL(1, SOCK_RAW, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, htons(sock->sk->sk_protocol));
				}
			}
			break;
		case AF_INET:
			if (addr_len >= sizeof(struct sockaddr_in)) {
				if (type != SOCK_RAW) {
					error = CheckNetworkBindACL(0, type, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, ((struct sockaddr_in *) addr)->sin_port);
				} else {
					error = CheckNetworkBindACL(0, SOCK_RAW, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, htons(sock->sk->sk_protocol));
				}
			}
			break;
		}
	}
	return error;
}

static inline int CheckSocketAcceptPermission(struct socket *sock, struct sockaddr *addr)
{
	int error = 0;
	int addr_len;
	if (segment_eq(get_fs(), KERNEL_DS)) return 0;
	switch (sock->sk->sk_family) {
	case PF_INET:
	case PF_INET6:
		if (sock->ops->getname(sock, addr, &addr_len, 2) == 0) {
			switch (addr->sa_family) {
			case AF_INET6:
				error = CheckNetworkAcceptACL(1, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, ((struct sockaddr_in6 *) addr)->sin6_port);
				break;
			case AF_INET:
				error = CheckNetworkAcceptACL(0, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, ((struct sockaddr_in *) addr)->sin_port);
				break;
			}
		} else {
			error = -EPERM;
		}
	}
	return error;
}

static inline int CheckSocketSendMsgPermission(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const int type = sock->type;
	if (segment_eq(get_fs(), KERNEL_DS)) return 0;
	if (addr && (type == SOCK_DGRAM || type == SOCK_RAW)) {
		switch (addr->sa_family) {
		case AF_INET6:
			if (addr_len >= SIN6_LEN_RFC2133) {
				error = CheckNetworkSendMsgACL(1, type, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, type == SOCK_DGRAM ? ((struct sockaddr_in6 *) addr)->sin6_port : htons(sock->sk->sk_protocol));
			}
			break;
		case AF_INET:
			if (addr_len >= sizeof(struct sockaddr_in)) {
				error = CheckNetworkSendMsgACL(0, type, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, type == SOCK_DGRAM ? ((struct sockaddr_in *) addr)->sin_port : htons(sock->sk->sk_protocol));
			}
			break;
		}
	}
	return error;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

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

static inline int CheckSocketRecvDatagramPermission(struct sock *sk, struct sk_buff *skb, const unsigned int flags)
{
	int error = 0;
	const unsigned int type = sk->sk_type;
	struct in6_addr sin6;
	struct in_addr sin;
	u16 port;
		
	if (!skb) return 0;

	if (in_interrupt()) return 0;
	
	if (segment_eq(get_fs(), KERNEL_DS)) return 0;
	
	if (type != SOCK_DGRAM && type != SOCK_RAW) return 0;
	
	switch (sk->sk_family) {
	case PF_INET6:
		if (type == SOCK_DGRAM) { /* UDP IPv6 */
			if (skb->protocol == htons(ETH_P_IP)) {
				ipv6_addr_set(&sin6, 0, 0, htonl(0xffff), ip_hdr(skb)->saddr);
			} else {
				ipv6_addr_copy(&sin6, &ipv6_hdr(skb)->saddr);
			}
			port = udp_hdr(skb)->source;
		} else { /* RAW IPv6 */
			ipv6_addr_copy(&sin6, &ipv6_hdr(skb)->saddr);
			port = htons(sk->sk_protocol);
		}
		error = CheckNetworkRecvMsgACL(1, type, (u8 *) &sin6, port);
		break;
	case PF_INET:
		if (type == SOCK_DGRAM) { /* UDP IPv4 */
			sin.s_addr = ip_hdr(skb)->saddr;
			port = udp_hdr(skb)->source;
		} else { /* RAW IPv4 */
			sin.s_addr = ip_hdr(skb)->saddr;
			port = htons(sk->sk_protocol);
		}
		error = CheckNetworkRecvMsgACL(0, type, (u8 *) &sin, port);
		break;
	}
	if (error) {
		/*
		 * Remove from queue if MSG_PEEK is used so that
		 * the head message from unwanted source in receive queue will not
		 * prevent the caller from picking up next message from wanted source
		 * when the caller is using MSG_PEEK flag for picking up.
		 */
		if (flags & MSG_PEEK) {
			unsigned long cpu_flags;
			spin_lock_irqsave(&sk->sk_receive_queue.lock, cpu_flags);
			if (skb == skb_peek(&sk->sk_receive_queue)) {
				__skb_unlink(skb, &sk->sk_receive_queue);
				atomic_dec(&skb->users);
			}
			spin_unlock_irqrestore(&sk->sk_receive_queue.lock, cpu_flags);
		}
		/* Drop reference count. */
		skb_free_datagram(sk, skb);
		/* Hope less harmful than -EPERM. */
		error = -EAGAIN;
	}
	return error;
}

#else

static inline int CheckSocketCreatePermission(int family, int type, int protocol) { return 0; }
static inline int CheckSocketListenPermission(struct socket *sock) { return 0; }
static inline int CheckSocketConnectPermission(struct socket *sock, struct sockaddr *addr, int addr_len) { return 0; }
static inline int CheckSocketBindPermission(struct socket *sock, struct sockaddr *addr, int addr_len) { return 0; }
static inline int CheckSocketAcceptPermission(struct socket *sock, struct sockaddr *addr) { return 0; }
static inline int CheckSocketSendMsgPermission(struct socket *sock, struct sockaddr *addr, int addr_len) { return 0; }
static inline int CheckSocketRecvDatagramPermission(struct sock *sk, struct sk_buff *skb, const unsigned int flags) { return 0; }

#endif

/***** TOMOYO Linux end. *****/
#endif
