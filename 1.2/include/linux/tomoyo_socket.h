/*
 * include/linux/tomoyo_socket.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.2   2006/09/03
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_TOMOYO_SOCKET_H
#define _LINUX_TOMOYO_SOCKET_H

/***** TOMOYO Linux start. *****/

#include <net/ip.h>
#include <net/ipv6.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#define sk_family family
#define sk_protocol protocol
#endif

#define MAX_SOCK_ADDR 128 /* net/socket.c */

static int CheckSocketCreatePermission(int family, int type, int protocol)
{
	int error = 0;
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

static int CheckSocketListenPermission(struct socket *sock)
{
	int error = 0;
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

static int CheckSocketConnectPermission(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	if (type == SOCK_STREAM || type == SOCK_DGRAM || type == SOCK_RAW) {
		switch (addr->sa_family) {
		case AF_INET6:
			if (addr_len >= SIN6_LEN_RFC2133) {
				if (type != SOCK_RAW) {
					error = CheckConnectEntry(type == SOCK_STREAM, ntohs(((struct sockaddr_in6 *) addr)->sin6_port));
					if (!error) error = CheckNetworkConnectACL(1, type, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, ((struct sockaddr_in6 *) addr)->sin6_port);
				} else {
					error = CheckNetworkConnectACL(1, SOCK_RAW, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, htons(sock->sk->sk_protocol));
				}
			}
			break;
		case AF_INET:
			if (addr_len >= sizeof(struct sockaddr_in)) {
				if (type != SOCK_RAW) {
					error = CheckConnectEntry(type == SOCK_STREAM, ntohs(((struct sockaddr_in *) addr)->sin_port));
					if (!error) error = CheckNetworkConnectACL(0, type, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, ((struct sockaddr_in *) addr)->sin_port);
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

static int CheckSocketBindPermission(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	if (type == SOCK_STREAM || type == SOCK_DGRAM || type == SOCK_RAW) {
		switch (addr->sa_family) {
		case AF_INET6:
			if (addr_len >= SIN6_LEN_RFC2133) {
				if (type != SOCK_RAW) {
					error = CheckBindEntry(type == SOCK_STREAM, ntohs(((struct sockaddr_in6 *) addr)->sin6_port));
					if (!error) error = CheckNetworkBindACL(1, type, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, ((struct sockaddr_in6 *) addr)->sin6_port);
				} else {
					error = CheckNetworkBindACL(1, SOCK_RAW, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, htons(sock->sk->sk_protocol));
				}
			}
			break;
		case AF_INET:
			if (addr_len >= sizeof(struct sockaddr_in)) {
				if (type != SOCK_RAW) {
					error = CheckBindEntry(type == SOCK_STREAM, ntohs(((struct sockaddr_in *) addr)->sin_port));
					if (!error) error = CheckNetworkBindACL(0, type, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, ((struct sockaddr_in *) addr)->sin_port);
				} else {
					error = CheckNetworkBindACL(0, SOCK_RAW, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, htons(sock->sk->sk_protocol));
				}
			}
			break;
		}
	}
	return error;
}

static int CheckSocketAcceptPermission(struct socket *sock, struct sockaddr *addr)
{
	int error = 0;
	int addr_len;
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

static int CheckSocketSendMsgPermission(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const int type = sock->type;
	if (addr && (type == SOCK_DGRAM || type == SOCK_RAW)) {
		switch (addr->sa_family) {
		case AF_INET6:
			if (addr_len >= SIN6_LEN_RFC2133) {
				if (type == SOCK_DGRAM) error = CheckConnectEntry(0, ntohs(((struct sockaddr_in6 *) addr)->sin6_port));
				if (!error) error = CheckNetworkSendMsgACL(1, type, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, type == SOCK_DGRAM ? ((struct sockaddr_in6 *) addr)->sin6_port : htons(sock->sk->sk_protocol));
			}
			break;
		case AF_INET:
			if (addr_len >= sizeof(struct sockaddr_in)) {
				if (type == SOCK_DGRAM) error = CheckConnectEntry(0, ntohs(((struct sockaddr_in *) addr)->sin_port));
				if (!error) error = CheckNetworkSendMsgACL(0, type, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, type == SOCK_DGRAM ? ((struct sockaddr_in *) addr)->sin_port : htons(sock->sk->sk_protocol));
			}
			break;
		}
	}
	return error;
}

static int CheckSocketRecvMsgPermission(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	int error = 0;
	const unsigned int type = sock->type;
	if (addr && (type == SOCK_DGRAM || type == SOCK_RAW)) {
		switch (addr->sa_family) {
		case AF_INET6:
			if (addr_len >= SIN6_LEN_RFC2133) error = CheckNetworkRecvMsgACL(1, type, ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr, type == SOCK_DGRAM ? ((struct sockaddr_in6 *) addr)->sin6_port : htons(sock->sk->sk_protocol));
			break;
		case AF_INET:
			if (addr_len >= sizeof(struct sockaddr_in)) error = CheckNetworkRecvMsgACL(0, type, (u8 *) &((struct sockaddr_in *) addr)->sin_addr, type == SOCK_DGRAM ? ((struct sockaddr_in *) addr)->sin_port : htons(sock->sk->sk_protocol));
			break;
		}
	}
	return error;
}

/***** TOMOYO Linux end. *****/
#endif
