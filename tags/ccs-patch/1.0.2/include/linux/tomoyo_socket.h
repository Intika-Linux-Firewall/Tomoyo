/*
 * include/linux/tomoyo_socket.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2006  NTT DATA CORPORATION
 *
 * Version: 1.0 2005/11/11
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_TOMOYO_SOCKET_H
#define _LINUX_TOMOYO_SOCKET_H

/***** TOMOYO Linux start. *****/

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <net/ip.h>
#include <net/ipv6.h>
#else
#define sk_family family
#endif

static int CheckSocketCreatePermission(int family, int type, int protocol) {
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

static int CheckSocketListenPermission(struct socket *sock) {
	int error = 0;
	if (sock->type == SOCK_STREAM) {
		switch (sock->sk->sk_family) {
		case PF_INET:
		case PF_INET6:
			error = CheckCapabilityACL(TOMOYO_INET_STREAM_SOCKET_LISTEN);
			break;
		}
	}
	return error;
}

static int CheckSocketConnectPermission(struct socket *sock, struct sockaddr *addr, int addr_len) {
	int error = 0;
	if (sock->type == SOCK_STREAM || sock->type == SOCK_DGRAM) {
		switch (sock->sk->sk_family) {
		case PF_INET:
			if (addr && addr_len >= sizeof(struct sockaddr_in))
				error = CheckConnectEntry(sock->type == SOCK_STREAM, htons(((struct sockaddr_in *) addr)->sin_port));
			break;
		case PF_INET6:
			if (addr && addr_len >= sizeof(struct sockaddr_in6))
				error = CheckConnectEntry(sock->type == SOCK_STREAM, htons(((struct sockaddr_in6 *) addr)->sin6_port));
			break;
		}
	}
	if (sock->type == SOCK_STREAM) {
		switch (sock->sk->sk_family) {
		case PF_INET:
		case PF_INET6:
			error = CheckCapabilityACL(TOMOYO_INET_STREAM_SOCKET_CONNECT) ? -EPERM : error;
			break;
		}
	}
	return error;
}

static int CheckSocketBindPermission(struct socket *sock, struct sockaddr *addr, int addr_len) {
	int error = 0;
	if (sock->type == SOCK_STREAM || sock->type == SOCK_DGRAM) {
		switch (sock->sk->sk_family) {
		case PF_INET:
			if (addr && addr_len >= sizeof(struct sockaddr_in))
				error = CheckBindEntry(sock->type == SOCK_STREAM, htons(((struct sockaddr_in *) addr)->sin_port));
			break;
		case PF_INET6:
			if (addr && addr_len >= sizeof(struct sockaddr_in6))
				error = CheckBindEntry(sock->type == SOCK_STREAM, htons(((struct sockaddr_in6 *) addr)->sin6_port));
			break;
		}
	}
	return error;
}

static int CheckSocketSendMsgPermission(struct socket *sock, struct sockaddr *addr, int addr_len) {
	int error = 0;
	/* Remote port check for SOCK_STREAM is done at CheckSocketConnectPermission(). */
	if (sock->type == SOCK_DGRAM) {
		switch (sock->sk->sk_family) {
		case PF_INET:
			if (addr && addr_len >= sizeof(struct sockaddr_in))
				error = CheckConnectEntry(sock->type == SOCK_STREAM, htons(((struct sockaddr_in *) addr)->sin_port));
			break;
		case PF_INET6:
			if (addr && addr_len >= sizeof(struct sockaddr_in6))
				error = CheckConnectEntry(sock->type == SOCK_STREAM, htons(((struct sockaddr_in6 *) addr)->sin6_port));
			break;
		}
	}
	return error;
}

/***** TOMOYO Linux end. *****/
#endif
