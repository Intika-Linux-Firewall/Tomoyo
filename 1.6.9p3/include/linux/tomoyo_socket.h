/*
 * include/linux/tomoyo_socket.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/04/01
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_TOMOYO_SOCKET_H
#define _LINUX_TOMOYO_SOCKET_H

struct socket;
struct sockaddr;
struct sock;
struct sk_buff;

#if defined(CONFIG_TOMOYO)

int ccs_socket_create_permission(int family, int type, int protocol);
int ccs_socket_listen_permission(struct socket *sock);
int ccs_socket_connect_permission(struct socket *sock, struct sockaddr *addr,
				  int addr_len);
int ccs_socket_bind_permission(struct socket *sock, struct sockaddr *addr,
			       int addr_len);
int ccs_socket_accept_permission(struct socket *sock, struct sockaddr *addr);
int ccs_socket_sendmsg_permission(struct socket *sock, struct sockaddr *addr,
				  int addr_len);
int ccs_socket_recvmsg_permission(struct sock *sk, struct sk_buff *skb,
				  const unsigned int flags);

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
static inline int ccs_socket_recvmsg_permission(struct sock *sk,
						struct sk_buff *skb,
						const unsigned int flags)
{
	return 0;
}

#endif

#endif
