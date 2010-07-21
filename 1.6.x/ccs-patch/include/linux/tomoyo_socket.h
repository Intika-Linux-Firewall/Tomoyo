/*
 * include/linux/tomoyo_socket.h
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.6.8+   2010/07/21
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#ifndef _LINUX_TOMOYO_SOCKET_H
#define _LINUX_TOMOYO_SOCKET_H

#include <linux/version.h>

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
int ccs_socket_post_accept_permission(struct socket *sock,
				      struct socket *newsock);
int ccs_socket_sendmsg_permission(struct socket *sock, struct sockaddr *addr,
				  int addr_len);
int ccs_socket_post_recvmsg_permission(struct sock *sk, struct sk_buff *skb);

/* for net/ipv4/raw.c and net/ipv6/raw.c */
#if defined(_RAW_H) || defined(_NET_RAWV6_H)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
static inline void skb_kill_datagram(struct sock *sk, struct sk_buff *skb,
				     unsigned int flags)
{
	/* Clear queue. */
	if (flags & MSG_PEEK) {
		int clear = 0;
		spin_lock_irq(&sk->receive_queue.lock);
		if (skb == skb_peek(&sk->receive_queue)) {
			__skb_unlink(skb, &sk->receive_queue);
			clear = 1;
		}
		spin_unlock_irq(&sk->receive_queue.lock);
		if (clear)
			kfree_skb(skb);
	}
	skb_free_datagram(sk, skb);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 12)
static inline void skb_kill_datagram(struct sock *sk, struct sk_buff *skb,
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
static inline void skb_kill_datagram(struct sock *sk, struct sk_buff *skb,
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
#endif

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
static inline int ccs_socket_post_accept_permission(struct socket *sock,
						    struct socket *newsock)
{
	return 0;
}
static inline int ccs_socket_sendmsg_permission(struct socket *sock,
						struct sockaddr *addr,
						int addr_len)
{
	return 0;
}
static inline int ccs_socket_post_recvmsg_permission(struct sock *sk,
						     struct sk_buff *skb)
{
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
static inline void skb_kill_datagram(struct sock *sk, struct sk_buff *skb,
				     unsigned int flags) {
}
#endif

#endif

#endif
