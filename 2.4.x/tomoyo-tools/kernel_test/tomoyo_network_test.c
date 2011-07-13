/*
 * ccs_network_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0-pre   2011/07/13
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
#include "include.h"

static int is_enforce = 0;

static void show_prompt(const char *str)
{
	printf("Testing %50s: (%s) ", str,
	       is_enforce ? "must fail" : "should success");
	errno = 0;
}

static void show_result(int result)
{
	if (is_enforce) {
		if (result == EOF) {
			if (errno == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("FAILED: %s\n", strerror(errno));
		} else {
			printf("BUG!(%d)\n", result);
		}
	} else {
		if (result != EOF)
			printf("OK\n");
		else
			printf("%s\n", strerror(errno));
	}
}

static void show_result2(int result)
{
	if (is_enforce) {
		if (result == EOF) {
			if (errno == EAGAIN)
				printf("OK: Permission denied.\n");
			else
				printf("FAILED: %s\n", strerror(errno));
		} else {
			char c;
			if (recv(result, &c, 1, MSG_DONTWAIT) == EOF &&
			    errno == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("BUG!(%d)\n", result);
		}
	} else {
		if (result != EOF)
			printf("OK\n");
		else
			printf("%s\n", strerror(errno));
	}
}

static void show_result3(int result)
{
	if (result == EOF) {
		if (errno == EDESTADDRREQ)
			printf("OK: Destination address required.\n");
		else if (errno == ENOTCONN)
			printf("OK: Transport endpoint is not connected.\n");
		else
			printf("BUG!: %s\n", strerror(errno));
	} else {
		printf("BUG!(%d)\n", result);
	}
}

static void set_enforce(int flag)
{
	is_enforce = flag;
	if (flag)
		flag = 3;
	else
		flag = 2;
	set_profile(flag, "network::inet_stream_bind");
	set_profile(flag, "network::inet_stream_listen");
	set_profile(flag, "network::inet_stream_connect");
	set_profile(flag, "network::inet_stream_accept");
	set_profile(flag, "network::inet_dgram_bind");
	set_profile(flag, "network::inet_dgram_send");
	set_profile(flag, "network::inet_dgram_recv");
	set_profile(flag, "network::inet_raw_bind");
	set_profile(flag, "network::inet_raw_send");
	set_profile(flag, "network::inet_raw_recv");
}

static void stage_network_test(void)
{
	int i;
	static char buf[16];
	static char sbuffer[1024];
	static char cbuffer[1024];
	memset(buf, 0, sizeof(buf));
	memset(sbuffer, 0, sizeof(sbuffer));
	memset(cbuffer, 0, sizeof(cbuffer));

	{ /* IPv4 TCP */
		struct sockaddr_in saddr;
		struct sockaddr_in caddr;
		socklen_t size = sizeof(saddr);
		int fd1 = EOF;
		int fd2 = EOF;
		int fd3 = EOF;

		fd1 = socket(PF_INET, SOCK_STREAM, 0);

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		saddr.sin_port = htons(0);
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Binding TCP 127.0.0.1 0");
		set_enforce(1);
		show_prompt(sbuffer);
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)));
		set_enforce(0);
		show_prompt(sbuffer);
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)));
		getsockname(fd1, (struct sockaddr *) &saddr, &size);

		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Listening TCP 127.0.0.1 %d",
			 ntohs(saddr.sin_port));
		set_enforce(1);
		show_prompt(sbuffer);
		show_result(listen(fd1, 5));
		set_enforce(0);
		show_prompt(sbuffer);
		show_result(listen(fd1, 5));

		fd2 = socket(PF_INET, SOCK_STREAM, 0);

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Connecting TCP 127.0.0.1 %d",
			 ntohs(saddr.sin_port));
		set_enforce(1);
		show_prompt(cbuffer);
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)));
		set_enforce(0);
		show_prompt(cbuffer);
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)));
		getsockname(fd2, (struct sockaddr *) &caddr, &size);

		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Accepting TCP 127.0.0.1 %d",
			 ntohs(caddr.sin_port));
		set_enforce(1);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) | O_NONBLOCK);
		show_prompt(sbuffer);
		fd3 = accept(fd1, (struct sockaddr *) &caddr, &size);
		show_result2(fd3);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) & ~O_NONBLOCK);

		set_enforce(0);
		close(fd2);
		fd2 = socket(PF_INET, SOCK_STREAM, 0);
		connect(fd2, (struct sockaddr *) &saddr, sizeof(saddr));
		getsockname(fd2, (struct sockaddr *) &caddr, &size);

		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Accepting TCP 127.0.0.1 %d",
			 ntohs(caddr.sin_port));
		set_enforce(0);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) | O_NONBLOCK);
		show_prompt(sbuffer);
		fd3 = accept(fd1, (struct sockaddr *) &caddr, &size);
		show_result2(fd3);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) & ~O_NONBLOCK);

		close(fd3);
		close(fd2);
		close(fd1);
	}

	{ /* IPv4 UDP */
		struct sockaddr_in saddr;
		struct sockaddr_in caddr;
		socklen_t size = sizeof(saddr);
		int fd1 = EOF;
		int fd2 = EOF;
		int ret_ignored;

		fd1 = socket(PF_INET, SOCK_DGRAM, 0);

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		saddr.sin_port = htons(0);
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Binding UDP 127.0.0.1 0");
		set_enforce(1);
		show_prompt(sbuffer);
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)));
		set_enforce(0);
		show_prompt(sbuffer);
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)));
		getsockname(fd1, (struct sockaddr *) &saddr, &size);

		fd2 = socket(PF_INET, SOCK_DGRAM, 0);

		/* send() -> recv() */

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Sending UDP 127.0.0.1 %d using send()",
			 ntohs(saddr.sin_port));
		set_enforce(1);
		show_prompt(cbuffer);
		show_result3(send(fd2, "", 1, 0));
		set_enforce(0);
		show_prompt(cbuffer);
		show_result3(send(fd2, "", 1, 0));

		/* write() -> read() */

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Sending UDP 127.0.0.1 %d using write()",
			 ntohs(saddr.sin_port));
		set_enforce(1);
		show_prompt(cbuffer);
		show_result3(write(fd2, "", 1));
		set_enforce(0);
		show_prompt(cbuffer);
		show_result3(write(fd2, "", 1));

		/* connect() */

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Connecting UDP 127.0.0.1 %d",
			 ntohs(saddr.sin_port));
		set_enforce(1);
		show_prompt(cbuffer);
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)));
		set_enforce(0);
		show_prompt(cbuffer);
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)));
		getsockname(fd2, (struct sockaddr *) &caddr, &size);

		/* sendto() -> recvfrom() */

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Sending UDP 127.0.0.1 %d using sendto()",
			 ntohs(saddr.sin_port));
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Receiving UDP 127.0.0.1 %d using recvfrom()",
			 ntohs(caddr.sin_port));

		set_enforce(1);
		show_prompt(cbuffer);
		show_result(sendto(fd2, "", 1, 0, (struct sockaddr *) &saddr,
				   sizeof(saddr)));
		set_enforce(0);
		show_prompt(cbuffer);
		show_result(sendto(fd2, "", 1, 0, (struct sockaddr *) &saddr,
				   sizeof(saddr)));
		set_enforce(1);
		show_prompt(sbuffer);
		show_result2(recvfrom(fd1, buf, sizeof(buf) - 1, MSG_DONTWAIT,
				      (struct sockaddr *) &caddr, &size));
		set_enforce(0);
		sendto(fd2, "", 1, 0, (struct sockaddr *) &saddr,
		       sizeof(saddr));
		set_enforce(0);
		show_prompt(sbuffer);
		show_result2(recvfrom(fd1, buf, sizeof(buf) - 1, MSG_DONTWAIT,
				      (struct sockaddr *) &caddr, &size));

		/* send() -> recv() */

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Sending UDP 127.0.0.1 %d using send()",
			 ntohs(saddr.sin_port));
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Receiving UDP 127.0.0.1 %d using recv()",
			 ntohs(caddr.sin_port));
		if (0) {
			set_enforce(1);
			show_prompt(cbuffer);
			show_result(send(fd2, "", 1, 0));
			/* This won't fail because dest address is given via
			   connect(). */
		}
		set_enforce(0);
		show_prompt(cbuffer);
		show_result(send(fd2, "", 1, 0));
		set_enforce(1);
		show_prompt(sbuffer);
		show_result2(recv(fd1, buf, sizeof(buf) - 1, MSG_DONTWAIT));
		set_enforce(0);
		send(fd2, "", 1, 0);
		set_enforce(0);
		show_prompt(sbuffer);
		show_result2(recv(fd1, buf, sizeof(buf) - 1, MSG_DONTWAIT));

		/* write() -> read() */

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Sending UDP 127.0.0.1 %d using write()",
			 ntohs(saddr.sin_port));
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Receiving UDP 127.0.0.1 %d using read()",
			 ntohs(caddr.sin_port));
		if (0) {
			set_enforce(1);
			show_prompt(cbuffer);
			show_result(write(fd2, "", 1));
			/* This won't fail because dest address is given via
			   connect(). */
		}
		set_enforce(0);
		show_prompt(cbuffer);
		show_result(write(fd2, "", 1));
		set_enforce(1);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) | O_NONBLOCK);
		show_prompt(sbuffer);
		show_result2(read(fd1, buf, sizeof(buf) - 1));
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) & ~O_NONBLOCK);
		set_enforce(0);
		ret_ignored = write(fd2, "", 1);
		set_enforce(0);
		show_prompt(sbuffer);
		show_result2(read(fd1, buf, sizeof(buf) - 1));

		/* sendmsg() -> recvmsg() */
		{
			struct msghdr msg1;
			struct msghdr msg2;
			struct iovec iov1 = { "", 1 };
			struct iovec iov2 = { buf, sizeof(buf) - 1 };
			memset(&msg1, 0, sizeof(msg1));
			memset(&msg2, 0, sizeof(msg2));
			msg1.msg_iov = &iov1;
			msg1.msg_iovlen = 1;
			msg1.msg_name = &saddr;
			msg1.msg_namelen = sizeof(saddr);
			msg2.msg_iov = &iov2;
			msg2.msg_iovlen = 1;
			/*
			  msg2.msg_name = &caddr;
			  msg2.msg_namelen = sizeof(caddr);
			*/
			snprintf(cbuffer, sizeof(cbuffer) - 1,
				 "Client: Sending UDP 127.0.0.1 %d using "
				 "sendmsg()", ntohs(saddr.sin_port));
			snprintf(sbuffer, sizeof(sbuffer) - 1,
				 "Server: Receiving UDP 127.0.0.1 %d using "
				 "recvmsg()", ntohs(caddr.sin_port));
			set_enforce(1);
			show_prompt(cbuffer);
			show_result(sendmsg(fd1, &msg1, 0));
			set_enforce(0);
			show_prompt(cbuffer);
			show_result(sendmsg(fd1, &msg1, 0));
			set_enforce(1);
			show_prompt(sbuffer);
			show_result2(recvmsg(fd1, &msg2, MSG_DONTWAIT));
			set_enforce(0);
			sendmsg(fd1, &msg1, 0);
			set_enforce(0);
			show_prompt(sbuffer);
			show_result2(recvmsg(fd1, &msg2, MSG_DONTWAIT));
		}

		close(fd2);
		close(fd1);

	}

	{ /* IPv4 RAW */
		static struct iphdr ip;
		struct sockaddr_in saddr;
		struct sockaddr_in caddr;
		socklen_t size = sizeof(saddr);
		int fd1 = EOF;
		int fd2 = EOF;

		fd1 = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		saddr.sin_port = htons(0);
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Binding RAW 127.0.0.1 IPPROTO_RAW");
		set_enforce(1);
		show_prompt(sbuffer);
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)));
		set_enforce(0);
		show_prompt(sbuffer);
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)));

		fd2 = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

		getsockname(fd1, (struct sockaddr *) &saddr, &size);
		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Connecting RAW 127.0.0.1 %d",
			 ntohs(saddr.sin_port));
		set_enforce(1);
		show_prompt(cbuffer);
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)));
		set_enforce(0);
		show_prompt(cbuffer);
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)));

		memset(&ip, 0, sizeof(ip));
		ip.version = 4;
		ip.ihl = sizeof(struct iphdr) / 4;
		ip.protocol = IPPROTO_RAW;
		ip.daddr = htonl(INADDR_LOOPBACK);
		ip.saddr = ip.daddr;

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Sending RAW 127.0.0.1 %d",
			 ntohs(saddr.sin_port));
		set_enforce(1);
		show_prompt(cbuffer);
		show_result(sendto(fd2, &ip, sizeof(ip), 0,
				   (struct sockaddr *) &saddr, sizeof(saddr)));
		set_enforce(0);
		show_prompt(cbuffer);
		show_result(sendto(fd2, &ip, sizeof(ip), 0,
				   (struct sockaddr *) &saddr, sizeof(saddr)));

		getsockname(fd2, (struct sockaddr *) &caddr, &size);
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Receiving RAW 127.0.0.1 %d",
			 ntohs(caddr.sin_port));
		set_enforce(1);
		show_prompt(sbuffer);
		show_result2(recvfrom(fd1, buf, sizeof(buf) - 1, MSG_DONTWAIT,
				      (struct sockaddr *) &caddr, &size));
		set_enforce(0);
		sendto(fd2, &ip, sizeof(ip), 0, (struct sockaddr *) &saddr,
		       sizeof(saddr));
		set_enforce(0);
		show_prompt(sbuffer);
		show_result2(recvfrom(fd1, buf, sizeof(buf) - 1, MSG_DONTWAIT,
				      (struct sockaddr *) &caddr, &size));

		close(fd2);
		close(fd1);

	}

	i = socket(PF_INET6, SOCK_STREAM, 0);
	if (i == EOF)
		return;
	close(i);

	{
		struct sockaddr_in6 saddr;
		struct sockaddr_in6 caddr;
		socklen_t size = sizeof(saddr);
		int fd1 = EOF;
		int fd2 = EOF;
		int fd3 = EOF;

		fd1 = socket(PF_INET6, SOCK_STREAM, 0);

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin6_family = AF_INET6;
		saddr.sin6_addr = in6addr_loopback;
		saddr.sin6_port = htons(0);
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Binding TCP ::1 0");
		set_enforce(1);
		show_prompt(sbuffer);
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)));
		set_enforce(0);
		show_prompt(sbuffer);
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)));
		getsockname(fd1, (struct sockaddr *) &saddr, &size);

		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Listening TCP ::1 %d",
			 ntohs(saddr.sin6_port));
		set_enforce(1);
		show_prompt(sbuffer);
		show_result(listen(fd1, 5));
		set_enforce(0);
		show_prompt(sbuffer);
		show_result(listen(fd1, 5));

		fd2 = socket(PF_INET6, SOCK_STREAM, 0);

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Connecting TCP ::1 %d",
			 ntohs(saddr.sin6_port));
		set_enforce(1);
		show_prompt(cbuffer);
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)));
		set_enforce(0);
		show_prompt(cbuffer);
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)));

		getsockname(fd2, (struct sockaddr *) &caddr, &size);
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Accepting TCP ::1 %d",
			 ntohs(caddr.sin6_port));
		set_enforce(1);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) | O_NONBLOCK);
		show_prompt(sbuffer);
		fd3 = accept(fd1, (struct sockaddr *) &caddr, &size);
		show_result2(fd3);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) & ~O_NONBLOCK);

		set_enforce(0);
		close(fd2);
		fd2 = socket(PF_INET6, SOCK_STREAM, 0);
		connect(fd2, (struct sockaddr *) &saddr, sizeof(saddr));
		getsockname(fd2, (struct sockaddr *) &caddr, &size);

		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Accepting TCP ::1 %d",
			 ntohs(caddr.sin6_port));
		set_enforce(0);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) | O_NONBLOCK);
		show_prompt(sbuffer);
		fd3 = accept(fd1, (struct sockaddr *) &caddr, &size);
		show_result2(fd3);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) & ~O_NONBLOCK);

		close(fd3);
		close(fd2);
		close(fd1);
	}

	{
		struct sockaddr_in6 saddr;
		struct sockaddr_in6 caddr;
		socklen_t size = sizeof(saddr);
		int fd1 = EOF;
		int fd2 = EOF;

		fd1 = socket(PF_INET6, SOCK_DGRAM, 0);

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin6_family = AF_INET6;
		saddr.sin6_addr = in6addr_loopback;
		saddr.sin6_port = htons(0);
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Binding UDP ::1 0");
		set_enforce(1);
		show_prompt(sbuffer);
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)));
		set_enforce(0);
		show_prompt(sbuffer);
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)));
		getsockname(fd1, (struct sockaddr *) &saddr, &size);

		fd2 = socket(PF_INET6, SOCK_DGRAM, 0);

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Connecting UDP ::1 %d",
			 ntohs(saddr.sin6_port));
		set_enforce(1);
		show_prompt(cbuffer);
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)));
		set_enforce(0);
		show_prompt(cbuffer);
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)));
		getsockname(fd2, (struct sockaddr *) &caddr, &size);

		snprintf(cbuffer, sizeof(cbuffer) - 1,
			 "Client: Sending UDP ::1 %d",
			 ntohs(saddr.sin6_port));
		snprintf(sbuffer, sizeof(sbuffer) - 1,
			 "Server: Receiving UDP ::1 %d",
			 ntohs(caddr.sin6_port));

		set_enforce(1);
		show_prompt(cbuffer);
		show_result(sendto(fd2, "", 1, 0, (struct sockaddr *) &saddr,
				   sizeof(saddr)));
		set_enforce(0);
		show_prompt(cbuffer);
		show_result(sendto(fd2, "", 1, 0, (struct sockaddr *) &saddr,
				   sizeof(saddr)));
		set_enforce(1);
		show_prompt(sbuffer);
		show_result2(recvfrom(fd1, buf, sizeof(buf) - 1, MSG_DONTWAIT,
				      (struct sockaddr *) &caddr, &size));
		set_enforce(0);
		sendto(fd2, "", 1, 0, (struct sockaddr *) &saddr,
		       sizeof(saddr));
		set_enforce(0);
		show_prompt(sbuffer);
		show_result2(recvfrom(fd1, buf, sizeof(buf) - 1, MSG_DONTWAIT,
				      (struct sockaddr *) &caddr, &size));

		close(fd2);
		close(fd1);

	}

	/* Where can I find an example program that uses IPv6 raw socket? */

}

int main(int argc, char *argv[])
{
	ccs_test_init();
	if (access(proc_policy_domain_policy, F_OK)) {
		fprintf(stderr, "You can't use this program for this kernel."
			"\n");
		return 1;
	}
	stage_network_test();
	clear_status();
	if (0) { /* To suppress "defined but not used" warnings. */
		write_domain_policy("", 0);
		write_exception_policy("", 0);
	}
	return 0;
}
