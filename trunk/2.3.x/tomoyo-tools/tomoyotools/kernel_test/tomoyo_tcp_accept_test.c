/*
 * tomoyo_tcp_accept_test.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 */
#include "include.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

static void show_prompt(const char *str)
{
	printf("Testing %s: (must fail) ", str);
	fflush(stdout);
	errno = 0;
}

static void show_result(int result)
{
	if (result == EOF) {
		if (errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("FAILED: %s\n", strerror(errno));
	} else {
		printf("BUG!(%d)\n", result);
	}
}

static void stage_network_test(void)
{
	int i;
	for (i = 0; i < 17; i++) {
		struct sockaddr_in addr = {};
		socklen_t size = sizeof(addr);
		struct msghdr msg = {};
		char c = 0;
		struct iovec iov = { &c, 1 };
		unsigned int value = 0;
		int retry = 0;
		int fd1 = socket(PF_INET, SOCK_STREAM, 0);
		int fd2 = socket(PF_INET, SOCK_STREAM, 0);
		int fd3 = EOF;
		int fd4 = EOF;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = htons(0);
		msg.msg_name = &addr;
		msg.msg_namelen = sizeof(addr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		errno = 0;
		if (bind(fd1, (struct sockaddr *) &addr, sizeof(addr)) ||
		    listen(fd1, 5) ||
		    getsockname(fd1, (struct sockaddr *) &addr, &size) ||
		    connect(fd2, (struct sockaddr *) &addr, sizeof(addr))) {
			printf("BUG!(%d)\n", errno);
			break;
		}
		fd3 = accept(fd1, (struct sockaddr *) &addr, &size);
		if (fd3 == EOF) {
			printf("BUG!(%d)\n", errno);
			break;
		}
		set_profile(3, "network::inet_tcp_accept");
retry:
		switch (i) {
		case 0:
			show_prompt("getsockname() after accept()");
			show_result(getsockname(fd3, (struct sockaddr *)
						&addr, &size));
			break;
		case 1:
			show_prompt("getpeername() after accept()");
			show_result(getpeername(fd3, (struct sockaddr *)
						&addr, &size));
			break;
		case 2:
			show_prompt("getsockopt() after accept()");
			show_result(getsockopt(fd3, IPPROTO_TCP, TCP_CORK,
					       &addr, &size));
			break;
		case 3:
			show_prompt("setsockopt() after accept()");
			show_result(setsockopt(fd3,  IPPROTO_TCP, TCP_CORK,
					       &addr, size));
			break;
		case 4:
			show_prompt("bind() after accept()");
			show_result(bind(fd3, (struct sockaddr *) &addr,
					 sizeof(addr)));
			break;
		case 5:
			show_prompt("listen() after accept()");
			show_result(listen(fd3, 5));
			break;
		case 6:
			show_prompt("accept() after accept()");
			fd4 = accept(fd3, (struct sockaddr *) &addr, &size);
			show_result(fd4);
			break;
		case 7:
			show_prompt("connect() after accept()");
			show_result(connect(fd3, (struct sockaddr *) &addr,
					    sizeof(addr)));
			break;
		case 8:
			show_prompt("ioctl() after accept()");
			show_result(ioctl(fd3, FIONREAD, &value));
			break;
		case 9:
			show_prompt("read() after accept()");
			show_result(read(fd3, &c, 1));
			break;
		case 10:
			show_prompt("write() after accept()");
			show_result(write(fd3, &c, 1));
			break;
		case 11:
			show_prompt("recv() after accept()");
			show_result(recv(fd3, &c, 1, 0));
			break;
		case 12:
			show_prompt("send() after accept()");
			show_result(send(fd3, &c, 1, 0));
			break;
		case 13:
			show_prompt("recvfrom() after accept()");
			show_result(recvfrom(fd3, &c, 1, 0, (struct sockaddr *)
					     &addr, &size));
			break;
		case 14:
			show_prompt("sendto() after accept()");
			show_result(sendto(fd3, &c, 1, 0, (struct sockaddr *)
					   &addr, size));
			break;
		case 15:
			show_prompt("recvmsg() after accept()");
			show_result(recvmsg(fd3, &msg, 0));
			break;
		case 16:
			show_prompt("sendmsg() after accept()");
			show_result(sendmsg(fd3, &msg, 0));
			break;
		}
		if (retry < 5) {
			retry++;
			goto retry;
		}
		set_profile(2, "network::inet_tcp_accept");
		close(fd4);
		close(fd3);
		close(fd2);
		close(fd1);
	}
}

int main(int argc, char *argv[])
{
	tomoyo_test_init();
	if (access(proc_policy_domain_policy, F_OK)) {
		fprintf(stderr, "You can't use this program for this kernel."
			"\n");
		return 1;
	}
	fprintf(profile_fp, "255-PREFERENCE::enforcing={ verbose=yes }\n");
	stage_network_test();
	clear_status();
	return 0;
}
