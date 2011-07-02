/*
 * ccs_new_network_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2+   2011/07/02
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

static const char *policy = "";

static int write_policy(void)
{
	FILE *fp = fopen(proc_policy_domain_policy, "r");
	char buffer[8192];
	char *cp;
	int domain_found = 0;
	int policy_found = 0;
	memset(buffer, 0, sizeof(buffer));
	fprintf(domain_fp, "%s\n", policy);
	if (!fp) {
		printf("%s : BUG: policy read failed\n", policy);
		return 0;
	}
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!strncmp(buffer, "<kernel>", 8))
			domain_found = !strcmp(self_domain, buffer);
		if (domain_found) {
			if (!strcmp(buffer, policy)) {
				policy_found = 1;
				break;
			}
		}
	}
	fclose(fp);
	if (!policy_found) {
		printf("%s : BUG: policy write failed\n", policy);
		return 0;
	}
	errno = 0;
	return 1;
}

static void delete_policy(void)
{
	fprintf(domain_fp, "delete %s\n", policy);
}

static void show_result(int result, char should_success)
{
	printf("%s : ", policy);
	if (should_success) {
		if (result != EOF)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
	} else {
		if (result == EOF) {
			if (errno == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("FAILED: %s\n", strerror(errno));
		} else {
			printf("BUG\n");
		}
	}
}

static void show_result2(int result)
{
	printf("%s : ", policy);
	if (result == EOF) {
		if (errno == EAGAIN)
			printf("OK: Not ready.\n");
		else
			printf("FAILED: %s\n", strerror(errno));
	} else {
		char c;
		if (recv(result, &c, 1, MSG_DONTWAIT) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG\n");
	}
}

static void stage_network_test(void)
{
	int i;

	{ /* IPv4 stream */
		char buffer[1024];
		struct sockaddr_in saddr;
		struct sockaddr_in caddr;
		socklen_t size = sizeof(saddr);
		int fd1 = socket(PF_INET, SOCK_STREAM, 0);
		int fd2 = socket(PF_INET, SOCK_STREAM, 0);
		int fd3 = EOF;
		memset(buffer, 0, sizeof(buffer));
		policy = buffer;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		saddr.sin_port = htons(0);

		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream bind 127.0.0.1 0-1");
		errno = 0;
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)), 0);
		if (write_policy()) {
			show_result(bind(fd1, (struct sockaddr *) &saddr,
					 sizeof(saddr)), 1);
			delete_policy();
		}
		getsockname(fd1, (struct sockaddr *) &saddr, &size);

		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream listen 127.0.0.0-127.255.255.255 "
			 "%u-%u", ntohs(saddr.sin_port) - 1,
			 ntohs(saddr.sin_port) + 1);
		errno = 0;
		show_result(listen(fd1, 5), 0);
		if (write_policy()) {
			show_result(listen(fd1, 5), 1);
			delete_policy();
		}

		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream connect 127.0.0.1 %u-%u",
			 ntohs(saddr.sin_port) - 1, ntohs(saddr.sin_port) + 1);
		errno = 0;
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)), 0);
		if (write_policy()) {
			show_result(connect(fd2, (struct sockaddr *) &saddr,
					    sizeof(saddr)), 1);
			delete_policy();
		}
		getsockname(fd2, (struct sockaddr *) &caddr, &size);

		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream accept 127.0.0.1 %u-%u",
			 ntohs(caddr.sin_port) - 1, ntohs(caddr.sin_port) + 1);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) | O_NONBLOCK);
		errno = 0;
		fd3 = accept(fd1, (struct sockaddr *) &caddr, &size);
		show_result2(fd3);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) & ~O_NONBLOCK);
		if (fd3 != EOF)
			close(fd3);

		close(fd2);
		fd2 = socket(PF_INET, SOCK_STREAM, 0);
		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream connect "
			 "127.0.0.0-127.255.255.255 %u-%u",
			 ntohs(saddr.sin_port) - 1, ntohs(saddr.sin_port) + 1);
		if (write_policy()) {
			connect(fd2, (struct sockaddr *) &saddr,
				sizeof(saddr));
			delete_policy();
		}
		getsockname(fd2, (struct sockaddr *) &caddr, &size);
		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream accept "
			 "127.0.0.0-127.255.255.255 %u-%u",
			 ntohs(caddr.sin_port) - 1, ntohs(caddr.sin_port) + 1);
		if (write_policy()) {
			fd3 = accept(fd1, (struct sockaddr *) &caddr, &size);
			show_result(fd3, 1);
			delete_policy();
			if (fd3 != EOF)
				close(fd3);
		}

		if (fd2 != EOF)
			close(fd2);
		if (fd1 != EOF)
			close(fd1);
	}

	{ /* IPv4 address_group */
		char buffer[1024];
		int fd1 = socket(PF_INET, SOCK_STREAM, 0);
		int fd2 = socket(PF_INET, SOCK_STREAM, 0);
		struct sockaddr_in saddr;
		memset(buffer, 0, sizeof(buffer));
		policy = buffer;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		saddr.sin_port = htons(10001);
		fprintf(exception_fp, "address_group TESTADDRESS 127.0.0.1\n");
		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream bind @TESTADDRESS 10001");
		errno = 0;
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)), 0);
		if (write_policy()) {
			show_result(bind(fd1, (struct sockaddr *) &saddr,
					 sizeof(saddr)), 1);
			delete_policy();
		}
		fprintf(exception_fp,
			"delete address_group TESTADDRESS 127.0.0.1\n");
		saddr.sin_port = htons(20002);
		fprintf(exception_fp, "address_group TESTADDRESS "
			"127.0.0.0-127.0.0.2\n");
		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream bind @TESTADDRESS 20002");
		errno = 0;
		show_result(bind(fd2, (struct sockaddr *) &saddr,
				 sizeof(saddr)), 0);
		if (write_policy()) {
			show_result(bind(fd2, (struct sockaddr *) &saddr,
					 sizeof(saddr)), 1);
			delete_policy();
		}
		fprintf(exception_fp, "delete address_group TESTADDRESS "
			"127.0.0.0-127.0.0.2\n");
		if (fd1 != EOF)
			close(fd1);
		if (fd2 != EOF)
			close(fd2);
	}

	i = socket(PF_INET6, SOCK_STREAM, 0);
	if (i == EOF)
		return;
	close(i);

	{ /* IPv6 stream */
		char buffer[1024];
		struct sockaddr_in6 saddr, caddr;
		socklen_t size = sizeof(saddr);
		int fd1 = socket(PF_INET6, SOCK_STREAM, 0);
		int fd2 = socket(PF_INET6, SOCK_STREAM, 0);
		int fd3 = EOF;
		memset(buffer, 0, sizeof(buffer));
		policy = buffer;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin6_family = AF_INET6;
		saddr.sin6_addr = in6addr_loopback;
		saddr.sin6_port = htons(0);

		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream bind 0:0:0:0:0:0:0:1 0-1");
		errno = 0;
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)), 0);
		if (write_policy()) {
			show_result(bind(fd1, (struct sockaddr *) &saddr,
					 sizeof(saddr)), 1);
			delete_policy();
		}
		getsockname(fd1, (struct sockaddr *) &saddr, &size);

		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream listen "
			 "0:0:0:0:0:0:0:0-0:0:0:0:0:0:0:ff %u-%u",
			 ntohs(saddr.sin6_port) - 1,
			 ntohs(saddr.sin6_port) + 1);
		errno = 0;
		show_result(listen(fd1, 5), 0);
		if (write_policy()) {
			show_result(listen(fd1, 5), 1);
			delete_policy();
		}

		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream connect 0:0:0:0:0:0:0:1 %u-%u",
			 ntohs(saddr.sin6_port) - 1,
			 ntohs(saddr.sin6_port) + 1);
		errno = 0;
		show_result(connect(fd2, (struct sockaddr *) &saddr,
				    sizeof(saddr)), 0);
		if (write_policy()) {
			show_result(connect(fd2, (struct sockaddr *) &saddr,
					    sizeof(saddr)), 1);
			delete_policy();
		}
		getsockname(fd2, (struct sockaddr *) &caddr, &size);

		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream accept 0:0:0:0:0:0:0:1 %u-%u",
			 ntohs(caddr.sin6_port) - 1,
			 ntohs(caddr.sin6_port) + 1);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) | O_NONBLOCK);
		errno = 0;
		fd3 = accept(fd1, (struct sockaddr *) &caddr, &size);
		show_result2(fd3);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) & ~O_NONBLOCK);
		if (fd3 != EOF)
			close(fd3);

		close(fd2);
		fd2 = socket(PF_INET6, SOCK_STREAM, 0);
		snprintf(buffer, sizeof(buffer) - 1, "network inet stream "
			 "connect 0:0:0:0:0:0:0:0-0:0:0:0:0:0:0:ff %u-%u",
			 ntohs(saddr.sin6_port) - 1,
			 ntohs(saddr.sin6_port) + 1);
		if (write_policy()) {
			connect(fd2, (struct sockaddr *) &saddr,
				sizeof(saddr));
			delete_policy();
		}
		getsockname(fd2, (struct sockaddr *) &caddr, &size);
		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream accept "
			 "0:0:0:0:0:0:0:0-0:0:0:0:0:0:0:ff %u-%u",
			 ntohs(caddr.sin6_port) - 1,
			 ntohs(caddr.sin6_port) + 1);
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) | O_NONBLOCK);
		if (write_policy()) {
			fd3 = accept(fd1, (struct sockaddr *) &caddr, &size);
			show_result(fd3, 1);
			delete_policy();
			if (fd3 != EOF)
				close(fd3);
		}
		fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL, 0) & ~O_NONBLOCK);

		if (fd2 != EOF)
			close(fd2);
		if (fd1 != EOF)
			close(fd1);
	}

	{ /* IPv6 address_group */
		char buffer[1024];
		int fd1 = socket(PF_INET6, SOCK_STREAM, 0);
		int fd2 = socket(PF_INET6, SOCK_STREAM, 0);
		struct sockaddr_in6 saddr;
		memset(buffer, 0, sizeof(buffer));
		policy = buffer;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin6_family = AF_INET6;
		saddr.sin6_addr = in6addr_loopback;
		saddr.sin6_port = htons(30003);
		fprintf(exception_fp, "address_group TESTADDRESS "
			"0:0:0:0:0:0:0:1\n");
		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream bind @TESTADDRESS 30003");
		errno = 0;
		show_result(bind(fd1, (struct sockaddr *) &saddr,
				 sizeof(saddr)), 0);
		if (write_policy()) {
			show_result(bind(fd1, (struct sockaddr *) &saddr,
					 sizeof(saddr)), 1);
			delete_policy();
		}
		fprintf(exception_fp, "delete address_group "
			"TESTADDRESS 0:0:0:0:0:0:0:1\n");
		saddr.sin6_port = htons(40004);
		fprintf(exception_fp, "address_group TESTADDRESS "
			"0:0:0:0:0:0:0:0-0:0:0:0:0:0:0:2\n");
		snprintf(buffer, sizeof(buffer) - 1,
			 "network inet stream bind @TESTADDRESS 40004");
		errno = 0;
		show_result(bind(fd2, (struct sockaddr *) &saddr,
				 sizeof(saddr)), 0);
		if (write_policy()) {
			show_result(bind(fd2, (struct sockaddr *) &saddr,
					 sizeof(saddr)), 1);
			delete_policy();
		}
		fprintf(exception_fp, "delete address_group TESTADDRESS "
			"0:0:0:0:0:0:0:0-0:0:0:0:0:0:0:2\n");
		if (fd1 != EOF)
			close(fd1);
		if (fd2 != EOF)
			close(fd2);
	}

}

static void do_unix_bind_test(int i, int protocol, const char *proto_str,
			      int should_success)
{
	struct {
		unsigned short int family;
		char address[512];
	} buf = {
		AF_UNIX,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	};
	int fd = socket(PF_UNIX, protocol, 0);
	int ret;
	int err;
	if (fd == EOF && errno == ESOCKTNOSUPPORT)
		return;
	printf("Testing network unix %s bind with %d bytes (%s): ", proto_str,
	       i, should_success ? "should success" : "must fail");
	if (i > 2) {
		buf.address[i - 2] = '\0';
		unlink(buf.address);
		buf.address[i - 2] = 'a';
	}
	errno = 0;
	ret = bind(fd, (struct sockaddr *) &buf, i);
	err = errno;
	close(fd);
	if (i > 2) {
		buf.address[i - 2] = '\0';
		unlink(buf.address);
		buf.address[i - 2] = 'a';
	}
	if (should_success) {
		if (ret == EOF && err != EINVAL)
			printf("Failed. %s\n", strerror(err));
		else
			printf("OK\n");
	} else {
		if (ret != EOF || (err != EPERM && err != EINVAL))
			printf("BUG! %s\n", strerror(err));
		else
			printf("OK: Permission denied.\n");
	}
}

static void do_unix_recv_test(int named, int should_success)
{
	struct {
		unsigned short int family;
		char address[512];
	} buf = {
		AF_UNIX
	};
	int fd1 = socket(PF_UNIX, SOCK_DGRAM, 0);
	int fd2 = socket(PF_UNIX, SOCK_DGRAM, 0);
	socklen_t size = sizeof(buf);
	int ret;
	int err;
	printf("Testing network unix dgram recv (%s): ",
	       should_success ? "should success" : "must fail");
	errno = 0;
	ret = bind(fd1, (struct sockaddr *) &buf.family, sizeof(buf.family));
	err = errno;
	if (ret) {
		printf("Failed to bind(). %s\n", strerror(err));
		goto out;
	}
	if (named) {
		buf.address[0] = '\0';
		snprintf(buf.address + 1, sizeof(buf.address) - 2,
			 "named_unix_domain_socket");
		ret = bind(fd2, (struct sockaddr *) &buf, 27);
		err = errno;
		if (ret) {
			printf("Failed to bind(). %s\n", strerror(err));
			goto out;
		}
	}
	ret = getsockname(fd1, (struct sockaddr *) &buf, &size);
	err = errno;
	if (ret) {
		printf("Failed to getsockname(). %s\n", strerror(err));
		goto out;
	}
	ret = connect(fd2, (struct sockaddr *) &buf, size);
	err = errno;
	if (ret) {
		printf("Failed to connect(). %s\n", strerror(err));
		goto out;
	}
	ret = write(fd2, &buf, sizeof(buf));
	err = errno;
	if (ret != sizeof(buf)) {
		printf("Failed to send(). %s\n", strerror(err));
		goto out;
	}
	ret = recv(fd1, (char *) &buf, sizeof(buf), 0);
	err = errno;
	if (should_success) {
		if (ret == EOF)
			printf("Failed to recv(). %s\n", strerror(err));
		else
			printf("OK\n");
	} else {
		if (ret != EOF || err != EAGAIN)
			printf("BUG! %s\n", strerror(err));
		else
			printf("OK: Permission denied.\n");
	}
out:
	close(fd2);
	close(fd1);
}

static void update_policy(int i, const char *proto_str, int is_delete)
{
	if (is_delete)
		fprintf(domain_fp, "delete ");
	fprintf(domain_fp, "network unix %s bind ", proto_str);
	if (i > 2) {
		char buf[512] = { };
		memset(buf, 'a', i - 2);
		fprintf(domain_fp, "%s\n", buf);
	} else {
		fprintf(domain_fp, "%s\n", "anonymous");
	}
}

static void stage_unix_network_test(void)
{
	int j;
	int i;
	const char *profile_str;
	const char *proto_str;
	int proto;
	for (j = 0; j < 3; j++) {
		switch (j) {
		case 0:
			profile_str = "network::unix_stream_bind";
			proto_str = "stream";
			proto = SOCK_STREAM;
			break;
		case 1:
			profile_str = "network::unix_dgram_bind";
			proto_str = "dgram";
			proto = SOCK_DGRAM;
			break;
		default:
			profile_str = "network::unix_seqpacket_bind";
			proto_str = "seqpacket";
			proto = SOCK_SEQPACKET;
			break;
		}
		for (i = 0; i <= 130; i++) {
			if (i >= 5 && i <= 104)
				continue;
			set_profile(0, profile_str);
			do_unix_bind_test(i, proto, proto_str, 1);
			set_profile(3, profile_str);
			do_unix_bind_test(i, proto, proto_str, 0);
			set_profile(2, profile_str);
			do_unix_bind_test(i, proto, proto_str, 1);
			set_profile(1, profile_str);
			do_unix_bind_test(i, proto, proto_str, 1);
			set_profile(3, profile_str);
			do_unix_bind_test(i, proto, proto_str, 1);
			update_policy(i, proto_str, 1);
			do_unix_bind_test(i, proto, proto_str, 0);
			update_policy(i, proto_str, 0);
			do_unix_bind_test(i, proto, proto_str, 1);
			update_policy(i, proto_str, 1);
		}
		set_profile(0, profile_str);
	}
	for (j = 0; j < 2; j++) {
		profile_str = "network::unix_dgram_recv";
		set_profile(0, profile_str);
		do_unix_recv_test(j, 1);
		set_profile(3, profile_str);
		do_unix_recv_test(j, 0);
		set_profile(2, profile_str);
		do_unix_recv_test(j, 1);
		set_profile(1, profile_str);
		do_unix_recv_test(j, 1);
		set_profile(3, profile_str);
		do_unix_recv_test(j, 1);
		fprintf(domain_fp, "delete ");
		fprintf(domain_fp, "network unix dgram recv %s\n",
			j ? "\\000named_unix_domain_socket" : "anonymous");
		do_unix_recv_test(j, 0);
		fprintf(domain_fp, "network unix dgram recv %s\n",
			j ? "\\000named_unix_domain_socket" : "anonymous");
		do_unix_recv_test(j, 1);
		fprintf(domain_fp, "delete ");
		fprintf(domain_fp, "network unix dgram recv %s\n",
			j ? "\\000named_unix_domain_socket" : "anonymous");
	}
	set_profile(0, profile_str);
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	set_profile(3, "network::inet_stream_bind");
	set_profile(3, "network::inet_stream_listen");
	set_profile(3, "network::inet_stream_connect");
	set_profile(3, "network::inet_stream_accept");
	set_profile(3, "network::inet_dgram_bind");
	set_profile(3, "network::inet_dgram_send");
	set_profile(3, "network::inet_dgram_recv");
	set_profile(3, "network::inet_raw_bind");
	set_profile(3, "network::inet_raw_send");
	set_profile(3, "network::inet_raw_recv");
	fprintf(profile_fp, "255-PREFERENCE={ max_reject_log=1024 }\n");
	stage_network_test();
	stage_unix_network_test();
	clear_status();
	if (0) { /* To suppress "defined but not used" warnings. */
		write_domain_policy("", 0);
		write_exception_policy("", 0);
	}
	return 0;
}
