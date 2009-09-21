/*
 * tomoyo_capability_test.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0   2009/09/03
 *
 */
#include "include.h"

static int child(void *arg)
{
	errno = 0;
	pivot_root("/sys/kernel/security", proc_policy_dir);
	return errno;
}

static int should_success = 0;
static int is_enforce = 0;

static void show_prompt(const char *str)
{
	if (should_success)
		printf("Testing %34s: (%s) ", str, "should success");
	else
		printf("Testing %34s: (%s) ", str,
		       is_enforce ? "must fail" : "should success");
	errno = 0;
}

static void show_result(int result)
{
	if (should_success) {
		if (result != EOF)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
	} else if (is_enforce) {
		if (result == EOF) {
			if (errno == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("FAILED: %s\n", strerror(errno));
		} else {
			printf("BUG!\n");
		}
	} else {
		if (result != EOF)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
	}
}

static void set_capability(const char *capability)
{
	char buffer[128];
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "capability::%s", capability);
	set_profile(is_enforce ? 3 : 2, buffer);
	if (should_success)
		fprintf(domain_fp, "allow_capability %s\n", capability);
}

static void unset_capability(const char *capability)
{
	char buffer[128];
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "capability::%s", capability);
	set_profile(0, buffer);
	if (should_success)
		fprintf(domain_fp, "delete allow_capability %s\n", capability);
}

static void stage_capability_test(void)
{
	int fd;
	char tmp1[128];
	char tmp2[128];
	memset(tmp1, 0, sizeof(tmp1));
	memset(tmp2, 0, sizeof(tmp2));
	set_capability("inet_tcp_create");
	show_prompt("inet_tcp_create");
	fd = socket(AF_INET, SOCK_STREAM, 0);
	show_result(fd);
	if (fd != EOF)
		close(fd);
	unset_capability("inet_tcp_create");

	{
		struct sockaddr_in addr;
		int fd1;
		int fd2;
		socklen_t size = sizeof(addr);
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = htons(0);

		fd1 = socket(AF_INET, SOCK_STREAM, 0);
		bind(fd1, (struct sockaddr *) &addr, sizeof(addr));
		getsockname(fd1, (struct sockaddr *) &addr, &size);
		set_capability("inet_tcp_listen");
		show_prompt("inet_tcp_listen");
		show_result(listen(fd1, 5));
		unset_capability("inet_tcp_listen");

		fd2 = socket(AF_INET, SOCK_STREAM, 0);
		set_capability("inet_tcp_connect");
		show_prompt("inet_tcp_connect");
		show_result(connect(fd2, (struct sockaddr *) &addr,
				   sizeof(addr)));
		unset_capability("inet_tcp_connect");

		if (fd2 != EOF)
			close(fd2);
		if (fd1 != EOF)
			close(fd1);
	}

	set_capability("use_inet_udp");
	show_prompt("use_inet_udp");
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	show_result(fd);
	if (fd != EOF)
		close(fd);
	unset_capability("use_inet_udp");

	set_capability("use_inet_ip");
	show_prompt("use_inet_ip");
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	show_result(fd);
	if (fd != EOF)
		close(fd);
	unset_capability("use_inet_ip");

	set_capability("use_route");
	show_prompt("use_route");
	fd = socket(AF_ROUTE, SOCK_RAW, 0);
	show_result(fd);
	if (fd != EOF)
		close(fd);
	unset_capability("use_route");

	set_capability("use_packet");
	show_prompt("use_packet");
	fd = socket(AF_PACKET, SOCK_RAW, 0);
	show_result(fd);
	if (fd != EOF)
		close(fd);
	unset_capability("use_packet");

	set_capability("create_fifo");
	show_prompt("create_fifo");
	strcpy(tmp1, "/tmp/XXXXXX");
	close(mkstemp(tmp1));
	unlink(tmp1);
	show_result(mknod(tmp1, S_IFIFO, 0));
	unlink(tmp1);
	unset_capability("create_fifo");

	set_capability("create_block_dev");
	show_prompt("create_block_dev");
	strcpy(tmp1, "/tmp/XXXXXX");
	close(mkstemp(tmp1));
	unlink(tmp1);
	show_result(mknod(tmp1, S_IFBLK, MKDEV(1, 0)));
	unlink(tmp1);
	unset_capability("create_block_dev");

	set_capability("create_char_dev");
	show_prompt("create_char_dev");
	strcpy(tmp1, "/tmp/XXXXXX");
	close(mkstemp(tmp1));
	unlink(tmp1);
	show_result(mknod(tmp1, S_IFCHR, MKDEV(1, 3)));
	unlink(tmp1);
	unset_capability("create_char_dev");

	set_capability("create_unix_socket");
	show_prompt("create_unix_socket(mknod)");
	strcpy(tmp1, "/tmp/XXXXXX");
	close(mkstemp(tmp1));
	unlink(tmp1);
	show_result(mknod(tmp1, S_IFSOCK, 0));
	unlink(tmp1);
	{
		struct sockaddr_un addr;
		int fd;
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strcpy(tmp1, "/tmp/XXXXXX");
		strncpy(addr.sun_path, tmp1, sizeof(addr.sun_path) - 1);
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		show_prompt("create_unix_socket(bind)");
		show_result(bind(fd, (struct sockaddr *) &addr, sizeof(addr)));
		unlink(tmp1);
		if (fd != EOF)
			close(fd);
	}
	unset_capability("create_unix_socket");

	set_capability("SYS_MOUNT");
	show_prompt("SYS_MOUNT");
	show_result(mount("/", "/", "tmpfs", 0, NULL));
	unset_capability("SYS_MOUNT");

	set_capability("SYS_UMOUNT");
	show_prompt("SYS_UMOUNT");
	mount("/tmp", "/tmp", "tmpfs", 0, NULL);
	show_result(umount("/tmp"));
	unset_capability("SYS_UMOUNT");

	set_capability("SYS_CHROOT");
	show_prompt("SYS_CHROOT");
	show_result(chroot("/"));
	unset_capability("SYS_CHROOT");

	set_capability("SYS_PIVOT_ROOT");
	show_prompt("SYS_PIVOT_ROOT");

	{
		int error;
		char *stack = malloc(8192);
		const pid_t pid = clone(child, stack + (8192 / 2), CLONE_NEWNS,
					NULL);
		while (waitpid(pid, &error, __WALL) == EOF && errno == EINTR)
			error += 0; /* Dummy. */
		free(stack);
		errno = WIFEXITED(error) ? WEXITSTATUS(error) : -1;
		show_result(errno ? EOF : 0);
		unset_capability("SYS_PIVOT_ROOT");
	}

	set_capability("SYS_LINK");
	show_prompt("SYS_LINK");
	strcpy(tmp1, "/tmp/link_source_XXXXXX");
	close(mkstemp(tmp1));
	strcpy(tmp2, "/tmp/link_target_XXXXXX");
	show_result(link(tmp1, tmp2));
	unlink(tmp2);
	unlink(tmp1);
	unset_capability("SYS_LINK");

	set_capability("SYS_SYMLINK");
	show_prompt("SYS_SYMLINK");
	strcpy(tmp1, "/tmp/symlink_target_XXXXXX");
	close(mkstemp(tmp1));
	strcpy(tmp2, "/tmp/symlink_source_XXXXXX");
	show_result(symlink(tmp1, tmp2));
	unlink(tmp2);
	unlink(tmp1);
	unset_capability("SYS_SYMLINK");

	set_capability("SYS_RENAME");
	show_prompt("SYS_RENAME");
	strcpy(tmp1, "/tmp/rename_old_XXXXXX");
	close(mkstemp(tmp1));
	strcpy(tmp2, "/tmp/rename_new_XXXXXX");
	show_result(rename(tmp1, tmp2));
	unlink(tmp2);
	unlink(tmp1);
	unset_capability("SYS_RENAME");

	set_capability("SYS_UNLINK");
	show_prompt("SYS_UNLINK");
	strcpy(tmp1, "/tmp/unlinkXXXXXX");
	close(mkstemp(tmp1));
	show_result(unlink(tmp1));
	unset_capability("SYS_UNLINK");
	unlink(tmp1);

	set_capability("SYS_CHMOD");
	show_prompt("SYS_CHMOD");
	show_result(chmod("/dev/null", 0));
	chmod("/dev/null", 0666);
	unset_capability("SYS_CHMOD");

	set_capability("SYS_CHOWN");
	show_prompt("SYS_CHOWN");
	show_result(chown("/dev/null", 1, 1));
	chown("/dev/null", 0, 0);
	unset_capability("SYS_CHOWN");

	set_capability("SYS_IOCTL");
	if (0) {
		int fd = open("/dev/null", O_RDONLY);
		show_prompt("SYS_IOCTL");
		show_result(ioctl(fd, 0 /* Use invalid value so that nothing
					  happen. */));
		close(fd);
	}
	{
		struct ifreq ifreq;
		int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
		memset(&ifreq, 0, sizeof(ifreq));
		snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name) - 1, "lo");
		show_prompt("SYS_IOCTL");
		show_result(ioctl(fd, 35123, &ifreq));
		close(fd);
	}
	unset_capability("SYS_IOCTL");
}

int main(int argc, char *argv[])
{
	tomoyo_test_init();
	printf("***** Testing capability hooks in enforce mode. *****\n");
	is_enforce = 1;
	stage_capability_test();
	printf("\n\n");
	printf("***** Testing capability hooks in permissive mode. *****\n");
	is_enforce = 0;
	stage_capability_test();
	printf("\n\n");
	should_success = 1;
	printf("***** Testing capability hooks in enforce mode with policy. "
	       "*****\n");
	is_enforce = 1;
	fprintf(domain_fp, "select pid=%u\n", getpid());
	stage_capability_test();
	printf("\n\n");
	clear_status();
	return 0;
}
