#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/kdev_t.h>
#include <sys/mount.h>
#include <sys/ioctl.h>

#include <asm/unistd.h>
static inline int pivot_root(const char *new_root, const char *put_old)
{
	return syscall(__NR_pivot_root, new_root, put_old);
}

static _Bool debug = 0;

static char *read_log(const char *expected_result, const char *expected_action)
{
	static int fd = EOF;
	static char buffer[16384];
	if (fd == EOF)
		fd = open("/proc/ccs/audit", O_RDONLY);
	memset(buffer, 0, sizeof(buffer));
	while (buffer[0] = '\0', read(fd, buffer, sizeof(buffer) - 1) > 0) {
		char *cp1;
		char *cp2;
		if (debug)
			printf("Got '%s'\n", buffer);
		cp1 = strstr(buffer, " / ");
		if (buffer[0] != '#' || !cp1 || !strchr(buffer, '\n')) {
			fprintf(stderr,
				"Expected complete audit log, got '%s'\n",
				buffer);
			return NULL;
		}
		*cp1 = '\0';
		if (!strstr(buffer, expected_result))
			continue;
		cp1 += 3;
		cp2 = strchr(cp1, ' ');
		if (!cp2) {
			fprintf(stderr,
				"Expected complete audit log, got '%s'\n",
				cp1);
			return NULL;
		}
		*cp2++ = '\0';
		if (strcmp(expected_action, cp1))
			continue;
		return cp2;
	}
	fprintf(stderr, "Expected '%s' '%s', found none\n",
		expected_result, expected_action);
	return NULL;
}

static void create_dummy(const char *path)
{
	close(open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600));
}

static void test_execute(void)
{
	char *args[3] = { "null", "--help", NULL };
	char *envs[3] = { "PATH=/", "HOME=/", NULL };
	create_dummy("/tmp/null");
	chmod("/tmp/null", 0700);
	execve("/tmp/null", args, envs);
}

static void test_read(void)
{
	close(open("/dev/null", O_RDONLY));
}

static void test_write(void)
{
	close(open("/dev/null", O_WRONLY));
}

static void test_append(void)
{
	close(open("/dev/null", O_WRONLY | O_APPEND));
}

static void test_create(void)
{
	unlink("/tmp/null");
	create_dummy("/tmp/null");
}

static void test_unlink(void)
{
	create_dummy("/tmp/null");
	unlink("/tmp/null");
}

static void test_getattr(void)
{
	struct stat buf;
	create_dummy("/tmp/null");
	stat("/tmp/null", &buf);
}

static void test_mkdir(void)
{
	rmdir("/tmp/nulldir");
	mkdir("/tmp/nulldir", 0755);
}

static void test_rmdir(void)
{
	mkdir("/tmp/nulldir", 0755);
	rmdir("/tmp/nulldir");
}

static void test_mkfifo(void)
{
	unlink("/tmp/null");
	mknod("/tmp/null", S_IFIFO, 0);
}

static void test_mksock(void)
{
	unlink("/tmp/null");
	mknod("/tmp/null", S_IFSOCK, 0);
}

static void test_truncate(void)
{
	create_dummy("/tmp/null");
	truncate("/tmp/null", 0);
}

static void test_symlink(void)
{
	unlink("/tmp/null");
	symlink("symlink'starget", "/tmp/null");
}

static void test_mkblock(void)
{
	unlink("/tmp/null");
	mknod("/tmp/null", S_IFBLK, MKDEV(1, 0));
}

static void test_mkchar(void)
{
	unlink("/tmp/null");
	mknod("/tmp/null", S_IFCHR, MKDEV(1, 3));
}

static void test_link(void)
{
	create_dummy("/tmp/link");
	unlink("/tmp/newlink");
	link("/tmp/link", "/tmp/newlink");
}

static void test_rename(void)
{
	link("/dev/null", "/dev/null0");
	rename("/dev/null0", "/dev/null1");
	unlink("/dev/null1");
}

static void test_chmod(void)
{
	chmod("/dev/null", 0666);
}

static void test_chown(void)
{
	chown("/dev/null", 0, -1);
}

static void test_chgrp(void)
{
	chown("/dev/null", -1, 0);
}

static void test_ioctl(void)
{
	int fd = open("/dev/null", 3);
	ioctl(fd, 0);
	close(fd);
}

static void test_chroot(void)
{
	chroot("/");
}

static void test_mount(void)
{
	mount(NULL, "/tmp", "tmpfs", 0, NULL);
	umount("/tmp");
}

static void test_unmount(void)
{
	umount("/");
}

static void test_pivot_root(void)
{
	pivot_root("/", "/");
}

static _Bool check_policy(const char *policy, const char *decision,
			  const char *condition)
{
	static char buffer[16384];
	FILE *fp = fopen("/proc/ccs/policy", "r");
	_Bool found = 0;
	if (!fp) {
		fprintf(stderr, "Can't read /proc/ccs/policy interface.\n");
		return 0;
	}
	memset(buffer, 0, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		if (strstr(buffer, decision) && strstr(buffer, condition)) {
			found = 1;
			break;
		}
	}
	fclose(fp);
	if (found) {
		printf("%s    %s%s\n", policy, decision, condition);
		return 1;
	}
	fprintf(stderr, "Can't find %s    %s%s\n",
		policy, decision, condition);
	return 0;
}

int main(int argc, char *argv[])
{
	unsigned int i;
	char buffer[16384];
	struct {
		const char *action;
		void (*func) (void);
	} testcases[] = {
		{ "execute", test_execute },
		{ "read", test_read },
		{ "write", test_write },
		{ "append", test_append },
		{ "create", test_create },
		{ "unlink", test_unlink },
		{ "getattr", test_getattr },
		{ "mkdir", test_mkdir },
		{ "rmdir", test_rmdir },
		{ "mkfifo", test_mkfifo },
		{ "mksock", test_mksock },
		{ "truncate", test_truncate },
		{ "symlink", test_symlink },
		{ "mkblock", test_mkblock },
		{ "mkchar", test_mkchar },
		{ "link", test_link },
		{ "rename", test_rename },
		{ "chmod", test_chmod },
		{ "chown", test_chown },
		{ "chgrp", test_chgrp },
		{ "ioctl", test_ioctl },
		{ "chroot", test_chroot },
		{ "mount", test_mount },
		{ "unmount", test_unmount },
		{ "pivot_root", test_pivot_root },
		/*
		  acl inet_stream_bind
		  acl inet_stream_listen
		  acl inet_stream_connect
		  acl inet_stream_accept
		  acl inet_dgram_bind
		  acl inet_dgram_send
		  acl inet_dgram_recv
		  acl inet_raw_bind
		  acl inet_raw_send
		  acl inet_raw_recv
		  acl unix_stream_bind
		  acl unix_stream_listen
		  # acl unix_stream_connect
		  acl unix_stream_accept
		  acl unix_dgram_bind
		  acl unix_dgram_send
		  acl unix_dgram_recv
		  acl unix_seqpacket_bind
		  acl unix_seqpacket_listen
		  acl unix_seqpacket_connect
		  acl unix_seqpacket_accept
		  # acl environ
		  acl ptrace
		  acl signal
		  acl modify_policy
		  # acl use_netlink_socket
		  acl use_packet_socket
		  acl use_reboot
		  acl use_vhangup
		  acl set_time
		  acl set_priority
		  acl set_hostname
		  acl use_kernel_module
		  acl use_new_kernel
		  # acl auto_domain_transition
		  acl manual_domain_transition
		*/
		{ NULL, NULL },
	};
	int fd_out = open("/proc/ccs/policy", O_WRONLY);
	char *cp1;
	char *cp2;
	memset(buffer, 0, sizeof(buffer));
	if (fd_out == EOF) {
		fprintf(stderr, "Can't write /proc/ccs/policy interface.\n");
		goto out;
	}
	cp1 = "POLICY_VERSION=20100903\n"
		"quota memory audit 16777216\n"
		"quota memory query 1048576\n"
		"quota audit[1] allowed=1024 denied=1024 unmatched=1024\n";
	i = strlen(cp1);
	if (write(fd_out, cp1, i) != i) {
		fprintf(stderr, "Can't write /proc/ccs/policy interface.\n");
		goto out;
	}
	for (i = 0; testcases[i].action; i++) {
		int fd_in = open("/proc/ccs/policy", O_RDONLY);
		if (fd_in == EOF) {
			fprintf(stderr,
				"Can't read /proc/ccs/policy interface.\n");
			goto out;
		}
		snprintf(buffer, sizeof(buffer) - 1, "0 acl %s task.pid=%u\n"
			 "    audit 1\n", testcases[i].action, getpid());
		write(fd_out, buffer, strlen(buffer));
		testcases[i].func();
		cp2 = read_log("result=unmatched", testcases[i].action);
		if (!cp2)
			goto out;
		cp1 = "0 deny ";
		write(fd_out, cp1, strlen(cp1));
		write(fd_out, cp2, strlen(cp2));
		if (!check_policy(buffer, cp1, cp2))
			goto out;
		testcases[i].func();
		cp2 = read_log("result=denied", testcases[i].action);
		if (!cp2)
			goto out;
		snprintf(buffer, sizeof(buffer) - 1,
			 "delete 0 acl %s task.pid=%u\n",
			 testcases[i].action, getpid());
		write(fd_out, buffer, strlen(buffer));
	}
	return 0;
out:
	return 1;
}
