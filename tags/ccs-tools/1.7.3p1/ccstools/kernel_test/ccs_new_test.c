#include "include.h"

static int result = 0;
static int err = 0;

static void show_result(const char *test, int should_success)
{
	err = errno;
	printf("%s : ", test);
	if (should_success) {
		if (err == 0)
			printf("OK (%d)\n", result);
		else
			printf("FAILED: %s\n", strerror(err));
	} else {
		if (err == 0)
			printf("BUG: Didn't fail (%d)\n", result);
		else if (err == EPERM)
			printf("OK: permission denied\n");
		else
			printf("FAILED: %s\n", strerror(err));
	}
}

static void test_read_etc_fstab(void)
{
	result = open("/etc/fstab", O_RDONLY);
}

static void test_write_dev_null(void)
{
	result = open("/dev/null", O_WRONLY);
}

static void cleanup_file_open(void)
{
	if (result != EOF)
		close(result);
}

static void test_mkdir_testdir(void)
{
	result = mkdir("/tmp/testdir", 0755);
}

static void cleanup_mkdir_testdir(void)
{
	rmdir("/tmp/testdir");
}

static void setup_mkdir_testdir(void)
{
	mkdir("/tmp/testdir", 0755);
}

static void test_rmdir_testdir(void)
{
	result = rmdir("/tmp/testdir");
}

static void setup_execute_bin_true(void)
{
	fprintf(domain_fp, "%s /bin/true\n", self_domain);
	fprintf(domain_fp, "use_profile 0\n");
	fprintf(domain_fp, "select pid=%u\n", pid);
}

static void cleanup_execute_bin_true(void)
{
	wait(NULL);
	fprintf(domain_fp, "delete %s /bin/true\n", self_domain);
	fprintf(domain_fp, "select pid=%u\n", pid);
}

static void test_execute_bin_true(void)
{
	char *argv[] = { "/bin/true", NULL };
	char *envp[] = { "HOME=/", NULL };
	int pipe_fd[2] = { EOF, EOF };
	int err = 0;
	pipe(pipe_fd);
	switch (fork()) {
	case 0:
		execve("/bin/true", argv, envp);
		err = errno;
		write(pipe_fd[1], &err, sizeof(err));
		_exit(0);
		break;
	case -1:
		err = -ENOMEM;
		break;
	}
	close(pipe_fd[1]);
	read(pipe_fd[0], &err, sizeof(err));
	close(pipe_fd[0]);
	result = err ? EOF : 0;
	errno = err;
}

static void test_chmod_dev_null(void)
{
	result = chmod("/dev/null", 0666);
}

static void test_chown_dev_null(void)
{
	result = chown("/dev/null", 0, -1);
}

static void test_chgrp_dev_null(void)
{
	result = chown("/dev/null", -1, 0);
}

static void test_ioctl_dev_null(void)
{
	int fd = open("/dev/null", O_RDWR);
	errno = 0;
	result = ioctl(fd, 0x5451, NULL);
	err = errno;
	close(fd);
	errno = err;
}

static void setup_chmod_group(void)
{
	write_exception_policy("path_group CHMOD_TARGET /dev/null", 0);
	write_exception_policy("number_group CHMOD_MODES 0666", 0);
}

static void cleanup_chmod_group(void)
{
	write_exception_policy("path_group CHMOD_TARGET /dev/null", 1);
	write_exception_policy("number_group CHMOD_MODES 0666", 1);
}

static void setup_chown_group(void)
{
	write_exception_policy("path_group CHOWN_TARGET /dev/\\*", 0);
	write_exception_policy("number_group CHOWN_IDS 0x0-0xFFFE", 0);
}

static void cleanup_chown_group(void)
{
	write_exception_policy("path_group CHOWN_TARGET /dev/\\*", 1);
	write_exception_policy("number_group CHOWN_IDS 0x0-0xFFFE", 1);
}

static void setup_ioctl_group(void)
{
	write_exception_policy("path_group IOCTL_TARGET /dev/\\*", 0);
	write_exception_policy("number_group IOCTL_NUMBERS 0x5450-0x5452", 0);
}

static void cleanup_ioctl_group(void)
{
	write_exception_policy("path_group IOCTL_TARGET /dev/\\*", 1);
	write_exception_policy("number_group IOCTL_NUMBERS 0x5450-0x5452", 1);
}

static void setup_open_group(void)
{
	write_exception_policy("path_group READABLE /etc/\\*", 0);
	write_exception_policy("number_group READABLE_IDS 0-0xFFF", 0);
}

static void cleanup_open_group(void)
{
	cleanup_file_open();
	write_exception_policy("path_group READABLE /etc/\\*", 1);
	write_exception_policy("number_group READABLE_IDS 0-0xFFF", 1);
}

static void test_file_open_0(void)
{
	result = open("/tmp/testfile0", O_RDONLY, 0600);
}

static void test_file_open_1(void)
{
	result = open("/tmp/testfile1", O_CREAT | O_RDONLY, 0600);
}

static void test_file_open_2(void)
{
	result = open("/tmp/testfile2", O_TRUNC | O_RDONLY, 0600);
}

static void test_file_open_3(void)
{
	result = open("/tmp/testfile3", O_TRUNC | O_CREAT | O_RDONLY, 0600);
}

static void test_file_open_4(void)
{
	result = open("/tmp/testfile4", O_APPEND | O_RDONLY, 0600);
}

static void test_file_open_5(void)
{
	result = open("/tmp/testfile5", O_APPEND | O_CREAT | O_RDONLY, 0600);
}

static void test_file_open_6(void)
{
	result = open("/tmp/testfile6", O_APPEND | O_TRUNC | O_RDONLY, 0600);
}

static void test_file_open_7(void)
{
	result = open("/tmp/testfile7",
		      O_APPEND | O_TRUNC | O_CREAT | O_RDONLY, 0600);
}

static void test_file_open_8(void)
{
	result = open("/tmp/testfile8", O_WRONLY, 0600);
}

static void test_file_open_9(void)
{
	result = open("/tmp/testfile9", O_CREAT | O_WRONLY, 0600);
}

static void test_file_open_10(void)
{
	result = open("/tmp/testfile10", O_TRUNC | O_WRONLY, 0600);
}

static void test_file_open_11(void)
{
	result = open("/tmp/testfile11", O_TRUNC | O_CREAT | O_WRONLY, 0600);
}

static void test_file_open_12(void)
{
	result = open("/tmp/testfile12", O_APPEND | O_WRONLY, 0600);
}

static void test_file_open_13(void)
{
	result = open("/tmp/testfile13", O_APPEND | O_CREAT | O_WRONLY, 0600);
}

static void test_file_open_14(void)
{
	result = open("/tmp/testfile14", O_APPEND | O_TRUNC | O_WRONLY, 0600);
}

static void test_file_open_15(void)
{
	result = open("/tmp/testfile15",
		      O_APPEND | O_TRUNC | O_CREAT | O_WRONLY, 0600);
}

static void test_file_open_16(void)
{
	result = open("/tmp/testfile16", O_RDWR, 0600);
}

static void test_file_open_17(void)
{
	result = open("/tmp/testfile17", O_CREAT | O_RDWR, 0600);
}

static void test_file_open_18(void)
{
	result = open("/tmp/testfile18", O_TRUNC | O_RDWR, 0600);
}

static void test_file_open_19(void)
{
	result = open("/tmp/testfile19", O_TRUNC | O_CREAT | O_RDWR, 0600);
}

static void test_file_open_20(void)
{
	result = open("/tmp/testfile20", O_APPEND | O_RDWR, 0600);
}

static void test_file_open_21(void)
{
	result = open("/tmp/testfile21", O_APPEND | O_CREAT | O_RDWR, 0600);
}

static void test_file_open_22(void)
{
	result = open("/tmp/testfile22", O_APPEND | O_TRUNC | O_RDWR, 0600);
}

static void test_file_open_23(void)
{
	result = open("/tmp/testfile23", O_APPEND | O_TRUNC | O_CREAT | O_RDWR,
		      0600);
}

static void setup_test_file(void)
{
	int i;
	char buffer[32];
	buffer[31] = '\0';
	for (i = 0; i < 24; i += 2) {
		snprintf(buffer, sizeof(buffer) - 1, "/tmp/testfile%u", i);
		close(open(buffer, O_WRONLY | O_CREAT, 0600));
	}
	write_exception_policy("deny_rewrite /tmp/testfile\\$", 0);
}

static void setup_test_file_truncate(void)
{
	setup_test_file();
	write_domain_policy("allow_truncate /tmp/testfile\\$", 0);
	set_profile(3, "file::truncate");
}

static void setup_all_test_file(void)
{
	int i;
	char buffer[32];
	buffer[31] = '\0';
	for (i = 0; i < 24; i++) {
		snprintf(buffer, sizeof(buffer) - 1, "/tmp/testfile%u", i);
		close(open(buffer, O_WRONLY | O_CREAT, 0600));
	}
	write_exception_policy("deny_rewrite /tmp/testfile\\$", 0);
}

static void setup_all_test_file_truncate(void)
{
	setup_all_test_file();
	write_domain_policy("allow_truncate /tmp/testfile\\$", 0);
	set_profile(3, "file::truncate");
}

static void cleanup_test_file(void)
{
	int i;
	char buffer[32];
	buffer[31] = '\0';
	for (i = 0; i < 24; i++) {
		snprintf(buffer, sizeof(buffer) - 1, "/tmp/testfile%u", i);
		unlink(buffer);
	}
	write_exception_policy("deny_rewrite /tmp/testfile\\$", 1);
	cleanup_file_open();
}

static void cleanup_test_file_truncate(void)
{
	cleanup_test_file();
	write_domain_policy("allow_truncate /tmp/testfile\\$", 1);
	set_profile(0, "file::truncate");
}

static void test_inet_tcp_create(void)
{
	int err;
	result = socket(AF_INET, SOCK_STREAM, 0);
	err = errno;
	close(result);
	errno = err;
}

static void test_inet_tcp_listen(void)
{
	int err;
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(0);
	bind(fd, (struct sockaddr *) &addr, sizeof(addr));
	errno = 0;
	result = listen(fd, 5);
	err = errno;
	close(fd);
	errno = err;
}

static void test_inet_tcp_connect(void)
{
	int err;
	int fd1 = socket(AF_INET, SOCK_STREAM, 0);
	int fd2 = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(0);
	bind(fd1, (struct sockaddr *) &addr, sizeof(addr));
	listen(fd1, 5);
	getsockname(fd1, (struct sockaddr *) &addr, &size);
	errno = 0;
	result = connect(fd2, (struct sockaddr *) &addr, sizeof(addr));
	err = errno;
	close(fd1);
	close(fd2);
	errno = err;
}

static void test_use_inet_udp(void)
{
	int err;
	result = socket(AF_INET, SOCK_DGRAM, 0);
	err = errno;
	close(result);
	errno = err;
}

static void test_use_inet_ip(void)
{
	int err;
	result = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	err = errno;
	close(result);
	errno = err;
}

static void test_use_route(void)
{
	int err;
	result = socket(AF_ROUTE, SOCK_RAW, 0);
	err = errno;
	close(result);
	errno = err;
}

static void test_use_packet(void)
{
	int err;
	result = socket(AF_PACKET, SOCK_RAW, 0);
	err = errno;
	close(result);
	errno = err;
}

static void test_SYS_MOUNT(void)
{
	int err;
	result = mount("none", "/tmp", "tmpfs", 0, NULL);
	err = errno;
	umount("/tmp");
	errno = err;
}

static void test_SYS_UMOUNT(void)
{
	mount("none", "/tmp", "tmpfs", 0, NULL);
	errno = 0;
	result = umount("/tmp");
}

static void test_SYS_REBOOT(void)
{
	FILE *fp = fopen("/proc/sys/kernel/ctrl-alt-del", "a+");
	unsigned int c;
	if (fp && fscanf(fp, "%u", &c) == 1) {
		errno = 0;
		result = reboot(LINUX_REBOOT_CMD_CAD_ON);
		err = errno;
		fprintf(fp, "%u\n", c);
	} else {
		errno = 0;
		result = reboot(0x0000C0DE); /* Use invalid value */
		err = errno;
	}
	if (fp)
		fclose(fp);
	errno = err;
}

static void test_SYS_CHROOT(void)
{
	result = chroot("/");
}

static void test_SYS_KILL(void)
{
	int err;
	signal(SIGINT, SIG_IGN);
	errno = 0;
	result = kill(pid, SIGINT);
	err = errno;
	signal(SIGINT, SIG_DFL);
	errno = err;
}

static void test_SYS_VHANGUP(void)
{
	int pty_fd = EOF;
	int status = 0;
	int pipe_fd[2] = { EOF, EOF };
	pipe(pipe_fd);
	switch (forkpty(&pty_fd, NULL, NULL, NULL)) {
	case 0:
		errno = 0;
		vhangup();
		/* Unreachable if vhangup() succeeded. */
		status = errno;
		write(pipe_fd[1], &status, sizeof(status));
		_exit(0);
	case -1:
		status = ENOMEM;
		break;
	default:
		close(pipe_fd[1]);
		read(pipe_fd[0], &status, sizeof(status));
		wait(NULL);
		close(pipe_fd[0]);
		close(pty_fd);
	}
	errno = status;
	result = status ? EOF : 0;
}

static void test_SYS_TIME(void)
{
	time_t now = time(NULL);
	errno = 0;
	result = stime(&now);
}

static void test_SYS_NICE(void)
{
	result = nice(0);
}

static void test_SYS_SETHOSTNAME(void)
{
	char buffer[4096];
	int len;
	memset(buffer, 0, sizeof(buffer));
	gethostname(buffer, sizeof(buffer) - 1);
	len = strlen(buffer);
	errno = 0;
	result = sethostname(buffer, len);
}

static void test_use_kernel_module(void)
{
	result = init_module("", NULL);
}

static void test_create_fifo(void)
{
	int err;
	char tmp[32];
	strcpy(tmp, "/tmp/XXXXXX");
	close(mkstemp(tmp));
	unlink(tmp);
	errno = 0;
	result = mknod(tmp, S_IFIFO, 0);
	err = errno;
	unlink(tmp);
	errno = err;
}

static void test_create_block_dev(void)
{
	int err;
	char tmp[32];
	strcpy(tmp, "/tmp/XXXXXX");
	close(mkstemp(tmp));
	unlink(tmp);
	errno = 0;
	result = mknod(tmp, S_IFBLK, MKDEV(1, 0));
	err = errno;
	unlink(tmp);
	errno = err;
}

static void test_create_char_dev(void)
{
	int err;
	char tmp[32];
	strcpy(tmp, "/tmp/XXXXXX");
	close(mkstemp(tmp));
	unlink(tmp);
	errno = 0;
	result = mknod(tmp, S_IFCHR, MKDEV(1, 3));
	err = errno;
	unlink(tmp);
	errno = err;
}

static void test_create_unix_socket(void)
{
	int err;
	struct sockaddr_un addr;
	char tmp[32];
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(tmp, "/tmp/XXXXXX");
	strncpy(addr.sun_path, tmp, sizeof(addr.sun_path) - 1);
	errno = 0;
	result = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
	err = errno;
	unlink(tmp);
	close(fd);
	errno = err;
}

static void test_SYS_LINK(void)
{
	int err;
	char tmp1[32];
	char tmp2[32];
	strcpy(tmp1, "/tmp/link_source_XXXXXX");
	close(mkstemp(tmp1));
	strcpy(tmp2, "/tmp/link_target_XXXXXX");
	errno = 0;
	result = link(tmp1, tmp2);
	err = errno;
	unlink(tmp2);
	unlink(tmp1);
	errno = err;
}

static void test_SYS_SYMLINK(void)
{
	int err;
	char tmp1[32];
	char tmp2[32];
	strcpy(tmp1, "/tmp/symlink_target_XXXXXX");
	close(mkstemp(tmp1));
	strcpy(tmp2, "/tmp/symlink_source_XXXXXX");
	errno = 0;
	result = symlink(tmp1, tmp2);
	err = errno;
	unlink(tmp2);
	unlink(tmp1);
	errno = err;
}

static void test_SYS_RENAME(void)
{
	int err;
	char tmp1[32];
	char tmp2[32];
	strcpy(tmp1, "/tmp/rename_old_XXXXXX");
	close(mkstemp(tmp1));
	strcpy(tmp2, "/tmp/rename_new_XXXXXX");
	errno = 0;
	result = rename(tmp1, tmp2);
	err = errno;
	unlink(tmp2);
	unlink(tmp1);
	errno = err;
}

static void test_SYS_UNLINK(void)
{
	char tmp[32];
	strcpy(tmp, "/tmp/unlinkXXXXXX");
	close(mkstemp(tmp));
	errno = 0;
	result = unlink(tmp);
}

static void test_SYS_CHMOD(void)
{
	result = chmod("/dev/null", 0222);
	if (!result)
		chmod("/dev/null", 0666);
}

static void test_SYS_CHOWN(void)
{
	result = chown("/dev/null", 1, 1);
	if (!result)
		chown("/dev/null", 0, 0);
}

static void test_SYS_IOCTL(void)
{
	struct ifreq ifreq;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	int err;
	memset(&ifreq, 0, sizeof(ifreq));
	snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name) - 1, "lo");
	errno = 0;
	result = ioctl(fd, 35123, &ifreq);
	err = errno;
	close(fd);
	errno = err;
}

static void test_SYS_KEXEC_LOAD(void)
{
#ifdef __NR_sys_kexec_load
	if (is_kernel26) {
		result = sys_kexec_load(0, 0, NULL, 0);
		return;
	}
#endif
	errno = ENOSYS;
	result = EOF;
}

static int child(void *arg)
{
	errno = 0;
	pivot_root("/proc", "/proc/ccs");
	return errno;
}

static void test_SYS_PIVOT_ROOT(void)
{
	int error;
	char *stack = malloc(8192);
	pid_t pid = clone(child, stack + (8192 / 2), CLONE_NEWNS, NULL);
	while (waitpid(pid, &error, __WALL) == EOF && errno == EINTR)
		error += 0; /* Dummy. */
	errno = WIFEXITED(error) ? WEXITSTATUS(error) : -1;
	result = errno ? EOF : 0;
}

static void test_SYS_PTRACE(void)
{
	int status = 0;
	int pipe_fd[2] = { EOF, EOF };
	pipe(pipe_fd);
	switch (fork()) {
	case 0:
		errno = 0;
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		status = errno;
		write(pipe_fd[1], &status, sizeof(status));
		_exit(0);
	case -1:
		status = ENOMEM;
		break;
	default:
		close(pipe_fd[1]);
		read(pipe_fd[0], &status, sizeof(status));
		wait(NULL);
		close(pipe_fd[0]);
	}
	errno = status;
	result = status ? EOF : 0;
}

static void test_conceal_mount(void)
{
	int err = 0;
	while (umount("/tmp") == 0)
		err += 0;
	mount("none", "/tmp", "tmpfs", 0, NULL);
	errno = 0;
	result = mount("none", "/tmp", "tmpfs", 0, NULL);
	err = errno;
	while (umount("/tmp") == 0)
		err += 0;
	errno = err;
}

static struct test_struct {
	void (*do_setup) (void);
	void (*do_test) (void);
	void (*do_cleanup) (void);
	const char *name;
	const char *policy;
} tests[] = {
	{ NULL, test_read_etc_fstab, cleanup_file_open, "file::open",
	  "allow_read /etc/fstab" },
	{ NULL, test_read_etc_fstab, cleanup_file_open, "file::open",
	  "allow_read /etc/fstab if task.uid=0" },
	{ NULL, test_read_etc_fstab, cleanup_file_open, "file::open",
	  "allow_read /etc/fstab if path1.uid=0 path1.parent.uid=0" },
	{ setup_open_group, test_read_etc_fstab, cleanup_open_group,
	  "file::open", "allow_read @READABLE if path1.uid=@READABLE_IDS "
	  "path1.parent.uid=0" },
	{ NULL, test_write_dev_null, cleanup_file_open, "file::open",
	  "allow_write /dev/null" },
	{ NULL, test_write_dev_null, cleanup_file_open, "file::open",
	  "allow_write /dev/null if task.uid=0" },
	{ NULL, test_write_dev_null, cleanup_file_open, "file::open",
	  "allow_write /dev/null if path1.type=char path1.dev_major=1 "
	  "path1.dev_minor=3 path1.perm=0666" },
	{ cleanup_mkdir_testdir, test_mkdir_testdir, cleanup_mkdir_testdir,
	  "file::mkdir", "allow_mkdir /tmp/testdir/ 0755" },
	{ cleanup_mkdir_testdir, test_mkdir_testdir, cleanup_mkdir_testdir,
	  "file::mkdir", "allow_mkdir /tmp/testdir/ 0755 "
	  "if path1.parent.uid=0 path1.parent.perm=01777" },
	{ cleanup_mkdir_testdir, test_mkdir_testdir, cleanup_mkdir_testdir,
	  "file::mkdir", "allow_mkdir /tmp/testdir/ 0755 "
	  "if task.uid=path1.parent.uid" },
	{ setup_mkdir_testdir, test_rmdir_testdir, cleanup_mkdir_testdir,
	  "file::rmdir", "allow_rmdir /tmp/testdir/" },
	{ setup_mkdir_testdir, test_rmdir_testdir, cleanup_mkdir_testdir,
	  "file::rmdir", "allow_rmdir /tmp/testdir/ if path1.parent.uid=0 "
	  "path1.parent.perm=01777" },
	{ setup_mkdir_testdir, test_rmdir_testdir, cleanup_mkdir_testdir,
	  "file::rmdir", "allow_rmdir /tmp/testdir/ if task.uid=0-100 "
	  "task.gid=0x0-0xFF path1.uid=0" },
	{ setup_execute_bin_true, test_execute_bin_true,
	  cleanup_execute_bin_true, "file::execute",
	  "allow_execute /bin/true" },
	{ setup_execute_bin_true, test_execute_bin_true,
	  cleanup_execute_bin_true, "file::execute", "allow_execute /bin/true "
	  "if exec.argc=1 exec.argv[0]=\"/bin/true\"" },
	{ setup_execute_bin_true, test_execute_bin_true,
	  cleanup_execute_bin_true, "file::execute", "allow_execute /bin/true "
	  "if exec.envc=1 exec.envp[\"HOME\"]=\"/\" exec.envp[\"PATH\"]=NULL"
	},
	{ NULL, test_chmod_dev_null, NULL, "file::chmod",
	  "allow_chmod /dev/null 0666 if path1.perm=00-07777 path1.type=char"
	},
	{ NULL, test_chown_dev_null, NULL, "file::chown",
	  "allow_chown /dev/null 0 if task.gid=path1.gid path1.type!=block" },
	{ NULL, test_chgrp_dev_null, NULL, "file::chgrp",
	  "allow_chgrp /dev/null 0 if task.uid=path1.parent.uid" },
	{ NULL, test_ioctl_dev_null, NULL, "file::ioctl",
	  "allow_ioctl /dev/null 0x5451 if 0=0-1000" },
	{ setup_chmod_group, test_chmod_dev_null, cleanup_chmod_group,
	  "file::chmod", "allow_chmod @CHMOD_TARGET @CHMOD_MODES" },
	{ setup_chown_group, test_chown_dev_null, cleanup_chown_group,
	  "file::chown", "allow_chown @CHOWN_TARGET @CHOWN_IDS" },
	{ setup_chown_group, test_chgrp_dev_null, cleanup_chown_group,
	  "file::chgrp", "allow_chgrp @CHOWN_TARGET @CHOWN_IDS" },
	{ setup_ioctl_group, test_ioctl_dev_null, cleanup_ioctl_group,
	  "file::ioctl", "allow_ioctl @IOCTL_TARGET @IOCTL_NUMBERS" },
	{ setup_test_file, test_file_open_0, cleanup_test_file, "file::open",
	  "allow_read /tmp/testfile0 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_1, cleanup_test_file, "file::open",
	  "allow_read /tmp/testfile1 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_1, cleanup_test_file, "file::create",
	  "allow_create /tmp/testfile1 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_2, cleanup_test_file, "file::open",
	  "allow_read /tmp/testfile2 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_2, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile2 "
	  "if task.uid=path1.uid" },
	{ setup_test_file_truncate, test_file_open_2,
	  cleanup_test_file_truncate, "file::rewrite",
	  "allow_rewrite /tmp/testfile2 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_3, cleanup_test_file,
	  "file::open", "allow_read /tmp/testfile3 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_3, cleanup_test_file,
	  "file::create", "allow_create /tmp/testfile3 0600 "
	  "if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_4, cleanup_test_file, "file::open",
	  "allow_read /tmp/testfile4 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_5, cleanup_test_file, "file::open",
	  "allow_read /tmp/testfile5 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_5, cleanup_test_file, "file::create",
	  "allow_create /tmp/testfile5 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_6, cleanup_test_file, "file::open",
	  "allow_read /tmp/testfile6 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_6, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile6 "
	  "if task.uid=path1.uid" },
	{ setup_test_file_truncate, test_file_open_6,
	  cleanup_test_file_truncate, "file::rewrite",
	  "allow_rewrite /tmp/testfile6 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_7, cleanup_test_file, "file::open",
	  "allow_read /tmp/testfile7 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_7, cleanup_test_file, "file::create",
	  "allow_create /tmp/testfile7 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_8, cleanup_test_file, "file::open",
	  "allow_write /tmp/testfile8 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_8, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile8 if task.uid=path1.uid"
	},
	{ setup_test_file, test_file_open_9, cleanup_test_file, "file::open",
	  "allow_write /tmp/testfile9 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_9, cleanup_test_file, "file::create",
	  "allow_create /tmp/testfile9 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_9, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile9 if task.uid=path1.uid"
	},
	{ setup_test_file, test_file_open_10, cleanup_test_file, "file::open",
	  "allow_write /tmp/testfile10 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_10, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile10 "
	  "if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_10, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile10 "
	  "if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_11, cleanup_test_file, "file::open",
	  "allow_write /tmp/testfile11 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_11, cleanup_test_file,
	  "file::create", "allow_create /tmp/testfile11 0600 "
	  "if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_11, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile11 "
	  "if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_12, cleanup_test_file, "file::open",
	  "allow_write /tmp/testfile12 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_13, cleanup_test_file, "file::open",
	  "allow_write /tmp/testfile13 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_13, cleanup_test_file,
	  "file::create", "allow_create /tmp/testfile13 0600 "
	  "if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_14, cleanup_test_file, "file::open",
	  "allow_write /tmp/testfile14 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_14, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile14 "
	  "if task.uid=path1.uid" },
	{ setup_test_file_truncate, test_file_open_14,
	  cleanup_test_file_truncate, "file::rewrite",
	  "allow_rewrite /tmp/testfile14 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_15, cleanup_test_file, "file::open",
	  "allow_write /tmp/testfile15 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_15, cleanup_test_file,
	  "file::create", "allow_create /tmp/testfile15 0600 "
	  "if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_16, cleanup_test_file, "file::open",
	  "allow_read/write /tmp/testfile16 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_16, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile16 "
	  "if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_17, cleanup_test_file, "file::open",
	  "allow_read/write /tmp/testfile17 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_17, cleanup_test_file,
	  "file::create", "allow_create /tmp/testfile17 0600 "
	  "if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_17, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile17 "
	  "if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_18, cleanup_test_file, "file::open",
	  "allow_read/write /tmp/testfile18 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_18, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile18 "
	  "if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_18, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile18 "
	  "if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_19, cleanup_test_file, "file::open",
	  "allow_read/write /tmp/testfile19 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_19, cleanup_test_file,
	  "file::create", "allow_create /tmp/testfile19 0600 "
	  "if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_19, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile19 "
	  "if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_20, cleanup_test_file, "file::open",
	  "allow_read/write /tmp/testfile20 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_21, cleanup_test_file, "file::open",
	  "allow_read/write /tmp/testfile21 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_21, cleanup_test_file,
	  "file::create", "allow_create /tmp/testfile21 0600 "
	  "if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_22, cleanup_test_file, "file::open",
	  "allow_read/write /tmp/testfile22 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_22, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile22 "
	  "if task.uid=path1.uid" },
	{ setup_test_file_truncate, test_file_open_22,
	  cleanup_test_file_truncate, "file::rewrite",
	  "allow_rewrite /tmp/testfile22 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_23, cleanup_test_file, "file::open",
	  "allow_read/write /tmp/testfile23 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_23, cleanup_test_file,
	  "file::create", "allow_create /tmp/testfile23 0600 "
	  "if task.uid=path1.parent.uid" },
	{ setup_all_test_file, test_file_open_0, cleanup_test_file,
	  "file::open", "allow_read /tmp/testfile0 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_2, cleanup_test_file,
	  "file::open", "allow_read /tmp/testfile2 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_2, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile2 "
	  "if task.uid=path1.gid" },
	{ setup_all_test_file_truncate, test_file_open_2,
	  cleanup_test_file_truncate, "file::rewrite",
	  "allow_rewrite /tmp/testfile2 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_4, cleanup_test_file,
	  "file::open", "allow_read /tmp/testfile4 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_6, cleanup_test_file,
	  "file::open", "allow_read /tmp/testfile6 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_6, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile6 "
	  "if task.uid=path1.gid" },
	{ setup_all_test_file_truncate, test_file_open_6,
	  cleanup_test_file_truncate, "file::rewrite",
	  "allow_rewrite /tmp/testfile6 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_8, cleanup_test_file,
	  "file::open", "allow_write /tmp/testfile8 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_8, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile8 if task.uid=path1.gid"
	},
	{ setup_all_test_file, test_file_open_10, cleanup_test_file,
	  "file::open", "allow_write /tmp/testfile10 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_10, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile10 "
	  "if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_10, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile10 "
	  "if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_12, cleanup_test_file,
	  "file::open", "allow_write /tmp/testfile12 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_14, cleanup_test_file,
	  "file::open", "allow_write /tmp/testfile14 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_14, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile14 "
	  "if task.uid=path1.gid" },
	{ setup_all_test_file_truncate, test_file_open_14,
	  cleanup_test_file_truncate, "file::rewrite",
	  "allow_rewrite /tmp/testfile14 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_16, cleanup_test_file,
	  "file::open", "allow_read/write /tmp/testfile16 "
	  "if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_16, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile16 "
	  "if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_18, cleanup_test_file,
	  "file::open", "allow_read/write /tmp/testfile18 "
	  "if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_18, cleanup_test_file,
	  "file::truncate", "allow_truncate /tmp/testfile18 "
	  "if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_18, cleanup_test_file,
	  "file::rewrite", "allow_rewrite /tmp/testfile18 "
	  "if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_20, cleanup_test_file,
	  "file::open",
	  "allow_read/write /tmp/testfile20 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_22, cleanup_test_file,
	  "file::open",
	  "allow_read/write /tmp/testfile22 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_22, cleanup_test_file,
	  "file::truncate",
	  "allow_truncate /tmp/testfile22 if task.uid=path1.gid" },
	{ setup_all_test_file_truncate, test_file_open_22,
	  cleanup_test_file_truncate, "file::rewrite",
	  "allow_rewrite /tmp/testfile22 if task.uid=path1.gid" },
	{ NULL, test_inet_tcp_create, NULL,    "capability::inet_tcp_create",
	  "allow_capability inet_tcp_create" },
	{ NULL, test_inet_tcp_listen, NULL,    "capability::inet_tcp_listen",
	  "allow_capability inet_tcp_listen" },
	{ NULL, test_inet_tcp_connect, NULL,   "capability::inet_tcp_connect",
	  "allow_capability inet_tcp_connect" },
	{ NULL, test_use_inet_udp, NULL,       "capability::use_inet_udp",
	  "allow_capability use_inet_udp" },
	{ NULL, test_use_inet_ip, NULL,        "capability::use_inet_ip",
	  "allow_capability use_inet_ip" },
	{ NULL, test_use_route, NULL,          "capability::use_route",
	  "allow_capability use_route" },
	{ NULL, test_use_packet, NULL,         "capability::use_packet",
	  "allow_capability use_packet" },
	{ NULL, test_SYS_MOUNT, NULL,          "capability::SYS_MOUNT",
	  "allow_capability SYS_MOUNT" },
	{ NULL, test_SYS_UMOUNT, NULL,         "capability::SYS_UMOUNT",
	  "allow_capability SYS_UMOUNT" },
	{ NULL, test_SYS_REBOOT, NULL,         "capability::SYS_REBOOT",
	  "allow_capability SYS_REBOOT" },
	{ NULL, test_SYS_CHROOT, NULL,         "capability::SYS_CHROOT",
	  "allow_capability SYS_CHROOT" },
	{ NULL, test_SYS_KILL, NULL,           "capability::SYS_KILL",
	  "allow_capability SYS_KILL" },
	{ NULL, test_SYS_VHANGUP, NULL,        "capability::SYS_VHANGUP",
	  "allow_capability SYS_VHANGUP" },
	{ NULL, test_SYS_TIME, NULL,           "capability::SYS_TIME",
	  "allow_capability SYS_TIME" },
	{ NULL, test_SYS_NICE, NULL,           "capability::SYS_NICE",
	  "allow_capability SYS_NICE" },
	{ NULL, test_SYS_SETHOSTNAME, NULL,    "capability::SYS_SETHOSTNAME",
	  "allow_capability SYS_SETHOSTNAME" },
	{ NULL, test_use_kernel_module, NULL,  "capability::use_kernel_module",
	  "allow_capability use_kernel_module" },
	{ NULL, test_create_fifo, NULL,        "capability::create_fifo",
	  "allow_capability create_fifo" },
	{ NULL, test_create_block_dev, NULL,   "capability::create_block_dev",
	  "allow_capability create_block_dev" },
	{ NULL, test_create_char_dev, NULL,    "capability::create_char_dev",
	  "allow_capability create_char_dev" },
	{ NULL, test_create_unix_socket, NULL,
	  "capability::create_unix_socket",
	  "allow_capability create_unix_socket" },
	{ NULL, test_SYS_LINK, NULL,           "capability::SYS_LINK",
	  "allow_capability SYS_LINK" },
	{ NULL, test_SYS_SYMLINK, NULL,        "capability::SYS_SYMLINK",
	  "allow_capability SYS_SYMLINK" },
	{ NULL, test_SYS_RENAME, NULL,         "capability::SYS_RENAME",
	  "allow_capability SYS_RENAME" },
	{ NULL, test_SYS_UNLINK, NULL,         "capability::SYS_UNLINK",
	  "allow_capability SYS_UNLINK" },
	{ NULL, test_SYS_CHMOD, NULL,          "capability::SYS_CHMOD",
	  "allow_capability SYS_CHMOD" },
	{ NULL, test_SYS_CHOWN, NULL,          "capability::SYS_CHOWN",
	  "allow_capability SYS_CHOWN" },
	{ NULL, test_SYS_IOCTL, NULL,          "capability::SYS_IOCTL",
	  "allow_capability SYS_IOCTL" },
	{ NULL, test_SYS_KEXEC_LOAD, NULL,     "capability::SYS_KEXEC_LOAD",
	  "allow_capability SYS_KEXEC_LOAD" },
	{ NULL, test_SYS_PIVOT_ROOT, NULL,     "capability::SYS_PIVOT_ROOT",
	  "allow_capability SYS_PIVOT_ROOT" },
	{ NULL, test_SYS_PTRACE, NULL,         "capability::SYS_PTRACE",
	  "allow_capability SYS_PTRACE" },
	{ NULL, test_conceal_mount, NULL,      "capability::conceal_mount",
	  "allow_capability conceal_mount" },
	{ NULL }
};

int main(int argc, char *argv[])
{
	int i;
	ccs_test_init();
	for (i = 0; tests[i].do_test; i++) {
		int trial;
		for (trial = 0; trial < 2; trial++) {
			int should_fail;
			for (should_fail = 0; should_fail < 2; should_fail++) {
				if (tests[i].do_setup)
					tests[i].do_setup();
				if (!should_fail)
					write_domain_policy(tests[i].policy, 0);
				set_profile(3, tests[i].name);
				tests[i].do_test();
				show_result(tests[i].policy, !should_fail);
				set_profile(0, tests[i].name);
				if (tests[i].do_cleanup)
					tests[i].do_cleanup();
				if (!should_fail)
					write_domain_policy(tests[i].policy, 1);
			}
		}
	}
	for (i = 0; tests[i].do_test; i++) {
		int mode;
		for (mode = 0; mode < 4; mode++) {
			if (tests[i].do_setup)
				tests[i].do_setup();
			set_profile(mode, tests[i].name);
			tests[i].do_test();
			show_result(tests[i].name, 1);
			set_profile(0, tests[i].name);
			if (tests[i].do_cleanup)
				tests[i].do_cleanup();
		}
	}
	fprintf(domain_fp, "delete %s\n", self_domain);
	return 0;
}
