/*
 * ccs_new_file_test.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.1   2009/11/11
 *
 */
#include "include.h"

static const char *policy = "";

#if 0
static int write_policy(void)
{
	FILE *fp;
	char buffer[8192];
	int domain_found = 0;
	int policy_found = 0;
	memset(buffer, 0, sizeof(buffer));
	set_profile(0, "file::open");
	fp = fopen(proc_policy_domain_policy, "r");
	set_profile(3, "file::open");
	fprintf(domain_fp, "%s\n", policy);
	if (!fp) {
		printf("%s : BUG: policy read failed\n", policy);
		return 0;
	}
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!strncmp(buffer, "<kernel>", 8))
			domain_found = !strcmp(self_domain, buffer);
		if (!domain_found)
			continue;
		/* printf("<%s>\n", buffer); */
		if (!strcmp(buffer, policy)) {
			policy_found = 1;
			break;
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
#endif

static void show_result(int result, char should_success)
{
	int err = errno;
	printf("%s : ", policy);
	if (should_success) {
		if (result != EOF)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(err));
	} else {
		if (result == EOF) {
			if (err == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("FAILED: %s\n", strerror(err));
		} else {
			printf("BUG: didn't fail.\n");
		}
	}
}

static void create2(const char *pathname)
{
	set_profile(0, "file::create");
	set_profile(0, "file::open");
	close(creat(pathname, 0600));
	set_profile(3, "file::create");
	set_profile(3, "file::open");
	errno = 0;
}

static void mkdir2(const char *pathname)
{
	set_profile(0, "file::mkdir");
	mkdir(pathname, 0600);
	set_profile(3, "file::mkdir");
	errno = 0;
}

static void unlink2(const char *pathname)
{
	set_profile(0, "file::unlink");
	unlink(pathname);
	set_profile(3, "file::unlink");
	errno = 0;
}

static void rmdir2(const char *pathname)
{
	set_profile(0, "file::rmdir");
	rmdir(pathname);
	set_profile(3, "file::rmdir");
	errno = 0;
}

static void mkfifo2(const char *pathname)
{
	set_profile(0, "file::mkfifo");
	mkfifo(pathname, 0600);
	set_profile(3, "file::mkfifo");
	errno = 0;
}

static void stage_file_test(void)
{
	static int name[] = { CTL_NET, NET_IPV4, NET_IPV4_LOCAL_PORT_RANGE };
	int buffer[2] = { 32768, 61000 };
	size_t size = sizeof(buffer);
	int pipe_fd[2] = { EOF, EOF };
	int err = 0;
	int fd;
	char pbuffer[1024];
	struct stat sbuf;
	struct sockaddr_un addr;
	struct ifreq ifreq;
	char *filename = "";
	set_profile(3, "file::execute");
	set_profile(3, "file::open");
	set_profile(3, "file::create");
	set_profile(3, "file::unlink");
	set_profile(3, "file::mkdir");
	set_profile(3, "file::rmdir");
	set_profile(3, "file::mkfifo");
	set_profile(3, "file::mksock");
	set_profile(3, "file::truncate");
	set_profile(3, "file::symlink");
	set_profile(3, "file::rewrite");
	set_profile(3, "file::mkblock");
	set_profile(3, "file::mkchar");
	set_profile(3, "file::link");
	set_profile(3, "file::rename");
	set_profile(3, "file::chmod");
	set_profile(3, "file::chown");
	set_profile(3, "file::chgrp");
	set_profile(3, "file::ioctl");
	set_profile(3, "file::chroot");
	set_profile(3, "file::mount");
	set_profile(3, "file::umount");
	set_profile(3, "file::pivot_root");

	policy = "allow_read /proc/sys/net/ipv4/ip_local_port_range "
		"if task.uid=0 task.gid=0";
	write_domain_policy(policy, 0);
	show_result(sysctl(name, 3, buffer, &size, 0, 0), 1);
	write_domain_policy(policy, 1);
	show_result(sysctl(name, 3, buffer, &size, 0, 0), 0);

	policy = "allow_write /proc/sys/net/ipv4/ip_local_port_range "
		"if task.euid=0 0=0 1-100=10-1000";
	write_domain_policy(policy, 0);
	show_result(sysctl(name, 3, 0, 0, buffer, size), 1);
	write_domain_policy(policy, 1);
	show_result(sysctl(name, 3, 0, 0, buffer, size), 0);

	policy = "allow_read/write /proc/sys/net/ipv4/ip_local_port_range "
		"if 1!=10-100";
	write_domain_policy(policy, 0);
	show_result(sysctl(name, 3, buffer, &size, buffer, size), 1);
	write_domain_policy(policy, 1);
	show_result(sysctl(name, 3, buffer, &size, buffer, size), 0);

	policy = "allow_read /bin/true "
		"if path1.uid=0 path1.parent.uid=0 10=10-100";
	write_domain_policy(policy, 0);
	show_result(uselib("/bin/true"), 1);
	write_domain_policy(policy, 1);
	show_result(uselib("/bin/true"), 0);

	policy = "allow_execute /bin/true if task.uid!=10 path1.parent.uid=0";
	write_domain_policy(policy, 0);
	fflush(stdout);
	fflush(stderr);
	pipe(pipe_fd);
	if (fork() == 0) {
		execl("/bin/true", "/bin/true", NULL);
		err = errno;
		write(pipe_fd[1], &err, sizeof(err));
		_exit(0);
	}
	close(pipe_fd[1]);
	read(pipe_fd[0], &err, sizeof(err));
	close(pipe_fd[0]);
	wait(NULL);
	errno = err;
	show_result(err ? EOF : 0, 1);
	write_domain_policy(policy, 1);
	fflush(stdout);
	fflush(stderr);
	pipe(pipe_fd);
	if (fork() == 0) {
		execl("/bin/true", "/bin/true", NULL);
		err = errno;
		write(pipe_fd[1], &err, sizeof(err));
		_exit(0);
	}
	close(pipe_fd[1]);
	read(pipe_fd[0], &err, sizeof(err));
	close(pipe_fd[0]);
	wait(NULL);
	errno = err;
	show_result(err ? EOF : 0, 0);

	policy = "allow_read /dev/null if path1.type=char path1.dev_major=1 "
		"path1.dev_minor=3";
	write_domain_policy(policy, 0);
	fd = open("/dev/null", O_RDONLY);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open("/dev/null", O_RDONLY);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	policy = "allow_read /dev/null if path1.perm=0666";
	write_domain_policy(policy, 0);
	fd = open("/dev/null", O_RDONLY);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open("/dev/null", O_RDONLY);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	policy = "allow_read /dev/null if path1.perm!=0777";
	write_domain_policy(policy, 0);
	fd = open("/dev/null", O_RDONLY);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open("/dev/null", O_RDONLY);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	policy = "allow_read /dev/null if path1.perm=owner_read "
		"path1.perm=owner_write path1.perm!=owner_execute "
		"path1.perm=group_read path1.perm=group_write "
		"path1.perm!=group_execute path1.perm=others_read "
		"path1.perm=others_write path1.perm!=others_execute "
		"path1.perm!=setuid path1.perm!=setgid path1.perm!=sticky";
	write_domain_policy(policy, 0);
	fd = open("/dev/null", O_RDONLY);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open("/dev/null", O_RDONLY);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	set_profile(3, "file::mkfifo");
	policy = "allow_mkfifo /tmp/mknod_fifo_test 0644 "
		"if path1.parent.perm=01777 path1.parent.perm=sticky "
		"path1.parent.uid=0 path1.parent.gid=0";
	write_domain_policy(policy, 0);
	filename = "/tmp/mknod_fifo_test";
	show_result(mknod(filename, S_IFIFO | 0644, 0), 1);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(mknod(filename, S_IFIFO | 0644, 0), 0);

	memset(pbuffer, 0, sizeof(pbuffer));
	memset(&sbuf, 0, sizeof(sbuf));
	filename = "/dev/null";
	stat(filename, &sbuf);
	snprintf(pbuffer, sizeof(pbuffer) - 1,
		 "allow_write %s if path1.major=%u path1.minor=%u",
		 filename, (unsigned int) MAJOR(sbuf.st_dev),
		 (unsigned int) MINOR(sbuf.st_dev));
	policy = pbuffer;
	write_domain_policy(policy, 0);
	fd = open(filename, O_WRONLY);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open(filename, O_WRONLY);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	policy = "allow_read/write /tmp/fifo if path1.type=fifo";
	mkfifo2("/tmp/fifo");
	write_domain_policy(policy, 0);
	fd = open("/tmp/fifo", O_RDWR);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open("/tmp/fifo", O_RDWR);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	policy = "allow_read /dev/null if path1.parent.ino=path1.parent.ino";
	write_domain_policy(policy, 0);
	fd = open("/dev/null", O_RDONLY);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open("/dev/null", O_RDONLY);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	policy = "allow_write /dev/null if path1.uid=path1.gid";
	write_domain_policy(policy, 0);
	fd = open("/dev/null", O_WRONLY);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open("/dev/null", O_WRONLY);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	policy = "allow_read/write /dev/null if task.uid=path1.parent.uid";
	write_domain_policy(policy, 0);
	fd = open("/dev/null", O_RDWR);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open("/dev/null", O_RDWR);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	policy = "allow_create /tmp/open_test 0644 "
		"if path1.parent.uid=task.uid";
	write_domain_policy(policy, 0);
	policy = "allow_write /tmp/open_test if path1.parent.uid=0";
	write_domain_policy(policy, 0);
	fd = open("/tmp/open_test", O_WRONLY | O_CREAT | O_EXCL, 0644);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	unlink2("/tmp/open_test");
	write_domain_policy(policy, 1);
	fd = open("/tmp/open_test", O_WRONLY | O_CREAT | O_EXCL, 0644);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);
	unlink2("/tmp/open_test");

	policy = "allow_create /tmp/open_test 0644 "
		"if path1.parent.uid=task.uid";
	write_domain_policy(policy, 1);

	policy = "allow_write /tmp/open_test if task.uid=0 path1.ino!=0";
	write_domain_policy(policy, 0);
	policy = "allow_create /tmp/open_test 0644 if 0=0";
	write_domain_policy(policy, 0);
	fd = open("/tmp/open_test", O_WRONLY | O_CREAT | O_EXCL, 0644);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	unlink2("/tmp/open_test");
	write_domain_policy(policy, 1);
	fd = open("/tmp/open_test", O_WRONLY | O_CREAT | O_EXCL, 0644);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);
	unlink2("/tmp/open_test");
	policy = "allow_write /tmp/open_test if task.uid=0 path1.ino!=0";
	write_domain_policy(policy, 1);

	filename = "/tmp/truncate_test";
	create2(filename);

	policy = "allow_truncate /tmp/truncate_test if task.uid=path1.uid";
	write_domain_policy(policy, 0);
	policy = "allow_write /tmp/truncate_test if 1!=100-1000000";
	write_domain_policy(policy, 0);
	fd = open(filename, O_WRONLY | O_TRUNC);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open(filename, O_WRONLY | O_TRUNC);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);
	policy = "allow_truncate /tmp/truncate_test "
		"if task.uid=path1.uid";
	write_domain_policy(policy, 1);

	policy = "allow_write /tmp/truncate_test";
	write_domain_policy(policy, 0);
	policy = "allow_truncate /tmp/truncate_test";
	write_domain_policy(policy, 0);
	fd = open(filename, O_WRONLY | O_TRUNC);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	fd = open(filename, O_WRONLY | O_TRUNC);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);
	policy = "allow_write /tmp/truncate_test";
	write_domain_policy(policy, 1);

	policy = "allow_truncate /tmp/truncate_test";
	write_domain_policy(policy, 0);
	show_result(truncate(filename, 0), 1);
	write_domain_policy(policy, 1);
	show_result(truncate(filename, 0), 0);

	policy = "allow_truncate /tmp/truncate_test";
	write_domain_policy(policy, 0);
	set_profile(0, "file::open");
	fd = open(filename, O_WRONLY);
	set_profile(3, "file::open");
	show_result(ftruncate(fd, 0), 1);
	write_domain_policy(policy, 1);
	show_result(ftruncate(fd, 0), 0);
	if (fd != EOF)
		close(fd);

	unlink2(filename);

	policy = "allow_create /tmp/mknod_reg_test 0644";
	write_domain_policy(policy, 0);
	filename = "/tmp/mknod_reg_test";
	show_result(mknod(filename, S_IFREG | 0644, 0), 1);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(mknod(filename, S_IFREG | 0644, 0), 0);

	policy = "allow_mkchar /tmp/mknod_chr_test 0644 1 3";
	write_domain_policy(policy, 0);
	filename = "/tmp/mknod_chr_test";
	show_result(mknod(filename, S_IFCHR | 0644, MKDEV(1, 3)), 1);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(mknod(filename, S_IFCHR | 0644, MKDEV(1, 3)), 0);

	policy = "allow_mkblock /tmp/mknod_blk_test 0644 1 0";
	write_domain_policy(policy, 0);
	filename = "/tmp/mknod_blk_test";
	show_result(mknod(filename, S_IFBLK | 0644, MKDEV(1, 0)), 1);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(mknod(filename, S_IFBLK | 0644, MKDEV(1, 0)), 0);

	policy = "allow_mkfifo /tmp/mknod_fifo_test 0644";
	write_domain_policy(policy, 0);
	filename = "/tmp/mknod_fifo_test";
	show_result(mknod(filename, S_IFIFO | 0644, 0), 1);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(mknod(filename, S_IFIFO | 0644, 0), 0);

	policy = "allow_mksock /tmp/mknod_sock_test 0644";
	write_domain_policy(policy, 0);
	filename = "/tmp/mknod_sock_test";
	show_result(mknod(filename, S_IFSOCK | 0644, 0), 1);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(mknod(filename, S_IFSOCK | 0644, 0), 0);

	policy = "allow_mkdir /tmp/mkdir_test/ 0600";
	write_domain_policy(policy, 0);
	filename = "/tmp/mkdir_test";
	show_result(mkdir(filename, 0600), 1);
	write_domain_policy(policy, 1);
	rmdir2(filename);
	show_result(mkdir(filename, 0600), 0);

	policy = "allow_rmdir /tmp/rmdir_test/";
	write_domain_policy(policy, 0);
	filename = "/tmp/rmdir_test";
	mkdir2(filename);
	show_result(rmdir(filename), 1);
	write_domain_policy(policy, 1);
	mkdir2(filename);
	show_result(rmdir(filename), 0);
	rmdir2(filename);

	policy = "allow_unlink /tmp/unlink_test";
	write_domain_policy(policy, 0);
	filename = "/tmp/unlink_test";
	create2(filename);
	show_result(unlink(filename), 1);
	write_domain_policy(policy, 1);
	create2(filename);
	show_result(unlink(filename), 0);
	unlink2(filename);

	policy = "allow_symlink /tmp/symlink_source_test";
	write_domain_policy(policy, 0);
	filename = "/tmp/symlink_source_test";
	show_result(symlink("/tmp/symlink_dest_test", filename), 1);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(symlink("/tmp/symlink_dest_test", filename), 0);

	policy = "allow_symlink /tmp/symlink_source_test "
		"if symlink.target=\"/tmp/symlink_\\*_test\"";
	write_domain_policy(policy, 0);
	filename = "/tmp/symlink_source_test";
	show_result(symlink("/tmp/symlink_dest_test", filename), 1);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(symlink("/tmp/symlink_dest_test", filename), 0);

	policy = "allow_symlink /tmp/symlink_source_test "
		"if task.uid=0 symlink.target=\"/tmp/symlink_\\*_test\"";
	write_domain_policy(policy, 0);
	filename = "/tmp/symlink_source_test";
	show_result(symlink("/tmp/symlink_dest_test", filename), 1);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(symlink("/tmp/symlink_dest_test", filename), 0);

	policy = "allow_symlink /tmp/symlink_source_test "
		"if symlink.target!=\"\\*\"";
	write_domain_policy(policy, 0);
	filename = "/tmp/symlink_source_test";
	show_result(symlink("/tmp/symlink_dest_test", filename), 1);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(symlink("/tmp/symlink_dest_test", filename), 0);

	policy = "allow_symlink /tmp/symlink_source_test "
		"if symlink.target!=\"/tmp/symlink_\\*_test\"";
	write_domain_policy(policy, 0);
	filename = "/tmp/symlink_source_test";
	show_result(symlink("/tmp/symlink_dest_test", filename), 0);
	write_domain_policy(policy, 1);
	unlink2(filename);
	show_result(symlink("/tmp/symlink_dest_test", filename), 0);

	policy = "allow_link /tmp/link_source_test /tmp/link_dest_test";
	write_domain_policy(policy, 0);
	filename = "/tmp/link_source_test";
	create2(filename);
	show_result(link(filename, "/tmp/link_dest_test"), 1);
	write_domain_policy(policy, 1);
	unlink2("/tmp/link_dest_test");
	show_result(link(filename, "/tmp/link_dest_test"), 0);
	unlink2(filename);

	policy = "allow_rename /tmp/rename_source_test /tmp/rename_dest_test";
	write_domain_policy(policy, 0);
	filename = "/tmp/rename_source_test";
	create2(filename);
	show_result(rename(filename, "/tmp/rename_dest_test"), 1);
	write_domain_policy(policy, 1);
	unlink2("/tmp/rename_dest_test");
	create2(filename);
	show_result(rename(filename, "/tmp/rename_dest_test"), 0);
	unlink2(filename);

	policy = "allow_mksock /tmp/socket_test 0755";
	write_domain_policy(policy, 0);
	filename = "/tmp/socket_test";
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, filename, sizeof(addr.sun_path) - 1);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	show_result(bind(fd, (struct sockaddr *) &addr, sizeof(addr)),
		    1);
	if (fd != EOF)
		close(fd);
	write_domain_policy(policy, 1);
	unlink2(filename);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	show_result(bind(fd, (struct sockaddr *) &addr, sizeof(addr)),
		    0);
	if (fd != EOF)
		close(fd);

	filename = "/tmp/rewrite_test";
	create2(filename);
	policy = "allow_read/write /tmp/rewrite_test";
	write_domain_policy(policy, 0);
	write_exception_policy("deny_rewrite /tmp/rewrite_test", 0);
	policy = "allow_truncate /tmp/rewrite_test";
	write_domain_policy(policy, 0);

	fd = open(filename, O_RDONLY);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);

	fd = open(filename, O_WRONLY | O_APPEND);
	show_result(fd, 1);
	if (fd != EOF)
		close(fd);

	fd = open(filename, O_WRONLY);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	fd = open(filename, O_WRONLY | O_TRUNC);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	fd = open(filename, O_WRONLY | O_TRUNC | O_APPEND);
	show_result(fd, 0);
	if (fd != EOF)
		close(fd);

	show_result(truncate(filename, 0), 0);

	set_profile(0, "file::open");
	fd = open(filename, O_WRONLY | O_APPEND);
	set_profile(3, "file::open");
	show_result(ftruncate(fd, 0), 0);

	show_result(fcntl(fd, F_SETFL,
			  fcntl(fd, F_GETFL) & ~O_APPEND), 0);
	if (fd != EOF)
		close(fd);

	write_domain_policy(policy, 1);

	policy = "allow_read/write /tmp/rewrite_test";
	write_domain_policy(policy, 1);
	write_exception_policy("deny_rewrite /tmp/rewrite_test", 1);

	unlink2(filename);

	policy = "allow_ioctl socket:[family=2:type=2:protocol=17] "
		"35122-35124 if task.uid=0";
	write_domain_policy(policy, 0);
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	memset(&ifreq, 0, sizeof(ifreq));
	snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name) - 1,
		 "lo");
	show_result(ioctl(fd, 35123, &ifreq), 1);
	write_domain_policy(policy, 1);
	policy = "allow_ioctl "
		"socket:[family=2:type=2:protocol=17] 0-35122";
	write_domain_policy(policy, 0);
	show_result(ioctl(fd, 35123, &ifreq), 0);
	write_domain_policy(policy, 1);
	if (fd != EOF)
		close(fd);
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	fprintf(domain_fp, "%s /bin/true\n", self_domain);
	fprintf(domain_fp, "use_profile 255\n");
	fprintf(domain_fp, "select pid=%u\n", pid);
	fprintf(profile_fp, "255-PREFERENCE::audit={ max_reject_log=1024 }\n");
	stage_file_test();
	fprintf(domain_fp, "use_profile 0\n");
	clear_status();
	return 0;
}
