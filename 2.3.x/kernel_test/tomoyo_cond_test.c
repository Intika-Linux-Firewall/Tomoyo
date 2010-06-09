/*
 * tomoyo_cond_test.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0   2009/09/03
 *
 */
#include "include.h"

static void try_open(const char *policy, const char *file, const int mode,
		     const char should_success) {
	FILE *fp;
	char buffer[8192];
	int domain_found = 0;
	int policy_found = 0;
	int err = 0;
	memset(buffer, 0, sizeof(buffer));
	set_profile(0, "file::open");
	fp = fopen(proc_policy_domain_policy, "r+");
	set_profile(3, "file::open");
	printf("%s: ", policy);
	fflush(stdout);
	fprintf(domain_fp, "%s\n", policy);
	if (!fp) {
		printf("BUG: policy read failed\n");
		return;
	}
	fprintf(fp, "select pid=%d\n", pid);
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
		printf("BUG: policy write failed\n");
		return;
	}
	{
		int fd;
		errno = 0;
		fd = open(file, mode, 0);
		err = errno;
		if (fd != EOF)
			close(fd);
	}
	fprintf(domain_fp, "delete %s\n", policy);
	if (should_success) {
		if (!err)
			printf("OK\n");
		else
			printf("BUG: failed (%d)\n", err);
	} else {
		if (err == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: failed (%d)\n", err);
	}
}

static void stage_open_test(void)
{
	const pid_t pid = getppid();
	int i;
	char buffer[128];
	for (i = 0; i < 5; i++) {
		memset(buffer, 0, sizeof(buffer));
		snprintf(buffer, sizeof(buffer) - 1, "/proc/%u/mounts", pid);
		try_open("allow_read /etc/fstab", "/etc/fstab", O_RDONLY, 1);
		try_open("allow_write /etc/fstab", "/etc/fstab", O_WRONLY, 1);
		try_open("allow_write /etc/fstab", "/etc/fstab", O_RDONLY, 0);
		try_open("allow_read /etc/fstab", "/etc/fstab", O_WRONLY, 0);
		try_open("allow_read/write /etc/fstab", "/etc/fstab", O_RDWR,
			 1);
		try_open("allow_read/write /etc/fstab", "/etc/fstab", O_RDONLY,
			 1);
		try_open("allow_read/write /etc/fstab", "/etc/fstab", O_WRONLY,
			 1);
		try_open("allow_read /etc/fstab if task.uid=0 task.euid=0",
			 "/etc/fstab", O_RDONLY, 1);
		try_open("allow_read /etc/fstab "
			 "if task.uid=0 task.euid=0-4294967295", "/etc/fstab",
			 O_RDONLY, 1);
		try_open("allow_read /etc/fstab "
			 "if task.uid=0 task.euid!=0-4294967295", "/etc/fstab",
			 O_RDONLY, 0);
		try_open("allow_read /etc/fstab if task.uid=0 task.euid!=0",
			 "/etc/fstab", O_RDONLY, 0);
		try_open("allow_read /etc/fstab if exec.argc=0", "/etc/fstab",
			 O_RDONLY, 0);
		try_open("allow_read /etc/fstab if exec.envc=0", "/etc/fstab",
			 O_RDONLY, 0);
		try_open("allow_read /etc/fstab if exec.argv[0]=\"\"",
			 "/etc/fstab", O_RDONLY, 0);
		try_open("allow_read /etc/fstab if exec.argv[0]!=\"\"",
			 "/etc/fstab", O_RDONLY, 0);
		try_open("allow_read /etc/fstab if exec.envp[\"HOME\"]=\"\"",
			 "/etc/fstab", O_RDONLY, 0);
		try_open("allow_read /etc/fstab if exec.envp[\"HOME\"]!=\"\"",
			 "/etc/fstab", O_RDONLY, 0);
		try_open("allow_read /etc/fstab if exec.envp[\"HOME\"]=NULL",
			 "/etc/fstab", O_RDONLY, 0);
		try_open("allow_read /etc/fstab if exec.envp[\"HOME\"]!=NULL",
			 "/etc/fstab", O_RDONLY, 0);

		try_open("allow_read /proc/\\*/mounts", buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\@/mounts", buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\$/mounts", buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\X/mounts", buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\+/mounts", buffer, O_RDONLY,
			 pid >= 0 && pid < 10);
		try_open("allow_read /proc/\\+\\+/mounts", buffer, O_RDONLY,
			 pid >= 10 && pid < 100);
		try_open("allow_read /proc/\\+\\+\\+/mounts", buffer, O_RDONLY,
			 pid >= 100 && pid < 1000);
		try_open("allow_read /proc/\\+\\+\\+\\+/mounts", buffer,
			 O_RDONLY, pid >= 1000 && pid < 10000);
		try_open("allow_read /proc/\\+\\+\\+\\+\\+/mounts", buffer,
			 O_RDONLY, pid >= 10000 && pid < 100000);
		try_open("allow_read /proc/\\+\\+\\+\\+\\+\\+/mounts", buffer,
			 O_RDONLY, pid >= 100000 && pid < 1000000);

		try_open("allow_read /proc/\\x/mounts", buffer, O_RDONLY,
			 pid < 10);
		try_open("allow_read /proc/\\x\\x/mounts", buffer, O_RDONLY,
			 pid >= 10 && pid < 100);
		try_open("allow_read /proc/\\x\\x\\x/mounts", buffer, O_RDONLY,
			 pid >= 100 && pid < 1000);
		try_open("allow_read /proc/\\x\\x\\x\\x/mounts", buffer,
			 O_RDONLY, pid >= 1000 && pid < 10000);
		try_open("allow_read /proc/\\x\\x\\x\\x\\x/mounts", buffer,
			 O_RDONLY, pid >= 10000 && pid < 100000);
		try_open("allow_read /proc/\\x\\x\\x\\x\\x\\x/mounts", buffer,
			 O_RDONLY, pid >= 100000 && pid < 1000000);

		try_open("allow_read /proc/\\$\\*/mounts", buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\$\\@/mounts", buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\$\\*\\*/mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\$\\@\\@/mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\$\\*\\@/mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\$\\@\\*/mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\$\\*/mounts\\*", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\$\\@/mounts\\@", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\$\\*\\*/mounts\\*\\*", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\$\\@\\@/mounts\\@\\@", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\$\\*\\@/mounts\\*\\@", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\$\\@\\*/mounts\\@\\*", buffer,
			 O_RDONLY, 1);

		try_open("allow_read /proc/\\*\\$/mounts", buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\@\\$/mounts", buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\*\\*\\$/mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\@\\@\\$/mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\*\\@\\$/mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\@\\*\\$/mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\*\\$/\\*mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\@\\$/\\@mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\*\\*\\$/\\*\\*mounts", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\@\\@\\$/\\@\\@mounts", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\*\\@\\$/\\*\\@mounts", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\@\\*\\$/\\@\\*mounts", buffer,
			 O_RDONLY, 1);

		try_open("allow_read /proc/\\*\\$\\*/mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\@\\$\\@/mounts", buffer, O_RDONLY,
			 1);
		try_open("allow_read /proc/\\*\\*\\$\\*\\*/mounts", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\@\\@\\$\\@\\@/mounts", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\*\\@\\$\\*\\@/mounts", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\@\\*\\$\\@\\*/mounts", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\*\\$\\*/\\*mounts\\*", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\@\\$\\@/\\@mounts\\@", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /proc/\\*\\*\\$\\*\\*/\\*\\*mounts\\*\\*",
			 buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\@\\@\\$\\@\\@/\\@\\@mounts\\@\\@",
			 buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\*\\@\\$\\*\\@/\\*\\@mounts\\*\\@",
			 buffer, O_RDONLY, 1);
		try_open("allow_read /proc/\\@\\*\\$\\@\\*/\\@\\*mounts\\@\\*",
			 buffer, O_RDONLY, 1);
	}
}

int main(int argc, char *argv[])
{
	tomoyo_test_init();
	fprintf(domain_fp, "ignore_global_allow_read\n");
	fprintf(domain_fp, "allow_read/write %s\n", proc_policy_domain_policy);
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
	stage_open_test();
	set_profile(0, "file::execute");
	set_profile(0, "file::open");
	set_profile(0, "file::create");
	set_profile(0, "file::unlink");
	set_profile(0, "file::mkdir");
	set_profile(0, "file::rmdir");
	set_profile(0, "file::mkfifo");
	set_profile(0, "file::mksock");
	set_profile(0, "file::truncate");
	set_profile(0, "file::symlink");
	set_profile(0, "file::rewrite");
	set_profile(0, "file::mkblock");
	set_profile(0, "file::mkchar");
	set_profile(0, "file::link");
	set_profile(0, "file::rename");
	set_profile(0, "file::chmod");
	set_profile(0, "file::chown");
	set_profile(0, "file::chgrp");
	set_profile(0, "file::ioctl");
	set_profile(0, "file::chroot");
	set_profile(0, "file::mount");
	set_profile(0, "file::umount");
	set_profile(0, "file::pivot_root");
	clear_status();
	return 0;
}
