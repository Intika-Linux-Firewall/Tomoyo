/*
 * ccs_policy_memory_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
 *
 * Usage: Run this program using init= boot option.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>

static void BUG(const char *msg)
{
	printf("%s", msg);
	fflush(stdout);
	while (1)
		sleep(100);
}

static const char *policy_file = NULL;
static const char *policy = NULL;

static _Bool ignore_ns = 0;

static void get_meminfo(unsigned int *policy_memory)
{
	static char buf[1024];
	FILE *fp = fopen("/proc/ccs/stat", "r+");
	while (memset(buf, 0, sizeof(buf)),
	       fp && fgets(buf, sizeof(buf) - 1, fp)) {
		if (sscanf(buf,
			   "Memory used by policy: %u", policy_memory) != 1)
			continue;
		fclose(fp);
		return;
	}
	BUG("BUG: Policy read error\n");
}

static void check_policy_common(const int found_expected, const int id)
{
	FILE *fp = fopen(policy_file, "r");
	char buffer[8192];
	int policy_found = 0;
	memset(buffer, 0, sizeof(buffer));
	if (!fp)
		BUG("BUG: Policy read error\n");
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (ignore_ns && !strncmp(buffer, "<kernel> ", 9))
			memmove(buffer, buffer + 9, strlen(buffer + 9) + 1);
		if (strcmp(buffer, policy))
			continue;
		policy_found = 1;
		break;
	}
	fclose(fp);
	if (policy_found != found_expected) {
		printf("BUG: Policy write error: %s %s at %d\n", policy,
		       found_expected ? "not added" : "not deleted", id);
		BUG("");
	}
}

static inline void check_policy_written(FILE *fp, const int id)
{
	fflush(fp);
	check_policy_common(1, id);
}

static inline void check_policy_deleted(FILE *fp, const int id)
{
	fflush(fp);
	check_policy_common(0, id);
}

static const char * const domain_testcases[] = {
	"file create /tmp/mknod_reg_test 0600",
	"file create /tmp/open_test 0600 path1.parent.uid=task.uid",
	"file create /tmp/open_test 0600 0=0",
	"file create /tmp/open_test 0600",
	"file execute /bin/true task.uid!=10 path1.parent.uid=0",
	"file execute /bin/true",
	"file execute /bin/true0 task.uid=0",
	"file execute /bin/true1 task.uid=task.gid",
	"file execute /bin/true2 0=0",
	"file execute /bin/true3 0!=0",
	"file execute /bin/true4 123-456=789",
	"file execute /bin/true5 exec.realpath=\"/bin/true5\"",
	"file execute /bin/true6 exec.argv[0]=\"true6\"",
	"file execute /bin/true7 1-2=@bar",
	"file execute /bin/true7 exec.realpath!=@foo",
	"file execute /bin/true7 exec.realpath=@foo",
	"file execute /bin/true8 "
	"exec.argv[0]=\"test8\" exec.realpath=\"/bin/true8\"",
	"file ioctl socket:[family=2:type=2:protocol=17] 0-35122",
	"file ioctl socket:[family=2:type=2:protocol=17] 35122-35124 "
	"task.uid=0",
	"file link /tmp/link_source_test /tmp/link_dest_test",
	"file mkblock /tmp/mknod_blk_test 0600 1 0",
	"file mkchar /tmp/mknod_chr_test 0600 1 3",
	"file mkdir /tmp/mkdir_test/ 0755",
	"file mkfifo /tmp/mknod_fifo_test 0600 path1.parent.perm=01777 "
	"path1.parent.perm=sticky path1.parent.uid=0 path1.parent.gid=0",
	"file mkfifo /tmp/mknod_fifo_test 0600",
	"file mksock /tmp/mknod_sock_test 0600",
	"file mksock /tmp/socket_test 0600",
	"file read /bin/true path1.uid=0 path1.parent.uid=0 10=10-100",
	"file read /bin/true",
	"file read /dev/null path1.parent.ino=path1.parent.ino",
	"file read /dev/null path1.perm!=0777",
	"file read /dev/null path1.perm=0666",
	"file read /dev/null path1.perm=owner_read path1.perm=owner_write "
	"path1.perm!=owner_execute path1.perm=group_read "
	"path1.perm=group_write path1.perm!=group_execute "
	"path1.perm=others_read path1.perm=others_write "
	"path1.perm!=others_execute path1.perm!=setuid path1.perm!=setgid "
	"path1.perm!=sticky",
	"file read /dev/null "
	"path1.type=char path1.dev_major=1 path1.dev_minor=3",
	"file read /dev/null",
	"file read /foo",
	"file read proc:/sys/net/ipv4/ip_local_port_range "
	"task.uid=0 task.gid=0",
	"file read proc:/sys/net/ipv4/ip_local_port_range",
	"file append /bar",
	"file append /dev/null task.uid=path1.parent.uid",
	"file append /dev/null",
	"file read proc:/sys/net/ipv4/ip_local_port_range 1!=10-100",
	"file read proc:/sys/net/ipv4/ip_local_port_range",
	"file append /tmp/fifo path1.type=fifo",
	"file append /tmp/fifo",
	"file append /tmp/rewrite_test",
	"file rename /tmp/rename_source_test /tmp/rename_dest_test",
	"file rmdir /tmp/rmdir_test/",
	"file symlink /symlink symlink.target!=@target",
	"file symlink /symlink symlink.target!=\"target\"",
	"file symlink /symlink symlink.target=@symlink_target",
	"file symlink /symlink symlink.target=\"target\"",
	"file symlink /tmp/symlink_source_test "
	"symlink.target!=\"/tmp/symlink_\\*_test\"",
	"file symlink /tmp/symlink_source_test symlink.target!=\"\\*\"",
	"file symlink /tmp/symlink_source_test "
	"symlink.target=\"/tmp/symlink_\\*_test\"",
	"file symlink /tmp/symlink_source_test "
	"task.uid=0 symlink.target=\"/tmp/symlink_\\*_test\"",
	"file symlink /tmp/symlink_source_test",
	"file truncate /tmp/rewrite_test",
	"file truncate /tmp/truncate_test task.uid=path1.uid",
	"file truncate /tmp/truncate_test",
	"file unlink /tmp/unlink_test",
	"file write /123",
	"file write /dev/null path1.uid=path1.gid",
	"file write /dev/null",
	"file write /devfile path1.major=1024 path1.minor=1048576",
	"file write /devfile",
	"file write proc:/sys/net/ipv4/ip_local_port_range "
	"task.euid=0 0=0 1-100=10-1000",
	"file write proc:/sys/net/ipv4/ip_local_port_range",
	"file write /tmp/open_test path1.parent.uid=0",
	"file write /tmp/open_test task.uid=0 path1.ino!=0",
	"file write /tmp/open_test",
	"file write /tmp/truncate_test 1!=100-1000000",
	"file write /tmp/truncate_test",
	"file mount /dev/sda1 /mnt/sda1/ ext3 0x123",
	"file mount /dev/sda1 /mnt/sda1/ ext3 123",
	"file mount /dev/sda1 /mnt/sda1/ ext3 0123",
	"file mount /dev/sda1 /mnt/sda1/ ext3 0x123 path1.uid=path2.uid",
	"file mount /dev/sda1 /mnt/sda1/ ext3 123 path1.uid=task.uid",
	"file mount /dev/sda1 /mnt/sda1/ ext3 0123 path1.uid=@uid",
	"file chroot /",
	"file chroot / task.uid=123-456",
	"file chroot /mnt/ task.uid=123-456 path1.gid=0",
	"file pivot_root / /proc/ path1.uid!=0",
	"file pivot_root /mnt/ /proc/mnt/ path1.uid!=0 path2.gid=150",
	"file unmount / path1.uid!=0",
	"file unmount /proc/ path1.uid!=0",
	NULL
};

static void domain_policy_test(const unsigned int before)
{
	unsigned int after;
	int j;
	policy_file = "/proc/ccs/domain_policy";
	printf("Processing domain policy\n");
	for (j = 0; domain_testcases[j]; j++) {
		int i;
		FILE *fp = fopen(policy_file, "w");
		if (!fp)
			BUG("BUG: Policy write error\n");
		fprintf(fp, "<kernel>\n");
		policy = domain_testcases[j];
		printf("Processing: %s\n", policy);
		for (i = 0; i < 100; i++) {
			fprintf(fp, "%s\n", policy);
			if (!i)
				check_policy_written(fp, 1);
			fprintf(fp, "delete %s\n", policy);
		}
		check_policy_deleted(fp, 1);
		for (i = 0; i < 100; i++)
			fprintf(fp, "%s\n", policy);
		check_policy_written(fp, 2);
		fprintf(fp, "delete %s\n", policy);
		check_policy_deleted(fp, 2);
		fclose(fp);
		for (i = 0; i < 300; i++) {
			usleep(100000);
			get_meminfo(&after);
			if (before == after)
				break;
		}
		if (before != after) {
			printf("Policy: %d\n", after - before);
			BUG("Policy read/write test: Fail\n");
		}
	}
	printf("Processing all.\n");
	for (j = 0; j < 10; j++) {
		int i;
		FILE *fp = fopen(policy_file, "w");
		if (!fp)
			BUG("BUG: Policy write error\n");
		fprintf(fp, "<kernel> /sbin/init\n");
		for (i = 0; domain_testcases[i]; i++)
			fprintf(fp, "%s\n", domain_testcases[i]);
		fprintf(fp, "delete <kernel> /sbin/init\n");
		fclose(fp);
		for (i = 0; i < 500; i++) {
			usleep(100000);
			get_meminfo(&after);
			if (before == after)
				break;
		}
		if (before != after) {
			printf("Policy: %d\n", after - before);
			BUG("Policy read/write test: Fail\n");
		}
	}
}

static const char * const domain_random_args[] = {
	"file", "file execute", "file execute @", "file execute @1",
	"file execute @1 @2", "file create", "file create @", "file create @1",
	"file create @1 @", "file create @1 @2", "file create @1 @2 @3",
	"file mkblock", "file mkblock @", "file mkblock @1",
	"file mkblock @1 @", "file mkblock @1 @2", "file mkblock @1 @2 @",
	"file mkblock @1 @2 @3", "file mkblock @1 @2 @3 @",
	"file mkblock @1 @2 @3 @4", "file mkblock @1 @2 @3 @4 @5", "file link",
	"file link @", "file link @1", "file link @1 @", "file link @1 @2",
	"file link @1 @2 @3", "file mount", "file mount @", "file mount @1",
	"file mount @1 @", "file mount @1 @2", "file mount @1 @2 @",
	"file mount @1 @2 @3", "file mount @1 @2 @3 @",
	"file mount @1 @2 @3 @4", "file mount @1 @2 @3 @4 @5", "network",
	"network inet", "network inet stream", "network inet stream bind",
	"network inet stream bind @", "network inet stream bind @1",
	"network inet stream bind @1 @", "network inet stream bind @1 @2",
	"network inet stream bind @1 @2 @3", "network unix",
	"network unix stream", "network unix stream bind",
	"network unix stream bind @", "network unix stream bind @1",
	"network unix stream bind @1 @2", "capability", "capability use_route",
	"capability use_route @1", "misc", "misc env", "misc env @",
	"misc env @1", "misc env @1 @2", "ipc", "ipc signal", "ipc signal @",
	"ipc signal @1", "ipc signal @1 <kernel>", "ipc signal @1 <kernel> @2",
	"task", "task auto_execute_handler", "task auto_execute_handler /",
	"task auto_execute_handler / @1", "task auto_domain_transition",
	"task auto_domain_transition <kernel> 0=1",
	"task manual_domain_transition <kernel> @1", NULL
};

static void domain_random_test(const unsigned int before)
{
	unsigned int after;
	int j;
	policy_file = "/proc/ccs/domain_policy";
	printf("Processing random policy\n");
	for (j = 0; domain_random_args[j]; j++) {
		int i;
		FILE *fp = fopen(policy_file, "w");
		if (!fp)
			BUG("BUG: Policy write error\n");
		fprintf(fp, "<kernel>\n");
		policy = domain_random_args[j];
		printf("Processing: %s\n", policy);
		for (i = 0; i < 100; i++) {
			fprintf(fp, "%s\n", policy);
			fprintf(fp, "delete %s\n", policy);
		}
		for (i = 0; i < 100; i++)
			fprintf(fp, "%s\n", policy);
		for (i = 0; i < 100; i++)
			fprintf(fp, "delete %s\n", policy);
		fclose(fp);
		for (i = 0; i < 300; i++) {
			usleep(100000);
			get_meminfo(&after);
			if (before == after)
				break;
		}
		if (before != after) {
			printf("Policy: %d\n", after - before);
			BUG("Policy read/write test: Fail\n");
		}
	}
}

static const char * const exception_testcases[] = {
	"acl_group 0 file read /tmp/mknod_reg_test",
	"acl_group 0 misc env HOME",
	"path_group PG1 /",
	"path_group PG2 /",
	"address_group AG3 0.0.0.0",
	"address_group AG3 1.2.3.4-5.6.7.8",
	"address_group AG3 f:ee:ddd:cccc:b:aa:999:8888",
	"address_group AG4 0:1:2:3:4:5:6:7-8:90:a00:b000:c00:d0:e:f000",
	"number_group NG1 1000",
	"number_group NG2 10-0x100000",
	"number_group NG3 01234567-0xABCDEF89",
	"deny_autobind 1024",
	"deny_autobind 32668-65535",
	"deny_autobind 0-1023",
	"initialize_domain /usr/sbin/sshd from any",
	"no_initialize_domain /usr/sbin/sshd from any",
	"initialize_domain /usr/sbin/sshd from /bin/bash",
	"no_initialize_domain /usr/sbin/sshd from /bin/bash",
	"initialize_domain /usr/sbin/sshd from "
	"<kernel> /bin/mingetty /bin/bash",
	"no_initialize_domain /usr/sbin/sshd from "
	"<kernel> /bin/mingetty /bin/bash",
	"keep_domain any from <kernel> /usr/sbin/sshd /bin/bash",
	"no_keep_domain any from <kernel> /usr/sbin/sshd /bin/bash",
	"keep_domain /bin/pwd from <kernel> /usr/sbin/sshd /bin/bash",
	"no_keep_domain /bin/pwd from <kernel> /usr/sbin/sshd /bin/bash",
	"keep_domain /bin/pwd from /bin/bash",
	"no_keep_domain /bin/pwd from /bin/bash",
	"acl_group 0 file read /etc/ld.so.cache",
	"acl_group 0 file read proc:/meminfo",
	"acl_group 0 file read proc:/sys/kernel/version",
	"acl_group 0 file read /etc/localtime",
	"acl_group 0 file read proc:/self/task/\\$/attr/current",
	"acl_group 0 file read proc:/self/task/\\$/oom_score",
	"acl_group 0 file read proc:/self/wchan",
	"acl_group 0 file read /lib/ld-2.5.so",
	"aggregator /etc/rc.d/rc\\?.d/\\?\\+\\+smb /etc/rc.d/init.d/smb",
	"aggregator /etc/rc.d/rc\\?.d/\\?\\+\\+crond /etc/rc.d/init.d/crond",
	NULL
};

static void exception_policy_test(const unsigned int before)
{
	unsigned int after;
	int j;
	ignore_ns = 1;
	policy_file = "/proc/ccs/exception_policy";
	printf("Processing exception policy\n");
	for (j = 0; exception_testcases[j]; j++) {
		int i;
		FILE *fp = fopen(policy_file, "w");
		if (!fp)
			BUG("BUG: Policy write error\n");
		policy = exception_testcases[j];
		printf("Processing: %s\n", policy);
		for (i = 0; i < 100; i++) {
			fprintf(fp, "%s\n", policy);
			if (!i)
				check_policy_written(fp, 1);
			fprintf(fp, "delete %s\n", policy);
		}
		check_policy_deleted(fp, 1);
		for (i = 0; i < 100; i++)
			fprintf(fp, "%s\n", policy);
		check_policy_written(fp, 2);
		fprintf(fp, "delete %s\n", policy);
		check_policy_deleted(fp, 2);
		fclose(fp);
		for (i = 0; i < 300; i++) {
			usleep(100000);
			get_meminfo(&after);
			if (before == after)
				break;
		}
		if (before != after) {
			printf("Policy: %d\n", after - before);
			BUG("Policy read/write test: Fail\n");
		}
	}
	printf("Processing all.\n");
	for (j = 0; j < 10; j++) {
		int i;
		FILE *fp = fopen(policy_file, "w");
		if (!fp)
			BUG("BUG: Policy write error\n");
		for (i = 0; exception_testcases[i]; i++)
			fprintf(fp, "%s\n", exception_testcases[i]);
		for (i = 0; exception_testcases[i]; i++)
			fprintf(fp, "delete %s\n", exception_testcases[i]);
		fclose(fp);
		for (i = 0; i < 500; i++) {
			usleep(100000);
			get_meminfo(&after);
			if (before == after)
				break;
		}
		if (before != after) {
			printf("Policy: %d\n", after - before);
			BUG("Policy read/write test: Fail\n");
		}
	}
}

int main(int argc, char *argv[])
{
	unsigned int before = 0;
	mount("/proc", "/proc/", "proc", 0, NULL);
	printf("Waiting for stabilized.\n");
	while (1) {
		unsigned int prev = before;
		get_meminfo(&before);
		printf("Memory used by policy: %10u\r", before);
		fflush(stdout);
		sleep(3);
		if (prev == before)
			break;
	}
	printf("\n");
	get_meminfo(&before);
	domain_policy_test(before);
	domain_random_test(before);
	exception_policy_test(before);
	BUG("Policy read/write test: Success\n");
	return 0;
}
