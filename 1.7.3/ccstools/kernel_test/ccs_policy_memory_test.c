/*
 * Usage: Run this program using init= boot option.
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

static void get_meminfo(unsigned int *policy_memory)
{
	FILE *fp = fopen("/proc/ccs/meminfo", "r");
	if (!fp || fscanf(fp, "Policy: %u", policy_memory) != 1 || fclose(fp))
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
	"allow_create /tmp/mknod_reg_test 0600",
	"allow_create /tmp/open_test 0600 if path1.parent.uid=task.uid",
	"allow_create /tmp/open_test 0600 if 0=0",
	"allow_create /tmp/open_test 0600",
	"allow_execute /bin/true if task.uid!=10 path1.parent.uid=0",
	"allow_execute /bin/true",
	"allow_execute /bin/true0 if task.uid=0",
	"allow_execute /bin/true1 if task.uid=task.gid",
	"allow_execute /bin/true2 if 0=0",
	"allow_execute /bin/true3 if 0!=0",
	"allow_execute /bin/true4 if 123-456=789",
	"allow_execute /bin/true5 if exec.realpath=\"/bin/true5\"",
	"allow_execute /bin/true6 if exec.argv[0]=\"true6\"",
	"allow_execute /bin/true7 if 1-2=@bar",
	"allow_execute /bin/true7 if exec.realpath!=@foo",
	"allow_execute /bin/true7 if exec.realpath=@foo",
	"allow_execute /bin/true8 "
	"if exec.argv[0]=\"test8\" exec.realpath=\"/bin/true8\"",
	"allow_ioctl socket:[family=2:type=2:protocol=17] 0-35122",
	"allow_ioctl socket:[family=2:type=2:protocol=17] 35122-35124 "
	"if task.uid=0",
	"allow_link /tmp/link_source_test /tmp/link_dest_test",
	"allow_mkblock /tmp/mknod_blk_test 0600 1 0",
	"allow_mkchar /tmp/mknod_chr_test 0600 1 3",
	"allow_mkdir /tmp/mkdir_test/ 0755",
	"allow_mkfifo /tmp/mknod_fifo_test 0600 if path1.parent.perm=01777 "
	"path1.parent.perm=sticky path1.parent.uid=0 path1.parent.gid=0",
	"allow_mkfifo /tmp/mknod_fifo_test 0600",
	"allow_mksock /tmp/mknod_sock_test 0600",
	"allow_mksock /tmp/socket_test 0600",
	"allow_read /bin/true if path1.uid=0 path1.parent.uid=0 10=10-100",
	"allow_read /bin/true",
	"allow_read /dev/null if path1.parent.ino=path1.parent.ino",
	"allow_read /dev/null if path1.perm!=0777",
	"allow_read /dev/null if path1.perm=0666",
	"allow_read /dev/null if path1.perm=owner_read path1.perm=owner_write "
	"path1.perm!=owner_execute path1.perm=group_read "
	"path1.perm=group_write path1.perm!=group_execute "
	"path1.perm=others_read path1.perm=others_write "
	"path1.perm!=others_execute path1.perm!=setuid path1.perm!=setgid "
	"path1.perm!=sticky",
	"allow_read /dev/null "
	"if path1.type=char path1.dev_major=1 path1.dev_minor=3",
	"allow_read /dev/null",
	"allow_read /foo",
	"allow_read /proc/sys/net/ipv4/ip_local_port_range "
	"if task.uid=0 task.gid=0",
	"allow_read /proc/sys/net/ipv4/ip_local_port_range",
	"allow_read/write /bar",
	"allow_read/write /dev/null if task.uid=path1.parent.uid",
	"allow_read/write /dev/null",
	"allow_read/write /proc/sys/net/ipv4/ip_local_port_range if 1!=10-100",
	"allow_read/write /proc/sys/net/ipv4/ip_local_port_range",
	"allow_read/write /tmp/fifo if path1.type=fifo",
	"allow_read/write /tmp/fifo",
	"allow_read/write /tmp/rewrite_test",
	"allow_rename /tmp/rename_source_test /tmp/rename_dest_test",
	"allow_rmdir /tmp/rmdir_test/",
	"allow_symlink /symlink if symlink.target!=@target",
	"allow_symlink /symlink if symlink.target!=\"target\"",
	"allow_symlink /symlink if symlink.target=@symlink_target",
	"allow_symlink /symlink if symlink.target=\"target\"",
	"allow_symlink /tmp/symlink_source_test "
	"if symlink.target!=\"/tmp/symlink_\\*_test\"",
	"allow_symlink /tmp/symlink_source_test if symlink.target!=\"\\*\"",
	"allow_symlink /tmp/symlink_source_test "
	"if symlink.target=\"/tmp/symlink_\\*_test\"",
	"allow_symlink /tmp/symlink_source_test "
	"if task.uid=0 symlink.target=\"/tmp/symlink_\\*_test\"",
	"allow_symlink /tmp/symlink_source_test",
	"allow_truncate /tmp/rewrite_test",
	"allow_truncate /tmp/truncate_test if task.uid=path1.uid",
	"allow_truncate /tmp/truncate_test",
	"allow_unlink /tmp/unlink_test",
	"allow_write /123",
	"allow_write /dev/null if path1.uid=path1.gid",
	"allow_write /dev/null",
	"allow_write /devfile if path1.major=1024 path1.minor=1048576",
	"allow_write /devfile",
	"allow_write /proc/sys/net/ipv4/ip_local_port_range "
	"if task.euid=0 0=0 1-100=10-1000",
	"allow_write /proc/sys/net/ipv4/ip_local_port_range",
	"allow_write /tmp/open_test if path1.parent.uid=0",
	"allow_write /tmp/open_test if task.uid=0 path1.ino!=0",
	"allow_write /tmp/open_test",
	"allow_write /tmp/truncate_test if 1!=100-1000000",
	"allow_write /tmp/truncate_test",
	"allow_rewrite /tmp/rewrite_test if path1.uid!=path1.parent.uid",
	"allow_rewrite /tmp/rewrite_test",
	"allow_mount /dev/sda1 /mnt/sda1/ ext3 0x123",
	"allow_mount /dev/sda1 /mnt/sda1/ ext3 123",
	"allow_mount /dev/sda1 /mnt/sda1/ ext3 0123",
	"allow_mount /dev/sda1 /mnt/sda1/ ext3 0x123 if path1.uid=path2.uid",
	"allow_mount /dev/sda1 /mnt/sda1/ ext3 123 if path1.uid=task.uid",
	"allow_mount /dev/sda1 /mnt/sda1/ ext3 0123 if path1.uid=@uid",
	"allow_chroot /",
	"allow_chroot / if task.uid=123-456",
	"allow_chroot /mnt/ if task.uid=123-456 path1.gid=0",
	"allow_pivot_root / /proc/ if path1.uid!=0",
	"allow_pivot_root /mnt/ /proc/mnt/ if path1.uid!=0 path2.gid=150",
	"allow_unmount / if path1.uid!=0",
	"allow_unmount /proc/ if path1.uid!=0",
	NULL
};

static void domain_policy_test(const unsigned int before)
{
	unsigned int after;
	int j;
	policy_file = "/proc/ccs/domain_policy";
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

static const char * const exception_testcases[] = {
	"allow_read /tmp/mknod_reg_test",
	"allow_env HOME",
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
	"initialize_domain /usr/sbin/sshd",
	"no_initialize_domain /usr/sbin/sshd",
	"initialize_domain /usr/sbin/sshd from /bin/bash",
	"no_initialize_domain /usr/sbin/sshd from /bin/bash",
	"initialize_domain /usr/sbin/sshd from "
	"<kernel> /bin/mingetty/bin/bash",
	"no_initialize_domain /usr/sbin/sshd from "
	"<kernel> /bin/mingetty/bin/bash",
	"keep_domain <kernel> /usr/sbin/sshd /bin/bash",
	"no_keep_domain <kernel> /usr/sbin/sshd /bin/bash",
	"keep_domain /bin/pwd from <kernel> /usr/sbin/sshd /bin/bash",
	"no_keep_domain /bin/pwd from <kernel> /usr/sbin/sshd /bin/bash",
	"keep_domain /bin/pwd from /bin/bash",
	"no_keep_domain /bin/pwd from /bin/bash",
	"file_pattern /proc/\\$/task/\\$/environ",
	"file_pattern /proc/\\$/task/\\$/auxv",
	"allow_read /etc/ld.so.cache",
	"allow_read /proc/meminfo",
	"allow_read /proc/sys/kernel/version",
	"allow_read /etc/localtime",
	"allow_read /proc/self/task/\\$/attr/current",
	"allow_read /proc/self/task/\\$/oom_score",
	"allow_read /proc/self/wchan",
	"allow_read /lib/ld-2.5.so",
	"file_pattern pipe:[\\$]",
	"file_pattern socket:[\\$]",
	"file_pattern /var/cache/logwatch/logwatch.\\*/",
	"file_pattern /var/cache/logwatch/logwatch.\\*/\\*",
	"deny_rewrite /var/log/\\*",
	"deny_rewrite /var/log/\\*/\\*",
	"aggregator /etc/rc.d/rc\\?.d/\\?\\+\\+smb /etc/rc.d/init.d/smb",
	"aggregator /etc/rc.d/rc\\?.d/\\?\\+\\+crond /etc/rc.d/init.d/crond",
	NULL
};

static void exception_policy_test(const unsigned int before)
{
	unsigned int after;
	int j;
	policy_file = "/proc/ccs/exception_policy";
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
	unsigned int before;
	mount("/proc", "/proc/", "proc", 0, NULL);
	get_meminfo(&before);
	domain_policy_test(before);
	exception_policy_test(before);
	BUG("Policy read/write test: Success\n");
	return 0;
}
