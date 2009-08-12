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

static const char *policy_file = "/proc/ccs/domain_policy";
static const char *policy = NULL;

static void get_meminfo(unsigned int *string, unsigned int *non_string)
{
	FILE *fp = fopen("/proc/ccs/meminfo", "r");
	char buffer[8192];
	if (!fp || !fgets(buffer, sizeof(buffer) - 1, fp) ||
	    sscanf(buffer, "Policy (string): %u", string) != 1 ||
	    !fgets(buffer, sizeof(buffer) - 1, fp) ||
	    sscanf(buffer, "Policy (non-string): %u", non_string) != 1 ||
	    fclose(fp))
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

static const char *testcases[] = {
	"allow_create /tmp/mknod_reg_test",
	"allow_create /tmp/open_test if 0=0",
	"allow_create /tmp/open_test if path1.parent.uid=task.uid",
	"allow_create /tmp/open_test",
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
	"allow_execute /bin/true8 if exec.argv[0]=\"test8\" exec.realpath=\"/bin/true8\"",
	"allow_ioctl socket:[family=2:type=2:protocol=17] 0-35122",
	"allow_ioctl socket:[family=2:type=2:protocol=17] 35122-35124 if task.uid=0",
	"allow_link /tmp/link_source_test /tmp/link_dest_test",
	"allow_mkblock /tmp/mknod_blk_test 1 0",
	"allow_mkchar /tmp/mknod_chr_test 1 3",
	"allow_mkdir /tmp/mkdir_test/",
	"allow_mkfifo /tmp/mknod_fifo_test if path1.parent.perm=01777 path1.parent.perm=sticky path1.parent.uid=0 path1.parent.gid=0",
	"allow_mkfifo /tmp/mknod_fifo_test",
	"allow_mksock /tmp/mknod_sock_test",
	"allow_mksock /tmp/socket_test",
	"allow_read /bin/true if path1.uid=0 path1.parent.uid=0 10=10-100",
	"allow_read /bin/true",
	"allow_read /dev/null if path1.parent.ino=path1.parent.ino",
	"allow_read /dev/null if path1.perm!=0777",
	"allow_read /dev/null if path1.perm=0666",
	"allow_read /dev/null if path1.perm=owner_read path1.perm=owner_write path1.perm!=owner_execute path1.perm=group_read path1.perm=group_write path1.perm!=group_execute path1.perm=others_read path1.perm=others_write path1.perm!=others_execute path1.perm!=setuid path1.perm!=setgid path1.perm!=sticky",
	"allow_read /dev/null if path1.type=char path1.dev_major=1 path1.dev_minor=3",
	"allow_read /dev/null",
	"allow_read /foo",
	"allow_read /proc/sys/net/ipv4/ip_local_port_range if task.uid=0 task.gid=0",
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
	"allow_symlink /tmp/symlink_source_test if symlink.target!=\"/tmp/symlink_\\*_test\"",
	"allow_symlink /tmp/symlink_source_test if symlink.target!=\"\\*\"",
	"allow_symlink /tmp/symlink_source_test if symlink.target=\"/tmp/symlink_\\*_test\"",
	"allow_symlink /tmp/symlink_source_test if task.uid=0 symlink.target=\"/tmp/symlink_\\*_test\"",
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
	"allow_write /proc/sys/net/ipv4/ip_local_port_range if task.euid=0 0=0 1-100=10-1000",
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

int main(int argc, char *argv[]) {
	unsigned int string0;
	unsigned int non_string0;
	unsigned int string1;
	unsigned int non_string1;
	int j;
	mount("/proc", "/proc/", "proc", 0, NULL);
	get_meminfo(&string0, &non_string0);
	for (j = 0; testcases[j]; j++) {
		int i;
		FILE *fp = fopen(policy_file, "w");
		if (!fp)
			BUG("BUG: Policy write error\n");
		fprintf(fp, "<kernel>\n");
		policy = testcases[j];
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
		for (i = 0; i < 30; i++) {
			usleep(100000);
			get_meminfo(&string1, &non_string1);
			if (string0 == string1 && non_string0 == non_string1)
				break;
		}
		if (string0 != string1 || non_string0 != non_string1) {
			printf("string: %d\n", string1 - string0);
			printf("non-string: %d\n", non_string1 - non_string0);
			BUG("Policy read/write test: Fail\n");
		}
	}
	BUG("Policy read/write test: Success\n");
	return 0;
}
