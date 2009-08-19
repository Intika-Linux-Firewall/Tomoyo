#include "include.h"
#include <stdarg.h>

static void BUG(const char *fmt, ...)
	__attribute__ ((format(printf, 1, 2)));

static void BUG(const char *fmt, ...)
{
	va_list args;
	printf("BUG: ");
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	putchar('\n');
	fflush(stdout);
	while (1)
		sleep(100);
}

static int write_domain_policy(const char *policy, int is_delete)
{
	FILE *fp = fopen(proc_policy_domain_policy, "r");
	char buffer[8192];
	int domain_found = 0;
	int policy_found = 0;
	memset(buffer, 0, sizeof(buffer));
	if (!fp) {
		BUG("Can't read %s", proc_policy_domain_policy);
		return 0;
	}
	if (is_delete)
		fprintf(domain_fp, "delete ");
	fprintf(domain_fp, "%s\n", policy);
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!strncmp(buffer, "<kernel>", 8))
			domain_found = !strcmp(self_domain, buffer);
		if (!domain_found)
			continue;
		/* printf("<%s>\n", buffer); */
		if (strcmp(buffer, policy))
			continue;
		policy_found = 1;
		break;
	}
	fclose(fp);
	if (policy_found == is_delete) {
		BUG("Can't %s %s", is_delete ? "delete" : "append",
		    policy);
		return 0;
	}
	errno = 0;
	return 1;

}

static int write_exception_policy(const char *policy, int is_delete)
{
	FILE *fp = fopen(proc_policy_exception_policy, "r");
	char buffer[8192];
	int policy_found = 0;
	memset(buffer, 0, sizeof(buffer));
	if (!fp) {
		BUG("Can't read %s", proc_policy_exception_policy);
		return 0;
	}
	if (is_delete)
		fprintf(exception_fp, "delete ");
	fprintf(exception_fp, "%s\n", policy);
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
	if (policy_found == is_delete) {
		BUG("Can't %s %s", is_delete ? "delete" : "append",
		    policy);
		return 0;
	}
	errno = 0;
	return 1;

}

static int set_profile(const int mode, const char *name)
{
	static const char *modes[4] = { "DISABLED", "LEARNING", "PERMISSIVE", "ENFORCING" };
	FILE *fp = fopen(proc_policy_profile, "r");
	char buffer[8192];
	int policy_found = 0;
	const int len = strlen(modes[mode]);
	if (!fp) {
		BUG("Can't read %s", proc_policy_profile);
		return 0;
	}
	fprintf(profile_fp, "255-MAC_MODE_%s=%s\n", modes[mode], name);
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (strncmp(buffer, "255-MAC_MODE_", 13) ||
		    strncmp(buffer + 13, modes[mode], len) ||
		    buffer[13 + len] != '=')
			continue;
		if (strstr(buffer + 14 + len, name))
			policy_found = 1;
		break;
	}
	fclose(fp);
	if (!policy_found) {
		BUG("Can't change profile to 255-MAC_MODE_%s=%s",
		    modes[mode], name);
		return 0;
	}
	errno = 0;
	return 1;
}

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
	result = open("/tmp/testfile7", O_APPEND | O_TRUNC | O_CREAT | O_RDONLY, 0600);
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
	result = open("/tmp/testfile15", O_APPEND | O_TRUNC | O_CREAT | O_WRONLY, 0600);
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
	result = open("/tmp/testfile23", O_APPEND | O_TRUNC | O_CREAT | O_RDWR, 0600);
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
	set_profile(3, "truncate");
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
	set_profile(3, "truncate");
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
	set_profile(0, "truncate");
}

static struct test_struct {
	void (*do_setup) (void);
	void (*do_test) (void);
	void (*do_cleanup) (void);
	const char *name;
	const char *policy;
} tests[] = {
	{ NULL, test_read_etc_fstab, cleanup_file_open, "open", "allow_read /etc/fstab" },
	{ NULL, test_read_etc_fstab, cleanup_file_open, "open", "allow_read /etc/fstab if task.uid=0" },
	{ NULL, test_read_etc_fstab, cleanup_file_open, "open", "allow_read /etc/fstab if path1.uid=0 path1.parent.uid=0" },
	{ setup_open_group, test_read_etc_fstab, cleanup_open_group, "open", "allow_read @READABLE if path1.uid=@READABLE_IDS path1.parent.uid=0" },
	{ NULL, test_write_dev_null, cleanup_file_open, "open", "allow_write /dev/null" },
	{ NULL, test_write_dev_null, cleanup_file_open, "open", "allow_write /dev/null if task.uid=0" },
	{ NULL, test_write_dev_null, cleanup_file_open, "open", "allow_write /dev/null if path1.type=char path1.dev_major=1 path1.dev_minor=3 path1.perm=0666" },
	{ cleanup_mkdir_testdir, test_mkdir_testdir, cleanup_mkdir_testdir, "mkdir", "allow_mkdir /tmp/testdir/ 0755" },
	{ cleanup_mkdir_testdir, test_mkdir_testdir, cleanup_mkdir_testdir, "mkdir", "allow_mkdir /tmp/testdir/ 0755 if path1.parent.uid=0 path1.parent.perm=01777" },
	{ cleanup_mkdir_testdir, test_mkdir_testdir, cleanup_mkdir_testdir, "mkdir", "allow_mkdir /tmp/testdir/ 0755 if task.uid=path1.parent.uid" },
	{ setup_mkdir_testdir, test_rmdir_testdir, cleanup_mkdir_testdir, "rmdir", "allow_rmdir /tmp/testdir/" },
	{ setup_mkdir_testdir, test_rmdir_testdir, cleanup_mkdir_testdir, "rmdir", "allow_rmdir /tmp/testdir/ if path1.parent.uid=0 path1.parent.perm=01777" },
	{ setup_mkdir_testdir, test_rmdir_testdir, cleanup_mkdir_testdir, "rmdir", "allow_rmdir /tmp/testdir/ if task.uid=0-100 task.gid=0x0-0xFF path1.uid=0" },
	{ setup_execute_bin_true, test_execute_bin_true, cleanup_execute_bin_true, "execute", "allow_execute /bin/true" },
	{ setup_execute_bin_true, test_execute_bin_true, cleanup_execute_bin_true, "execute", "allow_execute /bin/true if exec.argc=1 exec.argv[0]=\"/bin/true\"" },
	{ setup_execute_bin_true, test_execute_bin_true, cleanup_execute_bin_true, "execute", "allow_execute /bin/true if exec.envc=1 exec.envp[\"HOME\"]=\"/\" exec.envp[\"PATH\"]=NULL" },
	{ NULL, test_chmod_dev_null, NULL, "chmod", "allow_chmod /dev/null 0666 if path1.perm=00-07777 path1.type=char" },
	{ NULL, test_chown_dev_null, NULL, "chown", "allow_chown /dev/null 0 if task.gid=path1.gid path1.type!=block" },
	{ NULL, test_chgrp_dev_null, NULL, "chgrp", "allow_chgrp /dev/null 0 if task.uid=path1.parent.uid" },
	{ NULL, test_ioctl_dev_null, NULL, "ioctl", "allow_ioctl /dev/null 0x5451 if 0=0-1000" },
	{ setup_chmod_group, test_chmod_dev_null, cleanup_chmod_group, "chmod", "allow_chmod @CHMOD_TARGET @CHMOD_MODES" },
	{ setup_chown_group, test_chown_dev_null, cleanup_chown_group, "chown", "allow_chown @CHOWN_TARGET @CHOWN_IDS" },
	{ setup_chown_group, test_chgrp_dev_null, cleanup_chown_group, "chgrp", "allow_chgrp @CHOWN_TARGET @CHOWN_IDS" },
	{ setup_ioctl_group, test_ioctl_dev_null, cleanup_ioctl_group, "ioctl", "allow_ioctl @IOCTL_TARGET @IOCTL_NUMBERS" },
	{ setup_test_file, test_file_open_0, cleanup_test_file, "open", "allow_read /tmp/testfile0 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_1, cleanup_test_file, "open", "allow_read /tmp/testfile1 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_1, cleanup_test_file, "create", "allow_create /tmp/testfile1 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_2, cleanup_test_file, "open", "allow_read /tmp/testfile2 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_2, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile2 if task.uid=path1.uid" },
	{ setup_test_file_truncate, test_file_open_2, cleanup_test_file_truncate, "rewrite", "allow_rewrite /tmp/testfile2 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_3, cleanup_test_file, "open", "allow_read /tmp/testfile3 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_3, cleanup_test_file, "create", "allow_create /tmp/testfile3 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_4, cleanup_test_file, "open", "allow_read /tmp/testfile4 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_5, cleanup_test_file, "open", "allow_read /tmp/testfile5 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_5, cleanup_test_file, "create", "allow_create /tmp/testfile5 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_6, cleanup_test_file, "open", "allow_read /tmp/testfile6 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_6, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile6 if task.uid=path1.uid" },
	{ setup_test_file_truncate, test_file_open_6, cleanup_test_file_truncate, "rewrite", "allow_rewrite /tmp/testfile6 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_7, cleanup_test_file, "open", "allow_read /tmp/testfile7 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_7, cleanup_test_file, "create", "allow_create /tmp/testfile7 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_8, cleanup_test_file, "open", "allow_write /tmp/testfile8 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_8, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile8 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_9, cleanup_test_file, "open", "allow_write /tmp/testfile9 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_9, cleanup_test_file, "create", "allow_create /tmp/testfile9 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_9, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile9 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_10, cleanup_test_file, "open", "allow_write /tmp/testfile10 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_10, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile10 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_10, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile10 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_11, cleanup_test_file, "open", "allow_write /tmp/testfile11 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_11, cleanup_test_file, "create", "allow_create /tmp/testfile11 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_11, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile11 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_12, cleanup_test_file, "open", "allow_write /tmp/testfile12 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_13, cleanup_test_file, "open", "allow_write /tmp/testfile13 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_13, cleanup_test_file, "create", "allow_create /tmp/testfile13 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_14, cleanup_test_file, "open", "allow_write /tmp/testfile14 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_14, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile14 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_14, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile14 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_15, cleanup_test_file, "open", "allow_write /tmp/testfile15 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_15, cleanup_test_file, "create", "allow_create /tmp/testfile15 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_16, cleanup_test_file, "open", "allow_read/write /tmp/testfile16 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_16, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile16 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_17, cleanup_test_file, "open", "allow_read/write /tmp/testfile17 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_17, cleanup_test_file, "create", "allow_create /tmp/testfile17 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_17, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile17 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_18, cleanup_test_file, "open", "allow_read/write /tmp/testfile18 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_18, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile18 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_18, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile18 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_19, cleanup_test_file, "open", "allow_read/write /tmp/testfile19 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_19, cleanup_test_file, "create", "allow_create /tmp/testfile19 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_19, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile19 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_20, cleanup_test_file, "open", "allow_read/write /tmp/testfile20 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_21, cleanup_test_file, "open", "allow_read/write /tmp/testfile21 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_21, cleanup_test_file, "create", "allow_create /tmp/testfile21 0600 if task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_22, cleanup_test_file, "open", "allow_read/write /tmp/testfile22 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_22, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile22 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_22, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile22 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_23, cleanup_test_file, "open", "allow_read/write /tmp/testfile23 if task.uid=path1.uid" },
	{ setup_test_file, test_file_open_23, cleanup_test_file, "create", "allow_create /tmp/testfile23 0600 if task.uid=path1.parent.uid" },
	{ setup_all_test_file, test_file_open_0, cleanup_test_file, "open", "allow_read /tmp/testfile0 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_2, cleanup_test_file, "open", "allow_read /tmp/testfile2 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_2, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile2 if task.uid=path1.gid" },
	{ setup_all_test_file_truncate, test_file_open_2, cleanup_test_file_truncate, "rewrite", "allow_rewrite /tmp/testfile2 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_4, cleanup_test_file, "open", "allow_read /tmp/testfile4 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_6, cleanup_test_file, "open", "allow_read /tmp/testfile6 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_6, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile6 if task.uid=path1.gid" },
	{ setup_all_test_file_truncate, test_file_open_6, cleanup_test_file_truncate, "rewrite", "allow_rewrite /tmp/testfile6 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_8, cleanup_test_file, "open", "allow_write /tmp/testfile8 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_8, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile8 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_10, cleanup_test_file, "open", "allow_write /tmp/testfile10 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_10, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile10 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_10, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile10 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_12, cleanup_test_file, "open", "allow_write /tmp/testfile12 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_14, cleanup_test_file, "open", "allow_write /tmp/testfile14 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_14, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile14 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_14, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile14 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_16, cleanup_test_file, "open", "allow_read/write /tmp/testfile16 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_16, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile16 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_18, cleanup_test_file, "open", "allow_read/write /tmp/testfile18 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_18, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile18 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_18, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile18 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_20, cleanup_test_file, "open", "allow_read/write /tmp/testfile20 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_22, cleanup_test_file, "open", "allow_read/write /tmp/testfile22 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_22, cleanup_test_file, "truncate", "allow_truncate /tmp/testfile22 if task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_22, cleanup_test_file, "rewrite", "allow_rewrite /tmp/testfile22 if task.uid=path1.gid" },
	{ NULL }
};

int main(int argc, char *argv[])
{
	int i;
	ccs_test_init();
	//fprintf(profile_fp, "255-PRINT_VIOLATION=enabled\n");
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
	return 0;
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
