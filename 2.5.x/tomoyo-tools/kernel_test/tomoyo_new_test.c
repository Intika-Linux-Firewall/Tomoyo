/*
 * ccs_new_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.5.0   2011/09/29
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
	fprintf(domain_fp, "%s " BINDIR "/true\n", self_domain);
	fprintf(domain_fp, "use_profile 0\n");
	fprintf(domain_fp, "select pid=%u\n", pid);
}

static void cleanup_execute_bin_true(void)
{
	wait(NULL);
	fprintf(domain_fp, "delete %s " BINDIR "/true\n", self_domain);
	fprintf(domain_fp, "select pid=%u\n", pid);
}

static void test_execute_bin_true(void)
{
	char *argv[] = { BINDIR "/true", NULL };
	char *envp[] = { "HOME=/", NULL };
	int pipe_fd[2] = { EOF, EOF };
	int err = 0;
	int ret_ignored;
	ret_ignored = pipe(pipe_fd);
	switch (fork()) {
	case 0:
		execve(BINDIR "/true", argv, envp);
		err = errno;
		ret_ignored = write(pipe_fd[1], &err, sizeof(err));
		_exit(0);
		break;
	case -1:
		err = -ENOMEM;
		break;
	}
	close(pipe_fd[1]);
	ret_ignored = read(pipe_fd[0], &err, sizeof(err));
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
		close(open(buffer, O_APPEND | O_CREAT, 0600));
	}
}


static void setup_all_test_file(void)
{
	int i;
	char buffer[32];
	buffer[31] = '\0';
	for (i = 0; i < 24; i++) {
		snprintf(buffer, sizeof(buffer) - 1, "/tmp/testfile%u", i);
		close(open(buffer, O_WRONLY | O_CREAT, 0600));
		close(open(buffer, O_APPEND | O_CREAT, 0600));
	}
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
	cleanup_file_open();
}

static struct test_struct {
	void (*do_setup) (void);
	void (*do_test) (void);
	void (*do_cleanup) (void);
	const char *name;
	const char *policy;
} tests[] = {
	{ NULL, test_read_etc_fstab, cleanup_file_open, "file::open",
	  "file read /etc/fstab" },
	{ NULL, test_read_etc_fstab, cleanup_file_open, "file::open",
	  "file read /etc/fstab task.uid=0" },
	{ NULL, test_read_etc_fstab, cleanup_file_open, "file::open",
	  "file read /etc/fstab path1.uid=0 path1.parent.uid=0" },
	{ setup_open_group, test_read_etc_fstab, cleanup_open_group,
	  "file::open", "file read @READABLE path1.uid=@READABLE_IDS "
	  "path1.parent.uid=0" },
	{ NULL, test_write_dev_null, cleanup_file_open, "file::open",
	  "file write /dev/null" },
	{ NULL, test_write_dev_null, cleanup_file_open, "file::open",
	  "file write /dev/null task.uid=0" },
	{ NULL, test_write_dev_null, cleanup_file_open, "file::open",
	  "file write /dev/null path1.type=char path1.dev_major=1 "
	  "path1.dev_minor=3 path1.perm=0666" },
	{ cleanup_mkdir_testdir, test_mkdir_testdir, cleanup_mkdir_testdir,
	  "file::mkdir", "file mkdir /tmp/testdir/ 0755" },
	{ cleanup_mkdir_testdir, test_mkdir_testdir, cleanup_mkdir_testdir,
	  "file::mkdir", "file mkdir /tmp/testdir/ 0755 "
	  "path1.parent.uid=0 path1.parent.perm=01777" },
	{ cleanup_mkdir_testdir, test_mkdir_testdir, cleanup_mkdir_testdir,
	  "file::mkdir", "file mkdir /tmp/testdir/ 0755 "
	  "task.uid=path1.parent.uid" },
	{ setup_mkdir_testdir, test_rmdir_testdir, cleanup_mkdir_testdir,
	  "file::rmdir", "file rmdir /tmp/testdir/" },
	{ setup_mkdir_testdir, test_rmdir_testdir, cleanup_mkdir_testdir,
	  "file::rmdir", "file rmdir /tmp/testdir/ path1.parent.uid=0 "
	  "path1.parent.perm=01777" },
	{ setup_mkdir_testdir, test_rmdir_testdir, cleanup_mkdir_testdir,
	  "file::rmdir", "file rmdir /tmp/testdir/ task.uid=0-100 "
	  "task.gid=0x0-0xFF path1.uid=0" },
	{ setup_execute_bin_true, test_execute_bin_true,
	  cleanup_execute_bin_true, "file::execute",
	  "file execute " BINDIR "/true" },
	{ setup_execute_bin_true, test_execute_bin_true,
	  cleanup_execute_bin_true, "file::execute", "file execute " BINDIR "/true "
	  "exec.argc=1 exec.argv[0]=\"" BINDIR "/true\"" },
	{ setup_execute_bin_true, test_execute_bin_true,
	  cleanup_execute_bin_true, "file::execute", "file execute " BINDIR "/true "
	  "exec.envc=1 exec.envp[\"HOME\"]=\"/\" exec.envp[\"PATH\"]=NULL"
	},
	{ NULL, test_chmod_dev_null, NULL, "file::chmod",
	  "file chmod /dev/null 0666 path1.perm=00-07777 path1.type=char"
	},
	{ NULL, test_chown_dev_null, NULL, "file::chown",
	  "file chown /dev/null 0 task.gid=path1.gid path1.type!=block" },
	{ NULL, test_chgrp_dev_null, NULL, "file::chgrp",
	  "file chgrp /dev/null 0 task.uid=path1.parent.uid" },
	{ NULL, test_ioctl_dev_null, NULL, "file::ioctl",
	  "file ioctl /dev/null 0x5451 0=0-1000" },
	{ setup_chmod_group, test_chmod_dev_null, cleanup_chmod_group,
	  "file::chmod", "file chmod @CHMOD_TARGET @CHMOD_MODES" },
	{ setup_chown_group, test_chown_dev_null, cleanup_chown_group,
	  "file::chown", "file chown @CHOWN_TARGET @CHOWN_IDS" },
	{ setup_chown_group, test_chgrp_dev_null, cleanup_chown_group,
	  "file::chgrp", "file chgrp @CHOWN_TARGET @CHOWN_IDS" },
	{ setup_ioctl_group, test_ioctl_dev_null, cleanup_ioctl_group,
	  "file::ioctl", "file ioctl @IOCTL_TARGET @IOCTL_NUMBERS" },
	{ setup_test_file, test_file_open_0, cleanup_test_file, "file::open",
	  "file read /tmp/testfile0 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_1, cleanup_test_file, "file::open",
	  "file read /tmp/testfile1 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_1, cleanup_test_file, "file::create",
	  "file create /tmp/testfile1 0600 task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_2, cleanup_test_file, "file::open",
	  "file read /tmp/testfile2 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_2, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile2 "
	  "task.uid=path1.uid" },
	{ setup_test_file, test_file_open_3, cleanup_test_file,
	  "file::open", "file read /tmp/testfile3 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_3, cleanup_test_file,
	  "file::create", "file create /tmp/testfile3 0600 "
	  "task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_4, cleanup_test_file, "file::open",
	  "file read /tmp/testfile4 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_5, cleanup_test_file, "file::open",
	  "file read /tmp/testfile5 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_5, cleanup_test_file, "file::create",
	  "file create /tmp/testfile5 0600 task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_6, cleanup_test_file, "file::open",
	  "file read /tmp/testfile6 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_6, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile6 "
	  "task.uid=path1.uid" },
	{ setup_test_file, test_file_open_7, cleanup_test_file, "file::open",
	  "file read /tmp/testfile7 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_7, cleanup_test_file, "file::create",
	  "file create /tmp/testfile7 0600 task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_8, cleanup_test_file, "file::open",
	  "file write /tmp/testfile8 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_9, cleanup_test_file, "file::open",
	  "file write /tmp/testfile9 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_9, cleanup_test_file, "file::create",
	  "file create /tmp/testfile9 0600 task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_10, cleanup_test_file, "file::open",
	  "file write /tmp/testfile10 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_10, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile10 "
	  "task.uid=path1.uid" },
	{ setup_test_file, test_file_open_11, cleanup_test_file, "file::open",
	  "file write /tmp/testfile11 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_11, cleanup_test_file,
	  "file::create", "file create /tmp/testfile11 0600 "
	  "task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_12, cleanup_test_file, "file::open",
	  "file append /tmp/testfile12 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_13, cleanup_test_file, "file::open",
	  "file append /tmp/testfile13 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_13, cleanup_test_file,
	  "file::create", "file create /tmp/testfile13 0600 "
	  "task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_14, cleanup_test_file, "file::open",
	  "file append /tmp/testfile14 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_14, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile14 "
	  "task.uid=path1.uid" },
	{ setup_test_file, test_file_open_15, cleanup_test_file, "file::open",
	  "file append /tmp/testfile15 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_15, cleanup_test_file,
	  "file::create", "file create /tmp/testfile15 0600 "
	  "task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_16, cleanup_test_file, "file::open",
	  "file read /tmp/testfile16 task.uid=path1.uid\t"
	  "file write /tmp/testfile16 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_17, cleanup_test_file, "file::open",
	  "file read /tmp/testfile17 task.uid=path1.uid\t"
	  "file write /tmp/testfile17 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_17, cleanup_test_file,
	  "file::create", "file create /tmp/testfile17 0600 "
	  "task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_18, cleanup_test_file, "file::open",
	  "file read /tmp/testfile18 task.uid=path1.uid\t"
	  "file write /tmp/testfile18 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_18, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile18 "
	  "task.uid=path1.uid" },
	{ setup_test_file, test_file_open_19, cleanup_test_file, "file::open",
	  "file read /tmp/testfile19 task.uid=path1.uid\t"
	  "file write /tmp/testfile19 task.uid=path1.uid" },
	{ setup_test_file, test_file_open_19, cleanup_test_file,
	  "file::create", "file create /tmp/testfile19 0600 "
	  "task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_21, cleanup_test_file,
	  "file::create", "file create /tmp/testfile21 0600 "
	  "task.uid=path1.parent.uid" },
	{ setup_test_file, test_file_open_22, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile22 "
	  "task.uid=path1.uid" },
	{ setup_test_file, test_file_open_23, cleanup_test_file,
	  "file::create", "file create /tmp/testfile23 0600 "
	  "task.uid=path1.parent.uid" },
	{ setup_all_test_file, test_file_open_0, cleanup_test_file,
	  "file::open", "file read /tmp/testfile0 task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_2, cleanup_test_file,
	  "file::open", "file read /tmp/testfile2 task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_2, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile2 "
	  "task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_4, cleanup_test_file,
	  "file::open", "file read /tmp/testfile4 task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_6, cleanup_test_file,
	  "file::open", "file read /tmp/testfile6 task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_6, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile6 "
	  "task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_8, cleanup_test_file,
	  "file::open", "file write /tmp/testfile8 task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_10, cleanup_test_file,
	  "file::open", "file write /tmp/testfile10 task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_10, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile10 "
	  "task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_12, cleanup_test_file,
	  "file::open", "file append /tmp/testfile12 task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_14, cleanup_test_file,
	  "file::open", "file append /tmp/testfile14 task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_14, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile14 "
	  "task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_16, cleanup_test_file,
	  "file::open", "file read /tmp/testfile16 task.uid=path1.gid\t"
	  "file write /tmp/testfile16 task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_18, cleanup_test_file,
	  "file::open", "file read /tmp/testfile18 task.uid=path1.gid\t"
	  "file write /tmp/testfile18 task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_18, cleanup_test_file,
	  "file::truncate", "file truncate /tmp/testfile18 "
	  "task.uid=path1.gid" },
	{ setup_all_test_file, test_file_open_22, cleanup_test_file,
	  "file::truncate",
	  "file truncate /tmp/testfile22 task.uid=path1.gid" },
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
