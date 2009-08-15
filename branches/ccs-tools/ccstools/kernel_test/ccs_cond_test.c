/*
 * ccs_cond_test.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
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
	fprintf(profile_fp, "255-MAC_FOR_FILE=disabled\n");
	fp = fopen(proc_policy_domain_policy, "r+");
	fprintf(profile_fp, "255-MAC_FOR_FILE=enforcing\n");
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

		snprintf(buffer, sizeof(buffer) - 1, "/etc/fstab");
		try_open("allow_read /etc/fstab ; set task.state[0]=1", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /etc/fstab "
			 "if task.state[0]=0-2 ; set task.state[1]=3", buffer,
			 O_RDONLY, 1);
		try_open("allow_read /etc/fstab "
			 "if task.state[0]=1 task.state[1]=3 "
			 "; set task.state[1]=5", buffer, O_RDONLY, 1);
		try_open("allow_read /etc/fstab if task.state[0]!=1 "
			 "; set task.state[2]=254", buffer, O_RDONLY, 0);
		try_open("allow_read /etc/fstab "
			 "if task.state[0]!=2-255 task.state[1]=5-7 "
			 "; set task.state[2]=10", buffer, O_RDONLY, 1);
		try_open("allow_read /etc/fstab "
			 "if task.state[0]=4-255 task.state[1]=5-7 "
			 "; set task.state[2]=0", buffer, O_RDONLY, 0);
		try_open("allow_read /etc/fstab "
			 "if task.state[0]=1 task.state[1]=0-10 "
			 "task.state[2]!=0-9 ; set task.state[0]=0 "
			 "task.state[1]=0 task.state[2]=0", buffer, O_RDONLY,
			 1);
	}
}

static void try_signal(const char *condition, const unsigned char s0,
		       const unsigned char s1, const unsigned char s2) {
	char buffer[8192];
	int err = 0;
	int fd = open(proc_policy_process_status, O_RDWR);
	char *cp;
	int sig = (rand() % 10000) + 100;
	memset(buffer, 0, sizeof(buffer));
	fprintf(domain_fp, "select pid=%d\n", pid);
	snprintf(buffer, sizeof(buffer) - 1, "allow_signal %d <kernel> %s",
		 sig, condition);
	printf("%s: ", buffer);
	fprintf(domain_fp, "%s\n", buffer);
	errno = 0;
	kill(1, sig);
	err = errno;
	fprintf(domain_fp, "delete %s\n", buffer);
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "info %d\n", pid);
	write(fd, buffer, strlen(buffer));
	buffer[0] = '\0';
	read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	cp = strstr(buffer, " state[0]=");
	if (!cp || atoi(cp + 10) != s0)
		goto out;
	cp = strstr(buffer, " state[1]=");
	if (!cp || atoi(cp + 10) != s1)
		goto out;
	cp = strstr(buffer, " state[2]=");
	if (!cp || atoi(cp + 10) != s2)
		goto out;
	if (err == EINVAL)
		printf("OK. State changed.\n");
	else
		printf("BUG: failed (%d)\n", err);
	return;
 out:
	printf("BUG: state change failed: %s\n", buffer);
}

static void stage_signal_test(void)
{
	int i;
	for (i = 0; i < 5; i++) {
		try_signal("; set task.state[0]=0 task.state[1]=0 "
			   "task.state[2]=1", 0, 0, 1);
		try_signal("if task.state[0]=0 ; set task.state[0]=1", 1, 0, 1);
		try_signal("if task.state[0]=1 ; set task.state[0]=10", 10, 0,
			   1);
		try_signal("if task.state[0]=10 ; set task.state[0]=100", 100,
			   0, 1);
		try_signal("if task.state[0]=100 ; set task.state[1]=100", 100,
			   100, 1);
		try_signal("if task.state[1]=100 ; set task.state[2]=200", 100,
			   100, 200);
	}
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	fprintf(domain_fp, "ignore_global_allow_read\n");
	fprintf(domain_fp, "allow_read/write %s\n", proc_policy_domain_policy);
	fprintf(profile_fp, "255-MAC_FOR_FILE=enforcing\n");
	stage_open_test();
	fprintf(profile_fp, "255-MAC_FOR_FILE=disabled\n");
	fprintf(profile_fp, "255-MAC_FOR_SIGNAL=enforcing\n");
	stage_signal_test();
	fprintf(profile_fp, "255-MAC_FOR_SIGNAL=disabled\n");
	clear_status();
	return 0;
}
