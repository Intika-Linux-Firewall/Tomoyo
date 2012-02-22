/*
 * ccs-init.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
 *
 * This program is executed automatically by kernel
 * when execution of /sbin/init is requested.
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
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <sys/vfs.h>
#include <errno.h>

static void panic(void)
{
	printf("Fatal error while loading policy.\n");
	fflush(stdout);
	while (1)
		sleep(100);
}

#define policy_dir  "/etc/ccs/"
#define proc_policy "/proc/ccs/policy"
static _Bool proc_unmount = 0;

static char buffer[8192];

static void copy_files(const char *src, const char *dest)
{
	int sfd;
	int dfd = open(dest, O_WRONLY);
	if (dfd == EOF) {
		if (errno != ENOENT)
			panic();
		return;
	}
	sfd = open(src, O_RDONLY);
	if (sfd != EOF) {
		while (1) {
			int ret_ignored;
			int len = read(sfd, buffer, sizeof(buffer));
			if (len <= 0)
				break;
			ret_ignored = write(dfd, buffer, len);
		}
		close(sfd);
	}
	close(dfd);
}

static void show_stat(void)
{
	unsigned int acl = 0;
	unsigned int size = -1;
	FILE *fp = fopen(proc_policy, "r");
	if (!fp)
		return;
	while (memset(buffer, 0, sizeof(buffer)) &&
	       fgets(buffer, sizeof(buffer) - 1, fp)) {
		if (!strncmp(buffer, "acl ", 4))
			acl++;
		else if (size == -1)
			sscanf(buffer, "stat Memory used by policy: %u",
			       &size);
	}
	fclose(fp);
	printf("%u ACL entr%s.\n", acl, acl > 1 ? "ies" : "y");
	if (size != -1)
		printf("%u KB used by policy.\n", (size + 1023) / 1024);
}

int main(int argc, char *argv[])
{
	struct stat buf;

	/* Mount /proc if not mounted. */
	if (lstat("/proc/self/", &buf) || !S_ISDIR(buf.st_mode))
		proc_unmount = !mount("/proc", "/proc/", "proc", 0, NULL);

	/*
	 * Open /dev/console if stdio are not connected.
	 *
	 * WARNING: Don't let this program be invoked implicitly
	 * if you are not operating from console.
	 * Otherwise, you will get unable to respond to prompt
	 * if something went wrong.
	 */
	if (access("/proc/self/fd/0", R_OK)) {
		close(0);
		close(1);
		close(2);
		open("/dev/console", O_RDONLY);
		open("/dev/console", O_WRONLY);
		open("/dev/console", O_WRONLY);
	}

	/* Load kernel module if needed. */
	if (lstat("/proc/ccs/", &buf) || !S_ISDIR(buf.st_mode)) {
		if (!access("/etc/ccs/ccs-load-module", X_OK)) {
			const pid_t pid = fork();
			switch (pid) {
			case 0:
				execl("/etc/ccs/ccs-load-module",
				      "/etc/ccs/ccs-load-module", NULL);
				_exit(0);
			case -1:
				panic();
			}
			while (waitpid(pid, NULL, __WALL) == EOF &&
			       errno == EINTR);
		}
	}

	/* Stop if policy interface doesn't exist. */
	if (lstat("/proc/ccs/", &buf) || !S_ISDIR(buf.st_mode)) {
		printf("FATAL: Policy interface does not exist.\n");
		fflush(stdout);
		while (1)
			sleep(100);
	}

	/*
	 * Unmount /proc and execute /sbin/init if this program was executed by
	 * passing init=/sbin/ccs-init . The kernel will try to execute this
	 * program again with getpid() != 1 when /sbin/init starts.
	 */
	if (getpid() == 1) {
		if (proc_unmount)
			umount("/proc/");
		argv[0] = "/sbin/init";
		execv(argv[0], argv);
		printf("FATAL: Failed to execute %s\n", argv[0]);
		fflush(stdout);
		while (1)
			sleep(100);
	}

	/* Load policy. */
	if (!chdir(policy_dir))
		copy_files("policy.conf", proc_policy);

	/* Do additional initialization. */
	if (!access("/etc/ccs/ccs-post-init", X_OK)) {
		const pid_t pid = fork();
		switch (pid) {
		case 0:
			execl("/etc/ccs/ccs-post-init",
			      "/etc/ccs/ccs-post-init", NULL);
			_exit(0);
		case -1:
			panic();
		}
		while (waitpid(pid, NULL, __WALL) == EOF &&
		       errno == EINTR);
	}

	show_stat();

	if (proc_unmount)
		umount("/proc");

	return 0;
}
