/*
 * ccs-init.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.8   2009/07/11
 *
 * This program is executed automatically by kernel
 * when execution of /sbin/init is requested.
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

static void panic(void)
{
	printf("Fatal error while loading policy.\n");
	exit(1);
}

static unsigned int ccs_version = 168;
static const char *policy_dir = "/etc/ccs/";
static const char *proc_manager = "/proc/ccs/manager";
static const char *proc_system_policy = "/proc/ccs/system_policy";
static const char *proc_exception_policy = "/proc/ccs/exception_policy";
static const char *proc_domain_policy = "/proc/ccs/domain_policy";
static const char *proc_profile = "/proc/ccs/profile";
static const char *proc_meminfo = "/proc/ccs/meminfo";
static const char *profile_name = "default";
static _Bool tomoyo_noload = 0;
static _Bool tomoyo_quiet = 0;
static _Bool proc_unmount = 0;
static _Bool sys_unmount = 0;
static _Bool security_unmount = 0;
static _Bool chdir_ok = 0;

static _Bool profile_used[256];
static char buffer[8192];

static void check_arg(const char *arg)
{
	if (!strcmp(arg, "CCS=ask"))
		profile_name = "ask";
	else if (!strcmp(arg, "CCS=default"))
		profile_name = "default";
	else if (!strcmp(arg, "CCS=disabled"))
		profile_name = "disable";
	else if (!strncmp(arg, "CCS=", 4)) {
		memset(buffer, 0, sizeof(buffer));
		snprintf(buffer, sizeof(buffer) - 1, "profile-%s.conf",
			 arg + 4);
		profile_name = strdup(buffer);
		if (!profile_name)
			panic();
	} else if (!strcmp(arg, "TOMOYO_NOLOAD"))
		tomoyo_noload = 1;
	else if (!strcmp(arg, "TOMOYO_QUIET"))
		tomoyo_quiet = 1;
}

static void ask_profile(void)
{
	static char input[128];
	while (1) {
		printf("TOMOYO Linux: Select a profile from "
		       "the following list.\n");
		if (chdir_ok) {
			/* Show profiles in policy directory. */
			DIR *dir = opendir(".");
			if (!access("profile.conf", R_OK))
				printf("default\n");
			while (1) {
				struct dirent *entry = readdir(dir);
				int len;
				char *name;
				if (!entry)
					break;
				name = entry->d_name;
				if (strncmp(name, "profile-", 8))
					continue;
				if (!strcmp(name, "profile-default.conf") ||
				    !strcmp(name, "profile-disable.conf"))
					continue;
				len = strlen(name);
				if (len > 13 &&
				    !strcmp(name + len - 5, ".conf")) {
					int i;
					for (i = 8; i < len - 5; i++)
						putchar(name[i]);
					putchar('\n');
				}
			}
			closedir(dir);
		}
		printf("disable\n");
		profile_name = "";
		printf("> ");
		memset(input, 0, sizeof(input));
		scanf(input, sizeof(input) - 1);
		if (chdir_ok) {
			if (!strcmp(input, "default")) {
				if (!access("profile.conf", R_OK)) {
					profile_name = "default";
					break;
				}
			} else if (strcmp(input, "disable")) {
				memset(buffer, 0, sizeof(buffer));
				snprintf(buffer, sizeof(buffer) - 1,
					 "profile-%s.conf", input);
				if (!access(profile_name, R_OK)) {
					profile_name = strdup(buffer);
					if (!profile_name)
						panic();
					break;
				}
			}
		}
		if (!strcmp(input, "disable")) {
			profile_name = "disable";
			break;
		}
		if (!strcmp(input, "TOMOYO_NOLOAD"))
			tomoyo_noload = 1;
		if (!strcmp(input, "TOMOYO_QUIET"))
			tomoyo_quiet = 1;
	}
}

static void copy_files(const char *src1, const char *src2, const char *dest)
{
	int sfd;
	int dfd = open(dest, O_WRONLY);
	if (dfd == EOF)
		return;
	sfd = open(src1, O_RDONLY);
	if (sfd != EOF) {
		while (1) {
			int len = read(sfd, buffer, sizeof(buffer));
			if (len <= 0)
				break;
			write(dfd, buffer, len);
		}
		close(sfd);
		write(dfd, "\n", 1);
	}
	sfd = open(src2, O_RDONLY);
	if (sfd != EOF) {
		while (1) {
			int len = read(sfd, buffer, sizeof(buffer));
			if (len <= 0)
				break;
			write(dfd, buffer, len);
		}
		close(sfd);
	}
	close(dfd);
}

static void scan_used_profile_index(void)
{
	static _Bool checked = 0;
	unsigned int i;
	FILE *fp;
	if (checked)
		return;
	checked = 1;
	fp = fopen(proc_domain_policy, "r");
	if (fp) {
		for (i = 0; i < 256; i++)
			profile_used[i] = 0;
		while (memset(buffer, 0, sizeof(buffer)),
		       fgets(buffer, sizeof(buffer) - 1, fp)) {
			if (sscanf(buffer, "use_profile %u", &i) == 1 &&
			    i < 256)
				profile_used[i] = 1;
		}
		fclose(fp);
	} else {
		for (i = 0; i < 256; i++)
			profile_used[i] = 1;
	}
}

static void disable_profile(void)
{
	FILE *fp_out = fopen(proc_profile, "w");
	FILE *fp_in;
	int i;
	scan_used_profile_index();
	for (i = 0; i < 256; i++) {
		if (!profile_used[i])
			continue;
		fprintf(fp_out, "%u-COMMENT=disabled\n", i);
	}
	fclose(fp_out);
	fp_in = fopen(proc_profile, "r");
	fp_out = fopen(proc_profile, "w");
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp_in)) {
		unsigned int count;
		char *cp = strchr(buffer, '=');
		if (!cp)
			continue;
		*cp++ = '\0';
		if (sscanf(cp, "%u", &count) == 1) {
			if (count)
				fprintf(fp_out, "%s=0\n", buffer);
		} else if (strcmp(cp, "disabled")) {
			fprintf(fp_out, "%s=disabled\n", buffer);
		}
	}
	fclose(fp_in);
	fclose(fp_out);
}

static void disable_verbose(void)
{
	unsigned int i;
	FILE *fp = fopen(proc_profile, "w");
	if (!fp)
		return;
	scan_used_profile_index();
	for (i = 0; i < 256; i++)
		if (profile_used[i])
			fprintf(fp, "%u-TOMOYO_VERBOSE=disabled\n", i);
	fclose(fp);
}

static void show_domain_usage(void)
{
	unsigned int domain = 0;
	unsigned int acl = 0;
	FILE *fp = fopen(proc_domain_policy, "r");
	if (!fp)
		return;
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp)) {
		if (!strncmp(buffer, "<kernel>", 8))
			domain++;
		else if (buffer[0] && strcmp(buffer, "use_profile"))
			acl++;
	}
	fclose(fp);
	printf("%u domains. %u ACL entries.\n", domain, acl);
}

static void show_memory_usage(void)
{
	unsigned int shared_mem = 0;
	unsigned int private_mem = 0;
	FILE *fp = fopen(proc_meminfo, "r");
	if (!fp)
		return;
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp)) {
		unsigned int size;
		if (sscanf(buffer, "Shared: %u", &size) == 1)
			shared_mem = size;
		else if (sscanf(buffer, "Private: %u", &size) == 1)
			private_mem = size;
	}
	fclose(fp);
	printf("%u KB shared. %u KB private.\n", shared_mem, private_mem);
}

static _Bool mount_securityfs(void)
{
	struct stat buf;
	/* Mount /sys if not mounted. */
	if (lstat("/sys/kernel/", &buf) || !S_ISDIR(buf.st_mode))
		sys_unmount = !mount("/sys", "/sys", "sysfs", 0, NULL);
	/* Mount /sys/kernel/security if not mounted. */
	if (lstat("/sys/kernel/security/", &buf) || !S_ISDIR(buf.st_mode))
		security_unmount = !mount("none", "/sys/kernel/security",
					  "securityfs", 0, NULL);
	/* Unmount and exit if policy interface doesn't exist. */
	if (lstat("/sys/kernel/security/tomoyo", &buf) ||
	    !S_ISDIR(buf.st_mode)) {
		if (security_unmount)
			umount("/sys/kernel/security/");
		if (sys_unmount)
			umount("/sys/");
		return 0;
	}
	/*
	 * Use /etc/tomoyo/ instead of /etc/ccs/ and
	 * /sys/kernel/security/tomoyo/ instead of /proc/ccs/ .
	 */
	policy_dir = "/etc/tomoyo/";
	proc_manager = "/sys/kernel/security/tomoyo/manager";
	proc_system_policy = NULL;
	proc_exception_policy = "/sys/kernel/security/tomoyo/exception_policy";
	proc_domain_policy = "/sys/kernel/security/tomoyo/domain_policy";
	proc_profile = "/sys/kernel/security/tomoyo/profile";
	proc_meminfo = "/sys/kernel/security/tomoyo/meminfo";
	ccs_version = 220;
	return 1;
}

int main(int argc, char *argv[])
{
	struct stat buf;
	
	/* Mount /proc if not mounted. */
	if (lstat("/proc/self/", &buf) || !S_ISDIR(buf.st_mode))
		proc_unmount = !mount("/proc", "/proc/", "proc", 0, NULL);
	
	/* Unmount /proc and exit if policy interface doesn't exist. */
	if ((lstat("/proc/ccs/", &buf) || !S_ISDIR(buf.st_mode)) &&
	    !mount_securityfs()) {
		if (proc_unmount)
			umount("/proc/");
		return 1;
	}

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
	
	/* Check /proc/cmdline and /proc/self/cmdline */
	{
		int i;
		int fd = open("/proc/cmdline", O_RDONLY);
		memset(buffer, 0, sizeof(buffer));
		read(fd, buffer, sizeof(buffer) - 1);
		close(fd);
		while (1) {
			char *cp = strchr(buffer, ' ');
			if (cp)
				*cp = '\0';
			check_arg(buffer);
			if (!cp)
				break;
			cp++;
			memmove(buffer, cp, strlen(cp) + 1);
		}
		for (i = 1; i < argc; i++)
			check_arg(argv[i]);
	}

	/* Does policy directory exist? */
	if (!chdir(policy_dir))
		chdir_ok = 1;
	else
		profile_name = "disable";

	/* Does selected profile exist? */
	if (chdir_ok) {
		if (!strcmp(profile_name, "default")) {
			if (access("profile.conf", R_OK)) {
				printf("TOMOYO Linux: Default profile "
				       "doesn't exist.\n");
				profile_name = "ask";
			}
		} else if (strcmp(profile_name, "ask") &&
			   strcmp(profile_name, "disable")) {
			if (access(profile_name, R_OK)) {
				printf("TOMOYO Linux: Specified profile "
				       "doesn't exist.\n");
				profile_name = "ask";
			}
		}
	}

	/* Show prompt if something went wrong or explicitly asked. */
	if (!strcmp(profile_name, "ask"))
		ask_profile();

	/* Load policy. */
	if (chdir_ok) {
		copy_files("manager.base", "manager.conf", proc_manager);
		if (ccs_version < 170)
			copy_files("system_policy.base", "system_policy.conf",
				   proc_system_policy);
		copy_files("exception_policy.base", "exception_policy.conf",
			   proc_exception_policy);
		if (!tomoyo_noload)
			copy_files("domain_policy.base", "domain_policy.conf",
				   proc_domain_policy);
		if (!strcmp(profile_name, "default"))
			copy_files("profile.base", "profile.conf",
				   proc_profile);
		else if (strcmp(profile_name, "disable"))
			copy_files("profile.base", profile_name,
				   proc_profile);
		copy_files("meminfo.base", "meminfo.conf", proc_meminfo);
	}

	/* Use disabled mode? */
	if (!strcmp(profile_name, "disable"))
		disable_profile();

	/* Disable verbose mode? */
	if (tomoyo_quiet)
		disable_verbose();

	/* Do additional initialization. */
	if (ccs_version < 200) {
		if (!access("/etc/ccs/ccs-post-init", X_OK)) {
			switch (fork()) {
			case 0:
				execl("/etc/ccs/ccs-post-init",
				      "/etc/ccs/ccs-post-init", NULL);
				_exit(0);
			case -1:
				panic();
			}
			wait(NULL);
		}
	} else {
		if (!access("/etc/tomoyo/tomoyo-post-init", X_OK)) {
			switch (fork()) {
			case 0:
				execl("/etc/tomoyo/tomoyo-post-init",
				      "/etc/tomoyo/tomoyo-post-init", NULL);
				_exit(0);
			case -1:
				panic();
			}
			wait(NULL);
		}
	}

	show_domain_usage();

	/* Show memory usage. */
	show_memory_usage();

	if (proc_unmount)
		umount("/proc");

	return 0;
}
