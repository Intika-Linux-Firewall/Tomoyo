/*
 * ccs-init.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/24
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
#include <errno.h>

static void panic(void)
{
	printf("Fatal error while loading policy.\n");
	while (1)
		sleep(100);
}

#define policy_dir            "/etc/ccs/"
#define proc_manager          "/proc/ccs/manager"
#define proc_exception_policy "/proc/ccs/exception_policy"
#define proc_domain_policy    "/proc/ccs/domain_policy"
#define proc_profile          "/proc/ccs/profile"
#define proc_meminfo          "/proc/ccs/meminfo"
static const char *profile_name = "default";
static _Bool ccs_noload = 0;
static _Bool ccs_quiet = 0;
static _Bool proc_unmount = 0;
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
		char buffer[1024];
		memset(buffer, 0, sizeof(buffer));
		snprintf(buffer, sizeof(buffer) - 1, "profile-%s.conf",
			 arg + 4);
		profile_name = strdup(buffer);
		if (!profile_name)
			panic();
	} else if (!strcmp(arg, "CCS_NOLOAD"))
		ccs_noload = 1;
	else if (!strcmp(arg, "CCS_QUIET"))
		ccs_quiet = 1;
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
		fgets(input, sizeof(input) - 1, stdin);
		{
			char *cp = strchr(input, '\n');
			if (cp)
				*cp = '\0';
		}
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
				if (!access(buffer, R_OK)) {
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
		if (!strcmp(input, "CCS_NOLOAD"))
			ccs_noload = 1;
		if (!strcmp(input, "CCS_QUIET"))
			ccs_quiet = 1;
	}
}

static void copy_files(const char *src1, const char *src2, const char *dest)
{
	int sfd;
	int dfd = open(dest, O_WRONLY);
	if (dfd == EOF) {
		if (errno != ENOENT)
			panic();
		return;
	}
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
	if (!fp)
		panic();
	for (i = 0; i < 256; i++)
		profile_used[i] = 0;
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp)) {
		if (sscanf(buffer, "use_profile %u", &i) == 1 && i < 256)
			profile_used[i] = 1;
	}
	fclose(fp);
}

static void disable_profile(void)
{
	FILE *fp_out = fopen(proc_profile, "w");
	FILE *fp_in;
	int i;
	if (!fp_out)
		panic();
	scan_used_profile_index();
	for (i = 0; i < 256; i++) {
		if (!profile_used[i])
			continue;
		fprintf(fp_out, "%u-COMMENT=disabled\n", i);
	}
	fclose(fp_out);
	fp_in = fopen(proc_profile, "r");
	fp_out = fopen(proc_profile, "w");
	if (!fp_in || !fp_out)
		panic();
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp_in)) {
		char *cp = strchr(buffer, '=');
		if (!cp)
			continue;
		*cp = '\0';
		fprintf(fp_out, "%s={ mode=disabled }\n", buffer);
	}
	fclose(fp_in);
	fclose(fp_out);
}

static void disable_verbose(void)
{
	unsigned int i;
	FILE *fp = fopen(proc_profile, "w");
	if (!fp)
		panic();
	scan_used_profile_index();
	fprintf(fp, "PREFERENCE::learning={ verbose=disabled }\n");
	fprintf(fp, "PREFERENCE::permissive={ verbose=disabled }\n");
	fprintf(fp, "PREFERENCE::enforcing={ verbose=disabled }\n");
	for (i = 0; i < 256; i++) {
		if (!profile_used[i])
			continue;
		fprintf(fp, "%u-PREFERENCE::learning={ verbose=disabled }\n", i);
		fprintf(fp, "%u-PREFERENCE::permissive={ verbose=disabled }\n", i);
		fprintf(fp, "%u-PREFERENCE::enforcing={ verbose=disabled }\n", i);
	}
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
	printf("%u domain%s. %u ACL entr%s.\n", domain, domain > 1 ? "s" : "",
	       acl, acl > 1 ? "ies" : "y");
}

static void show_memory_usage(void)
{
	FILE *fp = fopen(proc_meminfo, "r");
	if (!fp)
		return;
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp)) {
		unsigned int size;
		if (sscanf(buffer, "Shared: %u", &size) == 1)
			printf("%u KB shared. ", (size + 1023) / 1024);
		else if (sscanf(buffer, "Private: %u", &size) == 1)
			printf("%u KB private. ", (size + 1023) / 1024);
		else if (sscanf(buffer, "Policy: %u", &size) == 1)
			printf("%u KB used by policy.", (size + 1023) / 1024);
	}
	fclose(fp);
	putchar('\n');
}

static void check_profile_version(const char *profile)
{
	const char *files[2] = { "profile.base", profile };
	int i;
	for (i = 0; i < 2; i++) {
		FILE *fp = fopen(files[i], "r");
		if (!fp)
			continue;
		while (memset(buffer, 0, sizeof(buffer)),
		       fgets(buffer, sizeof(buffer) - 1, fp)) {
			char *cp = strchr(buffer, '\n');
			if (cp)
				*cp = '\0';
			if (!strcmp(buffer, "PROFILE_VERSION"))
				break;
			if (strstr(buffer, "MAC_FOR_")) {
				printf("This profile format is not supported."
				       "\n");
				panic();
			}
		}
		fclose(fp);
	}
}

int main(int argc, char *argv[])
{
	struct stat buf;
	
	/* Mount /proc if not mounted. */
	if (lstat("/proc/self/", &buf) || !S_ISDIR(buf.st_mode))
		proc_unmount = !mount("/proc", "/proc/", "proc", 0, NULL);

	/* Unmount /proc and exit if policy interface doesn't exist. */
	if (lstat("/proc/ccs/", &buf) || !S_ISDIR(buf.st_mode)) {
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
		char *cp;
		int i;
		int fd = open("/proc/cmdline", O_RDONLY);
		memset(buffer, 0, sizeof(buffer));
		read(fd, buffer, sizeof(buffer) - 1);
		close(fd);
		cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
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
		copy_files("exception_policy.base", "exception_policy.conf",
			   proc_exception_policy);
		if (!ccs_noload)
			copy_files("domain_policy.base", "domain_policy.conf",
				   proc_domain_policy);
		if (!strcmp(profile_name, "default")) {
			check_profile_version("profile.conf");
			copy_files("profile.base", "profile.conf",
				   proc_profile);
		} else if (strcmp(profile_name, "disable")) {
			check_profile_version(profile_name);
			copy_files("profile.base", profile_name,
				   proc_profile);
		}
		copy_files("meminfo.base", "meminfo.conf", proc_meminfo);
	}

	/* Use disabled mode? */
	if (!strcmp(profile_name, "disable"))
		disable_profile();

	/* Disable verbose mode? */
	if (ccs_quiet)
		disable_verbose();

	/* Do additional initialization. */
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

	show_domain_usage();

	/* Show memory usage. */
	show_memory_usage();

	if (proc_unmount)
		umount("/proc");

	return 0;
}
