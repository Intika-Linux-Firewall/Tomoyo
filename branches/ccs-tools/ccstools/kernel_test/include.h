/*
 * include.h
 *
 * Common functions for testing TOMOYO Linux's kernel.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/kdev_t.h>
struct module;
#include <linux/reboot.h>
#include <linux/unistd.h>
#include <netinet/in.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <linux/ip.h>
#include <sched.h>
#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifndef __NR_sys_kexec_load
#ifdef __NR_kexec_load
#define __NR_sys_kexec_load  __NR_kexec_load
#endif
#endif

static inline pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
static inline int uselib(const char *library)
{
	return syscall(__NR_uselib, library);
}
static inline caddr_t create_module(const char *name, size_t size)
{
	return (caddr_t) syscall(__NR_create_module, name, size);
}
static inline int pivot_root(const char *new_root, const char *put_old)
{
	return syscall(__NR_pivot_root, new_root, put_old);
}
static inline int tkill(int tid, int sig)
{
	return syscall(__NR_tkill, tid, sig);
}
#ifdef __NR_tgkill
static inline int tgkill(int tgid, int tid, int sig)
{
	return syscall(__NR_tgkill, tgid, tid, sig);
}
#endif
#ifdef __NR_sys_kexec_load
struct kexec_segment;
static inline long sys_kexec_load(unsigned long entry,
				  unsigned long nr_segments,
				  struct kexec_segment *segments,
				  unsigned long flags)
{
	return (long) syscall(__NR_sys_kexec_load, entry, nr_segments,
			      segments, flags);
}
#endif
/* reboot() in glibc takes just one argument. */
int reboot(int cmd);
int init_module(const char *name, struct module *image);
int delete_module(const char *name);

#define proc_policy_dir              "/proc/ccs/"
#define proc_policy_domain_policy    "/proc/ccs/domain_policy"
#define proc_policy_exception_policy "/proc/ccs/exception_policy"
#define proc_policy_profile          "/proc/ccs/profile"
#define proc_policy_manager          "/proc/ccs/manager"
#define proc_policy_query            "/proc/ccs/query"
#define proc_policy_grant_log        "/proc/ccs/grant_log"
#define proc_policy_reject_log       "/proc/ccs/reject_log"
#define proc_policy_domain_status    "/proc/ccs/.domain_status"
#define proc_policy_process_status   "/proc/ccs/.process_status"
#define proc_policy_self_domain      "/proc/ccs/self_domain"

static FILE *profile_fp = NULL;
static FILE *domain_fp = NULL;
static FILE *exception_fp = NULL;
static char self_domain[4096] = "";
static int is_kernel26 = 0;
static pid_t pid = 0;

static void clear_status(void)
{
	FILE *fp = fopen(proc_policy_profile, "r");
	static char buffer[4096];
	if (!fp) {
		fprintf(stderr, "Can't open %s\n", proc_policy_profile);
		exit(1);
	}
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 10, fp)) {
		const char *mode;
		int v;
		char *cp = strchr(buffer, '=');
		if (!cp)
			continue;
		*cp = '\0';
		mode = cp + 1;
		cp = strchr(buffer, '-');
		if (!cp)
			continue;
		*cp++ = '\0';
		if (strcmp(buffer, "0"))
			continue;
		/*
		  if (strcmp(cp, "TOMOYO_VERBOSE") == 0)
		  continue;
		*/
		fprintf(profile_fp, "255-%s", cp);
		if (!strcmp(cp, "COMMENT"))
			mode = "Profile for kernel test\n";
		else if (sscanf(mode, "%u", &v) == 1)
			mode = "0\n";
		else if (!strcmp(cp, "MAC_MODE_LEARNING") ||
			 !strcmp(cp, "MAC_MODE_PERMISSIVE") ||
			 !strcmp(cp, "MAC_MODE_ENFORCING"))
			cp = "MAC_MODE_DISABLED";
		else if (!strcmp(cp, "MAC_MODE_CAPABILITY_LEARNING") ||
			 !strcmp(cp, "MAC_MODE_CAPABILITY_PERMISSIVE") ||
			 !strcmp(cp, "MAC_MODE_CAPABILITY_ENFORCING"))
			cp = "MAC_MODE_CAPABILITY_DISABLED";
		else
			mode = "disabled\n";
		fprintf(profile_fp, "255-%s=%s", cp, mode);
	}
	/* fprintf(profile_fp, "255-SLEEP_PERIOD=1\n"); */
	/* fprintf(profile_fp, "255-TOMOYO_VERBOSE=enabled\n"); */
	fprintf(profile_fp, "255-MAX_ACCEPT_ENTRY=2048\n");
	fflush(profile_fp);
	fclose(fp);
}

static void ccs_test_init(void)
{
	pid = getpid();
	if (access(proc_policy_dir, F_OK)) {
		fprintf(stderr, "You can't use this program for this kernel."
			"\n");
		exit(1);
	}
	profile_fp = fopen(proc_policy_profile, "w");
	if (!profile_fp) {
		fprintf(stderr, "Can't open %s .\n", proc_policy_profile);
		exit(1);
	}
	setlinebuf(profile_fp);
	domain_fp = fopen(proc_policy_domain_policy, "w");
	if (!domain_fp) {
		fprintf(stderr, "Can't open %s .\n", proc_policy_domain_policy);
		exit(1);
	}
	setlinebuf(domain_fp);
	exception_fp = fopen(proc_policy_exception_policy, "w");
	if (!exception_fp) {
		fprintf(stderr, "Can't open %s .\n", proc_policy_exception_policy);
		exit(1);
	}
	setlinebuf(exception_fp);
	if (fputc('\n', profile_fp) != '\n' || fflush(profile_fp)) {
		fprintf(stderr, "You need to register this program to %s to "
			"run this program.\n", proc_policy_manager);
		exit(1);
	}
	clear_status();
	{
		FILE *fp = fopen("/proc/sys/kernel/osrelease", "r");
		int version = 0;
		if (!fp || fscanf(fp, "2.%d.", &version) != 1 || fclose(fp)) {
			fprintf(stderr, "Can't read /proc/sys/kernel/osrelease"
				"\n");
			exit(1);
		}
		if (version == 6)
			is_kernel26 = 1;
	}
	{
		FILE *fp = fopen(proc_policy_self_domain, "r");
		memset(self_domain, 0, sizeof(self_domain));
		if (!fp || !fgets(self_domain, sizeof(self_domain) - 1, fp) ||
		    fclose(fp)) {
			fprintf(stderr, "Can't open %s .\n", proc_policy_self_domain);
			exit(1);
		}
	}
	fprintf(domain_fp, "select pid=%u\n", pid);
	fprintf(domain_fp, "use_profile 255\n");
	fprintf(domain_fp, "allow_read/write /proc/ccs/domain_policy\n");
	fprintf(domain_fp, "allow_truncate /proc/ccs/domain_policy\n");
	fprintf(domain_fp, "allow_read/write /proc/ccs/profile\n");
	fprintf(domain_fp, "allow_truncate /proc/ccs/profile\n");
}
