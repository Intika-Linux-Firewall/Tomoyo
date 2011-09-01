/*
 * include.h
 *
 * Common functions for testing TOMOYO Linux's kernel.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 2.3.0   2010/08/20
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
#include <stdarg.h>

#ifndef __NR_sys_kexec_load
#ifdef __NR_kexec_load
#define __NR_sys_kexec_load  __NR_kexec_load
#endif
#endif
/* #define __NR_sys_kexec_load 283 */

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

#define proc_policy_dir              "/sys/kernel/security/tomoyo/"
#define proc_policy_domain_policy    "/sys/kernel/security/tomoyo/domain_policy"
#define proc_policy_exception_policy "/sys/kernel/security/tomoyo/exception_policy"
#define proc_policy_profile          "/sys/kernel/security/tomoyo/profile"
#define proc_policy_manager          "/sys/kernel/security/tomoyo/manager"
#define proc_policy_query            "/sys/kernel/security/tomoyo/query"
#define proc_policy_grant_log        "/sys/kernel/security/tomoyo/grant_log"
#define proc_policy_reject_log       "/sys/kernel/security/tomoyo/reject_log"
#define proc_policy_domain_status    "/sys/kernel/security/tomoyo/.domain_status"
#define proc_policy_process_status   "/sys/kernel/security/tomoyo/.process_status"
#define proc_policy_self_domain      "/sys/kernel/security/tomoyo/self_domain"

static FILE *profile_fp = NULL;
static FILE *domain_fp = NULL;
static FILE *exception_fp = NULL;
static char self_domain[4096] = "";
static pid_t pid = 0;

static void clear_status(void)
{
	static const char *keywords[] = {
		"file::execute",
		"file::open",
		"file::create",
		"file::unlink",
		"file::mkdir",
		"file::rmdir",
		"file::mkfifo",
		"file::mksock",
		"file::truncate",
		"file::symlink",
		"file::rewrite",
		"file::mkblock",
		"file::mkchar",
		"file::link",
		"file::rename",
		"file::chmod",
		"file::chown",
		"file::chgrp",
		"file::ioctl",
		"file::chroot",
		"file::mount",
		"file::umount",
		"file::pivot_root",
		"misc::env",
		"network::inet_udp_bind",
		"network::inet_udp_connect",
		"network::inet_tcp_bind",
		"network::inet_tcp_listen",
		"network::inet_tcp_connect",
		"network::inet_tcp_accept",
		"network::inet_raw_bind",
		"network::inet_raw_connect",
		"ipc::signal",
		"capability::inet_tcp_create",
		"capability::inet_tcp_listen",
		"capability::inet_tcp_connect",
		"capability::use_inet_udp",
		"capability::use_inet_ip",
		"capability::use_route",
		"capability::use_packet",
		"capability::SYS_MOUNT",
		"capability::SYS_UMOUNT",
		"capability::SYS_REBOOT",
		"capability::SYS_CHROOT",
		"capability::SYS_KILL",
		"capability::SYS_VHANGUP",
		"capability::SYS_TIME",
		"capability::SYS_NICE",
		"capability::SYS_SETHOSTNAME",
		"capability::use_kernel_module",
		"capability::create_fifo",
		"capability::create_block_dev",
		"capability::create_char_dev",
		"capability::create_unix_socket",
		"capability::SYS_LINK",
		"capability::SYS_SYMLINK",
		"capability::SYS_RENAME",
		"capability::SYS_UNLINK",
		"capability::SYS_CHMOD",
		"capability::SYS_CHOWN",
		"capability::SYS_IOCTL",
		"capability::SYS_KEXEC_LOAD",
		"capability::SYS_PIVOT_ROOT",
		"capability::SYS_PTRACE",
		"capability::conceal_mount",
		NULL
	};
	int i;
	FILE *fp = fopen(proc_policy_profile, "r");
	static char buffer[4096];
	if (!fp) {
		fprintf(stderr, "Can't open %s\n", proc_policy_profile);
		exit(1);
	}
	for (i = 0; keywords[i]; i++)
		fprintf(profile_fp,
			"255-CONFIG::%s={ mode=disabled }\n",
			keywords[i]);
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 10, fp)) {
		const char *mode;
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
		fprintf(profile_fp, "255-%s", cp);
		if (!strcmp(cp, "COMMENT"))
			mode = "Profile for kernel test\n";
		else
			mode = "{ mode=disabled verbose=no }\n";
		fprintf(profile_fp, "255-%s=%s", cp, mode);
	}
	/* fprintf(profile_fp, "255-PREFERENCE::enforcing= penalty=1\n"); */
	
	  fprintf(profile_fp, "255-PREFERENCE::learning= verbose=yes\n");
	  fprintf(profile_fp, "255-PREFERENCE::enforcing= verbose=yes\n");
	  fprintf(profile_fp, "255-PREFERENCE::permissive= verbose=yes\n");
	  fprintf(profile_fp, "255-PREFERENCE::disabled= verbose=yes\n");
	  /*
	fprintf(profile_fp, "255-PREFERENCE::learning= verbose=no\n");
	fprintf(profile_fp, "255-PREFERENCE::enforcing= verbose=no\n");
	fprintf(profile_fp, "255-PREFERENCE::permissive= verbose=no\n");
	fprintf(profile_fp, "255-PREFERENCE::disabled= verbose=no\n");
	fprintf(profile_fp, "255-PREFERENCE::learning= max_entry=2048\n");
	  */
	fflush(profile_fp);
	fclose(fp);
}

static void tomoyo_test_init(void)
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
		fprintf(stderr, "Can't open %s .\n",
			proc_policy_domain_policy);
		exit(1);
	}
	setlinebuf(domain_fp);
	exception_fp = fopen(proc_policy_exception_policy, "w");
	if (!exception_fp) {
		fprintf(stderr, "Can't open %s .\n",
			proc_policy_exception_policy);
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
		FILE *fp = fopen(proc_policy_self_domain, "r");
		memset(self_domain, 0, sizeof(self_domain));
		if (!fp || !fgets(self_domain, sizeof(self_domain) - 1, fp) ||
		    fclose(fp)) {
			fprintf(stderr, "Can't open %s .\n",
				proc_policy_self_domain);
			exit(1);
		}
	}
	fprintf(domain_fp, "select pid=%u\n", pid);
	fprintf(domain_fp, "use_profile 255\n");
	fprintf(domain_fp, "allow_read/write /sys/kernel/security/tomoyo/domain_policy\n");
	fprintf(domain_fp, "allow_truncate /sys/kernel/security/tomoyo/domain_policy\n");
	fprintf(domain_fp, "allow_read/write /sys/kernel/security/tomoyo/exception_policy\n");
	fprintf(domain_fp, "allow_truncate /sys/kernel/security/tomoyo/exception_policy\n");
	fprintf(domain_fp, "allow_read/write /sys/kernel/security/tomoyo/profile\n");
	fprintf(domain_fp, "allow_truncate /sys/kernel/security/tomoyo/profile\n");
}

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
	static const char *modes[4] = { "disabled", "learning", "permissive",
					"enforcing" };
	FILE *fp = fopen(proc_policy_profile, "r");
	char buffer[8192];
	int policy_found = 0;
	const int len = strlen(name);
	if (!fp) {
		BUG("Can't read %s", proc_policy_profile);
		return 0;
	}
	fprintf(profile_fp, "255-CONFIG::%s=%s\n", name, modes[mode]);
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (strncmp(buffer, "255-CONFIG::", 12) ||
		    strncmp(buffer + 12, name, len) ||
		    buffer[12 + len] != '=')
			continue;
		if (strstr(buffer + 13 + len, modes[mode]))
			policy_found = 1;
		break;
	}
	fclose(fp);
	if (!policy_found) {
		BUG("Can't change profile to 255-CONFIG::%s=%s",
		    name, modes[mode]);
		return 0;
	}
	errno = 0;
	return 1;
}
