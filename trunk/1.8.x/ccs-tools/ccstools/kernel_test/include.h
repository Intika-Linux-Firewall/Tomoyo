/*
 * include.h
 *
 * Common functions for testing TOMOYO Linux's kernel.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2+   2011/08/20
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
#ifndef CLONE_NEWNS
#include <linux/sched.h>
#endif
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

#define proc_policy_dir              "/proc/ccs/"
#define proc_policy_domain_policy    "/proc/ccs/domain_policy"
#define proc_policy_exception_policy "/proc/ccs/exception_policy"
#define proc_policy_profile          "/proc/ccs/profile"
#define proc_policy_manager          "/proc/ccs/manager"
#define proc_policy_query            "/proc/ccs/query"
#define proc_policy_audit            "/proc/ccs/audit"
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
	static const char * const keywords[] = {
		"file::execute",
		"file::open",
		"file::create",
		"file::unlink",
		"file::getattr",
		"file::mkdir",
		"file::rmdir",
		"file::mkfifo",
		"file::mksock",
		"file::truncate",
		"file::symlink",
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
		"file::unmount",
		"file::pivot_root",
		"misc::env",
		"network::inet_stream_bind",
		"network::inet_stream_listen",
		"network::inet_stream_connect",
		"network::inet_stream_accept",
		"network::inet_dgram_bind",
		"network::inet_dgram_send",
		"network::inet_dgram_recv",
		"network::inet_raw_bind",
		"network::inet_raw_send",
		"network::inet_raw_recv",
		"network::unix_stream_bind",
		"network::unix_stream_listen",
		"network::unix_stream_connect",
		"network::unix_dgram_bind",
		"network::unix_dgram_send",
		"network::unix_seqpacket_bind",
		"network::unix_seqpacket_listen",
		"network::unix_seqpacket_connect",
		"ipc::signal",
		"capability::use_route",
		"capability::use_packet",
		"capability::SYS_REBOOT",
		"capability::SYS_VHANGUP",
		"capability::SYS_TIME",
		"capability::SYS_NICE",
		"capability::SYS_SETHOSTNAME",
		"capability::use_kernel_module",
		"capability::SYS_KEXEC_LOAD",
		"capability::SYS_PTRACE",
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
		fprintf(profile_fp, "255-CONFIG::%s={ mode=disabled "
			"grant_log=no reject_log=no }\n", keywords[i]);
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
			mode = "{ mode=disabled grant_log=no reject_log=no }"
				"\n";
		fprintf(profile_fp, "255-%s=%s", cp, mode);
	}
	/* fprintf(profile_fp, "255-PREFERENCE={ enforcing_penalty=1 }\n"); */
	fprintf(profile_fp, "255-PREFERENCE={ max_learning_entry=2048 }\n");
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
		FILE *fp = fopen("/proc/sys/kernel/osrelease", "r");
		int version = 0;
		if (!fp || (fscanf(fp, "2.%d.", &version) != 1 &&
			    fscanf(fp, "%d.", &version) != 1) || fclose(fp)) {
			fprintf(stderr, "Can't read /proc/sys/kernel/osrelease"
				"\n");
			exit(1);
		}
		if (version == 6 || version == 3)
			is_kernel26 = 1;
	}
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
	fprintf(domain_fp, "file read/write/truncate/getattr "
		"proc:/ccs/domain_policy\n");
	fprintf(domain_fp, "file read/write/truncate/getattr "
		"proc:/ccs/exception_policy\n");
	fprintf(domain_fp, "file read/write/truncate/getattr "
		"proc:/ccs/profile\n");
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

static char *ccs_freadline(FILE *fp)
{
	static char *policy = NULL;
	int pos = 0;
	while (1) {
		static int max_policy_len = 0;
		const int c = fgetc(fp);
		if (c == EOF)
			return NULL;
		if (pos == max_policy_len) {
			char *cp;
			max_policy_len += 4096;
			cp = realloc(policy, max_policy_len);
			if (!cp) {
				BUG("Out of memory");
				exit(1);
			}
			policy = cp;
		}
		policy[pos++] = (char) c;
		if (c == '\n') {
			policy[--pos] = '\0';
			break;
		}
	}
	return policy;
}

static char *ccs_freadline_unpack(FILE *fp)
{
	static char *previous_line = NULL;
	static char *cached_line = NULL;
	static int pack_start = 0;
	static int pack_len = 0;
	if (cached_line)
		goto unpack;
	if (!fp)
		return NULL;
	{
		char *pos;
		unsigned int offset;
		unsigned int len;
		char *line = ccs_freadline(fp);
		if (!line)
			return NULL;
		if (sscanf(line, "acl_group %u", &offset) == 1 && offset < 256)
			pos = strchr(line + 11, ' ');
		else
			pos = NULL;
		if (pos++)
			offset = pos - line;
		else
			offset = 0;
		if (!strncmp(line + offset, "file ", 5)) {
			char *cp = line + offset + 5;
			char *cp2 = strchr(cp + 1, ' ');
			len = cp2 - cp;
			if (cp2 && memchr(cp, '/', len)) {
				pack_start = cp - line;
				goto prepare;
			}
		} else if (!strncmp(line + offset, "network ", 8)) {
			char *cp = strchr(line + offset + 8, ' ');
			char *cp2 = NULL;
			if (cp)
				cp = strchr(cp + 1, ' ');
			if (cp)
				cp2 = strchr(cp + 1, ' ');
			cp++;
			len = cp2 - cp;
			if (cp2 && memchr(cp, '/', len)) {
				pack_start = cp - line;
				goto prepare;
			}
		}
		return line;
prepare:
		pack_len = len;
		cached_line = strdup(line);
		if (!cached_line) {
			BUG("Out of memory");
			exit(1);
		}
	}
unpack:
	{
		char *line = NULL;
		char *pos = cached_line + pack_start;
		char *cp = memchr(pos, '/', pack_len);
		unsigned int len = cp - pos;
		free(previous_line);
		previous_line = NULL;
		if (!cp) {
			previous_line = cached_line;
			cached_line = NULL;
			line = previous_line;
		} else if (pack_len == 1) {
			/* Ignore trailing empty word. */
			free(cached_line);
			cached_line = NULL;
		} else {
			/* Current string is "abc d/e/f ghi". */
			line = strdup(cached_line);
			if (!line) {
				BUG("Out of memory");
				exit(1);
			}
			previous_line = line;
			/* Overwrite "abc d/e/f ghi" with "abc d ghi". */
			memmove(line + pack_start + len, pos + pack_len,
				strlen(pos + pack_len) + 1);
			/* Overwrite "abc d/e/f ghi" with "abc e/f ghi". */
			cp++;
			memmove(pos, cp, strlen(cp) + 1);
			/* Forget "d/" component. */
			pack_len -= len + 1;
			/* Ignore leading and middle empty word. */
			if (!len)
				goto unpack;
		}
		return line;
	}
}

static int write_domain_policy(const char *policy, int is_delete)
{
	char *tmp_policy = strdup(policy);
	if (!tmp_policy) {
		BUG("Out of memory");
		exit(1);
	}
	while (1) {
		FILE *fp = fopen(proc_policy_domain_policy, "r");
		_Bool domain_found = 0;
		_Bool policy_found = 0;
		if (!fp) {
			BUG("Can't read %s", proc_policy_domain_policy);
			return 0;
		}
		{
			char *cp = strrchr(tmp_policy, '\t');
			if (cp)
				*cp++ = '\0';
			else
				cp = tmp_policy;
			policy = cp;
		}
		if (is_delete)
			fprintf(domain_fp, "delete ");
		fprintf(domain_fp, "%s\n", policy);
		while (1) {
			char *line = ccs_freadline_unpack(fp);
			if (!line)
				break;
			if (!strncmp(line, "<kernel>", 8))
				domain_found = !strcmp(self_domain, line);
			if (!domain_found)
				continue;
			/* printf("<%s>\n", buffer); */
			if (strcmp(line, policy))
				continue;
			policy_found = 1;
			while (ccs_freadline_unpack(NULL));
			break;
		}
		fclose(fp);
		if (policy_found == is_delete) {
			BUG("Can't %s %s", is_delete ? "delete" : "append",
			    policy);
			return 0;
		}
		if (policy == tmp_policy)
			break;
	}
	free(tmp_policy);
	errno = 0;
	return 1;

}

static int write_exception_policy(const char *policy, int is_delete)
{
	char *tmp_policy = strdup(policy);
	if (!tmp_policy) {
		BUG("Out of memory");
		exit(1);
	}
	while (1) {
		FILE *fp = fopen(proc_policy_exception_policy, "r");
		_Bool policy_found = 0;
		if (!fp) {
			BUG("Can't read %s", proc_policy_exception_policy);
			return 0;
		}
		{
			char *cp = strrchr(tmp_policy, '\t');
			if (cp)
				*cp++ = '\0';
			else
				cp = tmp_policy;
			policy = cp;
		}
		if (is_delete)
			fprintf(exception_fp, "delete ");
		fprintf(exception_fp, "%s\n", policy);
		while (1) {
			char *line = ccs_freadline_unpack(fp);
			if (!line)
				break;
			if (!strncmp(line, "<kernel> ", 9))
				line += 9;
			/* printf("<%s>\n", buffer); */
			if (strcmp(line, policy))
				continue;
			policy_found = 1;
			while (ccs_freadline_unpack(NULL));
			break;
		}
		fclose(fp);
		if (policy_found == is_delete) {
			BUG("Can't %s %s", is_delete ? "delete" : "append",
			    policy);
			return 0;
		}
		if (policy == tmp_policy)
			break;
	}
	free(tmp_policy);
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
	fprintf(profile_fp, "255-CONFIG::%s={ mode=%s }\n", name, modes[mode]);
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!strncmp(buffer, "<kernel> ", 9))
			memmove(buffer, buffer + 9, strlen(buffer + 9) + 1);
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
		BUG("Can't change profile to 255-CONFIG::%s={ mode=%s }",
		    name, modes[mode]);
		return 0;
	}
	errno = 0;
	return 1;
}
