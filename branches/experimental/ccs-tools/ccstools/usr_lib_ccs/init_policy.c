/*
 * init_policy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3+   2011/10/25
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
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <sys/vfs.h>
#include <time.h>
#include <errno.h>

#if defined(__GLIBC__)
/**
 * get_realpath - Wrapper for realpath(3).
 *
 * @path: Pathname to resolve.
 *
 * Returns realpath of @path on success, NULL otherwise.
 *
 * Caller must free() the returned pointer if this function did not return
 * NULL.
 */
static inline char *get_realpath(const char *path)
{
	return realpath(path, NULL);
}
#else
/**
 * get_realpath - Fallback routine for realpath(3).
 *
 * @path: Pathname to resolve.
 *
 * Returns realpath of @path on success, NULL otherwise.
 *
 * realpath(@path, NULL) works on GLIBC, but will SIGSEGV on others.
 *
 * Caller must free() the returned pointer if this function did not return
 * NULL.
 */
static char *get_realpath(const char *path)
{
	struct stat buf;
	static const int pwd_len = PATH_MAX * 2;
	char *dir = strdup(path);
	char *pwd = malloc(pwd_len);
	char *basename = NULL;
	int len;
	if (!dir || !pwd)
		goto out;
	if (stat(dir, &buf))
		goto out;
	len = strlen(dir);
	while (len > 1 && dir[len - 1] == '/')
		dir[--len] = '\0';
	while (!lstat(dir, &buf) && S_ISLNK(buf.st_mode)) {
		char *new_dir;
		char *old_dir = dir;
		memset(pwd, 0, pwd_len);
		if (readlink(dir, pwd, pwd_len - 1) < 1)
			goto out;
		if (pwd[0] == '/') {
			dir[0] = '\0';
		} else {
			char *cp = strrchr(dir, '/');
			if (cp)
				*cp = '\0';
		}
		len = strlen(dir) + strlen(pwd) + 4;
		new_dir = malloc(len);
		if (new_dir)
			snprintf(new_dir, len - 1, "%s/%s", dir, pwd);
		dir = new_dir;
		free(old_dir);
		if (!dir)
			goto out;
	}
	if (!dir)
		goto out;
	basename = strrchr(dir, '/');
	if (basename)
		*basename++ = '\0';
	else
		basename = "";
	if (chdir(dir))
		goto out;
	memset(pwd, 0, pwd_len);
	if (!getcwd(pwd, pwd_len - 1))
		goto out;
	if (strcmp(pwd, "/"))
		len = strlen(pwd);
	else
		len = 0;
	snprintf(pwd + len, pwd_len - len - 1, "/%s", basename);
	free(dir);
	return pwd;
out:
	free(dir);
	free(pwd);
	return NULL;
}
#endif

#define elementof(x) (sizeof(x) / sizeof(x[0]))

/**
 * scandir_file_filter - Callback for scandir().
 *
 * @buf: Pointer to "const struct dirent".
 *
 * Returns non 0 if @buf seems to be a file, 0 otherwise.
 *
 * Since several kernels have a bug that leaves @buf->d_type == DT_UNKNOWN,
 * we allow it for now and recheck it later.
 */
static int scandir_file_filter(const struct dirent *buf)
{
	return (buf->d_type == DT_REG || buf->d_type == DT_UNKNOWN) &&
		strcmp(buf->d_name, ".") && strcmp(buf->d_name, "..");
}

/**
 * revalidate_path - Recheck file's attribute.
 *
 * @path: Pathname to check.
 *
 * Returns type of @path.
 *
 * This is needed by buggy kernels that report DT_UNKNOWN upon scandir().
 */
static unsigned char revalidate_path(const char *path)
{
	struct stat buf;
	unsigned char type = DT_UNKNOWN;
	if (!lstat(path, &buf)) {
		if (S_ISREG(buf.st_mode))
			type = DT_REG;
		else if (S_ISDIR(buf.st_mode))
			type = DT_DIR;
		else if (S_ISLNK(buf.st_mode))
			type = DT_LNK;
	}
	return type;
}

/* File handle to /etc/ccs/policy/current . */
static FILE *filp = NULL;

/**
 * printf_encoded - Print a word to the policy file, with escaping as needed.
 *
 * @str: Word to print. Needn't to follow TOMOYO's escape rules.
 *
 * Returns nothing.
 *
 * If @str starts with "/proc/", it is converted with "proc:/".
 */
static void printf_encoded(const char *str)
{
	if (!strncmp(str, "/proc/", 6)) {
		fprintf(filp, "proc:");
		str += 5;
	}
	while (1) {
		const char c = *str++;
		if (!c)
			break;
		if (c > ' ' && c < 127 && c != '\\')
			fputc(c, filp);
		else
			fprintf(filp, "\\%c%c%c", (c >> 6) + '0',
				((c >> 3) & 7) + '0', (c & 7) + '0');
	}
}

static void make_default_domain_transition(const char *path)
{
	fprintf(filp, "10000 acl file execute path=\"");
	printf_encoded(path);
	fprintf(filp, "\" transition=\"");
	printf_encoded(path);
	fprintf(filp, "\"\n");
	//fprintf(filp, "    audit 0\n");
	//fprintf(filp, "\n");
}


/* Shared buffer for scandir(). */
static char path[8192];

/**
 * scan_executable_files - Find executable files in the specific directory.
 *
 * @dir: Directory name to scan.
 *
 * Returns nothing.
 */
static void scan_executable_files(const char *dir)
{
	struct dirent **namelist;
	int n = scandir(dir, &namelist, scandir_file_filter, 0);
	int i;
	if (n < 0)
		return;
	for (i = 0; i < n; i++) {
		unsigned char type = namelist[i]->d_type;
		snprintf(path, sizeof(path) - 1, "%s/%s", dir,
			 namelist[i]->d_name);
		if (type == DT_UNKNOWN)
			type = revalidate_path(path);
		if (type == DT_REG && !access(path, X_OK))
			make_default_domain_transition(path);
		free(namelist[i]);
	}
	free(namelist);
}

/**
 * scan_modprobe_and_hotplug - Mark modprobe and hotplug as domain_transition entries.
 *
 * Returns nothing.
 */
static void scan_modprobe_and_hotplug(void)
{
	static const char * const files[2] = {
		"/proc/sys/kernel/modprobe", "/proc/sys/kernel/hotplug"
	};
	int i;
	for (i = 0; i < elementof(files); i++) {
		char *ret_ignored;
		char buffer[PATH_MAX + 1];
		char *cp;
		FILE *fp = fopen(files[i], "r");
		if (!fp)
			continue;
		memset(buffer, 0, sizeof(buffer));
		ret_ignored = fgets(buffer, sizeof(buffer) - 1, fp);
		fclose(fp);
		cp = strrchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!buffer[0])
			continue;
		cp = get_realpath(buffer);
		if (!cp)
			continue;
		/* We ignore /bin/true if /proc/sys/kernel/modprobe said so. */
		if (strcmp(cp, "/bin/true") && !access(cp, X_OK))
			make_default_domain_transition(cp);
		free(cp);
	}
}

/**
 * scan_init_dir - Mark programs under /etc/init.d/ directory as default domain transition entries.
 *
 * Returns nothing.
 */
static void scan_init_dir(void)
{
	char *dir = get_realpath("/etc/init.d/");
	if (!dir)
		return;
	scan_executable_files(dir);
	free(dir);
}

/**
 * scan_daemons - Mark daemon programs as default domain transition entries.
 *
 * Returns nothing.
 */
static void scan_daemons(void)
{
	static const char * const files[] = {
		"/sbin/cardmgr",
		"/sbin/getty",
		"/sbin/init",
		"/sbin/klogd",
		"/sbin/mingetty",
		"/sbin/portmap",
		"/sbin/rpc.statd",
		"/sbin/syslogd",
		"/sbin/udevd",
		"/usr/X11R6/bin/xfs",
		"/usr/bin/dbus-daemon",
		"/usr/bin/dbus-daemon-1",
		"/usr/bin/jserver",
		"/usr/bin/mDNSResponder",
		"/usr/bin/nifd",
		"/usr/bin/spamd",
		"/usr/sbin/acpid",
		"/usr/sbin/afpd",
		"/usr/sbin/anacron",
		"/usr/sbin/apache2",
		"/usr/sbin/apmd",
		"/usr/sbin/atalkd",
		"/usr/sbin/atd",
		"/usr/sbin/cannaserver",
		"/usr/sbin/cpuspeed",
		"/usr/sbin/cron",
		"/usr/sbin/crond",
		"/usr/sbin/cupsd",
		"/usr/sbin/dhcpd",
		"/usr/sbin/exim4",
		"/usr/sbin/gpm",
		"/usr/sbin/hald",
		"/usr/sbin/htt",
		"/usr/sbin/httpd",
		"/usr/sbin/inetd",
		"/usr/sbin/logrotate",
		"/usr/sbin/lpd",
		"/usr/sbin/nmbd",
		"/usr/sbin/papd",
		"/usr/sbin/rpc.idmapd",
		"/usr/sbin/rpc.mountd",
		"/usr/sbin/rpc.rquotad",
		"/usr/sbin/sendmail.sendmail",
		"/usr/sbin/smartd",
		"/usr/sbin/smbd",
		"/usr/sbin/squid",
		"/usr/sbin/sshd",
		"/usr/sbin/vmware-guestd",
		"/usr/sbin/vsftpd",
		"/usr/sbin/xinetd"
	};
	int i;
	for (i = 0; i < elementof(files); i++) {
		char *cp = get_realpath(files[i]);
		if (!cp)
			continue;
		if (!access(cp, X_OK))
			make_default_domain_transition(cp);
		free(cp);
	}
}

/**
 * mkdir2 - mkdir() with ignoring EEXIST error.
 *
 * @dir:  Directory to create.
 * @mode: Create mode.
 *
 * Returns 0 on success, EOF otehrwise.
 */
static int mkdir2(const char *dir, int mode)
{
	return mkdir(dir, mode) == 0 || errno == EEXIST ? 0 : EOF;
}

/* Policy directory. Default is "/etc/ccs/". */
static char *policy_dir = NULL;

/**
 * make_policy_dir - Create policy directories and tools directories.
 *
 * Returns nothing.
 */
static void make_policy_dir(void)
{
	char *dir = policy_dir;
	const time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	char stamp[20] = { };
	snprintf(stamp, sizeof(stamp) - 1, "%02d-%02d-%02d.%02d:%02d:%02d",
		 tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
		 tm->tm_min, tm->tm_sec);
	if (!chdir(policy_dir) && !chdir("policy"))
		goto tools_dir;
	fprintf(stderr, "Creating policy directory... ");
	while (1) {
		const char c = *dir++;
		if (!c)
			break;
		if (c != '/')
			continue;
		*(dir - 1) = '\0';
		mkdir(policy_dir, 0700);
		*(dir - 1) = '/';
	}
	if (mkdir2(policy_dir, 0700) || chdir(policy_dir) ||
	    mkdir2("policy", 0700) || chdir("policy")) {
		fprintf(stderr, "failed.\n");
		exit(1);
	} else {
		fprintf(stderr, "OK\n");
	}
tools_dir:
	if (!chdir(policy_dir) && !chdir("tools"))
		return;
	fprintf(stderr, "Creating configuration directory... ");
	mkdir("tools", 0700);
	if (!chdir("tools"))
		fprintf(stderr, "OK\n");
	else {
		fprintf(stderr, "failed.\n");
		exit(1);
	}
}

/**
 * chdir_policy - Change to policy directory.
 *
 * Returns 1 on success, 0 otherwise.
 */
static _Bool chdir_policy(void)
{
	if (chdir(policy_dir) || chdir("policy")) {
		fprintf(stderr, "ERROR: Can't chdir to %s/policy/ "
			"directory.\n", policy_dir);
		return 0;
	}
	return 1;
}

/**
 * close_file - Close file and rename.
 *
 * @fp:        Pointer to "FILE".
 * @condition: Preconditions before rename().
 * @old:       Temporary file's pathname.
 * @new:       Final file's pathname.
 *
 * Returns nothing.
 */
static void close_file(FILE *fp, _Bool condition, const char *old,
		       const char *new)
{
	if (fsync(fileno(fp)) || fclose(fp) || !condition || rename(old, new))
		fprintf(stderr, "failed.\n");
	else
		fprintf(stderr, "OK.\n");
}

/**
 * make_policy - Make /etc/ccs/policy/current .
 *
 * Returns nothing.
 */
static void make_policy(void)
{
	if (!chdir_policy())
		return;
	if (!access("current", R_OK))
		return;
	filp = fopen("current.tmp", "w");
	if (!filp) {
		fprintf(stderr, "ERROR: Can't create policy.\n");
		return;
	}
	fprintf(stderr, "Creating default policy... ");
	fprintf(filp, "POLICY_VERSION=20100903\n");
	fprintf(filp, "\n");
	fprintf(filp, "quota memory audit 16777216\n");
	fprintf(filp, "quota memory query 1048576\n");
	fprintf(filp, "quota audit[0] allowed=0 denied=1024 unmatched=1024\n");
	fprintf(filp, "\n");
	scan_modprobe_and_hotplug();
	scan_daemons();
	scan_init_dir();
	{
		char *tools_dir = get_realpath("/usr/sbin");
		fprintf(filp, "0 acl capability modify_policy\n"
			"    audit 0\n"
			"    1 deny task.uid!=0\n"
			"    1 deny task.euid!=0\n"
			"    100 allow task.exe=\"%s/ccs-loadpolicy\"\n"
			"    100 allow task.exe=\"%s/ccs-queryd\"\n"
			"    10000 deny\n", tools_dir, tools_dir);
	}
	close_file(filp, chdir_policy(), "current.tmp", "current");
	filp = NULL;
}

/* The name of loadable kernel module to load. */
static const char *module_name = "ccsecurity";

/**
 * make_module_loader - Make /etc/ccs/ccs-load-module .
 *
 * Returns nothing.
 */
static void make_module_loader(void)
{
	FILE *fp;
	if (chdir(policy_dir) || !access("ccs-load-module", X_OK)
	    || !module_name[0])
		return;
	fp = fopen("ccs-load-module.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create module loader.\n");
		return;
	}
	fprintf(stderr, "Creating module loader... ");
	fprintf(fp, "#! /bin/sh\n");
	fprintf(fp, "export PATH=$PATH:/sbin:/bin\n");
	fprintf(fp, "exec modprobe %s\n", module_name);
	close_file(fp, !chmod("ccs-load-module.tmp", 0700),
		   "ccs-load-module.tmp", "ccs-load-module");
}

/* Content of /etc/ccs/tools/auditd.conf . */
static const char auditd_data[] =
"# This file contains sorting rules used by ccs-auditd command.\n"
"\n"
"# An audit log consists with two parts delimited by \" / \" sequence.\n"
"# You can refer the former part using 'header' keyword, the latter part\n"
"# using 'acl' keyword.\n"
"#\n"
"# Words in each part are separated by a space character. Therefore, you can\n"
"# use 'header[index]', 'acl[index]' for referring index'th word of the\n"
"# part.\n"
"# The index starts from 1, and 0 refers the whole line\n"
"# (i.e. 'header[0]' = 'header', 'acl[0]' = 'acl').\n"
"#\n"
"# Three operators are provided for conditional sorting.\n"
"# '.contains' is for 'fgrep keyword' match.\n"
"# '.equals' is for 'grep ^keyword$' match.\n"
"# '.starts' is for 'grep ^keyword' match.\n"
"#\n"
"# Sorting rules are defined using multi-lined chunks. A chunk is terminated\n"
"# by a 'destination' line which specifies the pathname to write the audit\n"
"# log. A 'destination' line is processed only when all preceding 'header'\n"
"# and 'acl' lines in that chunk have matched.\n"
"# Evaluation stops at the first processed 'destination' line.\n"
"# Therefore, no audit logs are written more than once.\n"
"#\n"
"# More specific matches should be placed before less specific matches.\n"
"# For example:\n"
"#\n"
"# header.contains result=denied\n"
"# acl.contains    task.domain=\"/usr/sbin/httpd\"\n"
"# destination     /var/log/tomoyo/httpd_denied.log\n"
"#\n"
"# This chunk should be placed before the chunk that matches logs with\n"
"# result=denied. If placed after, the audit logs for /usr/sbin/httpd will\n"
"# be sent to /var/log/tomoyo/denied.log .\n"
"\n"
"# Please use TOMOYO Linux's escape rule (e.g. '\\040' rather than '\\ ' for\n"
"# representing a ' ' in a word).\n"
"\n"
"# Send all allowed logs to /dev/null.\n"
"header.contains result=allowed\n"
"destination     /dev/null\n"
"\n"
"# Send all unmatched logs to /var/log/tomoyo/unmatched.log\n"
"header.contains result=unmatched\n"
"destination     /var/log/tomoyo/unmatched.log\n"
"\n"
"# Send all denied logs to /var/log/tomoyo/denied.log\n"
"header.contains result=denied\n"
"destination     /var/log/tomoyo/denied.log\n"
"\n";

/**
 * make_auditd_conf - Make /etc/ccs/tools/auditd.conf .
 *
 * Returns nothing.
 */
static void make_auditd_conf(void)
{
	FILE *fp;
	if (chdir(policy_dir) || chdir("tools") ||
	    !access("auditd.conf", R_OK))
		return;
	fp = fopen("auditd.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create configuration file.\n");
		return;
	}
	fprintf(stderr, "Creating configuration file for ccs-auditd ... ");
	fprintf(fp, "%s", auditd_data);
	close_file(fp, !chmod("auditd.tmp", 0644), "auditd.tmp",
		   "auditd.conf");
}

/* Content of /etc/ccs/tools/patternize.conf . */
static const char patternize_data[] =
"# This file contains rewriting rules used by ccs-patternize command.\n"
"\n"
"# Domain policy consists with domain declaration lines (which start with\n"
"# '<' ,) and acl declaration lines (which do not start with '<' ).\n"
"# You can refer the former using 'domain' keyword and the latter using 'acl'"
"\n"
"# keyword.\n"
"#\n"
"# Words in each line are separated by a space character. Therefore, you can\n"
"# use 'domain[index]', 'acl[index]' for referring index'th word of the line."
"\n"
"# The index starts from 1, and 0 refers the whole line (i.e.\n"
"# 'domain[0]' = 'domain', 'acl[0]' = 'acl').\n"
"#\n"
"# Three operators are provided for conditional rewriting.\n"
"# '.contains' is for 'fgrep keyword' match.\n"
"# '.equals' is for 'grep ^keyword$' match.\n"
"# '.starts' is for 'grep ^keyword' match.\n"
"#\n"
"# Rewriting rules are defined using multi-lined chunks. A chunk is terminated"
"\n"
"# by a 'rewrite' line which specifies old pattern and new pattern.\n"
"# A 'rewrite' line is evaluated only when all preceding 'domain' and 'acl'\n"
"# lines in that chunk have matched.\n"
"# Evaluation stops at first 'rewrite' line where a word matched old pattern."
"\n"
"# Therefore, no words are rewritten more than once.\n"
"#\n"
"# For user's convenience, new pattern can be omitted if old pattern is reused"
"\n"
"# for new pattern.\n"
"\n"
"# Please use TOMOYO Linux's escape rule (e.g. '\\040' rather than '\\ ' for\n"
"# representing a ' ' in a word).\n"
"\n"
"# Files on proc filesystem.\n"
"rewrite path_pattern proc:/self/task/\\$/fdinfo/\\$\n"
"rewrite path_pattern proc:/self/task/\\$/fd/\\$\n"
"rewrite head_pattern proc:/self/task/\\$/\n"
"rewrite path_pattern proc:/self/fdinfo/\\$\n"
"rewrite path_pattern proc:/self/fd/\\$\n"
"rewrite head_pattern proc:/self/\n"
"rewrite path_pattern proc:/\\$/task/\\$/fdinfo/\\$\n"
"rewrite path_pattern proc:/\\$/task/\\$/fd/\\$\n"
"rewrite head_pattern proc:/\\$/task/\\$/\n"
"rewrite path_pattern proc:/\\$/fdinfo/\\$\n"
"rewrite path_pattern proc:/\\$/fd/\\$\n"
"rewrite head_pattern proc:/\\$/\n"
"\n"
"# Files on devpts filesystem.\n"
"rewrite path_pattern devpts:/\\$\n"
"\n"
"# Files on pipe filesystem.\n"
"rewrite path_pattern pipe:[\\$]\n"
"rewrite path_pattern pipefs:/[\\$]\n"
"\n"
"# Files on / partition.\n"
"rewrite tail_pattern /etc/mtab~\\$\n"
"rewrite tail_pattern /etc/ccs/policy/\\*\n"
"\n"
"# Files on /tmp/ partition.\n"
"rewrite tail_pattern /vte\\?\\?\\?\\?\\?\\?\n"
"rewrite tail_pattern /.ICE-unix/\\$\n"
"rewrite tail_pattern /keyring-\\?\\?\\?\\?\\?\\?/socket.ssh\n"
"rewrite tail_pattern /orbit-\\*/bonobo-activation-register-\\X.lock\n"
"rewrite tail_pattern /orbit-\\*/bonobo-activation-server-\\X-ior\n"
"rewrite tail_pattern /orbit-\\*/linc-\\*\n"
"rewrite tail_pattern /orbit-\\*/\n"
"rewrite tail_pattern /sh-thd-\\$\n"
"rewrite tail_pattern /zman\\?\\?\\?\\?\\?\\?\n"
"\n"
"# Files on home directory.\n"
"rewrite tail_pattern /.ICEauthority-\\?\n"
"rewrite tail_pattern /.xauth\\?\\?\\?\\?\\?\\?\n"
"rewrite tail_pattern /.xauth\\?\\?\\?\\?\\?\\?-?\n"
"rewrite tail_pattern "
"/.local/share/applications/preferred-mail-reader.desktop.\\?\\?\\?\\?\\?\\?\n"
"rewrite tail_pattern "
"/.local/share/applications/preferred-web-browser.desktop.\\?\\?\\?\\?\\?\\?\n"
"\n"
"# Files on /var/ partition.\n"
"rewrite tail_pattern /cache/fontconfig/\\X-le64.cache-3\n"
"rewrite tail_pattern /lib/gdm/.pulse/\\X-default-source\n"
"rewrite tail_pattern /lib/gdm/.pulse/\\X-default-sink\n"
"rewrite tail_pattern /lib/gdm/.dbus/session-bus/\\X-\\X\n"
"rewrite tail_pattern /run/gdm/auth-for-\\*/database-\\?\n"
"rewrite tail_pattern /run/gdm/auth-for-\\*/database\n"
"rewrite tail_pattern /run/gdm/auth-for-\\*/\n"
"rewrite tail_pattern /spool/abrt/pyhook-\\*/\\{\\*\\}/\\*\n"
"rewrite tail_pattern /spool/abrt/pyhook-\\*/\\{\\*\\}/\n"
"\n";

/**
 * make_patternize_conf - Make /etc/ccs/tools/patternize.conf .
 *
 * Returns nothing.
 */
static void make_patternize_conf(void)
{
	FILE *fp;
	if (chdir(policy_dir) || chdir("tools") ||
	    !access("patternize.conf", R_OK))
		return;
	fp = fopen("patternize.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create configuration file.\n");
		return;
	}
	fprintf(stderr, "Creating configuration file for ccs-patternize ... ");
	fprintf(fp, "%s", patternize_data);
	close_file(fp, !chmod("patternize.tmp", 0644), "patternize.tmp",
		   "patternize.conf");
}

/* Content of /etc/ccs/tools/notifyd.conf . */
static const char notifyd_data[] =
"# This file contains configuration used by ccs-notifyd command.\n"
"\n"
"# ccs-notifyd is a daemon that notifies the occurrence of policy violation\n"
"# in enforcing mode.\n"
"#\n"
"# time_to_wait is grace time in second before rejecting the request that\n"
"# caused policy violation in enforcing mode. For example, if you specify\n"
"# 30, you will be given 30 seconds for starting ccs-queryd command and\n"
"# responding to the policy violation event.\n"
"# If you specify non 0 value, you need to register ccs-notifyd command to\n"
"# /proc/ccs/policy as well as ccs-queryd command, for ccs-notifyd needs to\n"
"# behave as if ccs-queryd command is running.\n"
"# Also, you should avoid specifying too large value (e.g. 3600) because\n"
"# the request will remain pending for that period if you can't respond.\n"
"#\n"
"# action_to_take is a command line you want to use for notification.\n"
"# The command specified by this parameter must read the policy violation\n"
"# notification from standard input. For example, mail, curl and xmessage\n"
"# commands can read from standard input.\n"
"# This parameter is passed to execve(). Thus, please use a wrapper program\n"
"# if you need shell processing (e.g. wildcard expansion, environment\n"
"# variables).\n"
"#\n"
"# minimal_interval is grace time in second before re-notifying the next\n"
"# occurrence of policy violation. You can specify 60 to limit notification\n"
"# to once per a minute, 3600 to limit notification to once per an hour.\n"
"# You can specify 0 to unlimit, but notifying of every policy violation\n"
"# events (e.g. sending a mail) might annoy you because policy violation\n"
"# can occur in clusters if once occurred.\n"
"\n"
"# Please use TOMOYO Linux's escape rule (e.g. '\\040' rather than '\\ ' for\n"
"# representing a ' ' in a word).\n"
"\n"
"# Examples:\n"
"#\n"
"# time_to_wait 180\n"
"# action_to_take mail admin@example.com\n"
"#\n"
"#    Wait for 180 seconds before rejecting the request.\n"
"#    The occurrence is notified by sending mail to admin@example.com\n"
"#    (if SMTP service is available).\n"
"#\n"
"# time_to_wait 0\n"
"# action_to_take curl --data-binary @- https://your.server/path_to_cgi\n"
"#\n"
"#    Reject the request immediately.\n"
"#    The occurrence is notified by executing curl command.\n"
"#\n"
"time_to_wait 0\n"
"action_to_take mail -s Notification\\040from\\040ccs-notifyd root@localhost\n"
"minimal_interval 60\n"
"\n";

/**
 * make_notifyd_conf - Make /etc/ccs/tools/notifyd.conf .
 *
 * Returns nothing.
 */
static void make_notifyd_conf(void)
{
	FILE *fp;
	if (chdir(policy_dir) || chdir("tools") ||
	    !access("notifyd.conf", R_OK))
		return;
	fp = fopen("notifyd.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create configuration file.\n");
		return;
	}
	fprintf(stderr, "Creating configuration file for ccs-notifyd ... ");
	fprintf(fp, "%s", notifyd_data);
	close_file(fp, !chmod("notifyd.tmp", 0644), "notifyd.tmp",
		   "notifyd.conf");
}

int main(int argc, char *argv[])
{
	int i;
	const char *dir = NULL;
	for (i = 1; i < argc; i++) {
		char *arg = argv[i];
		if (*arg == '-' && *(arg + 1) == '-')
			arg += 2;
		if (!strncmp(arg, "root=", 5)) {
			if (chroot(arg + 5) || chdir("/")) {
				fprintf(stderr, "Can't chroot to '%s'\n",
					arg + 5);
				return 1;
			}
		} else if (!strncmp(arg, "policy_dir=", 11)) {
			dir = arg + 11;
		} else if (!strncmp(arg, "module_name=", 12)) {
			module_name = arg + 12;
		} else {
			fprintf(stderr, "Unknown option: '%s'\n", argv[i]);
			return 1;
		}
	}
	if (!dir)
		dir = "/etc/ccs";
	policy_dir = strdup(dir);
	memset(path, 0, sizeof(path));
	make_policy_dir();
	make_policy();
	make_module_loader();
	make_auditd_conf();
	make_patternize_conf();
	make_notifyd_conf();
	return 0;
}
