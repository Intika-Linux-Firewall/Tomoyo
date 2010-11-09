/*
 * init_policy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/08/01
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

#if defined(__GLIBC__)
static inline char *get_realpath(const char *path)
{
	return realpath(path, NULL);
}
#else
static char *get_realpath(const char *path)
{
	struct stat buf;
	static const int pwd_len = PATH_MAX * 2;
	char *dir = strdup(path);
	char *pwd = malloc(pwd_len);
	char *basename = NULL;
	int len;
	if (stat(dir, &buf))
		goto out;
	if (!dir || !pwd)
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
	}
	if (!dir || !pwd)
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

static int scandir_file_filter(const struct dirent *buf)
{
	return (buf->d_type == DT_REG || buf->d_type == DT_UNKNOWN) &&
		strcmp(buf->d_name, ".") && strcmp(buf->d_name, "..");
}

static int scandir_symlink_and_dir_filter(const struct dirent *buf)
{
	return (buf->d_type == DT_LNK || buf->d_type == DT_DIR ||
		buf->d_type == DT_UNKNOWN) &&
		strcmp(buf->d_name, ".") && strcmp(buf->d_name, "..");
}

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

static _Bool file_only_profile = 0;
static FILE *filp = NULL;

static inline void echo(const char *str)
{
	fprintf(filp, "%s\n", str);
}

static const char *keyword = NULL;

#define SCANDIR_MUST_CONTAIN_NUMBER_WILDCARD 1

static void printf_encoded(const char *str, const unsigned int flags)
{
	if (flags == SCANDIR_MUST_CONTAIN_NUMBER_WILDCARD) {
		_Bool found = 0;
		const char *p = str;
		while (1) {
			const char c = *p++;
			if (!c)
				break;
			if (c == '/') {
				const size_t numbers = strspn(p, "0123456789");
				const char c2 = p[numbers];
				if (numbers && (c2 == '/' || !c2)) {
					found = 1;
					break;
				}
			}
		}
		if (!found)
			return;
	}
	if (keyword)
		fprintf(filp, "%s ", keyword);
	if (!strncmp(str, "/proc/", 6)) {
		fprintf(filp, "proc:");
		str += 5;
	}
	while (1) {
		const char c = *str++;
		if (!c)
			break;
		if (c == '/' &&
		    (flags == SCANDIR_MUST_CONTAIN_NUMBER_WILDCARD)) {
			const size_t numbers = strspn(str, "0123456789");
			const char c2 = str[numbers];
			if (numbers && (c2 == '/' || !c2)) {
				fprintf(filp, "/\\$");
				str += numbers;
				continue;
			}
		}
		if (c == '\\') {
			fputc('\\', filp);
			fputc('\\', filp);
		} else if (c > ' ' && c < 127) {
			fputc(c, filp);
		} else {
			fprintf(filp, "\\%c%c%c", (c >> 6) + '0',
				((c >> 3) & 7) + '0', (c & 7) + '0');
		}
	}
	if (keyword && !strcmp(keyword, "initialize_domain"))
		fprintf(filp, " from any");
	if (keyword)
		fputc('\n', filp);
}

static char path[8192];

static void scan_init_scripts(void)
{
	struct dirent **namelist;
	int n = scandir(path, &namelist, scandir_symlink_and_dir_filter, 0);
	int len;
	int i;
	if (n < 0)
		return;
	len = strlen(path);
	for (i = 0; i < n; i++) {
		const char *name = namelist[i]->d_name;
		unsigned char type = namelist[i]->d_type;
		snprintf(path + len, sizeof(path) - len - 1, "/%s", name);
		if (type == DT_UNKNOWN)
			type = revalidate_path(path);
		if (type == DT_DIR)
			scan_init_scripts();
		else if (type == DT_LNK
			 && (name[0] == 'S' || name[0] == 'K')
			 && (name[1] >= '0' && name[1] <= '9')
			 && (name[2] >= '0' && name[2] <= '9')
			 && !access(path, X_OK)) {
			char *entity = get_realpath(path);
			path[len] = '\0';
			if (entity) {
				char *cp = strrchr(path, '/');
				fprintf(filp, "aggregator ");
				if (cp && !strncmp(cp, "/rc", 3) &&
				    ((cp[3] >= '0' && cp[3] <= '6') ||
				     cp[3] == 'S') && !strcmp(cp + 4, ".d")) {
					*cp = '\0';
					printf_encoded(path, 0);
					fprintf(filp, "/rc\\?.d");
					*cp = '/';
				} else
					printf_encoded(path, 0);
				fprintf(filp, "/\\?\\+\\+");
				printf_encoded(name + 3, 0);
				fputc(' ', filp);
				printf_encoded(entity, 0);
				fputc('\n', filp);
				free(entity);
			}
		}
		free((void *) namelist[i]);
	}
	free((void *) namelist);
}

static void make_init_scripts_as_aggregators(void)
{
	/* Mark symlinks under /etc/rc\?.d/ directory as aggregator. */
	static const char *dirs[] = {
		"/etc/boot.d", "/etc/rc.d/boot.d", "/etc/init.d/boot.d",
		"/etc/rc0.d", "/etc/rd1.d", "/etc/rc2.d", "/etc/rc3.d",
		"/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d", "/etc/rcS.d",
		"/etc/rc.d/rc0.d", "/etc/rc.d/rc1.d", "/etc/rc.d/rc2.d",
		"/etc/rc.d/rc3.d", "/etc/rc.d/rc4.d", "/etc/rc.d/rc5.d",
		"/etc/rc.d/rc6.d",
	};
	int i;
	keyword = NULL;
	memset(path, 0, sizeof(path));
	for (i = 0; i < elementof(dirs); i++) {
		char *dir = get_realpath(dirs[i]);
		if (!dir)
			continue;
		strncpy(path, dir, sizeof(path) - 1);
		free(dir);
		if (!strcmp(path, dirs[i]))
			scan_init_scripts();
	}
}

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
			printf_encoded(path, 0);
		free((void *) namelist[i]);
	}
	free((void *) namelist);
}

static void scan_modprobe_and_hotplug(void)
{
	/* Make /sbin/modprobe and /sbin/hotplug as initializers. */
	const char *files[2] = {
		"/proc/sys/kernel/modprobe", "/proc/sys/kernel/hotplug"
	};
	int i;
	for (i = 0; i < elementof(files); i++) {
		char *ret_ignored;
		char buffer[8192];
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
		if (strcmp(cp, "/bin/true") && !access(cp, X_OK)) {
			keyword = "initialize_domain";
			printf_encoded(cp, 0);
		}
		free(cp);
	}
}

static void make_globally_readable_files(void)
{
	/* Allow reading some data files. */
	static const char *files[] = {
		"/etc/ld.so.cache", "/proc/meminfo",
		"/proc/sys/kernel/version", "/etc/localtime",
		"/usr/lib/gconv/gconv-modules.cache",
		"/usr/lib32/gconv/gconv-modules.cache",
		"/usr/lib64/gconv/gconv-modules.cache",
		"/usr/share/locale/locale.alias"
	};
	int i;
	keyword = "acl_group 0 file read";
	for (i = 0; i < elementof(files); i++) {
		char *cp = get_realpath(files[i]);
		if (!cp)
			continue;
		printf_encoded(cp, 0);
		free(cp);
	}
}

static void make_self_readable_files(void)
{
	/* Allow reading information for current process. */
	fprintf(filp, "acl_group 0 file read proc:/self/\\*\n");
	fprintf(filp, "acl_group 0 file read proc:/self/\\{\\*\\}/\\*\n");
}

static void make_ldconfig_readable_files(void)
{
	/* Allow reading DLL files registered with ldconfig(8). */
	static const char *dirs[] = {
		"/lib/", "/lib/i486/", "/lib/i586/", "/lib/i686/",
		"/lib/i686/cmov/", "/lib/tls/", "/lib/tls/i486/",
		"/lib/tls/i586/", "/lib/tls/i686/", "/lib/tls/i686/cmov/",
		"/lib/i686/nosegneg/", "/usr/lib/", "/usr/lib/i486/",
		"/usr/lib/i586/", "/usr/lib/i686/", "/usr/lib/i686/cmov/",
		"/usr/lib/tls/", "/usr/lib/tls/i486/", "/usr/lib/tls/i586/",
		"/usr/lib/tls/i686/", "/usr/lib/tls/i686/cmov/",
		"/usr/lib/sse2/", "/usr/X11R6/lib/", "/usr/lib32/",
		"/usr/lib64/", "/lib64/", "/lib64/tls/",
	};
	int i;
	FILE *fp = !access("/sbin/ldconfig", X_OK) ||
		!access("/bin/ldconfig", X_OK)
		? popen("ldconfig -NXp", "r") : NULL;
	if (!fp)
		return;
	keyword = NULL;
	for (i = 0; i < elementof(dirs); i++) {
		char *cp = get_realpath(dirs[i]);
		if (!cp)
			continue;
		fprintf(filp, "acl_group 0 file read %s/lib\\*.so\\*\n", cp);
		free(cp);
	}
	while (memset(path, 0, sizeof(path)),
	       fgets(path, sizeof(path) - 1, fp)) {
		char *cp = strchr(path, '\n');
		if (!cp)
			break;
		*cp = '\0';
		cp = strstr(path, " => ");
		if (!cp)
			continue;
		cp = get_realpath(cp + 4);
		if (!cp)
			continue;
		for (i = 0; i < elementof(dirs); i++) {
			const int len = strlen(dirs[i]);
			if (!strncmp(cp, dirs[i], len) &&
			    !strncmp(cp + len, "lib", 3) &&
			    strstr(cp + len + 3, ".so"))
				break;
		}
		if (i == elementof(dirs)) {
			char *cp2 = strrchr(cp, '/');
			const int len = strlen(cp);
			char buf[16];
			memset(buf, 0, sizeof(buf));
			fprintf(filp, "acl_group 0 file read ");
			if (cp2 && !strncmp(cp2, "/ld-2.", 6) &&
			    len > 3 && !strcmp(cp + len - 3, ".so"))
				*(cp2 + 6) = '\0';
			else
				cp2 = NULL;
			printf_encoded(cp, 0);
			if (cp2)
				fprintf(filp, "\\*.so");
			fputc('\n', filp);
		}
		free(cp);
	}
	pclose(fp);
}

static void make_init_dir_as_initializers(void)
{
	/* Mark programs under /etc/init.d/ directory as initializer. */
	char *dir = get_realpath("/etc/init.d/");
	if (!dir)
		return;
	keyword = "initialize_domain";
	scan_executable_files(dir);
	free(dir);
}

static void make_initializers(void)
{
	/*
	 * Mark some programs that you want to assign short domainname as
	 * initializer.
	 */
	static const char *files[] = {
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
	keyword = "initialize_domain";
	for (i = 0; i < elementof(files); i++) {
		char *cp = get_realpath(files[i]);
		if (!cp)
			continue;
		if (!access(cp, X_OK))
			printf_encoded(cp, 0);
		free(cp);
	}
}

static char *policy_dir = NULL;

static void make_policy_dir(void)
{
	char *dir = policy_dir;
	if (!chdir(policy_dir))
		return;
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
	mkdir(policy_dir, 0700);
	if (!chdir(policy_dir))
		fprintf(stderr, "OK\n");
	else {
		fprintf(stderr, "failed.\n");
		exit(1);
	}
}

static void make_getattr(void)
{
	/* Allow getting attributes. */
	fprintf(filp, "acl_group 0 file getattr /\n");
	fprintf(filp, "acl_group 0 file getattr /\\*\n");
	fprintf(filp, "acl_group 0 file getattr /\\{\\*\\}/\n");
	fprintf(filp, "acl_group 0 file getattr /\\{\\*\\}/\\*\n");
	fprintf(filp, "acl_group 0 file getattr \\*:/\n");
	fprintf(filp, "acl_group 0 file getattr \\*:/\\*\n");
	fprintf(filp, "acl_group 0 file getattr \\*:/\\{\\*\\}/\n");
	fprintf(filp, "acl_group 0 file getattr \\*:/\\{\\*\\}/\\*\n");
}

static void make_readdir(void)
{
	/* Allow reading directories. */
	fprintf(filp, "acl_group 0 file read /\n");
	fprintf(filp, "acl_group 0 file read /\\{\\*\\}/\n");
	fprintf(filp, "acl_group 0 file read \\*:/\n");
	fprintf(filp, "acl_group 0 file read \\*:/\\{\\*\\}/\n");
}

static void make_exception_policy(void)
{
	if (chdir(policy_dir) || !access("exception_policy.conf", R_OK))
		return;
	filp = fopen("exception_policy.tmp", "w");
	if (!filp) {
		fprintf(stderr, "ERROR: Can't create exception policy.\n");
		return;
	}
	fprintf(stderr, "Creating exception policy... ");
	make_globally_readable_files();
	make_self_readable_files();
	make_ldconfig_readable_files();
	make_readdir();
	make_getattr();
	scan_modprobe_and_hotplug();
	make_init_dir_as_initializers();
	make_initializers();
	make_init_scripts_as_aggregators();
	fclose(filp);
	filp = NULL;
	if (!chdir(policy_dir) &&
	    !rename("exception_policy.tmp", "exception_policy.conf"))
		fprintf(stderr, "OK\n");
	else
		fprintf(stderr, "failed.\n");
}

static void make_manager(void)
{
	char *tools_dir;
	FILE *fp;
	if (chdir(policy_dir) || !access("manager.conf", R_OK))
		return;
	fp = fopen("manager.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create manager policy.\n");
		return;
	}
	fprintf(stderr, "Creating manager policy... ");
	tools_dir = get_realpath("/usr/sbin");
	fprintf(fp, "%s/ccs-loadpolicy\n", tools_dir);
	fprintf(fp, "%s/ccs-editpolicy\n", tools_dir);
	fprintf(fp, "%s/ccs-setlevel\n", tools_dir);
	fprintf(fp, "%s/ccs-setprofile\n", tools_dir);
	fprintf(fp, "%s/ccs-queryd\n", tools_dir);
	fclose(fp);
	if (!chdir(policy_dir) &&
	    !rename("manager.tmp", "manager.conf"))
		fprintf(stderr, "OK\n");
	else
		fprintf(stderr, "failed.\n");
}

static const char *grant_log = "no";
static const char *reject_log = "yes";
static unsigned int max_grant_log = 1024;
static unsigned int max_reject_log = 1024;
static unsigned int max_learning_entry = 2048;
static unsigned int enforcing_penalty = 0;

static void make_profile(void)
{
	static const char *file_only = "";
	FILE *fp;
	if (chdir(policy_dir) || !access("profile.conf", R_OK))
		return;
	fp = fopen("profile.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create profile policy.\n");
		return;
	}
	fprintf(stderr, "Creating default profile... ");
	if (file_only_profile)
		file_only = "::file";
	fprintf(fp, "PROFILE_VERSION=20100903\n");
	fprintf(fp, "0-COMMENT=-----Disabled Mode-----\n"
		"0-PREFERENCE={ max_grant_log=%u max_reject_log=%u "
		"max_learning_entry=%u enforcing_penalty=%u }\n"
		"0-CONFIG%s={ mode=disabled grant_log=%s reject_log=%s }\n",
		max_grant_log, max_reject_log, max_learning_entry,
		enforcing_penalty, file_only, grant_log, reject_log);
	fprintf(fp, "1-COMMENT=-----Learning Mode-----\n"
		"1-PREFERENCE={ max_grant_log=%u max_reject_log=%u "
		"max_learning_entry=%u enforcing_penalty=%u }\n"
		"1-CONFIG%s={ mode=learning grant_log=%s reject_log=%s }\n",
		max_grant_log, max_reject_log, max_learning_entry,
		enforcing_penalty, file_only, grant_log, reject_log);
	fprintf(fp, "2-COMMENT=-----Permissive Mode-----\n"
		"2-PREFERENCE={ max_grant_log=%u max_reject_log=%u "
		"max_learning_entry=%u enforcing_penalty=%u }\n"
		"2-CONFIG%s={ mode=permissive grant_log=%s reject_log=%s }\n",
		max_grant_log, max_reject_log, max_learning_entry,
		enforcing_penalty, file_only, grant_log, reject_log);
	fprintf(fp, "3-COMMENT=-----Enforcing Mode-----\n"
		"3-PREFERENCE={ max_grant_log=%u max_reject_log=%u "
		"max_learning_entry=%u enforcing_penalty=%u }\n"
		"3-CONFIG%s={ mode=enforcing grant_log=%s reject_log=%s }\n",
		max_grant_log, max_reject_log, max_learning_entry,
		enforcing_penalty, file_only, grant_log, reject_log);
	fclose(fp);
	if (!chdir(policy_dir) && !rename("profile.tmp", "profile.conf"))
		fprintf(stderr, "OK\n");
	else
		fprintf(stderr, "failed.\n");
}

static unsigned char default_profile = 0;
static unsigned char default_group = 0;

static void make_domain_policy(void)
{
	FILE *fp;
	if (chdir(policy_dir) || !access("domain_policy.conf", R_OK))
		return;
	fp = fopen("domain_policy.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create domain policy.\n");
		return;
	}
	fprintf(stderr, "Creating domain policy... ");
	fprintf(fp, "<kernel>\nuse_profile %u\nuse_group %u\n",
		default_profile, default_group);
	fclose(fp);
	if (!chdir(policy_dir) &&
	    !rename("domain_policy.tmp", "domain_policy.conf"))
		fprintf(stderr, "OK\n");
	else
		fprintf(stderr, "failed.\n");
}

static void make_meminfo(void)
{
	FILE *fp;
	if (chdir(policy_dir) || !access("meminfo.conf", R_OK))
		return;
	fp = fopen("meminfo.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create meminfo policy.\n");
		return;
	}
	fprintf(stderr, "Creating memory quota policy... ");
	fprintf(fp, "# Memory quota (byte). 0 means no quota.\n");
	fprintf(fp, "Policy:            0\n");
	fprintf(fp, "Audit logs: 16777216\n");
	fprintf(fp, "Query lists: 1048576\n");
	fclose(fp);
	if (!chdir(policy_dir) &&
	    !rename("meminfo.tmp", "meminfo.conf"))
		fprintf(stderr, "OK\n");
	else
		fprintf(stderr, "failed.\n");
}

static const char *module_name = "ccsecurity";

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
	fclose(fp);
	if (!chdir(policy_dir) &&
	    !chmod("ccs-load-module.tmp", 0700) &&
	    !rename("ccs-load-module.tmp", "ccs-load-module"))
		fprintf(stderr, "OK\n");
	else
		fprintf(stderr, "failed.\n");
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
		} else if (!strcmp(arg, "file-only-profile")) {
			file_only_profile = 1;
		} else if (!strcmp(arg, "full-profile")) {
			file_only_profile = 0;
		} else if (!strncmp(arg, "module_name=", 12)) {
			module_name = arg + 12;
		} else if (!strncmp(arg, "use_profile=", 12)) {
			default_profile = atoi(arg + 12);
		} else if (!strncmp(arg, "use_group=", 10)) {
			default_group = atoi(arg + 10);
		} else if (!strncmp(arg, "grant_log=", 10)) {
			grant_log = arg + 10;
		} else if (!strncmp(arg, "reject_log=", 11)) {
			reject_log = arg + 11;
		} else if (!sscanf(arg, "max_grant_log=%u",
				   &max_grant_log) &&
			   !sscanf(arg, "max_reject_log=%u",
				   &max_reject_log) &&
			   !sscanf(arg, "max_learning_entry=%u",
				   &max_learning_entry) &&
			   !sscanf(arg, "enforcing_penalty=%u",
				   &enforcing_penalty)) {
			fprintf(stderr, "Unknown option: '%s'\n", argv[i]);
			return 1;
		}
	}
	if (!dir)
		dir = "/etc/ccs";
	policy_dir = strdup(dir);
	memset(path, 0, sizeof(path));
	make_policy_dir();
	make_exception_policy();
	make_domain_policy();
	make_manager();
	make_profile();
	make_meminfo();
	make_module_loader();
	return 0;
}
