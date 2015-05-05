/*
 * init_policy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.4   2015/05/05
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
 * scandir_symlink_and_dir_filter - Callback for scandir().
 *
 * @buf: Pointer to "const struct dirent".
 *
 * Returns non 0 if @buf seems to be a symlink or a directory, 0 otherwise.
 *
 * Since several kernels have a bug that leaves @buf->d_type == DT_UNKNOWN,
 * we allow it for now and recheck it later.
 */
static int scandir_symlink_and_dir_filter(const struct dirent *buf)
{
	return (buf->d_type == DT_LNK || buf->d_type == DT_DIR ||
		buf->d_type == DT_UNKNOWN) &&
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

/* File handle to /etc/ccs/policy/current/exception_policy.conf . */
static FILE *filp = NULL;

/**
 * echo - Print a line to the policy file, without escaping.
 *
 * @str: Line to print. Must follow TOMOYO's escape rules.
 *
 * Returns nothing.
 */
static inline void echo(const char *str)
{
	fprintf(filp, "%s\n", str);
}

/* Keyword before printing a line. */
static const char *keyword = NULL;

/**
 * printf_encoded - Print a line to the policy file, with escaping as needed.
 *
 * @str: Line to print. Needn't to follow TOMOYO's escape rules.
 *
 * Returns nothing.
 *
 * If @str starts with "/proc/", it is converted with "proc:/".
 * If keyword is not NULL, keyword is printed before printing @str.
 * If keyword is "initialize_domain", " from any" is printed after printing
 * @str.
 */
static void printf_encoded(const char *str)
{
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

/* Shared buffer for scandir(). */
static char path[8192];

/**
 * scan_init_scripts - Scan /etc/rc\?.d/ directories for initialize_domain entries.
 *
 * Returns nothing.
 */
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
				/*
				 * Use /rc\?.d/ rather than /rc0.d/ /rc1.d/
				 * /rc2.d/ /rc3.d/ /rc4.d/ /rc5.d/ /rc6.d/
				 * /rcS.d/ .
				 */
				if (cp && !strncmp(cp, "/rc", 3) &&
				    ((cp[3] >= '0' && cp[3] <= '6') ||
				     cp[3] == 'S') && !strcmp(cp + 4, ".d")) {
					*cp = '\0';
					printf_encoded(path);
					fprintf(filp, "/rc\\?.d");
					*cp = '/';
				} else
					printf_encoded(path);
				fprintf(filp, "/\\?\\+\\+");
				printf_encoded(name + 3);
				fputc(' ', filp);
				printf_encoded(entity);
				fputc('\n', filp);
				free(entity);
			}
		}
		free(namelist[i]);
	}
	free(namelist);
}

/**
 * make_systemd_exceptions - Exceptions specific to systemd
 *
 * Returns nothing.
 */
static void make_systemd_exceptions(void)
{
	/* allow systemd to re-execute itself */
	static const char * const systemd[] = {
		"/lib/systemd/systemd",
		"/usr/lib/systemd/systemd",
	};
	int i;
	keyword = NULL;
	for (i = 0; i < elementof(systemd); i++) {
		/* Check realpath because /lib may be a symlink to /usr/lib .*/
		char *path = get_realpath(systemd[i]);
		if (!path)
			continue;
		fprintf(filp, "keep_domain ");
		printf_encoded(path);
		fprintf(filp, " from <kernel> /sbin/init\n");
		free(path);
	}
}

/**
 * make_init_scripts_as_aggregators - Use realpath for startup/shutdown scripts in /etc/ directory.
 *
 * Returns nothing.
 */
static void make_init_scripts_as_aggregators(void)
{
	/* Mark symlinks under /etc/rc\?.d/ directory as aggregator. */
	static const char * const dirs[] = {
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
			printf_encoded(path);
		free(namelist[i]);
	}
	free(namelist);
}

/**
 * scan_modprobe_and_hotplug - Mark modprobe and hotplug as initialize_domain entries.
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
		if (strcmp(cp, "/bin/true") && !access(cp, X_OK)) {
			keyword = "initialize_domain";
			printf_encoded(cp);
		}
		free(cp);
	}
}

/**
 * make_globally_readable_files - Mark some files as globally readable.
 *
 * Returns nothing.
 */
static void make_globally_readable_files(void)
{
	/* Allow reading some data files. */
	static const char * const files[] = {
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
		printf_encoded(cp);
		free(cp);
	}
}

/**
 * make_self_readable_files - Mark /proc/self/ files as globally readable.
 *
 * Returns nothing.
 */
static void make_self_readable_files(void)
{
	/* Allow reading information for current process. */
	echo("acl_group 0 file read proc:/self/\\*");
	echo("acl_group 0 file read proc:/self/\\{\\*\\}/\\*");
}

/**
 * make_ldconfig_readable_files - Mark shared library files as globally readable.
 *
 * Returns nothing.
 *
 * We don't scan predefined directories if ldconfig does not exist (e.g.
 * embedded environment).
 */
static void make_ldconfig_readable_files(void)
{
	/* Allow reading DLL files registered with ldconfig(8). */
	static const char * const dirs[] = {
		"/lib/", "/lib/i486/", "/lib/i586/", "/lib/i686/",
		"/lib/i686/cmov/", "/lib/tls/", "/lib/tls/i486/",
		"/lib/tls/i586/", "/lib/tls/i686/", "/lib/tls/i686/cmov/",
		"/lib/i686/nosegneg/", "/usr/lib/", "/usr/lib/i486/",
		"/usr/lib/i586/", "/usr/lib/i686/", "/usr/lib/i686/cmov/",
		"/usr/lib/tls/", "/usr/lib/tls/i486/", "/usr/lib/tls/i586/",
		"/usr/lib/tls/i686/", "/usr/lib/tls/i686/cmov/",
		"/usr/lib/sse2/", "/usr/X11R6/lib/", "/usr/lib32/",
		"/usr/lib64/", "/lib64/", "/lib64/tls/",
		"/usr/lib/x86_64-linux-gnu/", "/lib/x86_64-linux-gnu/",
		"/usr/lib/i386-linux-gnu/", "/lib/i386-linux-gnu/",
		"/usr/lib/arm-linux-gnueabihf/", "/lib/arm-linux-gnueabihf/",
		"/usr/lib/arm-linux-gnueabi/", "/lib/arm-linux-gnueabi/",
		"/usr/lib/aarch64-linux-gnu/", "/lib/aarch64-linux-gnu/",
		"/usr/lib/ia64-linux-gnu/", "/lib/ia64-linux-gnu/",
		"/usr/lib/mips-linux-gnu/", "/lib/mips-linux-gnu/",
		"/usr/lib/mipsel-linux-gnu/", "/lib/mipsel-linux-gnu/",
		"/usr/lib/powerpc-linux-gnu/", "/lib/powerpc-linux-gnu/",
		"/usr/lib/ppc64-linux-gnu/", "/lib/ppc64-linux-gnu/",
		"/usr/lib/s390-linux-gnu/", "/lib/s390-linux-gnu/",
		"/usr/lib/s390x-linux-gnu/", "/lib/s390x-linux-gnu/",
		"/usr/lib/sh4-linux-gnu/", "/lib/sh4-linux-gnu/",
		"/usr/lib/sparc-linux-gnu/", "/lib/sparc-linux-gnu/",
		"/usr/lib/sparc64-linux-gnu/", "/lib/sparc64-linux-gnu/",
		"/usr/lib/x86_64-linux-gnux32/", "/lib/x86_64-linux-gnux32/",
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
		fprintf(filp, "acl_group 0 file read ");
		printf_encoded(cp);
		fprintf(filp, "/lib\\*.so\\*\n");
		free(cp);
	}
	while (memset(path, 0, sizeof(path)) &&
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
			printf_encoded(cp);
			if (cp2)
				fprintf(filp, "\\*.so");
			fputc('\n', filp);
		}
		free(cp);
	}
	pclose(fp);
}

/**
 * make_init_dir_as_initializers - Mark programs under /etc/init.d/ directory as initialize_domain entries.
 *
 * Returns nothing.
 */
static void make_init_dir_as_initializers(void)
{
	char *dir = get_realpath("/etc/init.d/");
	if (!dir)
		return;
	keyword = "initialize_domain";
	scan_executable_files(dir);
	free(dir);
}

/**
 * make_initializers - Mark daemon programs as initialize_domain entries.
 *
 * Returns nothing.
 */
static void make_initializers(void)
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
	keyword = "initialize_domain";
	for (i = 0; i < elementof(files); i++) {
		char *cp = get_realpath(files[i]);
		if (!cp)
			continue;
		if (!access(cp, X_OK))
			printf_encoded(cp);
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

/**
 * symlink2 - symlink() with ignoring EEXIST error.
 *
 * @old: Symlink's content.
 * @new: Symlink to create.
 *
 * Returns 0 on success, EOF otehrwise.
 */
static int symlink2(const char *old, const char *new)
{
	return symlink(old, new) == 0 || errno == EEXIST ? 0 : EOF;
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
	if (!chdir(policy_dir) && !chdir("policy/current/"))
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
	    symlink2("policy/current/exception_policy.conf",
		     "exception_policy.conf") ||
	    symlink2("policy/current/domain_policy.conf",
		     "domain_policy.conf") ||
	    symlink2("policy/current/profile.conf", "profile.conf") ||
	    symlink2("policy/current/manager.conf", "manager.conf") ||
	    mkdir2("policy", 0700) || chdir("policy") || mkdir2(stamp, 0700) ||
	    symlink2(stamp, "previous") || symlink2(stamp, "current") ||
	    chdir(policy_dir) || chdir("policy/current/")) {
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
 * make_path_group - Make path_group entries.
 *
 * Returns nothing.
 */
static void make_path_group(void)
{
	echo("path_group ANY_PATHNAME /");
	echo("path_group ANY_PATHNAME /\\*");
	echo("path_group ANY_PATHNAME /\\{\\*\\}/");
	echo("path_group ANY_PATHNAME /\\{\\*\\}/\\*");
	echo("path_group ANY_PATHNAME \\*:/");
	echo("path_group ANY_PATHNAME \\*:/\\*");
	echo("path_group ANY_PATHNAME \\*:/\\{\\*\\}/");
	echo("path_group ANY_PATHNAME \\*:/\\{\\*\\}/\\*");
	echo("path_group ANY_PATHNAME \\*:[\\$]");
	echo("path_group ANY_PATHNAME "
	     "socket:[family=\\$:type=\\$:protocol=\\$]");
	echo("path_group ANY_DIRECTORY /");
	echo("path_group ANY_DIRECTORY /\\{\\*\\}/");
	echo("path_group ANY_DIRECTORY \\*:/");
	echo("path_group ANY_DIRECTORY \\*:/\\{\\*\\}/");
}

/**
 * make_number_group - Make number_group entries.
 *
 * Returns nothing.
 */
static void make_number_group(void)
{
	echo("number_group COMMON_IOCTL_CMDS 0x5401");
}

/**
 * make_ioctl - Allow ioctl with common ioctl numbers.
 *
 * Returns nothing.
 */
static void make_ioctl(void)
{
	echo("acl_group 0 file ioctl @ANY_PATHNAME @COMMON_IOCTL_CMDS");
}

/**
 * make_getattr - Allow getting attributes.
 *
 * Returns nothing.
 */
static void make_getattr(void)
{
	echo("acl_group 0 file getattr @ANY_PATHNAME");
}

/**
 * make_readdir - Allow reading directories.
 *
 * Returns nothing.
 */
static void make_readdir(void)
{
	echo("acl_group 0 file read @ANY_DIRECTORY");
}

/**
 * chdir_policy - Change to policy directory.
 *
 * Returns 1 on success, 0 otherwise.
 */
static _Bool chdir_policy(void)
{
	if (chdir(policy_dir) || chdir("policy/current/")) {
		fprintf(stderr, "ERROR: Can't chdir to %s/policy/current/ "
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
 * make_exception_policy - Make /etc/ccs/policy/current/exception_policy.conf .
 *
 * Returns nothing.
 */
static void make_exception_policy(void)
{
	if (!chdir_policy())
		return;
	if (!access("exception_policy.conf", R_OK))
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
	make_path_group();
	make_number_group();
	make_ioctl();
	make_readdir();
	make_getattr();
	scan_modprobe_and_hotplug();
	make_init_dir_as_initializers();
	make_initializers();
	make_init_scripts_as_aggregators();
	make_systemd_exceptions();
	/* Some applications do execve("/proc/self/exe"). */
	fprintf(filp, "aggregator proc:/self/exe /proc/self/exe\n");
	close_file(filp, chdir_policy(), "exception_policy.tmp",
		   "exception_policy.conf");
	filp = NULL;
}

/**
 * make_manager - Make /etc/ccs/policy/current/manager.conf .
 *
 * Returns nothing.
 */
static void make_manager(void)
{
	char *tools_dir;
	FILE *fp;
	if (!chdir_policy())
		return;
	if (!access("manager.conf", R_OK))
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
	close_file(fp, 1, "manager.tmp", "manager.conf");
}

/* Should we create profiles that restricts file only? */
static _Bool file_only_profile = 0;
/* Should we audit access granted logs? */
static const char *grant_log = "no";
/* Should we audit access rejected logs? */
static const char *reject_log = "yes";
/* How many audit log entries to spool in the kenrel memory? */
static unsigned int max_audit_log = 1024;
/* How many ACL entries to add automatically by learning mode? */
static unsigned int max_learning_entry = 2048;
/* How long should we carry sleep penalty? */
static unsigned int enforcing_penalty = 0;

/**
 * make_profile - Make /etc/ccs/policy/current/profile.conf .
 *
 * Returns nothing.
 */
static void make_profile(void)
{
	static const char *file_only = "";
	FILE *fp;
	if (!chdir_policy())
		return;
	if (!access("profile.conf", R_OK))
		return;
	fp = fopen("profile.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create profile policy.\n");
		return;
	}
	fprintf(stderr, "Creating default profile... ");
	if (file_only_profile)
		file_only = "::file";
	fprintf(fp, "PROFILE_VERSION=20150505\n");
	fprintf(fp, "0-COMMENT=-----Disabled Mode-----\n"
		"0-PREFERENCE={ max_audit_log=%u max_learning_entry=%u "
		"enforcing_penalty=%u }\n"
		"0-CONFIG%s={ mode=disabled grant_log=%s reject_log=%s }\n",
		max_audit_log, max_learning_entry, enforcing_penalty,
		file_only, grant_log, reject_log);
	fprintf(fp, "1-COMMENT=-----Learning Mode-----\n"
		"1-PREFERENCE={ max_audit_log=%u max_learning_entry=%u "
		"enforcing_penalty=%u }\n"
		"1-CONFIG%s={ mode=learning grant_log=%s reject_log=%s }\n",
		max_audit_log, max_learning_entry, enforcing_penalty,
		file_only, grant_log, reject_log);
	fprintf(fp, "2-COMMENT=-----Permissive Mode-----\n"
		"2-PREFERENCE={ max_audit_log=%u max_learning_entry=%u "
		"enforcing_penalty=%u }\n"
		"2-CONFIG%s={ mode=permissive grant_log=%s reject_log=%s }\n",
		max_audit_log, max_learning_entry, enforcing_penalty,
		file_only, grant_log, reject_log);
	fprintf(fp, "3-COMMENT=-----Enforcing Mode-----\n"
		"3-PREFERENCE={ max_audit_log=%u max_learning_entry=%u "
		"enforcing_penalty=%u }\n"
		"3-CONFIG%s={ mode=enforcing grant_log=%s reject_log=%s }\n",
		max_audit_log, max_learning_entry, enforcing_penalty,
		file_only, grant_log, reject_log);
	close_file(fp, 1, "profile.tmp", "profile.conf");
}

/* Which profile number does <kernel> domain use? */
static unsigned char default_profile = 0;
/* Which ACL group does <kernel> domain use? */
static _Bool use_group[256] = { };

/**
 * make_domain_policy - Make /etc/ccs/policy/current/domain_policy.conf .
 *
 * Returns nothing.
 */
static void make_domain_policy(void)
{
	FILE *fp;
	int i;
	if (!chdir_policy())
		return;
	if (!access("domain_policy.conf", R_OK))
		return;
	fp = fopen("domain_policy.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create domain policy.\n");
		return;
	}
	fprintf(stderr, "Creating domain policy... ");
	fprintf(fp, "<kernel>\nuse_profile %u\n", default_profile);
	for (i = 0; i < 256; i++)
		if (use_group[i])
			fprintf(fp, "use_group %u\n", i);
	close_file(fp, 1, "domain_policy.tmp", "domain_policy.conf");
}

/**
 * make_stat - Make /etc/ccs/stat.conf .
 *
 * Returns nothing.
 */
static void make_stat(void)
{
	FILE *fp;
	if (chdir(policy_dir) || !access("stat.conf", R_OK))
		return;
	fp = fopen("stat.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create stat policy.\n");
		return;
	}
	fprintf(stderr, "Creating stat policy... ");
	fprintf(fp, "# Memory quota (byte). 0 means no quota.\n");
	fprintf(fp, "Memory used by policy:               0\n");
	fprintf(fp, "Memory used by audit log:     16777216\n");
	fprintf(fp, "Memory used by query message:  1048576\n");
	close_file(fp, 1, "stat.tmp", "stat.conf");
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

/* Content of /etc/ccs/tools/editpolicy.conf . */
static const char editpolicy_data[] =
"# This file contains configuration used by ccs-editpolicy command.\n"
"\n"
"# Keyword alias. ( directive-name = display-name )\n"
"keyword_alias acl_group   0                 = acl_group   0\n"
"keyword_alias acl_group   1                 = acl_group   1\n"
"keyword_alias acl_group   2                 = acl_group   2\n"
"keyword_alias acl_group   3                 = acl_group   3\n"
"keyword_alias acl_group   4                 = acl_group   4\n"
"keyword_alias acl_group   5                 = acl_group   5\n"
"keyword_alias acl_group   6                 = acl_group   6\n"
"keyword_alias acl_group   7                 = acl_group   7\n"
"keyword_alias acl_group   8                 = acl_group   8\n"
"keyword_alias acl_group   9                 = acl_group   9\n"
"keyword_alias acl_group  10                 = acl_group  10\n"
"keyword_alias acl_group  11                 = acl_group  11\n"
"keyword_alias acl_group  12                 = acl_group  12\n"
"keyword_alias acl_group  13                 = acl_group  13\n"
"keyword_alias acl_group  14                 = acl_group  14\n"
"keyword_alias acl_group  15                 = acl_group  15\n"
"keyword_alias acl_group  16                 = acl_group  16\n"
"keyword_alias acl_group  17                 = acl_group  17\n"
"keyword_alias acl_group  18                 = acl_group  18\n"
"keyword_alias acl_group  19                 = acl_group  19\n"
"keyword_alias acl_group  20                 = acl_group  20\n"
"keyword_alias acl_group  21                 = acl_group  21\n"
"keyword_alias acl_group  22                 = acl_group  22\n"
"keyword_alias acl_group  23                 = acl_group  23\n"
"keyword_alias acl_group  24                 = acl_group  24\n"
"keyword_alias acl_group  25                 = acl_group  25\n"
"keyword_alias acl_group  26                 = acl_group  26\n"
"keyword_alias acl_group  27                 = acl_group  27\n"
"keyword_alias acl_group  28                 = acl_group  28\n"
"keyword_alias acl_group  29                 = acl_group  29\n"
"keyword_alias acl_group  30                 = acl_group  30\n"
"keyword_alias acl_group  31                 = acl_group  31\n"
"keyword_alias acl_group  32                 = acl_group  32\n"
"keyword_alias acl_group  33                 = acl_group  33\n"
"keyword_alias acl_group  34                 = acl_group  34\n"
"keyword_alias acl_group  35                 = acl_group  35\n"
"keyword_alias acl_group  36                 = acl_group  36\n"
"keyword_alias acl_group  37                 = acl_group  37\n"
"keyword_alias acl_group  38                 = acl_group  38\n"
"keyword_alias acl_group  39                 = acl_group  39\n"
"keyword_alias acl_group  40                 = acl_group  40\n"
"keyword_alias acl_group  41                 = acl_group  41\n"
"keyword_alias acl_group  42                 = acl_group  42\n"
"keyword_alias acl_group  43                 = acl_group  43\n"
"keyword_alias acl_group  44                 = acl_group  44\n"
"keyword_alias acl_group  45                 = acl_group  45\n"
"keyword_alias acl_group  46                 = acl_group  46\n"
"keyword_alias acl_group  47                 = acl_group  47\n"
"keyword_alias acl_group  48                 = acl_group  48\n"
"keyword_alias acl_group  49                 = acl_group  49\n"
"keyword_alias acl_group  50                 = acl_group  50\n"
"keyword_alias acl_group  51                 = acl_group  51\n"
"keyword_alias acl_group  52                 = acl_group  52\n"
"keyword_alias acl_group  53                 = acl_group  53\n"
"keyword_alias acl_group  54                 = acl_group  54\n"
"keyword_alias acl_group  55                 = acl_group  55\n"
"keyword_alias acl_group  56                 = acl_group  56\n"
"keyword_alias acl_group  57                 = acl_group  57\n"
"keyword_alias acl_group  58                 = acl_group  58\n"
"keyword_alias acl_group  59                 = acl_group  59\n"
"keyword_alias acl_group  60                 = acl_group  60\n"
"keyword_alias acl_group  61                 = acl_group  61\n"
"keyword_alias acl_group  62                 = acl_group  62\n"
"keyword_alias acl_group  63                 = acl_group  63\n"
"keyword_alias acl_group  64                 = acl_group  64\n"
"keyword_alias acl_group  65                 = acl_group  65\n"
"keyword_alias acl_group  66                 = acl_group  66\n"
"keyword_alias acl_group  67                 = acl_group  67\n"
"keyword_alias acl_group  68                 = acl_group  68\n"
"keyword_alias acl_group  69                 = acl_group  69\n"
"keyword_alias acl_group  70                 = acl_group  70\n"
"keyword_alias acl_group  71                 = acl_group  71\n"
"keyword_alias acl_group  72                 = acl_group  72\n"
"keyword_alias acl_group  73                 = acl_group  73\n"
"keyword_alias acl_group  74                 = acl_group  74\n"
"keyword_alias acl_group  75                 = acl_group  75\n"
"keyword_alias acl_group  76                 = acl_group  76\n"
"keyword_alias acl_group  77                 = acl_group  77\n"
"keyword_alias acl_group  78                 = acl_group  78\n"
"keyword_alias acl_group  79                 = acl_group  79\n"
"keyword_alias acl_group  80                 = acl_group  80\n"
"keyword_alias acl_group  81                 = acl_group  81\n"
"keyword_alias acl_group  82                 = acl_group  82\n"
"keyword_alias acl_group  83                 = acl_group  83\n"
"keyword_alias acl_group  84                 = acl_group  84\n"
"keyword_alias acl_group  85                 = acl_group  85\n"
"keyword_alias acl_group  86                 = acl_group  86\n"
"keyword_alias acl_group  87                 = acl_group  87\n"
"keyword_alias acl_group  88                 = acl_group  88\n"
"keyword_alias acl_group  89                 = acl_group  89\n"
"keyword_alias acl_group  90                 = acl_group  90\n"
"keyword_alias acl_group  91                 = acl_group  91\n"
"keyword_alias acl_group  92                 = acl_group  92\n"
"keyword_alias acl_group  93                 = acl_group  93\n"
"keyword_alias acl_group  94                 = acl_group  94\n"
"keyword_alias acl_group  95                 = acl_group  95\n"
"keyword_alias acl_group  96                 = acl_group  96\n"
"keyword_alias acl_group  97                 = acl_group  97\n"
"keyword_alias acl_group  98                 = acl_group  98\n"
"keyword_alias acl_group  99                 = acl_group  99\n"
"keyword_alias acl_group 100                 = acl_group 100\n"
"keyword_alias acl_group 101                 = acl_group 101\n"
"keyword_alias acl_group 102                 = acl_group 102\n"
"keyword_alias acl_group 103                 = acl_group 103\n"
"keyword_alias acl_group 104                 = acl_group 104\n"
"keyword_alias acl_group 105                 = acl_group 105\n"
"keyword_alias acl_group 106                 = acl_group 106\n"
"keyword_alias acl_group 107                 = acl_group 107\n"
"keyword_alias acl_group 108                 = acl_group 108\n"
"keyword_alias acl_group 109                 = acl_group 109\n"
"keyword_alias acl_group 110                 = acl_group 110\n"
"keyword_alias acl_group 111                 = acl_group 111\n"
"keyword_alias acl_group 112                 = acl_group 112\n"
"keyword_alias acl_group 113                 = acl_group 113\n"
"keyword_alias acl_group 114                 = acl_group 114\n"
"keyword_alias acl_group 115                 = acl_group 115\n"
"keyword_alias acl_group 116                 = acl_group 116\n"
"keyword_alias acl_group 117                 = acl_group 117\n"
"keyword_alias acl_group 118                 = acl_group 118\n"
"keyword_alias acl_group 119                 = acl_group 119\n"
"keyword_alias acl_group 120                 = acl_group 120\n"
"keyword_alias acl_group 121                 = acl_group 121\n"
"keyword_alias acl_group 122                 = acl_group 122\n"
"keyword_alias acl_group 123                 = acl_group 123\n"
"keyword_alias acl_group 124                 = acl_group 124\n"
"keyword_alias acl_group 125                 = acl_group 125\n"
"keyword_alias acl_group 126                 = acl_group 126\n"
"keyword_alias acl_group 127                 = acl_group 127\n"
"keyword_alias acl_group 128                 = acl_group 128\n"
"keyword_alias acl_group 129                 = acl_group 129\n"
"keyword_alias acl_group 130                 = acl_group 130\n"
"keyword_alias acl_group 131                 = acl_group 131\n"
"keyword_alias acl_group 132                 = acl_group 132\n"
"keyword_alias acl_group 133                 = acl_group 133\n"
"keyword_alias acl_group 134                 = acl_group 134\n"
"keyword_alias acl_group 135                 = acl_group 135\n"
"keyword_alias acl_group 136                 = acl_group 136\n"
"keyword_alias acl_group 137                 = acl_group 137\n"
"keyword_alias acl_group 138                 = acl_group 138\n"
"keyword_alias acl_group 139                 = acl_group 139\n"
"keyword_alias acl_group 140                 = acl_group 140\n"
"keyword_alias acl_group 141                 = acl_group 141\n"
"keyword_alias acl_group 142                 = acl_group 142\n"
"keyword_alias acl_group 143                 = acl_group 143\n"
"keyword_alias acl_group 144                 = acl_group 144\n"
"keyword_alias acl_group 145                 = acl_group 145\n"
"keyword_alias acl_group 146                 = acl_group 146\n"
"keyword_alias acl_group 147                 = acl_group 147\n"
"keyword_alias acl_group 148                 = acl_group 148\n"
"keyword_alias acl_group 149                 = acl_group 149\n"
"keyword_alias acl_group 150                 = acl_group 150\n"
"keyword_alias acl_group 151                 = acl_group 151\n"
"keyword_alias acl_group 152                 = acl_group 152\n"
"keyword_alias acl_group 153                 = acl_group 153\n"
"keyword_alias acl_group 154                 = acl_group 154\n"
"keyword_alias acl_group 155                 = acl_group 155\n"
"keyword_alias acl_group 156                 = acl_group 156\n"
"keyword_alias acl_group 157                 = acl_group 157\n"
"keyword_alias acl_group 158                 = acl_group 158\n"
"keyword_alias acl_group 159                 = acl_group 159\n"
"keyword_alias acl_group 160                 = acl_group 160\n"
"keyword_alias acl_group 161                 = acl_group 161\n"
"keyword_alias acl_group 162                 = acl_group 162\n"
"keyword_alias acl_group 163                 = acl_group 163\n"
"keyword_alias acl_group 164                 = acl_group 164\n"
"keyword_alias acl_group 165                 = acl_group 165\n"
"keyword_alias acl_group 166                 = acl_group 166\n"
"keyword_alias acl_group 167                 = acl_group 167\n"
"keyword_alias acl_group 168                 = acl_group 168\n"
"keyword_alias acl_group 169                 = acl_group 169\n"
"keyword_alias acl_group 170                 = acl_group 170\n"
"keyword_alias acl_group 171                 = acl_group 171\n"
"keyword_alias acl_group 172                 = acl_group 172\n"
"keyword_alias acl_group 173                 = acl_group 173\n"
"keyword_alias acl_group 174                 = acl_group 174\n"
"keyword_alias acl_group 175                 = acl_group 175\n"
"keyword_alias acl_group 176                 = acl_group 176\n"
"keyword_alias acl_group 177                 = acl_group 177\n"
"keyword_alias acl_group 178                 = acl_group 178\n"
"keyword_alias acl_group 179                 = acl_group 179\n"
"keyword_alias acl_group 180                 = acl_group 180\n"
"keyword_alias acl_group 181                 = acl_group 181\n"
"keyword_alias acl_group 182                 = acl_group 182\n"
"keyword_alias acl_group 183                 = acl_group 183\n"
"keyword_alias acl_group 184                 = acl_group 184\n"
"keyword_alias acl_group 185                 = acl_group 185\n"
"keyword_alias acl_group 186                 = acl_group 186\n"
"keyword_alias acl_group 187                 = acl_group 187\n"
"keyword_alias acl_group 188                 = acl_group 188\n"
"keyword_alias acl_group 189                 = acl_group 189\n"
"keyword_alias acl_group 190                 = acl_group 190\n"
"keyword_alias acl_group 191                 = acl_group 191\n"
"keyword_alias acl_group 192                 = acl_group 192\n"
"keyword_alias acl_group 193                 = acl_group 193\n"
"keyword_alias acl_group 194                 = acl_group 194\n"
"keyword_alias acl_group 195                 = acl_group 195\n"
"keyword_alias acl_group 196                 = acl_group 196\n"
"keyword_alias acl_group 197                 = acl_group 197\n"
"keyword_alias acl_group 198                 = acl_group 198\n"
"keyword_alias acl_group 199                 = acl_group 199\n"
"keyword_alias acl_group 200                 = acl_group 200\n"
"keyword_alias acl_group 201                 = acl_group 201\n"
"keyword_alias acl_group 202                 = acl_group 202\n"
"keyword_alias acl_group 203                 = acl_group 203\n"
"keyword_alias acl_group 204                 = acl_group 204\n"
"keyword_alias acl_group 205                 = acl_group 205\n"
"keyword_alias acl_group 206                 = acl_group 206\n"
"keyword_alias acl_group 207                 = acl_group 207\n"
"keyword_alias acl_group 208                 = acl_group 208\n"
"keyword_alias acl_group 209                 = acl_group 209\n"
"keyword_alias acl_group 210                 = acl_group 210\n"
"keyword_alias acl_group 211                 = acl_group 211\n"
"keyword_alias acl_group 212                 = acl_group 212\n"
"keyword_alias acl_group 213                 = acl_group 213\n"
"keyword_alias acl_group 214                 = acl_group 214\n"
"keyword_alias acl_group 215                 = acl_group 215\n"
"keyword_alias acl_group 216                 = acl_group 216\n"
"keyword_alias acl_group 217                 = acl_group 217\n"
"keyword_alias acl_group 218                 = acl_group 218\n"
"keyword_alias acl_group 219                 = acl_group 219\n"
"keyword_alias acl_group 220                 = acl_group 220\n"
"keyword_alias acl_group 221                 = acl_group 221\n"
"keyword_alias acl_group 222                 = acl_group 222\n"
"keyword_alias acl_group 223                 = acl_group 223\n"
"keyword_alias acl_group 224                 = acl_group 224\n"
"keyword_alias acl_group 225                 = acl_group 225\n"
"keyword_alias acl_group 226                 = acl_group 226\n"
"keyword_alias acl_group 227                 = acl_group 227\n"
"keyword_alias acl_group 228                 = acl_group 228\n"
"keyword_alias acl_group 229                 = acl_group 229\n"
"keyword_alias acl_group 230                 = acl_group 230\n"
"keyword_alias acl_group 231                 = acl_group 231\n"
"keyword_alias acl_group 232                 = acl_group 232\n"
"keyword_alias acl_group 233                 = acl_group 233\n"
"keyword_alias acl_group 234                 = acl_group 234\n"
"keyword_alias acl_group 235                 = acl_group 235\n"
"keyword_alias acl_group 236                 = acl_group 236\n"
"keyword_alias acl_group 237                 = acl_group 237\n"
"keyword_alias acl_group 238                 = acl_group 238\n"
"keyword_alias acl_group 239                 = acl_group 239\n"
"keyword_alias acl_group 240                 = acl_group 240\n"
"keyword_alias acl_group 241                 = acl_group 241\n"
"keyword_alias acl_group 242                 = acl_group 242\n"
"keyword_alias acl_group 243                 = acl_group 243\n"
"keyword_alias acl_group 244                 = acl_group 244\n"
"keyword_alias acl_group 245                 = acl_group 245\n"
"keyword_alias acl_group 246                 = acl_group 246\n"
"keyword_alias acl_group 247                 = acl_group 247\n"
"keyword_alias acl_group 248                 = acl_group 248\n"
"keyword_alias acl_group 249                 = acl_group 249\n"
"keyword_alias acl_group 250                 = acl_group 250\n"
"keyword_alias acl_group 251                 = acl_group 251\n"
"keyword_alias acl_group 252                 = acl_group 252\n"
"keyword_alias acl_group 253                 = acl_group 253\n"
"keyword_alias acl_group 254                 = acl_group 254\n"
"keyword_alias acl_group 255                 = acl_group 255\n"
"keyword_alias address_group                 = address_group\n"
"keyword_alias aggregator                    = aggregator\n"
"keyword_alias capability                    = capability\n"
"keyword_alias deny_autobind                 = deny_autobind\n"
"keyword_alias file append                   = file append\n"
"keyword_alias file chgrp                    = file chgrp\n"
"keyword_alias file chmod                    = file chmod\n"
"keyword_alias file chown                    = file chown\n"
"keyword_alias file chroot                   = file chroot\n"
"keyword_alias file create                   = file create\n"
"keyword_alias file execute                  = file execute\n"
"keyword_alias file getattr                  = file getattr\n"
"keyword_alias file ioctl                    = file ioctl\n"
"keyword_alias file link                     = file link\n"
"keyword_alias file mkblock                  = file mkblock\n"
"keyword_alias file mkchar                   = file mkchar\n"
"keyword_alias file mkdir                    = file mkdir\n"
"keyword_alias file mkfifo                   = file mkfifo\n"
"keyword_alias file mksock                   = file mksock\n"
"keyword_alias file mount                    = file mount\n"
"keyword_alias file pivot_root               = file pivot_root\n"
"keyword_alias file read                     = file read\n"
"keyword_alias file rename                   = file rename\n"
"keyword_alias file rmdir                    = file rmdir\n"
"keyword_alias file symlink                  = file symlink\n"
"keyword_alias file truncate                 = file truncate\n"
"keyword_alias file unlink                   = file unlink\n"
"keyword_alias file unmount                  = file unmount\n"
"keyword_alias file write                    = file write\n"
"keyword_alias initialize_domain             = initialize_domain\n"
"keyword_alias ipc signal                    = ipc signal\n"
"keyword_alias keep_domain                   = keep_domain\n"
"keyword_alias misc env                      = misc env\n"
"keyword_alias network inet                  = network inet\n"
"keyword_alias network unix                  = network unix\n"
"keyword_alias no_initialize_domain          = no_initialize_domain\n"
"keyword_alias no_keep_domain                = no_keep_domain\n"
"keyword_alias no_reset_domain               = no_reset_domain\n"
"keyword_alias number_group                  = number_group\n"
"keyword_alias path_group                    = path_group\n"
"keyword_alias quota_exceeded                = quota_exceeded\n"
"keyword_alias reset_domain                  = reset_domain\n"
"keyword_alias task auto_domain_transition   = task auto_domain_transition\n"
"keyword_alias task auto_execute_handler     = task auto_execute_handler\n"
"keyword_alias task denied_execute_handler   = task denied_execute_handler\n"
"keyword_alias task manual_domain_transition = task manual_domain_transition\n"
"keyword_alias transition_failed             = transition_failed\n"
"keyword_alias use_group                     = use_group\n"
"keyword_alias use_profile                   = use_profile\n"
"\n"
"# Line color. 0 = BLACK, 1 = RED, 2 = GREEN, 3 = YELLOW, 4 = BLUE, "
"5 = MAGENTA, 6 = CYAN, 7 = WHITE\n"
"line_color ACL_CURSOR       = 03\n"
"line_color ACL_HEAD         = 03\n"
"line_color DOMAIN_CURSOR    = 02\n"
"line_color DOMAIN_HEAD      = 02\n"
"line_color EXCEPTION_CURSOR = 06\n"
"line_color EXCEPTION_HEAD   = 06\n"
"line_color MANAGER_CURSOR   = 72\n"
"line_color MANAGER_HEAD     = 72\n"
"line_color STAT_CURSOR      = 03\n"
"line_color STAT_HEAD        = 03\n"
"line_color PROFILE_CURSOR   = 71\n"
"line_color PROFILE_HEAD     = 71\n"
"line_color DEFAULT_COLOR    = 70\n";

/**
 * make_editpolicy_conf - Make /etc/ccs/tools/editpolicy.conf .
 *
 * Returns nothing.
 */
static void make_editpolicy_conf(void)
{
	FILE *fp;
	if (chdir(policy_dir) || chdir("tools") ||
	    !access("editpolicy.conf", R_OK))
		return;
	fp = fopen("editpolicy.tmp", "w");
	if (!fp) {
		fprintf(stderr, "ERROR: Can't create configuration file.\n");
		return;
	}
	fprintf(stderr, "Creating configuration file for ccs-editpolicy ... ");
	fprintf(fp, "%s", editpolicy_data);
	close_file(fp, !chmod("editpolicy.tmp", 0644), "editpolicy.tmp",
		   "editpolicy.conf");
}

/* Content of /etc/ccs/tools/auditd.conf . */
static const char auditd_data[] =
"# This file contains sorting rules used by ccs-auditd command.\n"
"\n"
"# An audit log consists with three lines. You can refer the first line\n"
"# using 'header' keyword, the second line using 'domain' keyword, and the\n"
"# third line using 'acl' keyword.\n"
"#\n"
"# Words in each line are separated by a space character. Therefore, you can\n"
"# use 'header[index]', 'domain[index]', 'acl[index]' for referring index'th\n"
"# word of the line. The index starts from 1, and 0 refers the whole line\n"
"# (i.e. 'header[0]' = 'header', 'domain[0]' = 'domain', 'acl[0]' = 'acl').\n"
"#\n"
"# Three operators are provided for conditional sorting.\n"
"# '.contains' is for 'fgrep keyword' match.\n"
"# '.equals' is for 'grep ^keyword$' match.\n"
"# '.starts' is for 'grep ^keyword' match.\n"
"#\n"
"# Sorting rules are defined using multi-lined chunks. A chunk is terminated\n"
"# by a 'destination' line which specifies the pathname to write the audit\n"
"# log. A 'destination' line is processed only when all preceding 'header',\n"
"# 'domain' and 'acl' lines in that chunk have matched.\n"
"# Evaluation stops at the first processed 'destination' line.\n"
"# Therefore, no audit logs are written more than once.\n"
"#\n"
"# More specific matches should be placed before less specific matches.\n"
"# For example:\n"
"#\n"
"# header.contains profile=3\n"
"# domain.contains /usr/sbin/httpd\n"
"# destination     /var/log/tomoyo/reject_003_httpd.log\n"
"#\n"
"# This chunk should be placed before the chunk that matches logs with\n"
"# profile=3. If placed after, the audit logs for /usr/sbin/httpd will be\n"
"# sent to /var/log/tomoyo/reject_003.log .\n"
"\n"
"# Please use TOMOYO Linux's escape rule (e.g. '\\040' rather than '\\ ' for\n"
"# representing a ' ' in a word).\n"
"\n"
"# Discard all granted logs.\n"
"header.contains granted=yes\n"
"destination     /dev/null\n"
"\n"
"# Save rejected logs with profile=0 to /var/log/tomoyo/reject_000.log\n"
"header.contains profile=0\n"
"destination     /var/log/tomoyo/reject_000.log\n"
"\n"
"# Save rejected logs with profile=1 to /var/log/tomoyo/reject_001.log\n"
"header.contains profile=1\n"
"destination     /var/log/tomoyo/reject_001.log\n"
"\n"
"# Save rejected logs with profile=2 to /var/log/tomoyo/reject_002.log\n"
"header.contains profile=2\n"
"destination     /var/log/tomoyo/reject_002.log\n"
"\n"
"# Save rejected logs with profile=3 to /var/log/tomoyo/reject_003.log\n"
"header.contains profile=3\n"
"destination     /var/log/tomoyo/reject_003.log\n"
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
"rewrite tail_pattern /etc/ccs/policy/\\*/domain_policy.conf\n"
"rewrite tail_pattern /etc/ccs/policy/\\*/exception_policy.conf\n"
"rewrite tail_pattern /etc/ccs/policy/\\*/manager.conf\n"
"rewrite tail_pattern /etc/ccs/policy/\\*/profile.conf\n"
"rewrite tail_pattern /etc/ccs/policy/\\*/\n"
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
"# /proc/ccs/manager as well as ccs-queryd command, for ccs-notifyd needs to\n"
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
		} else if (!strcmp(arg, "file-only-profile")) {
			file_only_profile = 1;
		} else if (!strcmp(arg, "full-profile")) {
			file_only_profile = 0;
		} else if (!strncmp(arg, "module_name=", 12)) {
			module_name = arg + 12;
		} else if (!strncmp(arg, "use_profile=", 12)) {
			default_profile = atoi(arg + 12);
		} else if (!strncmp(arg, "use_group=", 10)) {
			use_group[(unsigned char) atoi(arg + 10)] = 1;
		} else if (!strncmp(arg, "grant_log=", 10)) {
			grant_log = arg + 10;
		} else if (!strncmp(arg, "reject_log=", 11)) {
			reject_log = arg + 11;
		} else if (!sscanf(arg, "max_audit_log=%u", &max_audit_log) &&
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
	for (i = 0; i < 256; i++)
		if (use_group[i])
			break;
	if (i == 256)
		use_group[0] = 1;
	policy_dir = strdup(dir);
	memset(path, 0, sizeof(path));
	make_policy_dir();
	make_exception_policy();
	make_domain_policy();
	make_manager();
	make_profile();
	make_stat();
	make_module_loader();
	make_editpolicy_conf();
	make_auditd_conf();
	make_patternize_conf();
	make_notifyd_conf();
	return 0;
}
