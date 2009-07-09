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

#define elementof(x) (sizeof(x) / sizeof(x[0]))

static const char *which(const char *program)
{
	static char path[8192];
	char *cp = getenv("PATH");
	if (!cp)
		cp = "/sbin:/bin:/usr/sbin:/usr/bin:"
			"/usr/local/sbin:/usr/local/bin";
	memset(path, 0, sizeof(path));
	strncpy(path, cp, sizeof(path) - 1);
	while (path[0]) {
		cp = strchr(path, ':');
		if (cp)
			*cp = '\0';
		if (path[0] && !chdir(path) && !access(program, X_OK)) {
			const int len = strlen(path);
			snprintf(path + len, sizeof(path) - len - 1, "/%s",
				 program);
			return path;
		}
		if (!cp)
			break;
		memmove(path, cp + 1, strlen(cp + 1) + 1);
	}
	return NULL;
}

static _Bool fgrep(const char *word, const char *filename)
{
	static const int buffer_len = 4096;
	char *buffer;
	_Bool found = 0;
	const int word_len = strlen(word);
	FILE *fp = fopen(filename, "r");
	if (!fp)
		return 0;
	buffer = malloc(word_len + buffer_len + 1);
	if (!buffer) {
		fclose(fp);
		return 0;
	}
	memset(buffer, 0, word_len + buffer_len + 1);
	while (1) {
		int len;
		int i;
		len = fread(buffer + word_len, 1, buffer_len, fp);
		for (i = 0; i < word_len + len; i++)
			if (!buffer[i])
				buffer[i] = ' ';
		buffer[word_len + len] = '\0';
		if (strstr(buffer, word)) {
			found = 1;
			break;
		}
		if (len < word_len)
			break;
		memmove(buffer, buffer + len - word_len, word_len);
	}
	fclose(fp);
	free(buffer);
	return found;
}

static int scandir_file_filter(const struct dirent *buf)
{
	return (buf->d_type == DT_REG || buf->d_type == DT_UNKNOWN) &&
		strcmp(buf->d_name, ".") && strcmp(buf->d_name, "..");
}


static int scandir_dir_filter(const struct dirent *buf)
{
	return (buf->d_type == DT_DIR || buf->d_type == DT_UNKNOWN) &&
		strcmp(buf->d_name, ".") && strcmp(buf->d_name, "..");
}

static int scandir_file_and_dir_filter(const struct dirent *buf)
{
	return (buf->d_type == DT_REG || buf->d_type == DT_DIR ||
		buf->d_type == DT_UNKNOWN) &&
		strcmp(buf->d_name, ".") && strcmp(buf->d_name, "..");
}

static unsigned char revalidate_path(const char *path)
{
	struct stat buf;
	unsigned char type = DT_UNKNOWN;
	fprintf(stderr, "Revalidate %s ", path);
	if (!lstat(path, &buf)) {
		if (S_ISREG(buf.st_mode))
			type = DT_REG;
		else if (S_ISDIR(buf.st_mode))
			type = DT_DIR;
	}
	if (type == DT_UNKNOWN)
		fprintf(stderr, "failed\n");
	else
		fprintf(stderr, "ok\n");
	return type;
}

static const char *keyword = NULL;

#define SCANDIR_MAY_CONTAIN_NUMBER_WILDCARD  1
#define SCANDIR_MUST_CONTAIN_NUMBER_WILDCARD 2

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
		printf("%s ", keyword);
	while (1) {
		const char c = *str++;
		if (!c)
			break;
		if (c == '/' &&
		    (flags == SCANDIR_MAY_CONTAIN_NUMBER_WILDCARD ||
		     flags == SCANDIR_MUST_CONTAIN_NUMBER_WILDCARD)) {
			const size_t numbers = strspn(str, "0123456789");
			const char c2 = str[numbers];
			if (numbers && (c2 == '/' || !c2)) {
				printf("/\\$");
				str += numbers;
				continue;
			}
		}
		if (c == '\\') {
			putchar('\\');
			putchar('\\');
		} else if (c > ' ' && c < 127) {
			putchar(c);
		} else {
			printf("\\%c%c%c", (c >> 6) + '0',
			       ((c >> 3) & 7) + '0', (c & 7) + '0');
		}
	}
	if (keyword)
		putchar('\n');
}

static char path[8192];

static void scan_dir_for_pattern2(const unsigned int flags)
{
	struct dirent **namelist;
	int n = scandir(path, &namelist, scandir_file_and_dir_filter, 0);
	int len;
	int i;
	if (n < 0)
		return;
	len = strlen(path);
	for (i = 0; i < n; i++) {
		unsigned char type = namelist[i]->d_type;
		snprintf(path + len, sizeof(path) - len - 1, "/%s",
			 namelist[i]->d_name);
		if (type == DT_UNKNOWN)
			type = revalidate_path(path);
		if (type == DT_REG)
			printf_encoded(path, flags);
		else if (type == DT_DIR)
			scan_dir_for_pattern2(flags);
		free((void *) namelist[i]);
	}
	free((void *) namelist);
}

static void scan_dir_for_pattern(const char *dir)
{
	keyword = "file_pattern";
	memset(path, 0, sizeof(path));
	strncpy(path, dir, sizeof(path) - 1);
	return scan_dir_for_pattern2(SCANDIR_MUST_CONTAIN_NUMBER_WILDCARD);
}

static void scan_dir_for_read(const char *dir)
{
	keyword = "allow_read";
	memset(path, 0, sizeof(path));
	strncpy(path, dir, sizeof(path) - 1);
	return scan_dir_for_pattern2(SCANDIR_MAY_CONTAIN_NUMBER_WILDCARD);
}

static void scan_dir_for_depth2(int depth, int *max_depth)
{
	struct dirent **namelist;
	int n = scandir(path, &namelist, scandir_dir_filter, 0);
	int len;
	int i;
	if (n < 0)
		return;
	len = strlen(path);
	if (depth > *max_depth)
		*max_depth = depth;
	for (i = 0; i < n; i++) {
		unsigned char type = namelist[i]->d_type;
		snprintf(path + len, sizeof(path) - len - 1, "/%s",
			 namelist[i]->d_name);
		if (type == DT_UNKNOWN)
			type = revalidate_path(path);
		if (type == DT_DIR)
			scan_dir_for_depth2(depth + 1, max_depth);
		free((void *) namelist[i]);
	}
	free((void *) namelist);
}

static int scan_depth(const char *dir)
{
	int max_depth = 0;
	memset(path, 0, sizeof(path));
	strncpy(path, dir, sizeof(path) - 1);
	scan_dir_for_depth2(0, &max_depth);
	return max_depth;
}

static void printf_patterned(const char *str, const int const_len)
{
	const char *str0 = str;
	_Bool flag = 0;
	if (keyword)
		printf("%s ", keyword);
	while (str - str0 < const_len) {
		const char c = *str++;
		if (!c)
			break;
		if (c == '\\') {
			putchar('\\');
			putchar('\\');
		} else if (c > ' ' && c < 127) {
			putchar(c);
		} else {
			printf("\\%c%c%c", (c >> 6) + '0',
			       ((c >> 3) & 7) + '0', (c & 7) + '0');
		}
	}
	flag = 0;
	while (*str) {
		if (*str++ == '/') {
			putchar('/');
			flag = 0;
		} else if (!flag) {
			printf("\\*");
			flag = 1;
		}
	}
	if (keyword)
		putchar('\n');
}

static void scan_dir_for_read2(_Bool flag, int const_len)
{
	struct dirent **namelist;
	int n = scandir(path, &namelist, scandir_file_and_dir_filter, 0);
	int len;
	int i;
	_Bool done = 0;
	if (n < 0)
		return;
	len = strlen(path);
	for (i = 0; i < n; i++) {
		const char *name = namelist[i]->d_name;
		unsigned char type = namelist[i]->d_type;
		snprintf(path + len, sizeof(path) - len - 1, "/%s", name);
		if (type == DT_UNKNOWN)
			type = revalidate_path(path);
		if (type == DT_REG && flag && !done) {
			printf_patterned(path, const_len);
			done = 1;
		} else if (type == DT_DIR) {
			const _Bool f = flag ||
				!strcmp(name, "locale") ||
				!strcmp(name, "locales") ||
				!strcmp(name, "locale-langpack") ||
				strstr(name, "fonts") ||
				strstr(name, "icons");
			scan_dir_for_read2(f, f != flag ?
					   strlen(path) : const_len);
		}
		free((void *) namelist[i]);
	}
	free((void *) namelist);
}

static void scan_dir_pattern(const char *dir)
{
	keyword = "allow_read";
	memset(path, 0, sizeof(path));
	strncpy(path, dir, sizeof(path) - 1);
	scan_dir_for_read2(0, 0);
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
		char buffer[8192];
		char *cp;
		FILE *fp = fopen(files[i], "r");
		if (!fp)
			continue;
		memset(buffer, 0, sizeof(buffer));
		fgets(buffer, sizeof(buffer) - 1, fp);
		fclose(fp);
		cp = strrchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!buffer[0])
			continue;
		cp = realpath(buffer, NULL);
		if (!cp)
			continue;
		if (strcmp(cp, "/bin/true") && !access(cp, X_OK)) {
			keyword = "initialize_domain";
			printf_encoded(cp, 0);
		}
		free(cp);
	}
}

static void make_patterns_for_proc_directory(void)
{
	/* Make patterns for /proc/[number]/ and /proc/self/ directory. */
	scan_dir_for_pattern("/proc/1");
	scan_dir_for_pattern("/proc/self");
}

static void make_patterns_for_dev_directory(void)
{
	/* Make patterns for /dev/ directory. */
	puts("file_pattern /dev/pts/\\$");
	puts("file_pattern /dev/vc/\\$");
	puts("file_pattern /dev/tty\\$");
}

static void make_patterns_for_policy_directory(void)
{
	/* Make patterns for policy directory. */
	puts("file_pattern "
	     "/etc/ccs/system_policy.\\$-\\$-\\$.\\$:\\$:\\$.conf");
	puts("file_pattern "
	     "/etc/ccs/exception_policy.\\$-\\$-\\$.\\$:\\$:\\$.conf");
	puts("file_pattern "
	     "/etc/ccs/domain_policy.\\$-\\$-\\$.\\$:\\$:\\$.conf");
	puts("file_pattern "
	     "/etc/tomoyo/exception_policy.\\$-\\$-\\$.\\$:\\$:\\$.conf");
	puts("file_pattern "
	     "/etc/tomoyo/domain_policy.\\$-\\$-\\$.\\$:\\$:\\$.conf");
}

static void make_patterns_for_man_directory(void)
{
	/* Make patterns for man directory. */
	static const char *dirs[] = {
		"/usr/share/man", "/usr/X11R6/man"
	};
	int i;
	for (i = 0; i < elementof(dirs); i++) {
		const int max_depth = scan_depth(dirs[i]);
		int j;
		for (j = 0; j < max_depth; j++) {
			int k;
			printf("file_pattern %s", dirs[i]);
			for (k = 0; k <= j; k++)
				printf("/\\*");
			puts("/\\*");
		}
	}
}

static void make_patterns_for_spool_directory(void)
{
	/* Make patterns for spool directory. */
	struct stat buf;
	static const char *dirs[] = {
		"/var/spool/clientmqueue",
		"/var/spool/mail",
		"/var/spool/mqueue",
		"/var/spool/at",
		"/var/spool/exim4/msglog",
		"/var/spool/exim4/input",
		"/var/spool/cron/atjobs",
		"/var/spool/postfix/maildrop",
		"/var/spool/postfix/incoming",
		"/var/spool/postfix/active",
		"/var/spool/postfix/bounce"
	};
	int i;
	keyword = NULL;
	for (i = 0; i < elementof(dirs); i++) {
		if (lstat(dirs[i], &buf) || !S_ISDIR(buf.st_mode))
			continue;
		printf("file_pattern ");
		printf_encoded(dirs[i], 0);
		puts("/\\*");
	}
	if (!lstat("/var/spool/postfix/", &buf) && S_ISDIR(buf.st_mode)) {
		puts("file_pattern /var/spool/postfix/deferred/\\x/");
		puts("file_pattern /var/spool/postfix/deferred/\\x/\\X");
		puts("file_pattern /var/spool/postfix/defer/\\x/");
		puts("file_pattern /var/spool/postfix/defer/\\x/\\X");
	}
}

static void make_patterns_for_man(void)
{
	/* Make patterns for man(1). */
	puts("file_pattern /tmp/man.\\?\\?\\?\\?\\?\\?");
}

static void make_patterns_for_mount(void)
{
	/* Make patterns for mount(8). */
	puts("file_pattern /etc/mtab~\\$");
}

static void make_patterns_for_crontab(void)
{
	/* Make patterns for crontab(1). */
	if (fgrep("Red Hat Linux", "/etc/issue"))
		puts("file_pattern /tmp/crontab.\\$");
	if (fgrep("Fedora Core", "/etc/issue"))
		puts("file_pattern /tmp/crontab.XXXX\\?\\?\\?\\?\\?\\?");
	if (fgrep("Debian", "/etc/issue")) {
		puts("file_pattern "
		     "/tmp/crontab.\\?\\?\\?\\?\\?\\?/");
		puts("file_pattern "
		     "/tmp/crontab.\\?\\?\\?\\?\\?\\?/crontab");
	}
}

static void make_globally_readable_files(void)
{
	/* Allow reading some data files. */
	static const char *files[] = {
		"/etc/ld.so.cache", "/proc/meminfo",
		"/proc/sys/kernel/version", "/etc/localtime",
		"/usr/lib/gconv/gconv-modules.cache",
		"/usr/share/locale/locale.alias"
	};
	int i;
	keyword = "allow_read";
	for (i = 0; i < elementof(files); i++) {
		char *cp = realpath(files[i], NULL);
		if (!cp)
			continue;
		printf_encoded(cp, 0);
		free(cp);
	}
	scan_dir_pattern("/usr/share");
	scan_dir_pattern("/usr/lib");
	scan_dir_pattern("/usr/lib32");
	scan_dir_pattern("/usr/lib64");
}

static void make_self_readable_files(void)
{
	/* Allow reading information for current process. */
	scan_dir_for_read("/proc/self");
}

static void make_ldconfig_readable_files(void)
{
	/* Allow reading DLL files registered with ldconfig(8). */
	FILE *fp = popen("ldconfig -NXp", "r");
	if (!fp)
		return;
	keyword = "allow_read";
	while (memset(path, 0, sizeof(path)),
	       fgets(path, sizeof(path) - 1, fp)) {
		char *cp = strchr(path, '\n');
		if (!cp)
			break;
		*cp = '\0';
		cp = strstr(path, " => ");
		if (!cp)
			continue;
		cp = realpath(cp + 4, NULL);
		if (!cp)
			continue;
		printf_encoded(cp, 0);
		free(cp);
	}
	pclose(fp);
}

static void make_init_dir_as_initializers(void)
{
	/* Mark programs under /etc/init.d/ directory as initializer. */
	char *dir = realpath("/etc/init.d/", NULL);
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
		char *cp = realpath(files[i], NULL);
		if (!cp)
			continue;
		if (!access(cp, X_OK))
			printf_encoded(cp, 0);
		free(cp);
	}
}

static void make_patterns_for_unnamed_objects(void)
{
	/* Make patterns for unnamed pipes and sockets. */
	puts("file_pattern pipe:[\\$]");
	puts("file_pattern socket:[\\$]");
}

static void make_patterns_for_emacs(void)
{
	/* Make patterns for emacs(1). */
	struct stat buf;
	if (!lstat("/root/.emacs.d", &buf) && S_ISDIR(buf.st_mode))
		puts("file_pattern "
		     "/root/.emacs.d/auto-save-list/.saves-\\$-\\*");
}

static void make_patterns_for_mh(void)
{
	/* Make patterns for mh-rmail from emacs(1). */
	struct stat buf;
	if (!lstat("/root/Mail/inbox", &buf) && S_ISDIR(buf.st_mode))
		puts("file_pattern /root/Mail/inbox/\\$");
}

static void make_patterns_for_ksymoops(void)
{
	/* Make patterns for ksymoops(8). */
	struct stat buf;
	if (!lstat("/var/log/ksymoops", &buf) && S_ISDIR(buf.st_mode))
		puts("file_pattern /var/log/ksymoops/\\*");
}

static void make_patterns_for_squid(void)
{
	/* Make patterns for squid(8). */
	struct stat buf;
	if (!lstat("/var/spool/squid", &buf) && S_ISDIR(buf.st_mode)) {
		puts("file_pattern /var/spool/squid/\\*/");
		puts("file_pattern /var/spool/squid/\\*/\\*/");
		puts("file_pattern /var/spool/squid/\\*/\\*/\\*");
	}
}

static void make_patterns_for_spamd(void)
{
	/* Make patterns for spamd(1). */
	const char *exe = which("spamd");
	if (!exe)
		return;
	if (fgrep("/tmp/spamassassin-$$", exe)) {
		puts("file_pattern /tmp/spamassassin-\\$/");
		puts("file_pattern /tmp/spamassassin-\\$/.spamassassin/");
		puts("file_pattern "
		     "/tmp/spamassassin-\\$/.spamassassin/auto-whitelist\\*");
	}
	if (fgrep("spamd-$$-init", exe)) {
		puts("file_pattern /tmp/spamd-\\$-init/");
		puts("file_pattern /tmp/spamd-\\$-init/.spamassassin/");
		puts("file_pattern /tmp/spamd-\\$-init/.spamassassin/\\*");
	}
}

static void make_patterns_for_mail(void)
{
	/* Make patterns for mail(1). */
	const char *exe = which("mail");
	if (!exe)
		return;
	if (fgrep("/mail.XXXXXX", exe))
		puts("file_pattern /tmp/mail.\\?\\?\\?\\?\\?\\?");
	if (fgrep("/mail.RsXXXXXXXXXX", exe))
		puts("file_pattern /tmp/mail.RsXXXX\\?\\?\\?\\?\\?\\?");
	if (fgrep("/mail.ReXXXXXXXXXX", exe))
		puts("file_pattern /tmp/mail.ReXXXX\\?\\?\\?\\?\\?\\?");
	if (fgrep("/mail.XXXXXXXXXX", exe))
		puts("file_pattern /tmp/mail.XXXX\\?\\?\\?\\?\\?\\?");
	if (fgrep("/mail.RxXXXXXXXXXX", exe))
		puts("file_pattern /tmp/mail.RxXXXX\\?\\?\\?\\?\\?\\?");
	if (fgrep("/mail.RmXXXXXXXXXX", exe))
		puts("file_pattern /tmp/mail.RmXXXX\\?\\?\\?\\?\\?\\?");
	if (fgrep("/mail.RqXXXXXXXXXX", exe))
		puts("file_pattern /tmp/mail.RqXXXX\\?\\?\\?\\?\\?\\?");
	puts("file_pattern /tmp/Rs\\?\\?\\?\\?\\?\\?");
	puts("file_pattern /tmp/Rq\\?\\?\\?\\?\\?\\?");
	puts("file_pattern /tmp/Rm\\?\\?\\?\\?\\?\\?");
	puts("file_pattern /tmp/Re\\?\\?\\?\\?\\?\\?");
	puts("file_pattern /tmp/Rx\\?\\?\\?\\?\\?\\?");
}

static void make_patterns_for_udev(void)
{
	/* Make patterns for udev(8). */
	struct stat buf;
	if (!lstat("/dev/.udev", &buf) && S_ISDIR(buf.st_mode)) {
		puts("file_pattern /dev/.udev/\\*");
		puts("file_pattern /dev/.udev/\\*/");
		puts("file_pattern /dev/.udev/\\*/\\*");
		puts("file_pattern /dev/.udev/\\*/\\*/");
		puts("file_pattern /dev/.udev/\\*/\\*/\\*");
		puts("file_pattern /dev/.udev/\\*/\\*/\\*/");
		puts("file_pattern /dev/.udev/\\*/\\*/\\*/\\*");
		puts("file_pattern /dev/.udev/\\*/\\*/\\*/\\*/");
		puts("file_pattern /dev/.udev/\\*/\\*/\\*/\\*/\\*");
	}
	if (!lstat("/dev/.udevdb", &buf) && S_ISDIR(buf.st_mode))
		puts("file_pattern /dev/.udevdb/\\*");
}

static void make_patterns_for_sh(void)
{
	/* Make patterns for sh(1). */
	if (fgrep("sh-thd", "/bin/sh"))
		puts("file_pattern /tmp/sh-thd-\\$");
}

static void make_patterns_for_smbd(void)
{
	/* Make patterns for smbd(8). */
	struct stat buf;
	if (!lstat("/var/log/samba", &buf) && S_ISDIR(buf.st_mode))
		puts("file_pattern /var/log/samba/\\*");
}

static void make_patterns_for_blkid(void)
{
	/* Make patterns for blkid(8). */
	if (!access("/etc/blkid.tab", F_OK))
		puts("file_pattern /etc/blkid.tab-\\?\\?\\?\\?\\?\\?");
	if (!access("/etc/blkid/blkid.tab", F_OK))
		puts("file_pattern /etc/blkid/blkid.tab-\\?\\?\\?\\?\\?\\?");
}

static void make_patterns_for_gpm(void)
{
	/* Make patterns for gpm(8). */
	const char *exe = which("gpm");
	if (exe && fgrep("/gpmXXXXXX", exe))
		puts("file_pattern /var/run/gpm\\?\\?\\?\\?\\?\\?");
}

static void make_patterns_for_mrtg(void)
{
	/* Make patterns for mrtg(1). */
	struct stat buf;
	if (!lstat("/etc/mrtg", &buf) && S_ISDIR(buf.st_mode))
		puts("file_pattern /etc/mrtg/mrtg.cfg_l_\\$");
	if (!lstat("/var/lock/mrtg", &buf) && S_ISDIR(buf.st_mode))
		puts("file_pattern /var/lock/mrtg/mrtg_l_\\$");
}

static void make_patterns_for_autofs(void)
{
	/* Make patterns for autofs(8). */
	if (!access("/etc/init.d/autofs", X_OK) &&
	    fgrep("/tmp/autofs.XXXXXX", "/etc/init.d/autofs"))
		puts("file_pattern /tmp/autofs.\\?\\?\\?\\?\\?\\?");
}

static void make_patterns_for_dhcpd(void)
{
	/* Make patterns for dhcpd(8). */
	if (!access("/var/lib/dhcp/dhcpd.leases", F_OK))
		puts("file_pattern /var/lib/dhcp/dhcpd.leases.\\$");
}

static void make_patterns_for_mlocate(void)
{
	/* Make patterns for mlocate(1). */
	struct stat buf;
	if (!lstat("/var/lib/mlocate", &buf) && S_ISDIR(buf.st_mode))
		puts("file_pattern "
		     "/var/lib/mlocate/mlocate.db.\\?\\?\\?\\?\\?\\?");
}

static void make_patterns_for_mailman(void)
{
	/* Make patterns for mailman. */
	struct stat buf;
	if (!lstat("/var/mailman/locks", &buf) && S_ISDIR(buf.st_mode))
		puts("file_pattern /var/mailman/locks/gate_news.lock.\\*");
}

static void make_patterns_for_makewhatis(void)
{
	/* Make patterns for makewhatis(8). */
	const char *exe = which("makewhatis");
	if (!exe)
		return;
	if (fgrep("/tmp/makewhatisXXXXXX", exe)) {
		puts("file_pattern /tmp/makewhatis\\?\\?\\?\\?\\?\\?/");
		puts("file_pattern /tmp/makewhatis\\?\\?\\?\\?\\?\\?/w");
	}
	if (fgrep("/tmp/whatis.XXXXXX", exe))
		puts("file_pattern /tmp/whatis.\\?\\?\\?\\?\\?\\?");
}

static void make_patterns_for_automount(void)
{
	/* Make patterns for automount(8). */
	const char *exe = which("automount");
	if (!exe)
		return;
	if (fgrep("/var/lock/autofs", exe))
		puts("file_pattern /var/lock/autofs.\\$");
	puts("file_pattern /tmp/auto\\?\\?\\?\\?\\?\\?/");
}

static void make_patterns_for_logwatch(void)
{
	/* Make patterns for logwatch(8). */
	const char *exe = which("logwatch");
	if (!exe)
		return;
	if (fgrep("/var/cache/logwatch", exe)) {
		puts("file_pattern "
		     "/var/cache/logwatch/logwatch.XX\\?\\?\\?\\?\\?\\?/");
		puts("file_pattern "
		     "/var/cache/logwatch/logwatch.XX\\?\\?\\?\\?\\?\\?/\\*");
	} else {
		puts("file_pattern /tmp/logwatch.XX\\?\\?\\?\\?\\?\\?/");
		puts("file_pattern /tmp/logwatch.XX\\?\\?\\?\\?\\?\\?/\\*");
	}
}

static void make_patterns_for_logrotate(void)
{
	/* Make patterns for logrotate(8). */
	const char *exe = which("logrotate");
	if (exe && fgrep("/logrotate.XXXXXX", exe)) {
		puts("file_pattern /tmp/logrotate.\\?\\?\\?\\?\\?\\?");
		puts("aggregator "
		     "/tmp/logrotate.\\?\\?\\?\\?\\?\\? /tmp/logrotate.tmp");
	}
}

static void make_patterns_for_cardmgr(void)
{
	/* Make patterns for cardmgr(8). */
	const char *exe = which("cardmgr");
	if (exe && fgrep("%s/cm-%d-%d", exe))
		puts("file_pattern /var/lib/pcmcia/cm-\\$-\\$");
}

static void make_patterns_for_anacron(void)
{
	/* Make patterns for anacron(8). */
	const char *exe = which("anacron");
	if (exe)
		puts("file_pattern /tmp/file\\?\\?\\?\\?\\?\\?");
}

static void make_patterns_for_run_crons(void)
{
	/* Make patterns for run-crons(?). */
	if (!access("/usr/lib/cron/run-crons", X_OK) &&
	    fgrep("/tmp/run-crons.XXXXXX", "/usr/lib/cron/run-crons")) {
		puts("file_pattern /tmp/run-crons.\\?\\?\\?\\?\\?\\?/");
		puts("file_pattern "
		     "/tmp/run-crons.\\?\\?\\?\\?\\?\\?/run-crons.\\*");
	}
}

static void make_patterns_for_postgresql(void)
{
	/* Make patterns for postgresql. */
	struct stat buf;
	if (!lstat("/var/lib/pgsql", &buf) && S_ISDIR(buf.st_mode)) {
		puts("file_pattern /var/lib/pgsql/data/base/\\$/");
		puts("file_pattern /var/lib/pgsql/data/base/\\$/\\$");
		puts("file_pattern "
		     "/var/lib/pgsql/data/base/global/pg_database.\\$");
		puts("file_pattern "
		     "/var/lib/pgsql/data/base/\\$/pg_internal.init.\\$");
		puts("file_pattern "
		     "/var/lib/pgsql/data/base/\\$/pg_internal.init");
		puts("file_pattern "
		     "/var/lib/pgsql/data/base/pgsql_tmp/pgsql_tmp\\*");
		puts("file_pattern /var/lib/pgsql/data/base/\\$/PG_VERSION");
		puts("file_pattern /var/lib/pgsql/data/global/\\$");
		puts("file_pattern /var/lib/pgsql/data/global/pg_auth.\\$");
		puts("file_pattern /var/lib/pgsql/data/global/pg_database.\\$");
		puts("file_pattern /var/lib/pgsql/data/pg_clog/\\X");
		puts("file_pattern "
		     "/var/lib/pgsql/data/pg_multixact/members/\\X");
		puts("file_pattern "
		     "/var/lib/pgsql/data/pg_multixact/offsets/\\X");
		puts("file_pattern /var/lib/pgsql/data/pg_subtrans/\\X");
		puts("file_pattern /var/lib/pgsql/data/pg_tblspc/\\$");
		puts("file_pattern /var/lib/pgsql/data/pg_twophase/\\X");
		puts("file_pattern /var/lib/pgsql/data/pg_xlog/\\X");
		puts("file_pattern /var/lib/pgsql/data/pg_xlog/xlogtemp.\\$");
	}
	if (!lstat("/var/lib/postgres", &buf) && S_ISDIR(buf.st_mode)) {
		puts("file_pattern /var/lib/postgres/data/base/\\$/");
		puts("file_pattern /var/lib/postgres/data/base/\\$/\\$");
		puts("file_pattern /var/lib/postgres/data/global/\\$");
		puts("file_pattern "
		     "/var/lib/postgres/data/global/pgstat.tmp.\\$");
		puts("file_pattern /var/lib/postgres/data/pg_clog/\\X");
		puts("file_pattern /var/lib/postgres/data/pg_xlog/\\X");
	}
	if (!lstat("/var/lib/postgresql", &buf) && S_ISDIR(buf.st_mode)) {
		puts("file_pattern /var/lib/postgresql/\\*/main/base/\\$/");
		puts("file_pattern /var/lib/postgresql/\\*/main/base/\\$/\\$");
		puts("file_pattern /var/lib/postgresql/\\*/main/base/\\$/"
		     "pg_internal.init.\\$");
		puts("file_pattern "
		     "/var/lib/postgresql/\\*/main/base/\\$/PG_VERSION");
		puts("file_pattern /var/lib/postgresql/\\*/main/global/\\$");
		puts("file_pattern /var/lib/postgresql/\\*/main/global/\\$/"
		     "pg_auth.\\$");
		puts("file_pattern /var/lib/postgresql/\\*/main/global/\\$/"
		     "pg_database.\\$");
		puts("file_pattern /var/lib/postgresql/\\*/main/pg_clog/\\X");
		puts("file_pattern /var/lib/postgresql/\\*/main/pg_multixact/"
		     "members/\\X");
		puts("file_pattern /var/lib/postgresql/\\*/main/pg_multixact/"
		     "offsets/\\X");
		puts("file_pattern /var/lib/postgresql/\\*/main/pg_subtrans/"
		     "\\X");
		puts("file_pattern /var/lib/postgresql/\\*/main/pg_xlog/\\X");
		puts("file_pattern /var/lib/postgresql/\\*/main/pg_xlog/"
		     "xlogtemp.\\$");
	}
}

static void make_patterns_for_misc(void)
{
	/* Miscellaneous patterns. */
	struct stat buf;
	if (fgrep("Red Hat Linux", "/etc/issue")) {
		if (!lstat("/var/log/sa", &buf) && S_ISDIR(buf.st_mode))
			puts("file_pattern /var/log/sa/sa\\*");
		puts("file_pattern /tmp/man.\\?\\?\\?\\?\\?\\?");
		puts("file_pattern /tmp/file.\\?\\?\\?\\?\\?\\?");
	}
	if (fgrep("Fedora Core", "/etc/issue") ||
	    fgrep("CentOS", "/etc/issue")) {
		puts("file_pattern /etc/.fstab.hal.\\?");
		puts("file_pattern /tmp/file\\?\\?\\?\\?\\?\\?");
	}
	if (fgrep("Debian", "/etc/issue")) {
		puts("file_pattern /tmp/ex4\\?\\?\\?\\?\\?\\?");
		puts("file_pattern /tmp/tmpf\\?\\?\\?\\?\\?\\?");
		puts("file_pattern /tmp/zcat\\?\\?\\?\\?\\?\\?");
		puts("file_pattern /tmp/zman\\?\\?\\?\\?\\?\\?");
		puts("file_pattern /var/cache/man/\\$");
		puts("file_pattern /var/cache/man/\\*/\\$");
		puts("file_pattern /root/mbox.XXXX\\?\\?\\?\\?\\?\\?");
	}
	if (fgrep("SUSE LINUX 10", "/etc/issue")) {
		puts("file_pattern /tmp/used_interface_names.\\*");
		puts("file_pattern /var/run/fence\\?\\?\\?\\?\\?\\?");
		puts("file_pattern /dev/shm/sysconfig/tmp/if-lo.\\$");
		puts("file_pattern /dev/shm/sysconfig/tmp/if-lo.\\$.tmp");
		puts("file_pattern /dev/shm/sysconfig/tmp/if-eth0.\\$");
		puts("file_pattern /dev/shm/sysconfig/tmp/if-eth0.\\$.tmp");
		puts("file_pattern /var/run/nscd/db\\?\\?\\?\\?\\?\\?");
	}

	if (!lstat("/var/lib/init.d", &buf) && S_ISDIR(buf.st_mode)) {
		puts("file_pattern /var/lib/init.d/mtime-test.\\$");
		puts("file_pattern /var/lib/init.d/exclusive/\\*.\\$");
		puts("file_pattern "
		     "/var/lib/init.d/depcache.\\?\\?\\?\\?\\?\\?\\?");
		puts("file_pattern "
		     "/var/lib/init.d/treecache.\\?\\?\\?\\?\\?\\?\\?");
	}

	puts("file_pattern /etc/group.\\$");
	puts("file_pattern /etc/gshadow.\\$");
	puts("file_pattern /etc/passwd.\\$");
	puts("file_pattern /etc/shadow.\\$");
	puts("file_pattern /var/cache/logwatch/logwatch.\\*/");
	puts("file_pattern /var/cache/logwatch/logwatch.\\*/\\*");
	puts("file_pattern /var/tmp/sqlite_\\*");
	puts("file_pattern /tmp/ib\\?\\?\\?\\?\\?\\?");
	puts("file_pattern /tmp/PerlIO_\\?\\?\\?\\?\\?\\?");
	if (!lstat("/var/run/hald", &buf) && S_ISDIR(buf.st_mode))
		puts("file_pattern /var/run/hald/acl-list.\\?\\?\\?\\?\\?\\?");
	if (!lstat("/usr/share/zoneinfo", &buf) && S_ISDIR(buf.st_mode)) {
		puts("file_pattern /usr/share/zoneinfo/\\*");
		puts("file_pattern /usr/share/zoneinfo/\\*/\\*");
		puts("file_pattern /usr/share/zoneinfo/\\*/\\*/\\*");
		puts("file_pattern /usr/share/zoneinfo/\\*/\\*/\\*/\\*");
	}
}

static void make_deny_rewrite_for_log_directory(void)
{
	/* Make /var/log/ directory not rewritable by default. */
	struct stat buf;
	if (!lstat("/var/log", &buf) && S_ISDIR(buf.st_mode)) {
		const int max_depth = scan_depth("/var/log");
		int j;
		for (j = 0; j < max_depth; j++) {
			int k;
			printf("deny_rewrite /var/log");
			for (k = 0; k <= j; k++)
				printf("/\\*");
			putchar('\n');
		}
	}
}

int main(int argc, char *argv[])
{
	scan_modprobe_and_hotplug();
	make_patterns_for_proc_directory();
	make_patterns_for_dev_directory();
	make_patterns_for_policy_directory();
	make_patterns_for_man_directory();
	make_patterns_for_spool_directory();
	make_patterns_for_man();
	make_patterns_for_mount();
	make_patterns_for_crontab();
	make_globally_readable_files();
	make_self_readable_files();
	make_ldconfig_readable_files();
	make_init_dir_as_initializers();
	make_initializers();
	make_patterns_for_unnamed_objects();
	make_patterns_for_emacs();
	make_patterns_for_mh();
	make_patterns_for_ksymoops();
	make_patterns_for_squid();
	make_patterns_for_spamd();
	make_patterns_for_mail();
	make_patterns_for_udev();
	make_patterns_for_sh();
	make_patterns_for_smbd();
	make_patterns_for_blkid();
	make_patterns_for_gpm();
	make_patterns_for_mrtg();
	make_patterns_for_autofs();
	make_patterns_for_dhcpd();
	make_patterns_for_mlocate();
	make_patterns_for_mailman();
	make_patterns_for_makewhatis();
	make_patterns_for_automount();
	make_patterns_for_logwatch();
	make_patterns_for_logrotate();
	make_patterns_for_cardmgr();
	make_patterns_for_anacron();
	make_patterns_for_run_crons();
	make_patterns_for_postgresql();
	make_patterns_for_misc();
	make_deny_rewrite_for_log_directory();
	return 0;
}
