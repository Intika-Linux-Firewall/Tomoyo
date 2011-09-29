/* gcc -O3 -o /kernel-test kernel-test.c */
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

#if (!defined(TOMOYO_2) && !defined(TOMOYO_1)) || (defined(TOMOYO_2) && defined(TOMOYO_1))
#error Pass either -DTOMOYO_2 or -DTOMOYO_1
#endif

static char *freadline(FILE *fp)
{
	static char *line = NULL;
        int pos = 0;
        while (1) {
                static int max_line_len = 0;
                const int c = fgetc(fp);
                if (c == EOF)
                        return NULL;
                if (pos == max_line_len) {
                        max_line_len += 4096;
                        line = realloc(line, max_line_len);
			if (!line) {
				fprintf(stderr, "Out of memory\n");
				exit(1);
			}
                }
                line[pos++] = (char) c;
                if (c == '\n') {
                        line[--pos] = '\0';
                        break;
                }
        }
        return line;
}

static FILE *fopen2(const char *filename, const char *mode)
{
#ifndef TOMOYO_2
	FILE *fp = fopen(filename, mode);
#else
	char buffer[128];
	FILE *fp = NULL;
	if (!strncmp(filename, "/proc/ccs/", 10)) {
		memset(buffer, 0, sizeof(buffer));
		snprintf(buffer, sizeof(buffer) - 1,
			 "/sys/kernel/security/tomoyo/%s", filename + 10);
		filename = buffer;
		fp = fopen(filename, mode);
	}
#endif
	if (fp)
		return fp;
	fprintf(stderr, "Can't open %s\n", filename);
	exit(1);
}

static _Bool find_domain_policy(const char *policy)
{
	static FILE *fp = NULL;
	if (!fp)
		fp = fopen2("/proc/ccs/domain_policy", "a+");
	fseek(fp, 0, SEEK_SET);
	fprintf(fp, "select domain=</kernel-test>\n");
	fflush(fp);
	fseek(fp, 0, SEEK_SET);
	/* printf("Finding <%s>\n", policy); */
	while (1) {
		char *line = freadline(fp);
		if (!line)
			break;
		/* printf("Read <%s>\n", line); */
		if (strcmp(line, policy))
			continue;
		return 1;
	}
	return 0;
}

static void write_domain_policy(const char *policy)
{
	static FILE *fp = NULL;
	if (!fp)
		fp = fopen2("/proc/ccs/domain_policy", "a");
	fprintf(fp, "select </kernel-test>\n%s\n", policy);
	fflush(fp);
	if (!find_domain_policy(policy)) {
		fprintf(stderr, "Can't write domain policy: %s\n", policy);
		exit(1);
	}
}

static void delete_domain_policy(const char *policy)
{
	static FILE *fp = NULL;
	if (!fp)
		fp = fopen2("/proc/ccs/domain_policy", "a");
	fprintf(fp, "select </kernel-test>\ndelete %s\n", policy);
	fflush(fp);
	if (find_domain_policy(policy)) {
		fprintf(stderr, "Can't delete domain policy: %s\n", policy);
		exit(1);
	}
}

static _Bool find_child_domain_policy(const char *policy)
{
	static FILE *fp = NULL;
	if (!fp)
		fp = fopen2("/proc/ccs/domain_policy", "a+");
	fseek(fp, 0, SEEK_SET);
	fprintf(fp, "select domain=</kernel-test> /bin/true\n");
	fflush(fp);
	fseek(fp, 0, SEEK_SET);
	/* printf("Finding <%s>\n", policy); */
	while (1) {
		char *line = freadline(fp);
		if (!line)
			break;
		/* printf("Read <%s>\n", line); */
		if (strcmp(line, policy))
			continue;
		return 1;
	}
	return 0;
}

static void write_child_domain_policy(const char *policy)
{
	static FILE *fp = NULL;
	if (!fp)
		fp = fopen2("/proc/ccs/domain_policy", "a");
	fprintf(fp, "select </kernel-test> /bin/true\n%s\n", policy);
	fflush(fp);
	if (!find_child_domain_policy(policy)) {
		fprintf(stderr, "Can't write domain policy: %s\n", policy);
		exit(1);
	}
}

static void delete_child_domain_policy(const char *policy)
{
	static FILE *fp = NULL;
	if (!fp)
		fp = fopen2("/proc/ccs/domain_policy", "a");
	fprintf(fp, "select </kernel-test> /bin/true\ndelete %s\n", policy);
	fflush(fp);
	if (find_child_domain_policy(policy)) {
		fprintf(stderr, "Can't delete domain policy: %s\n", policy);
		exit(1);
	}
}

static void write_bad_domain_policy(const char *policy)
{
	static FILE *fp = NULL;
	if (!fp)
		fp = fopen2("/proc/ccs/domain_policy", "a");
	fprintf(fp, "select </kernel-test>\n%s\n", policy);
	fflush(fp);
	if (find_domain_policy(policy)) {
		fprintf(stderr, "Can't reject bad domain policy: %s\n",
			policy);
		exit(1);
	}
}

static void write_profile(const char *policy)
{
	static FILE *fp = NULL;
	if (!fp)
		fp = fopen2("/proc/ccs/profile", "a");
	fprintf(fp, "</kernel-test> 128-%s\n", policy);
	fflush(fp);
}

static void init_policy(int argc)
{
	{
		FILE *fp = fopen2("/proc/ccs/profile", "a");
		fprintf(fp, "</kernel-test> 128-COMMENT=kernel testing\n");
		fclose(fp);
	}
	{
		FILE *fp_in = fopen2("/proc/ccs/profile", "r");
		FILE *fp_out = fopen2("/proc/ccs/profile", "a");
		while (1) {
			char *line = freadline(fp_in);
			char *cp;
			if (!line)
				break;
			if (strncmp(line, "</kernel-test> ", 15))
				continue;
			cp = strchr(line, '=');
			if (!cp)
				continue;
			*cp = '\0';
			if (strstr(line, "CONFIG::"))
				fprintf(fp_out, "%s=use_default\n", line);
			else if (strstr(line, "CONFIG"))
				fprintf(fp_out, "%s={ mode=disabled "
					"grant_log=no reject_log=no\n", line);
			else if (strstr(line, "PREFERENCE"))
				fprintf(fp_out, "%s={ max_audit_log=0 "
					"max_learning_entry=0 "
					"enforcing_penalty=0 \n", line);
		}
		fclose(fp_in);
		fclose(fp_out);
	}
	{
		FILE *fp = fopen2("/proc/ccs/profile", "r");
		while (1) {
			char *line = freadline(fp);
			char *cp;
			if (!line)
				break;
			if (strncmp(line, "</kernel-test> ", 15))
				continue;
			cp = strchr(line, '=');
			if (!cp)
				continue;
			*cp = '\0';
			if (!strstr(line, "::"))
				continue;
			fprintf(stderr, "Policy not deleted: %s\n", line);
			exit(1);
		}
		fclose(fp);
	}
	{
		FILE *fp_in = fopen2("/proc/ccs/exception_policy", "r");
		FILE *fp_out = fopen2("/proc/ccs/exception_policy", "a");
		while (1) {
			char *line = freadline(fp_in);
			if (!line)
				break;
			if (strncmp(line, "</kernel-test> ", 15))
				continue;
			fprintf(fp_out, "delete %s\n", line);
		}
		fclose(fp_in);
		fclose(fp_out);
	}
	{
		FILE *fp = fopen2("/proc/ccs/exception_policy", "r");
		while (1) {
			char *line = freadline(fp);
			if (!line)
				break;
			if (strncmp(line, "</kernel-test> ", 15))
				continue;
			fprintf(stderr, "Policy not deleted: %s\n", line);
			exit(1);
		}
		fclose(fp);
	}
	{
		FILE *fp_in = fopen2("/proc/ccs/domain_policy", "r");
		FILE *fp_out = fopen2("/proc/ccs/domain_policy", "a");
		while (1) {
			char *line = freadline(fp_in);
			if (!line)
				break;
			if (strncmp(line, "</kernel-test> ", 15))
				continue;
			fprintf(fp_out, "delete %s\n", line);
		}
		if (argc == 1)
			fprintf(fp_out, "delete </kernel-test>\n");
		fclose(fp_in);
		fclose(fp_out);
	}
	{
		FILE *fp = fopen2("/proc/ccs/domain_policy", "r");
		while (1) {
			char *line = freadline(fp);
			if (!line)
				break;
			if (strncmp(line, "</kernel-test> ", 15))
				continue;
			fprintf(stderr, "Policy not deleted: %s\n", line);
			exit(1);
		}
		fclose(fp);
	}
#if 1 //#ifndef TOMOYO_2
	{
		FILE *fp1 = fopen2("/proc/ccs/domain_policy", "a");
		FILE *fp2 = fopen2("/proc/ccs/self_domain", "a");
		fprintf(fp1, "</kernel-test>\n"
			"use_profile 128\n"
			"use_group 64\n"
			"select pid=%u\n"
			"task manual_domain_transition </kernel-test>\n",
			getpid());
		fprintf(fp1, "</kernel-test> /bin/true\n"
			"use_profile 128\n"
			"use_group 64\n");
		fflush(fp1);
		fprintf(fp2, "</kernel-test>\n");
		fflush(fp2);
		fprintf(fp1, "delete task manual_domain_transition "
			"</kernel-test>\n");
		fclose(fp1);
	}
#else
	if (argc == 1) {
		FILE *fp = fopen2("/proc/ccs/domain_policy", "a");
		fprintf(fp, "</kernel-test>\n"
			"use_profile 128\n"
			"use_group 64\n");
		fclose(fp);
		fp = fopen2("/proc/ccs/exception_policy", "a");
		/* Assume we are in <kernel> namespace. */
		fprintf(fp, "reset_domain /kernel-test from "
			"/kernel-test\n");
		fclose(fp);
		execlp("/kernel-test", "/kernel-test", "", NULL);
		fprintf(stderr, "Can't execute /kernel-test\n");
		exit(1);
	}
#endif
	{
		FILE *fp = fopen2("/proc/ccs/self_domain", "r");
		char buffer[1024];
		memset(buffer, 0, sizeof(buffer));
		fgets(buffer, sizeof(buffer) - 1, fp);
		if (strcmp(buffer, "</kernel-test>")) {
			fprintf(stderr, "Can't change domain. %s\n", buffer);
			exit(1);
		}
		fclose(fp);
	}
	write_domain_policy("file read /");
	delete_domain_policy("file read /");
	write_bad_domain_policy("file read / /");
	write_profile("");
}

static void show_file_exec(const char *prompt, int result,
			   _Bool should_success)
{
	const int err = errno;
	printf("%s : ", prompt);
	if (should_success) {
		if (result != EOF)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(err));
	} else {
		if (result == EOF) {
			if (err == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("FAILED: %s\n", strerror(err));
		} else {
			printf("BUG: didn't fail.\n");
		}
	}
}

static void show_file_open(const char *prompt, int result,
			   _Bool should_success)
{
	show_file_exec(prompt, result, should_success);
	if (result != EOF)
		close(result);
}

static void do_open_test(void)
{
	const char *policy;

	policy = "file read /dev/null";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	
	policy = "file write /dev/null";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_WRONLY), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_WRONLY), 0);
	
	policy = "file read/write /dev/null";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDWR), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDWR), 0);
	
	policy = "file append /dev/null";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_WRONLY | O_APPEND), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_WRONLY | O_APPEND), 0);
	
	policy = "file read/append /dev/null";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDWR | O_APPEND), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDWR | O_APPEND), 0);
	
	/*
	policy = "file read /dev/null task.uid=path1.uid";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);

	policy = "file read /dev/null task.uid=path1.uid 1=1";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);

	policy = "file read /dev/null task.uid!=path1.uid 1=1";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);

	policy = "file read /dev/null task.uid=path1.uid 1!=1";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);

	policy = "file read /dev/null path1.uid=path2.uid";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	*/
}

static void do_cond_policy_test(void)
{
	const char *policy;
	
	policy = "file read /dev/null 0=0 1=1 2=2 3=3 4=4 5=5 6=6 7=7 8=8 9=9 "
		"10=10 11=11 12=12 13=13 14=14 15=15 16=16 17=17 18=18 19=19 "
		"20=20 21=21 22=22 23=23 24=24 25=25 26=26 27=27 28=28 29=29 "
		"30=30 31=31 32=32 33=33 34=34 35=35 36=36 37=37 38=38 39=39 "
		"40=40 41=41 42=42 43=43 44=44 45=45 46=46 47=47 48=48 49=49 "
		"50=50 51=51 52=52 53=53 54=54 55=55 56=56 57=57 58=58 59=59 "
		"60=60 61=61 62=62 63=63 64=64 65=65 66=66 67=67 68=68 69=69 "
		"70=70 71=71 72=72 73=73 74=74 75=75 76=76 77=77 78=78 79=79 "
		"80=80 81=81 82=82 83=83 84=84 85=85 86=86 87=87 88=88 89=89 "
		"90=90 91=91 92=92 93=93 94=94 95=95 96=96 97=97 98=98 99=99";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);

	policy = "file read /dev/null path1.uid=path1.uid path1.gid=path1.gid "
		"path1.ino=path1.ino path1.major=path1.major "
		"path1.minor=path1.minor path1.perm=path1.perm "
		"path1.type=path1.type path1.dev_major=path1.dev_major "
		"path1.dev_minor=path1.dev_minor "
		"path1.parent.uid=path1.parent.uid "
		"path1.parent.gid=path1.parent.gid "
		"path1.parent.ino=path1.parent.ino "
		"task.uid=task.uid task.euid=task.euid task.suid=task.suid "
		"task.fsuid=task.fsuid task.gid=task.gid task.egid=task.egid "
		"task.sgid=task.sgid task.fsgid=task.fsgid task.pid=task.pid "
		"task.ppid=task.ppid";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);

	policy = "file read /dev/null path1.uid=path2.uid path1.gid=path2.gid "
                "path1.ino=path2.ino path1.major=path2.major "
                "path1.minor=path2.minor path1.perm=path2.perm "
                "path1.type=path2.type path1.dev_major=path2.dev_major "
                "path1.dev_minor=path2.dev_minor "
                "path1.parent.uid=path2.parent.uid "
                "path1.parent.gid=path2.parent.gid "
                "path1.parent.ino=path2.parent.ino "
                "task.uid=task.uid task.euid=task.euid task.suid=task.suid "
                "task.fsuid=task.fsuid task.gid=task.gid task.egid=task.egid "
                "task.sgid=task.sgid task.fsgid=task.fsgid task.pid=task.pid "
                "task.ppid=task.ppid";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);

	policy = "file read /dev/null 0=0 1=1 2=2 3=3 4=4 5=5 6=6 7=7 8=8 9=9 "
		"10=10 11=11 12=12 13=13 14=14 15=15 16=16 17=17 18=18 19=19 "
		"20=20 21=21 22=22 23=23 24=24 25=25 26=26 27=27 28=28 29=29 "
		"30=30 31=31 32=32 33=33 34=34 35=35 36=36 37=37 38=38 39=39 "
		"40=40 41=41 42=42 43=43 44=44 45=45 46=46 47=47 48=48 49=49 "
		"50=50 51=51 52=52 53=53 54=54 55=55 56=56 57=57 58=58 59=59 "
		"60=60 61=61 62=62 63=63 64=64 65=65 66=66 67=67 68=68 69=69 "
		"70=70 71=71 72=72 73=73 74=74 75=75 76=76 77=77 78=78 79=79 "
		"80=80 81=81 82=82 83=83 84=84 85=85 86=86 87=87 88=88 89=89 "
		"90=90 91=91 92=92 93=93 94=94 95=95 96=96 97=97 98=98 99=99 "
		"path1.uid=path1.uid path1.gid=path1.gid path1.ino=path1.ino "
		"path1.major=path1.major path1.minor=path1.minor "
		"path1.perm=path1.perm path1.type=path1.type "
		"path1.dev_major=path1.dev_major "
		"path1.dev_minor=path1.dev_minor "
		"path1.parent.uid=path1.parent.uid "
		"path1.parent.gid=path1.parent.gid "
		"path1.parent.ino=path1.parent.ino "
		"task.uid=task.uid task.euid=task.euid task.suid=task.suid "
		"task.fsuid=task.fsuid task.gid=task.gid task.egid=task.egid "
		"task.sgid=task.sgid task.fsgid=task.fsgid task.pid=task.pid "
		"task.ppid=task.ppid path1.dev_major=1 path1.dev_minor=3 "
		"task.uid=path1.uid task.gid=path1.gid path1.perm=0666";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);

	policy = "file read /dev/null 0=0 1=1 2=2 3=3 4=4 5=5 6=6 7=7 8=8 9=9 "
		"10=10 11=11 12=12 13=13 14=14 15=15 16=16 17=17 18=18 19=19 "
		"20=20 21=21 22=22 23=23 24=24 25=25 26=26 27=27 28=28 29=29 "
		"30=30 31=31 32=32 33=33 34=34 35=35 36=36 37=37 38=38 39=39 "
		"40=40 41=41 42=42 43=43 44=44 45=45 46=46 47=47 48=48 49=49 "
		"50=50 51=51 52=52 53=53 54=54 55=55 56=56 57=57 58=58 59=59 "
		"60=60 61=61 62=62 63=63 64=64 65=65 66=66 67=67 68=68 69=69 "
		"70=70 71=71 72=72 73=73 74=74 75=75 76=76 77=77 78=78 79=79 "
		"80=80 81=81 82=82 83=83 84=84 85=85 86=86 87=87 88=88 89=89 "
		"90=90 91=91 92=92 93=93 94=94 95=95 96=96 97=97 98=98 99=99 "
		"path1.uid=path1.uid path1.gid=path1.gid path1.ino=path1.ino "
		"path1.major=path1.major path1.minor=path1.minor "
		"path1.perm=path1.perm path1.type=path1.type "
		"path1.dev_major=path1.dev_major "
		"path1.dev_minor=path1.dev_minor "
		"path1.parent.uid=path1.parent.uid "
		"path1.parent.gid=path1.parent.gid "
		"path1.parent.ino=path1.parent.ino "
		"task.uid=task.uid task.euid=task.euid task.suid=task.suid "
		"task.fsuid=task.fsuid task.gid=task.gid task.egid=task.egid "
		"task.sgid=task.sgid task.fsgid=task.fsgid task.pid=task.pid "
		"task.ppid=task.ppid path1.dev_major=1 path1.dev_minor=3 "
		"task.uid=path1.uid task.gid=path1.gid path1.perm=0666 "
		"symlink.target=\"\" symlink.target=@FOO";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	
	policy = "file read /dev/null 0=0 1=1 2=2 3=3 4=4 5=5 6=6 7=7 8=8 9=9 "
		"10=10 11=11 12=12 13=13 14=14 15=15 16=16 17=17 18=18 19=19 "
		"20=20 21=21 22=22 23=23 24=24 25=25 26=26 27=27 28=28 29=29 "
		"30=30 31=31 32=32 33=33 34=34 35=35 36=36 37=37 38=38 39=39 "
		"40=40 41=41 42=42 43=43 44=44 45=45 46=46 47=47 48=48 49=49 "
		"50=50 51=51 52=52 53=53 54=54 55=55 56=56 57=57 58=58 59=59 "
		"60=60 61=61 62=62 63=63 64=64 65=65 66=66 67=67 68=68 69=69 "
		"70=70 71=71 72=72 73=73 74=74 75=75 76=76 77=77 78=78 79=79 "
		"80=80 81=81 82=82 83=83 84=84 85=85 86=86 87=87 88=88 89=89 "
		"90=90 91=91 92=92 93=93 94=94 95=95 96=96 97=97 98=98 99=99 "
		"path1.uid=path1.uid path1.gid=path1.gid path1.ino=path1.ino "
		"path1.major=path1.major path1.minor=path1.minor "
		"path1.perm=path1.perm path1.type=path1.type "
		"path1.dev_major=path1.dev_major "
		"path1.dev_minor=path1.dev_minor "
		"path1.parent.uid=path1.parent.uid "
		"path1.parent.gid=path1.parent.gid "
		"path1.parent.ino=path1.parent.ino "
		"task.uid=task.uid task.euid=task.euid task.suid=task.suid "
		"task.fsuid=task.fsuid task.gid=task.gid task.egid=task.egid "
		"task.sgid=task.sgid task.fsgid=task.fsgid task.pid=task.pid "
		"task.ppid=task.ppid path1.dev_major=1 path1.dev_minor=3 "
		"task.uid=path1.uid task.gid=path1.gid path1.perm=0666 "
		"exec.realpath=\"\" exec.realpath=@BAR";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	
	policy = "file read /dev/null 0=0 1=1 2=2 3=3 4=4 5=5 6=6 7=7 8=8 9=9 "
		"exec.argv[0]=\"\" exec.argv[1]=\"\" exec.argv[0]=\"@BUZ\"";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
	
	policy = "file read /dev/null path1.type!=socket path1.type!=symlink "
		"path1.type!=file path1.type!=block path1.type!=directory "
		"path1.type=char path1.type!=fifo path1.perm!=setuid "
		"path1.perm!=setgid path1.perm!=sticky path1.perm=owner_read "
		"path1.perm=owner_write path1.perm!=owner_execute "
		"path1.perm=group_read path1.perm=group_write "
		"path1.perm!=group_execute path1.perm=others_read "
		"path1.perm=others_write path1.perm!=others_execute";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);

#ifndef TOMOYO_2
	policy = "file read /dev/null task.type=task.type "
		"task.type!=execute_handler execute_handler=execute_handler";
	write_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 1);
	delete_domain_policy(policy);
	show_file_open(policy, open("/dev/null", O_RDONLY), 0);
#endif
}

static int try_exec(char **argv, char **envp)
{
	int ret;
	int status = 0;
	int pipe_fd[2] = { EOF, EOF };
	if (pipe(pipe_fd)) {
		fprintf(stderr, "Can't create pipe\n.");
		exit(1);
	}
	switch (fork()) {
	case 0:
		execve("/bin/true", argv, envp);
		/* Unreachable if execve() succeeded. */
		status = errno;
		ret = write(pipe_fd[1], &status, sizeof(status));
		_exit(0);
	case -1:
		fprintf(stderr, "Can't fork()\n");
		exit(1);
	default:
		close(pipe_fd[1]);
		ret = read(pipe_fd[0], &status, sizeof(status));
		close(pipe_fd[0]);
		errno = status;
	}
	return ret ? EOF : 0;
}

static void do_exec_test(void)
{
	const char *policy;
	char *argv[128];
	char *envp[128];
	char buffer[16384];
	char buf[4100];
	int i;
	int j;
	int k;

	memset(argv, 0, sizeof(argv));
	memset(envp, 0, sizeof(envp));
	memset(buffer, 0, sizeof(buffer));
	memset(buf, 0, sizeof(buf));
	argv[0] = "/bin/true";
	for (i = 4050; i < sizeof(buf) - 1; i++) {
		memset(buf, 'a', i);
		argv[1] = buf;
		argv[2] = buf;
		argv[3] = buf;
		envp[0] = buf;
		envp[1] = buf;
		for (j = 1; j < 6; j++) {
			snprintf(buffer, sizeof(buffer) - 1,
				 "file execute /bin/true exec.argv[%d]=\"%s\"",
				 j, buf);
			policy = buffer;
			write_domain_policy(policy);
			show_file_exec(policy, try_exec(argv, envp),
				       i <= 4096 - 10 && j < 4);
			delete_domain_policy(policy);
			show_file_exec(policy, try_exec(argv, envp), 0);
		}
	}

	memset(argv, 0, sizeof(argv));
	memset(envp, 0, sizeof(envp));
	memset(buffer, 0, sizeof(buffer));
	memset(buf, 0, sizeof(buf));
	argv[0] = "/bin/true";
	j = strlen("name\\040and\\040value=");
	k = snprintf(buf, sizeof(buf) - 1, "name and value=");
	for (i = 4050; i < sizeof(buf) - 1 - k; i++) {
		memset(buf + k, 'a', i);
		envp[0] = buf;
		envp[1] = buf;
		envp[2] = buf;
		envp[3] = buf;
		snprintf(buffer, sizeof(buffer) - 1, "file execute /bin/true "
			 "exec.envp[\"name\\040and\\040value\"]=\"%s\"",
			 buf + k);
		policy = buffer;
		write_domain_policy(policy);
		show_file_exec(policy, try_exec(argv, envp),
			       i <= 4096 - 10 - j);
		delete_domain_policy(policy);
		show_file_exec(policy, try_exec(argv, envp), 0);
	}

	memset(argv, 0, sizeof(argv));
	memset(envp, 0, sizeof(envp));
	memset(buffer, 0, sizeof(buffer));
	memset(buf, 0, sizeof(buf));
	argv[0] = "/bin/true";
	for (i = 4050; i < sizeof(buf) - 2; i++) {
		memset(buf, 'a', i);
		buf[i] = '\0';
		snprintf(buffer, sizeof(buffer) - 1, "file execute /bin/true "
			 "exec.envp[\"%s\"]=\"\"", buf);
		buf[i] = '=';
		buf[i + 1] = '\0';
		envp[0] = buf;
		envp[1] = buf;
		envp[2] = buf;
		envp[3] = buf;
		policy = buffer;
		write_domain_policy(policy);
		show_file_exec(policy, try_exec(argv, envp),
			       i <= 4096 - 10 - 1);
		delete_domain_policy(policy);
		show_file_exec(policy, try_exec(argv, envp), 0);
	}
}

static void do_env_test(void)
{
	const char *policy;
	char *argv[2] = { "/bin/true", NULL };
	char *envp[16];
	char buffer[16384];
	char buf[4100];
	int i;
	int j;
	int k;

	memset(envp, 0, sizeof(envp));
	memset(buffer, 0, sizeof(buffer));
	memset(buf, 0, sizeof(buf));
	memmove(buf, "ENV=", 4);
	envp[0] = buf;
	for (i = 4050; i < sizeof(buf) - 1 - 4; i++) {
		memset(buf + 4, 'a', i);
		snprintf(buffer, sizeof(buffer) - 1,
			 "misc env ENV exec.envp[\"ENV\"]=\"%s\"", buf + 4);
		policy = buffer;
		write_child_domain_policy(policy);
		delete_child_domain_policy(policy);
		write_child_domain_policy(policy);
		show_file_exec(policy, try_exec(argv, envp), i <= 4096 - 10 - 4);
		delete_child_domain_policy(policy);
		show_file_exec(policy, try_exec(argv, envp), 0);
	}

	memset(buffer, 0, sizeof(buffer));
	memset(buf, 0, sizeof(buf));
	j = strlen("name\\040and\\040value=");
	k = snprintf(buf, sizeof(buf) - 1, "name and value=");
	for (i = 4050; i < sizeof(buf) - 1 - k; i++) {
		memset(buf + k, 'a', i);
		envp[0] = buf;
		envp[1] = buf;
		envp[2] = buf;
		envp[3] = buf;
		snprintf(buffer, sizeof(buffer) - 1, "misc env "
			 "name\\040and\\040value "
			 "exec.envp[\"name\\040and\\040value\"]=\"%s\"",
			 buf + k);
		policy = buffer;
		write_child_domain_policy(policy);
		show_file_exec(policy, try_exec(argv, envp),
			       i <= 4096 - 10 - j);
		delete_child_domain_policy(policy);
		show_file_exec(policy, try_exec(argv, envp), 0);
	}

	memset(buffer, 0, sizeof(buffer));
	memset(buf, 0, sizeof(buf));
	argv[0] = "/bin/true";
	for (i = 4050; i < sizeof(buf) - 2; i++) {
		memset(buf, 'a', i);
		buf[i] = '\0';
		snprintf(buffer, sizeof(buffer) - 1, "misc env %s "
			 "exec.envp[\"%s\"]=\"\"", buf, buf);
		buf[i] = '=';
		buf[i + 1] = '\0';
		envp[0] = buf;
		envp[1] = buf;
		envp[2] = buf;
		envp[3] = buf;
		policy = buffer;
		write_child_domain_policy(policy);
		show_file_exec(policy, try_exec(argv, envp),
			       i <= 4096 - 10 - 1);
		delete_child_domain_policy(policy);
		show_file_exec(policy, try_exec(argv, envp), 0);
	}

	memset(envp, 0, sizeof(envp));
	envp[0] = "PWD=/tmp";
	envp[1] = "OLDPWD=/";
	policy = "misc env PWD";
	write_child_domain_policy(policy);

	policy = "misc env OLDPWD exec.envp[\"PWD\"]!=NULL";
	write_child_domain_policy(policy);
	show_file_exec(policy, try_exec(argv, envp), 1);
	delete_child_domain_policy(policy);
	show_file_exec(policy, try_exec(argv, envp), 0);

	policy = "misc env OLDPWD exec.envp[\"PWD\"]=\"/tmp\"";
	write_child_domain_policy(policy);
	show_file_exec(policy, try_exec(argv, envp), 1);
	delete_child_domain_policy(policy);
	show_file_exec(policy, try_exec(argv, envp), 0);

	policy = "misc env OLDPWD exec.envp[\"PWD\"]!=\"/tmp/\"";
	write_child_domain_policy(policy);
	show_file_exec(policy, try_exec(argv, envp), 1);
	delete_child_domain_policy(policy);
	show_file_exec(policy, try_exec(argv, envp), 0);

	policy = "misc env PWD";
	delete_child_domain_policy(policy);

	policy = "misc env \\*PWD";
	write_child_domain_policy(policy);
	show_file_exec(policy, try_exec(argv, envp), 1);
	delete_child_domain_policy(policy);
	show_file_exec(policy, try_exec(argv, envp), 0);
}

int main(int argc, char *argv[])
{
	int i;
	init_policy(argc);
	write_profile("CONFIG::file::open={ mode=enforcing }");
	for (i = 0; i < 2; i++)
		do_open_test();
	do_cond_policy_test();
	write_profile("CONFIG::file::open={ mode=disabled }");
	write_profile("CONFIG::file::execute={ mode=enforcing }");
	do_exec_test();
	write_profile("CONFIG::file::execute={ mode=disabled }");
	write_profile("CONFIG::misc::env={ mode=enforcing }");
	do_env_test();
	write_profile("CONFIG::misc::env={ mode=disabled }");
	return 0;
}
