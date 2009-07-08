#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/vfs.h>

static void printf_encoded(const char *str)
{
	while (1) {
		unsigned char c = *(const unsigned char *) str++;
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
}

static void scan_symlink(char *path)
{
	char *base1;
	char *base2;
	char *cp = strrchr(path, '/');
	struct statfs buf;
	int ret;
	if (!cp)
		return;
	*cp = '\0';
	ret = statfs(path, &buf);
	*cp = '/';
	if (ret)
		return;
	switch (buf.f_type) {
	case 0x00009FA0: /* proc */
	case 0x62656572: /* sys */
	case 0x64626720: /* debug */
	case 0x73636673: /* security */
	case 0x00009FA2: /* usb */
	case 0x0027E0EB: /* cgroup */
	case 0x0BAD1DEA: /* futex */
	case 0x2BAD1DEA: /* inotify */
	case 0x00001373: /* device */
	case 0x00001CD1: /* devpts */
	case 0x42494E4D: /* binfmt_misc */
	case 0x67596969: /* rpc_pipefs */
	case 0x19800202: /* mqueue */
	case 0xABABABAB: /* vmblock */
		return;
	}
	if (statfs(path, &buf))
		return;
	switch (buf.f_type) {
	case 0x00009FA0: /* proc */
	case 0x62656572: /* sys */
	case 0x64626720: /* debug */
	case 0x73636673: /* security */
	case 0x00009FA2: /* usb */
	case 0x0027E0EB: /* cgroup */
	case 0x0BAD1DEA: /* futex */
	case 0x2BAD1DEA: /* inotify */
	case 0x00001373: /* device */
	case 0x00001CD1: /* devpts */
	case 0x42494E4D: /* binfmt_misc */
	case 0x67596969: /* rpc_pipefs */
	case 0x19800202: /* mqueue */
	case 0xABABABAB: /* vmblock */
		return;
	}
	cp = realpath(path, NULL);
	if (!cp)
		return;
	base1 = strrchr(path, '/');
	base2 = strrchr(cp, '/');
	if (strcmp(base1, base2) && strncmp(base1, "/lib", 4) &&
	    !strstr(base1, ".so")) {
		printf("alias ");
		printf_encoded(cp);
		putchar(' ');
		printf_encoded(path);
		putchar('\n');
	}
	free(cp);
}

static unsigned char revalidate_path(const char *path)
{
	struct stat buf;
	unsigned char type = DT_UNKNOWN;
	fprintf(stderr, "Revalidate %s ", path);
	if (!lstat(path, &buf)) {
		if (S_ISREG(buf.st_mode))
			type = DT_REG;
		else if (S_ISREG(buf.st_mode))
			type = DT_DIR;
		else if (S_ISLNK(buf.st_mode))
			type = DT_LNK;
	}
	if (type == DT_UNKNOWN)
		fprintf(stderr, "failed\n");
	else
		fprintf(stderr, "ok\n");
	return type;
}

static int scandir_filter(const struct dirent *buf)
{
	return (buf->d_type == DT_UNKNOWN || buf->d_type == DT_LNK ||
		buf->d_type == DT_DIR) &&
		strcmp(buf->d_name, ".") && strcmp(buf->d_name, "..");
}

static char path[8192];

static void scan_dir(void)
{
	static struct stat buf;
	struct dirent **namelist;
	int i;
	int len;
	int n = scandir(path[0] ? path : "/", &namelist, scandir_filter, 0);
	if (n < 0)
		return;
	len = strlen(path);
	for (i = 0; i < n; i++) {
		unsigned char type = namelist[i]->d_type;
		snprintf(path + len, sizeof(path) - len - 1, "/%s",
			 namelist[i]->d_name);
		if (type == DT_UNKNOWN)
			type = revalidate_path(path);
		if (type == DT_LNK && !stat(path, &buf) &&
		    S_ISREG(buf.st_mode) && (buf.st_mode & 0111))
			scan_symlink(path);
		else if (type == DT_DIR)
			scan_dir();
		free((void *) namelist[i]);
	}
	free((void *) namelist);
}

int main(int argc, char *argv[])
{
	memset(path, 0, sizeof(path));
	if (argc > 1 && (chroot(argv[1]) || chdir("/")))
		return 1;
	scan_dir();
	return 0;
}
