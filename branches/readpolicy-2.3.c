#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static void run_gc(void)
{
	fprintf(stderr, "Running GC.\n");
	close(open("/sys/kernel/security/tomoyo/profile", O_WRONLY));
	sleep(3);
}

static unsigned int read1(const int fd, unsigned int size)
{
	char c;
	unsigned int len = 0;
	while (size-- && read(fd, &c, 1) == 1 && write(1, "{", 1) == 1 &&
	       write(1, &c, 1) == 1 && write(1, "}", 1) == 1)
		len++;
	return len;
}

static void write1(const int fd, const char *str)
{
	write(1, str, strlen(str));
	write(fd, str, strlen(str));
}

static inline void write2(const int fd, const char *str1, const char *str2)
{
	write1(fd, str1);
	write1(fd, str2);
}

int main(int argc, char *argv[])
{
	static const char *path1 = "/path/to/some/file/in/very/very/deep/"
		"location/which/will/surely/stop/within/this/pathname/"
		"while/reading/policy\n";
	static const char *path2 = "/path/to/other/file/in/very/very/deep/"
		"location/which/will/surely/stop/within/this/pathname/"
		"while/reading/policy\n";
	int fd1 = open("/sys/kernel/security/tomoyo/domain_policy", O_RDWR);
	int fd2 = open("/sys/kernel/security/tomoyo/domain_policy", O_RDWR);
	write1(fd1, "<kernel> /foo/bar /foo/bar/buz\n");
	write2(fd1, "allow_read ", path1);
	write2(fd1, "allow_write ", path1);
	write2(fd1, "allow_execute ", path1);
	write2(fd1, "allow_read ", path2);
	write2(fd1, "allow_write ", path2);
	write2(fd1, "allow_execute ", path2);
	write2(fd2, "select ", "<kernel> /foo/bar /foo/bar/buz\n");
	read1(fd2, 128);
	write1(fd1, "delete ");
	write2(fd1, "allow_read ", path2);
	write1(fd1, "delete ");
	write2(fd1, "allow_write ", path2);
	write1(fd1, "delete ");
	write2(fd1, "allow_execute ", path2);
	write1(fd1, "delete ");
	write2(fd1, "allow_read ", path1);
	write1(fd1, "delete ");
	write2(fd1, "allow_write ", path1);
	write1(fd1, "delete ");
	write2(fd1, "allow_execute ", path1);
	run_gc();
	write2(fd1, "delete ", "<kernel> /foo/bar /foo/bar/buz\n");
	run_gc();
	while (read1(fd2, 1) > 0);
	close(fd1);
	close(fd2);
	fd1 = open("/sys/kernel/security/tomoyo/exception_policy", O_RDWR);
	fd2 = open("/sys/kernel/security/tomoyo/exception_policy", O_RDWR);
	write2(fd1, "path_group VERY_VERY_LONG_PATH ", path1);
	write2(fd1, "path_group VERY_VERY_LONG_PATH ", path2);
	read1(fd2, 128);
	write1(fd1, "delete ");
	write2(fd1, "path_group VERY_VERY_LONG_PATH ", path1);
	write1(fd1, "delete ");
	write2(fd1, "path_group VERY_VERY_LONG_PATH ", path2);
	run_gc();
	while (read1(fd2, 1) > 0);
	close(fd1);
	close(fd2);
	return 0;
}
