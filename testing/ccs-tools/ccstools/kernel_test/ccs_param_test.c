#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/ip.h>
#include <fcntl.h>
#include <errno.h>

static FILE *fp = NULL;

static void set(const char *str)
{
	fprintf(fp, "%s\n", str);
	fflush(fp);
}

static void unset(const char *str)
{
	fprintf(fp, "delete %s\n", str);
	fflush(fp);
}

static void unset2(const char *str)
{
	const char *cp = str;
	while (*cp) {
		if (*cp++ != '\n')
			continue;
		fprintf(fp, "delete ");
		fwrite(str, cp - str, 1, fp);
		str = cp;
	}
	fprintf(fp, "delete %s\n", str);
	fflush(fp);
}

static void check(const char *prompt, int result)
{
	int err = errno;
	printf("%s%s\n", prompt, result ? "Success" : "Failed");
	if (!result) {
		fprintf(stderr, "Err: %s(%d)\n", strerror(err), err);
		{
			int fd2 = open("/proc/ccs/self_domain", O_RDONLY);
			char c;
			fprintf(stderr, "task.domain=\"");
			while (read(fd2, &c, 1) == 1)
				fprintf(stderr, "%c", c);
			close(fd2);
			fprintf(stderr, "\"\n");
		}
		exit(1);
	}
	printf("\n");
	fflush(stdout);
}

static void check_init(const char *prompt, const char *expected)
{
	int result;
	int fd = open("/proc/ccs/.process_status", O_RDWR);
	char buffer[1024];
	char *cp;
	memset(buffer, 0, sizeof(buffer));
	kill(1, SIGHUP);
	sleep(1);
	write(fd, "1\n", 2);
	read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	cp = strchr(buffer, ' ');
	if (cp++)
		memmove(buffer, cp, strlen(cp) + 1);
	result = !strcmp(buffer, expected);
	printf("%s%s\n", prompt, result ? "Success" : "Failed");
	if (!result) {
		fprintf(stderr, "Err: expected='%s' result='%s'\n",
			expected, buffer);
		exit(1);
	}
	printf("\n");
	fflush(stdout);
}

static void test_task_transition(void)
{
	int fd = open("/proc/ccs/self_domain", O_WRONLY);
	char *policy;

	policy = "100 acl manual_domain_transition\n"
		"0 allow domain=\"domain\\$\"\n";
	set(policy);
	check(policy, write(fd, "domain0", 7) != EOF);
	check(policy, write(fd, "domain10", 8) != EOF);
	check(policy, write(fd, "domainXYX", 9) == EOF);
	check(policy, write(fd, "domain200", 9) != EOF);
	unset(policy);

	policy = "100 acl auto_domain_transition\n"
		"0 allow task.pid=1 transition=\"<init3>\"\n";
	set(policy);
	check_init(policy, "<init3>");
	unset(policy);

	policy = "100 acl auto_domain_transition\n"
		"0 allow task.pid=1 task.uid!=0 transition=\"<init2>\"\n";
	set(policy);
	check_init(policy, "<init3>");
	unset(policy);
	
	policy = "100 acl auto_domain_transition\n"
		"0 allow task.pid=1 transition=\"<init>\"\n";
	set(policy);
	check_init(policy, "<init>");
	unset(policy);

	close(fd);
}

static void test_file_read(void)
{
	int fd;
	char *policy;

	policy = "100 acl read\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);
	
	policy = "100 acl read\n"
		"0 allow\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);
	
	policy = "100 acl read\n"
		"0 deny\n"
		"1 allow\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd == EOF);
	close(fd);
	unset(policy);
	
	policy = "100 acl read path=\"/dev/null\"\n"
		"0 allow\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);

	policy = "100 acl read path=\"/dev/null\"\n"
		"0 deny\n"
		"1 allow\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd == EOF);
	close(fd);
	unset(policy);

	policy = "100 acl read\n"
		"0 allow path=\"/dev/null\"\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);

	policy = "100 acl read\n"
		"0 deny path=\"/dev/null\"\n"
		"1 allow\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd == EOF);
	close(fd);
	unset(policy);

	policy = "100 acl read\n"
		"0 allow path.type=char path.dev_major=1 path.dev_minor=3\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);

	policy = "100 acl read\n"
		"0 deny path.type=char path.dev_major=1 path.dev_minor=3\n"
		"1 allow\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd == EOF);
	close(fd);
	unset(policy);

	policy = "100 acl read\n"
		"0 allow path.type=char path.dev_major=1 path.dev_minor!=3\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd == EOF);
	close(fd);
	unset(policy);

	policy = "100 acl read\n"
		"0 deny path.type=char path.dev_major=1 path.dev_minor!=3\n"
		"1 allow\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);

	policy = "string_group GROUP1 /dev/null\n"
		"100 acl read\n"
		"0 allow path=@GROUP1\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd != EOF);
	close(fd);
	unset2(policy);

	policy = "string_group GROUP1 /dev/null\n"
		"100 acl read\n"
		"0 deny path=@GROUP1\n"
		"1 allow\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd == EOF);
	close(fd);
	unset2(policy);

	policy = "string_group GROUP1 /dev/null\n"
		"100 acl read\n"
		"0 allow path!=@GROUP1\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd == EOF);
	close(fd);
	unset2(policy);

	policy = "string_group GROUP1 /dev/null\n"
		"100 acl read\n"
		"0 deny path!=@GROUP1\n"
		"1 allow\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd != EOF);
	close(fd);
	unset2(policy);

	policy = "string_group GROUP1 /dev/null\n"
		"number_group MAJOR 1\n"
		"number_group MINOR 3\n"
		"100 acl read\n"
		"0 allow path=@GROUP1 path.dev_major=@MAJOR"
		" path.dev_minor=@MINOR\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd != EOF);
	close(fd);
	unset2(policy);

	policy = "string_group GROUP1 /dev/null\n"
		"number_group MAJOR 1\n"
		"number_group MINOR 3\n"
		"100 acl read\n"
		"0 deny path=@GROUP1 path.dev_major=@MAJOR"
		" path.dev_minor=@MINOR\n"
		"1 allow\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd == EOF);
	close(fd);
	unset2(policy);

	policy = "string_group GROUP1 /dev/zero\n"
		"string_group GROUP1 /dev/null\n"
		"string_group GROUP1 /dev/urandom\n"
		"number_group MAJOR 0\n"
		"number_group MAJOR 2-255\n"
		"number_group MINOR 00-0x2\n"
		"number_group MINOR 255\n"
		"100 acl read\n"
		"0 allow path=@GROUP1 path.dev_major=@MAJOR"
		" path.dev_minor=@MINOR\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd == EOF);
	close(fd);
	unset2(policy);

	policy = "string_group GROUP1 /dev/zero\n"
		"string_group GROUP1 /dev/null\n"
		"string_group GROUP1 /dev/urandom\n"
		"number_group MAJOR 0\n"
		"number_group MAJOR 2-255\n"
		"number_group MINOR 00-0x2\n"
		"number_group MINOR 255\n"
		"100 acl read\n"
		"0 allow path=@GROUP1 path.dev_major!=@MAJOR"
		" path.dev_minor!=@MINOR\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_RDONLY);
	check(policy, fd != EOF);
	close(fd);
	unset2(policy);
}

static void test_file_write(void)
{
	int fd;
	char *policy;

	policy = "100 acl write\n"
		"0 allow\n"
		"100 acl append\n"
		"0 deny\n";
	set(policy);
	fd = open("/dev/null", O_WRONLY);
	check(policy, fd != EOF);
	close(fd);
	unset2(policy);

	policy = "100 acl write\n"
		"0 deny\n"
		"100 acl append\n"
		"0 allow\n";
	set(policy);
	fd = open("/dev/null", O_WRONLY);
	check(policy, fd == EOF);
	close(fd);
	unset2(policy);

	policy = "100 acl write\n"
		"0 allow\n"
		"100 acl append\n"
		"0 deny\n";
	set(policy);
	fd = open("/dev/null", O_WRONLY | O_APPEND);
	check(policy, fd == EOF);
	close(fd);
	unset2(policy);

	policy = "100 acl write\n"
		"0 deny\n"
		"100 acl append\n"
		"0 append\n";
	set(policy);
	fd = open("/dev/null", O_WRONLY | O_APPEND);
	check(policy, fd != EOF);
	close(fd);
	unset2(policy);

	policy = "100 acl write\n"
		"0 allow path.type=char path.dev_major=1 path.dev_minor=3\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_WRONLY | O_TRUNC);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);

	policy = "100 acl write\n"
		"0 allow path.type=char path.dev_major=1"
		" path.dev_minor=@MINOR\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_WRONLY | O_TRUNC);
	check(policy, fd == EOF);
	close(fd);
	unset(policy);

	policy = "100 acl write\n"
		"0 allow path.parent.type=directory path.parent.uid=0"
		" path.parent.perm=0755\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_WRONLY);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);

	policy = "100 acl write\n"
		"0 allow path.parent.uid=task.uid path.parent.gid=task.gid\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_WRONLY);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);

	policy = "100 acl write\n"
		"0 allow task.uid=path.parent.uid task.gid=path.parent.gid\n"
		"1 deny\n";
	set(policy);
	fd = open("/dev/null", O_WRONLY);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);
}

static void test_file_create(void)
{
	int fd;
	char *policy;

	policy = "100 acl create\n"
		"0 allow path.uid=0\n"
		"1 deny\n";
	set(policy);
	unlink("/tmp/file");
	fd = open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600);
	check(policy, fd == EOF);
	close(fd);
	unset(policy);

	policy = "100 acl create\n"
		"0 allow path=\"/tmp/file\" path.parent.uid=0\n"
		"1 deny\n";
	set(policy);
	unlink("/tmp/file");
	fd = open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);

	policy = "number_group GROUP1 1-0xFFFFFFFF\n"
		"100 acl create\n"
		"0 allow path.parent.uid!=@GROUP1 perm=0600\n"
		"1 deny\n";
	set(policy);
	unlink("/tmp/file");
	fd = open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600);
	check(policy, fd != EOF);
	close(fd);
	unset2(policy);

	policy = "number_group GROUP1 1-0xFFFFFFFF\n"
		"100 acl create\n"
		"0 allow path.parent.uid!=@GROUP1 perm!=0600\n"
		"1 deny\n";
	set(policy);
	unlink("/tmp/file");
	fd = open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600);
	check(policy, fd == EOF);
	close(fd);
	unset2(policy);

	policy = "100 acl create\n"
		"0 allow path.parent.uid=task.uid\n"
		"1 deny\n";
	set(policy);
	unlink("/tmp/file");
	fd = open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600);
	check(policy, fd != EOF);
	close(fd);
	unset(policy);
}

static void test_file_unlink(void)
{
	char *policy;

	policy = "100 acl unlink\n"
		"0 allow path.uid=0 path.uid=path.parent.uid\n"
		"1 deny\n";
	set(policy);
	close(open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600));
	check(policy, unlink("/tmp/file") == 0);
	unset(policy);

	policy = "100 acl unlink\n"
		"0 deny path.uid=0 path.uid=path.parent.uid\n"
		"1 allow\n";
	set(policy);
	close(open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600));
	check(policy, unlink("/tmp/file") == EOF);
	unset(policy);
}

static void test_file_link(void)
{
	char *policy;

	policy = "100 acl link\n"
		"0 allow old_path.uid=0 old_path.uid=old_path.parent.uid"
		" old_path.parent.ino=new_path.parent.ino\n"
		"1 deny\n";
	set(policy);
	close(open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600));
	unlink("/tmp/file2");
	check(policy, link("/tmp/file", "/tmp/file2") == 0);
	unset(policy);
	
	policy = "100 acl link\n"
		"0 deny old_path.uid=0 old_path.uid=old_path.parent.uid\n"
		"1 allow\n";
	set(policy);
	close(open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600));
	unlink("/tmp/file2");
	check(policy, link("/tmp/file", "/tmp/file2") == EOF);
	unset(policy);
}

static void test_file_rename(void)
{
	char *policy;

	policy = "100 acl rename\n"
		"0 allow old_path.uid=0 old_path.uid=old_path.parent.uid"
		" old_path.parent.ino=new_path.parent.ino\n"
		"1 deny\n";
	set(policy);
	close(open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600));
	unlink("/tmp/file2");
	check(policy, rename("/tmp/file", "/tmp/file2") == 0);
	unset(policy);
	
	policy = "100 acl rename\n"
		"0 deny old_path.uid=0 old_path.uid=old_path.parent.uid\n"
		"1 allow\n";
	set(policy);
	close(open("/tmp/file", O_CREAT | O_WRONLY | O_EXCL, 0600));
	unlink("/tmp/file2");
	check(policy, rename("/tmp/file", "/tmp/file2") == EOF);
	unset(policy);
}

static void test_network_inet_stream(void)
{
	struct sockaddr_in addr1 = { };
	struct sockaddr_in addr2 = { };
	socklen_t size = sizeof(addr1);
	int fd1;
	int fd2;
	int fd3;
	char *policy;
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));

	fd1 = socket(PF_INET, SOCK_STREAM, 0);
	fd2 = socket(PF_INET, SOCK_STREAM, 0);
	addr1.sin_family = AF_INET;
	addr1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	policy = "100 acl inet_stream_bind\n"
		"0 allow ip=127.0.0.1 port!=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);
	
	policy = "100 acl inet_stream_bind\n"
		"0 allow ip!=127.0.0.1 port=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);

	policy = "100 acl inet_stream_bind\n"
		"0 allow ip=127.0.0.1 port=0 path.uid=task.uid\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);
	
	policy = "100 acl inet_stream_bind\n"
		"0 allow ip=127.0.0.1 port=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      0);
	unset(policy);

	getsockname(fd1, (struct sockaddr *) &addr1, &size);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_listen\n"
		 "0 allow ip=127.0.0.1 port!=%u\n"
		 "1 deny\n", ntohs(addr1.sin_port));
	policy = buffer;
	set(policy);
	check(policy, listen(fd1, 5) == EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_listen\n"
		 "0 allow ip=127.0.0.1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin_port));
	policy = buffer;
	set(policy);
	check(policy, listen(fd1, 5) == 0);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_connect\n"
		 "0 allow ip=127.0.0.1 port!=%u\n"
		 "1 deny\n", ntohs(addr1.sin_port));
	policy = buffer;
	set(policy);
	check(policy, connect(fd2, (struct sockaddr *) &addr1, sizeof(addr1))
	      == EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_connect\n"
		 "0 allow ip=127.0.0.1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin_port));
	policy = buffer;
	set(policy);
	check(policy, connect(fd2, (struct sockaddr *) &addr1, sizeof(addr1))
	      == 0);
	unset(policy);

	getsockname(fd2, (struct sockaddr *) &addr2, &size);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_accept\n"
		 "0 allow ip=127.0.0.1 port=%u\n"
		 "1 deny\n", ntohs(addr2.sin_port));
	policy = buffer;
	set(policy);
	fd3 = accept(fd1, NULL, 0);
	check(policy, fd3 != EOF);
	close(fd3);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_connect\n"
		 "0 allow ip=127.0.0.1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin_port));
	policy = buffer;
	set(policy);
	close(fd2);
	fd2 = socket(PF_INET, SOCK_STREAM, 0);
	check(policy, connect(fd2, (struct sockaddr *) &addr1, sizeof(addr1))
	      == 0);
	unset(policy);

	getsockname(fd2, (struct sockaddr *) &addr2, &size);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_accept\n"
		 "0 allow ip=127.0.0.1 port!=%u\n"
		 "1 deny\n", ntohs(addr2.sin_port));
	policy = buffer;
	set(policy);
	fd3 = accept(fd1, NULL, 0);
	check(policy, fd3 == EOF);
	close(fd3);
	unset(policy);

	close(fd1);
	close(fd2);
}

static void test_network_inet_dgram(void)
{
	struct sockaddr_in addr1 = { };
	struct sockaddr_in addr2 = { };
	socklen_t size = sizeof(addr1);
	int fd1;
	int fd2;
	char c;
	char *policy;
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));

	fd1 = socket(PF_INET, SOCK_DGRAM, 0);
	fd2 = socket(PF_INET, SOCK_DGRAM, 0);
	addr1.sin_family = AF_INET;
	addr1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	policy = "100 acl inet_dgram_bind\n"
		"0 allow ip=127.0.0.1 port!=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);
	
	policy = "100 acl inet_dgram_bind\n"
		"0 allow ip!=127.0.0.1 port=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);

	policy = "100 acl inet_dgram_bind\n"
		"0 allow ip=127.0.0.1 port=0 path.uid=task.uid\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);
	
	policy = "100 acl inet_dgram_bind\n"
		"0 allow ip=127.0.0.1 port=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      0);
	unset(policy);

	getsockname(fd1, (struct sockaddr *) &addr1, &size);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_send\n"
		 "0 allow ip=127.0.0.1 port!=%u\n"
		 "1 deny\n", ntohs(addr1.sin_port));
	policy = buffer;
	set(policy);
	check(policy, connect(fd2, (struct sockaddr *) &addr1, sizeof(addr1))
	      == EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_send\n"
		 "0 allow ip=127.0.0.1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin_port));
	policy = buffer;
	set(policy);
	check(policy, connect(fd2, (struct sockaddr *) &addr1, sizeof(addr1))
	      == 0);
	unset(policy);

	getsockname(fd2, (struct sockaddr *) &addr2, &size);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_send\n"
		 "0 allow ip=127.0.0.1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin_port));
	policy = buffer;
	set(policy);
	check(policy, send(fd2, "", 1, 0) != EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_recv\n"
		 "0 allow ip=127.0.0.1 port=%u\n"
		 "1 deny\n", ntohs(addr2.sin_port));
	policy = buffer;
	set(policy);
	check(policy, recv(fd1, &c, 1, 0) != EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_send\n"
		 "0 allow ip=127.0.0.1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin_port));
	policy = buffer;
	set(policy);
	check(policy, send(fd2, "", 1, 0) != EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_recv\n"
		 "0 allow ip=127.0.0.1 port!=%u\n"
		 "1 deny\n", ntohs(addr2.sin_port));
	policy = buffer;
	set(policy);
	check(policy, recv(fd1, &c, 1, 0) == EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1,
		 "ip_group LOCALHOST 127.0.0.0-127.255.255.255\n"
		 "100 acl inet_dgram_send\n"
		 "0 allow ip=@LOCALHOST port=%u\n"
		 "1 deny\n", ntohs(addr1.sin_port));
	policy = buffer;
	set(policy);
	check(policy, send(fd2, "", 1, 0) != EOF);
	unset2(policy);

	snprintf(buffer, sizeof(buffer) - 1,
		 "ip_group LOCALHOST 127.0.0.0-127.255.255.255\n"
		 "100 acl inet_dgram_recv\n"
		 "0 allow ip!=@LOCALHOST port=%u\n"
		 "1 deny\n", ntohs(addr2.sin_port));
	policy = buffer;
	set(policy);
	check(policy, recv(fd1, &c, 1, 0) == EOF);
	unset2(policy);

	close(fd1);
	close(fd2);
}

static void test_network_inet_raw(void)
{
	struct sockaddr_in addr = { };
	static struct iphdr ip = { };
	int fd1;
	int fd2;
	char *policy;
	fd1 = socket(PF_INET, SOCK_RAW, 1);
	fd2 = socket(PF_INET, SOCK_RAW, 1);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ip.version = 4;
	ip.ihl = sizeof(struct iphdr) / 4;
	ip.protocol = IPPROTO_RAW;
	ip.daddr = htonl(INADDR_LOOPBACK);
	ip.saddr = ip.daddr;

	policy = "100 acl inet_raw_bind\n"
		"0 allow ip=127.0.0.1 proto!=1\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr, sizeof(addr)) ==
	      EOF);
	unset(policy);

	policy = "100 acl inet_raw_bind\n"
		"0 allow ip!=127.0.0.1 proto=1\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr, sizeof(addr)) ==
	      EOF);
	unset(policy);

	policy = "100 acl inet_raw_bind\n"
		"0 allow ip=127.0.0.1 proto=1 path.uid=task.uid\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr, sizeof(addr)) ==
	      EOF);
	unset(policy);

	policy = "100 acl inet_raw_bind\n"
		"0 allow ip=127.0.0.1 proto=1\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd2, (struct sockaddr *) &addr, sizeof(addr)) ==
	      0);
	unset(policy);

	policy = "100 acl inet_raw_send\n"
		"0 allow ip=127.0.0.1 proto!=1\n"
		"1 deny\n";
	set(policy);
	check(policy, connect(fd2, (struct sockaddr *) &addr, sizeof(addr))
	      == EOF);
	unset(policy);

	policy = "100 acl inet_raw_send\n"
		"0 allow ip=127.0.0.1 proto=1\n"
		"1 deny\n";
	set(policy);
	check(policy, connect(fd2, (struct sockaddr *) &addr, sizeof(addr))
	      == 0);
	unset(policy);

	policy = "100 acl inet_raw_send\n"
		"0 allow ip=127.0.0.1 proto=1\n"
		"1 deny\n";
	set(policy);
	check(policy, send(fd2, &ip, sizeof(ip), 0) != EOF);
	unset(policy);

	policy = "100 acl inet_raw_recv\n"
		"0 allow ip=127.0.0.1 proto=1\n"
		"1 deny\n";
	set(policy);
	check(policy, recv(fd1, &ip, sizeof(ip), MSG_DONTWAIT) != EOF);
	unset(policy);

	policy = "100 acl inet_raw_send\n"
		 "0 allow ip=127.0.0.1 proto=1\n"
		"1 deny\n";
	set(policy);
	check(policy, send(fd2, &ip, sizeof(ip), 0) != EOF);
	unset(policy);

	policy = "100 acl inet_raw_recv\n"
		"0 allow ip=127.0.0.1 proto!=1\n"
		"1 deny\n";
	set(policy);
	check(policy, recv(fd1, &ip, sizeof(ip), MSG_DONTWAIT) == EOF);
	unset(policy);

	policy = "ip_group LOCALHOST 127.0.0.0-127.255.255.255\n"
		"100 acl inet_raw_send\n"
		"0 allow ip=@LOCALHOST proto=1\n"
		"1 deny\n";
	set(policy);
	check(policy, send(fd2, &ip, sizeof(ip), 0) != EOF);
	unset2(policy);

	policy = "ip_group LOCALHOST 127.0.0.0-127.255.255.255\n"
		"100 acl inet_raw_recv\n"
		"0 allow ip!=@LOCALHOST proto=1\n"
		"1 deny\n";
	set(policy);
	check(policy, recv(fd1, &ip, sizeof(ip), MSG_DONTWAIT) == EOF);
	unset2(policy);

	close(fd1);
	close(fd2);
}

static void test_network_inet6_stream(void)
{
	struct sockaddr_in6 addr1 = { };
	struct sockaddr_in6 addr2 = { };
	socklen_t size = sizeof(addr1);
	int fd1;
	int fd2;
	int fd3;
	char *policy;
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));

	fd1 = socket(PF_INET6, SOCK_STREAM, 0);
	fd2 = socket(PF_INET6, SOCK_STREAM, 0);
	addr1.sin6_family = AF_INET6;
	addr1.sin6_addr = in6addr_loopback;

	policy = "100 acl inet_stream_bind\n"
		"0 allow ip=::1 port!=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);
	
	policy = "100 acl inet_stream_bind\n"
		"0 allow ip!=::1 port=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);

	policy = "100 acl inet_stream_bind\n"
		"0 allow ip=::1 port=0 path.uid=task.uid\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);
	
	policy = "100 acl inet_stream_bind\n"
		"0 allow ip=::1 port=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      0);
	unset(policy);

	getsockname(fd1, (struct sockaddr *) &addr1, &size);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_listen\n"
		 "0 allow ip=::1 port!=%u\n"
		 "1 deny\n", ntohs(addr1.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, listen(fd1, 5) == EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_listen\n"
		 "0 allow ip=::1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, listen(fd1, 5) == 0);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_connect\n"
		 "0 allow ip=::1 port!=%u\n"
		 "1 deny\n", ntohs(addr1.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, connect(fd2, (struct sockaddr *) &addr1, sizeof(addr1))
	      == EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_connect\n"
		 "0 allow ip=::1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, connect(fd2, (struct sockaddr *) &addr1, sizeof(addr1))
	      == 0);
	unset(policy);

	getsockname(fd2, (struct sockaddr *) &addr2, &size);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_accept\n"
		 "0 allow ip=::1 port=%u\n"
		 "1 deny\n", ntohs(addr2.sin6_port));
	policy = buffer;
	set(policy);
	fd3 = accept(fd1, NULL, 0);
	check(policy, fd3 != EOF);
	close(fd3);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_connect\n"
		 "0 allow ip=::1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin6_port));
	policy = buffer;
	set(policy);
	close(fd2);
	fd2 = socket(PF_INET6, SOCK_STREAM, 0);
	check(policy, connect(fd2, (struct sockaddr *) &addr1, sizeof(addr1))
	      == 0);
	unset(policy);

	getsockname(fd2, (struct sockaddr *) &addr2, &size);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_stream_accept\n"
		 "0 allow ip=::1 port!=%u\n"
		 "1 deny\n", ntohs(addr2.sin6_port));
	policy = buffer;
	set(policy);
	fd3 = accept(fd1, NULL, 0);
	check(policy, fd3 == EOF);
	close(fd3);
	unset(policy);

	close(fd1);
	close(fd2);
}

static void test_network_inet6_dgram(void)
{
	struct sockaddr_in6 addr1 = { };
	struct sockaddr_in6 addr2 = { };
	socklen_t size = sizeof(addr1);
	int fd1;
	int fd2;
	char c;
	char *policy;
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));

	fd1 = socket(PF_INET6, SOCK_DGRAM, 0);
	fd2 = socket(PF_INET6, SOCK_DGRAM, 0);
	addr1.sin6_family = AF_INET6;
	addr1.sin6_addr = in6addr_loopback;

	policy = "100 acl inet_dgram_bind\n"
		"0 allow ip=::1 port!=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);
	
	policy = "100 acl inet_dgram_bind\n"
		"0 allow ip!=::1 port=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);

	policy = "100 acl inet_dgram_bind\n"
		"0 allow ip=::1 port=0 path.uid=task.uid\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      EOF);
	unset(policy);
	
	policy = "100 acl inet_dgram_bind\n"
		"0 allow ip=::1 port=0\n"
		"1 deny\n";
	set(policy);
	check(policy, bind(fd1, (struct sockaddr *) &addr1, sizeof(addr1)) ==
	      0);
	unset(policy);

	getsockname(fd1, (struct sockaddr *) &addr1, &size);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_send\n"
		 "0 allow ip=::1 port!=%u\n"
		 "1 deny\n", ntohs(addr1.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, connect(fd2, (struct sockaddr *) &addr1, sizeof(addr1))
	      == EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_send\n"
		 "0 allow ip=::1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, connect(fd2, (struct sockaddr *) &addr1, sizeof(addr1))
	      == 0);
	unset(policy);

	getsockname(fd2, (struct sockaddr *) &addr2, &size);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_send\n"
		 "0 allow ip=::1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, send(fd2, "", 1, 0) != EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_recv\n"
		 "0 allow ip=::1 port=%u\n"
		 "1 deny\n", ntohs(addr2.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, recv(fd1, &c, 1, 0) != EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_send\n"
		 "0 allow ip=::1 port=%u\n"
		 "1 deny\n", ntohs(addr1.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, send(fd2, "", 1, 0) != EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1, 
		 "100 acl inet_dgram_recv\n"
		 "0 allow ip=::1 port!=%u\n"
		 "1 deny\n", ntohs(addr2.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, recv(fd1, &c, 1, 0) == EOF);
	unset(policy);

	snprintf(buffer, sizeof(buffer) - 1,
		 "ip_group LOCALHOST ::-::ffff\n"
		 "100 acl inet_dgram_send\n"
		 "0 allow ip=@LOCALHOST port=%u\n"
		 "1 deny\n", ntohs(addr1.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, send(fd2, "", 1, 0) != EOF);
	unset2(policy);

	snprintf(buffer, sizeof(buffer) - 1,
		 "ip_group LOCALHOST ::-::ffff\n"
		 "100 acl inet_dgram_recv\n"
		 "0 allow ip!=@LOCALHOST port=%u\n"
		 "1 deny\n", ntohs(addr2.sin6_port));
	policy = buffer;
	set(policy);
	check(policy, recv(fd1, &c, 1, 0) == EOF);
	unset2(policy);

	close(fd1);
	close(fd2);
}

static void test_capability(void)
{
	char *policy;

	policy = "100 acl set_priority\n"
		"0 allow task.uid=0\n"
		"1 deny\n";
	set(policy);
	check(policy, nice(0) == 0);
	unset(policy);

	policy = "100 acl set_priority\n"
		"0 allow task.uid=task.gid task.type!=execute_handler\n"
		"1 deny\n";
	set(policy);
	check(policy, nice(0) == 0);
	unset(policy);

	policy = "100 acl set_priority\n"
		"0 deny task.uid=0\n"
		"1 allow\n";
	set(policy);
	check(policy, nice(0) == EOF);
	unset(policy);

	policy = "100 acl set_priority\n"
		"0 allow task.uid=task.gid task.type=execute_handler\n"
		"1 deny\n";
	set(policy);
	check(policy, nice(0) == EOF);
	unset(policy);
}

static void detach_init(void)
{
	ptrace(PTRACE_DETACH, 1, NULL, NULL);
	kill(1, SIGCONT);
	sleep(1);
}

static void test_ptrace(void)
{
	char *policy;

	policy = "100 acl ptrace\n"
		"0 allow cmd=1 domain!=\"foo\"\n"
		"0 allow cmd=17\n"
		"1 deny\n";
	set(policy);
	check(policy, ptrace(PTRACE_ATTACH, 1, NULL, NULL) == EOF);
	unset(policy);
	detach_init();

	policy = "100 acl ptrace\n"
		"0 allow cmd=16 domain=\"foo\"\n"
		"0 allow cmd=17\n"
		"1 deny\n";
	set(policy);
	check(policy, ptrace(PTRACE_ATTACH, 1, NULL, NULL) == EOF);
	unset(policy);
	detach_init();

	policy = "100 acl ptrace\n"
		"0 allow cmd=16 domain!=\"foo\"\n"
		"0 allow cmd=17\n"
		"1 deny\n";
	set(policy);
	check(policy, ptrace(PTRACE_ATTACH, 1, NULL, NULL) == 0);
	unset(policy);
	detach_init();

	policy = "string_group DOMAINS <init>\n"
		"100 acl ptrace\n"
		"0 allow cmd=16 domain=@DOMAINS\n"
		"0 allow cmd=17\n"
		"1 deny\n";
	set(policy);
	check(policy, ptrace(PTRACE_ATTACH, 1, NULL, NULL) == 0);
	unset2(policy);
	detach_init();
	
	policy = "string_group DOMAINS <init>\n"
		"100 acl ptrace\n"
		"0 allow cmd=16 domain!=@DOMAINS\n"
		"0 allow cmd=17\n"
		"1 deny\n";
	set(policy);
	check(policy, ptrace(PTRACE_ATTACH, 1, NULL, NULL) == EOF);
	unset2(policy);
	detach_init();
}

static void test_signal(void)
{
	char *policy;

	policy = "100 acl signal task.domain=\"domain200\"\n"
		"0 allow sig=1 task.uid=0\n"
		"1 deny\n";
	set(policy);
	check(policy, kill(1, 1) == 0);
	unset(policy);

	policy = "100 acl signal task.domain=\"domain200\"\n"
		"0 allow sig!=1 task.uid=0\n"
		"1 deny\n";
	set(policy);
	check(policy, kill(1, 1) == EOF);
	unset(policy);

	policy = "100 acl signal\n"
		"0 allow task.domain!=\"domain200\"\n"
		"0 allow sig=1\n"
		"1 deny\n";
	set(policy);
	check(policy, kill(1, 1) == 0);
	unset(policy);

	policy = "100 acl signal\n"
		"0 deny task.domain=\"domain200\"\n"
		"0 allow\n";
	set(policy);
	check(policy, kill(1, 1) == EOF);
	unset(policy);

	policy = "100 acl signal\n"
		"0 deny sig=1 task.domain=\"domain200\"\n"
		"0 allow\n";
	set(policy);
	check(policy, kill(1, 1) == EOF);
	unset(policy);
}

static int fork_exec(char *envp[])
{
	int ret_ignored;
	int pipe_fd[2] = { EOF, EOF };
	int err = 0;
	pid_t pid;
	if (pipe(pipe_fd)) {
		fprintf(stderr, "Err: %s(%d)\n", strerror(err), err);
		exit(1);
	}
	pid = fork();
	if (pid == 0) {
		char *argv[2] = { "/bin/true", NULL };
		execve("/bin/true", argv, envp);
		err = errno;
		ret_ignored = write(pipe_fd[1], &err, sizeof(err));
		_exit(0);
	}
	close(pipe_fd[1]);
	ret_ignored = read(pipe_fd[0], &err, sizeof(err));
	close(pipe_fd[0]);
	wait(NULL);
	errno = err;
	return err ? EOF : 0;
}

static void test_environ(void)
{
	char *policy;
	char *envp[2];
	envp[1] = NULL;

	policy = "100 acl environ name=\"PATH2\"\n"
		"0 allow value=\"/\"\n"
		"1 deny\n";
	set(policy);
	envp[0] = "PATH2=/";
	check(policy, fork_exec(envp) == 0);
	unset(policy);

	policy = "100 acl environ name=\"PATH2\"\n"
		"0 allow value!=\"/\"\n"
		"1 deny\n";
	set(policy);
	envp[0] = "PATH2=/";
	check(policy, fork_exec(envp) == EOF);
	unset(policy);

	policy = "100 acl environ name=\"PATH2\"\n"
		"0 deny value!=\"/\"\n"
		"1 allow\n";
	set(policy);
	envp[0] = "PATH2=/";
	check(policy, fork_exec(envp) == 0);
	unset(policy);

	policy = "100 acl environ name=\"PATH2\"\n"
		"0 deny value=\"/\"\n"
		"1 allow\n";
	set(policy);
	envp[0] = "PATH2=/";
	check(policy, fork_exec(envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH2\"]=\"/\"\n"
		"1 deny\n";
	set(policy);
	envp[0] = "PATH2=/";
	check(policy, fork_exec(envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH2\"]!=\"/\"\n"
		"1 deny\n";
	set(policy);
	envp[0] = "PATH2=/";
	check(policy, fork_exec(envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH2\"]!=NULL\n"
		"1 deny\n";
	set(policy);
	envp[0] = "PATH2";
	check(policy, fork_exec(envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH2\"]!=NULL\n"
		"1 deny\n";
	set(policy);
	envp[0] = "PATH2=";
	check(policy, fork_exec(envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH2\"]!=NULL\n"
		"1 deny\n";
	set(policy);
	envp[0] = "PATH2=/";
	check(policy, fork_exec(envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH2\"]=NULL\n"
		"1 deny\n";
	set(policy);
	envp[0] = "PATH2";
	check(policy, fork_exec(envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH2\"]=NULL\n"
		"1 deny\n";
	set(policy);
	envp[0] = "PATH2=";
	check(policy, fork_exec(envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH2\"]=NULL\n"
		"1 deny\n";
	set(policy);
	envp[0] = "PATH2=/";
	check(policy, fork_exec(envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"\"]=NULL\n"
		"1 deny\n";
	set(policy);
	envp[0] = "";
	check(policy, fork_exec(envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"\"]!=NULL\n"
		"1 deny\n";
	set(policy);
	envp[0] = "";
	check(policy, fork_exec(envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"\"]!=NULL\n"
		"1 deny\n";
	set(policy);
	envp[0] = "=";
	check(policy, fork_exec(envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"\"]!=NULL\n"
		"1 deny\n";
	set(policy);
	envp[0] = "=/";
	check(policy, fork_exec(envp) == 0);
	unset(policy);
}

static int fork_exec2(char *argv[], char *envp[])
{
	int ret_ignored;
	int pipe_fd[2] = { EOF, EOF };
	int err = 0;
	pid_t pid;
	if (pipe(pipe_fd)) {
		fprintf(stderr, "Err: %s(%d)\n", strerror(err), err);
		exit(1);
	}
	pid = fork();
	if (pid == 0) {
		execve("/bin/true", argv, envp);
		err = errno;
		ret_ignored = write(pipe_fd[1], &err, sizeof(err));
		_exit(0);
	}
	close(pipe_fd[1]);
	ret_ignored = read(pipe_fd[0], &err, sizeof(err));
	close(pipe_fd[0]);
	wait(NULL);
	errno = err;
	return err ? EOF : 0;
}

static void test_file_execute(void)
{
	char *policy;
	char *argv[5];
	char *envp[5];
	memset(argv, 0, sizeof(argv));
	memset(envp, 0, sizeof(envp));

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow argc=1\n"
		"1 deny\n";
	set(policy);
	argv[0]="true";
	check(policy, fork_exec2(argv, envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow argc!=1\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 deny argc!=1\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 deny argc=1\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 deny argv[0]!=\"true\"\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 deny argv[0]=\"true\"\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow argv[0]!=\"true\"\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow argv[0]=\"true\"\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset(policy);

	policy = "string_group EXEC_ARGV0 false\n"
		"string_group EXEC_ARGV0 true\n"
		"100 acl execute path=\"/bin/true\"\n"
		"0 deny argv[0]!=@EXEC_ARGV0\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset2(policy);

	policy = "string_group EXEC_ARGV0 false\n"
		"string_group EXEC_ARGV0 true\n"
		"100 acl execute path=\"/bin/true\"\n"
		"0 deny argv[0]=@EXEC_ARGV0\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset2(policy);

	policy = "string_group EXEC_ARGV0 false\n"
		"string_group EXEC_ARGV0 true\n"
		"100 acl execute path=\"/bin/true\"\n"
		"0 allow argv[0]!=@EXEC_ARGV0\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset2(policy);

	policy = "string_group EXEC_ARGV0 false\n"
		"string_group EXEC_ARGV0 true\n"
		"100 acl execute path=\"/bin/true\"\n"
		"0 allow argv[0]=@EXEC_ARGV0\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset2(policy);


	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envc=1\n"
		"1 deny\n";
	set(policy);
	envp[0]="PATH=/";
	check(policy, fork_exec2(argv, envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envc!=1\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 deny envc!=1\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 deny envc=1\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 deny envp[\"PATH\"]!=\"/\"\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 deny envp[\"PATH\"]=\"/\"\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH\"]!=\"/\"\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH\"]=\"/\"\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset(policy);

	policy = "string_group PATH_VALUES /bin\n"
		"string_group PATH_VALUES /\n"
		"string_group PATH_VALUES /sbin\n"
		"100 acl execute path=\"/bin/true\"\n"
		"0 deny envp[\"PATH\"]!=@PATH_VALUES\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset2(policy);

	policy = "string_group PATH_VALUES /bin\n"
		"string_group PATH_VALUES /\n"
		"string_group PATH_VALUES /sbin\n"
		"100 acl execute path=\"/bin/true\"\n"
		"0 deny envp[\"PATH\"]=@PATH_VALUES\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset2(policy);

	policy = "string_group PATH_VALUES /bin\n"
		"string_group PATH_VALUES /\n"
		"string_group PATH_VALUES /sbin\n"
		"100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH\"]!=@PATH_VALUES\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset2(policy);

	policy = "string_group PATH_VALUES /bin\n"
		"string_group PATH_VALUES /\n"
		"string_group PATH_VALUES /sbin\n"
		"100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH\"]=@PATH_VALUES\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset2(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 deny envp[\"PATH\"]!=NULL\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 deny envp[\"PATH\"]=NULL\n"
		"1 allow\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH\"]!=NULL\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == 0);
	unset(policy);

	policy = "100 acl execute path=\"/bin/true\"\n"
		"0 allow envp[\"PATH\"]=NULL\n"
		"1 deny\n";
	set(policy);
	check(policy, fork_exec2(argv, envp) == EOF);
	unset(policy);
}

int main(int argc, char *argv[])
{
	fp = fopen("/proc/ccs/policy", "w");
	if (!fp) {
		fprintf(stderr, " Can't open /proc/ccs/policy\n");
		return 1;
	}
	fprintf(fp, "quota audit[0]"
		" allowed=1024 unmatched=1024 denied=1024\n");

	test_task_transition();
	test_file_read();
	test_file_write();
	test_file_create();
	test_file_unlink();
	test_file_link();
	test_file_rename();
	test_network_inet_stream();
	test_network_inet_dgram();
	test_network_inet_raw();
	test_network_inet6_stream();
	test_network_inet6_dgram();
	test_capability();
	test_ptrace();
	test_signal();
	test_environ();
	test_file_execute();
	return 0;
}
