#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main(int raw_argc, char *raw_argv[])
{
	int i;
	int argc;
	int envc;
	char *filename;
	char **argv;
	char **envp;
	if (raw_argc < 7)
		return 1;
	filename = raw_argv[4];
	argc = atoi(raw_argv[5]);
	envc = atoi(raw_argv[6]);
	if (raw_argc != argc + envc + 7)
		return 1;
	for (i = 5; i < argc + 5; i++)
		raw_argv[i] = raw_argv[i + 2];
	raw_argv[argc + 5] = NULL;
	for (i = argc + 6; i < argc + envc + 6; i++)
		raw_argv[i] = raw_argv[i + 1];
	raw_argv[argc + envc + 6] = NULL;
	argv = raw_argv + 5;
	envp = raw_argv + argc + 6;
	{
		char buffer[4096];
		int len;
		int fd = open("/proc/ccs/self_domain", O_RDWR);
		if (fd == EOF) {
			if (errno == ENOENT)
				goto skip;
			fprintf(stderr, "Can't open /proc/ccs/self_domain\n");
			return 1;
		}
		memset(buffer, 0, sizeof(buffer));
		read(fd, buffer, sizeof(buffer) - 1);
		len = strlen(buffer);
		snprintf(buffer + len, sizeof(buffer) - 1 - len, "\\000%s",
			 filename);
		len = strlen(buffer);
		if (len < sizeof(buffer) - 1 && write(fd, buffer, len) == len)
			close(fd);
		else {
			fprintf(stderr, "Can't change to '%s'\n", buffer);
			return 1;
		}
	}
skip:
	execve(filename, argv, envp);
	i = errno;
	fprintf(stderr, "Can't execute %s: error=%u\n", filename, i);
	return i;
}
