/*
 * arglog.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/types.h>

int main(int argc0, char *argv0[])
{
	int fd1 = open("/proc/ccs/grant_log", O_RDONLY);
	int fd2 = open("/proc/ccs/reject_log", O_RDONLY);
	char *argv[12];
	char *envp[12];
	int j;
	memset(argv, 0, sizeof(argv));
	memset(envp, 0, sizeof(envp));
	for (j = 0; j < 11; j++) {
		char buffer1[8192];
		char buffer2[8192];
		int i;
		/* printf("%d\n", j); */
		memset(buffer1, 0, sizeof(buffer1));
		memset(buffer2, 0, sizeof(buffer2));
		for (i = 0; i < 11; i++) {
			argv[i] = "arg";
			envp[i] = "env";
		}
		argv[j] = buffer1;
		envp[j] = buffer2;
		for (i = 0; i < sizeof(buffer1) - 1; i++) {
			int len;
			char buffer[8192];
			buffer1[i] = '\n';
			buffer2[i] = '\t';
			if (fork() == 0) {
				execve("/bin/true", argv, envp);
				_exit(0);
			}
			while ((len = read(fd1, buffer, sizeof(buffer))) > 0)
				write(1, buffer, len);
			while ((len = read(fd2, buffer, sizeof(buffer))) > 0)
				write(1, buffer, len);
			wait(NULL);
		}
	}
	close(fd1);
	close(fd2);
	return 0;
}
