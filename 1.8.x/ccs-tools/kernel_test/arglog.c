/*
 * arglog.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/types.h>

int main(int argc0, char *argv0[])
{
	int fd = open("/proc/ccs/audit", O_RDONLY);
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
				execve(BINDIR "/true", argv, envp);
				_exit(0);
			}
			while ((len = read(fd, buffer, sizeof(buffer))) > 0)
				write(1, buffer, len);
			wait(NULL);
		}
	}
	close(fd);
	return 0;
}
