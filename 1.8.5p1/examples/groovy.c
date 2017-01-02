/*
 * groovy.c
 *
 * An example program for CERBERUS.
 * ( http://osdn.jp/projects/tomoyo/document/winf2005-en.pdf )
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.5   2015/11/11
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>

static const char *get_shell(void)
{
	static char *shell = NULL;
	if (!shell) {
		struct passwd *pw = getpwuid(getuid());
		shell = pw ? pw->pw_shell : "/bin/sh";
	}
	return shell;
}

int main(int argc, char *argv[])
{
	static char buffer[1024];
	static const char *lockfile = "/tmp/.lockme";
	int trial;
	const char *shell = get_shell();
	for (trial = 0; trial < 3; trial++) {
		char *ret_ignored;
		memset(buffer, 0, sizeof(buffer));
		printf("Password: ");
		ret_ignored = fgets(buffer, sizeof(buffer) - 1, stdin);
		if (shell) {
			int fd;
			fd = open(lockfile, O_WRONLY | O_CREAT | O_EXCL, 0600);
			if (fd != EOF) {
				close(fd);
				execlp(shell, shell, NULL);
			}
		}
		sleep(3);
	}
	printf("Authentication Failure\n");
	return 0;
}
