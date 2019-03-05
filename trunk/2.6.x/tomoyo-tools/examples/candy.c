/*
 * candy.c
 *
 * An example program for CERBERUS.
 * ( https://osdn.jp/projects/tomoyo/document/winf2005-en.pdf )
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.6.0   2019/03/05
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

static int get_start_time(pid_t pid, unsigned long long *t)
{
	FILE *fp;
	int i;
	char *cp;
	char buffer[1024];
	char *ret_ignored;
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "/proc/%d/stat", pid);
	fp = fopen(buffer, "r");
	if (!fp)
		return EOF;
	ret_ignored = fgets(buffer, sizeof(buffer) - 1, fp);
	fclose(fp);
	for (i = 0; i < 21; i++) {
		cp = strchr(buffer, ' ');
		if (!cp)
			return EOF;
		memmove(buffer, cp + 1, strlen(cp + 1) + 1);
	}
	cp = strchr(buffer, ' ');
	if (!cp)
		return EOF;
	*cp = '\0';
	if (sscanf(buffer, "%llu", t) != 1)
		return EOF;
	return 0;
}

int main(int argc, char *argv[])
{
	static char buffer[1024];
	static const char *passwd = "CERBERUS\n";
	int trial;
	const char *shell = get_shell();
	for (trial = 0; trial < 3; trial++) {
		char *ret_ignored;
		memset(buffer, 0, sizeof(buffer));
		printf("Password: ");
		ret_ignored = fgets(buffer, sizeof(buffer) - 1, stdin);
		if (shell && !strcmp(buffer, passwd)) {
			unsigned long long t0;
			unsigned long long t1;
			if (get_start_time(getppid(), &t0) == 0 &&
			    get_start_time(getpid(), &t1) == 0) {
				/* 10 sec */
				if ((t1 - t0) < 1000)
					execlp(shell, shell, NULL);
			}
		}
		sleep(3);
	}
	printf("Authentication Failure\n");
	return 0;
}
