/*
 * checktoken.c
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
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <time.h>

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
	static char seed[40];
	int i;
	int trial;
	const char *shell = get_shell();
	srand(time(NULL) / 30);
	memset(seed, 0, sizeof(seed));
	for (i = 0; i < sizeof(seed) - 1; i++)
		seed[i] = (rand() % 64) + 33;
	for (trial = 0; trial < 3; trial++) {
		char *dp;
		char *ret_ignored;
		memset(buffer, 0, sizeof(buffer));
		printf("Password: ");
		ret_ignored = fgets(buffer, sizeof(buffer) - 1, stdin);
		dp = strchr(buffer, '\n');
		if (dp)
			*dp = '\0';
		if (!strcmp(buffer, seed)) {
			if (shell)
				execlp(shell, shell, NULL);
		}
		sleep(3);
	}
	printf("Authentication Failure\n");
	return 0;
}
