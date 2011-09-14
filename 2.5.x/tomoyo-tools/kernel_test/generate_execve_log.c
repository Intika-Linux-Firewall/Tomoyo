/*
 * generate_execve_log.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0   2011/08/06
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

int main(int argc0, char *argv0[])
{
	char *argv[128];
	char *envp[128];
	char buffer[16384];
	memset(argv, 0, sizeof(argv));
	memset(envp, 0, sizeof(envp));

	if (fork() == 0) {
		execve("/bin/true", NULL, NULL);
		_exit(0);
	}
	wait(NULL);

	if (fork() == 0) {
		execve("/bin/true", argv, NULL);
		_exit(0);
	}
	wait(NULL);

	if (fork() == 0) {
		execve("/bin/true", NULL, envp);
		_exit(0);
	}
	wait(NULL);

	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	argv[0] = "";
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	argv[0] = NULL;
	envp[0] = "";
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	argv[0] = "\xFF\xFE\x01\x02";
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	memset(buffer, ' ', 1000);
	argv[1] = buffer;
	envp[0] = "envp[0]";
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	argv[2] = buffer;
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	argv[3] = buffer;
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	envp[1] = "envp[1]";
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	envp[2] = buffer;
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	return 0;
	/*
	  memset(argv, 0, sizeof(argv));
	  memset(envp, 0, sizeof(envp));
	*/
	memset(buffer, 'a', sizeof(buffer) - 1);
	argv[0] = "true";
	argv[1] = buffer;
	argv[2] = NULL;
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	/*
	  memset(argv, 0, sizeof(argv));
	  memset(envp, 0, sizeof(envp));
	*/
	buffer[4000] = '\0';
	argv[0] = buffer;
	argv[1] = buffer;
	argv[2] = buffer;
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	argv[2] = NULL;
	envp[0] = buffer;
	envp[1] = buffer;
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	argv[1] = NULL;
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	argv[0] = NULL;
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	envp[1] = NULL;
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		_exit(0);
	}
	wait(NULL);

	return 0;
}
