/*
 * newns.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0+   2011/09/29
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
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <stdlib.h>

static int child(void *arg)
{
	char **argv = (char **) arg;
	argv++;
	mount("/tmp/", "/tmp/", "tmpfs", 0, NULL);
	execvp(argv[0], argv);
	_exit(1);
}

int main(int argc, char *argv[])
{
	char c = 0;
	char *stack = malloc(8192);
	const pid_t pid = clone(child, stack + (8192 / 2), CLONE_NEWNS,
				(void *) argv);
	while (waitpid(pid, NULL, __WALL) == EOF && errno == EINTR)
		c++; /* Dummy. */
	return 0;
}
