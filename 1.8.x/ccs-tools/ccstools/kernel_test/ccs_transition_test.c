/*
 * ccs_transition_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/12/13
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
#include "include.h"

static void stage_transit_test(void)
{
	char buffer[1024];
	int ret_ignored;
	int fdd;
	int fds;
	set_profile(1, "file::open");
	memset(buffer, 0, sizeof(buffer));
	fdd = open("/proc/ccs/domain_policy", O_RDWR);
	snprintf(buffer, sizeof(buffer) - 1, "select pid=%u\n"
		 "task auto_domain_transition <kernel> //transition_test "
		 "task.pid=%u\n", pid, pid);
	ret_ignored = write(fdd, buffer, strlen(buffer));
	fds = open("/proc/ccs/self_domain", O_RDWR);
	memset(buffer, 0, sizeof(buffer));
	ret_ignored = read(fds, buffer, sizeof(buffer));
	printf("task auto_domain_transition <kernel> //transition_test : ");
	if (!strcmp(buffer, "<kernel> //transition_test"))
		printf("OK\n");
	else
		printf("FAILED ('%s')\n", buffer);
	snprintf(buffer, sizeof(buffer) - 1, "delete "
		 "task auto_domain_transition <kernel> //transition_test "
		 "task.pid=%u\n", pid);
	ret_ignored = write(fdd, buffer, strlen(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "select pid=%u\n"
		 "file read /dev/null auto_domain_transition=\"/dev/null\"\n",
		 pid);
	ret_ignored = write(fdd, buffer, strlen(buffer));
	close(open("/dev/null", O_RDONLY));
	ret_ignored = lseek(fds, 0, SEEK_SET);
	memset(buffer, 0, sizeof(buffer));
	ret_ignored = read(fds, buffer, sizeof(buffer));
	printf("file read /dev/null auto_domain_transition=\"/dev/null\" : ");
	if (!strcmp(buffer, "<kernel> //transition_test /dev/null"))
		printf("OK\n");
	else
		printf("FAILED ('%s')\n", buffer);
	snprintf(buffer, sizeof(buffer) - 1, "delete file read /dev/null "
		 "auto_domain_transition=\"/dev/null\"\n");
	ret_ignored = write(fdd, buffer, strlen(buffer));
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	stage_transit_test();
	clear_status();
	if (0) { /* To suppress "defined but not used" warnings. */
		write_exception_policy("", 0);
		write_domain_policy("", 0);
	}
	return 0;
}
