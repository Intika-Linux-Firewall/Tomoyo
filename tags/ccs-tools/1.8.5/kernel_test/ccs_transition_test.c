/*
 * ccs_transition_test.c
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
#include "include.h"

static void check_self_domain(const char *expected)
{
	static char buffer[4096];
	static int fd = EOF;
	int ret_ignored;
	if (fd == EOF)
		fd = open("/proc/ccs/self_domain", O_RDONLY);
	memset(buffer, 0, sizeof(buffer));
	ret_ignored = lseek(fd, 0, SEEK_SET);
	ret_ignored = read(fd, buffer, sizeof(buffer) - 1);
	if (!strcmp(buffer, expected))
		printf("OK\n");
	else
		printf("FAILED (expected='%s' result='%s')\n", expected,
		       buffer);
}

static void write_self_domain(const char *domain)
{
	static int fd = EOF;
	int ret_ignored;
	if (fd == EOF)
		fd = open("/proc/ccs/self_domain", O_WRONLY);
	ret_ignored = write(fd, domain, strlen(domain));
}

static void write_policy(const char *policy, _Bool delete)
{	
	static int fd = EOF;
	static char buf[64];
	int ret_ignored;
	memset(buf, 0, sizeof(buf));
	if (fd == EOF)
		fd = open("/proc/ccs/domain_policy", O_WRONLY);
	if (delete)
		snprintf(buf, sizeof(buf) - 1, "delete ");
	else
		snprintf(buf, sizeof(buf) - 1, "select pid=%u\n", pid);
	ret_ignored = write(fd, buf, strlen(buf));
	ret_ignored = write(fd, policy, strlen(policy));
	ret_ignored = write(fd, "\n", 1);
	if (!delete)
		printf("%s : ", policy);
}

static void stage_transit_test(void)
{
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	set_profile(2, "file::open");

	/* task auto_domain_transition with matched condition */
	snprintf(buffer, sizeof(buffer) - 1, "task auto_domain_transition "
		 "<kernel> //transition_test task.pid=%u", pid);
	write_policy(buffer, 0);
	close(open("/dev/null", O_RDONLY));
	check_self_domain("<kernel> //transition_test");
	write_policy(buffer, 1);

	/* task auto_domain_transition with unmatched condition */
	snprintf(buffer, sizeof(buffer) - 1, "task auto_domain_transition "
		 "<kernel> /bad task.pid=0");
	write_policy(buffer, 0);
	close(open("/dev/null", O_RDONLY));
	check_self_domain("<kernel> //transition_test");
	write_policy(buffer, 1);

	/* auto_domain_transition= with matched condition */
	snprintf(buffer, sizeof(buffer) - 1, "file read /dev/null "
		 "auto_domain_transition=\"/dev/null\"");
	write_policy(buffer, 0);
	close(open("/dev/null", O_RDONLY));
	check_self_domain("<kernel> //transition_test /dev/null");
	write_policy(buffer, 1);

	/* auto_domain_transition= with unmatched condition */
	snprintf(buffer, sizeof(buffer) - 1, "file read /dev/null "
		 "auto_domain_transition=\"/dev/null\" task.pid=0");
	write_policy(buffer, 0);
	close(open("/dev/null", O_RDONLY));
	check_self_domain("<kernel> //transition_test /dev/null");
	write_policy(buffer, 1);

	/*
	 * task manual_domain_transition with
	 * matched domain and matched condition
	 */
	snprintf(buffer, sizeof(buffer) - 1, "task manual_domain_transition "
		 "<kernel> //transition_test task.pid=%u", pid);
	write_policy(buffer, 0);
	write_self_domain("<kernel> //transition_test");
	check_self_domain("<kernel> //transition_test");
	write_policy(buffer, 1);

	/*
	 * task manual_domain_transition with
	 * matched domain and unmatched condition
	 */
	snprintf(buffer, sizeof(buffer) - 1, "task manual_domain_transition "
		 "<kernel> task.pid=%u", pid + 1);
	write_policy(buffer, 0);
	write_self_domain("<kernel>");
	check_self_domain("<kernel> //transition_test");
	write_policy(buffer, 1);

	/*
	 * task manual_domain_transition with
	 * unmatched domain and matched condition
	 */
	snprintf(buffer, sizeof(buffer) - 1, "task manual_domain_transition "
		 "<kernel> /bad task.pid=%u", pid);
	write_policy(buffer, 0);
	write_self_domain("<kernel>");
	check_self_domain("<kernel> //transition_test");
	write_policy(buffer, 1);

	/*
	 * task manual_domain_transition with
	 * unmatched domain and unmatched condition
	 */
	snprintf(buffer, sizeof(buffer) - 1, "task manual_domain_transition "
		 "<kernel> /bad task.pid=%u", pid + 2);
	write_policy(buffer, 0);
	write_self_domain("<kernel>");
	check_self_domain("<kernel> //transition_test");
	write_policy(buffer, 1);
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
