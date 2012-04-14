/*
 * ccs_accept_test.c
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
#include "include.h"

static void set_level(const int i)
{
	set_profile(i, "file::chgrp");
	set_profile(i, "file::chmod");
	set_profile(i, "file::chown");
	set_profile(i, "file::chroot");
	set_profile(i, "file::create");
	set_profile(i, "file::execute");
	set_profile(i, "file::ioctl");
	set_profile(i, "file::link");
	set_profile(i, "file::mkblock");
	set_profile(i, "file::mkchar");
	set_profile(i, "file::mkdir");
	set_profile(i, "file::mkfifo");
	set_profile(i, "file::mksock");
	set_profile(i, "file::mount");
	set_profile(i, "file::open");
	set_profile(i, "file::pivot_root");
	set_profile(i, "file::rename");
	set_profile(i, "file::rmdir");
	set_profile(i, "file::symlink");
	set_profile(i, "file::truncate");
	set_profile(i, "file::unmount");
	set_profile(i, "file::unlink");
	set_profile(i, "file::getattr");
}

static void test(int rw_loop, int truncate_loop, int append_loop,
		 int create_loop)
{
	static const int rw_flags[4] = { 0, O_RDONLY, O_WRONLY, O_RDWR };
	static const int create_flags[3] = { 0, O_CREAT /* nonexistent*/ ,
					     O_CREAT /* existent */ };
	static const int truncate_flags[2] = { 0, O_TRUNC };
	static const int append_flags[2] = { 0, O_APPEND };
	int level;
	int flags;
	int fd;
	static char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "/tmp/file:a=%d:t=%d:c=%d:m=%d",
		 append_loop, truncate_loop, create_loop, rw_loop);
	flags = rw_flags[rw_loop] | truncate_flags[truncate_loop] |
		append_flags[append_loop] | create_flags[create_loop];
	fprintf(domain_fp,
		"delete file read/write/append/execute/truncate %s\n", buffer);
	fprintf(domain_fp, "delete file create %s 0644\n", buffer);
	for (level = 0; level < 4; level++) {
		set_level(0);
		if (create_loop == 1)
			unlink(buffer);
		else
			close(open(buffer, O_CREAT, 0644));
		set_level(level);
		fd = open(buffer, flags, 0644);
		if (fd != EOF)
			close(fd);
		else
			fprintf(stderr, "%d: open(%04o) failed\n", level,
				flags);
		/*
		  fd = open(buffer, flags, 0644)
		  if (fd != EOF)
		  close(fd);
		  else
		  fprintf(stderr, "%d: open(%04o) failed\n", level, flags);
		*/
		/*
		  fd = open(buffer, flags, 0644);
		  if (fd != EOF)
		  close(fd);
		  else
		  fprintf(stderr, "%d: open(%04o) failed\n", level, flags);
		*/
	}
	fprintf(domain_fp,
		"delete file read/write/append/execute/truncate/getattr %s\n",
		buffer);
	fprintf(domain_fp, "delete file create %s 0644\n", buffer);
	fd = open(buffer, flags, 0644);
	if (fd != EOF) {
		close(fd);
		fprintf(stderr, "%d: open(%04o) didn't fail\n", 3, flags);
	}
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	set_profile(0, "file");
	fprintf(profile_fp, "255-PREFERENCE={ max_learning_entry=2048 }\n");
	{
		int append_loop;
		for (append_loop = 0; append_loop < 2; append_loop++) {
			int truncate_loop;
			for (truncate_loop = 0; truncate_loop < 2;
			     truncate_loop++) {
				int create_loop;
				for (create_loop = 0; create_loop < 3;
				     create_loop++) {
					int rw_loop;
					for (rw_loop = 0; rw_loop < 4;
					     rw_loop++)
						test(rw_loop, truncate_loop,
						     append_loop, create_loop);
				}
			}
		}
	}
	fprintf(profile_fp, "255-CONFIG::file={ mode=disabled }\n");
	printf("Done\n");
	clear_status();
	if (0) { /* To suppress "defined but not used" warnings. */
		write_domain_policy("", 0);
		write_exception_policy("", 0);
	}
	return 0;
}
