/*
 * ccs_accept_test.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 */
#include "include.h"

static void set_level(const int i)
{
	fprintf(profile_fp, "255-MAC_FOR_FILE=%d\n", i);
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
	int i;
	int fd;
	static char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer) - 1, "/tmp/file:a=%d:t=%d:c=%d:m=%d",
		 append_loop, truncate_loop, create_loop, rw_loop);
	fprintf(exception_fp, "deny_rewrite %s\n", buffer);
	flags = rw_flags[rw_loop] | truncate_flags[truncate_loop] |
		append_flags[append_loop] | create_flags[create_loop];
	for (i = 1; i < 8; i++)
		fprintf(domain_fp, "delete %d %s\n", i, buffer);
	for (level = 0; level < 4; level++) {
		set_level(0);
		if (create_loop == 1)
			unlink(buffer);
		else
			close(open(buffer, O_CREAT, 0666));
		set_level(level);
		fd = open(buffer, flags, 0666);
		if (fd != EOF)
			close(fd);
		else
			fprintf(stderr, "%d: open(%04o) failed\n", level,
				flags);
		/*
		  fd = open(buffer, flags, 0666)
		  if (fd != EOF)
		  close(fd);
		  else
		  fprintf(stderr, "%d: open(%04o) failed\n", level, flags);
		*/
		/*
		  fd = open(buffer, flags, 0666);
		  if (fd != EOF)
		  close(fd);
		  else
		  fprintf(stderr, "%d: open(%04o) failed\n", level, flags);
		*/
	}
	for (i = 1; i < 8; i++)
		fprintf(domain_fp, "delete %d %s\n", i, buffer);
	fprintf(domain_fp, "delete allow_truncate %s\n", buffer);
	fprintf(domain_fp, "delete allow_create %s\n", buffer);
	fprintf(domain_fp, "delete allow_rewrite %s\n", buffer);
	fd = open(buffer, flags, 0666);
	if (fd != EOF) {
		close(fd);
		fprintf(stderr, "%d: open(%04o) didn't fail\n", 3, flags);
	}
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	fprintf(profile_fp, "255-COMMENT=Test\n255-TOMOYO_VERBOSE=disabled\n"
		"255-MAC_FOR_FILE=disabled\n255-MAX_ACCEPT_ENTRY=2048\n");
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
	fprintf(profile_fp, "255-MAC_FOR_FILE=disabled\n");
	printf("Done\n");
	clear_status();
	return 0;
}
