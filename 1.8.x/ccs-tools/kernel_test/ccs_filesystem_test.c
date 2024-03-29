/*
 * ccs_filesystem_test.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
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
#define _GNU_SOURCE
#include "include.h"

static void show_prompt(const char *str, const int should_fail)
{
	printf("Testing %60s: (%s) ", str,
	       should_fail ? "must fail" : "should success");
	errno = 0;
}

#ifndef MS_MOVE
#define MS_MOVE         8192
#endif
#ifndef MS_UNBINDABLE
#define MS_UNBINDABLE   (1<<17)
#endif
#ifndef MS_PRIVATE
#define MS_PRIVATE      (1<<18)
#endif
#ifndef MS_SLAVE
#define MS_SLAVE        (1<<19)
#endif
#ifndef MS_SHARED
#define MS_SHARED       (1<<20)
#endif

static int child(void *arg)
{
	errno = 0;
	pivot_root("/proc/", "/proc/ccs/");
	return errno;
}

static void mount2(const char *source, const char *target,
		   const char *filesystemtype)
{
	if (mount(source, target, filesystemtype, 0, NULL)) {
		printf("BUG: mount() failed\n");
		fflush(stdout);
	}
}

static const unsigned char compressed_ext2_image_sample[1350] = {
	0x1F, 0x8B, 0x08, 0x00, 0xA8, 0xF2, 0x96, 0x4B, 0x02, 0x03, 0xED, 0xDC,
	0x3D, 0x4B, 0x5B, 0x51, 0x18, 0x07, 0xF0, 0xE7, 0xDE, 0xAB, 0x14, 0x8C,
	0xAB, 0xD5, 0x9A, 0xF8, 0x36, 0x0B, 0xA1, 0xE0, 0xE0, 0xDC, 0xD0, 0xAD,
	0xD0, 0xC5, 0xAF, 0x50, 0x9C, 0x42, 0x1D, 0x6A, 0xE6, 0xA6, 0x9B, 0x9B,
	0x8B, 0xD8, 0xA5, 0x5B, 0x97, 0x2E, 0xF9, 0x0E, 0x85, 0x4C, 0xF6, 0x23,
	0x74, 0x70, 0x55, 0x28, 0x52, 0xA8, 0xDD, 0xED, 0xB9, 0xB9, 0xB1, 0xA6,
	0xEA, 0x24, 0xA5, 0x81, 0xDE, 0xDF, 0x0F, 0x9E, 0xDC, 0xB7, 0x13, 0x2E,
	0xF7, 0xC0, 0xFF, 0x70, 0xCE, 0x85, 0x24, 0x02, 0xA8, 0xAB, 0x7E, 0xF9,
	0x31, 0x13, 0xB1, 0x95, 0x36, 0xA7, 0x45, 0x44, 0x2F, 0x6D, 0xB3, 0xC9,
	0x06, 0xEB, 0x55, 0xF5, 0xC7, 0x87, 0x9F, 0x7E, 0x1C, 0xBF, 0x88, 0x68,
	0xC5, 0xCE, 0xF7, 0x6C, 0xD4, 0x6E, 0x74, 0xFC, 0xF2, 0x62, 0x74, 0xED,
	0xFA, 0x7B, 0x8D, 0xB8, 0x69, 0x9F, 0x8F, 0xCF, 0x9F, 0x1D, 0x7E, 0x78,
	0xF7, 0x6D, 0xD8, 0x79, 0xFF, 0x71, 0xD0, 0xED, 0xBC, 0xCD, 0x9A, 0xBD,
	0x69, 0x3C, 0xEB, 0xE0, 0xCB, 0xF0, 0xA4, 0xF9, 0xF5, 0xF9, 0xCA, 0xE0,
	0xE0, 0x72, 0xBB, 0x7B, 0xD4, 0x1A, 0xE6, 0x13, 0xD7, 0xAA, 0xE7, 0x82,
	0x7A, 0x29, 0xAA, 0xF8, 0xC7, 0xEC, 0x28, 0xFF, 0xBD, 0xC8, 0x75, 0x09,
	0xD4, 0xC6, 0x55, 0x92, 0x4D, 0x71, 0xFA, 0x71, 0x05, 0x4C, 0xCF, 0xA3,
	0xBB, 0xE3, 0x01, 0x50, 0x0F, 0x93, 0xEB, 0xDF, 0xEB, 0xFA, 0x97, 0x13,
	0x80, 0x8B, 0x67, 0xD5, 0x02, 0xE4, 0xEE, 0xFD, 0x8B, 0x3F, 0xD6, 0x22,
	0x0B, 0xA6, 0x6A, 0xC0, 0x5F, 0xF6, 0xB9, 0x1C, 0x7F, 0x9E, 0xDE, 0x37,
	0xFE, 0xE4, 0xB1, 0x34, 0xD1, 0xEE, 0x71, 0xAA, 0xC5, 0x54, 0xE5, 0xB9,
	0x27, 0xA9, 0x96, 0x53, 0x35, 0xA3, 0x7C, 0x13, 0x1A, 0xB1, 0x92, 0x6A,
	0x35, 0xD5, 0xDA, 0xF8, 0x75, 0xE9, 0x86, 0x6E, 0x05, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x81,
	0xCA, 0xDF, 0xD8, 0xCF, 0x47, 0x96, 0xB7, 0x7F, 0xEF, 0xE7, 0x79, 0xBB,
	0x5D, 0xFD, 0x87, 0xDF, 0x79, 0x31, 0x97, 0x77, 0xF7, 0xDE, 0xEC, 0x6F,
	0xEE, 0xEE, 0xF5, 0x5E, 0xBF, 0xD2, 0x57, 0xF0, 0xBF, 0x69, 0xDC, 0xCA,
	0xFF, 0xCF, 0xA2, 0xCA, 0x3F, 0x50, 0x13, 0x33, 0xBA, 0x00, 0xE4, 0x1F,
	0x90, 0x7F, 0x40, 0xFE, 0x01, 0xF9, 0x07, 0xE4, 0x1F, 0x90, 0x7F, 0x40,
	0xFE, 0x01, 0xF9, 0x07, 0xE4, 0x1F, 0x90, 0x7F, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xFA, 0xF9, 0x05, 0x34, 0xF2,
	0x14, 0x08, 0x00, 0x00, 0x10, 0x00
};

int main(int argc, char *argv[])
{
	char c = 0;
	ccs_test_init();

	/* Test mount(). */
	{
		set_profile(3, "file::mount");
		show_prompt("mount('dev\\011name', '/', 'fs\\011name') ", 1);
		if (mount("dev\tname", "/", "fs\tname", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else if (errno == ENODEV)
			printf("OK: No such device.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		set_profile(1, "file::mount");
		show_prompt("mount('dev\\011name', '/', 'fs\\011name') ", 0);
		if (mount("dev\tname", "/", "fs\tname", 0, NULL) == EOF &&
		    errno == ENOMEM)
			printf("OK: Out of memory.\n");
		else if (errno == ENODEV)
			printf("OK: No such device.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		set_profile(3, "file::mount");
		show_prompt("mount('dev\\011name', '/', 'fs\\011name') ", 0);
		if (mount("dev\tname", "/", "fs\tname", 0, NULL) == EOF &&
		    errno == ENOMEM)
			printf("OK: Out of memory.\n");
		else if (errno == ENODEV)
			printf("OK: No such device.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		fprintf(domain_fp, "delete file mount dev\\011name / "
			"fs\\011name 0\n");
		show_prompt("mount('dev\\011name', '/', 'fs\\011name') ", 1);
		if (mount("dev\tname", "/", "fs\tname", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else if (errno == ENODEV)
			printf("OK: No such device.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		set_profile(1, "file::mount");
		show_prompt("mount(NULL, '/', 'tmpfs') ", 0);
		if (mount(NULL, "/", "tmpfs", 0, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success\n");
		set_profile(3, "file::mount");
		show_prompt("mount(NULL, '/', 'tmpfs') ", 0);
		if (mount(NULL, "/", "tmpfs", 0, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success\n");
		show_prompt("mount('anydev', '/', 'tmpfs') ", 0);
		if (mount("anydev", "/", "tmpfs", 0, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success\n");
		fprintf(domain_fp, "delete file mount <NULL> / tmpfs 0\n");
		fprintf(domain_fp, "file mount anydev / tmpfs 0\n");
		show_prompt("mount(NULL, '/', 'tmpfs') ", 0);
		if (mount(NULL, "/", "tmpfs", 0, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success\n");
		fprintf(domain_fp, "delete file mount anydev / tmpfs 0\n");
		set_profile(2, "file::mount");
		show_prompt("mount(NULL, NULL, 'tmpfs') ", 1);
		if (mount(NULL, NULL, "tmpfs", 0, NULL))
			printf("OK: %s\n", strerror(errno));
		else
			printf("BUG: Did not fail.\n");
		show_prompt("mount(NULL, NULL, NULL) ", 1);
		if (mount(NULL, NULL, NULL, 0, NULL))
			printf("OK: %s\n", strerror(errno));
		else
			printf("BUG: Did not fail.\n");
		show_prompt("mount('/', NULL, NULL) ", 1);
		if (mount("/", NULL, NULL, 0, NULL))
			printf("OK: %s\n", strerror(errno));
		else
			printf("BUG: Did not fail.\n");
		show_prompt("mount('/', NULL, 'tmpfs') ", 1);
		if (mount("/", NULL, "tmpfs", 0, NULL))
			printf("OK: %s\n", strerror(errno));
		else
			printf("BUG: Did not fail.\n");
		show_prompt("mount('/', '/', 'nonexistentfs') ", 1);
		if (mount("/", "/", "nonexistentfs", 0, NULL))
			printf("OK: %s\n", strerror(errno));
		else
			printf("BUG: Did not fail.\n");
		set_profile(0, "file::mount");
	}

	mkdir("/tmp/mount/", 0755);
	mkdir("/tmp/mount_bind/", 0755);
	mkdir("/tmp/mount_move/", 0755);

	/* Test mount(). */
	{
		static char buf[4096];
		char *dev_ram_path = canonicalize_file_name("/dev/ram0");
		if (!dev_ram_path)
			dev_ram_path = canonicalize_file_name("/dev/ram");
		if (!dev_ram_path) {
			dev_ram_path = "/dev/ram0";
			mknod(dev_ram_path, S_IFBLK, MKDEV(1, 0));
		}
		memset(buf, 0, sizeof(buf));
		{
			struct stat sbuf;
			FILE *fp = NULL;
			int ret_ignored;
			snprintf(buf, sizeof(buf) - 1, "zcat - > %s",
				 dev_ram_path);
			if (lstat(dev_ram_path, &sbuf) == 0 &&
			    S_ISBLK(sbuf.st_mode) && MAJOR(sbuf.st_rdev) == 1)
				fp = popen(buf, "w");
			if (fp) {
				ret_ignored =
					fwrite(compressed_ext2_image_sample, 1,
				       sizeof(compressed_ext2_image_sample),
				       fp);
				pclose(fp);
			} else
				fprintf(stderr, "Can't write to %s .\n",
					dev_ram_path);
		}
		set_profile(3, "file::mount");

		/* Test standard case */
		show_prompt("mount('none', '/tmp/mount/', 'tmpfs') for "
			    "'/tmp/mount/'", 1);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test device_name with pattern */
		snprintf(buf, sizeof(buf) - 1, "mount('%s', '/tmp/mount/', "
			 "'ext2') for '%s\\*'", dev_ram_path, dev_ram_path);
		show_prompt(buf, 1);
		if (mount(dev_ram_path, "/tmp/mount/", "ext2", MS_RDONLY, NULL)
		    == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test dir_name with pattern */
		show_prompt("mount('none', '/tmp/mount/', 'tmpfs') for "
			    "'/tmp/\\?\\?\\?\\?\\?/'", 1);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test standard case */
		fprintf(domain_fp, "file mount none /tmp/mount/ tmpfs 0\n");
		show_prompt("mount('none', '/tmp/mount/', 'tmpfs') for "
			    "'/tmp/mount/'", 0);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		fprintf(domain_fp,
			"delete file mount none /tmp/mount/ tmpfs 0\n");

		/* Test device_name with pattern */
		fprintf(domain_fp, "file mount %s\\* /tmp/mount/ ext2 1\n",
			dev_ram_path);
		snprintf(buf, sizeof(buf) - 1, "mount('%s', '/tmp/mount/', "
			 "'ext2') for '%s\\*'", dev_ram_path, dev_ram_path);
		show_prompt(buf, 0);
		if (mount(dev_ram_path, "/tmp/mount/", "ext2", MS_RDONLY, NULL)
		    == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		fprintf(domain_fp, "delete file mount %s\\* "
			"/tmp/mount/ ext2 1\n", dev_ram_path);

		/* Test dir_name with pattern */
		fprintf(domain_fp,
			"file mount none /tmp/\\?\\?\\?\\?\\?/ tmpfs 0\n");
		show_prompt("mount('none', '/tmp/mount/', 'tmpfs') for "
			    "'/tmp/\\?\\?\\?\\?\\?/'", 0);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		fprintf(domain_fp, "delete file mount none "
			"/tmp/\\?\\?\\?\\?\\?/ tmpfs 0\n");

		set_profile(0, "file::mount");
		while (umount("/tmp/mount/") == 0)
			c++; /* Dummy. */
	}

	/* Test mount(). */
	{
		mount2("none", "/tmp/mount/", "tmpfs");
		set_profile(3, "file::mount");

		/* Test remount case */
		show_prompt("mount('/tmp/mount/', MS_REMOUNT)", 1);
		if (mount("none", "/tmp/mount/", "tmpfs", MS_REMOUNT, NULL)
		    == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		show_prompt("mount('/tmp/mount/', MS_REMOUNT)", 1);
		if (mount(NULL, "/tmp/mount/", NULL, MS_REMOUNT, NULL) == EOF
		    && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		fprintf(domain_fp, "file mount something /tmp/mount/ "
			"--remount 0\n");
		show_prompt("mount('/tmp/mount/', MS_REMOUNT)", 0);
		if (mount(NULL, "/tmp/mount/", NULL, MS_REMOUNT, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success.\n");
		fprintf(domain_fp, "delete file mount something /tmp/mount/ "
			"--remount 0\n");

		/* Test bind case */
		show_prompt("mount('/tmp/mount/', '/tmp/mount_bind/', "
			    "MS_BIND)", 1);
		if (mount("/tmp/mount/", "/tmp/mount_bind/", NULL, MS_BIND,
			  NULL) == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test move case */
		show_prompt("mount('/tmp/mount/', '/tmp/mount_move/', "
			    "MS_MOVE)", 1);
		if (mount("/tmp/mount/", "/tmp/mount_move/", NULL, MS_MOVE,
			  NULL) == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test remount case */
		fprintf(domain_fp,
			"file mount any /tmp/mount/ --remount 0\n");
		show_prompt("mount('/tmp/mount/', MS_REMOUNT)", 0);
		if (mount("none", "/tmp/mount/", "tmpfs", MS_REMOUNT, NULL)
		    == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		fprintf(domain_fp, "delete file mount any /tmp/mount/ "
			"--remount 0\n");

		/* Test bind case */
		fprintf(domain_fp,
			"file mount /tmp/mount/ /tmp/mount_bind/ --bind 0\n");
		show_prompt("mount('/tmp/mount/', '/tmp/mount_bind', MS_BIND)",
			    0);
		if (mount("/tmp/mount/", "/tmp/mount_bind/", NULL, MS_BIND,
			  NULL) == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		set_profile(0, "file::mount");
		umount("/tmp/mount_bind/");
		fprintf(domain_fp, "delete file mount /tmp/mount/ "
			"/tmp/mount_bind/ --bind 0\n");

		/* Test move case */
		set_profile(3, "file::mount");
		fprintf(domain_fp, "file unmount /tmp/mount/\n");
		fprintf(domain_fp, "file mount /tmp/mount/ /tmp/mount_move/ "
			"--move 0\n");
		show_prompt("mount('/tmp/mount/', '/tmp/mount_move/', "
			    "MS_MOVE)", 0);
		if (mount("/tmp/mount/", "/tmp/mount_move/", NULL, MS_MOVE,
			  NULL) == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		set_profile(0, "file::mount");
		umount("/tmp/mount_move/");
		fprintf(domain_fp, "delete file unmount /tmp/mount/\n");
		fprintf(domain_fp, "delete file mount /tmp/mount/ "
			"/tmp/mount_move/ --move 0\n");

		fprintf(domain_fp, "file mount something /tmp/mount/ tmpfs"
			" 0\n");
		mount2("none", "/tmp/mount/", "tmpfs");
		fprintf(domain_fp, "delete file mount something /tmp/mount/"
			" tmpfs 0\n");

		/* Tests for shared subtree case. */
		set_profile(0, "file::mount");
		mount2("none", "/tmp/mount/", "tmpfs");
		set_profile(3, "file::mount");
		/* Test private case */
		fprintf(domain_fp, "file mount something /tmp/mount/"
			" --make-private 0\n");
		show_prompt("mount('/tmp/mount/', MS_PRIVATE)", 0);
		if (mount(NULL, "/tmp/mount/", NULL, MS_PRIVATE, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success.\n");
		fprintf(domain_fp, "delete file mount something"
			" /tmp/mount/ --make-private 0\n");
		show_prompt("mount('/tmp/mount/', MS_PRIVATE)", 1);
		if (mount(NULL, "/tmp/mount/", NULL, MS_PRIVATE, NULL) == EOF
		    && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		
		/* Test shared case */
		fprintf(domain_fp, "file mount something /tmp/mount/"
			" --make-shared 0\n");
		show_prompt("mount('/tmp/mount/', MS_SHARED)", 0);
		if (mount(NULL, "/tmp/mount/", NULL, MS_SHARED, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success.\n");
		fprintf(domain_fp, "delete file mount something"
			" /tmp/mount/ --make-shared 0\n");
		show_prompt("mount('/tmp/mount/', MS_SHARED)", 1);
		if (mount(NULL, "/tmp/mount/", NULL, MS_SHARED, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		
		/* Test slave case */
		fprintf(domain_fp, "file mount something /tmp/mount/"
			" --make-slave 0\n");
		show_prompt("mount('/tmp/mount/', MS_SLAVE)", 0);
		if (mount(NULL, "/tmp/mount/", NULL, MS_SLAVE, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success.\n");
		fprintf(domain_fp, "delete file mount something"
			" /tmp/mount/ --make-slave 0\n");
		show_prompt("mount('/tmp/mount/', MS_SLAVE)", 1);
		if (mount(NULL, "/tmp/mount/", NULL, MS_SLAVE, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test unbindable case */
		fprintf(domain_fp, "file mount something /tmp/mount/"
			" --make-unbindable 0\n");
		show_prompt("mount('/tmp/mount/', MS_UNBINDABLE)", 0);
		if (mount(NULL, "/tmp/mount/", NULL, MS_UNBINDABLE, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success.\n");
		fprintf(domain_fp, "delete file mount something"
			" /tmp/mount/ --make-unbindable 0\n");
		show_prompt("mount('/tmp/mount/', MS_UNBINDABLE)", 1);
		if (mount(NULL, "/tmp/mount/", NULL, MS_UNBINDABLE,
			  NULL) == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test invalid case */
		show_prompt("mount('/tmp/mount/', MS_PRIVATE | MS_SHARED)", 1);
		if (mount(NULL, "/tmp/mount/", NULL, MS_PRIVATE | MS_SHARED,
			  NULL) == EOF && errno == EINVAL)
			printf("OK: Invalid argument.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		set_profile(0, "file::mount");

		while (umount("/tmp/mount/") == 0)
			c++; /* Dummy. */
	}

	/* Test umount(). */
	{
		/* Test standard case */
		fprintf(domain_fp, "file unmount /tmp/mount/\n");

		set_profile(0, "file::unmount");
		mount2("none", "/tmp/mount/", "tmpfs");
		set_profile(3, "file::unmount");
		show_prompt("umount('/tmp/mount/') for '/tmp/mount/'", 0);
		if (umount("/tmp/mount/") == 0)
			printf("OK\n");
		else
			printf("BUG: %s\n", strerror(errno));
		fprintf(domain_fp, "delete file unmount /tmp/mount/\n");

		set_profile(0, "file::unmount");

		mount2("none", "/tmp/mount/", "tmpfs");
		set_profile(3, "file::unmount");
		show_prompt("umount('/tmp/mount/') for '/tmp/mount/'", 1);
		if (umount("/tmp/mount/") == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("FAILED: %s\n", strerror(errno));

		/* Test pattern */
		fprintf(domain_fp, "file unmount /tmp/\\?\\?\\?\\?\\?/\n");
		set_profile(0, "file::unmount");
		mount2("none", "/tmp/mount/", "tmpfs");
		set_profile(3, "file::unmount");
		show_prompt("umount('/tmp/mount/') for "
			    "'/tmp/\\?\\?\\?\\?\\?/'", 1);
		if (umount("/tmp/mount/") == 0)
			printf("OK\n");
		else
			printf("BUG: %s\n", strerror(errno));
		fprintf(domain_fp,
			"delete file unmount /tmp/\\?\\?\\?\\?\\?/\n");

		set_profile(0, "file::unmount");
		while (umount("/tmp/mount/") == 0)
			c++; /* Dummy. */
	}

	/* Test chroot(). */
	{
		set_profile(3, "file::chroot");

		/* Test standard case */
		fprintf(domain_fp, "file chroot /tmp/mount/\n");
		show_prompt("chroot('/tmp/mount/') for '/tmp/mount/'", 0);
		fflush(stdout);
		if (fork() == 0) {
			if (chroot("/tmp/mount/") == 0)
				printf("OK\n");
			else
				printf("FAILED: %s\n", strerror(errno));
			fflush(stdout);
			_exit(0);
		}
		wait(NULL);
		fprintf(domain_fp, "delete file chroot /tmp/mount/\n");

		show_prompt("chroot('/tmp/mount/') for '/tmp/mount/'", 1);
		fflush(stdout);
		if (fork() == 0) {
			if (chroot("/tmp/mount/") == EOF && errno == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("BUG: %s\n", strerror(errno));
			fflush(stdout);
			_exit(0);
		}
		wait(NULL);

		/* Test pattern */
		fprintf(domain_fp, "file chroot /tmp/\\?\\?\\?\\?\\?/\n");
		show_prompt("chroot('/tmp/mount/') for "
			    "'/tmp/\\?\\?\\?\\?\\?/'", 0);
		fflush(stdout);
		if (fork() == 0) {
			if (chroot("/tmp/mount/") == 0)
				printf("OK\n");
			else
				printf("FAILED: %s\n", strerror(errno));
			fflush(stdout);
			_exit(0);
		}
		wait(NULL);
		fprintf(domain_fp,
			"delete file chroot /tmp/\\?\\?\\?\\?\\?/\n");

		set_profile(0, "file::chroot");
	}

	/* Test pivot_root(). */
	{
		int error;
		char *stack = malloc(8192);
		set_profile(3, "file::pivot_root");
		fprintf(domain_fp, "file pivot_root proc:/ proc:/ccs/\n");
		snprintf(stack, 8191, "pivot_root('proc:/', 'proc:/ccs/')");
		show_prompt(stack, 0);
		{
			const pid_t pid = clone(child, stack + (8192 / 2),
						CLONE_NEWNS, NULL);
			while (waitpid(pid, &error, __WALL) == EOF &&
			       errno == EINTR)
				c++; /* Dummy. */
		}
		errno = WIFEXITED(error) ? WEXITSTATUS(error) : -1;
		if (errno == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));

		fprintf(domain_fp,
			"delete file pivot_root proc:/ proc:/ccs/\n");
		snprintf(stack, 8191, "pivot_root('proc:/', 'proc:/ccs/')");
		show_prompt(stack, 1);
		{
			const pid_t pid = clone(child, stack + (8192 / 2),
						CLONE_NEWNS, NULL);
			while (waitpid(pid, &error, __WALL) == EOF &&
			       errno == EINTR)
				c++; /* Dummy. */
		}
		errno = WIFEXITED(error) ? WEXITSTATUS(error) : -1;
		if (errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		set_profile(2, "file::pivot_root");
		snprintf(stack, 8191, "pivot_root('proc:/', 'proc:/ccs/')");
		show_prompt(stack, 0);
		{
			const pid_t pid = clone(child, stack + (8192 / 2),
						CLONE_NEWNS, NULL);
			while (waitpid(pid, &error, __WALL) == EOF &&
			       errno == EINTR)
				c++; /* Dummy. */
		}
		errno = WIFEXITED(error) ? WEXITSTATUS(error) : -1;
		if (errno == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));

		set_profile(0, "file::pivot_root");

		free(stack);
	}

	rmdir("/tmp/mount_move/");
	rmdir("/tmp/mount_bind/");
	rmdir("/tmp/mount/");

	clear_status();
	if (0) { /* To suppress "defined but not used" warnings. */
		write_domain_policy("", 0);
		write_exception_policy("", 0);
	}
	return 0;
}
