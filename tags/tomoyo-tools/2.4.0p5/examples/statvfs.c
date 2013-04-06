/*
 * statvfs.c
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
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <sys/vfs.h>

int main(int argc, char *argv[])
{
	struct statfs buf;
	if (statfs(argv[1], &buf))
		return 1;
	printf("0x%08X\n", buf.f_type);
	return 0;
}
