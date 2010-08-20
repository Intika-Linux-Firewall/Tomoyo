/*
 * force-logout.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/08/01
 *
 * This utility forcibly chases away the user who logged in via network (e.g.
 * SSH).
 * This utility is designed for denied_execute_handler so that an intruder who
 * attempted to execute some programs which are not permitted by policy is
 * automatically chased away.
 * You need to set SUID bit to make vhangup() work.
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
#include <unistd.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{
	vhangup();
	shutdown(0, SHUT_RD);
	shutdown(1, SHUT_WR);
	shutdown(2, SHUT_WR);
	return 0;
}
