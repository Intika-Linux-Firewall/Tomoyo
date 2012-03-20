/*
 * ccs-loadpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
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
#include "ccstools.h"

/**
 * ccs_close_write - Close stream opened by ccs_open_write().
 *
 * @fp: Pointer to "FILE".
 *
 * Returns true on success, false otherwise.
 */
static _Bool ccs_close_write(FILE *fp)
{
	_Bool result = true;
	if (ccs_network_mode) {
		if (fputc(0, fp) == EOF)
			result = false;
		if (fflush(fp) == EOF)
			result = false;
		if (fgetc(fp) == EOF)
			result = false;
	}
	if (fclose(fp) == EOF)
		result = false;
	return result;
}

static _Bool ccs_move_file_to_proc(const char *dest)
{
	FILE *proc_fp = ccs_open_write(dest);
	_Bool result = true;
	if (!proc_fp) {
		fprintf(stderr, "Can't open %s for writing.\n", dest);
		return false;
	}
	ccs_get();
	while (true) {
		char *line = ccs_freadline(stdin);
		if (!line)
			break;
		if (line[0])
			if (fprintf(proc_fp, "%s\n", line) < 0)
				result = false;
	}
	ccs_put();
	if (!ccs_close_write(proc_fp))
		result = false;
	return result;
}

int main(int argc, char *argv[])
{
	int i;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (!cp)
			goto usage;
		*cp++ = '\0';
		ccs_network_ip = inet_addr(ptr);
		ccs_network_port = htons(atoi(cp));
		if (ccs_network_mode) {
			fprintf(stderr, "You cannot specify multiple "
				"%s at the same time.\n\n",
				"remote agents");
			goto usage;
		}
		ccs_network_mode = true;
	}
	if (ccs_network_mode) {
		if (!ccs_check_remote_host())
			return 1;
	} else if (access(CCS_PROC_POLICY_DIR, F_OK)) {
		fprintf(stderr,
			"You can't run this program for this kernel.\n");
		return 1;
	}
	return !ccs_move_file_to_proc(CCS_PROC_POLICY_POLICY);
usage:
	printf("%s [remote_ip:remote_port]\n\n"
	       "remote_ip:remote_port : Write to ccs-editpolicy-agent "
	       "listening at remote_ip:remote_port rather than /proc/ccs/ "
	       "directory.\n", argv[0]);
	return 1;
}
