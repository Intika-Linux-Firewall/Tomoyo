/*
 * tomoyo-selectpolicy.c
 *
 * TOMOYO Linux's utilities.
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
#include "tomoyotools.h"

int main(int argc, char *argv[])
{
	_Bool recursive = false;
	_Bool matched = false;
	int start = 1;
	int i;
	if (argc > 1 && !strcmp(argv[1], "-r")) {
		recursive = true;
		start++;
	}
	if (argc <= start) {
		fprintf(stderr, "%s [-r] domainname [domainname ...]"
			" < domain_policy\n", argv[0]);
		return 0;
	}
	for (i = start; i < argc; i++)
		ccs_normalize_line(argv[i]);
	ccs_get();
	while (true) {
		char *line = ccs_freadline(stdin);
		if (!line)
			break;
		if (ccs_domain_def(line)) {
			matched = false;
			for (i = start; i < argc; i++) {
				const int len = strlen(argv[i]);
				if (strncmp(line, argv[i], len))
					continue;
				if (!recursive) {
					if (line[len])
						continue;
				} else {
					if (line[len] && line[len] != ' ')
						continue;
				}
				matched = true;
			}
		}
		if (matched)
			puts(line);
	}
	ccs_put();
	return 0;
}
