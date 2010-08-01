/*
 * ccs-selectpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/08/01
 *
 */
#include "ccstools.h"

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
