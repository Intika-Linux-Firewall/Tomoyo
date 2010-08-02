/*
 * tomoyo-selectpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 2.3.0   2010/08/02
 *
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
		tomoyo_normalize_line(argv[i]);
	tomoyo_get();
	while (true) {
		char *line = tomoyo_freadline(stdin);
		if (!line)
			break;
		if (tomoyo_domain_def(line)) {
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
	tomoyo_put();
	return 0;
}
