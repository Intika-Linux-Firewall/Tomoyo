/*
 * ccs-patternize.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/08/01
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

/*
 * Check whether the given filename is patterened.
 * Returns nonzero if patterned, zero otherwise.
 */
static _Bool ccs_path_contains_pattern(const char *filename)
{
	if (filename) {
		char c;
		char d;
		char e;
		while (true) {
			c = *filename++;
			if (!c)
				break;
			if (c != '\\')
				continue;
			c = *filename++;
			switch (c) {
			case '\\':  /* "\\" */
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				d = *filename++;
				if (d < '0' || d > '7')
					break;
				e = *filename++;
				if (e < '0' || e > '7')
					break;
				continue;
			}
			return true;
		}
	}
	return false;
}

struct ccs_path_pattern_entry {
	const char *group_name;
	struct ccs_path_info path;
	struct ccs_number_entry number;
	struct ccs_ip_address_entry ip;
	int type;
};

static struct ccs_path_pattern_entry *ccs_pattern_list = NULL;
static int ccs_pattern_list_len = 0;

static const char *ccs_path_patternize(const char *cp)
{
	int i;
	struct ccs_path_info cp2;
	cp2.name = cp;
	ccs_fill_path_info(&cp2);
	for (i = 1; i < ccs_pattern_list_len; i++) {
		const int type = ccs_pattern_list[i].type;
		if (type != 1 && type != 2)
			continue;
		if (!ccs_path_matches_pattern(&cp2, &ccs_pattern_list[i].path))
			continue;
		if (type == 2)
			return ccs_pattern_list[i].group_name;
		return ccs_pattern_list[i].path.name;
	}
	return cp;
}

static const char *ccs_number_patternize(const char *cp)
{
	int i;
	struct ccs_number_entry entry;
	if (ccs_parse_number(cp, &entry))
		return cp;
	for (i = 1; i < ccs_pattern_list_len; i++) {
		const int type = ccs_pattern_list[i].type;
		if (type != 3)
			continue;
		if (ccs_pattern_list[i].number.min > entry.min ||
		    ccs_pattern_list[i].number.max < entry.max)
			continue;
		return ccs_pattern_list[i].group_name;
	}
	return cp;
}

static const char *ccs_address_patternize(const char *cp)
{
	int i;
	struct ccs_ip_address_entry entry;
	if (ccs_parse_ip(cp, &entry))
		return cp;
	for (i = 1; i < ccs_pattern_list_len; i++) {
		const int type = ccs_pattern_list[i].type;
		if (type != 4)
			continue;
		if (ccs_pattern_list[i].ip.is_ipv6 != entry.is_ipv6 ||
		    memcmp(entry.min, ccs_pattern_list[i].ip.min, 16) < 0 ||
		    memcmp(ccs_pattern_list[i].ip.max, entry.max, 16) < 0)
			continue;
		return ccs_pattern_list[i].group_name;
	}
	return cp;
}

int main(int argc, char *argv[])
{
	int i;
	_Bool need_free = 0;
	if (argc == 3 && !strcmp(argv[1], "--file")) {
		FILE *fp = fopen(argv[2], "r");
		argv = NULL;
		argc = 0;
		ccs_get();
		while (fp) {
			char *line = ccs_freadline(fp);
			if (!line)
				break;
			ccs_normalize_line(line);
			if (ccs_str_starts(line, "file_pattern ") ||
			    ccs_str_starts(line, "path_group") ||
			    ccs_str_starts(line, "number_group") ||
			    ccs_correct_word(line)) {
				char *cp = strdup(line);
				argv = realloc(argv,
					       (argc + 1) * sizeof(char *));
				if (!argv || !cp)
					ccs_out_of_memory();
				argv[argc++] = cp;
			}
		}
		ccs_put();
		if (fp)
			fclose(fp);
		need_free = 1;
	}
	ccs_pattern_list_len = argc;
	ccs_pattern_list = calloc(argc, sizeof(struct ccs_path_pattern_entry));
	if (!ccs_pattern_list)
		ccs_out_of_memory();
	for (i = 0; i < argc; i++) {
		ccs_normalize_line(argv[i]);
		if (ccs_str_starts(argv[i], "file_pattern ")) {
			if (!ccs_correct_word(argv[i]))
				continue;
			ccs_pattern_list[i].path.name = argv[i];
			ccs_pattern_list[i].type = 1;
		} else if (ccs_str_starts(argv[i], "path_group")) {
			char *cp = strchr(argv[i] + 1, ' ');
			if (!cp)
				continue;
			*cp = '\0';
			if (argv[i][0] != ' ' ||
			    !ccs_correct_word(argv[i] + 1) ||
			    !ccs_correct_word(cp + 1))
				continue;
			argv[i][0] = '@';
			ccs_pattern_list[i].group_name = argv[i];
			ccs_pattern_list[i].path.name = cp + 1;
			ccs_pattern_list[i].type = 2;
		} else if (ccs_str_starts(argv[i], "number_group")) {
			char *cp = strchr(argv[i] + 1, ' ');
			if (!cp)
				continue;
			*cp = '\0';
			if (argv[i][0] != ' ' ||
			    !ccs_correct_word(argv[i] + 1) ||
			    ccs_parse_number(cp + 1, &ccs_pattern_list[i].number))
				continue;
			argv[i][0] = '@';
			ccs_pattern_list[i].group_name = argv[i];
			ccs_pattern_list[i].type = 3;
		} else if (ccs_str_starts(argv[i], "address_group")) {
			char *cp = strchr(argv[i] + 1, ' ');
			if (!cp)
				continue;
			*cp = '\0';
			if (argv[i][0] != ' ' ||
			    !ccs_correct_word(argv[i] + 1) ||
			    ccs_parse_ip(cp + 1, &ccs_pattern_list[i].ip))
				continue;
			argv[i][0] = '@';
			ccs_pattern_list[i].group_name = argv[i];
			ccs_pattern_list[i].type = 4;
		} else if (ccs_correct_word(argv[i])) {
			ccs_pattern_list[i].path.name = argv[i];
			ccs_pattern_list[i].type = 1;
		}
		if (ccs_pattern_list[i].path.name)
			ccs_fill_path_info(&ccs_pattern_list[i].path);
	}
	ccs_get();
	while (true) {
		char *sp = ccs_freadline(stdin);
		const char *cp;
		_Bool first = true;
		u8 path_count = 0;
		u8 number_count = 0;
		u8 address_count = 0;
		u8 skip_count = 0;
		if (!sp)
			break;
		while (true) {
			cp = strsep(&sp, " ");
			if (!cp)
				break;
			if (first) {
				if (!strcmp(cp, "network")) {
					cp = strsep(&sp, " ");
					if (!cp)
						break;
					if (strstr(cp, "unix")) {
						path_count = 1;
					} else if (strstr(cp, "inet")) {
						address_count = 1;
						number_count = 1;
					} else {
						break;
					}
					skip_count = 1;
				} else if (!strcmp(cp, "file")) {
					printf("file ");
					cp = strsep(&sp, " ");
					if (!cp)
						break;
					if (strstr(cp, "execute")  ||
					    strstr(cp, "read")     ||
					    strstr(cp, "write")    ||
					    strstr(cp, "append")   ||
					    strstr(cp, "unlink")   ||
					    strstr(cp, "rmdir")    ||
					    strstr(cp, "truncate") ||
					    strstr(cp, "symlink")  ||
					    strstr(cp, "chroot")   ||
					    strstr(cp, "unmount")) {
						path_count = 1;
					} else if (strstr(cp, "link")   ||
						   strstr(cp, "rename") ||
						   strstr(cp, "pivot_root")) {
						path_count = 2;
					} else if (strstr(cp, "create") ||
						   strstr(cp, "mkdir")  ||
						   strstr(cp, "mkfifo") ||
						   strstr(cp, "mksock") ||
						   strstr(cp, "ioctl")  ||
						   strstr(cp, "chmod")  ||
						   strstr(cp, "chown")  ||
						   strstr(cp, "chgrp")) {
						path_count = 1;
						number_count = 1;
					} else if (strstr(cp, "mkblock") ||
						   strstr(cp, "mkchar")) {
						path_count = 1;
						number_count = 3;
					} else if (!strcmp(cp, "mount")) {
						path_count = 3;
						number_count = 1;
					}
				}
			} else if (skip_count) {
				skip_count--;
			} else if (path_count) {
				if (path_count-- && *cp != '@' &&
				    !ccs_path_contains_pattern(cp))
					cp = ccs_path_patternize(cp);
			} else if (address_count) {
				if (address_count-- && *cp != '@')
					cp = ccs_address_patternize(cp);
			} else if (number_count) {
				if (number_count-- && *cp != '@')
					cp = ccs_number_patternize(cp);
			}
			if (!first)
				putchar(' ');
			first = false;
			printf("%s", cp);
		}
		putchar('\n');
	}
	ccs_put();
	free(ccs_pattern_list);
	if (need_free) {
		while (argc)
			free(argv[--argc]);
		free(argv);
	}
	return 0;
}
