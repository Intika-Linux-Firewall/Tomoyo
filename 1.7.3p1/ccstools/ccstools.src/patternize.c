/*
 * patternize.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include "ccstools.h"

/*
 * Check whether the given filename is patterened.
 * Returns nonzero if patterned, zero otherwise.
 */
static _Bool path_contains_pattern(const char *filename)
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
				if (c != '0' || d != '0' || e != '0')
					continue; /* pattern is not \000 */
			}
			return true;
		}
	}
	return false;
}

struct path_pattern_entry {
	const char *group_name;
	struct path_info path;
	struct number_entry number;
	struct ip_address_entry ip;
	int type;
};

static struct path_pattern_entry *pattern_list = NULL;
static int pattern_list_len = 0;

static const char *path_patternize(const char *cp)
{
	int i;
	struct path_info cp2;
	cp2.name = cp;
	fill_path_info(&cp2);
	for (i = 1; i < pattern_list_len; i++) {
		const int type = pattern_list[i].type;
		if (type != 1 && type != 2)
			continue;
		if (!path_matches_pattern(&cp2, &pattern_list[i].path))
			continue;
		if (type == 2)
			return pattern_list[i].group_name;
		return pattern_list[i].path.name;
	}
	return cp;
}

static const char *number_patternize(const char *cp)
{
	int i;
	struct number_entry entry;
	if (parse_number(cp, &entry))
		return cp;
	for (i = 1; i < pattern_list_len; i++) {
		const int type = pattern_list[i].type;
		if (type != 3)
			continue;
		if (pattern_list[i].number.min > entry.min ||
		    pattern_list[i].number.max < entry.max)
			continue;
		return pattern_list[i].group_name;
	}
	return cp;
}

static const char *address_patternize(const char *cp)
{
	int i;
	struct ip_address_entry entry;
	if (parse_ip(cp, &entry))
		return cp;
	for (i = 1; i < pattern_list_len; i++) {
		const int type = pattern_list[i].type;
		if (type != 4)
			continue;
		if (pattern_list[i].ip.is_ipv6 != entry.is_ipv6 ||
		    memcmp(entry.min, pattern_list[i].ip.min, 16) < 0 ||
		    memcmp(pattern_list[i].ip.max, entry.max, 16) < 0)
			continue;
		return pattern_list[i].group_name;
	}
	return cp;
}

int patternize_main(int argc, char *argv[])
{
	int i;
	_Bool need_free = 0;
	if (argc == 3 && !strcmp(argv[1], "--file")) {
		FILE *fp = fopen(argv[2], "r");
		argv = NULL;
		argc = 0;
		get();
		while (fp) {
			char *line = freadline(fp);
			if (!line)
				break;
			normalize_line(line);
			if (str_starts(line, "file_pattern ") ||
			    str_starts(line, "path_group") ||
			    str_starts(line, "number_group") ||
			    is_correct_path(line, 0, 1, 0)) {
				char *cp = strdup(line);
				argv = realloc(argv,
					       (argc + 1) * sizeof(char *));
				if (!argv || !cp)
					out_of_memory();
				argv[argc++] = cp;
			}
		}
		put();
		if (fp)
			fclose(fp);
		need_free = 1;
	}
	pattern_list_len = argc;
	pattern_list = calloc(argc, sizeof(struct path_pattern_entry));
	if (!pattern_list)
		out_of_memory();
	for (i = 0; i < argc; i++) {
		normalize_line(argv[i]);
		if (str_starts(argv[i], "file_pattern ")) {
			if (!is_correct_path(argv[i], 0, 1, 0))
				continue;
			pattern_list[i].path.name = argv[i];
			pattern_list[i].type = 1;
		} else if (str_starts(argv[i], "path_group")) {
			char *cp = strchr(argv[i] + 1, ' ');
			if (!cp)
				continue;
			*cp = '\0';
			if (argv[i][0] != ' ' ||
			    !is_correct_path(argv[i] + 1, 0, 0, 0) ||
			    !is_correct_path(cp + 1, 0, 0, 0))
				continue;
			argv[i][0] = '@';
			pattern_list[i].group_name = argv[i];
			pattern_list[i].path.name = cp + 1;
			pattern_list[i].type = 2;
		} else if (str_starts(argv[i], "number_group")) {
			char *cp = strchr(argv[i] + 1, ' ');
			if (!cp)
				continue;
			*cp = '\0';
			if (argv[i][0] != ' ' ||
			    !is_correct_path(argv[i] + 1, 0, 0, 0) ||
			    parse_number(cp + 1, &pattern_list[i].number))
				continue;
			argv[i][0] = '@';
			pattern_list[i].group_name = argv[i];
			pattern_list[i].type = 3;
		} else if (str_starts(argv[i], "address_group")) {
			char *cp = strchr(argv[i] + 1, ' ');
			if (!cp)
				continue;
			*cp = '\0';
			if (argv[i][0] != ' ' ||
			    !is_correct_path(argv[i] + 1, 0, 0, 0) ||
			    parse_ip(cp + 1, &pattern_list[i].ip))
				continue;
			argv[i][0] = '@';
			pattern_list[i].group_name = argv[i];
			pattern_list[i].type = 4;
		} else if (is_correct_path(argv[i], 0, 1, 0)) {
			pattern_list[i].path.name = argv[i];
			pattern_list[i].type = 1;
		}
		if (pattern_list[i].path.name)
			fill_path_info(&pattern_list[i].path);
	}
	get();
	while (true) {
		char *sp = freadline(stdin);
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
				if (!strcmp(cp, "allow_read") ||
				    !strcmp(cp, "allow_write") ||
				    !strcmp(cp, "allow_read/write") ||
				    !strcmp(cp, "allow_unlink") ||
				    !strcmp(cp, "allow_rmdir") ||
				    !strcmp(cp, "allow_truncate") ||
				    !strcmp(cp, "allow_symlink") ||
				    !strcmp(cp, "allow_rewrite") ||
				    !strcmp(cp, "allow_chroot") ||
				    !strcmp(cp, "allow_unmount")) {
					path_count = 1;
				} else if (!strcmp(cp, "allow_link") ||
					   !strcmp(cp, "allow_rename") ||
					   !strcmp(cp, "allow_pivot_root")) {
					path_count = 2;
				} else if (!strcmp(cp, "allow_create") ||
					   !strcmp(cp, "allow_mkdir") ||
					   !strcmp(cp, "allow_mkfifo") ||
					   !strcmp(cp, "allow_mksock") ||
					   !strcmp(cp, "allow_ioctl") ||
					   !strcmp(cp, "allow_chmod") ||
					   !strcmp(cp, "allow_chown") ||
					   !strcmp(cp, "allow_chgrp")) {
					path_count = 1;
					number_count = 1;
				} else if (!strcmp(cp, "allow_mkblock") ||
					   !strcmp(cp, "allow_mkchar")) {
					path_count = 1;
					number_count = 3;
				} else if (!strcmp(cp, "allow_mount")) {
					path_count = 3;
					number_count = 1;
				} else if (!strcmp(cp, "allow_network")) {
					skip_count = 2;
					address_count = 1;
					number_count = 1;
				}
			} else if (skip_count) {
				skip_count--;
			} else if (path_count) {
				if (path_count-- && *cp != '@' &&
				    !path_contains_pattern(cp))
					cp = path_patternize(cp);
			} else if (address_count) {
				if (address_count-- && *cp != '@')
					cp = address_patternize(cp);
			} else if (number_count) {
				if (number_count-- && *cp != '@')
					cp = number_patternize(cp);
			}
			if (!first)
				putchar(' ');
			first = false;
			printf("%s", cp);
		}
		putchar('\n');
	}
	put();
	free(pattern_list);
	if (need_free) {
		while (argc)
			free(argv[--argc]);
		free(argv);
	}
	return 0;
}
