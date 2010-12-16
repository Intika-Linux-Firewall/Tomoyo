/*
 * ccs-patternize.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0+   2010/12/16
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

#define CCS_PATTERNIZE_CONF "/etc/ccs/tools/patternize.conf"

enum ccs_pattern_type {
	CCS_PATTERN_FILE_PATTERN,
	CCS_PATTERN_HEAD_PATTERN,
	CCS_PATTERN_TAIL_PATTERN,
	CCS_PATTERN_PATH_GROUP,
	CCS_PATTERN_NUMBER_GROUP,
	CCS_PATTERN_ADDRESS_GROUP,
};

struct ccs_patternize_entry {
	const char *group_name;
	struct ccs_path_info path;
	struct ccs_number_entry number;
	struct ccs_ip_address_entry ip;
	enum ccs_pattern_type type;
};

static struct ccs_patternize_entry *rules = NULL;
static int rules_len = 0;

static void ccs_path_patternize(char *string)
{
	int i;
	struct ccs_path_info word;
	word.name = string;
	ccs_fill_path_info(&word);
	for (i = 0; i < rules_len; i++) {
		struct ccs_path_info *path = &rules[i].path;
		struct ccs_path_info subword;
		char *pos;
		switch (rules[i].type) {
		case CCS_PATTERN_HEAD_PATTERN:
			subword.name = string;
			for (pos = strrchr(string, '/'); pos >= string;
			     pos--) {
				char c;
				if (*pos != '/')
					continue;
				c = *(pos + 1);
				*(pos + 1) = '\0';
				ccs_fill_path_info(&subword);
				if (ccs_path_matches_pattern(&subword, path)) {
					printf("%s", path->name);
					if (c)
						printf("%c%s", c, pos + 2);
					*(pos + 1) = c;
					return;
				}
				*(pos + 1) = c;
			}
			continue;
		case CCS_PATTERN_TAIL_PATTERN:
			for (pos = string; *pos; pos++) {
				if (*pos != '/')
					continue;
				subword.name = pos;
				ccs_fill_path_info(&subword);
				if (ccs_path_matches_pattern(&subword, path)) {
					*pos = '\0';
					printf("%s%s", string, path->name);
					*pos = '/';
					return;
				}
			}
			continue;
		case CCS_PATTERN_FILE_PATTERN:
			if (!ccs_path_matches_pattern(&word, path))
				continue;
			printf("%s", rules[i].path.name);
			return;
		case CCS_PATTERN_PATH_GROUP:
			if (!ccs_path_matches_pattern(&word, path))
				continue;
			printf("%s", rules[i].group_name);
			return;
		default:
			break;
		}
	}
	printf("%s", string);
}

static void ccs_number_patternize(const char *cp)
{
	int i;
	struct ccs_number_entry entry;
	if (!ccs_parse_number(cp, &entry))
		goto out;
	for (i = 0; i < rules_len; i++) {
		if (rules[i].type != CCS_PATTERN_NUMBER_GROUP)
			continue;
		if (rules[i].number.min > entry.min ||
		    rules[i].number.max < entry.max)
			continue;
		cp = rules[i].group_name;
		break;
	}
out:
	printf("%s", cp);
}

static void ccs_address_patternize(const char *cp)
{
	int i;
	struct ccs_ip_address_entry entry;
	if (ccs_parse_ip(cp, &entry))
		goto out;
	for (i = 0; i < rules_len; i++) {
		if (rules[i].type != CCS_PATTERN_ADDRESS_GROUP)
			continue;
		if (rules[i].ip.is_ipv6 != entry.is_ipv6 ||
		    memcmp(entry.min, rules[i].ip.min, 16) < 0 ||
		    memcmp(rules[i].ip.max, entry.max, 16) < 0)
			continue;
		cp = rules[i].group_name;
		break;
	}
out:
	printf("%s", cp);
}

static void ccs_patternize_init_rules(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	unsigned int line_no = 0;
	if (!fp) {
		fprintf(stderr, "Can't open %s for reading.\n", filename);
		exit(1);
	}
	ccs_get();
	while (true) {
		struct ccs_patternize_entry *ptr;
		char *line = ccs_freadline(fp);
		if (!line)
			break;
		line_no++;
		ccs_normalize_line(line);
		line = strdup(line);
		if (!line)
			ccs_out_of_memory();
		rules = realloc(rules, (rules_len + 1) * sizeof(*ptr));
		if (!rules)
			ccs_out_of_memory();
		ptr = &rules[rules_len++];
		memset(ptr, 0, sizeof(*ptr));
		if (ccs_str_starts(line, "file_pattern ")) {
			if (!ccs_correct_word(line))
				goto invalid_pattern;
			ptr->path.name = line;
			ptr->type = CCS_PATTERN_FILE_PATTERN;
		} else if (ccs_str_starts(line, "head_pattern ")) {
			if (!ccs_correct_word(line))
				goto invalid_pattern;
			ptr->path.name = line;
			ptr->type = CCS_PATTERN_HEAD_PATTERN;
		} else if (ccs_str_starts(line, "tail_pattern ")) {
			if (!ccs_correct_word(line))
				goto invalid_pattern;
			ptr->path.name = line;
			ptr->type = CCS_PATTERN_TAIL_PATTERN;
		} else if (ccs_str_starts(line, "path_group")) {
			char *cp = strchr(line + 1, ' ');
			if (!cp)
				goto invalid_pattern;
			*cp++ = '\0';
			if (*line != ' ' || !ccs_correct_word(line + 1) ||
			    !ccs_correct_word(cp))
				goto invalid_pattern;
			*line = '@';
			ptr->group_name = line;
			ptr->path.name = cp;
			ptr->type = CCS_PATTERN_PATH_GROUP;
		} else if (ccs_str_starts(line, "number_group")) {
			char *cp = strchr(line + 1, ' ');
			if (!cp)
				goto invalid_pattern;
			*cp++ = '\0';
			if (*line != ' ' || !ccs_correct_word(line + 1) ||
			    ccs_parse_number(cp, &ptr->number))
				goto invalid_pattern;
			*line = '@';
			ptr->group_name = line;
			ptr->type = CCS_PATTERN_NUMBER_GROUP;
		} else if (ccs_str_starts(line, "address_group")) {
			char *cp = strchr(line + 1, ' ');
			if (!cp)
				goto invalid_pattern;
			*cp++ = '\0';
			if (*line != ' ' || !ccs_correct_word(line + 1) ||
			    ccs_parse_ip(cp, &ptr->ip))
				goto invalid_pattern;
			*line = '@';
			ptr->group_name = line;
			ptr->type = CCS_PATTERN_ADDRESS_GROUP;
		}
		if (ptr->path.name)
			ccs_fill_path_info(&ptr->path);
	}
	ccs_put();
	fclose(fp);
	if (!rules_len) {
		fprintf(stderr, "No patterns defined in %s .\n", filename);
		exit(1);
	}
	return;
invalid_pattern:
	fprintf(stderr, "Invalid pattern at line %u in %s .\n", line_no,
		filename);
	exit(1);
}

int main(int argc, char *argv[])
{
	ccs_patternize_init_rules(argc == 2 ? argv[2] : CCS_PATTERNIZE_CONF);
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
					printf("network ");
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
					skip_count = 2;
				} else if (!strcmp(cp, "file")) {
					printf("file ");
					cp = strsep(&sp, " ");
					if (!cp)
						break;
					if (strstr(cp, "execute")  ||
					    strstr(cp, "read")     ||
					    strstr(cp, "getattr")  ||
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
				printf("%s", cp);
				first = false;
				continue;
			}
			putchar(' ');
			if (skip_count) {
				skip_count--;
			} else if (path_count) {
				if (path_count-- && *cp != '@' &&
				    !ccs_path_contains_pattern(cp)) {
					ccs_path_patternize((char *) cp);
					cp = "";
				}
			} else if (address_count) {
				if (address_count-- && *cp != '@') {
					ccs_address_patternize(cp);
					cp = "";
				}
			} else if (number_count) {
				if (number_count-- && *cp != '@') {
					ccs_number_patternize(cp);
					cp = "";
				}
			}
			printf("%s", cp);
		}
		putchar('\n');
	}
	ccs_put();
	return 0;
}
