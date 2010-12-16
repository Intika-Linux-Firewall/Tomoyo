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

enum ccs_target_types {
	CCS_TARGET_DOMAIN,
	CCS_TARGET_ACL,
};

enum ccs_operator_types {
	CCS_TARGET_CONTAINS,
	CCS_TARGET_EQUALS,
	CCS_TARGET_STARTS,
};

struct ccs_preconditions {
	enum ccs_target_types type;
	enum ccs_operator_types operation;
	unsigned int index;
	const char *string;
	unsigned int string_len; /* strlen(string). */
};

enum ccs_pattern_type {
	CCS_PATTERN_PATH_PATTERN,
	CCS_PATTERN_HEAD_PATTERN,
	CCS_PATTERN_TAIL_PATTERN,
	CCS_PATTERN_NUMBER_PATTERN,
	CCS_PATTERN_ADDRESS_PATTERN,
};

struct ccs_replace_rules {
	enum ccs_pattern_type type;
	const char *new_value;
	union {
		struct ccs_path_info path;
		struct ccs_number_entry number;
		struct ccs_ip_address_entry ip;
	} old;
	struct ccs_preconditions *rules;
	unsigned int rules_len;
};

static struct ccs_replace_rules *ccs_rules_list = NULL;
static unsigned int ccs_rules_list_len = 0;

static char *ccs_current_domainname = NULL;
static char *ccs_current_acl = NULL;

static _Bool ccs_check_preconditions(const struct ccs_replace_rules *entry)
{
	unsigned int i;
	_Bool matched = true;
	for (i = 0; matched && i < entry->rules_len; i++) {
		const struct ccs_preconditions *ptr = &entry->rules[i];
		char *line;
		unsigned int index = ptr->index;
		const char *find = ptr->string;
		unsigned int find_len = ptr->string_len;
		if (ptr->type == CCS_TARGET_DOMAIN)
			line = ccs_current_domainname;
		else /* CCS_TARGET_ACL */
			line = ccs_current_acl;
		if (!index) {
			switch (ptr->operation) {
			case CCS_TARGET_CONTAINS:
				while (1) {
					char *cp = strstr(line, find);
					if (!cp) {
						matched = false;
						break;
					}
					if ((cp == line || *(cp - 1) == ' ') &&
					    (!cp[find_len] ||
					     cp[find_len] == ' '))
						break;
					line = cp + 1;
				}
				break;
			case CCS_TARGET_EQUALS:
				matched = !strcmp(line, find);
				break;
			default: /* CCS_TARGET_STARTS */
				matched = !strncmp(line, find, find_len) &&
					(!line[find_len] ||
					 line[find_len] == ' ');
			}
		} else {
			char *word = line;
			char *word_end;
			while (--index) {
				char *cp = strchr(word, ' ');
				if (!cp) {
					matched = false;
					break;
				}
				word = cp + 1;
			}
			if (!matched)
				break;
			word_end = strchr(word, ' ');
			if (word_end)
				*word_end = '\0';
			switch (ptr->operation) {
			case CCS_TARGET_CONTAINS:
				matched = strstr(word, find) != NULL;
				break;
			case CCS_TARGET_EQUALS:
				matched = !strcmp(word, find);
				break;
			default: /* CCS_TARGET_STARTS */
				matched = !strncmp(word, find, find_len);
				break;
			}
			if (word_end)
				*word_end = ' ';
		}
	}
	return matched;
}

static _Bool ccs_head_patternize(char *string,
				 const struct ccs_replace_rules *ptr)
{
	char *pos;
	struct ccs_path_info subword;
	subword.name = string;
	for (pos = strrchr(string, '/'); pos >= string; pos--) {
		char c;
		if (*pos != '/')
			continue;
		c = *(pos + 1);
		*(pos + 1) = '\0';
		ccs_fill_path_info(&subword);
		if (!ccs_path_matches_pattern(&subword, &ptr->old.path) ||
		    !ccs_check_preconditions(ptr)) {
			*(pos + 1) = c;
			continue;
		}
		printf("%s", ptr->new_value);
		if (c)
			printf("%c%s", c, pos + 2);
		*(pos + 1) = c;
		return true;
	}
	return false;
}

static _Bool ccs_tail_patternize(char *string,
				 const struct ccs_replace_rules *ptr)
{
	char *pos;
	struct ccs_path_info subword;
	for (pos = string; *pos; pos++) {
		if (*pos != '/')
			continue;
		subword.name = pos;
		ccs_fill_path_info(&subword);
		if (!ccs_path_matches_pattern(&subword, &ptr->old.path) ||
		    !ccs_check_preconditions(ptr))
			continue;
		*pos = '\0';
		printf("%s%s", string, ptr->new_value);
		*pos = '/';
		return true;
	}
	return false;
}

static void ccs_path_patternize(char *string)
{
	_Bool first = true;
	int i;
	struct ccs_path_info word;
	for (i = 0; i < ccs_rules_list_len; i++) {
		const struct ccs_replace_rules *ptr = &ccs_rules_list[i];
		if (ptr->type == CCS_PATTERN_PATH_PATTERN) {
			if (first) {
				word.name = string;
				ccs_fill_path_info(&word);
				first = false;
			}
			if (!ccs_path_matches_pattern(&word, &ptr->old.path) ||
			    !ccs_check_preconditions(ptr))
				continue;
			printf("%s", ptr->new_value);
			return;
		} else if (ptr->type == CCS_PATTERN_HEAD_PATTERN) {
			if (ccs_head_patternize(string, ptr))
				return;
		} else if (ptr->type == CCS_PATTERN_TAIL_PATTERN) {
			if (ccs_tail_patternize(string, ptr))
				return;
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
	for (i = 0; i < ccs_rules_list_len; i++) {
		const struct ccs_replace_rules *ptr = &ccs_rules_list[i];
		if (ptr->type != CCS_PATTERN_NUMBER_PATTERN)
			continue;
		if (ptr->old.number.min > entry.min ||
		    ptr->old.number.max < entry.max ||
		    !ccs_check_preconditions(ptr))
			continue;
		cp = ptr->new_value;
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
	for (i = 0; i < ccs_rules_list_len; i++) {
		const struct ccs_replace_rules *ptr = &ccs_rules_list[i];
		if (ptr->type != CCS_PATTERN_ADDRESS_PATTERN)
			continue;
		if (ptr->old.ip.is_ipv6 != entry.is_ipv6 ||
		    memcmp(entry.min, ptr->old.ip.min, 16) < 0 ||
		    memcmp(ptr->old.ip.max, entry.max, 16) < 0 ||
		    !ccs_check_preconditions(ptr))
			continue;
		cp = ptr->new_value;
		break;
	}
out:
	printf("%s", cp);
}

static void ccs_patternize_init_rules(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	struct ccs_replace_rules entry = { };
	unsigned int line_no = 0;
	if (!fp) {
		fprintf(stderr, "Can't open %s for reading.\n", filename);
		exit(1);
	}
	ccs_get();
	while (true) {
		char *line = ccs_freadline(fp);
		unsigned char c;
		char *cp;
		if (!line)
			break;
		line_no++;
		ccs_normalize_line(line);
		if (*line == '#' || !*line)
			continue;
		if (ccs_str_starts(line, "path_pattern "))
			entry.type = CCS_PATTERN_PATH_PATTERN;
		else if (ccs_str_starts(line, "head_pattern "))
			entry.type = CCS_PATTERN_HEAD_PATTERN;
		else if (ccs_str_starts(line, "tail_pattern "))
			entry.type = CCS_PATTERN_TAIL_PATTERN;
		else if (ccs_str_starts(line, "number_pattern "))
			entry.type = CCS_PATTERN_NUMBER_PATTERN;
		else if (ccs_str_starts(line, "address_pattern "))
			entry.type = CCS_PATTERN_ADDRESS_PATTERN;
		else {
			struct ccs_preconditions *ptr;
			entry.rules = realloc(entry.rules,
					      (entry.rules_len + 1) *
					      sizeof(*ptr));
			if (!entry.rules)
				ccs_out_of_memory();
			ptr = &entry.rules[entry.rules_len++];
			memset(ptr, 0, sizeof(*ptr));
			if (ccs_str_starts(line, "domain"))
				ptr->type = CCS_TARGET_DOMAIN;
			else if (ccs_str_starts(line, "acl"))
				ptr->type = CCS_TARGET_ACL;
			else
				goto invalid_rule;
			switch (sscanf(line, "[%u%c", &ptr->index, &c)) {
			case 0:
				break;
			case 2:
				if (c == ']') {
					char *cp = strchr(line, ']') + 1;
					memmove(line, cp, strlen(cp) + 1);
					break;
				}
			default:
				goto invalid_rule;
			}
			if (ccs_str_starts(line, ".contains "))
				ptr->operation = CCS_TARGET_CONTAINS;
			else if (ccs_str_starts(line, ".equals "))
				ptr->operation = CCS_TARGET_EQUALS;
			else if (ccs_str_starts(line, ".starts "))
				ptr->operation = CCS_TARGET_STARTS;
			else
				goto invalid_rule;
			if (!*line)
				goto invalid_rule;
			line = strdup(line);
			if (!line)
				ccs_out_of_memory();
			ptr->string = line;
			ptr->string_len = strlen(line);
			continue;
		}
		line = strdup(line);
		if (!line)
			ccs_out_of_memory();
		cp = strchr(line, ' ');
		if (cp)
			*cp++ = '\0';
		else
			cp = line;
		if (!ccs_correct_word(line) ||
		    (line != cp && !ccs_correct_word(cp)))
			goto invalid_rule;
		entry.new_value = cp;
		entry.old.path.name = line;
		ccs_fill_path_info(&entry.old.path);
		if (entry.type == CCS_PATTERN_NUMBER_PATTERN) {
			struct ccs_number_entry dummy;
			if (ccs_parse_number(line, &entry.old.number))
				goto invalid_rule;
			if (line != cp && *cp != '@' &&
			    ccs_parse_number(cp, &dummy))
				goto invalid_rule;
		} else if (entry.type == CCS_PATTERN_ADDRESS_PATTERN) {
			struct ccs_ip_address_entry dummy;
			if (ccs_parse_ip(line, &entry.old.ip))
				goto invalid_rule;
			if (line != cp && *cp != '@' &&
			    ccs_parse_ip(cp, &dummy))
				goto invalid_rule;
		}
		ccs_rules_list = realloc(ccs_rules_list,
					  (ccs_rules_list_len + 1) *
					  sizeof(entry));
		if (!ccs_rules_list)
			ccs_out_of_memory();
		ccs_rules_list[ccs_rules_list_len++] = entry;
		memset(&entry, 0, sizeof(entry));
	}
	ccs_put();
	fclose(fp);
	if (!ccs_rules_list_len) {
		fprintf(stderr, "No rules defined in %s .\n", filename);
		exit(1);
	}
	return;
invalid_rule:
	fprintf(stderr, "Invalid rule at line %u in %s .\n", line_no,
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
		if (!strncmp(sp, "<kernel>", 8) && (!sp[8] || sp[8] == ' ')) {
			free(ccs_current_domainname);
			ccs_current_domainname = strdup(sp);
			printf("%s\n", sp);
			continue;
		}
		free(ccs_current_acl);
		ccs_current_acl = strdup(sp);
		if (!ccs_current_domainname || !ccs_current_acl) {
			/* Continue without conversion. */
			printf("%s\n", sp);
			continue;
		}
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
