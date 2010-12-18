/*
 * ccs-patternize.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0+   2010/12/18
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
	CCS_PATH,
	CCS_HEAD,
	CCS_TAIL,
	CCS_NUMBER,
	CCS_ADDRESS,
	CCS_REWRITE,
};

enum ccs_operator_types {
	CCS_TARGET_CONTAINS,
	CCS_TARGET_EQUALS,
	CCS_TARGET_STARTS,
};

struct ccs_replace_rules {
	enum ccs_target_types type;
	union {
		/* Used by CCS_TARGET_DOMAIN and CCS_TARGET_ACL */
		struct {
			enum ccs_operator_types operation;
			unsigned int index;
			const char *string;
			unsigned int string_len; /* strlen(string). */
		} c;
		/* Used by CCS_NUMBER */
		struct ccs_number_entry number;
		/* Used by CCS_ADDRESS */
		struct ccs_ip_address_entry ip;
		/* Used by other values */
		struct ccs_path_info path;
	} u;
};

static struct ccs_replace_rules *rules = NULL;
static unsigned int rules_len = 0;

static char *ccs_current_domainname = NULL;
static char *ccs_current_acl = NULL;

static unsigned int ccs_matched_prefix_len = 0;
static const char *ccs_matched_suffix = "";

static _Bool ccs_head_pattern(char *string,
			      const struct ccs_replace_rules *ptr)
{
	char *pos;
	struct ccs_path_info subword;
	subword.name = string;
	for (pos = strrchr(string, '/'); pos >= string; pos--) {
		_Bool matched;
		char c;
		if (*pos != '/')
			continue;
		c = *(pos + 1);
		*(pos + 1) = '\0';
		ccs_fill_path_info(&subword);
		matched = ccs_path_matches_pattern(&subword, &ptr->u.path);
		*(pos + 1) = c;
		if (!matched)
			continue;
		ccs_matched_prefix_len = 0;
		ccs_matched_suffix = pos + 1;
		return true;
	}
	return false;
}

static _Bool ccs_tail_pattern(const char *string,
			      const struct ccs_replace_rules *ptr)
{
	const char *pos;
	struct ccs_path_info subword;
	for (pos = string; *pos; pos++) {
		if (*pos != '/')
			continue;
		subword.name = pos;
		ccs_fill_path_info(&subword);
		if (!ccs_path_matches_pattern(&subword, &ptr->u.path))
			continue;
		ccs_matched_prefix_len = pos - string;
		ccs_matched_suffix = "";
		return true;
	}
	return false;
}

static _Bool ccs_path_pattern(const char *string,
			      const struct ccs_replace_rules *ptr)
{
	struct ccs_path_info word;
	word.name = string;
	ccs_fill_path_info(&word);
	if (ccs_path_matches_pattern(&word, &ptr->u.path)) {
		ccs_matched_prefix_len = 0;
		ccs_matched_suffix = "";
		return true;
	}
	return false;
}

static _Bool ccs_number_pattern(const char *string,
				const struct ccs_replace_rules *ptr)
{
	struct ccs_number_entry entry;
	if (!ccs_parse_number(string, &entry) &&
	    ptr->u.number.min <= entry.min && ptr->u.number.max >= entry.max) {
		ccs_matched_prefix_len = 0;
		ccs_matched_suffix = "";
		return true;
	}
	return false;
}

static _Bool ccs_address_pattern(const char *string,
				 const struct ccs_replace_rules *ptr)
{
	struct ccs_ip_address_entry entry;
	if (!ccs_parse_ip(string, &entry) && ptr->u.ip.is_ipv6 == entry.is_ipv6
	    && memcmp(entry.min, ptr->u.ip.min, 16) >= 0 &&
	    memcmp(ptr->u.ip.max, entry.max, 16) >= 0) {
		ccs_matched_prefix_len = 0;
		ccs_matched_suffix = "";
		return true;
	}
	return false;
}

static _Bool ccs_check_rule(char *string, const enum ccs_target_types type)
{
	unsigned int i;
	_Bool matched = true;
	if (*string == '@')
		return false;
	for (i = 0; i < rules_len; i++) {
		const struct ccs_replace_rules *ptr = &rules[i];
		char *line = NULL;
		unsigned int index = ptr->u.c.index;
		const char *find = ptr->u.c.string;
		unsigned int find_len = ptr->u.c.string_len;
		switch (ptr->type) {
		case CCS_TARGET_DOMAIN:
			line = ccs_current_domainname;
			break;
		case CCS_TARGET_ACL:
			line = ccs_current_acl;
			break;
		case CCS_PATH:
			if (type == CCS_PATH && matched)
				matched = ccs_path_pattern(string, ptr);
			else
				matched = false;
			break;
		case CCS_HEAD:
			if (type == CCS_PATH && matched)
				matched = ccs_head_pattern(string, ptr);
			else
				matched = false;
			break;
		case CCS_TAIL:
			if (type == CCS_PATH && matched)
				matched = ccs_tail_pattern(string, ptr);
			else
				matched = false;
			break;
		case CCS_NUMBER:
			if (type == CCS_NUMBER && matched)
				matched = ccs_number_pattern(string, ptr);
			else
				matched = false;
			break;
		case CCS_ADDRESS:
			if (type == CCS_ADDRESS && matched)
				matched = ccs_address_pattern(string, ptr);
			else
				matched = false;
			break;
		case CCS_REWRITE:
			if (matched) {
				fwrite(string, 1, ccs_matched_prefix_len,
				       stdout);
				printf("%s%s", ptr->u.path.name,
				       ccs_matched_suffix);
				return true;
			}
			matched = true;
			continue;
		}
		if (!matched || !line)
			continue;
		if (!index) {
			switch (ptr->u.c.operation) {
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
			case CCS_TARGET_STARTS:
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
				continue;
			word_end = strchr(word, ' ');
			if (word_end)
				*word_end = '\0';
			switch (ptr->u.c.operation) {
			case CCS_TARGET_CONTAINS:
				matched = strstr(word, find) != NULL;
				break;
			case CCS_TARGET_EQUALS:
				matched = !strcmp(word, find);
				break;
			case CCS_TARGET_STARTS:
				matched = !strncmp(word, find, find_len);
				break;
			}
			if (word_end)
				*word_end = ' ';
		}
	}
	return false;
}

static void ccs_patternize_init_rules(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	unsigned int line_no = 0;
	char *last_pattern = NULL;
	if (!fp) {
		fprintf(stderr, "Can't open %s for reading.\n", filename);
		exit(1);
	}
	ccs_get();
	while (true) {
		struct ccs_replace_rules *ptr;
		char *line = ccs_freadline(fp);
		if (!line)
			break;
		line_no++;
		ccs_normalize_line(line);
		if (*line == '#' || !*line)
			continue;
		rules = realloc(rules, (rules_len + 1) * sizeof(*ptr));
		if (!rules)
			ccs_out_of_memory();
		ptr = &rules[rules_len++];
		memset(ptr, 0, sizeof(*ptr));
		if (ccs_str_starts(line, "rewrite ")) {
			ptr->type = CCS_REWRITE;
			line = strdup(line);
			if (!line)
				ccs_out_of_memory();
		} else if (!strcmp(line, "rewrite")) {
			ptr->type = CCS_REWRITE;
			line = last_pattern;
		} else if (ccs_str_starts(line, "path_pattern ")) {
			ptr->type = CCS_PATH;
		} else if (ccs_str_starts(line, "head_pattern ")) {
			ptr->type = CCS_HEAD;
			if (!*line || line[strlen(line) - 1] != '/')
				goto invalid_rule;
		} else if (ccs_str_starts(line, "tail_pattern ")) {
			ptr->type = CCS_TAIL;
			if (*line != '/')
				goto invalid_rule;
		} else if (ccs_str_starts(line, "number_pattern ")) {
			if (ccs_parse_number(line, &ptr->u.number))
				goto invalid_rule;
			ptr->type = CCS_NUMBER;
		} else if (ccs_str_starts(line, "address_pattern ")) {
			if (ccs_parse_ip(line, &ptr->u.ip))
				goto invalid_rule;
			ptr->type = CCS_ADDRESS;
		} else {
			unsigned char c;
			if (ccs_str_starts(line, "domain"))
				ptr->type = CCS_TARGET_DOMAIN;
			else if (ccs_str_starts(line, "acl"))
				ptr->type = CCS_TARGET_ACL;
			else
				goto invalid_rule;
			switch (sscanf(line, "[%u%c", &ptr->u.c.index, &c)) {
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
				ptr->u.c.operation = CCS_TARGET_CONTAINS;
			else if (ccs_str_starts(line, ".equals "))
				ptr->u.c.operation = CCS_TARGET_EQUALS;
			else if (ccs_str_starts(line, ".starts "))
				ptr->u.c.operation = CCS_TARGET_STARTS;
			else
				goto invalid_rule;
			if (!*line)
				goto invalid_rule;
			line = strdup(line);
			if (!line)
				ccs_out_of_memory();
			ptr->u.c.string = line;
			ptr->u.c.string_len = strlen(line);
			continue;
		}
		if (!line || !*line)
			goto invalid_rule;
		if (!ccs_correct_word(line))
			goto invalid_rule;
		if (ptr->type != CCS_REWRITE) {
			if (last_pattern)
				goto invalid_rule;
			line = strdup(line);
			if (!line)
				ccs_out_of_memory();
			last_pattern = line;
		} else {
			if (!last_pattern)
				goto invalid_rule;
			/* Do not free(last_pattern) here. */
			last_pattern = NULL;
		}
		if (ptr->type != CCS_NUMBER && ptr->type != CCS_ADDRESS) {
			ptr->u.path.name = line;
			ccs_fill_path_info(&ptr->u.path);
		}
	}
	ccs_put();
	fclose(fp);
	if (!rules_len) {
		fprintf(stderr, "No rules defined in %s .\n", filename);
		exit(1);
	}
	return;
invalid_rule:
	fprintf(stderr, "Invalid rule at line %u in %s .\n", line_no,
		filename);
	exit(1);
}

static void ccs_process_line(char *sp)
{
	char *cp;
	_Bool first = true;
	u8 path_count = 0;
	u8 number_count = 0;
	u8 address_count = 0;
	u8 skip_count = 0;
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
			path_count--;
			if (!ccs_path_contains_pattern(cp) &&
			    ccs_check_rule(cp, CCS_PATH))
				continue;
		} else if (address_count) {
			address_count--;
			if (ccs_check_rule(cp, CCS_ADDRESS))
				continue;
		} else if (number_count) {
			number_count--;
			if (ccs_check_rule(cp, CCS_NUMBER))
				continue;
		}
		printf("%s", cp);
	}
	putchar('\n');
}

int main(int argc, char *argv[])
{
	ccs_patternize_init_rules(argc == 2 ? argv[2] : CCS_PATTERNIZE_CONF);
	ccs_get();
	while (true) {
		char *sp = ccs_freadline(stdin);
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
		ccs_process_line(sp);
	}
	ccs_put();
	return 0;
}
