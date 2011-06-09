/*
 * tomoyo-patternize.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0-pre   2011/06/09
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

/*
 * Check whether the given filename is patterened.
 * Returns nonzero if patterned, zero otherwise.
 */
static _Bool tomoyo_path_contains_pattern(const char *filename)
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

#define TOMOYO_PATTERNIZE_CONF "/etc/tomoyo/tools/patternize.conf"

enum tomoyo_target_types {
	TOMOYO_TARGET_DOMAIN,
	TOMOYO_TARGET_ACL,
	TOMOYO_REWRITE_PATH,
	TOMOYO_REWRITE_HEAD,
	TOMOYO_REWRITE_TAIL,
	TOMOYO_REWRITE_NUMBER,
	TOMOYO_REWRITE_ADDRESS,
};

enum tomoyo_operator_types {
	TOMOYO_TARGET_CONTAINS,
	TOMOYO_TARGET_EQUALS,
	TOMOYO_TARGET_STARTS,
};

struct tomoyo_replace_rules {
	enum tomoyo_target_types type;
	union {
		/* Used by TOMOYO_TARGET_{DOMAIN,ACL} */
		struct {
			enum tomoyo_operator_types operation;
			unsigned int index;
		} cond;
		/* Used by TOMOYO_REWRITE_NUMBER */
		struct tomoyo_number_entry number;
		/* Used by TOMOYO_REWRITE_ADDRESS */
		struct tomoyo_ip_address_entry ip;
		/* Used by TOMOYO_REWRITE_{PATH,HEAD,TAIL} */
		struct tomoyo_path_info path;
	} u;
	const char *string;
	unsigned int string_len; /* strlen(string). */
};

static struct tomoyo_replace_rules *rules = NULL;
static unsigned int rules_len = 0;

static char *tomoyo_current_domainname = NULL;
static char *tomoyo_current_acl = NULL;

static _Bool tomoyo_head_pattern(char *string,
			      const struct tomoyo_replace_rules *ptr)
{
	char *pos;
	struct tomoyo_path_info subword;
	subword.name = string;
	for (pos = strrchr(string, '/'); pos >= string; pos--) {
		_Bool matched;
		char c;
		if (*pos != '/')
			continue;
		c = *(pos + 1);
		*(pos + 1) = '\0';
		tomoyo_fill_path_info(&subword);
		matched = tomoyo_path_matches_pattern(&subword, &ptr->u.path);
		*(pos + 1) = c;
		if (!matched)
			continue;
		printf("%s%s", ptr->string, pos + 1);
		return true;
	}
	return false;
}

static _Bool tomoyo_tail_pattern(const char *string,
			      const struct tomoyo_replace_rules *ptr)
{
	const char *pos;
	struct tomoyo_path_info subword;
	int ret_ignored;
	for (pos = string; *pos; pos++) {
		if (*pos != '/')
			continue;
		subword.name = pos;
		tomoyo_fill_path_info(&subword);
		if (!tomoyo_path_matches_pattern(&subword, &ptr->u.path))
			continue;
		ret_ignored = fwrite(string, 1, pos - string, stdout);
		printf("%s", ptr->string);
		return true;
	}
	return false;
}

static _Bool tomoyo_path_pattern(const char *string,
			      const struct tomoyo_replace_rules *ptr)
{
	struct tomoyo_path_info word;
	word.name = string;
	tomoyo_fill_path_info(&word);
	if (tomoyo_path_matches_pattern(&word, &ptr->u.path)) {
		printf("%s", ptr->string);
		return true;
	}
	return false;
}

static _Bool tomoyo_number_pattern(const char *string,
				const struct tomoyo_replace_rules *ptr)
{
	struct tomoyo_number_entry entry;
	if (!tomoyo_parse_number(string, &entry) &&
	    ptr->u.number.min <= entry.min && ptr->u.number.max >= entry.max) {
		printf("%s", ptr->string);
		return true;
	}
	return false;
}

static _Bool tomoyo_address_pattern(const char *string,
				 const struct tomoyo_replace_rules *ptr)
{
	struct tomoyo_ip_address_entry entry;
	if (!tomoyo_parse_ip(string, &entry) && ptr->u.ip.is_ipv6 == entry.is_ipv6
	    && memcmp(entry.min, ptr->u.ip.min, 16) >= 0 &&
	    memcmp(ptr->u.ip.max, entry.max, 16) >= 0) {
		printf("%s", ptr->string);
		return true;
	}
	return false;
}

static _Bool tomoyo_check_rule(char *string, const enum tomoyo_target_types type)
{
	unsigned int i;
	_Bool matched = true;
	if (*string == '@')
		return false;
	for (i = 0; i < rules_len; i++) {
		const struct tomoyo_replace_rules *ptr = &rules[i];
		char *line = NULL;
		unsigned int index = ptr->u.cond.index;
		const char *find = ptr->string;
		unsigned int find_len = ptr->string_len;
		switch (ptr->type) {
		case TOMOYO_TARGET_DOMAIN:
			line = tomoyo_current_domainname;
			break;
		case TOMOYO_TARGET_ACL:
			line = tomoyo_current_acl;
			break;
		case TOMOYO_REWRITE_PATH:
			if (type == TOMOYO_REWRITE_PATH && matched &&
			    tomoyo_path_pattern(string, ptr))
				return true;
			matched = true;
			continue;
		case TOMOYO_REWRITE_HEAD:
			if (type == TOMOYO_REWRITE_PATH && matched &&
			    tomoyo_head_pattern(string, ptr))
				return true;
			matched = true;
			continue;
		case TOMOYO_REWRITE_TAIL:
			if (type == TOMOYO_REWRITE_PATH && matched &&
			    tomoyo_tail_pattern(string, ptr))
				return true;
			matched = true;
			continue;
		case TOMOYO_REWRITE_NUMBER:
			if (type == TOMOYO_REWRITE_NUMBER && matched &&
			    tomoyo_number_pattern(string, ptr))
				return true;
			matched = true;
			continue;
		case TOMOYO_REWRITE_ADDRESS:
			if (type == TOMOYO_REWRITE_ADDRESS && matched &&
			    tomoyo_address_pattern(string, ptr))
				return true;
			matched = true;
			continue;
		}
		if (!matched || !line)
			continue;
		if (!index) {
			switch (ptr->u.cond.operation) {
			case TOMOYO_TARGET_CONTAINS:
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
			case TOMOYO_TARGET_EQUALS:
				matched = !strcmp(line, find);
				break;
			case TOMOYO_TARGET_STARTS:
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
			switch (ptr->u.cond.operation) {
			case TOMOYO_TARGET_CONTAINS:
				matched = strstr(word, find) != NULL;
				break;
			case TOMOYO_TARGET_EQUALS:
				matched = !strcmp(word, find);
				break;
			case TOMOYO_TARGET_STARTS:
				matched = !strncmp(word, find, find_len);
				break;
			}
			if (word_end)
				*word_end = ' ';
		}
	}
	return false;
}

static void tomoyo_patternize_init_rules(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	unsigned int line_no = 0;
	if (!fp) {
		fprintf(stderr, "Can't open %s for reading.\n", filename);
		exit(1);
	}
	tomoyo_get();
	while (true) {
		struct tomoyo_replace_rules *ptr;
		char *line = tomoyo_freadline(fp);
		if (!line)
			break;
		line_no++;
		tomoyo_normalize_line(line);
		if (*line == '#' || !*line)
			continue;
		rules = tomoyo_realloc(rules, (rules_len + 1) * sizeof(*ptr));
		ptr = &rules[rules_len++];
		memset(ptr, 0, sizeof(*ptr));
		if (tomoyo_str_starts(line, "rewrite ")) {
			char *cp = strchr(line, ' ');
			if (!cp)
				goto invalid_rule;
			cp = strchr(cp + 1, ' ');
			if (cp)
				*cp++ = '\0';
			if (tomoyo_str_starts(line, "path_pattern ")) {
				ptr->type = TOMOYO_REWRITE_PATH;
			} else if (tomoyo_str_starts(line, "head_pattern ")) {
				ptr->type = TOMOYO_REWRITE_HEAD;
				if (!*line || line[strlen(line) - 1] != '/')
					goto invalid_rule;
			} else if (tomoyo_str_starts(line, "tail_pattern ")) {
				ptr->type = TOMOYO_REWRITE_TAIL;
				if (*line != '/')
					goto invalid_rule;
			} else if (tomoyo_str_starts(line, "number_pattern ")) {
				if (tomoyo_parse_number(line, &ptr->u.number))
					goto invalid_rule;
				ptr->type = TOMOYO_REWRITE_NUMBER;
			} else if (tomoyo_str_starts(line, "address_pattern ")) {
				if (tomoyo_parse_ip(line, &ptr->u.ip))
					goto invalid_rule;
				ptr->type = TOMOYO_REWRITE_ADDRESS;
			} else {
				goto invalid_rule;
			}
			if (ptr->type != TOMOYO_REWRITE_NUMBER &&
			    ptr->type != TOMOYO_REWRITE_ADDRESS) {
				if (!*line)
					goto invalid_rule;
				if (!tomoyo_correct_word(line))
					goto invalid_rule;
				line = tomoyo_strdup(line);
				ptr->u.path.name = line;
				tomoyo_fill_path_info(&ptr->u.path);
			}
			if (cp)
				line = cp;
			if (!tomoyo_correct_word(line))
				goto invalid_rule;
		} else {
			unsigned char c;
			if (tomoyo_str_starts(line, "domain"))
				ptr->type = TOMOYO_TARGET_DOMAIN;
			else if (tomoyo_str_starts(line, "acl"))
				ptr->type = TOMOYO_TARGET_ACL;
			else
				goto invalid_rule;
			switch (sscanf(line, "[%u%c", &ptr->u.cond.index,
				       &c)) {
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
			if (tomoyo_str_starts(line, ".contains "))
				ptr->u.cond.operation = TOMOYO_TARGET_CONTAINS;
			else if (tomoyo_str_starts(line, ".equals "))
				ptr->u.cond.operation = TOMOYO_TARGET_EQUALS;
			else if (tomoyo_str_starts(line, ".starts "))
				ptr->u.cond.operation = TOMOYO_TARGET_STARTS;
			else
				goto invalid_rule;
		}
		if (!*line)
			goto invalid_rule;
		line = tomoyo_strdup(line);
		ptr->string = line;
		ptr->string_len = strlen(line);
	}
	tomoyo_put();
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

static void tomoyo_process_line(char *sp)
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
			if (!tomoyo_path_contains_pattern(cp) &&
			    tomoyo_check_rule(cp, TOMOYO_REWRITE_PATH))
				continue;
		} else if (address_count) {
			address_count--;
			if (tomoyo_check_rule(cp, TOMOYO_REWRITE_ADDRESS))
				continue;
		} else if (number_count) {
			number_count--;
			if (tomoyo_check_rule(cp, TOMOYO_REWRITE_NUMBER))
				continue;
		}
		printf("%s", cp);
	}
	putchar('\n');
}

int main(int argc, char *argv[])
{
	tomoyo_patternize_init_rules(argc == 2 ? argv[1] : TOMOYO_PATTERNIZE_CONF);
	tomoyo_get();
	while (true) {
		char *sp = tomoyo_freadline_unpack(stdin);
		if (!sp)
			break;
		if (tomoyo_domain_def(sp)) {
			free(tomoyo_current_domainname);
			tomoyo_current_domainname = strdup(sp);
			printf("%s\n", sp);
			continue;
		}
		free(tomoyo_current_acl);
		tomoyo_current_acl = strdup(sp);
		if (!tomoyo_current_domainname || !tomoyo_current_acl) {
			/* Continue without conversion. */
			printf("%s\n", sp);
			continue;
		}
		tomoyo_process_line(sp);
	}
	tomoyo_put();
	return 0;
}
