/*
 * tomoyo-patternize.c
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

#define CCS_PATTERNIZE_CONF "/etc/tomoyo/tools/patternize.conf"

enum ccs_target_types {
	CCS_TARGET_DOMAIN,
	CCS_TARGET_ACL,
	CCS_REWRITE_PATH,
	CCS_REWRITE_HEAD,
	CCS_REWRITE_TAIL,
	CCS_REWRITE_NUMBER,
};

enum ccs_operator_types {
	CCS_TARGET_CONTAINS,
	CCS_TARGET_EQUALS,
	CCS_TARGET_STARTS,
};

struct ccs_replace_rules {
	enum ccs_target_types type;
	union {
		/* Used by CCS_TARGET_{DOMAIN,ACL} */
		struct {
			enum ccs_operator_types operation;
			unsigned int index;
		} cond;
		/* Used by CCS_REWRITE_NUMBER */
		struct ccs_number_entry number;
		/* Used by CCS_REWRITE_{PATH,HEAD,TAIL} */
		struct ccs_path_info path;
	} u;
	const char *string;
	unsigned int string_len; /* strlen(string). */
};

static struct ccs_replace_rules *rules = NULL;
static unsigned int rules_len = 0;

static char *ccs_current_domainname = NULL;
static char *ccs_current_acl = NULL;

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
		printf("%s%s", ptr->string, pos + 1);
		return true;
	}
	return false;
}

static _Bool ccs_tail_pattern(const char *string,
			      const struct ccs_replace_rules *ptr)
{
	const char *pos;
	struct ccs_path_info subword;
	int ret_ignored;
	for (pos = string; *pos; pos++) {
		if (*pos != '/')
			continue;
		subword.name = pos;
		ccs_fill_path_info(&subword);
		if (!ccs_path_matches_pattern(&subword, &ptr->u.path))
			continue;
		ret_ignored = fwrite(string, 1, pos - string, stdout);
		printf("%s", ptr->string);
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
		printf("%s", ptr->string);
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
		printf("%s", ptr->string);
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
		unsigned int index = ptr->u.cond.index;
		const char *find = ptr->string;
		unsigned int find_len = ptr->string_len;
		switch (ptr->type) {
		case CCS_TARGET_DOMAIN:
			line = ccs_current_domainname;
			break;
		case CCS_TARGET_ACL:
			line = ccs_current_acl;
			break;
		case CCS_REWRITE_PATH:
			if (type == CCS_REWRITE_PATH && matched &&
			    ccs_path_pattern(string, ptr))
				return true;
			matched = true;
			continue;
		case CCS_REWRITE_HEAD:
			if (type == CCS_REWRITE_PATH && matched &&
			    ccs_head_pattern(string, ptr))
				return true;
			matched = true;
			continue;
		case CCS_REWRITE_TAIL:
			if (type == CCS_REWRITE_PATH && matched &&
			    ccs_tail_pattern(string, ptr))
				return true;
			matched = true;
			continue;
		case CCS_REWRITE_NUMBER:
			if (type == CCS_REWRITE_NUMBER && matched &&
			    ccs_number_pattern(string, ptr))
				return true;
			matched = true;
			continue;
		}
		if (!matched || !line)
			continue;
		if (!index) {
			switch (ptr->u.cond.operation) {
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
			switch (ptr->u.cond.operation) {
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
		rules = ccs_realloc(rules, (rules_len + 1) * sizeof(*ptr));
		ptr = &rules[rules_len++];
		memset(ptr, 0, sizeof(*ptr));
		if (ccs_str_starts(line, "rewrite ")) {
			char *cp = strchr(line, ' ');
			if (!cp)
				goto invalid_rule;
			cp = strchr(cp + 1, ' ');
			if (cp)
				*cp++ = '\0';
			if (ccs_str_starts(line, "path_pattern ")) {
				ptr->type = CCS_REWRITE_PATH;
			} else if (ccs_str_starts(line, "head_pattern ")) {
				ptr->type = CCS_REWRITE_HEAD;
				if (!*line || line[strlen(line) - 1] != '/')
					goto invalid_rule;
			} else if (ccs_str_starts(line, "tail_pattern ")) {
				ptr->type = CCS_REWRITE_TAIL;
				if (*line != '/')
					goto invalid_rule;
			} else if (ccs_str_starts(line, "number_pattern ")) {
				if (ccs_parse_number(line, &ptr->u.number))
					goto invalid_rule;
				ptr->type = CCS_REWRITE_NUMBER;
			} else {
				goto invalid_rule;
			}
			if (ptr->type != CCS_REWRITE_NUMBER) {
				if (!*line)
					goto invalid_rule;
				if (!ccs_correct_word(line))
					goto invalid_rule;
				line = ccs_strdup(line);
				ptr->u.path.name = line;
				ccs_fill_path_info(&ptr->u.path);
			}
			if (cp)
				line = cp;
			if (!ccs_correct_word(line))
				goto invalid_rule;
		} else {
			unsigned char c;
			if (ccs_str_starts(line, "domain"))
				ptr->type = CCS_TARGET_DOMAIN;
			else if (ccs_str_starts(line, "acl"))
				ptr->type = CCS_TARGET_ACL;
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
			if (ccs_str_starts(line, ".contains "))
				ptr->u.cond.operation = CCS_TARGET_CONTAINS;
			else if (ccs_str_starts(line, ".equals "))
				ptr->u.cond.operation = CCS_TARGET_EQUALS;
			else if (ccs_str_starts(line, ".starts "))
				ptr->u.cond.operation = CCS_TARGET_STARTS;
			else
				goto invalid_rule;
		}
		if (!*line)
			goto invalid_rule;
		line = ccs_strdup(line);
		ptr->string = line;
		ptr->string_len = strlen(line);
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
	u8 skip_count = 0;
	while (true) {
		cp = strsep(&sp, " ");
		if (!cp)
			break;
		if (first) {
			if (!strcmp(cp, "file")) {
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
			    ccs_check_rule(cp, CCS_REWRITE_PATH))
				continue;
		} else if (number_count) {
			number_count--;
			if (ccs_check_rule(cp, CCS_REWRITE_NUMBER))
				continue;
		}
		printf("%s", cp);
	}
	putchar('\n');
}

int main(int argc, char *argv[])
{
	ccs_patternize_init_rules(argc == 2 ? argv[1] : CCS_PATTERNIZE_CONF);
	ccs_get();
	while (true) {
		char *sp = ccs_freadline_unpack(stdin);
		if (!sp)
			break;
		if (ccs_domain_def(sp)) {
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
