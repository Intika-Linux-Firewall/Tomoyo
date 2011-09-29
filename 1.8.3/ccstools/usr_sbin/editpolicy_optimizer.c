/*
 * editpolicy_optimizer.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
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
#include "editpolicy.h"

struct ccs_address_group_entry {
	const struct ccs_path_info *group_name;
	struct ccs_ip_address_entry *member_name;
	int member_name_len;
};

struct ccs_number_group_entry {
	const struct ccs_path_info *group_name;
	struct ccs_number_entry *member_name;
	int member_name_len;
};

/* Array of "address_group" entry. */
static struct ccs_address_group_entry *ccs_address_group_list = NULL;
/* Length of ccs_address_group_list array. */
static int ccs_address_group_list_len = 0;
/* Array of "number_group" entry. */
static struct ccs_number_group_entry *ccs_number_group_list = NULL;
/* Length of ccs_number_group_list array. */
static int ccs_number_group_list_len = 0;

static _Bool ccs_compare_address(const char *sarg, const char *darg);
static _Bool ccs_compare_number(const char *sarg, const char *darg);
static _Bool ccs_compare_path(const char *sarg, const char *darg);
static int ccs_add_address_group_entry(const char *group_name,
				       const char *member_name,
				       const _Bool is_delete);
static int ccs_add_number_group_entry(const char *group_name,
				      const char *member_name,
				      const _Bool is_delete);
static struct ccs_address_group_entry *ccs_find_address_group
(const char *group_name);
static struct ccs_number_group_entry *ccs_find_number_group
(const char *group_name);

/**
 * ccs_find_path_group_ns - Find "path_group" entry.
 *
 * @ns:         Pointer to "const struct ccs_path_info".
 * @group_name: Name of path group.
 *
 * Returns pointer to "struct ccs_path_group_entry" if found, NULL otherwise.
 */
struct ccs_path_group_entry *ccs_find_path_group_ns
(const struct ccs_path_info *ns, const char *group_name)
{
	int i;
	for (i = 0; i < ccs_path_group_list_len; i++) {
		if (!ccs_pathcmp(ccs_path_group_list[i].ns, ns) &&
		    !strcmp(group_name,
			    ccs_path_group_list[i].group_name->name))
			return &ccs_path_group_list[i];
	}
	return NULL;
}

/**
 * ccs_add_address_group_policy - Add "address_group" entry.
 *
 * @data:      Line to parse.
 * @is_delete: True if it is delete request, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_add_address_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return ccs_add_address_group_entry(data, cp, is_delete);
}

/**
 * ccs_compare_path - Compare two pathnames.
 *
 * @sarg: First pathname. Maybe wildcard.
 * @darg: Second pathname.
 *
 * Returns true if @darg is included in @sarg, false otherwise.
 */
static _Bool ccs_compare_path(const char *sarg, const char *darg)
{
	int i;
	struct ccs_path_group_entry *group;
	struct ccs_path_info s;
	struct ccs_path_info d;
	s.name = sarg;
	d.name = darg;
	ccs_fill_path_info(&s);
	ccs_fill_path_info(&d);
	if (!ccs_pathcmp(&s, &d))
		return true;
	if (d.name[0] == '@')
		return false;
	if (s.name[0] != '@')
		/* Pathname component. */
		return ccs_path_matches_pattern(&d, &s);
	/* path_group component. */
	group = ccs_find_path_group_ns(ccs_current_ns, s.name + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		const struct ccs_path_info *member_name;
		member_name = group->member_name[i];
		if (!ccs_pathcmp(member_name, &d))
			return true;
		if (ccs_path_matches_pattern(&d, member_name))
			return true;
	}
	return false;
}

/**
 * ccs_compare_address - Compare two IPv4/v6 addresses.
 *
 * @sarg: First address.
 * @darg: Second address.
 *
 * Returns true if @darg is included in @sarg, false otherwise.
 */
static _Bool ccs_compare_address(const char *sarg, const char *darg)
{
	int i;
	struct ccs_ip_address_entry sentry;
	struct ccs_ip_address_entry dentry;
	struct ccs_address_group_entry *group;
	if (ccs_parse_ip(darg, &dentry))
		return false;
	if (sarg[0] != '@') {
		/* IP address component. */
		if (ccs_parse_ip(sarg, &sentry))
			return false;
		if (sentry.is_ipv6 != dentry.is_ipv6 ||
		    memcmp(dentry.min, sentry.min, 16) < 0 ||
		    memcmp(sentry.max, dentry.max, 16) < 0)
			return false;
		return true;
	}
	/* IP address group component. */
	group = ccs_find_address_group(sarg + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		struct ccs_ip_address_entry *sentry = &group->member_name[i];
		if (sentry->is_ipv6 == dentry.is_ipv6
		    && memcmp(sentry->min, dentry.min, 16) <= 0
		    && memcmp(dentry.max, sentry->max, 16) <= 0)
			return true;
	}
	return false;
}

/**
 * ccs_tokenize - Tokenize a line.
 *
 * @buffer: Line to tokenize.
 * @w:      A "char *" array with 5 elements.
 * @index:  One of values in "enum ccs_editpolicy_directives".
 *
 * Returns nothing.
 */
static void ccs_tokenize(char *buffer, char *w[5],
			 enum ccs_editpolicy_directives index)
{
	u8 i;
	u8 words;
	switch (index) {
	case CCS_DIRECTIVE_FILE_MKBLOCK:
	case CCS_DIRECTIVE_FILE_MKCHAR:
	case CCS_DIRECTIVE_FILE_MOUNT:
	case CCS_DIRECTIVE_NETWORK_INET:
		words = 4;
		break;
	case CCS_DIRECTIVE_NETWORK_UNIX:
		words = 3;
		break;
	case CCS_DIRECTIVE_FILE_CREATE:
	case CCS_DIRECTIVE_FILE_MKDIR:
	case CCS_DIRECTIVE_FILE_MKFIFO:
	case CCS_DIRECTIVE_FILE_MKSOCK:
	case CCS_DIRECTIVE_FILE_IOCTL:
	case CCS_DIRECTIVE_FILE_CHMOD:
	case CCS_DIRECTIVE_FILE_CHOWN:
	case CCS_DIRECTIVE_FILE_CHGRP:
	case CCS_DIRECTIVE_FILE_LINK:
	case CCS_DIRECTIVE_FILE_RENAME:
	case CCS_DIRECTIVE_FILE_PIVOT_ROOT:
	case CCS_DIRECTIVE_IPC_SIGNAL:
		words = 2;
		break;
	case CCS_DIRECTIVE_FILE_EXECUTE:
	case CCS_DIRECTIVE_FILE_READ:
	case CCS_DIRECTIVE_FILE_WRITE:
	case CCS_DIRECTIVE_FILE_UNLINK:
	case CCS_DIRECTIVE_FILE_GETATTR:
	case CCS_DIRECTIVE_FILE_RMDIR:
	case CCS_DIRECTIVE_FILE_TRUNCATE:
	case CCS_DIRECTIVE_FILE_APPEND:
	case CCS_DIRECTIVE_FILE_UNMOUNT:
	case CCS_DIRECTIVE_FILE_CHROOT:
	case CCS_DIRECTIVE_FILE_SYMLINK:
	case CCS_DIRECTIVE_MISC_ENV:
		words = 1;
		break;
	default:
		words = 0;
		break;
	}
	for (i = 0; i < 5; i++)
		w[i] = "";
	for (i = 0; i < words; i++) {
		char *cp = strchr(buffer, ' ');
		w[i] = buffer;
		if (!cp)
			return;
		if (index == CCS_DIRECTIVE_IPC_SIGNAL && i == 1 &&
		    ccs_domain_def(buffer)) {
			cp = strchr(buffer, ' ');
			if (!cp)
				return;
			while (*cp) {
				if (*cp++ != ' ' || *cp++ == '/')
					continue;
				cp -= 2;
				break;
			}
			if (!*cp)
				return;
		}
		*cp = '\0';
		buffer = cp + 1;
	}
	w[4] = buffer;
}

/**
 * ccs_add_number_group_policy - Add "number_group" entry.
 *
 * @data:      Line to parse.
 * @is_delete: True if it is delete request, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_add_number_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return ccs_add_number_group_entry(data, cp, is_delete);
}

/**
 * ccs_compare_number - Compare two numeric values.
 *
 * @sarg: First number.
 * @darg: Second number.
 *
 * Returns true if @darg is included in @sarg, false otherwise.
 */
static _Bool ccs_compare_number(const char *sarg, const char *darg)
{
	int i;
	struct ccs_number_entry sentry;
	struct ccs_number_entry dentry;
	struct ccs_number_group_entry *group;
	if (ccs_parse_number(darg, &dentry))
		return false;
	if (sarg[0] != '@') {
		/* Number component. */
		if (ccs_parse_number(sarg, &sentry))
			return false;
		if (sentry.min > dentry.min || sentry.max < dentry.max)
			return false;
		return true;
	}
	/* Number group component. */
	group = ccs_find_number_group(sarg + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		struct ccs_number_entry *entry = &group->member_name[i];
		if (entry->min > dentry.min || entry->max < dentry.max)
			continue;
		return true;
	}
	return false;
}

/**
 * ccs_editpolicy_optimize - Try to merge entries included in other entries.
 *
 * @current: Index in the domain policy.
 *
 * Returns nothing.
 */
void ccs_editpolicy_optimize(const int current)
{
	char *cp;
	const bool is_exception_list =
		ccs_current_screen == CCS_SCREEN_EXCEPTION_LIST;
	enum ccs_editpolicy_directives s_index;
	enum ccs_editpolicy_directives s_index2;
	int index;
	char *s[5];
	char *d[5];
	if (current < 0)
		return;
	s_index = ccs_gacl_list[current].directive;
	if (s_index == CCS_DIRECTIVE_NONE)
		return;
	/* Allow acl_group lines to be optimized. */
	if (is_exception_list &&
	    (s_index < CCS_DIRECTIVE_ACL_GROUP_000 ||
	     s_index > CCS_DIRECTIVE_ACL_GROUP_255))
		return;
	cp = strdup(ccs_gacl_list[current].operand);
	if (!cp)
		return;
	s_index2 = s_index;
	if (is_exception_list)
		s_index = ccs_find_directive(true, cp);
	ccs_tokenize(cp, s, s_index);
	ccs_get();
	for (index = 0; index < ccs_list_item_count; index++) {
		char *line;
		enum ccs_editpolicy_directives d_index =
			ccs_gacl_list[index].directive;
		enum ccs_editpolicy_directives d_index2;
		if (index == current)
			/* Skip source. */
			continue;
		if (ccs_gacl_list[index].selected)
			/* Dest already selected. */
			continue;
		else if (s_index == s_index2 && s_index != d_index)
			/* Source and dest have different directive. */
			continue;
		else if (is_exception_list && s_index2 != d_index)
			/* Source and dest have different directive. */
			continue;
		/* Source and dest have same directive. */
		line = ccs_shprintf("%s", ccs_gacl_list[index].operand);
		d_index2 = d_index;
		if (is_exception_list)
			d_index = ccs_find_directive(true, line);
		if (s_index != d_index || s_index2 != d_index2)
			/* Source and dest have different directive. */
			continue;
		ccs_tokenize(line, d, d_index);
		/* Compare condition part. */
		if (strcmp(s[4], d[4]))
			continue;
		/* Compare non condition word. */
		if (0) {
			FILE *fp = fopen("/tmp/log", "a+");
			int i;
			for (i = 0; i < 5; i++) {
				fprintf(fp, "s[%d]='%s'\n", i, s[i]);
				fprintf(fp, "d[%d]='%s'\n", i, d[i]);
			}
			fclose(fp);
		}
		switch (d_index) {
			struct ccs_path_info sarg;
			struct ccs_path_info darg;
			char c;
			int len;
		case CCS_DIRECTIVE_FILE_MKBLOCK:
		case CCS_DIRECTIVE_FILE_MKCHAR:
			if (!ccs_compare_number(s[3], d[3]) ||
			    !ccs_compare_number(s[2], d[2]))
				continue;
			/* fall through */
		case CCS_DIRECTIVE_FILE_CREATE:
		case CCS_DIRECTIVE_FILE_MKDIR:
		case CCS_DIRECTIVE_FILE_MKFIFO:
		case CCS_DIRECTIVE_FILE_MKSOCK:
		case CCS_DIRECTIVE_FILE_IOCTL:
		case CCS_DIRECTIVE_FILE_CHMOD:
		case CCS_DIRECTIVE_FILE_CHOWN:
		case CCS_DIRECTIVE_FILE_CHGRP:
			if (!ccs_compare_number(s[1], d[1]))
				continue;
			/* fall through */
		case CCS_DIRECTIVE_FILE_EXECUTE:
		case CCS_DIRECTIVE_FILE_READ:
		case CCS_DIRECTIVE_FILE_WRITE:
		case CCS_DIRECTIVE_FILE_UNLINK:
		case CCS_DIRECTIVE_FILE_GETATTR:
		case CCS_DIRECTIVE_FILE_RMDIR:
		case CCS_DIRECTIVE_FILE_TRUNCATE:
		case CCS_DIRECTIVE_FILE_APPEND:
		case CCS_DIRECTIVE_FILE_UNMOUNT:
		case CCS_DIRECTIVE_FILE_CHROOT:
		case CCS_DIRECTIVE_FILE_SYMLINK:
			if (!ccs_compare_path(s[0], d[0]))
				continue;
			break;
		case CCS_DIRECTIVE_FILE_MOUNT:
			if (!ccs_compare_number(s[3], d[3]) ||
			    !ccs_compare_path(s[2], d[2]))
				continue;
			/* fall through */
		case CCS_DIRECTIVE_FILE_LINK:
		case CCS_DIRECTIVE_FILE_RENAME:
		case CCS_DIRECTIVE_FILE_PIVOT_ROOT:
			if (!ccs_compare_path(s[1], d[1]) ||
			    !ccs_compare_path(s[0], d[0]))
				continue;
			break;
		case CCS_DIRECTIVE_IPC_SIGNAL:
			/* Signal number component. */
			if (strcmp(s[0], d[0]))
				continue;
			/* Domainname component. */
			len = strlen(s[1]);
			if (strncmp(s[1], d[1], len))
				continue;
			c = d[1][len];
			if (c && c != ' ')
				continue;
			break;
		case CCS_DIRECTIVE_NETWORK_INET:
			if (strcmp(s[0], d[0]) || strcmp(s[1], d[1]) ||
			    !ccs_compare_address(s[2], d[2]) ||
			    !ccs_compare_number(s[3], d[3]))
				continue;
			break;
		case CCS_DIRECTIVE_NETWORK_UNIX:
			if (strcmp(s[0], d[0]) || strcmp(s[1], d[1]) ||
			    !ccs_compare_path(s[2], d[2]))
				continue;
			break;
		case CCS_DIRECTIVE_MISC_ENV:
			/* An environemnt variable name component. */
			sarg.name = s[0];
			ccs_fill_path_info(&sarg);
			darg.name = d[0];
			ccs_fill_path_info(&darg);
			if (!ccs_pathcmp(&sarg, &darg))
				break;
			/* "misc env" doesn't interpret leading @ as
			   path_group. */
			if (darg.is_patterned ||
			    !ccs_path_matches_pattern(&darg, &sarg))
				continue;
			break;
		default:
			continue;
		}
		ccs_gacl_list[index].selected = 1;
	}
	ccs_put();
	free(cp);
}

/**
 * ccs_add_address_group_entry - Add "address_group" entry.
 *
 * @group_name:  Name of address group.
 * @member_name: Address string.
 * @is_delete:   True if it is delete request, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_add_address_group_entry(const char *group_name,
				       const char *member_name,
				       const _Bool is_delete)
{
	const struct ccs_path_info *saved_group_name;
	int i;
	int j;
	struct ccs_ip_address_entry entry;
	struct ccs_address_group_entry *group = NULL;
	if (ccs_parse_ip(member_name, &entry))
		return -EINVAL;
	if (!ccs_correct_word(group_name))
		return -EINVAL;
	saved_group_name = ccs_savename(group_name);
	for (i = 0; i < ccs_address_group_list_len; i++) {
		group = &ccs_address_group_list[i];
		if (saved_group_name != group->group_name)
			continue;
		for (j = 0; j < group->member_name_len; j++) {
			if (memcmp(&group->member_name[j], &entry,
				   sizeof(entry)))
				continue;
			if (!is_delete)
				return 0;
			while (j < group->member_name_len - 1)
				group->member_name[j]
					= group->member_name[j + 1];
			group->member_name_len--;
			return 0;
		}
		break;
	}
	if (is_delete)
		return -ENOENT;
	if (i == ccs_address_group_list_len) {
		ccs_address_group_list =
			ccs_realloc(ccs_address_group_list,
				    (ccs_address_group_list_len + 1) *
				    sizeof(struct ccs_address_group_entry));
		group = &ccs_address_group_list[ccs_address_group_list_len++];
		memset(group, 0, sizeof(struct ccs_address_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name =
		ccs_realloc(group->member_name, (group->member_name_len + 1) *
			    sizeof(const struct ccs_ip_address_entry));
	group->member_name[group->member_name_len++] = entry;
	return 0;
}

/**
 * ccs_find_address_group - Find an "address_group" by name.
 *
 * @group_name: Group name to find.
 *
 * Returns pointer to "struct ccs_address_group_entry" if found,
 * NULL otherwise.
 */
static struct ccs_address_group_entry *ccs_find_address_group
(const char *group_name)
{
	int i;
	for (i = 0; i < ccs_address_group_list_len; i++) {
		if (!strcmp(group_name,
			    ccs_address_group_list[i].group_name->name))
			return &ccs_address_group_list[i];
	}
	return NULL;
}

/**
 * ccs_add_number_group_entry - Add "number_group" entry.
 *
 * @group_name:  Name of number group.
 * @member_name: Number string.
 * @is_delete:   True if it is delete request, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_add_number_group_entry(const char *group_name,
				      const char *member_name,
				      const _Bool is_delete)
{
	const struct ccs_path_info *saved_group_name;
	int i;
	int j;
	struct ccs_number_entry entry;
	struct ccs_number_group_entry *group = NULL;
	if (ccs_parse_number(member_name, &entry))
		return -EINVAL;
	if (!ccs_correct_word(group_name))
		return -EINVAL;
	saved_group_name = ccs_savename(group_name);
	for (i = 0; i < ccs_number_group_list_len; i++) {
		group = &ccs_number_group_list[i];
		if (saved_group_name != group->group_name)
			continue;
		for (j = 0; j < group->member_name_len; j++) {
			if (memcmp(&group->member_name[j], &entry,
				   sizeof(entry)))
				continue;
			if (!is_delete)
				return 0;
			while (j < group->member_name_len - 1)
				group->member_name[j]
					= group->member_name[j + 1];
			group->member_name_len--;
			return 0;
		}
		break;
	}
	if (is_delete)
		return -ENOENT;
	if (i == ccs_number_group_list_len) {
		ccs_number_group_list =
			ccs_realloc(ccs_number_group_list,
				    (ccs_number_group_list_len + 1) *
				    sizeof(struct ccs_number_group_entry));
		group = &ccs_number_group_list[ccs_number_group_list_len++];
		memset(group, 0, sizeof(struct ccs_number_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name =
		ccs_realloc(group->member_name, (group->member_name_len + 1) *
			    sizeof(const struct ccs_number_entry));
	group->member_name[group->member_name_len++] = entry;
	return 0;
}

/**
 * ccs_find_number_group - Find an "number_group" by name.
 *
 * @group_name: Group name to find.
 *
 * Returns pointer to "struct ccs_number_group_entry" if found,
 * NULL otherwise.
 */
static struct ccs_number_group_entry *ccs_find_number_group
(const char *group_name)
{
	int i;
	for (i = 0; i < ccs_number_group_list_len; i++) {
		if (!strcmp(group_name,
			    ccs_number_group_list[i].group_name->name))
			return &ccs_number_group_list[i];
	}
	return NULL;
}

/**
 * ccs_editpolicy_clear_groups - Clear path_group/number_group/address_group for reloading policy.
 *
 * Returns nothing.
 */
void ccs_editpolicy_clear_groups(void)
{
	while (ccs_path_group_list_len)
		free(ccs_path_group_list[--ccs_path_group_list_len].
		     member_name);
	/*
	while (ccs_address_group_list_len)
		free(ccs_address_group_list[--ccs_address_group_list_len].
		     member_name);
	*/
	ccs_address_group_list_len = 0;
	ccs_number_group_list_len = 0;
}
