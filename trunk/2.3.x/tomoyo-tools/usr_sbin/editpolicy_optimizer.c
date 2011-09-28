/*
 * editpolicy_optimizer.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.3.0+   2011/09/29
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
#include "editpolicy.h"

struct tomoyo_address_group_entry {
	const struct tomoyo_path_info *group_name;
	struct tomoyo_ip_address_entry *member_name;
	int member_name_len;
};

struct tomoyo_number_group_entry {
	const struct tomoyo_path_info *group_name;
	struct tomoyo_number_entry *member_name;
	int member_name_len;
};

/* Prototypes */
static int tomoyo_add_address_group_entry(const char *group_name, const char *member_name, const _Bool is_delete);
static struct tomoyo_address_group_entry *tomoyo_find_address_group(const char *group_name);
static int tomoyo_add_number_group_entry(const char *group_name, const char *member_name, const _Bool is_delete);
static struct tomoyo_number_group_entry *tomoyo_find_number_group(const char *group_name);
static _Bool tomoyo_compare_path(const char *sarg, const char *darg, const u8 directive);
static _Bool tomoyo_compare_number(const char *sarg, const char *darg);
static _Bool tomoyo_compare_address(const char *sarg, const char *darg);

/* Utility functions */

struct tomoyo_path_group_entry *tomoyo_find_path_group(const char *group_name)
{
	int i;
	for (i = 0; i < tomoyo_path_group_list_len; i++) {
		if (!strcmp(group_name, tomoyo_path_group_list[i].group_name->name))
			return &tomoyo_path_group_list[i];
	}
	return NULL;
}

int tomoyo_add_address_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return tomoyo_add_address_group_entry(data, cp, is_delete);
}

static _Bool tomoyo_compare_path(const char *sarg, const char *darg,
			      const u8 directive)
{
	int i;
	struct tomoyo_path_group_entry *group;
	struct tomoyo_path_info s;
	struct tomoyo_path_info d;
	s.name = sarg;
	d.name = darg;
	tomoyo_fill_path_info(&s);
	tomoyo_fill_path_info(&d);
	if (!tomoyo_pathcmp(&s, &d))
		return true;
	if (d.name[0] == '@')
		return false;
	if (s.name[0] != '@')
		/* Pathname component. */
		return tomoyo_path_matches_pattern(&d, &s);
	/* path_group component. */
	group = tomoyo_find_path_group(s.name + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		const struct tomoyo_path_info *member_name;
		member_name = group->member_name[i];
		if (!tomoyo_pathcmp(member_name, &d))
			return true;
		if (tomoyo_path_matches_pattern(&d, member_name))
			return true;
	}
	return false;
}

static _Bool tomoyo_compare_address(const char *sarg, const char *darg)
{
	int i;
	struct tomoyo_ip_address_entry sentry;
	struct tomoyo_ip_address_entry dentry;
	struct tomoyo_address_group_entry *group;
	if (tomoyo_parse_ip(darg, &dentry))
		return false;
	if (sarg[0] != '@') {
		/* IP address component. */
		if (tomoyo_parse_ip(sarg, &sentry))
			return false;
		if (sentry.is_ipv6 != dentry.is_ipv6 ||
		    memcmp(dentry.min, sentry.min, 16) < 0 ||
		    memcmp(sentry.max, dentry.max, 16) < 0)
			return false;
		return true;
	}
	/* IP address group component. */
	group = tomoyo_find_address_group(sarg + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		struct tomoyo_ip_address_entry *sentry = &group->member_name[i];
		if (sentry->is_ipv6 == dentry.is_ipv6
		    && memcmp(sentry->min, dentry.min, 16) <= 0
		    && memcmp(dentry.max, sentry->max, 16) <= 0)
			return true;
	}
	return false;
}

static char *tomoyo_tokenize(char *buffer, char *w[], size_t size)
{
	int count = size / sizeof(char *);
	int i;
	char *cp;
	cp = strstr(buffer, " if ");
	if (!cp)
		cp = strstr(buffer, " ; set ");
	if (cp)
		*cp++ = '\0';
	else
		cp = "";
	for (i = 0; i < count; i++)
		w[i] = "";
	for (i = 0; i < count; i++) {
		char *cp = strchr(buffer, ' ');
		if (cp)
			*cp = '\0';
		w[i] = buffer;
		if (!cp)
			break;
		buffer = cp + 1;
	}
	return i < count || !*buffer ? cp : NULL;
}

int tomoyo_add_number_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return tomoyo_add_number_group_entry(data, cp, is_delete);
}

static _Bool tomoyo_compare_number(const char *sarg, const char *darg)
{
	int i;
	struct tomoyo_number_entry sentry;
	struct tomoyo_number_entry dentry;
	struct tomoyo_number_group_entry *group;
	if (tomoyo_parse_number(darg, &dentry))
		return false;
	if (sarg[0] != '@') {
		/* Number component. */
		if (tomoyo_parse_number(sarg, &sentry))
			return false;
		if (sentry.min > dentry.min || sentry.max < dentry.max)
			return false;
		return true;
	}
	/* Number group component. */
	group = tomoyo_find_number_group(sarg + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		struct tomoyo_number_entry *entry = &group->member_name[i];
		if (entry->min > dentry.min || entry->max < dentry.max)
			continue;
		return true;
	}
	return false;
}

void tomoyo_editpolicy_try_optimize(struct tomoyo_domain_policy *dp, const int current,
				 const int screen)
{
	char *cp;
	u8 s_index;
	int index;
	char *s_cond;
	char *d_cond;
	char *s[5];
	char *d[5];
	if (current < 0)
		return;
	s_index = tomoyo_generic_acl_list[current].directive;
	if (s_index == CCS_DIRECTIVE_NONE)
		return;
	/* Allow allow_read lines to be optimized. */
	if (screen == CCS_SCREEN_EXCEPTION_LIST &&
	    s_index != CCS_DIRECTIVE_ALLOW_READ)
		return;
	cp = strdup(tomoyo_generic_acl_list[current].operand);
	if (!cp)
		return;

	s_cond = tomoyo_tokenize(cp, s, sizeof(s));
	if (!s_cond) {
		free(cp);
		return;
	}

	tomoyo_get();
	for (index = 0; index < tomoyo_list_item_count[screen]; index++) {
		char *line;
		const u8 d_index = tomoyo_generic_acl_list[index].directive;
		if (index == current)
			continue;
		if (tomoyo_generic_acl_list[index].selected)
			continue;
		if (s_index == CCS_DIRECTIVE_ALLOW_READ_WRITE) {
			/* Source starts with "allow_read/write " */
			if (d_index == CCS_DIRECTIVE_ALLOW_READ_WRITE) {
				/* Dest starts with "allow_read/write " */
			} else if (d_index == CCS_DIRECTIVE_ALLOW_READ) {
				/* Dest starts with "allow_read " */
			} else if (d_index == CCS_DIRECTIVE_ALLOW_WRITE) {
				/* Dest starts with "allow_write " */
			} else {
				/*
				 * Source and dest start with different
				 * directive.
				 */
				continue;
			}
		} else if (s_index == d_index) {
			/* Source and dest start with same directive. */
		} else {
			/* Source and dest start with different directive. */
			continue;
		}
		line = tomoyo_shprintf("%s", tomoyo_generic_acl_list[index].operand);
		d_cond = tomoyo_tokenize(line, d, sizeof(d));

		/* Compare condition part. */
		if (!d_cond || strcmp(s_cond, d_cond))
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
			struct tomoyo_path_info sarg;
			struct tomoyo_path_info darg;
			char c;
			int len;
		case CCS_DIRECTIVE_ALLOW_MKBLOCK:
		case CCS_DIRECTIVE_ALLOW_MKCHAR:
			if (!tomoyo_compare_number(s[3], d[3]) ||
			    !tomoyo_compare_number(s[2], d[2]))
				continue;
			/* fall through */
		case CCS_DIRECTIVE_ALLOW_CREATE:
		case CCS_DIRECTIVE_ALLOW_MKDIR:
		case CCS_DIRECTIVE_ALLOW_MKFIFO:
		case CCS_DIRECTIVE_ALLOW_MKSOCK:
		case CCS_DIRECTIVE_ALLOW_IOCTL:
		case CCS_DIRECTIVE_ALLOW_CHMOD:
		case CCS_DIRECTIVE_ALLOW_CHOWN:
		case CCS_DIRECTIVE_ALLOW_CHGRP:
			if (!tomoyo_compare_number(s[1], d[1]))
				continue;
			/* fall through */
		case CCS_DIRECTIVE_ALLOW_EXECUTE:
		case CCS_DIRECTIVE_ALLOW_READ:
		case CCS_DIRECTIVE_ALLOW_WRITE:
		case CCS_DIRECTIVE_ALLOW_READ_WRITE:
		case CCS_DIRECTIVE_ALLOW_UNLINK:
		case CCS_DIRECTIVE_ALLOW_RMDIR:
		case CCS_DIRECTIVE_ALLOW_TRUNCATE:
		case CCS_DIRECTIVE_ALLOW_REWRITE:
		case CCS_DIRECTIVE_ALLOW_UNMOUNT:
		case CCS_DIRECTIVE_ALLOW_CHROOT:
		case CCS_DIRECTIVE_ALLOW_SYMLINK:
			if (!tomoyo_compare_path(s[0], d[0], d_index))
				continue;
			break;
		case CCS_DIRECTIVE_ALLOW_MOUNT:
			if (!tomoyo_compare_number(s[3], d[3]) ||
			    !tomoyo_compare_path(s[2], d[2], d_index))
				continue;
			/* fall through */
		case CCS_DIRECTIVE_ALLOW_LINK:
		case CCS_DIRECTIVE_ALLOW_RENAME:
		case CCS_DIRECTIVE_ALLOW_PIVOT_ROOT:
			if (!tomoyo_compare_path(s[1], d[1], d_index) ||
			    !tomoyo_compare_path(s[0], d[0], d_index))
				continue;
			break;
		case CCS_DIRECTIVE_ALLOW_SIGNAL:
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
		case CCS_DIRECTIVE_ALLOW_NETWORK:
			if (strcmp(s[0], d[0]) || strcmp(s[1], d[1]) ||
			    !tomoyo_compare_address(s[2], d[2]) ||
			    !tomoyo_compare_number(s[3], d[3]))
				continue;
			break;
		case CCS_DIRECTIVE_ALLOW_ENV:
			/* An environemnt variable name component. */
			sarg.name = s[0];
			tomoyo_fill_path_info(&sarg);
			darg.name = d[0];
			tomoyo_fill_path_info(&darg);
			if (!tomoyo_pathcmp(&sarg, &darg))
				break;
			/* allow_env doesn't interpret leading @ as
			   path_group. */
			if (darg.is_patterned ||
			    !tomoyo_path_matches_pattern(&darg, &sarg))
				continue;
			break;
		default:
			continue;
		}
		tomoyo_generic_acl_list[index].selected = 1;
	}
	tomoyo_put();
	free(cp);
}

/* Variables */

static struct tomoyo_address_group_entry *tomoyo_address_group_list = NULL;
int tomoyo_address_group_list_len = 0;

/* Main functions */

static int tomoyo_add_address_group_entry(const char *group_name,
				       const char *member_name,
				       const _Bool is_delete)
{
	const struct tomoyo_path_info *saved_group_name;
	int i;
	int j;
	struct tomoyo_ip_address_entry entry;
	struct tomoyo_address_group_entry *group = NULL;
	if (tomoyo_parse_ip(member_name, &entry))
		return -EINVAL;
	if (!tomoyo_correct_word(group_name))
		return -EINVAL;
	saved_group_name = tomoyo_savename(group_name);
	if (!saved_group_name)
		return -ENOMEM;
	for (i = 0; i < tomoyo_address_group_list_len; i++) {
		group = &tomoyo_address_group_list[i];
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
	if (i == tomoyo_address_group_list_len) {
		void *vp;
		vp = realloc(tomoyo_address_group_list,
			     (tomoyo_address_group_list_len + 1) *
			     sizeof(struct tomoyo_address_group_entry));
		if (!vp)
			tomoyo_out_of_memory();
		tomoyo_address_group_list = vp;
		group = &tomoyo_address_group_list[tomoyo_address_group_list_len++];
		memset(group, 0, sizeof(struct tomoyo_address_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1) *
				     sizeof(const struct tomoyo_ip_address_entry));
	if (!group->member_name)
		tomoyo_out_of_memory();
	group->member_name[group->member_name_len++] = entry;
	return 0;
}

static struct tomoyo_address_group_entry *tomoyo_find_address_group(const char *group_name)
{
	int i;
	for (i = 0; i < tomoyo_address_group_list_len; i++) {
		if (!strcmp(group_name, tomoyo_address_group_list[i].group_name->name))
			return &tomoyo_address_group_list[i];
	}
	return NULL;
}

static struct tomoyo_number_group_entry *tomoyo_number_group_list = NULL;
int tomoyo_number_group_list_len = 0;

static int tomoyo_add_number_group_entry(const char *group_name,
				      const char *member_name,
				      const _Bool is_delete)
{
	const struct tomoyo_path_info *saved_group_name;
	int i;
	int j;
	struct tomoyo_number_entry entry;
	struct tomoyo_number_group_entry *group = NULL;
	if (tomoyo_parse_number(member_name, &entry))
		return -EINVAL;
	if (!tomoyo_correct_word(group_name))
		return -EINVAL;
	saved_group_name = tomoyo_savename(group_name);
	if (!saved_group_name)
		return -ENOMEM;
	for (i = 0; i < tomoyo_number_group_list_len; i++) {
		group = &tomoyo_number_group_list[i];
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
	if (i == tomoyo_number_group_list_len) {
		void *vp;
		vp = realloc(tomoyo_number_group_list,
			     (tomoyo_number_group_list_len + 1) *
			     sizeof(struct tomoyo_number_group_entry));
		if (!vp)
			tomoyo_out_of_memory();
		tomoyo_number_group_list = vp;
		group = &tomoyo_number_group_list[tomoyo_number_group_list_len++];
		memset(group, 0, sizeof(struct tomoyo_number_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1) *
				     sizeof(const struct tomoyo_number_entry));
	if (!group->member_name)
		tomoyo_out_of_memory();
	group->member_name[group->member_name_len++] = entry;
	return 0;
}

static struct tomoyo_number_group_entry *tomoyo_find_number_group(const char *group_name)
{
	int i;
	for (i = 0; i < tomoyo_number_group_list_len; i++) {
		if (!strcmp(group_name, tomoyo_number_group_list[i].group_name->name))
			return &tomoyo_number_group_list[i];
	}
	return NULL;
}
