/*
 * editpolicy_optimizer.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/04/06
 *
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

/* Prototypes */
static int ccs_add_address_group_entry(const char *group_name, const char *member_name, const _Bool is_delete);
static struct ccs_address_group_entry *ccs_find_address_group(const char *group_name);
static int ccs_add_number_group_entry(const char *group_name, const char *member_name, const _Bool is_delete);
static struct ccs_number_group_entry *ccs_find_number_group(const char *group_name);
static _Bool ccs_compare_path(const char *sarg, const char *darg, const u8 directive);
static _Bool ccs_compare_number(const char *sarg, const char *darg);
static _Bool ccs_compare_address(const char *sarg, const char *darg);

/* Utility functions */

struct ccs_path_group_entry *ccs_find_path_group(const char *group_name)
{
	int i;
	for (i = 0; i < ccs_path_group_list_len; i++) {
		if (!strcmp(group_name, ccs_path_group_list[i].group_name->name))
			return &ccs_path_group_list[i];
	}
	return NULL;
}

int ccs_add_address_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return ccs_add_address_group_entry(data, cp, is_delete);
}

static _Bool ccs_compare_path(const char *sarg, const char *darg,
			      const u8 directive)
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
	group = ccs_find_path_group(s.name + 1);
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

static char *ccs_tokenize(char *buffer, char *w[], size_t size)
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

int ccs_add_number_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return ccs_add_number_group_entry(data, cp, is_delete);
}

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

void ccs_editpolicy_try_optimize(struct ccs_domain_policy *dp, const int current,
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
	s_index = ccs_generic_acl_list[current].directive;
	if (s_index == CCS_DIRECTIVE_NONE)
		return;
	cp = strdup(ccs_generic_acl_list[current].operand);
	if (!cp)
		return;

	s_cond = ccs_tokenize(cp, s, sizeof(s));
	if (!s_cond) {
		free(cp);
		return;
	}

	ccs_get();
	for (index = 0; index < ccs_list_item_count[screen]; index++) {
		char *line;
		const u8 d_index = ccs_generic_acl_list[index].directive;
		if (index == current)
			continue;
		if (ccs_generic_acl_list[index].selected)
			continue;
		else if (s_index == d_index) {
			/* Source and dest start with same directive. */
		} else {
			/* Source and dest start with different directive. */
			continue;
		}
		line = ccs_shprintf("%s", ccs_generic_acl_list[index].operand);
		d_cond = ccs_tokenize(line, d, sizeof(d));

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
			struct ccs_path_info sarg;
			struct ccs_path_info darg;
			char c;
			int len;
		case CCS_DIRECTIVE_ALLOW_MKBLOCK:
		case CCS_DIRECTIVE_ALLOW_MKCHAR:
			if (!ccs_compare_number(s[3], d[3]) ||
			    !ccs_compare_number(s[2], d[2]))
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
			if (!ccs_compare_number(s[1], d[1]))
				continue;
			/* fall through */
		case CCS_DIRECTIVE_ALLOW_EXECUTE:
		case CCS_DIRECTIVE_ALLOW_READ:
		case CCS_DIRECTIVE_ALLOW_WRITE:
		case CCS_DIRECTIVE_ALLOW_UNLINK:
		case CCS_DIRECTIVE_ALLOW_RMDIR:
		case CCS_DIRECTIVE_ALLOW_TRUNCATE:
		case CCS_DIRECTIVE_ALLOW_APPEND:
		case CCS_DIRECTIVE_ALLOW_UNMOUNT:
		case CCS_DIRECTIVE_ALLOW_CHROOT:
		case CCS_DIRECTIVE_ALLOW_SYMLINK:
			if (!ccs_compare_path(s[0], d[0], d_index))
				continue;
			break;
		case CCS_DIRECTIVE_ALLOW_MOUNT:
			if (!ccs_compare_number(s[3], d[3]) ||
			    !ccs_compare_path(s[2], d[2], d_index))
				continue;
			/* fall through */
		case CCS_DIRECTIVE_ALLOW_LINK:
		case CCS_DIRECTIVE_ALLOW_RENAME:
		case CCS_DIRECTIVE_ALLOW_PIVOT_ROOT:
			if (!ccs_compare_path(s[1], d[1], d_index) ||
			    !ccs_compare_path(s[0], d[0], d_index))
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
			    !ccs_compare_address(s[2], d[2]) ||
			    !ccs_compare_number(s[3], d[3]))
				continue;
			break;
		case CCS_DIRECTIVE_ALLOW_ENV:
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
		ccs_generic_acl_list[index].selected = 1;
	}
	ccs_put();
	free(cp);
}

/* Variables */

static struct ccs_address_group_entry *ccs_address_group_list = NULL;
int ccs_address_group_list_len = 0;

/* Main functions */

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
	if (!saved_group_name)
		return -ENOMEM;
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
		void *vp;
		vp = realloc(ccs_address_group_list,
			     (ccs_address_group_list_len + 1) *
			     sizeof(struct ccs_address_group_entry));
		if (!vp)
			ccs_out_of_memory();
		ccs_address_group_list = vp;
		group = &ccs_address_group_list[ccs_address_group_list_len++];
		memset(group, 0, sizeof(struct ccs_address_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1) *
				     sizeof(const struct ccs_ip_address_entry));
	if (!group->member_name)
		ccs_out_of_memory();
	group->member_name[group->member_name_len++] = entry;
	return 0;
}

static struct ccs_address_group_entry *ccs_find_address_group(const char *group_name)
{
	int i;
	for (i = 0; i < ccs_address_group_list_len; i++) {
		if (!strcmp(group_name, ccs_address_group_list[i].group_name->name))
			return &ccs_address_group_list[i];
	}
	return NULL;
}

static struct ccs_number_group_entry *ccs_number_group_list = NULL;
int ccs_number_group_list_len = 0;

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
	if (!saved_group_name)
		return -ENOMEM;
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
		void *vp;
		vp = realloc(ccs_number_group_list,
			     (ccs_number_group_list_len + 1) *
			     sizeof(struct ccs_number_group_entry));
		if (!vp)
			ccs_out_of_memory();
		ccs_number_group_list = vp;
		group = &ccs_number_group_list[ccs_number_group_list_len++];
		memset(group, 0, sizeof(struct ccs_number_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1) *
				     sizeof(const struct ccs_number_entry));
	if (!group->member_name)
		ccs_out_of_memory();
	group->member_name[group->member_name_len++] = entry;
	return 0;
}

static struct ccs_number_group_entry *ccs_find_number_group(const char *group_name)
{
	int i;
	for (i = 0; i < ccs_number_group_list_len; i++) {
		if (!strcmp(group_name, ccs_number_group_list[i].group_name->name))
			return &ccs_number_group_list[i];
	}
	return NULL;
}
