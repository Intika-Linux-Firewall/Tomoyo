/*
 * editpolicy_optimizer.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include "ccstools.h"

/* Prototypes */
static int add_address_group_entry(const char *group_name,
				   const char *member_name,
				   const _Bool is_delete);
static struct address_group_entry *find_address_group(const char *group_name);
static int add_number_group_entry(const char *group_name,
				  const char *member_name,
				  const _Bool is_delete);
static struct number_group_entry *find_number_group(const char *group_name);
static _Bool compare_path(const char *sarg, const char *darg,
			  const u8 directive);
static _Bool compare_number(const char *sarg, const char *darg);
static _Bool compare_address(const char *sarg, const char *darg);

/* Utility functions */

struct path_group_entry *find_path_group(const char *group_name)
{
	int i;
	for (i = 0; i < path_group_list_len; i++) {
		if (!strcmp(group_name, path_group_list[i].group_name->name))
			return &path_group_list[i];
	}
	return NULL;
}

int parse_ip(const char *address, struct ip_address_entry *entry)
{
	unsigned int min[8];
	unsigned int max[8];
	int i;
	int j;
	memset(entry, 0, sizeof(*entry));
	i = sscanf(address, "%u.%u.%u.%u-%u.%u.%u.%u",
		   &min[0], &min[1], &min[2], &min[3],
		   &max[0], &max[1], &max[2], &max[3]);
	if (i == 4)
		for (j = 0; j < 4; j++)
			max[j] = min[j];
	if (i == 4 || i == 8) {
		for (j = 0; j < 4; j++) {
			entry->min[j] = (u8) min[j];
			entry->max[j] = (u8) max[j];
		}
		return 0;
	}
	i = sscanf(address, "%X:%X:%X:%X:%X:%X:%X:%X-%X:%X:%X:%X:%X:%X:%X:%X",
		   &min[0], &min[1], &min[2], &min[3],
		   &min[4], &min[5], &min[6], &min[7],
		   &max[0], &max[1], &max[2], &max[3],
		   &max[4], &max[5], &max[6], &max[7]);
	if (i == 8)
		for (j = 0; j < 8; j++)
			max[j] = min[j];
	if (i == 8 || i == 16) {
		for (j = 0; j < 8; j++) {
			entry->min[j * 2] = (u8) (min[j] >> 8);
			entry->min[j * 2 + 1] = (u8) min[j];
			entry->max[j * 2] = (u8) (max[j] >> 8);
			entry->max[j * 2 + 1] = (u8) max[j];
		}
		entry->is_ipv6 = true;
		return 0;
	}
	return -EINVAL;
}

int add_address_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return add_address_group_entry(data, cp, is_delete);
}

static _Bool compare_path(const char *sarg, const char *darg,
			  const u8 directive)
{
	int i;
	struct path_group_entry *group;
	struct path_info s;
	struct path_info d;
	_Bool may_use_pattern;
	s.name = sarg;
	d.name = darg;
	fill_path_info(&s);
	fill_path_info(&d);
	may_use_pattern = !d.is_patterned
		&& (directive != DIRECTIVE_ALLOW_EXECUTE);
	if (!pathcmp(&s, &d))
		return true;
	if (d.name[0] == '@')
		return false;
	if (s.name[0] != '@') {
		/* Pathname component. */
		return may_use_pattern && path_matches_pattern(&d, &s);
	}
	/* path_group component. */
	group = find_path_group(s.name + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		const struct path_info *member_name;
		member_name = group->member_name[i];
		if (!pathcmp(member_name, &d))
			return true;
		if (may_use_pattern && path_matches_pattern(&d, member_name))
			return true;
	}
	return false;
}

static _Bool compare_address(const char *sarg, const char *darg)
{
	int i;
	struct ip_address_entry sentry;
	struct ip_address_entry dentry;
	struct address_group_entry *group;
	if (parse_ip(darg, &dentry))
		return false;
	if (sarg[0] != '@') {
		/* IP address component. */
		if (parse_ip(sarg, &sentry))
			return false;
		if (sentry.is_ipv6 != dentry.is_ipv6 ||
		    memcmp(dentry.min, sentry.min, 16) < 0 ||
		    memcmp(sentry.max, dentry.max, 16) < 0)
			return false;
		return true;
	}
	/* IP address group component. */
	group = find_address_group(sarg + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		struct ip_address_entry *sentry = &group->member_name[i];
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

int parse_number(const char *number, struct number_entry *entry)
{
	unsigned long min;
	unsigned long max;
	char *cp;
	memset(entry, 0, sizeof(*entry));
	if (number[0] != '0') {
		if (sscanf(number, "%lu", &min) != 1)
			return -EINVAL;
	} else if (number[1] == 'x' || number[1] == 'X') {
		if (sscanf(number + 2, "%lX", &min) != 1)
			return -EINVAL;
	} else if (sscanf(number, "%lo", &min) != 1)
		return -EINVAL;
	cp = strchr(number, '-');
	if (cp)
		number = cp + 1;
	if (number[0] != '0') {
		if (sscanf(number, "%lu", &max) != 1)
			return -EINVAL;
	} else if (number[1] == 'x' || number[1] == 'X') {
		if (sscanf(number + 2, "%lX", &max) != 1)
			return -EINVAL;
	} else if (sscanf(number, "%lo", &max) != 1)
		return -EINVAL;
	entry->min = min;
	entry->max = max;
	return 0;
}

int add_number_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return add_number_group_entry(data, cp, is_delete);
}

static _Bool compare_number(const char *sarg, const char *darg)
{
	int i;
	struct number_entry sentry;
	struct number_entry dentry;
	struct number_group_entry *group;
	if (parse_number(darg, &dentry))
		return false;
	if (sarg[0] != '@') {
		/* Number component. */
		if (parse_number(sarg, &sentry))
			return false;
		if (sentry.min > dentry.min || sentry.max < dentry.max)
			return false;
		return true;
	}
	/* Number group component. */
	group = find_number_group(sarg + 1);
	if (!group)
		return false;
	for (i = 0; i < group->member_name_len; i++) {
		struct number_entry *entry = &group->member_name[i];
		if (entry->min > dentry.min || entry->max < dentry.max)
			continue;
		return true;
	}
	return false;
}

void editpolicy_try_optimize(struct domain_policy *dp, const int current,
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
	s_index = generic_acl_list[current].directive;
	if (s_index == DIRECTIVE_NONE)
		return;
	/* Allow allow_read lines and allow_env lines to be optimized. */
	if (screen == SCREEN_EXCEPTION_LIST &&
	    s_index != DIRECTIVE_ALLOW_READ && s_index != DIRECTIVE_ALLOW_ENV)
		return;
	cp = strdup(generic_acl_list[current].operand);
	if (!cp)
		return;

	s_cond = ccs_tokenize(cp, s, sizeof(s));
	if (!s_cond) {
		free(cp);
		return;
	}

	get();
	for (index = 0; index < list_item_count[screen]; index++) {
		char *line;
		const u8 d_index = generic_acl_list[index].directive;
		if (index == current)
			continue;
		if (generic_acl_list[index].selected)
			continue;
		if (s_index == DIRECTIVE_ALLOW_READ_WRITE) {
			/* Source starts with "allow_read/write " */
			if (d_index == DIRECTIVE_ALLOW_READ_WRITE) {
				/* Dest starts with "allow_read/write " */
			} else if (d_index == DIRECTIVE_ALLOW_READ) {
				/* Dest starts with "allow_read " */
			} else if (d_index == DIRECTIVE_ALLOW_WRITE) {
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
		line = shprintf("%s", generic_acl_list[index].operand);
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
			struct path_info sarg;
			struct path_info darg;
			char c;
			int len;
		case DIRECTIVE_ALLOW_MKBLOCK:
		case DIRECTIVE_ALLOW_MKCHAR:
			if (!compare_number(s[3], d[3]) ||
			    !compare_number(s[2], d[2]))
				continue;
			/* fall through */
		case DIRECTIVE_ALLOW_CREATE:
		case DIRECTIVE_ALLOW_MKDIR:
		case DIRECTIVE_ALLOW_MKFIFO:
		case DIRECTIVE_ALLOW_MKSOCK:
		case DIRECTIVE_ALLOW_IOCTL:
		case DIRECTIVE_ALLOW_CHMOD:
		case DIRECTIVE_ALLOW_CHOWN:
		case DIRECTIVE_ALLOW_CHGRP:
			if (!compare_number(s[1], d[1]))
				continue;
			/* fall through */
		case DIRECTIVE_ALLOW_EXECUTE:
		case DIRECTIVE_ALLOW_READ:
		case DIRECTIVE_ALLOW_WRITE:
		case DIRECTIVE_ALLOW_READ_WRITE:
		case DIRECTIVE_ALLOW_UNLINK:
		case DIRECTIVE_ALLOW_RMDIR:
		case DIRECTIVE_ALLOW_TRUNCATE:
		case DIRECTIVE_ALLOW_REWRITE:
		case DIRECTIVE_ALLOW_UNMOUNT:
		case DIRECTIVE_ALLOW_CHROOT:
		case DIRECTIVE_ALLOW_SYMLINK:
			if (!compare_path(s[0], d[0], d_index))
				continue;
			break;
		case DIRECTIVE_ALLOW_MOUNT:
			if (!compare_number(s[3], d[3]) ||
			    !compare_path(s[2], d[2], d_index))
				continue;
			/* fall through */
		case DIRECTIVE_ALLOW_LINK:
		case DIRECTIVE_ALLOW_RENAME:
		case DIRECTIVE_ALLOW_PIVOT_ROOT:
			if (!compare_path(s[1], d[1], d_index) ||
			    !compare_path(s[0], d[0], d_index))
				continue;
			break;
		case DIRECTIVE_ALLOW_SIGNAL:
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
		case DIRECTIVE_ALLOW_NETWORK:
			if (strcmp(s[0], d[0]) || strcmp(s[1], d[1]) ||
			    !compare_address(s[2], d[2]) ||
			    !compare_number(s[3], d[3]))
				continue;
			break;
		case DIRECTIVE_ALLOW_ENV:
			/* An environemnt variable name component. */
			sarg.name = s[0];
			fill_path_info(&sarg);
			darg.name = d[0];
			fill_path_info(&darg);
			if (!pathcmp(&sarg, &darg))
				break;
			/* allow_env doesn't interpret leading @ as
			   path_group. */
			if (darg.is_patterned ||
			    !path_matches_pattern(&darg, &sarg))
				continue;
			break;
		default:
			continue;
		}
		generic_acl_list[index].selected = 1;
	}
	put();
	free(cp);
}

/* Variables */

static struct address_group_entry *address_group_list = NULL;
int address_group_list_len = 0;

/* Main functions */

static int add_address_group_entry(const char *group_name,
				   const char *member_name,
				   const _Bool is_delete)
{
	const struct path_info *saved_group_name;
	int i;
	int j;
	struct ip_address_entry entry;
	struct address_group_entry *group = NULL;
	if (parse_ip(member_name, &entry))
		return -EINVAL;
	if (!is_correct_path(group_name, 0, 0, 0))
		return -EINVAL;
	saved_group_name = savename(group_name);
	if (!saved_group_name)
		return -ENOMEM;
	for (i = 0; i < address_group_list_len; i++) {
		group = &address_group_list[i];
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
	if (i == address_group_list_len) {
		void *vp;
		vp = realloc(address_group_list,
			     (address_group_list_len + 1) *
			     sizeof(struct address_group_entry));
		if (!vp)
			out_of_memory();
		address_group_list = vp;
		group = &address_group_list[address_group_list_len++];
		memset(group, 0, sizeof(struct address_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1) *
				     sizeof(const struct ip_address_entry));
	if (!group->member_name)
		out_of_memory();
	group->member_name[group->member_name_len++] = entry;
	return 0;
}

static struct address_group_entry *find_address_group(const char *group_name)
{
	int i;
	for (i = 0; i < address_group_list_len; i++) {
		if (!strcmp(group_name, address_group_list[i].group_name->name))
			return &address_group_list[i];
	}
	return NULL;
}

static struct number_group_entry *number_group_list = NULL;
int number_group_list_len = 0;

static int add_number_group_entry(const char *group_name,
				  const char *member_name,
				  const _Bool is_delete)
{
	const struct path_info *saved_group_name;
	int i;
	int j;
	struct number_entry entry;
	struct number_group_entry *group = NULL;
	if (parse_number(member_name, &entry))
		return -EINVAL;
	if (!is_correct_path(group_name, 0, 0, 0))
		return -EINVAL;
	saved_group_name = savename(group_name);
	if (!saved_group_name)
		return -ENOMEM;
	for (i = 0; i < number_group_list_len; i++) {
		group = &number_group_list[i];
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
	if (i == number_group_list_len) {
		void *vp;
		vp = realloc(number_group_list,
			     (number_group_list_len + 1) *
			     sizeof(struct number_group_entry));
		if (!vp)
			out_of_memory();
		number_group_list = vp;
		group = &number_group_list[number_group_list_len++];
		memset(group, 0, sizeof(struct number_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1) *
				     sizeof(const struct number_entry));
	if (!group->member_name)
		out_of_memory();
	group->member_name[group->member_name_len++] = entry;
	return 0;
}

static struct number_group_entry *find_number_group(const char *group_name)
{
	int i;
	for (i = 0; i < number_group_list_len; i++) {
		if (!strcmp(group_name, number_group_list[i].group_name->name))
			return &number_group_list[i];
	}
	return NULL;
}
