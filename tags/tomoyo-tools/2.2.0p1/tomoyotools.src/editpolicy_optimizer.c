/*
 * editpolicy_optimizer.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 2.2.0+   2010/02/25
 *
 */
#include "tomoyotools.h"

/* Prototypes */
static _Bool compare_path(struct path_info *sarg, struct path_info *darg,
			  u8 directive);
static void split_acl(const u8 index, char *data, struct path_info *arg1,
		      struct path_info *arg2);

/* Utility functions */

static _Bool compare_path(struct path_info *sarg, struct path_info *darg,
			 u8 directive)
{
	_Bool may_use_pattern = !darg->is_patterned
		&& (directive != DIRECTIVE_1)
		&& (directive != DIRECTIVE_3)
		&& (directive != DIRECTIVE_5)
		&& (directive != DIRECTIVE_7)
		&& (directive != DIRECTIVE_ALLOW_EXECUTE);
	if (!pathcmp(sarg, darg))
		return true;
	if (darg->name[0] == '@' || sarg->name[0] == '@')
		return false;
	/* Pathname component. */
	return may_use_pattern && path_matches_pattern(darg, sarg);
}

static void split_acl(const u8 index, char *data, struct path_info *arg1,
		      struct path_info *arg2)
{
	/* data = w[0] w[1] ... w[n-1] w[n] */
	/*                                  */
	/* arg1 = w[0]                      */
	/* arg2 = w[1] ... w[n-1] w[n]      */
	char *cp;
	arg1->name = data;
	cp = strchr(data, ' ');
	if (cp)
		*cp++ = '\0';
	else
		cp = "";
	arg2->name = cp;
	fill_path_info(arg1);
	fill_path_info(arg2);
}

void editpolicy_try_optimize(struct domain_policy *dp, const int current,
			     const int screen)
{
	char *cp;
	u8 s_index;
	int index;
	struct path_info sarg1;
	struct path_info sarg2;
	struct path_info darg1;
	struct path_info darg2;
	if (current < 0)
		return;
	s_index = generic_acl_list[current].directive;
	if (s_index == DIRECTIVE_NONE)
		return;
	cp = strdup(generic_acl_list[current].operand);
	if (!cp)
		return;

	split_acl(s_index, cp, &sarg1, &sarg2);

	get();
	for (index = 0; index < list_item_count[screen]; index++) {
		const u8 d_index = generic_acl_list[index].directive;
		if (index == current)
			continue;
		if (generic_acl_list[index].selected)
			continue;
		if (s_index == DIRECTIVE_6 ||
		    s_index == DIRECTIVE_ALLOW_READ_WRITE) {
			/* Source starts with "6 " or "allow_read/write " */
			if (d_index == DIRECTIVE_6) {
				/* Dest starts with "6 " */
			} else if (d_index == DIRECTIVE_ALLOW_READ_WRITE) {
				/* Dest starts with "allow_read/write " */
			} else if (d_index == DIRECTIVE_2) {
				/* Dest starts with "2 " */
			} else if (d_index == DIRECTIVE_4) {
				/* Dest starts with "4 " */
			} else if (d_index == DIRECTIVE_ALLOW_READ) {
				/* Dest starts with "allow_read " */
			} else if (d_index == DIRECTIVE_ALLOW_WRITE) {
				/* Dest starts with "allow_write " */
			} else {
				/* Source and dest start with same directive. */
				continue;
			}
		} else if (s_index == DIRECTIVE_2 &&
			   d_index == DIRECTIVE_ALLOW_WRITE) {
			/* Source starts with "2 " and dest starts with
			   "allow_write " */
		} else if (s_index == DIRECTIVE_4 &&
			   d_index == DIRECTIVE_ALLOW_READ) {
			/* Source starts with "4 " and dest starts with
			   "allow_read " */
		} else if (s_index == DIRECTIVE_ALLOW_WRITE &&
			   d_index == DIRECTIVE_2) {
			/* Source starts with "allow_write " and dest starts
			   with "2 " */
		} else if (s_index == DIRECTIVE_ALLOW_READ &&
			   d_index == DIRECTIVE_4) {
			/* Source starts with "allow_read " and dest starts
			   with "4 " */
		} else if (s_index == d_index) {
			/* Source and dest start with same directive. */
		} else {
			/* Source and dest start with different directive. */
			continue;
		}
		shprintf("%s", generic_acl_list[index].operand);
		if (!memchr(shared_buffer, '\0', sizeof(shared_buffer)))
			continue; /* Line too long. */

		split_acl(d_index, shared_buffer, &darg1, &darg2);

		/* Compare first word. */
		switch (d_index) {
		case DIRECTIVE_1:
		case DIRECTIVE_2:
		case DIRECTIVE_3:
		case DIRECTIVE_4:
		case DIRECTIVE_5:
		case DIRECTIVE_6:
		case DIRECTIVE_7:
		case DIRECTIVE_ALLOW_EXECUTE:
		case DIRECTIVE_ALLOW_READ:
		case DIRECTIVE_ALLOW_WRITE:
		case DIRECTIVE_ALLOW_READ_WRITE:
		case DIRECTIVE_ALLOW_CREATE:
		case DIRECTIVE_ALLOW_UNLINK:
		case DIRECTIVE_ALLOW_MKDIR:
		case DIRECTIVE_ALLOW_RMDIR:
		case DIRECTIVE_ALLOW_MKFIFO:
		case DIRECTIVE_ALLOW_MKSOCK:
		case DIRECTIVE_ALLOW_MKBLOCK:
		case DIRECTIVE_ALLOW_MKCHAR:
		case DIRECTIVE_ALLOW_TRUNCATE:
		case DIRECTIVE_ALLOW_SYMLINK:
		case DIRECTIVE_ALLOW_LINK:
		case DIRECTIVE_ALLOW_RENAME:
		case DIRECTIVE_ALLOW_REWRITE:
		case DIRECTIVE_ALLOW_IOCTL:
		case DIRECTIVE_ALLOW_CHMOD:
		case DIRECTIVE_ALLOW_CHOWN:
		case DIRECTIVE_ALLOW_CHGRP:
		case DIRECTIVE_ALLOW_MOUNT:
		case DIRECTIVE_ALLOW_UNMOUNT:
		case DIRECTIVE_ALLOW_CHROOT:
		case DIRECTIVE_ALLOW_PIVOT_ROOT:
			if (!compare_path(&sarg1, &darg1, d_index))
				continue;
			break;
		default:
			continue;
		}

		/* Compare rest words. */
		switch (d_index) {
		case DIRECTIVE_ALLOW_LINK:
		case DIRECTIVE_ALLOW_RENAME:
		case DIRECTIVE_ALLOW_PIVOT_ROOT:
			if (!compare_path(&sarg2, &darg2, d_index))
				continue;
			break;
		default:
			/* This must be empty. */
			if (sarg2.total_len || darg2.total_len)
				continue;
		}
		generic_acl_list[index].selected = 1;
	}
	put();
	free(cp);
}
