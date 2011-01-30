/*
 * editpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0+   2010/12/31
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
#include "readline.h"

/* Variables */

/* File descriptor for offline mode. */
extern int ccs_persistent_fd;

/* Array of "path_group" entries. */
struct ccs_path_group_entry *ccs_path_group_list = NULL;
/* Length of ccs_path_group_list array. */
int ccs_path_group_list_len = 0;
/* Array of string ACL entries. */
struct ccs_generic_acl *ccs_generic_acl_list = NULL;
/* Length of ccs_generic_list array. */
int ccs_generic_acl_list_count = 0;

/* Policy directory. */
static const char *ccs_policy_dir = NULL;
/* Use ccs-editpolicy-agent program? */
static _Bool ccs_offline_mode = false;
/* Use readonly mode? */
static _Bool ccs_readonly_mode = false;
/* Refresh interval in second. 0 means no auto refresh. */
static unsigned int ccs_refresh_interval = 0;
/* Need to reload the screen due to auto refresh? */
static _Bool ccs_need_reload = false;
/* Policy file's name. */
static const char *ccs_policy_file = NULL;
/* Caption of the current screen. */
static const char *ccs_list_caption = NULL;
/* Currently selected domain. */
static char *ccs_current_domain = NULL;
/* Currently selected PID. */
static unsigned int ccs_current_pid = 0;
/* Currently active screen's index. */
static enum ccs_screen_type ccs_current_screen = CCS_SCREEN_DOMAIN_LIST;
/*
 * Array of "initialize_domain"/"no_initialize_domain"/"keep_domain"/
 *"no_keep_domain" entries.
 */
static struct ccs_transition_control_entry *ccs_transition_control_list = NULL;
/* Length of ccs_transition_control_list array. */
static int ccs_transition_control_list_len = 0;
/* Sort profiles by value? */
static _Bool ccs_profile_sort_type = false;
/* Number of domain initializer source domains. */
static int ccs_unnumbered_domain_count = 0;
/* Width of CUI screen. */
static int ccs_window_width = 0;
/* Height of CUI screen. */
static int ccs_window_height = 0;
/* Index of currently selected line on each screen. */
static int ccs_current_item_index[CCS_MAXSCREEN];
/* Current cursor position on CUI screen. */
int ccs_current_y[CCS_MAXSCREEN];
/* Number of entries available on each screen. */
int ccs_list_item_count[CCS_MAXSCREEN];
/* Lines available for displaying ACL entries.  */
static int ccs_body_lines = 0;
/* Columns to shift when displaying. */
static int ccs_max_eat_col[CCS_MAXSCREEN];
/* Columns to shift. */
static int ccs_eat_col = 0;
/* Max columns. */
static int ccs_max_col = 0;
/* Sort ACL by operand first? */
static _Bool ccs_acl_sort_type = false;
/* Last error message. */
static char *ccs_last_error = NULL;
/* Domain screen is dealing with process list rather than domain list? */
static _Bool ccs_domain_sort_type = false;

/* Prototypes */

static void ccs_sigalrm_handler(int sig);
static const char *ccs_get_last_name(const struct ccs_domain_policy *dp, const int index);
static _Bool ccs_keeper_domain(const struct ccs_domain_policy *dp, const int index);
static _Bool ccs_initializer_source(const struct ccs_domain_policy *dp, const int index);
static _Bool ccs_initializer_target(const struct ccs_domain_policy *dp, const int index);
static _Bool ccs_domain_unreachable(const struct ccs_domain_policy *dp, const int index);
static _Bool ccs_deleted_domain(const struct ccs_domain_policy *dp, const int index);
static const struct ccs_transition_control_entry *ccs_transition_control(const struct ccs_path_info *domainname, const char *program);
static int ccs_generic_acl_compare(const void *a, const void *b);
static int ccs_generic_acl_compare0(const void *a, const void *b);
static int ccs_string_acl_compare(const void *a, const void *b);
static int ccs_profile_entry_compare(const void *a, const void *b);
static void ccs_read_generic_policy(void);
static int ccs_add_transition_control_entry(const char *domainname, const char *program, const u8 type);
static int ccs_add_transition_control_policy(char *data, const u8 type);
static int ccs_add_path_group_entry(const char *group_name, const char *member_name, const _Bool is_delete);
static int ccs_add_path_group_policy(char *data, const _Bool is_delete);
static void ccs_assign_dis(struct ccs_domain_policy *dp, const struct ccs_path_info *domainname, const char *program);
static int ccs_domainname_attribute_compare(const void *a, const void *b);
static void ccs_read_domain_and_exception_policy(struct ccs_domain_policy *dp);
static void ccs_show_current(const struct ccs_domain_policy *dp);
static const char *ccs_eat(const char *str);
static int ccs_show_domain_line(const struct ccs_domain_policy *dp, const int index);
static int ccs_show_acl_line(const int index, const int list_indent);
static int ccs_show_profile_line(const int index);
static int ccs_show_literal_line(const int index);
static int ccs_show_stat_line(const int index);
static void ccs_show_list(const struct ccs_domain_policy *dp);
static void ccs_resize_window(void);
static void ccs_up_arrow_key(const struct ccs_domain_policy *dp);
static void ccs_down_arrow_key(const struct ccs_domain_policy *dp);
static void ccs_page_up_key(const struct ccs_domain_policy *dp);
static void ccs_page_down_key(const struct ccs_domain_policy *dp);
static void ccs_adjust_cursor_pos(const int item_count);
static void ccs_set_cursor_pos(const int index);
static int ccs_count(const unsigned char *array, const int len);
static int ccs_count2(const struct ccs_generic_acl *array, int len);
static _Bool ccs_select_item(struct ccs_domain_policy *dp, const int index);
static int ccs_generic_acl_compare(const void *a, const void *b);
static void ccs_delete_entry(struct ccs_domain_policy *dp, const int index);
static void ccs_add_entry(struct ccs_readline_data *rl);
static void ccs_find_entry(const struct ccs_domain_policy *dp, const _Bool input, const _Bool forward, const int current, struct ccs_readline_data *rl);
static void ccs_set_profile(struct ccs_domain_policy *dp, const int current);
static void ccs_set_level(const int current);
static void ccs_set_quota(const int current);
static int ccs_select_window(const struct ccs_domain_policy *dp, const int current);
static _Bool ccs_show_command_key(const int screen, const _Bool readonly);
static int ccs_generic_list_loop(struct ccs_domain_policy *dp);
static void ccs_copy_file(const char *source, const char *dest);
static FILE *ccs_editpolicy_open_write(const char *filename);

/* Utility Functions */

/**
 * ccs_copy_file - Copy local file to local or remote file.
 *
 * @source: Local file.
 * @dest:   Local or remote file name.
 *
 * Returns nothing.
 */
static void ccs_copy_file(const char *source, const char *dest)
{
	FILE *fp_in = fopen(source, "r");
	FILE *fp_out = fp_in ? ccs_editpolicy_open_write(dest) : NULL;
	while (fp_in && fp_out) {
		int c = fgetc(fp_in);
		if (c == EOF)
			break;
		fputc(c, fp_out);
	}
	if (fp_out)
		fclose(fp_out);
	if (fp_in)
		fclose(fp_in);
}

/**
 * ccs_get_last_name - Get last component of a domainname.
 *
 * @dp:    Pointer to "const struct ccs_domain_policy".
 * @index: Index in the @dp array.
 *
 * Returns the last componet of the domainname.
 */
static const char *ccs_get_last_name(const struct ccs_domain_policy *dp,
				     const int index)
{
	const char *cp0 = ccs_domain_name(dp, index);
	const char *cp1 = strrchr(cp0, ' ');
	if (cp1)
		return cp1 + 1;
	return cp0;
}

/**
 * ccs_count - Count non-zero elements in an array.
 *
 * @array: Pointer to "const unsigned char".
 * @len:   Length of @array array.
 *
 * Returns number of non-zero elements.
 */
static int ccs_count(const unsigned char *array, const int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i])
			c++;
	return c;
}

/**
 * ccs_count2 - Count non-zero elements in a "struct ccs_generic_acl" array.
 *
 * @array: Pointer to "const struct ccs_generic_acl".
 * @len:   Length of @array array.
 *
 * Returns number of non-zero elements.
 */
static int ccs_count2(const struct ccs_generic_acl *array, int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i].selected)
			c++;
	return c;
}

/**
 * ccs_count3 - Count non-zero elements in a "struct ccs_task_entry" array.
 *
 * @array: Pointer to "const struct ccs_task_entry".
 * @len:   Length of @array array.
 *
 * Returns number of non-zero elements.
 */
static int ccs_count3(const struct ccs_task_entry *array, int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i].selected)
			c++;
	return c;
}

/**
 * ccs_keeper_domain - Check whether the given domain is marked as "keep_domain".
 *
 * @dp:    Pointer to "const struct ccs_domain_policy".
 * @index: Index in the @dp array.
 *
 * Returns true if the given domain is marked as "keep_domain",
 * false otherwise.
 */
static _Bool ccs_keeper_domain(const struct ccs_domain_policy *dp,
			       const int index)
{
	return dp->list[index].is_dk;
}

/**
 * ccs_initializer_source - Check whether the given domain is marked as "initialize_domain".
 *
 * @dp:    Pointer to "const struct ccs_domain_policy".
 * @index: Index in the @dp array.
 *
 * Returns true if the given domain is marked as "initialize_domain",
 * false otherwise.
 */
static _Bool ccs_initializer_source(const struct ccs_domain_policy *dp,
				    const int index)
{
	return dp->list[index].is_dis;
}

/**
 * ccs_initializer_target - Check whether the given domain is a target of "initialize_domain".
 *
 * @dp:    Pointer to "const struct ccs_domain_policy".
 * @index: Index in the @dp array.
 *
 * Returns true if the given domain is a target of "initialize_domain",
 * false otherwise.
 */
static _Bool ccs_initializer_target(const struct ccs_domain_policy *dp,
				    const int index)
{
	return dp->list[index].is_dit;
}

/**
 * ccs_domain_unreachable - Check whether the given domain is unreachable or not.
 *
 * @dp:    Pointer to "const struct ccs_domain_policy".
 * @index: Index in the @dp array.
 *
 * Returns true if the given domain is unreachable, false otherwise.
 *
 * TODO: Check "task auto_domain_transition" and
 * "task manual_domain_transition" which allow other domains to reach
 * the given domain.
 */
static _Bool ccs_domain_unreachable(const struct ccs_domain_policy *dp,
				    const int index)
{
	return dp->list[index].is_du;
}

/**
 * ccs_deleted_domain - Check whether the given domain is marked as deleted or not.
 *
 * @dp:    Pointer to "const struct ccs_domain_policy".
 * @index: Index in the @dp array.
 *
 * Returns true if the given domain is marked as deleted, false otherwise.
 */
static _Bool ccs_deleted_domain(const struct ccs_domain_policy *dp,
				const int index)
{
	return dp->list[index].is_dd;
}

static int ccs_generic_acl_compare0(const void *a, const void *b)
{
	const struct ccs_generic_acl *a0 = (struct ccs_generic_acl *) a;
	const struct ccs_generic_acl *b0 = (struct ccs_generic_acl *) b;
	const char *a1 = ccs_directives[a0->directive].alias;
	const char *b1 = ccs_directives[b0->directive].alias;
	const char *a2 = a0->operand;
	const char *b2 = b0->operand;
	const int ret = strcmp(a1, b1);
	if (ret)
		return ret;
	return strcmp(a2, b2);
}

static int ccs_string_acl_compare(const void *a, const void *b)
{
	const struct ccs_generic_acl *a0 = (struct ccs_generic_acl *) a;
	const struct ccs_generic_acl *b0 = (struct ccs_generic_acl *) b;
	const char *a1 = a0->operand;
	const char *b1 = b0->operand;
	return strcmp(a1, b1);
}

static int ccs_add_transition_control_policy(char *data, const u8 type)
{
	char *domainname = strstr(data, " from ");
	if (domainname) {
		*domainname = '\0';
		domainname += 6;
	} else if (type == CCS_TRANSITION_CONTROL_NO_KEEP ||
		   type == CCS_TRANSITION_CONTROL_KEEP) {
		domainname = data;
		data = NULL;
	}
	return ccs_add_transition_control_entry(domainname, data, type);
}

static int ccs_add_path_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return ccs_add_path_group_entry(data, cp, is_delete);
}

static void ccs_assign_dis(struct ccs_domain_policy *dp,
			   const struct ccs_path_info *domainname,
			   const char *program)
{
	const struct ccs_transition_control_entry *d_t =
		ccs_transition_control(domainname, program);
	if (d_t && d_t->type == CCS_TRANSITION_CONTROL_INITIALIZE) {
		char *line;
		int source;
		ccs_get();
		line = ccs_shprintf("%s %s", domainname->name, program);
		ccs_normalize_line(line);
		source = ccs_assign_domain(dp, line, true, false);
		if (source == EOF)
			ccs_out_of_memory();
		line = ccs_shprintf(CCS_ROOT_NAME " %s", program);
		dp->list[source].target_domainname = strdup(line);
		if (!dp->list[source].target_domainname)
			ccs_out_of_memory();
		ccs_put();
	}
}

static int ccs_domainname_attribute_compare(const void *a, const void *b)
{
	const struct ccs_domain_info *a0 = a;
	const struct ccs_domain_info *b0 = b;
	const int k = strcmp(a0->domainname->name, b0->domainname->name);
	if ((k > 0) || (!k && !a0->is_dis && b0->is_dis))
		return 1;
	return k;
}

static const char *ccs_transition_type[CCS_MAX_TRANSITION_TYPE] = {
	[CCS_TRANSITION_CONTROL_INITIALIZE] = "initialize_domain ",
	[CCS_TRANSITION_CONTROL_NO_INITIALIZE] = "no_initialize_domain ",
	[CCS_TRANSITION_CONTROL_KEEP] = "keep_domain ",
	[CCS_TRANSITION_CONTROL_NO_KEEP] = "no_keep_domain ",
};

/**
 * ccs_find_target_domain - Find the initialize_domain target domain.
 *
 * @dp:    Pointer to "const struct ccs_domain_policy".
 * @index: Index in the @dp array.
 *
 * Returns index in the @dp array if found, EOF otherwise.
 */
static int ccs_find_target_domain(const struct ccs_domain_policy *dp,
				  const int index)
{
	return ccs_find_domain(dp, dp->list[index].target_domainname, false,
			       false);
}

/**
 * ccs_show_domain_line - Show a line of the domain transition tree. 
 *
 * @dp:    Pointer to "const struct ccs_domain_policy".
 * @index: Index in the @dp array.
 *
 * Returns length of the printed line.
 */
static int ccs_show_domain_line(const struct ccs_domain_policy *dp,
				const int index)
{
	int tmp_col = 0;
	const struct ccs_transition_control_entry *transition_control;
	char *line;
	const char *sp;
	const int number = dp->list[index].number;
	int redirect_index;
	const bool is_dis = ccs_initializer_source(dp, index);
	const bool is_deleted = ccs_deleted_domain(dp, index);
	if (number >= 0) {
		printw("%c%4d:", dp->list_selected[index] ? '&' : ' ', number);
		if (dp->list[index].profile_assigned)
			printw("%3u", dp->list[index].profile);
		else
			printw("???");
		printw(" %c%c%c ", ccs_keeper_domain(dp, index) ? '#' : ' ',
		       ccs_initializer_target(dp, index) ? '*' : ' ',
		       ccs_domain_unreachable(dp, index) ? '!' : ' ');
	} else
		printw("              ");
	tmp_col += 14;
	sp = ccs_domain_name(dp, index);
	while (true) {
		const char *cp = strchr(sp, ' ');
		if (!cp)
			break;
		printw("%s", ccs_eat("    "));
		tmp_col += 4;
		sp = cp + 1;
	}
	if (is_deleted) {
		printw("%s", ccs_eat("( "));
		tmp_col += 2;
	}
	printw("%s", ccs_eat(sp));
	tmp_col += strlen(sp);
	if (is_deleted) {
		printw("%s", ccs_eat(" )"));
		tmp_col += 2;
	}
	transition_control = dp->list[index].d_t;
	if (!transition_control || is_dis)
		goto no_transition_control;
	ccs_get();
	line = ccs_shprintf(" ( %s%s from %s )",
			    ccs_transition_type[transition_control->type],
			    transition_control->program ?
			    transition_control->program->name : "any",
			    transition_control->domainname ?
			    transition_control->domainname->name : "any");
	printw("%s", ccs_eat(line));
	tmp_col += strlen(line);
	ccs_put();
	goto done;
no_transition_control:
	if (!is_dis)
		goto done;
	ccs_get();
	redirect_index = ccs_find_target_domain(dp, index);
	if (redirect_index >= 0)
		line = ccs_shprintf(" ( -> %d )",
				    dp->list[redirect_index].number);
	else
		line = ccs_shprintf(" ( -> Not Found )");
	printw("%s", ccs_eat(line));
	tmp_col += strlen(line);
	ccs_put();
done:
	return tmp_col;
}

static int ccs_show_acl_line(const int index, const int list_indent)
{
	const enum ccs_editpolicy_directives directive =
		ccs_generic_acl_list[index].directive;
	const char *cp1 = ccs_directives[directive].alias;
	const char *cp2 = ccs_generic_acl_list[index].operand;
	int len = list_indent - ccs_directives[directive].alias_len;
	printw("%c%4d: %s ",
	       ccs_generic_acl_list[index].selected ? '&' : ' ',
	       index, ccs_eat(cp1));
	while (len-- > 0)
		printw("%s", ccs_eat(" "));
	printw("%s", ccs_eat(cp2));
	return strlen(cp1) + strlen(cp2) + 8 + list_indent;
}

static int ccs_show_profile_line(const int index)
{
	const char *cp = ccs_generic_acl_list[index].operand;
	const u16 profile = ccs_generic_acl_list[index].directive;
	char number[8] = "";
	if (profile <= 256)
		snprintf(number, sizeof(number) - 1, "%3u-", profile);
	printw("%c%4d: %s", ccs_generic_acl_list[index].selected ? '&' : ' ',
	       index, ccs_eat(number));
	printw("%s ", ccs_eat(cp));
	return strlen(number) + strlen(cp) + 8;
}

static int ccs_show_literal_line(const int index)
{
	const char *cp = ccs_generic_acl_list[index].operand;
	printw("%c%4d: %s ",
	       ccs_generic_acl_list[index].selected ? '&' : ' ',
	       index, ccs_eat(cp));
	return strlen(cp) + 8;
}

static int ccs_show_stat_line(const int index)
{
	char *line;
	unsigned int now;
	ccs_get();
	line = ccs_shprintf("%s", ccs_generic_acl_list[index].operand);
	if (line[0])
		printw("%s", ccs_eat(line));
	now = strlen(line);
	ccs_put();
	return now;
}

static _Bool ccs_show_command_key(const int screen, const _Bool readonly)
{
	int c;
	clear();
	printw("Commands available for this screen are:\n\n");
	printw("Q/q        Quit this editor.\n");
	printw("R/r        Refresh to the latest information.\n");
	switch (screen) {
	case CCS_SCREEN_STAT_LIST:
		break;
	default:
		printw("F/f        Find first.\n");
		printw("N/n        Find next.\n");
		printw("P/p        Find previous.\n");
	}
	printw("W/w        Switch to selected screen.\n");
	/* printw("Tab        Switch to next screen.\n"); */
	switch (screen) {
	case CCS_SCREEN_STAT_LIST:
		break;
	default:
		printw("Insert     Copy an entry at the cursor position to "
		       "history buffer.\n");
		printw("Space      Invert selection state of an entry at "
		       "the cursor position.\n");
		printw("C/c        Copy selection state of an entry at "
		       "the cursor position to all entries below the cursor "
		       "position.\n");
	}
	switch (screen) {
	case CCS_SCREEN_DOMAIN_LIST:
		if (ccs_domain_sort_type) {
			printw("S/s        Set profile number of selected "
			       "processes.\n");
			printw("Enter      Edit ACLs of a process at the "
			       "cursor position.\n");
		} else {
			if (!readonly) {
				printw("A/a        Add a new domain.\n");
				printw("D/d        Delete selected domains.\n");
				printw("S/s        Set profile number of "
				       "selected domains.\n");
			}
			printw("Enter      Edit ACLs of a domain at the "
			       "cursor position.\n");
		}
		break;
	case CCS_SCREEN_STAT_LIST:
		if (!readonly)
			printw("S/s        Set memory quota of selected "
			       "items.\n");
		break;
	case CCS_SCREEN_PROFILE_LIST:
		if (!readonly)
			printw("S/s        Set mode of selected items.\n");
		break;
	}
	switch (screen) {
	case CCS_SCREEN_EXCEPTION_LIST:
	case CCS_SCREEN_ACL_LIST:
	case CCS_SCREEN_MANAGER_LIST:
		if (!readonly) {
			printw("A/a        Add a new entry.\n");
			printw("D/d        Delete selected entries.\n");
		}
	}
	switch (screen) {
	case CCS_SCREEN_PROFILE_LIST:
		if (!readonly)
			printw("A/a        Define a new profile.\n");
	}
	switch (screen) {
	case CCS_SCREEN_ACL_LIST:
		printw("O/o        Set selection state to other entries "
		       "included in an entry at the cursor position.\n");
		/* Fall through. */
	case CCS_SCREEN_PROFILE_LIST:
		printw("@          Switch sort type.\n");
		break;
	case CCS_SCREEN_DOMAIN_LIST:
		if (!ccs_offline_mode)
			printw("@          Switch domain/process list.\n");
	}
	printw("Arrow-keys and PageUp/PageDown/Home/End keys "
	       "for scroll.\n\n");
	printw("Press '?' to escape from this help.\n");
	refresh();
	while (true) {
		c = ccs_getch2();
		if (c == '?' || c == EOF)
			break;
		if (c == 'Q' || c == 'q')
			return false;
	}
	return true;
}

/* Main Functions */

static void ccs_close_write(FILE *fp)
{
	if (ccs_network_mode) {
		fputc(0, fp);
		fflush(fp);
		fgetc(fp);
	}
	fclose(fp);
}

static void ccs_set_error(const char *filename)
{
	if (filename) {
		const int len = strlen(filename) + 128;
		ccs_last_error = realloc(ccs_last_error, len);
		if (!ccs_last_error)
			ccs_out_of_memory();
		memset(ccs_last_error, 0, len);
		snprintf(ccs_last_error, len - 1, "Can't open %s .", filename);
	} else {
		free(ccs_last_error);
		ccs_last_error = NULL;
	}
}

static FILE *ccs_editpolicy_open_write(const char *filename)
{
	if (ccs_network_mode) {
		FILE *fp = ccs_open_write(filename);
		if (!fp)
			ccs_set_error(filename);
		return fp;
	} else if (ccs_offline_mode) {
		char request[1024];
		int fd[2];
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd)) {
			fprintf(stderr, "socketpair()\n");
			exit(1);
		}
		if (shutdown(fd[0], SHUT_RD))
			goto out;
		memset(request, 0, sizeof(request));
		snprintf(request, sizeof(request) - 1, "POST %s", filename);
		ccs_send_fd(request, &fd[1]);
		return fdopen(fd[0], "w");
out:
		close(fd[1]);
		close(fd[0]);
		exit(1);
	} else {
		FILE *fp;
		if (ccs_readonly_mode)
			return NULL;
		fp = ccs_open_write(filename);
		if (!fp)
			ccs_set_error(filename);
		return fp;
	}
}

static FILE *ccs_editpolicy_open_read(const char *filename)
{
	if (ccs_network_mode) {
		return ccs_open_read(filename);
	} else if (ccs_offline_mode) {
		char request[1024];
		int fd[2];
		FILE *fp;
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd)) {
			fprintf(stderr, "socketpair()\n");
			exit(1);
		}
		if (shutdown(fd[0], SHUT_WR))
			goto out;
		fp = fdopen(fd[0], "r");
		if (!fp)
			goto out;
		memset(request, 0, sizeof(request));
		snprintf(request, sizeof(request) - 1, "GET %s", filename);
		ccs_send_fd(request, &fd[1]);
		return fp;
out:
		close(fd[1]);
		close(fd[0]);
		exit(1);
	} else {
		return fopen(filename, "r");
	}
}

static int ccs_open2(const char *filename, int mode)
{
	const int fd = open(filename, mode);
	if (fd == EOF && errno != ENOENT)
		ccs_set_error(filename);
	return fd;
}

static void ccs_sigalrm_handler(int sig)
{
	ccs_need_reload = true;
	alarm(ccs_refresh_interval);
}

static const char *ccs_eat(const char *str)
{
	while (*str && ccs_eat_col) {
		str++;
		ccs_eat_col--;
	}
	return str;
}

static const struct ccs_transition_control_entry *ccs_transition_control
(const struct ccs_path_info *domainname, const char *program)
{
	int i;
	u8 type;
	struct ccs_path_info last_name;
	last_name.name = strrchr(domainname->name, ' ');
	if (last_name.name)
		last_name.name++;
	else
		last_name.name = domainname->name;
	ccs_fill_path_info(&last_name);
	for (type = 0; type < CCS_MAX_TRANSITION_TYPE; type++) {
next:
		for (i = 0; i < ccs_transition_control_list_len; i++) {
			struct ccs_transition_control_entry *ptr
				= &ccs_transition_control_list[i];
			if (ptr->type != type)
                                continue;
			if (ptr->domainname) {
				if (!ptr->is_last_name) {
					if (ccs_pathcmp(ptr->domainname,
							domainname))
						continue;
				} else {
					if (ccs_pathcmp(ptr->domainname,
							&last_name))
						continue;
				}
			}
			if (ptr->program && strcmp(ptr->program->name, program))
				continue;
			if (type == CCS_TRANSITION_CONTROL_NO_INITIALIZE) {
				/*
				 * Do not check for initialize_domain if
				 * no_initialize_domain matched.
				 */
				type = CCS_TRANSITION_CONTROL_NO_KEEP;
				goto next;
			}
			if (type == CCS_TRANSITION_CONTROL_INITIALIZE ||
			    type == CCS_TRANSITION_CONTROL_KEEP)
				return ptr;
			else
				return NULL;
		}
	}
	return NULL;
}

static int ccs_profile_entry_compare(const void *a, const void *b)
{
	const struct ccs_generic_acl *a0 = (struct ccs_generic_acl *) a;
	const struct ccs_generic_acl *b0 = (struct ccs_generic_acl *) b;
	const char *a1 = a0->operand;
	const char *b1 = b0->operand;
	const int a2 = a0->directive;
	const int b2 = b0->directive;
	if (a2 >= 256 || b2 >= 256) {
		int i;
		static const char *global[5] = {
			"PROFILE_VERSION=",
			"PREFERENCE::audit=",
			"PREFERENCE::learning=",
			"PREFERENCE::permissive=",
			"PREFERENCE::enforcing="
		};
		for (i = 0; i < 5; i++) {
			if (!strncmp(a1, global[i], strlen(global[i])))
				return -1;
			if (!strncmp(b1, global[i], strlen(global[i])))
				return 1;
		}
	}
	if (!ccs_profile_sort_type) {
		if (a2 == b2)
			return strcmp(a1, b1);
		else
			return a2 - b2;
	} else {
		const int a3 = strcspn(a1, "=");
		const int b3 = strcspn(b1, "=");
		const int c = strncmp(a1, b1, a3 >= b3 ? b3 : a3);
		if (c)
			return c;
		if (a3 != b3)
			return a3 - b3;
		else
			return a2 - b2;
	}
}

static void ccs_read_generic_policy(void)
{
	FILE *fp = NULL;
	_Bool flag = false;
	while (ccs_generic_acl_list_count)
		free((void *)
		     ccs_generic_acl_list[--ccs_generic_acl_list_count].
		     operand);
	if (ccs_current_screen == CCS_SCREEN_ACL_LIST) {
		if (ccs_network_mode)
			/* We can read after write. */
			fp = ccs_editpolicy_open_write(ccs_policy_file);
		else if (!ccs_offline_mode)
			/* Don't set error message if failed. */
			fp = fopen(ccs_policy_file, "r+");
		if (fp) {
			if (ccs_domain_sort_type)
				fprintf(fp, "select pid=%u\n",
					ccs_current_pid);
			else
				fprintf(fp, "select domain=%s\n",
					ccs_current_domain);
			if (ccs_network_mode)
				fputc(0, fp);
			fflush(fp);
		}
	}
	if (!fp)
		fp = ccs_editpolicy_open_read(ccs_policy_file);
	if (!fp) {
		ccs_set_error(ccs_policy_file);
		return;
	}
	ccs_freadline_raw = ccs_current_screen == CCS_SCREEN_STAT_LIST;
	ccs_get();
	while (true) {
		char *line = ccs_freadline(fp);
		enum ccs_editpolicy_directives directive;
		char *cp;
		if (!line)
			break;
		if (ccs_current_screen == CCS_SCREEN_ACL_LIST) {
			if (ccs_domain_def(line)) {
				flag = !strcmp(line, ccs_current_domain);
				continue;
			}
			if (!flag || !line[0] ||
			    !strncmp(line, "use_profile ", 12))
				continue;
		} else {
			if (!line[0])
				continue;
		}
		switch (ccs_current_screen) {
		case CCS_SCREEN_EXCEPTION_LIST:
		case CCS_SCREEN_ACL_LIST:
			directive = ccs_find_directive(true, line);
			if (directive == CCS_DIRECTIVE_NONE)
				continue;
			break;
		case CCS_SCREEN_PROFILE_LIST:
			cp = strchr(line, '-');
			if (cp) {
				*cp++ = '\0';
				directive = atoi(line);
				memmove(line, cp, strlen(cp) + 1);
			} else
				directive = (u16) -1;
			break;
		default:
			directive = CCS_DIRECTIVE_NONE;
			break;
		}
		ccs_generic_acl_list =
			realloc(ccs_generic_acl_list,
				(ccs_generic_acl_list_count + 1) *
				sizeof(struct ccs_generic_acl));
		if (!ccs_generic_acl_list)
			ccs_out_of_memory();
		cp = strdup(line);
		if (!cp)
			ccs_out_of_memory();
		ccs_generic_acl_list[ccs_generic_acl_list_count].directive =
			directive;
		ccs_generic_acl_list[ccs_generic_acl_list_count].selected = 0;
		ccs_generic_acl_list[ccs_generic_acl_list_count++].operand = cp;
	}
	ccs_put();
	ccs_freadline_raw = false;
	fclose(fp);
	switch (ccs_current_screen) {
	case CCS_SCREEN_ACL_LIST:
		qsort(ccs_generic_acl_list, ccs_generic_acl_list_count,
		      sizeof(struct ccs_generic_acl), ccs_generic_acl_compare);
		break;
	case CCS_SCREEN_EXCEPTION_LIST:
		qsort(ccs_generic_acl_list, ccs_generic_acl_list_count,
		      sizeof(struct ccs_generic_acl), ccs_generic_acl_compare0);
		break;
	case CCS_SCREEN_PROFILE_LIST:
		qsort(ccs_generic_acl_list, ccs_generic_acl_list_count,
		      sizeof(struct ccs_generic_acl), ccs_profile_entry_compare);
		break;
	case CCS_SCREEN_STAT_LIST:
		break;
	default:
		qsort(ccs_generic_acl_list, ccs_generic_acl_list_count,
		      sizeof(struct ccs_generic_acl), ccs_string_acl_compare);
	}
}

static int ccs_add_transition_control_entry(const char *domainname,
					    const char *program,
					    const u8 type)
{
	void *vp;
	struct ccs_transition_control_entry *ptr;
	_Bool is_last_name = false;
	if (program && strcmp(program, "any")) {
		if (!ccs_correct_path(program))
			return -EINVAL;
	}
	if (domainname && strcmp(domainname, "any")) {
		if (!ccs_correct_domain(domainname)) {
			if (!ccs_correct_path(domainname))
				return -EINVAL;
			is_last_name = true;
		}
	}
	vp = realloc(ccs_transition_control_list,
		     (ccs_transition_control_list_len + 1) *
		     sizeof(struct ccs_transition_control_entry));
	if (!vp)
		ccs_out_of_memory();
	ccs_transition_control_list = vp;
	ptr = &ccs_transition_control_list[ccs_transition_control_list_len++];
	memset(ptr, 0, sizeof(struct ccs_transition_control_entry));
	if (program && strcmp(program, "any")) {
		ptr->program = ccs_savename(program);
		if (!ptr->program)
			ccs_out_of_memory();
	}
	if (domainname && strcmp(domainname, "any")) {
		ptr->domainname = ccs_savename(domainname);
		if (!ptr->domainname)
			ccs_out_of_memory();
	}
	ptr->type = type;
	ptr->is_last_name = is_last_name;
	return 0;
}

static int ccs_add_path_group_entry(const char *group_name, const char *member_name,
				const _Bool is_delete)
{
	const struct ccs_path_info *saved_group_name;
	const struct ccs_path_info *saved_member_name;
	int i;
	int j;
	struct ccs_path_group_entry *group = NULL;
	if (!ccs_correct_word(group_name) || !ccs_correct_word(member_name))
		return -EINVAL;
	saved_group_name = ccs_savename(group_name);
	saved_member_name = ccs_savename(member_name);
	if (!saved_group_name || !saved_member_name)
		return -ENOMEM;
	for (i = 0; i < ccs_path_group_list_len; i++) {
		group = &ccs_path_group_list[i];
		if (saved_group_name != group->group_name)
			continue;
		for (j = 0; j < group->member_name_len; j++) {
			if (group->member_name[j] != saved_member_name)
				continue;
			if (!is_delete)
				return 0;
			while (j < group->member_name_len - 1)
				group->member_name[j] =
					group->member_name[j + 1];
			group->member_name_len--;
			return 0;
		}
		break;
	}
	if (is_delete)
		return -ENOENT;
	if (i == ccs_path_group_list_len) {
		ccs_path_group_list = realloc(ccs_path_group_list,
					  (ccs_path_group_list_len + 1) *
					  sizeof(struct ccs_path_group_entry));
		if (!ccs_path_group_list)
			ccs_out_of_memory();
		group = &ccs_path_group_list[ccs_path_group_list_len++];
		memset(group, 0, sizeof(struct ccs_path_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1)
				     * sizeof(const struct ccs_path_info *));
	if (!group->member_name)
		ccs_out_of_memory();
	group->member_name[group->member_name_len++] = saved_member_name;
	return 0;
}

static void ccs_read_domain_and_exception_policy(struct ccs_domain_policy *dp)
{
	FILE *fp;
	int i;
	int j;
	int index;
	int max_index;
	static char **ccs_jump_list = NULL;
	static int ccs_jump_list_len = 0;
	while (ccs_jump_list_len)
		free(ccs_jump_list[--ccs_jump_list_len]);
	ccs_clear_domain_policy(dp);
	ccs_transition_control_list_len = 0;
	ccs_editpolicy_clear_groups();
	ccs_assign_domain(dp, CCS_ROOT_NAME, false, false);

	/* Load all domain list. */
	fp = NULL;
	if (ccs_network_mode)
		/* We can read after write. */
		fp = ccs_editpolicy_open_write(ccs_policy_file);
	else if (!ccs_offline_mode)
		/* Don't set error message if failed. */
		fp = fopen(ccs_policy_file, "r+");
	if (fp) {
		fprintf(fp, "select execute\n");
		if (ccs_network_mode)
			fputc(0, fp);
		fflush(fp);
	}
	if (!fp)
		fp = ccs_editpolicy_open_read(CCS_PROC_POLICY_DOMAIN_POLICY);
	if (!fp) {
		ccs_set_error(CCS_PROC_POLICY_DOMAIN_POLICY);
		goto no_domain;
	}
	index = EOF;
	ccs_get();
	while (true) {
		char *line = ccs_freadline(fp);
		unsigned int profile;
		if (!line)
			break;
		if (ccs_domain_def(line)) {
			index = ccs_assign_domain(dp, line, false, false);
			continue;
		} else if (index == EOF) {
			continue;
		}
		if (ccs_str_starts(line, "task auto_execute_handler ") ||
		    ccs_str_starts(line, "task denied_execute_handler ") ||
		    ccs_str_starts(line, "file execute ")) {
			char *cp = strchr(line, ' ');
			if (cp)
				*cp = '\0';
			if (*line == '@' || ccs_correct_path(line))
				ccs_add_string_entry(dp, line, index);
		} else if (ccs_str_starts(line,
					  "task auto_domain_transition ") ||
			   ccs_str_starts(line,
					  "task manual_domain_transition ")) {
			static char domainname[4096];
			int source;
			char *m;
			int i;
			for (i = 0; line[i]; i++)
				if (line[i] == ' ' && line[i + 1] != '/') {
					line[i] = '\0';
					break;
				}
			if (!ccs_correct_domain(line))
				continue;
			ccs_jump_list = realloc(ccs_jump_list,
						(ccs_jump_list_len + 1)
						* sizeof(char *));
			if (!ccs_jump_list)
				ccs_out_of_memory();
			ccs_jump_list[ccs_jump_list_len] = strdup(line);
			if (!ccs_jump_list[ccs_jump_list_len])
				ccs_out_of_memory();
			ccs_jump_list_len++;
			m = strrchr(line, ' ');
			if (m)
				m++;
			else
				m = line;
			snprintf(domainname, sizeof(domainname) - 1, "%s %s",
				 ccs_domain_name(dp, index), m);
			domainname[sizeof(domainname) - 1] = '\0';
			ccs_normalize_line(domainname);
			source = ccs_assign_domain(dp, domainname, true, false);
			if (source == EOF)
				ccs_out_of_memory();
			dp->list[source].target_domainname = strdup(line);
			if (!dp->list[source].target_domainname)
				ccs_out_of_memory();
		} else if (sscanf(line, "use_profile %u", &profile) == 1) {
			dp->list[index].profile = (u8) profile;
			dp->list[index].profile_assigned = 1;
		} else if (sscanf(line, "use_group %u", &profile) == 1) {
			dp->list[index].group = (u8) profile;
		}
	}
	ccs_put();
	fclose(fp);
no_domain:

	max_index = dp->list_len;

	/* Load domain_initializer list, domain_keeper list. */
	fp = ccs_editpolicy_open_read(CCS_PROC_POLICY_EXCEPTION_POLICY);
	if (!fp) {
		ccs_set_error(CCS_PROC_POLICY_EXCEPTION_POLICY);
		goto no_exception;
	}
	ccs_get();
	while (true) {
		unsigned int group;
		char *line = ccs_freadline(fp);
		if (!line)
			break;
		if (ccs_str_starts(line, "initialize_domain "))
			ccs_add_transition_control_policy(line, CCS_TRANSITION_CONTROL_INITIALIZE);
		else if (ccs_str_starts(line, "no_initialize_domain "))
			ccs_add_transition_control_policy(line, CCS_TRANSITION_CONTROL_NO_INITIALIZE);
		else if (ccs_str_starts(line, "keep_domain "))
			ccs_add_transition_control_policy(line, CCS_TRANSITION_CONTROL_KEEP);
		else if (ccs_str_starts(line, "no_keep_domain "))
			ccs_add_transition_control_policy(line, CCS_TRANSITION_CONTROL_NO_KEEP);
		else if (ccs_str_starts(line, "path_group "))
			ccs_add_path_group_policy(line, false);
		else if (ccs_str_starts(line, "address_group "))
			ccs_add_address_group_policy(line, false);
		else if (ccs_str_starts(line, "number_group "))
			ccs_add_number_group_policy(line, false);
		else if (sscanf(line, "acl_group %u", &group) == 1
			 && group < 256) {
			char *cp = strchr(line + 10, ' ');
			if (cp)
				line = cp + 1;
			if (ccs_str_starts(line,
					   "task auto_execute_handler ") ||
			    ccs_str_starts(line,
					   "task denied_execute_handler ") ||
			    ccs_str_starts(line, "file execute ")) {
				cp = strchr(line, ' ');
				if (cp)
					*cp = '\0';
				if (*line == '@' || ccs_correct_path(line)) {
					for (index = 0; index < max_index;
					     index++)
						if (dp->list[index].group
						    == group)
							ccs_add_string_entry(dp, line, index);
				}
			}
		}
	}
	ccs_put();
	fclose(fp);
no_exception:

	/* Find unreachable domains. */
	for (index = 0; index < max_index; index++) {
		char *line;
		ccs_get();
		line = ccs_shprintf("%s", ccs_domain_name(dp, index));
		while (true) {
			const struct ccs_transition_control_entry *d_t;
			struct ccs_path_info parent;
			char *cp = strrchr(line, ' ');
			if (!cp)
				break;
			*cp++ = '\0';
			parent.name = line;
			ccs_fill_path_info(&parent);
			d_t = ccs_transition_control(&parent, cp);
			if (!d_t)
				continue;
			/* Initializer under <kernel> is reachable. */
			if (d_t->type == CCS_TRANSITION_CONTROL_INITIALIZE &&
			    parent.total_len == CCS_ROOT_NAME_LEN)
				break;
			dp->list[index].d_t = d_t;
			continue;
		}
		ccs_put();
		if (dp->list[index].d_t)
			dp->list[index].is_du = true;
	}

	/* Find domain initializer target domains. */
	for (index = 0; index < max_index; index++) {
		char *cp = strchr(ccs_domain_name(dp, index), ' ');
		if (!cp || strchr(cp + 1, ' '))
			continue;
		for (i = 0; i < ccs_transition_control_list_len; i++) {
			struct ccs_transition_control_entry *ptr
				= &ccs_transition_control_list[i];
			if (ptr->type != CCS_TRANSITION_CONTROL_INITIALIZE)
				continue;
			if (ptr->program && strcmp(ptr->program->name, cp + 1))
				continue;
			dp->list[index].is_dit = true;
		}
	}

	/* Find domain keeper domains. */
	for (index = 0; index < max_index; index++) {
		for (i = 0; i < ccs_transition_control_list_len; i++) {
			struct ccs_transition_control_entry *ptr
				= &ccs_transition_control_list[i];
			char *cp;
			if (ptr->type != CCS_TRANSITION_CONTROL_KEEP)
				continue;
			if (!ptr->is_last_name) {
				if (ptr->domainname &&
				    ccs_pathcmp(ptr->domainname,
						dp->list[index].domainname))
					continue;
				dp->list[index].is_dk = true;
				continue;
			}
			cp = strrchr(dp->list[index].domainname->name,
				     ' ');
			if (!cp || (ptr->domainname->name &&
				    strcmp(ptr->domainname->name, cp + 1)))
				continue;
			dp->list[index].is_dk = true;
		}
	}

	/* Create domain initializer source domains. */
	for (index = 0; index < max_index; index++) {
		const struct ccs_path_info *domainname
			= dp->list[index].domainname;
		const struct ccs_path_info **string_ptr
			= dp->list[index].string_ptr;
		const int max_count = dp->list[index].string_count;
		/* Don't create source domain under <kernel> because
		   they will become ccs_target domains. */
		if (domainname->total_len == CCS_ROOT_NAME_LEN)
			continue;
		for (i = 0; i < max_count; i++) {
			const struct ccs_path_info *cp = string_ptr[i];
			struct ccs_path_group_entry *group;
			if (cp->name[0] != '@') {
				ccs_assign_dis(dp, domainname, cp->name);
				continue;
			}
			group = ccs_find_path_group(cp->name + 1);
			if (!group)
				continue;
			for (j = 0; j < group->member_name_len; j++) {
				cp = group->member_name[j];
				ccs_assign_dis(dp, domainname, cp->name);
			}
		}
	}

	/* Create domain jump target domains. */
	for (i = 0; i < ccs_jump_list_len; i++) {
		int index = ccs_find_domain(dp, ccs_jump_list[i], false,
					    false);
		if (index != EOF)
			dp->list[index].is_dit = true;
	}

	//max_index = dp->list_len;

	/* Create missing parent domains. */
	for (index = 0; index < max_index; index++) {
		char *line;
		ccs_get();
		line = ccs_shprintf("%s", ccs_domain_name(dp, index));
		while (true) {
			char *cp = strrchr(line, ' ');
			if (!cp)
				break;
			*cp = '\0';
			if (ccs_find_domain(dp, line, false, false) != EOF)
				continue;
			if (ccs_assign_domain(dp, line, false, true) == EOF)
				ccs_out_of_memory();
		}
		ccs_put();
	}

	/* Sort by domain name. */
	qsort(dp->list, dp->list_len, sizeof(struct ccs_domain_info),
	      ccs_domainname_attribute_compare);

	/* Assign domain numbers. */
	{
		int number = 0;
		int index;
		ccs_unnumbered_domain_count = 0;
		for (index = 0; index < dp->list_len; index++) {
			if (ccs_deleted_domain(dp, index) ||
			    ccs_initializer_source(dp, index)) {
				dp->list[index].number = -1;
				ccs_unnumbered_domain_count++;
			} else {
				dp->list[index].number = number++;
			}
		}
	}

	dp->list_selected = realloc(dp->list_selected, dp->list_len);
	if (dp->list_len && !dp->list_selected)
		ccs_out_of_memory();
	memset(dp->list_selected, 0, dp->list_len);
}

static int ccs_show_process_line(const int index)
{
	char *line;
	int tmp_col = 0;
	int i;
	printw("%c%4d:%3u ", ccs_task_list[index].selected ? '&' : ' ', index,
	       ccs_task_list[index].profile);
	tmp_col += 10;
	for (i = 0; i < ccs_task_list[index].depth - 1; i++) {
		printw("%s", ccs_eat("    "));
		tmp_col += 4;
	}
	ccs_get();
	line = ccs_shprintf("%s%s (%u) %s", ccs_task_list[index].depth ?
			    " +- " : "", ccs_task_list[index].name,
			    ccs_task_list[index].pid, ccs_task_list[index].domain);
	printw("%s", ccs_eat(line));
	tmp_col += strlen(line);
	ccs_put();
	return tmp_col;
}

static void ccs_show_list(const struct ccs_domain_policy *dp)
{
	int ccs_list_indent;
	const int offset = ccs_current_item_index[ccs_current_screen];
	int i;
	int tmp_col;
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST)
		ccs_list_item_count[CCS_SCREEN_DOMAIN_LIST] =
			ccs_domain_sort_type ?
			ccs_task_list_len : dp->list_len;
	else
		ccs_list_item_count[ccs_current_screen] =
			ccs_generic_acl_list_count;
	clear();
	move(0, 0);
	if (ccs_window_height < CCS_HEADER_LINES + 1) {
		printw("Please enlarge window.");
		clrtobot();
		refresh();
		return;
	}
	/* add color */
	ccs_editpolicy_color_change
		(ccs_editpolicy_color_head(ccs_current_screen), true);
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (ccs_domain_sort_type) {
			printw("<<< Process State Viewer >>>"
			       "      %d process%s    '?' for help",
			       ccs_task_list_len,
			       ccs_task_list_len > 1 ? "es" : "");
		} else {
			int i = ccs_list_item_count[CCS_SCREEN_DOMAIN_LIST]
				- ccs_unnumbered_domain_count;
			printw("<<< Domain Transition Editor >>>"
			       "      %d domain%c    '?' for help",
			       i, i > 1 ? 's' : ' ');
		}
	} else {
		int i = ccs_list_item_count[ccs_current_screen];
		printw("<<< %s >>>"
		       "      %d entr%s    '?' for help", ccs_list_caption,
		       i, i > 1 ? "ies" : "y");
	}
	/* add color */
	ccs_editpolicy_color_change
		(ccs_editpolicy_color_head(ccs_current_screen), false);
	ccs_eat_col = ccs_max_eat_col[ccs_current_screen];
	ccs_max_col = 0;
	if (ccs_current_screen == CCS_SCREEN_ACL_LIST) {
		char *line;
		ccs_get();
		line = ccs_shprintf("%s", ccs_eat(ccs_current_domain));
		ccs_editpolicy_attr_change(A_REVERSE, true);  /* add color */
		move(2, 0);
		printw("%s", line);
		ccs_editpolicy_attr_change(A_REVERSE, false); /* add color */
		ccs_put();
	}
	ccs_list_indent = 0;
	switch (ccs_current_screen) {
	case CCS_SCREEN_EXCEPTION_LIST:
	case CCS_SCREEN_ACL_LIST:
		for (i = 0; i < ccs_list_item_count[ccs_current_screen]; i++) {
			const enum ccs_editpolicy_directives directive =
				ccs_generic_acl_list[i].directive;
			const int len = ccs_directives[directive].alias_len;
			if (len > ccs_list_indent)
				ccs_list_indent = len;
		}
		break;
	default:
		break;
	}
	for (i = 0; i < ccs_body_lines; i++) {
		const int index = offset + i;
		ccs_eat_col = ccs_max_eat_col[ccs_current_screen];
		if (index >= ccs_list_item_count[ccs_current_screen])
			break;
		move(CCS_HEADER_LINES + i, 0);
		switch (ccs_current_screen) {
		case CCS_SCREEN_DOMAIN_LIST:
			if (!ccs_domain_sort_type)
				tmp_col = ccs_show_domain_line(dp, index);
			else
				tmp_col = ccs_show_process_line(index);
			break;
		case CCS_SCREEN_EXCEPTION_LIST:
		case CCS_SCREEN_ACL_LIST:
			tmp_col = ccs_show_acl_line(index, ccs_list_indent);
			break;
		case CCS_SCREEN_PROFILE_LIST:
			tmp_col = ccs_show_profile_line(index);
			break;
		case CCS_SCREEN_STAT_LIST:
			tmp_col = ccs_show_stat_line(index);
			break;
		default:
			tmp_col = ccs_show_literal_line(index);
			break;
		}
		clrtoeol();
		tmp_col -= ccs_window_width;
		if (tmp_col > ccs_max_col)
			ccs_max_col = tmp_col;
	}
	ccs_show_current(dp);
}

static void ccs_resize_window(void)
{
	getmaxyx(stdscr, ccs_window_height, ccs_window_width);
	ccs_body_lines = ccs_window_height - CCS_HEADER_LINES;
	if (ccs_body_lines <= ccs_current_y[ccs_current_screen])
		ccs_current_y[ccs_current_screen] = ccs_body_lines - 1;
	if (ccs_current_y[ccs_current_screen] < 0)
		ccs_current_y[ccs_current_screen] = 0;
}

static void ccs_up_arrow_key(const struct ccs_domain_policy *dp)
{
	if (ccs_current_y[ccs_current_screen] > 0) {
		ccs_current_y[ccs_current_screen]--;
		ccs_show_current(dp);
	} else if (ccs_current_item_index[ccs_current_screen] > 0) {
		ccs_current_item_index[ccs_current_screen]--;
		ccs_show_list(dp);
	}
}

static void ccs_down_arrow_key(const struct ccs_domain_policy *dp)
{
	if (ccs_current_y[ccs_current_screen] < ccs_body_lines - 1) {
		if (ccs_current_item_index[ccs_current_screen]
		    + ccs_current_y[ccs_current_screen]
		    < ccs_list_item_count[ccs_current_screen] - 1) {
			ccs_current_y[ccs_current_screen]++;
			ccs_show_current(dp);
		}
	} else if (ccs_current_item_index[ccs_current_screen]
		   + ccs_current_y[ccs_current_screen]
		   < ccs_list_item_count[ccs_current_screen] - 1) {
		ccs_current_item_index[ccs_current_screen]++;
		ccs_show_list(dp);
	}
}

static void ccs_page_up_key(const struct ccs_domain_policy *dp)
{
	int p0 = ccs_current_item_index[ccs_current_screen];
	int p1 = ccs_current_y[ccs_current_screen];
	_Bool refresh;
	if (p0 + p1 > ccs_body_lines) {
		p0 -= ccs_body_lines;
		if (p0 < 0)
			p0 = 0;
	} else if (p0 + p1 > 0) {
		p0 = 0;
		p1 = 0;
	} else {
		return;
	}
	refresh = (ccs_current_item_index[ccs_current_screen] != p0);
	ccs_current_item_index[ccs_current_screen] = p0;
	ccs_current_y[ccs_current_screen] = p1;
	if (refresh)
		ccs_show_list(dp);
	else
		ccs_show_current(dp);
}

static void ccs_page_down_key(const struct ccs_domain_policy *dp)
{
	int ccs_count = ccs_list_item_count[ccs_current_screen] - 1;
	int p0 = ccs_current_item_index[ccs_current_screen];
	int p1 = ccs_current_y[ccs_current_screen];
	_Bool refresh;
	if (p0 + p1 + ccs_body_lines < ccs_count) {
		p0 += ccs_body_lines;
	} else if (p0 + p1 < ccs_count) {
		while (p0 + p1 < ccs_count) {
			if (p1 + 1 < ccs_body_lines)
				p1++;
			else
				p0++;
		}
	} else {
		return;
	}
	refresh = (ccs_current_item_index[ccs_current_screen] != p0);
	ccs_current_item_index[ccs_current_screen] = p0;
	ccs_current_y[ccs_current_screen] = p1;
	if (refresh)
		ccs_show_list(dp);
	else
		ccs_show_current(dp);
}

int ccs_editpolicy_get_current(void)
{
	int ccs_count = ccs_list_item_count[ccs_current_screen];
	const int p0 = ccs_current_item_index[ccs_current_screen];
	const int p1 = ccs_current_y[ccs_current_screen];
	if (!ccs_count)
		return EOF;
	if (p0 + p1 < 0 || p0 + p1 >= ccs_count) {
		fprintf(stderr, "ERROR: ccs_current_item_index=%d ccs_current_y=%d\n",
			p0, p1);
		exit(127);
	}
	return p0 + p1;
}

static void ccs_show_current(const struct ccs_domain_policy *dp)
{
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST &&
	    !ccs_domain_sort_type) {
		char *line;
		const int index = ccs_editpolicy_get_current();
		ccs_get();
		ccs_eat_col = ccs_max_eat_col[ccs_current_screen];
		line = ccs_shprintf("%s", ccs_eat(ccs_domain_name(dp, index)));
		if (ccs_window_width < strlen(line))
			line[ccs_window_width] = '\0';
		move(2, 0);
		clrtoeol();
		ccs_editpolicy_attr_change(A_REVERSE, true);  /* add color */
		printw("%s", line);
		ccs_editpolicy_attr_change(A_REVERSE, false); /* add color */
		ccs_put();
	}
	move(CCS_HEADER_LINES + ccs_current_y[ccs_current_screen], 0);
	ccs_editpolicy_line_draw(ccs_current_screen);     /* add color */
	refresh();
}

static void ccs_adjust_cursor_pos(const int item_count)
{
	if (item_count == 0) {
		ccs_current_item_index[ccs_current_screen] = 0;
		ccs_current_y[ccs_current_screen] = 0;
	} else {
		while (ccs_current_item_index[ccs_current_screen]
		       + ccs_current_y[ccs_current_screen] >= item_count) {
			if (ccs_current_y[ccs_current_screen] > 0)
				ccs_current_y[ccs_current_screen]--;
			else if (ccs_current_item_index[ccs_current_screen] > 0)
				ccs_current_item_index[ccs_current_screen]--;
		}
	}
}

static void ccs_set_cursor_pos(const int index)
{
	while (index < ccs_current_y[ccs_current_screen]
	       + ccs_current_item_index[ccs_current_screen]) {
		if (ccs_current_y[ccs_current_screen] > 0)
			ccs_current_y[ccs_current_screen]--;
		else
			ccs_current_item_index[ccs_current_screen]--;
	}
	while (index > ccs_current_y[ccs_current_screen]
	       + ccs_current_item_index[ccs_current_screen]) {
		if (ccs_current_y[ccs_current_screen] < ccs_body_lines - 1)
			ccs_current_y[ccs_current_screen]++;
		else
			ccs_current_item_index[ccs_current_screen]++;
	}
}

/**
 * ccs_select_item - Select an item.
 *
 * @dp:    Pointer to "struct ccs_domain_policy". Maybe NULL.
 * @index: Index in the @dp array if @dp != NULL, currently selected line
 *         in the generic list otherwise.
 *
 * Returns true if selected, false otherwise.
 *
 * Domain transition source and deleted domains are not selectable.
 */
static _Bool ccs_select_item(struct ccs_domain_policy *dp, const int index)
{
	int x;
	int y;
	if (index < 0)
		return false;
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (!ccs_domain_sort_type) {
			if (ccs_deleted_domain(dp, index) ||
			    ccs_initializer_source(dp, index))
				return false;
			dp->list_selected[index] ^= 1;
		} else {
			ccs_task_list[index].selected ^= 1;
		}
	} else {
		ccs_generic_acl_list[index].selected ^= 1;
	}
	getyx(stdscr, y, x);
	ccs_editpolicy_sttr_save();    /* add color */
	ccs_show_list(dp);
	ccs_editpolicy_sttr_restore(); /* add color */
	move(y, x);
	return true;
}

static int ccs_generic_acl_compare(const void *a, const void *b)
{
	const struct ccs_generic_acl *a0 = (struct ccs_generic_acl *) a;
	const struct ccs_generic_acl *b0 = (struct ccs_generic_acl *) b;
	const char *a1 = ccs_directives[a0->directive].alias;
	const char *b1 = ccs_directives[b0->directive].alias;
	const char *a2 = a0->operand;
	const char *b2 = b0->operand;
	if (!ccs_acl_sort_type) {
		const int ret = strcmp(a1, b1);
		if (ret)
			return ret;
		return strcmp(a2, b2);
	} else {
		const int ret = strcmp(a2, b2);
		if (ret)
			return ret;
		return strcmp(a1, b1);
	}
}

/**
 * ccs_delete_entry - Delete an entry.
 *
 * @dp:    Pointer to "struct ccs_domain_policy".
 * @index: Index in the @dp array.
 *
 * Returns nothing.
 */
static void ccs_delete_entry(struct ccs_domain_policy *dp, const int index)
{
	int c;
	move(1, 0);
	ccs_editpolicy_color_change(CCS_DISP_ERR, true);	/* add color */
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		c = ccs_count(dp->list_selected, dp->list_len);
		if (!c && index < dp->list_len)
			c = ccs_select_item(dp, index);
		if (!c)
			printw("Select domain using Space key first.");
		else
			printw("Delete selected domain%s? ('Y'es/'N'o)",
			       c > 1 ? "s" : "");
	} else {
		c = ccs_count2(ccs_generic_acl_list,
			       ccs_generic_acl_list_count);
		if (!c)
			c = ccs_select_item(NULL, index);
		if (!c)
			printw("Select entry using Space key first.");
		else
			printw("Delete selected entr%s? ('Y'es/'N'o)",
			       c > 1 ? "ies" : "y");
	}
	ccs_editpolicy_color_change(CCS_DISP_ERR, false);	/* add color */
	clrtoeol();
	refresh();
	if (!c)
		return;
	do {
		c = ccs_getch2();
	} while (!(c == 'Y' || c == 'y' || c == 'N' || c == 'n' || c == EOF));
	ccs_resize_window();
	if (c != 'Y' && c != 'y') {
		ccs_show_list(dp);
		return;
	}
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		int i;
		FILE *fp = ccs_editpolicy_open_write
			(CCS_PROC_POLICY_DOMAIN_POLICY);
		if (!fp)
			return;
		for (i = 1; i < dp->list_len; i++) {
			if (!dp->list_selected[i])
				continue;
			fprintf(fp, "delete %s\n", ccs_domain_name(dp, i));
		}
		ccs_close_write(fp);
	} else {
		int i;
		FILE *fp = ccs_editpolicy_open_write(ccs_policy_file);
		if (!fp)
			return;
		if (ccs_current_screen == CCS_SCREEN_ACL_LIST) {
			if (ccs_domain_sort_type)
				fprintf(fp, "select pid=%u\n",
					ccs_current_pid);
			else
				fprintf(fp, "select domain=%s\n",
					ccs_current_domain);
		}
		for (i = 0; i < ccs_generic_acl_list_count; i++) {
			enum ccs_editpolicy_directives directive;
			if (!ccs_generic_acl_list[i].selected)
				continue;
			directive = ccs_generic_acl_list[i].directive;
			fprintf(fp, "delete %s %s\n",
				ccs_directives[directive].original,
				ccs_generic_acl_list[i].operand);
		}
		ccs_close_write(fp);
	}
}

static void ccs_add_entry(struct ccs_readline_data *rl)
{
	FILE *fp;
	char *line;
	ccs_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(ccs_window_height - 1, 0, "Enter new entry> ",
			    rl->history, rl->count, 128000, 8);
	ccs_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	rl->count = ccs_add_history(line, rl->history, rl->count, rl->max);
	fp = ccs_editpolicy_open_write(ccs_policy_file);
	if (!fp)
		goto out;
	switch (ccs_current_screen) {
		enum ccs_editpolicy_directives directive;
	case CCS_SCREEN_DOMAIN_LIST:
		if (!ccs_correct_domain(line)) {
			const int len = strlen(line) + 128;
			ccs_last_error = realloc(ccs_last_error, len);
			if (!ccs_last_error)
				ccs_out_of_memory();
			memset(ccs_last_error, 0, len);
			snprintf(ccs_last_error, len - 1,
				 "%s is an invalid domainname.", line);
			line[0] = '\0';
		}
		break;
	case CCS_SCREEN_ACL_LIST:
		if (ccs_domain_sort_type)
			fprintf(fp, "select pid=%u\n", ccs_current_pid);
		else
			fprintf(fp, "select domain=%s\n", ccs_current_domain);
		/* Fall through. */
	case CCS_SCREEN_EXCEPTION_LIST:
		directive = ccs_find_directive(false, line);
		if (directive != CCS_DIRECTIVE_NONE)
			fprintf(fp, "%s ",
				ccs_directives[directive].original);
		break;
	case CCS_SCREEN_PROFILE_LIST:
		if (!strchr(line, '='))
			fprintf(fp, "%s-COMMENT=\n", line);
		break;
	default:
		break;
	}
	fprintf(fp, "%s\n", line);
	ccs_close_write(fp);
out:
	free(line);
}

static void ccs_find_entry(const struct ccs_domain_policy *dp,
			   const _Bool input, const _Bool forward,
			   const int current, struct ccs_readline_data *rl)
{
	int index = current;
	char *line = NULL;
	if (current == EOF)
		return;
	if (!input)
		goto start_search;
	ccs_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(ccs_window_height - 1, 0, "Search> ",
			    rl->history, rl->count, 128000, 8);
	ccs_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	rl->count = ccs_add_history(line, rl->history, rl->count, rl->max);
	free(rl->search_buffer[ccs_current_screen]);
	rl->search_buffer[ccs_current_screen] = line;
	line = NULL;
	index = -1;
start_search:
	ccs_get();
	while (true) {
		const char *cp;
		if (forward) {
			if (++index >= ccs_list_item_count[ccs_current_screen])
				break;
		} else {
			if (--index < 0)
				break;
		}
		if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
			if (ccs_domain_sort_type)
				cp = ccs_task_list[index].name;
			else
				cp = ccs_get_last_name(dp, index);
		} else if (ccs_current_screen == CCS_SCREEN_PROFILE_LIST) {
			cp = ccs_shprintf("%u-%s",
					  ccs_generic_acl_list[index].directive,
					  ccs_generic_acl_list[index].operand);
		} else {
			const enum ccs_editpolicy_directives directive =
				ccs_generic_acl_list[index].directive;
			cp = ccs_shprintf("%s %s",
					  ccs_directives[directive].alias,
					  ccs_generic_acl_list[index].operand);
		}
		if (!strstr(cp, rl->search_buffer[ccs_current_screen]))
			continue;
		ccs_set_cursor_pos(index);
		break;
	}
	ccs_put();
out:
	free(line);
	ccs_show_list(dp);
}

/**
 * ccs_set_profile - Change profile number.
 *
 * @current: Currently selected line in the generic list.
 *
 * Returns nothing.
 */
static void ccs_set_profile(struct ccs_domain_policy *dp, const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!ccs_domain_sort_type) {
		if (!ccs_count(dp->list_selected, dp->list_len) &&
		    !ccs_select_item(NULL, current)) {
			move(1, 0);
			printw("Select domain using Space key first.");
			clrtoeol();
			refresh();
			return;
		}
	} else {
		if (!ccs_count3(ccs_task_list, ccs_task_list_len) &&
		    !ccs_select_item(NULL, current)) {
			move(1, 0);
			printw("Select processes using Space key first.");
			clrtoeol();
			refresh();
			return;
		}
	}
	ccs_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(ccs_window_height - 1, 0, "Enter profile number> ",
			    NULL, 0, 8, 1);
	ccs_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = ccs_editpolicy_open_write(CCS_PROC_POLICY_DOMAIN_POLICY);
	if (!fp)
		goto out;
	if (!ccs_domain_sort_type) {
		for (index = 0; index < dp->list_len; index++) {
			if (!dp->list_selected[index])
				continue;
			fprintf(fp, "select domain=%s\n" "use_profile %s\n",
				ccs_domain_name(dp, index), line);
		}
	} else {
		for (index = 0; index < ccs_task_list_len; index++) {
			if (!ccs_task_list[index].selected)
				continue;
			fprintf(fp, "select pid=%u\n" "use_profile %s\n",
				ccs_task_list[index].pid, line);
		}
	}
	ccs_close_write(fp);
out:
	free(line);
}

/**
 * ccs_set_level - Change profiles.
 *
 * @current: Currently selected line in the generic list.
 *
 * Returns nothing.
 */
static void ccs_set_level(const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!ccs_count2(ccs_generic_acl_list, ccs_generic_acl_list_count))
		ccs_select_item(NULL, current);
	ccs_editpolicy_attr_change(A_BOLD, true);  /* add color */
	ccs_initial_readline_data = NULL;
	for (index = 0; index < ccs_generic_acl_list_count; index++) {
		char *cp;
		if (!ccs_generic_acl_list[index].selected)
			continue;
		cp = strchr(ccs_generic_acl_list[index].operand, '=');
		if (!cp)
			continue;
		ccs_initial_readline_data = cp + 1;
		break;
	}
	line = ccs_readline(ccs_window_height - 1, 0, "Enter new value> ",
			    NULL, 0, 128000, 1);
	ccs_initial_readline_data = NULL;
	ccs_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = ccs_editpolicy_open_write(CCS_PROC_POLICY_PROFILE);
	if (!fp)
		goto out;
	for (index = 0; index < ccs_generic_acl_list_count; index++) {
		char *buf;
		char *cp;
		enum ccs_editpolicy_directives directive;
		if (!ccs_generic_acl_list[index].selected)
			continue;
		ccs_get();
		buf = ccs_shprintf("%s", ccs_generic_acl_list[index].operand);
		cp = strchr(buf, '=');
		if (cp)
			*cp = '\0';
		directive = ccs_generic_acl_list[index].directive;
		if (directive < 256)
			fprintf(fp, "%u-", directive);
		fprintf(fp, "%s=%s\n", buf, line);
		ccs_put();
	}
	ccs_close_write(fp);
out:
	free(line);
}

/**
 * ccs_set_quota - Set memory quota.
 *
 * @current: Currently selected line in the generic list.
 *
 * Returns nothing.
 */
static void ccs_set_quota(const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!ccs_count2(ccs_generic_acl_list, ccs_generic_acl_list_count))
		ccs_select_item(NULL, current);
	ccs_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(ccs_window_height - 1, 0, "Enter new value> ",
			    NULL, 0, 20, 1);
	ccs_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = ccs_editpolicy_open_write(CCS_PROC_POLICY_STAT);
	if (!fp)
		goto out;
	for (index = 0; index < ccs_generic_acl_list_count; index++) {
		char *buf;
		char *cp;
		if (!ccs_generic_acl_list[index].selected)
			continue;
		ccs_get();
		buf = ccs_shprintf("%s", ccs_generic_acl_list[index].operand);
		cp = strchr(buf, ':');
		if (cp)
			*cp = '\0';
		fprintf(fp, "%s: %s\n", buf, line);
		ccs_put();
	}
	ccs_close_write(fp);
out:
	free(line);
}

/**
 * ccs_select_acl_window - Check whether to switch to ACL list or not. 
 *
 * @dp:          Pointer to "const struct ccs_domain_policy".
 * @current:     Index in the @dp array.
 * @may_refresh: ???
 *
 * Returns true if next window is ACL list, false otherwise.
 */
static _Bool ccs_select_acl_window(const struct ccs_domain_policy *dp,
				   const int current, const _Bool may_refresh)
{
	if (ccs_current_screen != CCS_SCREEN_DOMAIN_LIST || current == EOF)
		return false;
	ccs_current_pid = 0;
	if (ccs_domain_sort_type) {
		ccs_current_pid = ccs_task_list[current].pid;
	} else if (ccs_initializer_source(dp, current)) {
		int redirect_index;
		if (!may_refresh)
			return false;
		redirect_index = ccs_find_target_domain(dp, current);
		if (redirect_index == EOF)
			return false;
		ccs_current_item_index[ccs_current_screen]
			= redirect_index - ccs_current_y[ccs_current_screen];
		while (ccs_current_item_index[ccs_current_screen] < 0) {
			ccs_current_item_index[ccs_current_screen]++;
			ccs_current_y[ccs_current_screen]--;
		}
		ccs_show_list(dp);
		return false;
	} else if (ccs_deleted_domain(dp, current)) {
		return false;
	}
	free(ccs_current_domain);
	if (ccs_domain_sort_type)
		ccs_current_domain = strdup(ccs_task_list[current].domain);
	else
		ccs_current_domain = strdup(ccs_domain_name(dp, current));
	if (!ccs_current_domain)
		ccs_out_of_memory();
	return true;
}

/**
 * ccs_select_window - Switch window.
 *
 * @dp:      Pointer to "const struct ccs_domain_policy".
 * @current: Index in the @dp array.
 *
 * Returns next window to display.
 */
static enum ccs_screen_type ccs_select_window
(const struct ccs_domain_policy *dp, const int current)
{
	move(0, 0);
	printw("Press one of below keys to switch window.\n\n");
	printw("e     <<< Exception Policy Editor >>>\n");
	printw("d     <<< Domain Transition Editor >>>\n");
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST && current != EOF &&
	    !ccs_initializer_source(dp, current) &&
	    !ccs_deleted_domain(dp, current))
		printw("a     <<< Domain Policy Editor >>>\n");
	printw("p     <<< Profile Editor >>>\n");
	printw("m     <<< Manager Policy Editor >>>\n");
	if (!ccs_offline_mode) {
		/* printw("i     <<< Interactive Enforcing Mode >>>\n"); */
		printw("s     <<< Statistics >>>\n");
	}
	printw("q     Quit this editor.\n");
	clrtobot();
	refresh();
	while (true) {
		int c = ccs_getch2();
		if (c == 'E' || c == 'e')
			return CCS_SCREEN_EXCEPTION_LIST;
		if (c == 'D' || c == 'd')
			return CCS_SCREEN_DOMAIN_LIST;
		if (c == 'A' || c == 'a')
			if (ccs_select_acl_window(dp, current, false))
				return CCS_SCREEN_ACL_LIST;
		if (c == 'P' || c == 'p')
			return CCS_SCREEN_PROFILE_LIST;
		if (c == 'M' || c == 'm')
			return CCS_SCREEN_MANAGER_LIST;
		if (!ccs_offline_mode) {
			/*
			if (c == 'I' || c == 'i')
				return CCS_SCREEN_QUERY_LIST;
			*/
			if (c == 'S' || c == 's')
				return CCS_SCREEN_STAT_LIST;
		}
		if (c == 'Q' || c == 'q')
			return CCS_MAXSCREEN;
		if (c == EOF)
			return CCS_MAXSCREEN;
	}
}

/**
 * ccs_copy_mark_state - Copy selected state to lines under the current line.
 *
 * @dp:      Pointer to "struct ccs_domain_policy".
 * @current: Index in the @dp array.
 *
 * Returns nothing.
 */
static void ccs_copy_mark_state(struct ccs_domain_policy *dp,
				const int current)
{
	int index;
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (ccs_domain_sort_type) {
			const u8 selected = ccs_task_list[current].selected;
			for (index = current; index < ccs_task_list_len;
			     index++)
				ccs_task_list[index].selected = selected;
		} else {
			const u8 selected = dp->list_selected[current];
			if (ccs_deleted_domain(dp, current) ||
			    ccs_initializer_source(dp, current))
				return;
			for (index = current;
			     index < dp->list_len; index++) {
				if (ccs_deleted_domain(dp, index) ||
				    ccs_initializer_source(dp, index))
					continue;
				dp->list_selected[index] = selected;
			}
		}
	} else {
		const u8 selected = ccs_generic_acl_list[current].selected;
		for (index = current; index < ccs_generic_acl_list_count;
		     index++)
			ccs_generic_acl_list[index].selected = selected;
	}
	ccs_show_list(dp);
}

/**
 * ccs_copy_to_history - Copy line to histoy buffer. 
 *
 * @dp:      Pointer to "const struct ccs_domain_policy".
 * @current: Index in the @dp array.
 * @rl:      Pointer to "struct ccs_readline_data".
 *
 * Returns nothing.
 */
static void ccs_copy_to_history(const struct ccs_domain_policy *dp,
				const int current,
				struct ccs_readline_data *rl)
{
	const char *line;
	if (current == EOF)
		return;
	ccs_get();
	switch (ccs_current_screen) {
		enum ccs_editpolicy_directives directive;
	case CCS_SCREEN_DOMAIN_LIST:
		line = ccs_domain_name(dp, current);
		break;
	case CCS_SCREEN_EXCEPTION_LIST:
	case CCS_SCREEN_ACL_LIST:
		directive = ccs_generic_acl_list[current].directive;
		line = ccs_shprintf("%s %s", ccs_directives[directive].alias,
				ccs_generic_acl_list[current].operand);
		break;
	case CCS_SCREEN_STAT_LIST:
		line = NULL;
		break;
	default:
		line = ccs_shprintf("%s",
				    ccs_generic_acl_list[current].operand);
	}
	rl->count = ccs_add_history(line, rl->history, rl->count, rl->max);
	ccs_put();
}

static int ccs_generic_list_loop(struct ccs_domain_policy *dp)
{
	static struct ccs_readline_data rl;
	static int saved_current_y[CCS_MAXSCREEN];
	static int saved_current_item_index[CCS_MAXSCREEN];
	static _Bool first = true;
	if (first) {
		memset(&rl, 0, sizeof(rl));
		rl.max = 20;
		rl.history = malloc(rl.max * sizeof(const char *));
		memset(saved_current_y, 0, sizeof(saved_current_y));
		memset(saved_current_item_index, 0,
		       sizeof(saved_current_item_index));
		first = false;
	}
	if (ccs_current_screen == CCS_SCREEN_EXCEPTION_LIST) {
		ccs_policy_file = CCS_PROC_POLICY_EXCEPTION_POLICY;
		ccs_list_caption = "Exception Policy Editor";
	} else if (ccs_current_screen == CCS_SCREEN_ACL_LIST) {
		ccs_policy_file = CCS_PROC_POLICY_DOMAIN_POLICY;
		ccs_list_caption = "Domain Policy Editor";
	} else if (ccs_current_screen == CCS_SCREEN_QUERY_LIST) {
		ccs_policy_file = CCS_PROC_POLICY_QUERY;
		ccs_list_caption = "Interactive Enforcing Mode";
	} else if (ccs_current_screen == CCS_SCREEN_PROFILE_LIST) {
		ccs_policy_file = CCS_PROC_POLICY_PROFILE;
		ccs_list_caption = "Profile Editor";
	} else if (ccs_current_screen == CCS_SCREEN_MANAGER_LIST) {
		ccs_policy_file = CCS_PROC_POLICY_MANAGER;
		ccs_list_caption = "Manager Policy Editor";
	} else if (ccs_current_screen == CCS_SCREEN_STAT_LIST) {
		ccs_policy_file = CCS_PROC_POLICY_STAT;
		ccs_list_caption = "Statistics";
	} else {
		ccs_policy_file = CCS_PROC_POLICY_DOMAIN_POLICY;
		/* ccs_list_caption = "Domain Transition Editor"; */
	}
	ccs_current_item_index[ccs_current_screen]
		= saved_current_item_index[ccs_current_screen];
	ccs_current_y[ccs_current_screen] = saved_current_y[ccs_current_screen];
start:
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (!ccs_domain_sort_type) {
			ccs_read_domain_and_exception_policy(dp);
			ccs_adjust_cursor_pos(dp->list_len);
		} else {
			ccs_read_process_list(true);
			ccs_adjust_cursor_pos(ccs_task_list_len);
		}
	} else {
		ccs_read_generic_policy();
		ccs_adjust_cursor_pos(ccs_generic_acl_list_count);
	}
start2:
	ccs_show_list(dp);
	if (ccs_last_error) {
		move(1, 0);
		printw("ERROR: %s", ccs_last_error);
		clrtoeol();
		refresh();
		free(ccs_last_error);
		ccs_last_error = NULL;
	}
	while (true) {
		const int current = ccs_editpolicy_get_current();
		const int c = ccs_getch2();
		saved_current_item_index[ccs_current_screen]
			= ccs_current_item_index[ccs_current_screen];
		saved_current_y[ccs_current_screen] = ccs_current_y[ccs_current_screen];
		if (c == 'q' || c == 'Q')
			return CCS_MAXSCREEN;
		if ((c == '\r' || c == '\n') &&
		    ccs_current_screen == CCS_SCREEN_ACL_LIST)
			return CCS_SCREEN_DOMAIN_LIST;
		if (c == '\t') {
			if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST)
				return CCS_SCREEN_EXCEPTION_LIST;
			else
				return CCS_SCREEN_DOMAIN_LIST;
		}
		if (ccs_need_reload) {
			ccs_need_reload = false;
			goto start;
		}
		if (c == ERR)
			continue; /* Ignore invalid key. */
		switch (c) {
		case KEY_RESIZE:
			ccs_resize_window();
			ccs_show_list(dp);
			break;
		case KEY_UP:
			ccs_up_arrow_key(dp);
			break;
		case KEY_DOWN:
			ccs_down_arrow_key(dp);
			break;
		case KEY_PPAGE:
			ccs_page_up_key(dp);
			break;
		case KEY_NPAGE:
			ccs_page_down_key(dp);
			break;
		case ' ':
			ccs_select_item(dp, current);
			break;
		case 'c':
		case 'C':
			if (current == EOF)
				break;
			ccs_copy_mark_state(dp, current);
			ccs_show_list(dp);
			break;
		case 'f':
		case 'F':
			if (ccs_current_screen != CCS_SCREEN_STAT_LIST)
				ccs_find_entry(dp, true, true, current, &rl);
			break;
		case 'p':
		case 'P':
			if (ccs_current_screen == CCS_SCREEN_STAT_LIST)
				break;
			if (!rl.search_buffer[ccs_current_screen])
				ccs_find_entry(dp, true, false, current, &rl);
			else
				ccs_find_entry(dp, false, false, current, &rl);
			break;
		case 'n':
		case 'N':
			if (ccs_current_screen == CCS_SCREEN_STAT_LIST)
				break;
			if (!rl.search_buffer[ccs_current_screen])
				ccs_find_entry(dp, true, true, current, &rl);
			else
				ccs_find_entry(dp, false, true, current, &rl);
			break;
		case 'd':
		case 'D':
			if (ccs_readonly_mode)
				break;
			switch (ccs_current_screen) {
			case CCS_SCREEN_DOMAIN_LIST:
				if (ccs_domain_sort_type)
					break;
			case CCS_SCREEN_EXCEPTION_LIST:
			case CCS_SCREEN_ACL_LIST:
			case CCS_SCREEN_MANAGER_LIST:
				ccs_delete_entry(dp, current);
				goto start;
			default:
				break;
			}
			break;
		case 'a':
		case 'A':
			if (ccs_readonly_mode)
				break;
			switch (ccs_current_screen) {
			case CCS_SCREEN_DOMAIN_LIST:
				if (ccs_domain_sort_type)
					break;
			case CCS_SCREEN_EXCEPTION_LIST:
			case CCS_SCREEN_ACL_LIST:
			case CCS_SCREEN_PROFILE_LIST:
			case CCS_SCREEN_MANAGER_LIST:
				ccs_add_entry(&rl);
				goto start;
			default:
				break;
			}
			break;
		case '\r':
		case '\n':
			if (ccs_select_acl_window(dp, current, true))
				return CCS_SCREEN_ACL_LIST;
			break;
		case 's':
		case 'S':
			if (ccs_readonly_mode)
				break;
			switch (ccs_current_screen) {
			case CCS_SCREEN_DOMAIN_LIST:
				ccs_set_profile(dp, current);
				goto start;
			case CCS_SCREEN_PROFILE_LIST:
				ccs_set_level(current);
				goto start;
			case CCS_SCREEN_STAT_LIST:
				ccs_set_quota(current);
				goto start;
			default:
				break;
			}
			break;
		case 'r':
		case 'R':
			goto start;
		case KEY_LEFT:
			if (!ccs_max_eat_col[ccs_current_screen])
				break;
			ccs_max_eat_col[ccs_current_screen]--;
			goto start2;
		case KEY_RIGHT:
			ccs_max_eat_col[ccs_current_screen]++;
			goto start2;
		case KEY_HOME:
			ccs_max_eat_col[ccs_current_screen] = 0;
			goto start2;
		case KEY_END:
			ccs_max_eat_col[ccs_current_screen] = ccs_max_col;
			goto start2;
		case KEY_IC:
			ccs_copy_to_history(dp, current, &rl);
			break;
		case 'o':
		case 'O':
			if (ccs_current_screen == CCS_SCREEN_ACL_LIST) {
				ccs_editpolicy_optimize(dp, current,
							ccs_current_screen);
				ccs_show_list(dp);
			}
			break;
		case '@':
			switch (ccs_current_screen) {
			case CCS_SCREEN_ACL_LIST:
				ccs_acl_sort_type = !ccs_acl_sort_type;
				goto start;
			case CCS_SCREEN_PROFILE_LIST:
				ccs_profile_sort_type = !ccs_profile_sort_type;
				goto start;
			case CCS_SCREEN_DOMAIN_LIST:
				if (ccs_offline_mode)
					break;
				ccs_domain_sort_type = !ccs_domain_sort_type;
				goto start;
			default:
				break;
			}
			break;
		case 'w':
		case 'W':
			return ccs_select_window(dp, current);
		case '?':
			if (ccs_show_command_key(ccs_current_screen,
						 ccs_readonly_mode))
				goto start;
			return CCS_MAXSCREEN;
		}
	}
}

static _Bool ccs_save_to_file(const char *src, const char *dest)
{
	FILE *proc_fp = ccs_editpolicy_open_read(src);
	FILE *file_fp = fopen(dest, "w");
	if (!file_fp) {
		fprintf(stderr, "Can't open %s\n", dest);
		fclose(proc_fp);
		return false;
	}
	while (true) {
		int c = fgetc(proc_fp);
		if (c == EOF)
			break;
		fputc(c, file_fp);
	}
	fclose(proc_fp);
	fclose(file_fp);
	return true;
}

static void parse_args(int argc, char *argv[])
{
	int i;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (ccs_network_mode || ccs_offline_mode)
				goto usage;
			ccs_policy_dir = ptr;
			ccs_offline_mode = true;
		} else if (cp) {
			*cp++ = '\0';
			if (ccs_network_mode || ccs_offline_mode)
				goto usage;
			ccs_network_ip = inet_addr(ptr);
			ccs_network_port = htons(atoi(cp));
			ccs_network_mode = true;
			if (!ccs_check_remote_host())
				exit(1);
		} else if (!strcmp(ptr, "e"))
			ccs_current_screen = CCS_SCREEN_EXCEPTION_LIST;
		else if (!strcmp(ptr, "d"))
			ccs_current_screen = CCS_SCREEN_DOMAIN_LIST;
		else if (!strcmp(ptr, "p"))
			ccs_current_screen = CCS_SCREEN_PROFILE_LIST;
		else if (!strcmp(ptr, "m"))
			ccs_current_screen = CCS_SCREEN_MANAGER_LIST;
		else if (!strcmp(ptr, "s"))
			ccs_current_screen = CCS_SCREEN_STAT_LIST;
		else if (!strcmp(ptr, "readonly"))
			ccs_readonly_mode = true;
		else if (sscanf(ptr, "refresh=%u", &ccs_refresh_interval)
			 != 1) {
usage:
			printf("Usage: %s [e|d|p|m|s] [readonly] "
			       "[refresh=interval] "
			       "[{policy_dir|remote_ip:remote_port}]\n",
			       argv[0]);
			exit(1);
		}
	}
}

static void load_offline(void)
{
	int fd[2] = { EOF, EOF };
	if (chdir(ccs_policy_dir) || chdir("policy/current/")) {
		fprintf(stderr, "Directory %s/policy/current/ doesn't "
			"exist.\n", ccs_policy_dir);
		exit(1);
	}
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd)) {
		fprintf(stderr, "socketpair()\n");
		exit(1);
	}
	switch (fork()) {
	case 0:
		close(fd[0]);
		ccs_persistent_fd = fd[1];
		ccs_editpolicy_offline_daemon();
		_exit(0);
	case -1:
		fprintf(stderr, "fork()\n");
		exit(1);
	}
	close(fd[1]);
	ccs_persistent_fd = fd[0];
	ccs_copy_file("exception_policy.conf",
		      CCS_PROC_POLICY_EXCEPTION_POLICY);
	ccs_copy_file("domain_policy.conf", CCS_PROC_POLICY_DOMAIN_POLICY);
	ccs_copy_file("profile.conf", CCS_PROC_POLICY_PROFILE);
	ccs_copy_file("manager.conf", CCS_PROC_POLICY_MANAGER);
	if (chdir("..")) {
		fprintf(stderr, "Directory %s/policy/ doesn't exist.\n",
			ccs_policy_dir);
		exit(1);
	}
		
}

static void load_readwrite(void)
{
	const int fd1 = ccs_open2(CCS_PROC_POLICY_EXCEPTION_POLICY, O_RDWR);
	const int fd2 = ccs_open2(CCS_PROC_POLICY_DOMAIN_POLICY, O_RDWR);
	if ((fd1 != EOF && write(fd1, "", 0) != 0) ||
	    (fd2 != EOF && write(fd2, "", 0) != 0)) {
		fprintf(stderr, "In order to run this program, it must be "
			"registered to %s . "
			"Please reboot.\n", CCS_PROC_POLICY_MANAGER);
		exit(1);
	}
	close(fd1);
	close(fd2);
}

static void save_offline(void)
{
	time_t now = time(NULL);
	static char stamp[32] = { };
	while (1) {
		struct tm *tm = localtime(&now);
		snprintf(stamp, sizeof(stamp) - 1,
			 "%02d-%02d-%02d.%02d:%02d:%02d/",
			 tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday,
			 tm->tm_hour, tm->tm_min, tm->tm_sec);
		if (!mkdir(stamp, 0700))
			break;
		else if (errno == EEXIST)
			now++;
		else {
			fprintf(stderr, "Can't create %s/%s .\n",
				ccs_policy_dir, stamp);
			exit(1);
		}
	}
	if ((symlink("policy/current/profile.conf", "../profile.conf") &&
	     errno != EEXIST) ||
	    (symlink("policy/current/manager.conf", "../manager.conf") &&
	     errno != EEXIST) ||
	    (symlink("policy/current/exception_policy.conf",
		     "../exception_policy.conf") && errno != EEXIST) ||
	    (symlink("policy/current/domain_policy.conf",
		     "../domain_policy.conf") && errno != EEXIST) ||
	    chdir(stamp) ||
	    !ccs_save_to_file(CCS_PROC_POLICY_PROFILE, "profile.conf") ||
	    !ccs_save_to_file(CCS_PROC_POLICY_MANAGER, "manager.conf") ||
	    !ccs_save_to_file(CCS_PROC_POLICY_EXCEPTION_POLICY,
			      "exception_policy.conf") ||
	    !ccs_save_to_file(CCS_PROC_POLICY_DOMAIN_POLICY,
			      "domain_policy.conf") ||
	    chdir("..") ||
	    (rename("current", "previous") && errno != ENOENT) ||
	    symlink(stamp, "current")) {
		fprintf(stderr, "Failed to save policy.\n");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	struct ccs_domain_policy dp = { NULL, 0, NULL };
	struct ccs_domain_policy bp = { NULL, 0, NULL };
	memset(ccs_current_y, 0, sizeof(ccs_current_y));
	memset(ccs_current_item_index, 0, sizeof(ccs_current_item_index));
	memset(ccs_list_item_count, 0, sizeof(ccs_list_item_count));
	memset(ccs_max_eat_col, 0, sizeof(ccs_max_eat_col));
	parse_args(argc, argv);
	ccs_editpolicy_init_keyword_map();
	if (ccs_offline_mode) {
		load_offline();
		goto start;
	}
	if (ccs_network_mode)
		goto start;
	if (chdir(CCS_PROC_POLICY_DIR)) {
		fprintf(stderr,
			"You can't use this editor for this kernel.\n");
		return 1;
	}
	if (!ccs_readonly_mode)
		load_readwrite();
start:
	initscr();
	ccs_editpolicy_color_init();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	getmaxyx(stdscr, ccs_window_height, ccs_window_width);
	if (ccs_refresh_interval) {
		signal(SIGALRM, ccs_sigalrm_handler);
		alarm(ccs_refresh_interval);
		timeout(1000);
	}
	while (ccs_current_screen < CCS_MAXSCREEN) {
		ccs_resize_window();
		ccs_current_screen = ccs_generic_list_loop(&dp);
	}
	alarm(0);
	clear();
	move(0, 0);
	refresh();
	endwin();
	if (ccs_offline_mode && !ccs_readonly_mode)
		save_offline();
	ccs_clear_domain_policy(&bp);
	ccs_clear_domain_policy(&dp);
	return 0;
}
