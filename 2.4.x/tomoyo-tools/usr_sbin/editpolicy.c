/*
 * editpolicy.c
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
#include "editpolicy.h"
#include "readline.h"

/* Domain policy. */
struct tomoyo_domain_policy tomoyo_dp = { };

/* Readline history. */
static struct tomoyo_readline_data tomoyo_rl = { };

/* File descriptor for offline mode. */
int tomoyo_persistent_fd = EOF;

/* Array of "path_group" entries. */
struct tomoyo_path_group_entry *tomoyo_path_group_list = NULL;
/* Length of tomoyo_path_group_list array. */
int tomoyo_path_group_list_len = 0;
/* Array of string ACL entries. */
struct tomoyo_generic_acl *tomoyo_gacl_list = NULL;
/* Length of tomoyo_generic_list array. */
static int tomoyo_gacl_list_count = 0;

/* Policy directory. */
static const char *tomoyo_policy_dir = NULL;
/* Use tomoyo-editpolicy-agent program? */
static _Bool tomoyo_offline_mode = false;
/* Use readonly mode? */
static _Bool tomoyo_readonly_mode = false;
/* Refresh interval in second. 0 means no auto refresh. */
static unsigned int tomoyo_refresh_interval = 0;
/* Need to reload the screen due to auto refresh? */
static _Bool tomoyo_need_reload = false;
/* Policy file's name. */
static const char *tomoyo_policy_file = NULL;
/* Caption of the current screen. */
static const char *tomoyo_list_caption = NULL;
/* Currently selected domain. */
static char *tomoyo_current_domain = NULL;
/* Currently selected PID. */
static unsigned int tomoyo_current_pid = 0;
/* Currently active screen's index. */
enum tomoyo_screen_type tomoyo_current_screen = TOMOYO_SCREEN_DOMAIN_LIST;
/* Previously active screen's index. */
static enum tomoyo_screen_type tomoyo_previous_screen = TOMOYO_SCREEN_DOMAIN_LIST;
/*
 * Array of "initialize_domain"/"no_initialize_domain"/"keep_domain"/
 * "no_keep_domain" entries.
 */
static struct tomoyo_transition_control_entry *tomoyo_transition_control_list = NULL;
/* Length of tomoyo_transition_control_list array. */
static int tomoyo_transition_control_list_len = 0;
/* Sort profiles by value? */
static _Bool tomoyo_profile_sort_type = false;
/* Number of domain initializer source domains. */
static int tomoyo_unnumbered_domain_count = 0;
/* Width of CUI screen. */
static int tomoyo_window_width = 0;
/* Height of CUI screen. */
static int tomoyo_window_height = 0;
/* Cursor info for CUI screen. */
struct tomoyo_screen tomoyo_screen[TOMOYO_MAXSCREEN] = { };
/* Number of entries available on current screen. */
int tomoyo_list_item_count = 0;
/* Lines available for displaying ACL entries.  */
static int tomoyo_body_lines = 0;
/* Columns to shift. */
static int tomoyo_eat_col = 0;
/* Max columns. */
static int tomoyo_max_col = 0;
/* Sort ACL by operand first? */
static _Bool tomoyo_acl_sort_type = false;
/* Last error message. */
static char *tomoyo_last_error = NULL;
/* Domain screen is dealing with process list rather than domain list? */
static _Bool tomoyo_domain_sort_type = false;
/* Start from the first line when showing ACL screen? */
static _Bool tomoyo_no_restore_cursor = false;

/* Namespace to use. */
static char *tomoyo_current_ns = NULL;
static int tomoyo_current_ns_len = 0;

/* Domain transition coltrol keywords. */
static const char *tomoyo_transition_type[TOMOYO_MAX_TRANSITION_TYPE] = {
	[TOMOYO_TRANSITION_CONTROL_RESET]         = "reset_domain ",
	[TOMOYO_TRANSITION_CONTROL_NO_RESET]      = "no_reset_domain ",
	[TOMOYO_TRANSITION_CONTROL_INITIALIZE]    = "initialize_domain ",
	[TOMOYO_TRANSITION_CONTROL_NO_INITIALIZE] = "no_initialize_domain ",
	[TOMOYO_TRANSITION_CONTROL_KEEP]          = "keep_domain ",
	[TOMOYO_TRANSITION_CONTROL_NO_KEEP]       = "no_keep_domain ",
};

static FILE *tomoyo_editpolicy_open_write(const char *filename);
static _Bool tomoyo_deleted_domain(const int index);
static _Bool tomoyo_domain_unreachable(const int index);
static _Bool tomoyo_initializer_source(const int index);
static _Bool tomoyo_initializer_target(const int index);
static _Bool tomoyo_keeper_domain(const int index);
static _Bool tomoyo_select_item(const int index);
static _Bool tomoyo_show_command_key(const enum tomoyo_screen_type screen,
				  const _Bool readonly);
static const char *tomoyo_eat(const char *str);
static const char *tomoyo_get_last_name(const int index);
static const struct tomoyo_transition_control_entry *tomoyo_transition_control
(const struct tomoyo_path_info *domainname, const char *program);
static enum tomoyo_screen_type tomoyo_generic_list_loop(void);
static enum tomoyo_screen_type tomoyo_select_window(const int current);
static int tomoyo_add_path_group_entry(const char *group_name,
				    const char *member_name,
				    const _Bool is_delete);
static int tomoyo_add_path_group_policy(char *data, const _Bool is_delete);
static int tomoyo_add_transition_control_entry(const char *domainname,
					    const char *program, const enum
					    tomoyo_transition_type type);
static int tomoyo_add_transition_control_policy(char *data, const enum
					     tomoyo_transition_type type);
static int tomoyo_count(const unsigned char *array, const int len);
static int tomoyo_count2(const struct tomoyo_generic_acl *array, int len);
static int tomoyo_domainname_attribute_compare(const void *a, const void *b);
static int tomoyo_gacl_compare(const void *a, const void *b);
static int tomoyo_gacl_compare0(const void *a, const void *b);
static int tomoyo_profile_entry_compare(const void *a, const void *b);
static int tomoyo_show_acl_line(const int index, const int list_indent);
static int tomoyo_show_domain_line(const int index);
static int tomoyo_show_literal_line(const int index);
static int tomoyo_show_profile_line(const int index);
static int tomoyo_show_stat_line(const int index);
static int tomoyo_string_acl_compare(const void *a, const void *b);
static void tomoyo_add_entry(void);
static void tomoyo_adjust_cursor_pos(const int item_count);
static void tomoyo_assign_dis(const struct tomoyo_path_info *domainname,
			   const char *program, const bool is_root);
static void tomoyo_copy_file(const char *source, const char *dest);
static void tomoyo_delete_entry(const int index);
static void tomoyo_down_arrow_key(void);
static void tomoyo_find_entry(const _Bool input, const _Bool forward,
			   const int current);
static void tomoyo_page_down_key(void);
static void tomoyo_page_up_key(void);
static void tomoyo_read_domain_and_exception_policy(void);
static void tomoyo_read_generic_policy(void);
static void tomoyo_resize_window(void);
static void tomoyo_set_cursor_pos(const int index);
static void tomoyo_set_level(const int current);
static void tomoyo_set_profile(const int current);
static void tomoyo_set_quota(const int current);
static void tomoyo_show_current(void);
static void tomoyo_show_list(void);
static void tomoyo_sigalrm_handler(int sig);
static void tomoyo_up_arrow_key(void);

/**
 * tomoyo_is_current_namespace - Check namespace.
 *
 * @line: Line to check namespace.
 *
 * Returns true if this line deals current namespace, false otherwise.
 */
static _Bool tomoyo_is_current_namespace(const char *line)
{
	return !strncmp(line, tomoyo_current_ns, tomoyo_current_ns_len)
		&& (line[tomoyo_current_ns_len] == ' ' ||
		    !line[tomoyo_current_ns_len]);
}

/**
 * tomoyo_copy_file - Copy local file to local or remote file.
 *
 * @source: Local file.
 * @dest:   Local or remote file name.
 *
 * Returns nothing.
 */
static void tomoyo_copy_file(const char *source, const char *dest)
{
	FILE *fp_in = fopen(source, "r");
	FILE *fp_out = fp_in ? tomoyo_editpolicy_open_write(dest) : NULL;
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
 * tomoyo_get_last_word - Get last component of a line.
 *
 * @line: A line of words.
 *
 * Returns the last component of the line.
 */
static const char *tomoyo_get_last_word(const char *line)
{
	const char *cp = strrchr(line, ' ');
	if (cp)
		return cp + 1;
	return line;
}

/**
 * tomoyo_get_last_name - Get last component of a domainname.
 *
 * @index: Index in the domain policy.
 *
 * Returns the last component of the domainname.
 */
static const char *tomoyo_get_last_name(const int index)
{
	return tomoyo_get_last_word(tomoyo_domain_name(&tomoyo_dp, index));
}

/**
 * tomoyo_count - Count non-zero elements in an array.
 *
 * @array: Pointer to "const unsigned char".
 * @len:   Length of @array array.
 *
 * Returns number of non-zero elements.
 */
static int tomoyo_count(const unsigned char *array, const int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i])
			c++;
	return c;
}

/**
 * tomoyo_count2 - Count non-zero elements in a "struct tomoyo_generic_acl" array.
 *
 * @array: Pointer to "const struct tomoyo_generic_acl".
 * @len:   Length of @array array.
 *
 * Returns number of non-zero elements.
 */
static int tomoyo_count2(const struct tomoyo_generic_acl *array, int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i].selected)
			c++;
	return c;
}

/**
 * tomoyo_count3 - Count non-zero elements in a "struct tomoyo_task_entry" array.
 *
 * @array: Pointer to "const struct tomoyo_task_entry".
 * @len:   Length of @array array.
 *
 * Returns number of non-zero elements.
 */
static int tomoyo_count3(const struct tomoyo_task_entry *array, int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i].selected)
			c++;
	return c;
}

/**
 * tomoyo_keeper_domain - Check whether the given domain is marked as "keep_domain".
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is marked as "keep_domain",
 * false otherwise.
 */
static _Bool tomoyo_keeper_domain(const int index)
{
	return tomoyo_dp.list[index].is_dk;
}

/**
 * tomoyo_initializer_source - Check whether the given domain is marked as "initialize_domain".
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is marked as "initialize_domain",
 * false otherwise.
 */
static _Bool tomoyo_initializer_source(const int index)
{
	return tomoyo_dp.list[index].is_dis;
}

/**
 * tomoyo_initializer_target - Check whether the given domain is a target of "initialize_domain".
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is a target of "initialize_domain",
 * false otherwise.
 */
static _Bool tomoyo_initializer_target(const int index)
{
	return tomoyo_dp.list[index].is_dit;
}

/**
 * tomoyo_domain_unreachable - Check whether the given domain is unreachable or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is unreachable, false otherwise.
 *
 * TODO: Check "task auto_domain_transition" and
 * "task manual_domain_transition" which allow other domains to reach
 * the given domain.
 */
static _Bool tomoyo_domain_unreachable(const int index)
{
	return tomoyo_dp.list[index].is_du;
}

/**
 * tomoyo_deleted_domain - Check whether the given domain is marked as deleted or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is marked as deleted, false otherwise.
 */
static _Bool tomoyo_deleted_domain(const int index)
{
	return tomoyo_dp.list[index].is_dd;
}

/**
 * tomoyo_gacl_compare0 - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int tomoyo_gacl_compare0(const void *a, const void *b)
{
	const struct tomoyo_generic_acl *a0 = (struct tomoyo_generic_acl *) a;
	const struct tomoyo_generic_acl *b0 = (struct tomoyo_generic_acl *) b;
	const char *a1 = tomoyo_directives[a0->directive].alias;
	const char *b1 = tomoyo_directives[b0->directive].alias;
	const char *a2 = a0->operand;
	const char *b2 = b0->operand;
	const int ret = strcmp(a1, b1);
	if (ret)
		return ret;
	return strcmp(a2, b2);
}

/**
 * tomoyo_string_acl_compare - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int tomoyo_string_acl_compare(const void *a, const void *b)
{
	const struct tomoyo_generic_acl *a0 = (struct tomoyo_generic_acl *) a;
	const struct tomoyo_generic_acl *b0 = (struct tomoyo_generic_acl *) b;
	const char *a1 = a0->operand;
	const char *b1 = b0->operand;
	return strcmp(a1, b1);
}

/**
 * tomoyo_add_transition_control_policy - Add "reset_domain"/"no_reset_domain"/"initialize_domain"/"no_initialize_domain"/"keep_domain"/"no_keep_domain" entries.
 *
 * @data: Line to parse.
 * @type: One of values in "enum tomoyo_transition_type".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_add_transition_control_policy
(char *data, const enum tomoyo_transition_type type)
{
	char *domainname = strstr(data, " from ");
	if (domainname) {
		*domainname = '\0';
		domainname += 6;
	} else if (type == TOMOYO_TRANSITION_CONTROL_NO_KEEP ||
		   type == TOMOYO_TRANSITION_CONTROL_KEEP) {
		domainname = data;
		data = NULL;
	}
	return tomoyo_add_transition_control_entry(domainname, data, type);
}

/**
 * tomoyo_add_path_group_policy - Add "path_group" entry.
 *
 * @data:      Line to parse.
 * @is_delete: True if it is delete request, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_add_path_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return tomoyo_add_path_group_entry(data, cp, is_delete);
}

/**
 * tomoyo_assign_dis - Assign domain initializer source domain.
 *
 * @domainname: Pointer to "const struct tomoyo_path_info".
 * @program:    Program name.
 * @is_root:    True if root of namespace, false otherwise.
 */
static void tomoyo_assign_dis(const struct tomoyo_path_info *domainname,
			   const char *program, const bool is_root)
{
	const struct tomoyo_transition_control_entry *d_t =
		tomoyo_transition_control(domainname, program);
	/*
	 * Don't create source domains under root of namespace because they
	 * will become target domains. However, create them under root of
	 * namespace anyway if namespace jump, for we need to indicate it.
	 */
	if (d_t && ((!is_root &&
		     d_t->type == TOMOYO_TRANSITION_CONTROL_INITIALIZE) ||
		    d_t->type == TOMOYO_TRANSITION_CONTROL_RESET)) {
		char *line;
		int source;
		tomoyo_get();
		if (d_t->type == TOMOYO_TRANSITION_CONTROL_INITIALIZE)
			line = tomoyo_shprintf("%s %s", domainname->name,
					    program);
		else
			line = tomoyo_shprintf("%s <%s>", domainname->name,
					    program);
		tomoyo_normalize_line(line);
		source = tomoyo_assign_domain(&tomoyo_dp, line, true, false);
		if (d_t->type == TOMOYO_TRANSITION_CONTROL_INITIALIZE)
			line = tomoyo_shprintf("%s %s", tomoyo_current_ns, program);
		else
			line = tomoyo_shprintf("<%s>", program);
		tomoyo_dp.list[source].target_domainname = tomoyo_strdup(line);
		tomoyo_put();
	}
}

/**
 * tomoyo_domainname_attribute_compare - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int tomoyo_domainname_attribute_compare(const void *a, const void *b)
{
	const struct tomoyo_domain_info *a0 = a;
	const struct tomoyo_domain_info *b0 = b;
	const int k = strcmp(a0->domainname->name, b0->domainname->name);
	if ((k > 0) || (!k && !a0->is_dis && b0->is_dis))
		return 1;
	return k;
}

/**
 * tomoyo_find_target_domain - Find the initialize_domain target domain.
 *
 * @index: Index in the domain policy.
 *
 * Returns index in the domain policy if found, -2 if namespace jump,
 * EOF otherwise.
 */
static int tomoyo_find_target_domain(const int index)
{
	const char *cp = tomoyo_dp.list[index].target_domainname;
	if (!tomoyo_is_current_namespace(cp))
		return -2;
	return tomoyo_find_domain(&tomoyo_dp, cp, false, false);
}

/**
 * tomoyo_show_domain_line - Show a line of the domain transition tree.
 *
 * @index: Index in the domain policy.
 *
 * Returns length of the printed line.
 */
static int tomoyo_show_domain_line(const int index)
{
	int tmp_col = 0;
	const struct tomoyo_transition_control_entry *transition_control;
	char *line;
	const char *sp;
	const int number = tomoyo_dp.list[index].number;
	int redirect_index;
	const bool is_dis = tomoyo_initializer_source(index);
	const bool is_deleted = tomoyo_deleted_domain(index);
	if (number >= 0) {
		printw("%c%4d:", tomoyo_dp.list_selected[index] ? '&' : ' ',
		       number);
		if (tomoyo_dp.list[index].profile_assigned)
			printw("%3u", tomoyo_dp.list[index].profile);
		else
			printw("???");
		printw(" %c%c%c ", tomoyo_keeper_domain(index) ? '#' : ' ',
		       tomoyo_initializer_target(index) ? '*' : ' ',
		       tomoyo_domain_unreachable(index) ? '!' : ' ');
	} else
		printw("              ");
	tmp_col += 14;
	sp = tomoyo_domain_name(&tomoyo_dp, index);
	while (true) {
		const char *cp = strchr(sp, ' ');
		if (!cp)
			break;
		printw("%s", tomoyo_eat("    "));
		tmp_col += 4;
		sp = cp + 1;
	}
	if (is_deleted) {
		printw("%s", tomoyo_eat("( "));
		tmp_col += 2;
	}
	printw("%s", tomoyo_eat(sp));
	tmp_col += strlen(sp);
	if (is_deleted) {
		printw("%s", tomoyo_eat(" )"));
		tmp_col += 2;
	}
	transition_control = tomoyo_dp.list[index].d_t;
	if (!transition_control || is_dis)
		goto no_transition_control;
	tomoyo_get();
	line = tomoyo_shprintf(" ( %s%s from %s )",
			    tomoyo_transition_type[transition_control->type],
			    transition_control->program ?
			    transition_control->program->name : "any",
			    transition_control->domainname ?
			    transition_control->domainname->name : "any");
	printw("%s", tomoyo_eat(line));
	tmp_col += strlen(line);
	tomoyo_put();
	goto done;
no_transition_control:
	if (!is_dis)
		goto done;
	tomoyo_get();
	redirect_index = tomoyo_find_target_domain(index);
	if (redirect_index >= 0)
		line = tomoyo_shprintf(" ( -> %d )",
				    tomoyo_dp.list[redirect_index].number);
	else if (redirect_index == EOF)
		line = tomoyo_shprintf(" ( -> Not Found )");
	else
		line = tomoyo_shprintf(" ( -> Namespace jump )");
	printw("%s", tomoyo_eat(line));
	tmp_col += strlen(line);
	tomoyo_put();
done:
	return tmp_col;
}

/**
 * tomoyo_show_acl_line - Print an ACL line.
 *
 * @index:       Index in the generic list.
 * @list_indent: Indent size.
 *
 * Returns length of the printed line.
 */
static int tomoyo_show_acl_line(const int index, const int list_indent)
{
	const enum tomoyo_editpolicy_directives directive =
		tomoyo_gacl_list[index].directive;
	const char *cp1 = tomoyo_directives[directive].alias;
	const char *cp2 = tomoyo_gacl_list[index].operand;
	int len = list_indent - tomoyo_directives[directive].alias_len;
	printw("%c%4d: %s ",
	       tomoyo_gacl_list[index].selected ? '&' : ' ',
	       index, tomoyo_eat(cp1));
	while (len-- > 0)
		printw("%s", tomoyo_eat(" "));
	printw("%s", tomoyo_eat(cp2));
	return strlen(cp1) + strlen(cp2) + 8 + list_indent;
}

/**
 * tomoyo_show_profile_line - Print a profile line.
 *
 * @index: Index in the generic list.
 *
 * Returns length of the printed line.
 */
static int tomoyo_show_profile_line(const int index)
{
	const char *cp = tomoyo_gacl_list[index].operand;
	const u16 profile = tomoyo_gacl_list[index].directive;
	char number[8] = "";
	if (profile <= 256)
		snprintf(number, sizeof(number) - 1, "%3u-", profile);
	printw("%c%4d: %s", tomoyo_gacl_list[index].selected ? '&' : ' ',
	       index, tomoyo_eat(number));
	printw("%s ", tomoyo_eat(cp));
	return strlen(number) + strlen(cp) + 8;
}

/**
 * tomoyo_show_literal_line - Print a literal line.
 *
 * @index: Index in the generic list.
 *
 * Returns length of the printed line.
 */
static int tomoyo_show_literal_line(const int index)
{
	const char *cp = tomoyo_gacl_list[index].operand;
	printw("%c%4d: %s ",
	       tomoyo_gacl_list[index].selected ? '&' : ' ',
	       index, tomoyo_eat(cp));
	return strlen(cp) + 8;
}

/**
 * tomoyo_show_stat_line - Print a statistics line.
 *
 * @index: Index in the generic list.
 *
 * Returns length of the printed line.
 */
static int tomoyo_show_stat_line(const int index)
{
	char *line;
	unsigned int now;
	tomoyo_get();
	line = tomoyo_shprintf("%s", tomoyo_gacl_list[index].operand);
	if (line[0])
		printw("%s", tomoyo_eat(line));
	now = strlen(line);
	tomoyo_put();
	return now;
}

/**
 * tomoyo_show_command_key - Print help screen.
 *
 * @screen:   Currently selected screen.
 * @readonly: True if readonly_mopde, false otherwise.
 *
 * Returns true to continue, false to quit.
 */
static _Bool tomoyo_show_command_key(const enum tomoyo_screen_type screen,
				  const _Bool readonly)
{
	int c;
	clear();
	printw("Commands available for this screen are:\n\n");
	printw("Q/q        Quit this editor.\n");
	printw("R/r        Refresh to the latest information.\n");
	switch (screen) {
	case TOMOYO_SCREEN_STAT_LIST:
		break;
	default:
		printw("F/f        Find first.\n");
		printw("N/n        Find next.\n");
		printw("P/p        Find previous.\n");
	}
	printw("W/w        Switch to selected screen.\n");
	/* printw("Tab        Switch to next screen.\n"); */
	switch (screen) {
	case TOMOYO_SCREEN_STAT_LIST:
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
	case TOMOYO_SCREEN_DOMAIN_LIST:
		if (tomoyo_domain_sort_type) {
			printw("S/s        Set profile number of selected "
			       "processes.\n");
			printw("Enter      Edit ACLs of a process at the "
			       "cursor position.\n");
		} else {
			if (!readonly) {
				printw("A/a        Add a new domain.\n");
				printw("D/d        Delete selected domains."
				       "\n");
				printw("S/s        Set profile number of "
				       "selected domains.\n");
			}
			printw("Enter      Edit ACLs of a domain at the "
			       "cursor position.\n");
		}
		break;
	case TOMOYO_SCREEN_STAT_LIST:
		if (!readonly)
			printw("S/s        Set memory quota of selected "
			       "items.\n");
		break;
	case TOMOYO_SCREEN_PROFILE_LIST:
		if (!readonly)
			printw("S/s        Set mode of selected items.\n");
		break;
	default:
		break;
	}
	switch (screen) {
	case TOMOYO_SCREEN_EXCEPTION_LIST:
	case TOMOYO_SCREEN_ACL_LIST:
	case TOMOYO_SCREEN_MANAGER_LIST:
		if (!readonly) {
			printw("A/a        Add a new entry.\n");
			printw("D/d        Delete selected entries.\n");
		}
	default:
		break;
	}
	switch (screen) {
	case TOMOYO_SCREEN_PROFILE_LIST:
		if (!readonly)
			printw("A/a        Define a new profile.\n");
	default:
		break;
	}
	switch (screen) {
	case TOMOYO_SCREEN_ACL_LIST:
		printw("O/o        Set selection state to other entries "
		       "included in an entry at the cursor position.\n");
		/* Fall through. */
	case TOMOYO_SCREEN_PROFILE_LIST:
		printw("@          Switch sort type.\n");
		break;
	case TOMOYO_SCREEN_DOMAIN_LIST:
		if (!tomoyo_offline_mode)
			printw("@          Switch domain/process list.\n");
	default:
		break;
	}
	printw("Arrow-keys and PageUp/PageDown/Home/End keys "
	       "for scroll.\n\n");
	printw("Press '?' to escape from this help.\n");
	refresh();
	while (true) {
		c = tomoyo_getch2();
		if (c == '?' || c == EOF)
			break;
		if (c == 'Q' || c == 'q')
			return false;
	}
	return true;
}

/**
 * tomoyo_set_error - Set error line's caption.
 *
 * @filename: Filename to print. Maybe NULL.
 *
 * Returns nothing.
 */
static void tomoyo_set_error(const char *filename)
{
	if (filename) {
		const int len = strlen(filename) + 128;
		tomoyo_last_error = tomoyo_realloc2(tomoyo_last_error, len);
		snprintf(tomoyo_last_error, len - 1, "Can't open %s .", filename);
	} else {
		free(tomoyo_last_error);
		tomoyo_last_error = NULL;
	}
}

/**
 * tomoyo_send_fd - Send file descriptor.
 *
 * @data: String data to send with file descriptor.
 * @fd:   Pointer to file desciptor.
 *
 * Returns nothing.
 */
static void tomoyo_send_fd(char *data, int *fd)
{
	struct msghdr msg;
	struct iovec iov = { data, strlen(data) };
	char cmsg_buf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg = (struct cmsghdr *) cmsg_buf;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	msg.msg_controllen = cmsg->cmsg_len;
	memmove(CMSG_DATA(cmsg), fd, sizeof(int));
	sendmsg(tomoyo_persistent_fd, &msg, 0);
	close(*fd);
}

/**
 * tomoyo_editpolicy_open_write - Wrapper for tomoyo_open_write().
 *
 * @filename: File to open for writing.
 *
 * Returns pointer to "FILE" on success, NULL otherwise.
 *
 * Since CUI policy editor screen provides a line for printing error message,
 * this function sets error line if failed. Also, this function returns NULL if
 * readonly mode.
 */
static FILE *tomoyo_editpolicy_open_write(const char *filename)
{
	if (tomoyo_network_mode) {
		FILE *fp = tomoyo_open_write(filename);
		if (!fp)
			tomoyo_set_error(filename);
		return fp;
	} else if (tomoyo_offline_mode) {
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
		tomoyo_send_fd(request, &fd[1]);
		return fdopen(fd[0], "w");
out:
		close(fd[1]);
		close(fd[0]);
		exit(1);
	} else {
		FILE *fp;
		if (tomoyo_readonly_mode)
			return NULL;
		fp = tomoyo_open_write(filename);
		if (!fp)
			tomoyo_set_error(filename);
		return fp;
	}
}

/**
 * tomoyo_editpolicy_open_read - Wrapper for tomoyo_open_read().
 *
 * @filename: File to open for reading.
 *
 * Returns pointer to "FILE" on success, NULL otherwise.
 *
 * Since CUI policy editor screen provides a line for printing error message,
 * this function sets error line if failed.
 */
static FILE *tomoyo_editpolicy_open_read(const char *filename)
{
	if (tomoyo_network_mode) {
		return tomoyo_open_read(filename);
	} else if (tomoyo_offline_mode) {
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
		tomoyo_send_fd(request, &fd[1]);
		return fp;
out:
		close(fd[1]);
		close(fd[0]);
		exit(1);
	} else {
		return fopen(filename, "r");
	}
}

/**
 * tomoyo_open2 - Wrapper for open().
 *
 * @filename: File to open.
 * @mode:     Flags to passed to open().
 *
 * Returns file descriptor on success, EOF otherwise.
 *
 * Since CUI policy editor screen provides a line for printing error message,
 * this function sets error line if failed.
 */
static int tomoyo_open2(const char *filename, int mode)
{
	const int fd = open(filename, mode);
	if (fd == EOF && errno != ENOENT)
		tomoyo_set_error(filename);
	return fd;
}

/**
 * tomoyo_sigalrm_handler - Callback routine for timer interrupt.
 *
 * @sig: Signal number. Not used.
 *
 * Returns nothing.
 *
 * This function is called when tomoyo_refresh_interval is non-zero. This function
 * marks current screen to reload. Also, this function reenables timer event.
 */
static void tomoyo_sigalrm_handler(int sig)
{
	tomoyo_need_reload = true;
	alarm(tomoyo_refresh_interval);
}

/**
 * tomoyo_eat - Shift string data before displaying.
 *
 * @str: String to be displayed.
 *
 * Returns shifted string.
 */
static const char *tomoyo_eat(const char *str)
{
	while (*str && tomoyo_eat_col) {
		str++;
		tomoyo_eat_col--;
	}
	return str;
}

/**
 * tomoyo_transition_control - Find domain transition control.
 *
 * @domainname: Pointer to "const struct tomoyo_path_info".
 * @program:    Program name.
 *
 * Returns pointer to "const struct tomoyo_transition_control_entry" if found one,
 * NULL otherwise.
 */
static const struct tomoyo_transition_control_entry *tomoyo_transition_control
(const struct tomoyo_path_info *domainname, const char *program)
{
	int i;
	u8 type;
	struct tomoyo_path_info last_name;
	last_name.name = tomoyo_get_last_word(domainname->name);
	tomoyo_fill_path_info(&last_name);
	for (type = 0; type < TOMOYO_MAX_TRANSITION_TYPE; type++) {
next:
		for (i = 0; i < tomoyo_transition_control_list_len; i++) {
			struct tomoyo_transition_control_entry *ptr
				= &tomoyo_transition_control_list[i];
			if (ptr->type != type)
				continue;
			if (ptr->domainname) {
				if (!ptr->is_last_name) {
					if (tomoyo_pathcmp(ptr->domainname,
							domainname))
						continue;
				} else {
					if (tomoyo_pathcmp(ptr->domainname,
							&last_name))
						continue;
				}
			}
			if (ptr->program &&
			    strcmp(ptr->program->name, program))
				continue;
			if (type == TOMOYO_TRANSITION_CONTROL_NO_RESET) {
				/*
				 * Do not check for reset_domain if
				 * no_reset_domain matched.
				 */
				type = TOMOYO_TRANSITION_CONTROL_NO_INITIALIZE;
				goto next;
			}
			if (type == TOMOYO_TRANSITION_CONTROL_NO_INITIALIZE) {
				/*
				 * Do not check for initialize_domain if
				 * no_initialize_domain matched.
				 */
				type = TOMOYO_TRANSITION_CONTROL_NO_KEEP;
				goto next;
			}
			if (type == TOMOYO_TRANSITION_CONTROL_RESET ||
			    type == TOMOYO_TRANSITION_CONTROL_INITIALIZE ||
			    type == TOMOYO_TRANSITION_CONTROL_KEEP)
				return ptr;
			else
				return NULL;
		}
	}
	return NULL;
}

/**
 * tomoyo_profile_entry_compare -  strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int tomoyo_profile_entry_compare(const void *a, const void *b)
{
	const struct tomoyo_generic_acl *a0 = (struct tomoyo_generic_acl *) a;
	const struct tomoyo_generic_acl *b0 = (struct tomoyo_generic_acl *) b;
	const char *a1 = a0->operand;
	const char *b1 = b0->operand;
	const int a2 = a0->directive;
	const int b2 = b0->directive;
	if (a2 >= 256 || b2 >= 256) {
		if (a1[0] == 'P')
			return -1;
		if (b1[0] == 'P')
			return 1;
	}
	if (!tomoyo_profile_sort_type) {
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

/**
 * tomoyo_add_generic_entry - Add text lines.
 *
 * @line:      Line to add.
 * @directive: One of values in "enum tomoyo_editpolicy_directives".
 *
 * Returns true if this line deals current namespace, false otherwise.
 */
static void tomoyo_add_generic_entry(const char *line, const enum
				  tomoyo_editpolicy_directives directive)
{
	int i;
	for (i = 0; i < tomoyo_gacl_list_count; i++)
		if (tomoyo_gacl_list[i].directive == directive &&
		    !strcmp(line, tomoyo_gacl_list[i].operand))
			return;
	i = tomoyo_gacl_list_count++;
	tomoyo_gacl_list = tomoyo_realloc(tomoyo_gacl_list, tomoyo_gacl_list_count *
				    sizeof(struct tomoyo_generic_acl));
	tomoyo_gacl_list[i].directive = directive;
	tomoyo_gacl_list[i].selected = 0;
	tomoyo_gacl_list[i].operand = tomoyo_strdup(line);
}

/**
 * tomoyo_read_generic_policy - Read policy data other than domain policy.
 *
 * Returns nothing.
 */
static void tomoyo_read_generic_policy(void)
{
	FILE *fp = NULL;
	_Bool flag = false;
	const _Bool is_kernel_ns = !strcmp(tomoyo_current_ns, "<kernel>");
	while (tomoyo_gacl_list_count)
		free((void *) tomoyo_gacl_list[--tomoyo_gacl_list_count].operand);
	if (tomoyo_current_screen == TOMOYO_SCREEN_ACL_LIST) {
		if (tomoyo_network_mode)
			/* We can read after write. */
			fp = tomoyo_editpolicy_open_write(tomoyo_policy_file);
		else if (!tomoyo_offline_mode)
			/* Don't set error message if failed. */
			fp = fopen(tomoyo_policy_file, "r+");
		if (fp) {
			if (tomoyo_domain_sort_type)
				fprintf(fp, "select pid=%u\n",
					tomoyo_current_pid);
			else
				fprintf(fp, "select domain=%s\n",
					tomoyo_current_domain);
			if (tomoyo_network_mode)
				fputc(0, fp);
			fflush(fp);
		}
	} else if (tomoyo_current_screen == TOMOYO_SCREEN_NS_LIST) {
		tomoyo_add_generic_entry("<kernel>", TOMOYO_DIRECTIVE_NONE);
	}
	if (!fp)
		fp = tomoyo_editpolicy_open_read(tomoyo_policy_file);
	if (!fp) {
		tomoyo_set_error(tomoyo_policy_file);
		return;
	}
	tomoyo_freadline_raw = tomoyo_current_screen == TOMOYO_SCREEN_STAT_LIST;
	tomoyo_get();
	while (true) {
		char *line = tomoyo_freadline_unpack(fp);
		enum tomoyo_editpolicy_directives directive;
		char *cp;
		if (!line)
			break;
		if (tomoyo_current_screen == TOMOYO_SCREEN_ACL_LIST) {
			if (tomoyo_domain_def(line)) {
				flag = !strcmp(line, tomoyo_current_domain);
				continue;
			}
			if (!flag || !line[0] ||
			    !strncmp(line, "use_profile ", 12))
				continue;
		} else {
			if (!line[0])
				continue;
		}
		if (tomoyo_current_screen == TOMOYO_SCREEN_EXCEPTION_LIST ||
		    tomoyo_current_screen == TOMOYO_SCREEN_PROFILE_LIST) {
			if (*line == '<') {
				cp = strchr(line, ' ');
				if (!cp++ || !tomoyo_is_current_namespace(line))
					continue;
				memmove(line, cp, strlen(cp) + 1);
			} else if (!is_kernel_ns)
				continue;
		}
		switch (tomoyo_current_screen) {
		case TOMOYO_SCREEN_EXCEPTION_LIST:
			directive = tomoyo_find_directive(true, line);
			if (directive == TOMOYO_DIRECTIVE_NONE)
				continue;
			/* Remember groups for tomoyo_editpolicy_optimize(). */
			if (directive != TOMOYO_DIRECTIVE_PATH_GROUP &&
			    directive != TOMOYO_DIRECTIVE_NUMBER_GROUP &&
			    directive != TOMOYO_DIRECTIVE_ADDRESS_GROUP)
				break;
			cp = tomoyo_strdup(line);
			if (directive == TOMOYO_DIRECTIVE_PATH_GROUP)
				tomoyo_add_path_group_policy(cp, false);
			else if (directive == TOMOYO_DIRECTIVE_NUMBER_GROUP)
				tomoyo_add_number_group_policy(cp, false);
			else
				tomoyo_add_address_group_policy(cp, false);
			free(cp);
			break;
		case TOMOYO_SCREEN_ACL_LIST:
			directive = tomoyo_find_directive(true, line);
			if (directive == TOMOYO_DIRECTIVE_NONE)
				continue;
			break;
		case TOMOYO_SCREEN_PROFILE_LIST:
			cp = strchr(line, '-');
			if (cp) {
				*cp++ = '\0';
				directive = atoi(line);
				memmove(line, cp, strlen(cp) + 1);
			} else
				directive = (u16) -1;
			break;
		case TOMOYO_SCREEN_NS_LIST:
			if (*line != '<')
				continue;
			cp = strchr(line, ' ');
			if (!cp)
				continue;
			*cp = '\0';
			if (!tomoyo_domain_def(line))
				continue;
			/* Fall through. */
		default:
			directive = TOMOYO_DIRECTIVE_NONE;
			break;
		}
		tomoyo_add_generic_entry(line, directive);
	}
	tomoyo_put();
	tomoyo_freadline_raw = false;
	fclose(fp);
	switch (tomoyo_current_screen) {
	case TOMOYO_SCREEN_ACL_LIST:
		qsort(tomoyo_gacl_list, tomoyo_gacl_list_count,
		      sizeof(struct tomoyo_generic_acl), tomoyo_gacl_compare);
		break;
	case TOMOYO_SCREEN_EXCEPTION_LIST:
		qsort(tomoyo_gacl_list, tomoyo_gacl_list_count,
		      sizeof(struct tomoyo_generic_acl),
		      tomoyo_gacl_compare0);
		break;
	case TOMOYO_SCREEN_PROFILE_LIST:
		qsort(tomoyo_gacl_list, tomoyo_gacl_list_count,
		      sizeof(struct tomoyo_generic_acl),
		      tomoyo_profile_entry_compare);
		break;
	case TOMOYO_SCREEN_STAT_LIST:
		break;
	default:
		qsort(tomoyo_gacl_list, tomoyo_gacl_list_count,
		      sizeof(struct tomoyo_generic_acl), tomoyo_string_acl_compare);
	}
}

/**
 * tomoyo_add_transition_control_entry - Add "initialize_domain"/"no_initialize_domain"/"keep_domain"/ "no_keep_domain" entries.
 *
 * @domainname: Domainname.
 * @program:    Program name.
 * @type:       One of values in "enum tomoyo_transition_type".
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int tomoyo_add_transition_control_entry
(const char *domainname, const char *program,
 const enum tomoyo_transition_type type)
{
	struct tomoyo_transition_control_entry *ptr;
	_Bool is_last_name = false;
	if (program && strcmp(program, "any")) {
		if (!tomoyo_correct_path(program))
			return -EINVAL;
	}
	if (domainname && strcmp(domainname, "any")) {
		if (!tomoyo_correct_domain(domainname)) {
			if (!tomoyo_correct_path(domainname))
				return -EINVAL;
			is_last_name = true;
		}
	}
	tomoyo_transition_control_list =
		tomoyo_realloc(tomoyo_transition_control_list,
			    (tomoyo_transition_control_list_len + 1) *
			    sizeof(struct tomoyo_transition_control_entry));
	ptr = &tomoyo_transition_control_list[tomoyo_transition_control_list_len++];
	memset(ptr, 0, sizeof(struct tomoyo_transition_control_entry));
	if (program && strcmp(program, "any"))
		ptr->program = tomoyo_savename(program);
	if (domainname && strcmp(domainname, "any"))
		ptr->domainname = tomoyo_savename(domainname);
	ptr->type = type;
	ptr->is_last_name = is_last_name;
	return 0;
}

/**
 * tomoyo_add_path_group_entry - Add "path_group" entry.
 *
 * @group_name:  Name of address group.
 * @member_name: Address string.
 * @is_delete:   True if it is delete request, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int tomoyo_add_path_group_entry(const char *group_name,
				    const char *member_name,
				    const _Bool is_delete)
{
	const struct tomoyo_path_info *saved_group_name;
	const struct tomoyo_path_info *saved_member_name;
	int i;
	int j;
	struct tomoyo_path_group_entry *group = NULL;
	if (!tomoyo_correct_word(group_name) || !tomoyo_correct_word(member_name))
		return -EINVAL;
	saved_group_name = tomoyo_savename(group_name);
	saved_member_name = tomoyo_savename(member_name);
	for (i = 0; i < tomoyo_path_group_list_len; i++) {
		group = &tomoyo_path_group_list[i];
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
	if (i == tomoyo_path_group_list_len) {
		tomoyo_path_group_list =
			tomoyo_realloc(tomoyo_path_group_list,
				    (tomoyo_path_group_list_len + 1) *
				    sizeof(struct tomoyo_path_group_entry));
		group = &tomoyo_path_group_list[tomoyo_path_group_list_len++];
		memset(group, 0, sizeof(struct tomoyo_path_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name =
		tomoyo_realloc(group->member_name, (group->member_name_len + 1) *
			    sizeof(const struct tomoyo_path_info *));
	group->member_name[group->member_name_len++] = saved_member_name;
	return 0;
}

/*
 * List of "task auto_domain_transition" "task manual_domain_transition"
 * "auto_domain_transition=" part.
 */
static char **tomoyo_jump_list = NULL;
static int tomoyo_jump_list_len = 0;

/**
 * tomoyo_add_condition_domain_transition - Add auto_domain_transition= part.
 *
 * @line:  Line to parse.
 * @index: Current domain's index.
 *
 * Returns nothing.
 */
static void tomoyo_add_condition_domain_transition(char *line, const int index)
{
	static char domainname[4096];
	int source;
	char *cp = strrchr(line, ' ');
	if (!cp)
		return;
	if (strncmp(cp, " auto_domain_transition=\"", 25))
		return;
	*cp = '\0';
	cp += 25;
	source = strlen(cp);
	if (!source)
		return;
	cp[source - 1] = '\0';
	snprintf(domainname, sizeof(domainname) - 1, "%s %s",
		 tomoyo_domain_name(&tomoyo_dp, index), cp);
	domainname[sizeof(domainname) - 1] = '\0';
	tomoyo_normalize_line(domainname);
	tomoyo_jump_list = tomoyo_realloc(tomoyo_jump_list,
				    (tomoyo_jump_list_len + 1) * sizeof(char *));
	tomoyo_jump_list[tomoyo_jump_list_len++] = tomoyo_strdup(domainname);
	source = tomoyo_assign_domain(&tomoyo_dp, domainname, true, false);
	if (*cp == '<')
		snprintf(domainname, sizeof(domainname) - 1, "%s", cp);
	tomoyo_dp.list[source].target_domainname = tomoyo_strdup(domainname);
}

/**
 * tomoyo_add_acl_domain_transition - Add task acl.
 *
 * @line:  Line to parse.
 * @index: Current domain's index.
 *
 * Returns nothing.
 */
static void tomoyo_add_acl_domain_transition(char *line, const int index)
{
	static char domainname[4096];
	int source;
	for (source = 0; line[source]; source++)
		if (line[source] == ' ' && line[source + 1] != '/') {
			line[source] = '\0';
			break;
		}
	if (!tomoyo_correct_domain(line))
		return;
	tomoyo_jump_list = tomoyo_realloc(tomoyo_jump_list,
				    (tomoyo_jump_list_len + 1) * sizeof(char *));
	tomoyo_jump_list[tomoyo_jump_list_len++] = tomoyo_strdup(line);
	snprintf(domainname, sizeof(domainname) - 1, "%s %s",
		 tomoyo_domain_name(&tomoyo_dp, index), tomoyo_get_last_word(line));
	domainname[sizeof(domainname) - 1] = '\0';
	tomoyo_normalize_line(domainname);
	source = tomoyo_assign_domain(&tomoyo_dp, domainname, true, false);
	tomoyo_dp.list[source].target_domainname = tomoyo_strdup(line);
}

/**
 * tomoyo_parse_domain_line - Parse an ACL entry in domain policy.
 *
 * @line:        Line to parse.
 * @index:       Current domain's index.
 * @parse_flags: True if parse use_profile and use_group lines, false
 *               otherwise.
 *
 * Returns nothing.
 */
static void tomoyo_parse_domain_line(char *line, const int index,
				  const bool parse_flags)
{
	tomoyo_add_condition_domain_transition(line, index);
	if (tomoyo_str_starts(line, "task auto_execute_handler ") ||
	    tomoyo_str_starts(line, "task denied_execute_handler ") ||
	    tomoyo_str_starts(line, "file execute ")) {
		char *cp = strchr(line, ' ');
		if (cp)
			*cp = '\0';
		if (*line == '@' || tomoyo_correct_path(line))
			tomoyo_add_string_entry(&tomoyo_dp, line, index);
	} else if (tomoyo_str_starts(line,
				  "task auto_domain_transition ") ||
		   tomoyo_str_starts(line,
				  "task manual_domain_transition ")) {
		tomoyo_add_acl_domain_transition(line, index);
	} else if (parse_flags) {
		unsigned int profile;
		if (sscanf(line, "use_profile %u", &profile) == 1) {
			tomoyo_dp.list[index].profile = (u8) profile;
			tomoyo_dp.list[index].profile_assigned = 1;
		} else if (sscanf(line, "use_group %u", &profile) == 1) {
			tomoyo_dp.list[index].group = (u8) profile;
		}
	}
}

/**
 * tomoyo_parse_exception_line - Parse an ACL entry in exception policy.
 *
 * @line:      Line to parse.
 * @max_index: Number of domains currently defined.
 *
 * Returns nothing.
 */
static void tomoyo_parse_exception_line(char *line, const int max_index)
{
	unsigned int group;
	for (group = 0; group < TOMOYO_MAX_TRANSITION_TYPE; group++) {
		if (!tomoyo_str_starts(line, tomoyo_transition_type[group]))
			continue;
		tomoyo_add_transition_control_policy(line, group);
		return;
	}
	if (tomoyo_str_starts(line, "path_group "))
		tomoyo_add_path_group_policy(line, false);
	else if (tomoyo_str_starts(line, "address_group "))
		tomoyo_add_address_group_policy(line, false);
	else if (tomoyo_str_starts(line, "number_group "))
		tomoyo_add_number_group_policy(line, false);
	else if (sscanf(line, "acl_group %u", &group) == 1 && group < 256) {
		int index;
		char *cp = strchr(line + 10, ' ');
		if (cp)
			line = cp + 1;
		for (index = 0; index < max_index; index++) {
			if (tomoyo_dp.list[index].group != group)
				continue;
			cp = tomoyo_strdup(line);
			tomoyo_parse_domain_line(cp, index, false);
			free(cp);
		}
	}
}

/**
 * tomoyo_read_domain_and_exception_policy - Read domain policy and exception policy.
 *
 * Returns nothing.
 *
 * Since CUI policy editor screen shows domain initializer source domains and
 * unreachable domains, we need to read not only the domain policy but also
 * the exception policy for printing the domain transition tree.
 */
static void tomoyo_read_domain_and_exception_policy(void)
{
	FILE *fp;
	int i;
	int j;
	int index;
	int max_index;
	while (tomoyo_jump_list_len)
		free(tomoyo_jump_list[--tomoyo_jump_list_len]);
	tomoyo_clear_domain_policy(&tomoyo_dp);
	tomoyo_transition_control_list_len = 0;
	tomoyo_editpolicy_clear_groups();

	/* Load all domain transition related entries. */
	fp = NULL;
	if (tomoyo_network_mode)
		/* We can read after write. */
		fp = tomoyo_editpolicy_open_write(TOMOYO_PROC_POLICY_DOMAIN_POLICY);
	else if (!tomoyo_offline_mode)
		/* Don't set error message if failed. */
		fp = fopen(TOMOYO_PROC_POLICY_DOMAIN_POLICY, "r+");
	if (fp) {
		fprintf(fp, "select transition_only\n");
		if (tomoyo_network_mode)
			fputc(0, fp);
		fflush(fp);
	} else {
		fp = tomoyo_editpolicy_open_read(TOMOYO_PROC_POLICY_DOMAIN_POLICY);
	}
	if (fp) {
		index = EOF;
		tomoyo_get();
		while (true) {
			char *line = tomoyo_freadline_unpack(fp);
			if (!line)
				break;
			if (*line == '<') {
				if (!tomoyo_is_current_namespace(line)) {
					index = EOF;
					continue;
				}
				index = tomoyo_assign_domain(&tomoyo_dp, line, false,
							  false);
				continue;
			} else if (index == EOF) {
				continue;
			}
			tomoyo_parse_domain_line(line, index, true);
		}
		tomoyo_put();
		fclose(fp);
	} else {
		tomoyo_set_error(TOMOYO_PROC_POLICY_DOMAIN_POLICY);
	}

	max_index = tomoyo_dp.list_len;

	/* Load domain transition related entries and group entries. */
	fp = NULL;
	if (tomoyo_network_mode)
		/* We can read after write. */
		fp = tomoyo_editpolicy_open_write
			(TOMOYO_PROC_POLICY_EXCEPTION_POLICY);
	else if (!tomoyo_offline_mode)
		/* Don't set error message if failed. */
		fp = fopen(TOMOYO_PROC_POLICY_EXCEPTION_POLICY, "r+");
	if (fp) {
		fprintf(fp, "select transition_only\n");
		if (tomoyo_network_mode)
			fputc(0, fp);
		fflush(fp);
	} else {
		fp = tomoyo_editpolicy_open_read
			(TOMOYO_PROC_POLICY_EXCEPTION_POLICY);
	}
	if (fp) {
		tomoyo_get();
		while (true) {
			char *line = tomoyo_freadline_unpack(fp);
			if (!line)
				break;
			if (*line == '<') {
				char *cp = strchr(line, ' ');
				if (!cp++ || !tomoyo_is_current_namespace(line))
					continue;
				memmove(line, cp, strlen(cp) + 1);
			}
			tomoyo_parse_exception_line(line, max_index);
		}
		tomoyo_put();
		fclose(fp);
	} else {
		tomoyo_set_error(TOMOYO_PROC_POLICY_EXCEPTION_POLICY);
	}

	/*
	 * Find unreachable domains.
	 *
	 * This is calculated based on "initialize_domain" and "keep_domain"
	 * keywords. However, since "task auto_domain_transition" and "task
	 * manual_domain_transition" keywords and "auto_domain_transition="
	 * condition are not subjected to "initialize_domain" and "keep_domain"
	 * keywords, we need to adjust later.
	 */
	for (index = 0; index < max_index; index++) {
		char *line;
		tomoyo_get();
		line = tomoyo_shprintf("%s", tomoyo_domain_name(&tomoyo_dp, index));
		while (true) {
			const struct tomoyo_transition_control_entry *d_t;
			struct tomoyo_path_info parent;
			char *cp = strrchr(line, ' ');
			if (!cp)
				break;
			*cp++ = '\0';
			parent.name = line;
			tomoyo_fill_path_info(&parent);
			d_t = tomoyo_transition_control(&parent, cp);
			if (!d_t)
				continue;
			/* Initializer under root of namespace is reachable. */
			if (d_t->type == TOMOYO_TRANSITION_CONTROL_INITIALIZE &&
			    !strchr(parent.name, ' '))
				break;
			tomoyo_dp.list[index].d_t = d_t;
			continue;
		}
		tomoyo_put();
		if (tomoyo_dp.list[index].d_t)
			tomoyo_dp.list[index].is_du = true;
	}

	/* Find domain initializer target domains. */
	for (index = 0; index < max_index; index++) {
		char *cp = strchr(tomoyo_domain_name(&tomoyo_dp, index), ' ');
		if (!cp || strchr(cp + 1, ' '))
			continue;
		for (i = 0; i < tomoyo_transition_control_list_len; i++) {
			struct tomoyo_transition_control_entry *ptr
				= &tomoyo_transition_control_list[i];
			if (ptr->type != TOMOYO_TRANSITION_CONTROL_INITIALIZE)
				continue;
			if (ptr->program && strcmp(ptr->program->name, cp + 1))
				continue;
			tomoyo_dp.list[index].is_dit = true;
		}
	}

	/* Find domain keeper domains. */
	for (index = 0; index < max_index; index++) {
		for (i = 0; i < tomoyo_transition_control_list_len; i++) {
			struct tomoyo_transition_control_entry *ptr
				= &tomoyo_transition_control_list[i];
			char *cp;
			if (ptr->type != TOMOYO_TRANSITION_CONTROL_KEEP)
				continue;
			if (!ptr->is_last_name) {
				if (ptr->domainname &&
				    tomoyo_pathcmp(ptr->domainname,
						tomoyo_dp.list[index].domainname))
					continue;
				tomoyo_dp.list[index].is_dk = true;
				continue;
			}
			cp = strrchr(tomoyo_dp.list[index].domainname->name,
				     ' ');
			if (!cp || (ptr->domainname->name &&
				    strcmp(ptr->domainname->name, cp + 1)))
				continue;
			tomoyo_dp.list[index].is_dk = true;
		}
	}

	/* Create domain initializer source domains. */
	for (index = 0; index < max_index; index++) {
		const struct tomoyo_path_info *domainname
			= tomoyo_dp.list[index].domainname;
		const struct tomoyo_path_info **string_ptr
			= tomoyo_dp.list[index].string_ptr;
		const int max_count = tomoyo_dp.list[index].string_count;
		const bool is_root = !strchr(domainname->name, ' ');
		for (i = 0; i < max_count; i++) {
			const struct tomoyo_path_info *cp = string_ptr[i];
			struct tomoyo_path_group_entry *group;
			if (cp->name[0] != '@') {
				tomoyo_assign_dis(domainname, cp->name, is_root);
				continue;
			}
			group = tomoyo_find_path_group(cp->name + 1);
			if (!group)
				continue;
			for (j = 0; j < group->member_name_len; j++) {
				cp = group->member_name[j];
				tomoyo_assign_dis(domainname, cp->name, is_root);
			}
		}
	}

	/*
	 * Create domain jump target domains.
	 * This may reset unreachable domains.
	 */
	for (i = 0; i < tomoyo_jump_list_len; i++) {
		const int index = tomoyo_find_domain(&tomoyo_dp, tomoyo_jump_list[i],
						  false, false);
		if (index == EOF)
			continue;
		tomoyo_dp.list[index].is_dit = true;
		tomoyo_dp.list[index].d_t = NULL;
		tomoyo_dp.list[index].is_du = false;
	}

	/* Create missing parent domains. */
	for (index = 0; index < max_index; index++) {
		char *line;
		tomoyo_get();
		line = tomoyo_shprintf("%s", tomoyo_domain_name(&tomoyo_dp, index));
		while (true) {
			char *cp = strrchr(line, ' ');
			if (!cp)
				break;
			*cp = '\0';
			if (tomoyo_find_domain(&tomoyo_dp, line, false, false)
			    != EOF)
				continue;
			tomoyo_assign_domain(&tomoyo_dp, line, false, true);
		}
		tomoyo_put();
	}

	/* Sort by domain name. */
	qsort(tomoyo_dp.list, tomoyo_dp.list_len, sizeof(struct tomoyo_domain_info),
	      tomoyo_domainname_attribute_compare);

	/* Assign domain numbers. */
	{
		int number = 0;
		int index;
		tomoyo_unnumbered_domain_count = 0;
		for (index = 0; index < tomoyo_dp.list_len; index++) {
			if (tomoyo_deleted_domain(index) ||
			    tomoyo_initializer_source(index)) {
				tomoyo_dp.list[index].number = -1;
				tomoyo_unnumbered_domain_count++;
			} else {
				tomoyo_dp.list[index].number = number++;
			}
		}
	}

	if (!tomoyo_dp.list_len)
		return;
	tomoyo_dp.list_selected = tomoyo_realloc2(tomoyo_dp.list_selected,
					    tomoyo_dp.list_len);
}

/**
 * tomoyo_show_process_line - Print a process line.
 *
 * @index: Index in the tomoyo_task_list array.
 *
 * Returns length of the printed line.
 */
static int tomoyo_show_process_line(const int index)
{
	char *line;
	int tmp_col = 0;
	int i;
	printw("%c%4d:%3u ", tomoyo_task_list[index].selected ? '&' : ' ', index,
	       tomoyo_task_list[index].profile);
	tmp_col += 10;
	for (i = 0; i < tomoyo_task_list[index].depth - 1; i++) {
		printw("%s", tomoyo_eat("    "));
		tmp_col += 4;
	}
	tomoyo_get();
	line = tomoyo_shprintf("%s%s (%u) %s", tomoyo_task_list[index].depth ?
			    " +- " : "", tomoyo_task_list[index].name,
			    tomoyo_task_list[index].pid,
			    tomoyo_task_list[index].domain);
	printw("%s", tomoyo_eat(line));
	tmp_col += strlen(line);
	tomoyo_put();
	return tmp_col;
}

/**
 * tomoyo_show_list - Print list on the screen.
 *
 * Returns nothing.
 */
static void tomoyo_show_list(void)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	int tomoyo_list_indent;
	const int offset = ptr->current;
	int i;
	int tmp_col;
	if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST)
		tomoyo_list_item_count = tomoyo_domain_sort_type ?
			tomoyo_task_list_len : tomoyo_dp.list_len;
	else
		tomoyo_list_item_count = tomoyo_gacl_list_count;
	clear();
	move(0, 0);
	if (tomoyo_window_height < TOMOYO_HEADER_LINES + 1) {
		printw("Please enlarge window.");
		clrtobot();
		refresh();
		return;
	}
	/* add color */
	tomoyo_editpolicy_color_change(tomoyo_editpolicy_color_head(), true);
	if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST) {
		if (tomoyo_domain_sort_type) {
			printw("<<< Process State Viewer >>>"
			       "      %d process%s    '?' for help",
			       tomoyo_task_list_len,
			       tomoyo_task_list_len > 1 ? "es" : "");
		} else {
			int i = tomoyo_list_item_count
				- tomoyo_unnumbered_domain_count;
			printw("<<< Domain Transition Editor >>>"
			       "      %d domain%c    '?' for help",
			       i, i > 1 ? 's' : ' ');
		}
	} else {
		int i = tomoyo_list_item_count;
		printw("<<< %s >>>"
		       "      %d entr%s    '?' for help", tomoyo_list_caption,
		       i, i > 1 ? "ies" : "y");
	}
	/* add color */
	tomoyo_editpolicy_color_change(tomoyo_editpolicy_color_head(), false);
	tomoyo_eat_col = ptr->x;
	tomoyo_max_col = 0;
	if (tomoyo_current_screen == TOMOYO_SCREEN_ACL_LIST) {
		char *line;
		tomoyo_get();
		line = tomoyo_shprintf("%s", tomoyo_eat(tomoyo_current_domain));
		tomoyo_editpolicy_attr_change(A_REVERSE, true);  /* add color */
		move(2, 0);
		printw("%s", line);
		tomoyo_editpolicy_attr_change(A_REVERSE, false); /* add color */
		tomoyo_put();
	}
	tomoyo_list_indent = 0;
	switch (tomoyo_current_screen) {
	case TOMOYO_SCREEN_EXCEPTION_LIST:
	case TOMOYO_SCREEN_ACL_LIST:
		for (i = 0; i < tomoyo_list_item_count; i++) {
			const enum tomoyo_editpolicy_directives directive =
				tomoyo_gacl_list[i].directive;
			const int len = tomoyo_directives[directive].alias_len;
			if (len > tomoyo_list_indent)
				tomoyo_list_indent = len;
		}
		break;
	default:
		break;
	}
	for (i = 0; i < tomoyo_body_lines; i++) {
		const int index = offset + i;
		tomoyo_eat_col = ptr->x;
		if (index >= tomoyo_list_item_count)
			break;
		move(TOMOYO_HEADER_LINES + i, 0);
		switch (tomoyo_current_screen) {
		case TOMOYO_SCREEN_DOMAIN_LIST:
			if (!tomoyo_domain_sort_type)
				tmp_col = tomoyo_show_domain_line(index);
			else
				tmp_col = tomoyo_show_process_line(index);
			break;
		case TOMOYO_SCREEN_EXCEPTION_LIST:
		case TOMOYO_SCREEN_ACL_LIST:
			tmp_col = tomoyo_show_acl_line(index, tomoyo_list_indent);
			break;
		case TOMOYO_SCREEN_PROFILE_LIST:
			tmp_col = tomoyo_show_profile_line(index);
			break;
		case TOMOYO_SCREEN_STAT_LIST:
			tmp_col = tomoyo_show_stat_line(index);
			break;
		default:
			tmp_col = tomoyo_show_literal_line(index);
			break;
		}
		clrtoeol();
		tmp_col -= tomoyo_window_width;
		if (tmp_col > tomoyo_max_col)
			tomoyo_max_col = tmp_col;
	}
	tomoyo_show_current();
}

/**
 * tomoyo_resize_window - Callback for resize event.
 *
 * Returns nothing.
 */
static void tomoyo_resize_window(void)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	getmaxyx(stdscr, tomoyo_window_height, tomoyo_window_width);
	tomoyo_body_lines = tomoyo_window_height - TOMOYO_HEADER_LINES;
	if (tomoyo_body_lines <= ptr->y)
		ptr->y = tomoyo_body_lines - 1;
	if (ptr->y < 0)
		ptr->y = 0;
}

/**
 * tomoyo_up_arrow_key - Callback event for pressing up-arrow key.
 *
 * Returns nothing.
 */
static void tomoyo_up_arrow_key(void)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	if (ptr->y > 0) {
		ptr->y--;
		tomoyo_show_current();
	} else if (ptr->current > 0) {
		ptr->current--;
		tomoyo_show_list();
	}
}

/**
 * tomoyo_down_arrow_key - Callback event for pressing down-arrow key.
 *
 * Returns nothing.
 */
static void tomoyo_down_arrow_key(void)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	if (ptr->y < tomoyo_body_lines - 1) {
		if (ptr->current + ptr->y < tomoyo_list_item_count - 1) {
			ptr->y++;
			tomoyo_show_current();
		}
	} else if (ptr->current + ptr->y < tomoyo_list_item_count - 1) {
		ptr->current++;
		tomoyo_show_list();
	}
}

/**
 * tomoyo_page_up_key - Callback event for pressing page-up key.
 *
 * Returns nothing.
 */
static void tomoyo_page_up_key(void)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	int p0 = ptr->current;
	int p1 = ptr->y;
	_Bool refresh;
	if (p0 + p1 > tomoyo_body_lines) {
		p0 -= tomoyo_body_lines;
		if (p0 < 0)
			p0 = 0;
	} else if (p0 + p1 > 0) {
		p0 = 0;
		p1 = 0;
	} else {
		return;
	}
	refresh = (ptr->current != p0);
	ptr->current = p0;
	ptr->y = p1;
	if (refresh)
		tomoyo_show_list();
	else
		tomoyo_show_current();
}

/**
 * tomoyo_page_down_key - Callback event for pressing page-down key.
 *
 * Returns nothing.
 */
static void tomoyo_page_down_key(void)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	int tomoyo_count = tomoyo_list_item_count - 1;
	int p0 = ptr->current;
	int p1 = ptr->y;
	_Bool refresh;
	if (p0 + p1 + tomoyo_body_lines < tomoyo_count) {
		p0 += tomoyo_body_lines;
	} else if (p0 + p1 < tomoyo_count) {
		while (p0 + p1 < tomoyo_count) {
			if (p1 + 1 < tomoyo_body_lines)
				p1++;
			else
				p0++;
		}
	} else {
		return;
	}
	refresh = (ptr->current != p0);
	ptr->current = p0;
	ptr->y = p1;
	if (refresh)
		tomoyo_show_list();
	else
		tomoyo_show_current();
}

/**
 * tomoyo_editpolicy_get_current - Get currently selected line's index.
 *
 * Returns index for currently selected line on success, EOF otherwise.
 *
 * If current screen has no entry, this function returns EOF.
 */
int tomoyo_editpolicy_get_current(void)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	int tomoyo_count = tomoyo_list_item_count;
	const int p0 = ptr->current;
	const int p1 = ptr->y;
	if (!tomoyo_count)
		return EOF;
	if (p0 + p1 < 0 || p0 + p1 >= tomoyo_count) {
		fprintf(stderr,
			"ERROR: tomoyo_current_item_index=%d tomoyo_current_y=%d\n",
			p0, p1);
		exit(127);
	}
	return p0 + p1;
}

/**
 * tomoyo_show_current - Show current cursor line.
 *
 * Returns nothing.
 */
static void tomoyo_show_current(void)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST &&
	    !tomoyo_domain_sort_type) {
		char *line;
		const int index = tomoyo_editpolicy_get_current();
		tomoyo_get();
		tomoyo_eat_col = ptr->x;
		if (index >= 0)
			line = tomoyo_shprintf("%s",
					    tomoyo_eat(tomoyo_domain_name(&tomoyo_dp,
								    index)));
		else
			line = tomoyo_shprintf("%s", tomoyo_current_ns);
		if (tomoyo_window_width < strlen(line))
			line[tomoyo_window_width] = '\0';
		move(2, 0);
		clrtoeol();
		tomoyo_editpolicy_attr_change(A_REVERSE, true);  /* add color */
		printw("%s", line);
		tomoyo_editpolicy_attr_change(A_REVERSE, false); /* add color */
		tomoyo_put();
	}
	if (tomoyo_current_screen == TOMOYO_SCREEN_EXCEPTION_LIST ||
	    tomoyo_current_screen == TOMOYO_SCREEN_PROFILE_LIST) {
		char *line;
		tomoyo_get();
		tomoyo_eat_col = ptr->x;
		line = tomoyo_shprintf("%s", tomoyo_current_ns);
		if (tomoyo_window_width < strlen(line))
			line[tomoyo_window_width] = '\0';
		move(2, 0);
		clrtoeol();
		tomoyo_editpolicy_attr_change(A_REVERSE, true);  /* add color */
		printw("%s", line);
		tomoyo_editpolicy_attr_change(A_REVERSE, false); /* add color */
		tomoyo_put();
	}
	move(TOMOYO_HEADER_LINES + ptr->y, 0);
	tomoyo_editpolicy_line_draw();     /* add color */
	refresh();
}

/**
 * tomoyo_adjust_cursor_pos - Adjust cursor position if needed.
 *
 * @item_count: Available item count in this screen.
 *
 * Returns nothing.
 */
static void tomoyo_adjust_cursor_pos(const int item_count)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	if (item_count == 0) {
		ptr->current = 0;
		ptr->y = 0;
	} else {
		while (ptr->current + ptr->y >= item_count) {
			if (ptr->y > 0)
				ptr->y--;
			else if (ptr->current > 0)
				ptr->current--;
		}
	}
}

/**
 * tomoyo_set_cursor_pos - Move cursor position if needed.
 *
 * @index: Index in the domain policy or currently selected line in the generic
 *         list.
 *
 * Returns nothing.
 */
static void tomoyo_set_cursor_pos(const int index)
{
	struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
	while (index < ptr->y + ptr->current) {
		if (ptr->y > 0)
			ptr->y--;
		else
			ptr->current--;
	}
	while (index > ptr->y + ptr->current) {
		if (ptr->y < tomoyo_body_lines - 1)
			ptr->y++;
		else
			ptr->current++;
	}
}

/**
 * tomoyo_select_item - Select an item.
 *
 * @index: Index in the domain policy or currently selected line in the generic
 *         list.
 *
 * Returns true if selected, false otherwise.
 *
 * Domain transition source and deleted domains are not selectable.
 */
static _Bool tomoyo_select_item(const int index)
{
	int x;
	int y;
	if (index < 0)
		return false;
	if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST) {
		if (!tomoyo_domain_sort_type) {
			if (tomoyo_deleted_domain(index) ||
			    tomoyo_initializer_source(index))
				return false;
			tomoyo_dp.list_selected[index] ^= 1;
		} else {
			tomoyo_task_list[index].selected ^= 1;
		}
	} else {
		tomoyo_gacl_list[index].selected ^= 1;
	}
	getyx(stdscr, y, x);
	tomoyo_editpolicy_sttr_save();    /* add color */
	tomoyo_show_list();
	tomoyo_editpolicy_sttr_restore(); /* add color */
	move(y, x);
	return true;
}

/**
 * tomoyo_gacl_compare - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int tomoyo_gacl_compare(const void *a, const void *b)
{
	const struct tomoyo_generic_acl *a0 = (struct tomoyo_generic_acl *) a;
	const struct tomoyo_generic_acl *b0 = (struct tomoyo_generic_acl *) b;
	const char *a1 = tomoyo_directives[a0->directive].alias;
	const char *b1 = tomoyo_directives[b0->directive].alias;
	const char *a2 = a0->operand;
	const char *b2 = b0->operand;
	if (!tomoyo_acl_sort_type) {
		const int ret = strcmp(a1, b1);
		if (ret)
			return ret;
		return strcmp(a2, b2);
	} else if (a0->directive == TOMOYO_DIRECTIVE_USE_GROUP) {
		return 1;
	} else if (b0->directive == TOMOYO_DIRECTIVE_USE_GROUP) {
		return -1;
	} else if (a0->directive == TOMOYO_DIRECTIVE_TRANSITION_FAILED) {
		return 2;
	} else if (b0->directive == TOMOYO_DIRECTIVE_TRANSITION_FAILED) {
		return -2;
	} else if (a0->directive == TOMOYO_DIRECTIVE_QUOTA_EXCEEDED) {
		return 3;
	} else if (b0->directive == TOMOYO_DIRECTIVE_QUOTA_EXCEEDED) {
		return -3;
	} else {
		const int ret = strcmp(a2, b2);
		if (ret)
			return ret;
		return strcmp(a1, b1);
	}
}

/**
 * tomoyo_delete_entry - Delete an entry.
 *
 * @index: Index in the domain policy.
 *
 * Returns nothing.
 */
static void tomoyo_delete_entry(const int index)
{
	int c;
	move(1, 0);
	tomoyo_editpolicy_color_change(TOMOYO_DISP_ERR, true);	/* add color */
	if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST) {
		c = tomoyo_count(tomoyo_dp.list_selected, tomoyo_dp.list_len);
		if (!c && index < tomoyo_dp.list_len)
			c = tomoyo_select_item(index);
		if (!c)
			printw("Select domain using Space key first.");
		else
			printw("Delete selected domain%s? ('Y'es/'N'o)",
			       c > 1 ? "s" : "");
	} else {
		c = tomoyo_count2(tomoyo_gacl_list,
			       tomoyo_gacl_list_count);
		if (!c)
			c = tomoyo_select_item(index);
		if (!c)
			printw("Select entry using Space key first.");
		else
			printw("Delete selected entr%s? ('Y'es/'N'o)",
			       c > 1 ? "ies" : "y");
	}
	tomoyo_editpolicy_color_change(TOMOYO_DISP_ERR, false);	/* add color */
	clrtoeol();
	refresh();
	if (!c)
		return;
	do {
		c = tomoyo_getch2();
	} while (!(c == 'Y' || c == 'y' || c == 'N' || c == 'n' || c == EOF));
	tomoyo_resize_window();
	if (c != 'Y' && c != 'y') {
		tomoyo_show_list();
		return;
	}
	if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST) {
		int i;
		FILE *fp = tomoyo_editpolicy_open_write
			(TOMOYO_PROC_POLICY_DOMAIN_POLICY);
		if (!fp)
			return;
		for (i = 0; i < tomoyo_dp.list_len; i++) {
			if (!tomoyo_dp.list_selected[i])
				continue;
			fprintf(fp, "delete %s\n",
				tomoyo_domain_name(&tomoyo_dp, i));
		}
		tomoyo_close_write(fp);
	} else {
		int i;
		const _Bool is_kernel_ns = !strcmp(tomoyo_current_ns, "<kernel>");
		FILE *fp = tomoyo_editpolicy_open_write(tomoyo_policy_file);
		if (!fp)
			return;
		if (tomoyo_current_screen == TOMOYO_SCREEN_ACL_LIST) {
			if (tomoyo_domain_sort_type)
				fprintf(fp, "select pid=%u\n",
					tomoyo_current_pid);
			else
				fprintf(fp, "select domain=%s\n",
					tomoyo_current_domain);
		}
		for (i = 0; i < tomoyo_gacl_list_count; i++) {
			enum tomoyo_editpolicy_directives directive;
			if (!tomoyo_gacl_list[i].selected)
				continue;
			directive = tomoyo_gacl_list[i].directive;
			fprintf(fp, "delete %s %s %s\n",
				tomoyo_current_screen == TOMOYO_SCREEN_EXCEPTION_LIST
				&& !is_kernel_ns ? tomoyo_current_ns : "",
				tomoyo_directives[directive].original,
				tomoyo_gacl_list[i].operand);
		}
		tomoyo_close_write(fp);
	}
}

/**
 * tomoyo_add_entry - Add an entry.
 *
 * Returns nothing.
 */
static void tomoyo_add_entry(void)
{
	FILE *fp;
	char *line;
	const _Bool is_kernel_ns = !strcmp(tomoyo_current_ns, "<kernel>");
	tomoyo_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = tomoyo_readline(tomoyo_window_height - 1, 0, "Enter new entry> ",
			    tomoyo_rl.history, tomoyo_rl.count, 128000, 8);
	tomoyo_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	tomoyo_rl.count = tomoyo_add_history(line, tomoyo_rl.history, tomoyo_rl.count,
				       tomoyo_rl.max);
	fp = tomoyo_editpolicy_open_write(tomoyo_policy_file);
	if (!fp)
		goto out;
	switch (tomoyo_current_screen) {
		enum tomoyo_editpolicy_directives directive;
	case TOMOYO_SCREEN_DOMAIN_LIST:
		if (!tomoyo_correct_domain(line)) {
			const int len = strlen(line) + 128;
			tomoyo_last_error = tomoyo_realloc2(tomoyo_last_error, len);
			snprintf(tomoyo_last_error, len - 1,
				 "%s is an invalid domainname.", line);
			line[0] = '\0';
		}
		break;
	case TOMOYO_SCREEN_ACL_LIST:
		if (tomoyo_domain_sort_type)
			fprintf(fp, "select pid=%u\n", tomoyo_current_pid);
		else
			fprintf(fp, "select domain=%s\n", tomoyo_current_domain);
		/* Fall through. */
	case TOMOYO_SCREEN_EXCEPTION_LIST:
		if (tomoyo_current_screen == TOMOYO_SCREEN_EXCEPTION_LIST &&
		    !is_kernel_ns)
			fprintf(fp, "%s ", tomoyo_current_ns);
		directive = tomoyo_find_directive(false, line);
		if (directive != TOMOYO_DIRECTIVE_NONE)
			fprintf(fp, "%s ", tomoyo_directives[directive].original);
		break;
	case TOMOYO_SCREEN_PROFILE_LIST:
		if (!strchr(line, '='))
			fprintf(fp, "%s %s-COMMENT=\n",
				!is_kernel_ns ? tomoyo_current_ns : "", line);
		if (!is_kernel_ns)
			fprintf(fp, "%s ", tomoyo_current_ns);
		break;
	case TOMOYO_SCREEN_NS_LIST:
		fprintf(fp, "%s PROFILE_VERSION=20100903\n", line);
		line[0] = '\0';
		break;
	default:
		break;
	}
	fprintf(fp, "%s\n", line);
	tomoyo_close_write(fp);
out:
	free(line);
}

/**
 * tomoyo_find_entry - Find an entry by user's key input.
 *
 * @input:   True if find next/previous, false if find first.
 * @forward: True if find next, false if find previous.
 * @current: Current position.
 *
 * Returns nothing.
 */
static void tomoyo_find_entry(const _Bool input, const _Bool forward,
			   const int current)
{
	int index = current;
	char *line = NULL;
	if (current == EOF)
		return;
	if (!input)
		goto start_search;
	tomoyo_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = tomoyo_readline(tomoyo_window_height - 1, 0, "Search> ",
			    tomoyo_rl.history, tomoyo_rl.count, 128000, 8);
	tomoyo_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	tomoyo_rl.count = tomoyo_add_history(line, tomoyo_rl.history, tomoyo_rl.count,
				       tomoyo_rl.max);
	free(tomoyo_rl.search_buffer[tomoyo_current_screen]);
	tomoyo_rl.search_buffer[tomoyo_current_screen] = line;
	line = NULL;
	index = -1;
start_search:
	tomoyo_get();
	while (true) {
		const char *cp;
		if (forward) {
			if (++index >= tomoyo_list_item_count)
				break;
		} else {
			if (--index < 0)
				break;
		}
		if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST) {
			if (tomoyo_domain_sort_type)
				cp = tomoyo_task_list[index].name;
			else
				cp = tomoyo_get_last_name(index);
		} else if (tomoyo_current_screen == TOMOYO_SCREEN_PROFILE_LIST) {
			cp = tomoyo_shprintf("%u-%s",
					  tomoyo_gacl_list[index].directive,
					  tomoyo_gacl_list[index].operand);
		} else {
			const enum tomoyo_editpolicy_directives directive =
				tomoyo_gacl_list[index].directive;
			cp = tomoyo_shprintf("%s %s",
					  tomoyo_directives[directive].alias,
					  tomoyo_gacl_list[index].operand);
		}
		if (!strstr(cp, tomoyo_rl.search_buffer[tomoyo_current_screen]))
			continue;
		tomoyo_set_cursor_pos(index);
		break;
	}
	tomoyo_put();
out:
	free(line);
	tomoyo_show_list();
}

/**
 * tomoyo_set_profile - Change profile number.
 *
 * @current: Currently selected line in the generic list.
 *
 * Returns nothing.
 */
static void tomoyo_set_profile(const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!tomoyo_domain_sort_type) {
		if (!tomoyo_count(tomoyo_dp.list_selected, tomoyo_dp.list_len) &&
		    !tomoyo_select_item(current)) {
			move(1, 0);
			printw("Select domain using Space key first.");
			clrtoeol();
			refresh();
			return;
		}
	} else {
		if (!tomoyo_count3(tomoyo_task_list, tomoyo_task_list_len) &&
		    !tomoyo_select_item(current)) {
			move(1, 0);
			printw("Select processes using Space key first.");
			clrtoeol();
			refresh();
			return;
		}
	}
	tomoyo_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = tomoyo_readline(tomoyo_window_height - 1, 0, "Enter profile number> ",
			    NULL, 0, 8, 1);
	tomoyo_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = tomoyo_editpolicy_open_write(TOMOYO_PROC_POLICY_DOMAIN_POLICY);
	if (!fp)
		goto out;
	if (!tomoyo_domain_sort_type) {
		for (index = 0; index < tomoyo_dp.list_len; index++) {
			if (!tomoyo_dp.list_selected[index])
				continue;
			fprintf(fp, "select domain=%s\n" "use_profile %s\n",
				tomoyo_domain_name(&tomoyo_dp, index), line);
		}
	} else {
		for (index = 0; index < tomoyo_task_list_len; index++) {
			if (!tomoyo_task_list[index].selected)
				continue;
			fprintf(fp, "select pid=%u\n" "use_profile %s\n",
				tomoyo_task_list[index].pid, line);
		}
	}
	tomoyo_close_write(fp);
out:
	free(line);
}

/**
 * tomoyo_set_level - Change profiles.
 *
 * @current: Currently selected line in the generic list.
 *
 * Returns nothing.
 */
static void tomoyo_set_level(const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!tomoyo_count2(tomoyo_gacl_list, tomoyo_gacl_list_count))
		tomoyo_select_item(current);
	tomoyo_editpolicy_attr_change(A_BOLD, true);  /* add color */
	tomoyo_initial_readline_data = NULL;
	for (index = 0; index < tomoyo_gacl_list_count; index++) {
		char *cp;
		if (!tomoyo_gacl_list[index].selected)
			continue;
		cp = strchr(tomoyo_gacl_list[index].operand, '=');
		if (!cp)
			continue;
		tomoyo_initial_readline_data = cp + 1;
		break;
	}
	line = tomoyo_readline(tomoyo_window_height - 1, 0, "Enter new value> ",
			    NULL, 0, 128000, 1);
	tomoyo_initial_readline_data = NULL;
	tomoyo_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = tomoyo_editpolicy_open_write(TOMOYO_PROC_POLICY_PROFILE);
	if (!fp)
		goto out;
	for (index = 0; index < tomoyo_gacl_list_count; index++) {
		char *buf;
		char *cp;
		enum tomoyo_editpolicy_directives directive;
		if (!tomoyo_gacl_list[index].selected)
			continue;
		tomoyo_get();
		buf = tomoyo_shprintf("%s", tomoyo_gacl_list[index].operand);
		cp = strchr(buf, '=');
		if (cp)
			*cp = '\0';
		directive = tomoyo_gacl_list[index].directive;
		fprintf(fp, "%s ", tomoyo_current_ns);
		if (directive < 256)
			fprintf(fp, "%u-", directive);
		fprintf(fp, "%s=%s\n", buf, line);
		tomoyo_put();
	}
	tomoyo_close_write(fp);
out:
	free(line);
}

/**
 * tomoyo_set_quota - Set memory quota.
 *
 * @current: Currently selected line in the generic list.
 *
 * Returns nothing.
 */
static void tomoyo_set_quota(const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!tomoyo_count2(tomoyo_gacl_list, tomoyo_gacl_list_count))
		tomoyo_select_item(current);
	tomoyo_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = tomoyo_readline(tomoyo_window_height - 1, 0, "Enter new value> ",
			    NULL, 0, 20, 1);
	tomoyo_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = tomoyo_editpolicy_open_write(TOMOYO_PROC_POLICY_STAT);
	if (!fp)
		goto out;
	for (index = 0; index < tomoyo_gacl_list_count; index++) {
		char *buf;
		char *cp;
		if (!tomoyo_gacl_list[index].selected)
			continue;
		tomoyo_get();
		buf = tomoyo_shprintf("%s", tomoyo_gacl_list[index].operand);
		cp = strchr(buf, ':');
		if (cp)
			*cp = '\0';
		fprintf(fp, "%s: %s\n", buf, line);
		tomoyo_put();
	}
	tomoyo_close_write(fp);
out:
	free(line);
}

/**
 * tomoyo_select_acl_window - Check whether to switch to ACL list or not.
 *
 * @current: Index in the domain policy.
 *
 * Returns true if next window is ACL list or namespace list, false otherwise.
 */
static _Bool tomoyo_select_acl_window(const int current)
{
	char *old_domain;
	if (current == EOF)
		return false;
	if (tomoyo_current_screen == TOMOYO_SCREEN_NS_LIST) {
		const char *namespace = tomoyo_gacl_list[current].operand;
		if (tomoyo_previous_screen == TOMOYO_SCREEN_ACL_LIST &&
		    strcmp(tomoyo_current_ns, namespace))
			tomoyo_previous_screen = TOMOYO_SCREEN_DOMAIN_LIST;
		free(tomoyo_current_ns);
		tomoyo_current_ns = tomoyo_strdup(namespace);
		tomoyo_current_ns_len = strlen(tomoyo_current_ns);
		tomoyo_current_screen = tomoyo_previous_screen;
		return true;
	}
	if (tomoyo_current_screen != TOMOYO_SCREEN_DOMAIN_LIST)
		return false;
	tomoyo_current_pid = 0;
	if (tomoyo_domain_sort_type) {
		tomoyo_current_pid = tomoyo_task_list[current].pid;
	} else if (tomoyo_initializer_source(current)) {
		struct tomoyo_screen *ptr = &tomoyo_screen[tomoyo_current_screen];
		const int redirect_index = tomoyo_find_target_domain(current);
		if (redirect_index >= 0) {
			ptr->current = redirect_index - ptr->y;
			while (ptr->current < 0) {
				ptr->current++;
				ptr->y--;
			}
			tomoyo_show_list();
		}
		if (redirect_index == -2) {
			char *cp;
			free(tomoyo_current_ns);
			tomoyo_current_ns = tomoyo_strdup(tomoyo_dp.list[current].
						    target_domainname);
			cp = strchr(tomoyo_current_ns, ' ');
			if (cp)
				*cp = '\0';
			tomoyo_current_ns_len = strlen(tomoyo_current_ns);
			tomoyo_current_screen = TOMOYO_SCREEN_DOMAIN_LIST;
			tomoyo_no_restore_cursor = true;
			return true;
		}
		return false;
	} else if (tomoyo_deleted_domain(current)) {
		return false;
	}
	old_domain = tomoyo_current_domain;
	if (tomoyo_domain_sort_type)
		tomoyo_current_domain = tomoyo_strdup(tomoyo_task_list[current].domain);
	else
		tomoyo_current_domain = tomoyo_strdup(tomoyo_domain_name(&tomoyo_dp,
								current));
	tomoyo_no_restore_cursor = old_domain &&
		strcmp(old_domain, tomoyo_current_domain);
	free(old_domain);
	tomoyo_current_screen = TOMOYO_SCREEN_ACL_LIST;
	return true;
}

/**
 * tomoyo_select_window - Switch window.
 *
 * @current: Index in the domain policy.
 *
 * Returns next window to display.
 */
static enum tomoyo_screen_type tomoyo_select_window(const int current)
{
	move(0, 0);
	printw("Press one of below keys to switch window.\n\n");
	printw("e     <<< Exception Policy Editor >>>\n");
	printw("d     <<< Domain Transition Editor >>>\n");
	if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST && current != EOF &&
	    !tomoyo_initializer_source(current) && !tomoyo_deleted_domain(current))
		printw("a     <<< Domain Policy Editor >>>\n");
	printw("p     <<< Profile Editor >>>\n");
	printw("m     <<< Manager Policy Editor >>>\n");
	printw("n     <<< Namespace Selector >>>\n");
	if (!tomoyo_offline_mode) {
		/* printw("i     <<< Interactive Enforcing Mode >>>\n"); */
		printw("s     <<< Statistics >>>\n");
	}
	printw("q     Quit this editor.\n");
	clrtobot();
	refresh();
	while (true) {
		int c = tomoyo_getch2();
		if (c == 'E' || c == 'e')
			return TOMOYO_SCREEN_EXCEPTION_LIST;
		if (c == 'D' || c == 'd')
			return TOMOYO_SCREEN_DOMAIN_LIST;
		if (c == 'A' || c == 'a')
			if (tomoyo_select_acl_window(current))
				return tomoyo_current_screen;
		if (c == 'P' || c == 'p')
			return TOMOYO_SCREEN_PROFILE_LIST;
		if (c == 'M' || c == 'm')
			return TOMOYO_SCREEN_MANAGER_LIST;
		if (c == 'N' || c == 'n') {
			tomoyo_previous_screen = tomoyo_current_screen;
			return TOMOYO_SCREEN_NS_LIST;
		}
		if (!tomoyo_offline_mode) {
			/*
			if (c == 'I' || c == 'i')
				return TOMOYO_SCREEN_QUERY_LIST;
			*/
			if (c == 'S' || c == 's')
				return TOMOYO_SCREEN_STAT_LIST;
		}
		if (c == 'Q' || c == 'q')
			return TOMOYO_MAXSCREEN;
		if (c == EOF)
			return TOMOYO_MAXSCREEN;
	}
}

/**
 * tomoyo_copy_mark_state - Copy selected state to lines under the current line.
 *
 * @current: Index in the domain policy.
 *
 * Returns nothing.
 */
static void tomoyo_copy_mark_state(const int current)
{
	int index;
	if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST) {
		if (tomoyo_domain_sort_type) {
			const u8 selected = tomoyo_task_list[current].selected;
			for (index = current; index < tomoyo_task_list_len;
			     index++)
				tomoyo_task_list[index].selected = selected;
		} else {
			const u8 selected = tomoyo_dp.list_selected[current];
			if (tomoyo_deleted_domain(current) ||
			    tomoyo_initializer_source(current))
				return;
			for (index = current; index < tomoyo_dp.list_len;
			     index++) {
				if (tomoyo_deleted_domain(index) ||
				    tomoyo_initializer_source(index))
					continue;
				tomoyo_dp.list_selected[index] = selected;
			}
		}
	} else {
		const u8 selected = tomoyo_gacl_list[current].selected;
		for (index = current; index < tomoyo_gacl_list_count;
		     index++)
			tomoyo_gacl_list[index].selected = selected;
	}
	tomoyo_show_list();
}

/**
 * tomoyo_copy_to_history - Copy line to histoy buffer.
 *
 * @current: Index in the domain policy.
 *
 * Returns nothing.
 */
static void tomoyo_copy_to_history(const int current)
{
	const char *line;
	if (current == EOF)
		return;
	tomoyo_get();
	switch (tomoyo_current_screen) {
		enum tomoyo_editpolicy_directives directive;
	case TOMOYO_SCREEN_DOMAIN_LIST:
		line = tomoyo_domain_name(&tomoyo_dp, current);
		break;
	case TOMOYO_SCREEN_EXCEPTION_LIST:
	case TOMOYO_SCREEN_ACL_LIST:
		directive = tomoyo_gacl_list[current].directive;
		line = tomoyo_shprintf("%s %s", tomoyo_directives[directive].alias,
				tomoyo_gacl_list[current].operand);
		break;
	case TOMOYO_SCREEN_STAT_LIST:
		line = NULL;
		break;
	default:
		line = tomoyo_shprintf("%s",
				    tomoyo_gacl_list[current].operand);
	}
	tomoyo_rl.count = tomoyo_add_history(line, tomoyo_rl.history, tomoyo_rl.count,
				       tomoyo_rl.max);
	tomoyo_put();
}

/**
 * tomoyo_generic_list_loop - Main loop.
 *
 * Returns next screen to display.
 */
static enum tomoyo_screen_type tomoyo_generic_list_loop(void)
{
	struct tomoyo_screen *ptr;
	static struct {
		int y;
		int current;
	} saved_cursor[TOMOYO_MAXSCREEN] = { };
	if (tomoyo_current_screen == TOMOYO_SCREEN_EXCEPTION_LIST) {
		tomoyo_policy_file = TOMOYO_PROC_POLICY_EXCEPTION_POLICY;
		tomoyo_list_caption = "Exception Policy Editor";
	} else if (tomoyo_current_screen == TOMOYO_SCREEN_ACL_LIST) {
		tomoyo_policy_file = TOMOYO_PROC_POLICY_DOMAIN_POLICY;
		tomoyo_list_caption = "Domain Policy Editor";
		/*
	} else if (tomoyo_current_screen == TOMOYO_SCREEN_QUERY_LIST) {
		tomoyo_policy_file = TOMOYO_PROC_POLICY_QUERY;
		tomoyo_list_caption = "Interactive Enforcing Mode";
		*/
	} else if (tomoyo_current_screen == TOMOYO_SCREEN_NS_LIST) {
		tomoyo_policy_file = TOMOYO_PROC_POLICY_PROFILE;
		tomoyo_list_caption = "Namespace Selector";
	} else if (tomoyo_current_screen == TOMOYO_SCREEN_PROFILE_LIST) {
		tomoyo_policy_file = TOMOYO_PROC_POLICY_PROFILE;
		tomoyo_list_caption = "Profile Editor";
	} else if (tomoyo_current_screen == TOMOYO_SCREEN_MANAGER_LIST) {
		tomoyo_policy_file = TOMOYO_PROC_POLICY_MANAGER;
		tomoyo_list_caption = "Manager Policy Editor";
	} else if (tomoyo_current_screen == TOMOYO_SCREEN_STAT_LIST) {
		tomoyo_policy_file = TOMOYO_PROC_POLICY_STAT;
		tomoyo_list_caption = "Statistics";
	} else {
		tomoyo_policy_file = TOMOYO_PROC_POLICY_DOMAIN_POLICY;
		/* tomoyo_list_caption = "Domain Transition Editor"; */
	}
	ptr = &tomoyo_screen[tomoyo_current_screen];
	if (tomoyo_no_restore_cursor) {
		ptr->current = 0;
		ptr->y = 0;
		tomoyo_no_restore_cursor = false;
	} else {
		ptr->current = saved_cursor[tomoyo_current_screen].current;
		ptr->y = saved_cursor[tomoyo_current_screen].y;
	}
start:
	if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST) {
		if (!tomoyo_domain_sort_type) {
			tomoyo_read_domain_and_exception_policy();
			tomoyo_adjust_cursor_pos(tomoyo_dp.list_len);
		} else {
			tomoyo_read_process_list(true);
			tomoyo_adjust_cursor_pos(tomoyo_task_list_len);
		}
	} else {
		tomoyo_read_generic_policy();
		tomoyo_adjust_cursor_pos(tomoyo_gacl_list_count);
	}
start2:
	tomoyo_show_list();
	if (tomoyo_last_error) {
		move(1, 0);
		printw("ERROR: %s", tomoyo_last_error);
		clrtoeol();
		refresh();
		free(tomoyo_last_error);
		tomoyo_last_error = NULL;
	}
	while (true) {
		const int current = tomoyo_editpolicy_get_current();
		const int c = tomoyo_getch2();
		saved_cursor[tomoyo_current_screen].current = ptr->current;
		saved_cursor[tomoyo_current_screen].y = ptr->y;
		if (c == 'q' || c == 'Q')
			return TOMOYO_MAXSCREEN;
		if ((c == '\r' || c == '\n') &&
		    tomoyo_current_screen == TOMOYO_SCREEN_ACL_LIST)
			return TOMOYO_SCREEN_DOMAIN_LIST;
		if (c == '\t') {
			if (tomoyo_current_screen == TOMOYO_SCREEN_DOMAIN_LIST)
				return TOMOYO_SCREEN_EXCEPTION_LIST;
			else
				return TOMOYO_SCREEN_DOMAIN_LIST;
		}
		if (tomoyo_need_reload) {
			tomoyo_need_reload = false;
			goto start;
		}
		if (c == ERR)
			continue; /* Ignore invalid key. */
		switch (c) {
		case KEY_RESIZE:
			tomoyo_resize_window();
			tomoyo_show_list();
			break;
		case KEY_UP:
			tomoyo_up_arrow_key();
			break;
		case KEY_DOWN:
			tomoyo_down_arrow_key();
			break;
		case KEY_PPAGE:
			tomoyo_page_up_key();
			break;
		case KEY_NPAGE:
			tomoyo_page_down_key();
			break;
		case ' ':
			tomoyo_select_item(current);
			break;
		case 'c':
		case 'C':
			if (current == EOF)
				break;
			tomoyo_copy_mark_state(current);
			tomoyo_show_list();
			break;
		case 'f':
		case 'F':
			if (tomoyo_current_screen != TOMOYO_SCREEN_STAT_LIST)
				tomoyo_find_entry(true, true, current);
			break;
		case 'p':
		case 'P':
			if (tomoyo_current_screen == TOMOYO_SCREEN_STAT_LIST)
				break;
			if (!tomoyo_rl.search_buffer[tomoyo_current_screen])
				tomoyo_find_entry(true, false, current);
			else
				tomoyo_find_entry(false, false, current);
			break;
		case 'n':
		case 'N':
			if (tomoyo_current_screen == TOMOYO_SCREEN_STAT_LIST)
				break;
			if (!tomoyo_rl.search_buffer[tomoyo_current_screen])
				tomoyo_find_entry(true, true, current);
			else
				tomoyo_find_entry(false, true, current);
			break;
		case 'd':
		case 'D':
			if (tomoyo_readonly_mode)
				break;
			switch (tomoyo_current_screen) {
			case TOMOYO_SCREEN_DOMAIN_LIST:
				if (tomoyo_domain_sort_type)
					break;
			case TOMOYO_SCREEN_EXCEPTION_LIST:
			case TOMOYO_SCREEN_ACL_LIST:
			case TOMOYO_SCREEN_MANAGER_LIST:
				tomoyo_delete_entry(current);
				goto start;
			default:
				break;
			}
			break;
		case 'a':
		case 'A':
			if (tomoyo_readonly_mode)
				break;
			switch (tomoyo_current_screen) {
			case TOMOYO_SCREEN_DOMAIN_LIST:
				if (tomoyo_domain_sort_type)
					break;
			case TOMOYO_SCREEN_EXCEPTION_LIST:
			case TOMOYO_SCREEN_ACL_LIST:
			case TOMOYO_SCREEN_PROFILE_LIST:
			case TOMOYO_SCREEN_MANAGER_LIST:
			case TOMOYO_SCREEN_NS_LIST:
				tomoyo_add_entry();
				goto start;
			default:
				break;
			}
			break;
		case '\r':
		case '\n':
			if (tomoyo_select_acl_window(current))
				return tomoyo_current_screen;
			break;
		case 's':
		case 'S':
			if (tomoyo_readonly_mode)
				break;
			switch (tomoyo_current_screen) {
			case TOMOYO_SCREEN_DOMAIN_LIST:
				tomoyo_set_profile(current);
				goto start;
			case TOMOYO_SCREEN_PROFILE_LIST:
				tomoyo_set_level(current);
				goto start;
			case TOMOYO_SCREEN_STAT_LIST:
				tomoyo_set_quota(current);
				goto start;
			default:
				break;
			}
			break;
		case 'r':
		case 'R':
			goto start;
		case KEY_LEFT:
			if (!ptr->x)
				break;
			ptr->x--;
			goto start2;
		case KEY_RIGHT:
			ptr->x++;
			goto start2;
		case KEY_HOME:
			ptr->x = 0;
			goto start2;
		case KEY_END:
			ptr->x = tomoyo_max_col;
			goto start2;
		case KEY_IC:
			tomoyo_copy_to_history(current);
			break;
		case 'o':
		case 'O':
			if (tomoyo_current_screen == TOMOYO_SCREEN_ACL_LIST ||
			    tomoyo_current_screen == TOMOYO_SCREEN_EXCEPTION_LIST) {
				tomoyo_editpolicy_optimize(current);
				tomoyo_show_list();
			}
			break;
		case '@':
			switch (tomoyo_current_screen) {
			case TOMOYO_SCREEN_ACL_LIST:
				tomoyo_acl_sort_type = !tomoyo_acl_sort_type;
				goto start;
			case TOMOYO_SCREEN_PROFILE_LIST:
				tomoyo_profile_sort_type = !tomoyo_profile_sort_type;
				goto start;
			case TOMOYO_SCREEN_DOMAIN_LIST:
				if (tomoyo_offline_mode)
					break;
				tomoyo_domain_sort_type = !tomoyo_domain_sort_type;
				goto start;
			default:
				break;
			}
			break;
		case 'w':
		case 'W':
			return tomoyo_select_window(current);
		case '?':
			if (tomoyo_show_command_key(tomoyo_current_screen,
						 tomoyo_readonly_mode))
				goto start;
			return TOMOYO_MAXSCREEN;
		}
	}
}

/**
 * tomoyo_save_to_file - Save policy to file.
 *
 * @src: Filename to read from.
 * @dest: Filename to write to.
 *
 * Returns true on success, false otherwise.
 */
static _Bool tomoyo_save_to_file(const char *src, const char *dest)
{
	FILE *proc_fp = tomoyo_editpolicy_open_read(src);
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

/**
 * tomoyo_parse_args - Parse command line arguments.
 *
 * @argc: argc passed to main().
 * @argv: argv passed to main().
 *
 * Returns nothing.
 */
static void tomoyo_parse_args(int argc, char *argv[])
{
	int i;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (tomoyo_network_mode || tomoyo_offline_mode)
				goto usage;
			tomoyo_policy_dir = ptr;
			tomoyo_offline_mode = true;
		} else if (*ptr == '<') {
			if (tomoyo_current_ns || strchr(ptr, ' ') ||
			    !tomoyo_domain_def(ptr))
				goto usage;
			tomoyo_current_ns = tomoyo_strdup(ptr);
		} else if (cp) {
			*cp++ = '\0';
			if (tomoyo_network_mode || tomoyo_offline_mode)
				goto usage;
			tomoyo_network_ip = inet_addr(ptr);
			tomoyo_network_port = htons(atoi(cp));
			tomoyo_network_mode = true;
			if (!tomoyo_check_remote_host())
				exit(1);
		} else if (!strcmp(ptr, "e"))
			tomoyo_current_screen = TOMOYO_SCREEN_EXCEPTION_LIST;
		else if (!strcmp(ptr, "d"))
			tomoyo_current_screen = TOMOYO_SCREEN_DOMAIN_LIST;
		else if (!strcmp(ptr, "p"))
			tomoyo_current_screen = TOMOYO_SCREEN_PROFILE_LIST;
		else if (!strcmp(ptr, "m"))
			tomoyo_current_screen = TOMOYO_SCREEN_MANAGER_LIST;
		else if (!strcmp(ptr, "s"))
			tomoyo_current_screen = TOMOYO_SCREEN_STAT_LIST;
		else if (!strcmp(ptr, "readonly"))
			tomoyo_readonly_mode = true;
		else if (sscanf(ptr, "refresh=%u", &tomoyo_refresh_interval)
			 != 1) {
usage:
			printf("Usage: %s [e|d|p|m|s] [readonly] "
			       "[refresh=interval] [<namespace>]"
			       "[{policy_dir|remote_ip:remote_port}]\n",
			       argv[0]);
			exit(1);
		}
	}
	if (!tomoyo_current_ns)
		tomoyo_current_ns = tomoyo_strdup("<kernel>");
	tomoyo_current_ns_len = strlen(tomoyo_current_ns);
}

/**
 * tomoyo_load_offline - Load policy for offline mode.
 *
 * Returns nothing.
 */
static void tomoyo_load_offline(void)
{
	int fd[2] = { EOF, EOF };
	if (chdir(tomoyo_policy_dir) || chdir("policy/current/")) {
		fprintf(stderr, "Directory %s/policy/current/ doesn't "
			"exist.\n", tomoyo_policy_dir);
		exit(1);
	}
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd)) {
		fprintf(stderr, "socketpair()\n");
		exit(1);
	}
	switch (fork()) {
	case 0:
		close(fd[0]);
		tomoyo_persistent_fd = fd[1];
		tomoyo_editpolicy_offline_daemon();
		_exit(0);
	case -1:
		fprintf(stderr, "fork()\n");
		exit(1);
	}
	close(fd[1]);
	tomoyo_persistent_fd = fd[0];
	tomoyo_copy_file("exception_policy.conf",
		      TOMOYO_PROC_POLICY_EXCEPTION_POLICY);
	tomoyo_copy_file("domain_policy.conf", TOMOYO_PROC_POLICY_DOMAIN_POLICY);
	tomoyo_copy_file("profile.conf", TOMOYO_PROC_POLICY_PROFILE);
	tomoyo_copy_file("manager.conf", TOMOYO_PROC_POLICY_MANAGER);
	if (chdir("..")) {
		fprintf(stderr, "Directory %s/policy/ doesn't exist.\n",
			tomoyo_policy_dir);
		exit(1);
	}
}

/**
 * tomoyo_load_readwrite - Check that this program can write to /sys/kernel/security/tomoyo/ interface.
 *
 * Returns nothing.
 */
static void tomoyo_load_readwrite(void)
{
	const int fd1 = tomoyo_open2(TOMOYO_PROC_POLICY_EXCEPTION_POLICY, O_RDWR);
	const int fd2 = tomoyo_open2(TOMOYO_PROC_POLICY_DOMAIN_POLICY, O_RDWR);
	if ((fd1 != EOF && write(fd1, "", 0) != 0) ||
	    (fd2 != EOF && write(fd2, "", 0) != 0)) {
		fprintf(stderr, "In order to run this program, it must be "
			"registered to %s . "
			"Please reboot.\n", TOMOYO_PROC_POLICY_MANAGER);
		exit(1);
	}
	close(fd1);
	close(fd2);
}

/**
 * tomoyo_save_offline - Save policy for offline mode.
 *
 * Returns nothing.
 */
static void tomoyo_save_offline(void)
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
				tomoyo_policy_dir, stamp);
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
	    !tomoyo_save_to_file(TOMOYO_PROC_POLICY_PROFILE, "profile.conf") ||
	    !tomoyo_save_to_file(TOMOYO_PROC_POLICY_MANAGER, "manager.conf") ||
	    !tomoyo_save_to_file(TOMOYO_PROC_POLICY_EXCEPTION_POLICY,
			      "exception_policy.conf") ||
	    !tomoyo_save_to_file(TOMOYO_PROC_POLICY_DOMAIN_POLICY,
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
	tomoyo_parse_args(argc, argv);
	tomoyo_editpolicy_init_keyword_map();
	if (tomoyo_offline_mode) {
		tomoyo_load_offline();
		goto start;
	}
	if (tomoyo_network_mode)
		goto start;
	if (chdir(TOMOYO_PROC_POLICY_DIR)) {
		fprintf(stderr,
			"You can't use this editor for this kernel.\n");
		return 1;
	}
	if (!tomoyo_readonly_mode)
		tomoyo_load_readwrite();
start:
	initscr();
	tomoyo_editpolicy_color_init();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	getmaxyx(stdscr, tomoyo_window_height, tomoyo_window_width);
	if (tomoyo_refresh_interval) {
		signal(SIGALRM, tomoyo_sigalrm_handler);
		alarm(tomoyo_refresh_interval);
		timeout(1000);
	}
	tomoyo_rl.max = 20;
	tomoyo_rl.history = tomoyo_malloc(tomoyo_rl.max * sizeof(const char *));
	while (tomoyo_current_screen < TOMOYO_MAXSCREEN) {
		tomoyo_resize_window();
		tomoyo_current_screen = tomoyo_generic_list_loop();
	}
	alarm(0);
	clear();
	move(0, 0);
	refresh();
	endwin();
	if (tomoyo_offline_mode && !tomoyo_readonly_mode)
		tomoyo_save_offline();
	tomoyo_clear_domain_policy(&tomoyo_dp);
	return 0;
}
