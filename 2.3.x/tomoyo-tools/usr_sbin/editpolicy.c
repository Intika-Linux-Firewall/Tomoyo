/*
 * editpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 2.3.0   2010/08/20
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

/* Variables */

extern int tomoyo_persistent_fd;

struct tomoyo_path_group_entry *tomoyo_path_group_list = NULL;
int tomoyo_path_group_list_len = 0;
struct tomoyo_generic_acl *tomoyo_generic_acl_list = NULL;
int tomoyo_generic_acl_list_count = 0;

static const char *tomoyo_policy_dir = NULL;
static _Bool tomoyo_offline_mode = false;
static _Bool tomoyo_readonly_mode = false;
static unsigned int tomoyo_refresh_interval = 0;
static _Bool tomoyo_need_reload = false;
static const char *tomoyo_policy_file = NULL;
static const char *tomoyo_list_caption = NULL;
static char *tomoyo_current_domain = NULL;
static unsigned int tomoyo_current_pid = 0;
static int tomoyo_current_screen = CCS_SCREEN_DOMAIN_LIST;
static struct tomoyo_domain_keeper_entry *tomoyo_domain_keeper_list = NULL;
static int tomoyo_domain_keeper_list_len = 0;
static struct tomoyo_domain_initializer_entry *tomoyo_domain_initializer_list = NULL;
static int tomoyo_domain_initializer_list_len = 0;
static int tomoyo_profile_sort_type = 0;
static int tomoyo_unnumbered_domain_count = 0;
static int tomoyo_window_width = 0;
static int tomoyo_window_height = 0;
static int tomoyo_current_item_index[CCS_MAXSCREEN];
int tomoyo_current_y[CCS_MAXSCREEN];
int tomoyo_list_item_count[CCS_MAXSCREEN];
static int tomoyo_body_lines = 0;
static int tomoyo_max_eat_col[CCS_MAXSCREEN];
static int tomoyo_eat_col = 0;
static int tomoyo_max_col = 0;
static int tomoyo_list_indent = 0;
static int tomoyo_acl_sort_type = 1;
static char *tomoyo_last_error = NULL;

/* Prototypes */

static void tomoyo_sigalrm_handler(int sig);
static const char *tomoyo_get_last_name(const struct tomoyo_domain_policy *dp, const int index);
static _Bool tomoyo_keeper_domain(struct tomoyo_domain_policy *dp, const int index);
static _Bool tomoyo_initializer_source(struct tomoyo_domain_policy *dp, const int index);
static _Bool tomoyo_initializer_target(struct tomoyo_domain_policy *dp, const int index);
static _Bool tomoyo_domain_unreachable(struct tomoyo_domain_policy *dp, const int index);
static _Bool tomoyo_deleted_domain(struct tomoyo_domain_policy *dp, const int index);
static const struct tomoyo_domain_keeper_entry *tomoyo_domain_keeper(const struct tomoyo_path_info *domainname, const char *program);
static const struct tomoyo_domain_initializer_entry *tomoyo_domain_initializer(const struct tomoyo_path_info *domainname, const char *program);
static int tomoyo_generic_acl_compare(const void *a, const void *b);
static int tomoyo_generic_acl_compare0(const void *a, const void *b);
static int tomoyo_string_acl_compare(const void *a, const void *b);
static int tomoyo_profile_entry_compare(const void *a, const void *b);
static void tomoyo_read_generic_policy(void);
static int tomoyo_add_domain_initializer_entry(const char *domainname, const char *program, const _Bool is_not);
static int tomoyo_add_domain_initializer_policy(char *data, const _Bool is_not);
static int tomoyo_add_domain_keeper_entry(const char *domainname, const char *program, const _Bool is_not);
static int tomoyo_add_domain_keeper_policy(char *data, const _Bool is_not);
static int tomoyo_add_path_group_entry(const char *group_name, const char *member_name, const _Bool is_delete);
static int tomoyo_add_path_group_policy(char *data, const _Bool is_delete);
static void tomoyo_assign_domain_initializer_source(struct tomoyo_domain_policy *dp, const struct tomoyo_path_info *domainname, const char *program);
static int tomoyo_domainname_attribute_compare(const void *a, const void *b);
static void tomoyo_read_domain_and_exception_policy(struct tomoyo_domain_policy *dp);
static void tomoyo_show_current(struct tomoyo_domain_policy *dp);
static const char *tomoyo_eat(const char *str);
static int tomoyo_show_domain_line(struct tomoyo_domain_policy *dp, const int index);
static int tomoyo_show_acl_line(const int index, const int list_indent);
static int tomoyo_show_profile_line(const int index);
static int tomoyo_show_literal_line(const int index);
static int tomoyo_show_meminfo_line(const int index);
static void tomoyo_show_list(struct tomoyo_domain_policy *dp);
static void tomoyo_resize_window(void);
static void tomoyo_up_arrow_key(struct tomoyo_domain_policy *dp);
static void tomoyo_down_arrow_key(struct tomoyo_domain_policy *dp);
static void tomoyo_page_up_key(struct tomoyo_domain_policy *dp);
static void tomoyo_page_down_key(struct tomoyo_domain_policy *dp);
static void tomoyo_adjust_cursor_pos(const int item_count);
static void tomoyo_set_cursor_pos(const int index);
static int tomoyo_count(const unsigned char *array, const int len);
static int tomoyo_count2(const struct tomoyo_generic_acl *array, int len);
static _Bool tomoyo_select_item(struct tomoyo_domain_policy *dp, const int index);
static int tomoyo_generic_acl_compare(const void *a, const void *b);
static void tomoyo_delete_entry(struct tomoyo_domain_policy *dp, const int index);
static void tomoyo_add_entry(struct tomoyo_readline_data *rl);
static void tomoyo_find_entry(struct tomoyo_domain_policy *dp, _Bool input, _Bool forward, const int current, struct tomoyo_readline_data *rl);
static void tomoyo_set_profile(struct tomoyo_domain_policy *dp, const int current);
static void tomoyo_set_level(struct tomoyo_domain_policy *dp, const int current);
static void tomoyo_set_quota(struct tomoyo_domain_policy *dp, const int current);
static int tomoyo_select_window(struct tomoyo_domain_policy *dp, const int current);
static _Bool tomoyo_show_command_key(const int screen, const _Bool readonly);
static int tomoyo_generic_list_loop(struct tomoyo_domain_policy *dp);
static void tomoyo_copy_file(const char *source, const char *dest);
static FILE *tomoyo_editpolicy_open_write(const char *filename);

/* Utility Functions */

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

static const char *tomoyo_get_last_name(const struct tomoyo_domain_policy *dp,
				     const int index)
{
	const char *cp0 = tomoyo_domain_name(dp, index);
	const char *cp1 = strrchr(cp0, ' ');
	if (cp1)
		return cp1 + 1;
	return cp0;
}

static int tomoyo_count(const unsigned char *array, const int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i])
			c++;
	return c;
}

static int tomoyo_count2(const struct tomoyo_generic_acl *array, int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i].selected)
			c++;
	return c;
}

static int tomoyo_count3(const struct tomoyo_task_entry *array, int len)
{
	int i;
	int c = 0;
	for (i = 0; i < len; i++)
		if (array[i].selected)
			c++;
	return c;
}

static _Bool tomoyo_keeper_domain(struct tomoyo_domain_policy *dp, const int index)
{
	return dp->list[index].is_dk;
}

static _Bool tomoyo_initializer_source(struct tomoyo_domain_policy *dp, const int index)
{
	return dp->list[index].is_dis;
}

static _Bool tomoyo_initializer_target(struct tomoyo_domain_policy *dp, const int index)
{
	return dp->list[index].is_dit;
}

static _Bool tomoyo_domain_unreachable(struct tomoyo_domain_policy *dp, const int index)
{
	return dp->list[index].is_du;
}

static _Bool tomoyo_deleted_domain(struct tomoyo_domain_policy *dp, const int index)
{
	return dp->list[index].is_dd;
}

static int tomoyo_generic_acl_compare0(const void *a, const void *b)
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

static int tomoyo_string_acl_compare(const void *a, const void *b)
{
	const struct tomoyo_generic_acl *a0 = (struct tomoyo_generic_acl *) a;
	const struct tomoyo_generic_acl *b0 = (struct tomoyo_generic_acl *) b;
	const char *a1 = a0->operand;
	const char *b1 = b0->operand;
	return strcmp(a1, b1);
}

static int tomoyo_add_domain_initializer_policy(char *data, const _Bool is_not)
{
	char *cp = strstr(data, " from ");
	if (cp) {
		*cp = '\0';
		return tomoyo_add_domain_initializer_entry(cp + 6, data, is_not);
	} else {
		return tomoyo_add_domain_initializer_entry(NULL, data, is_not);
	}
}

static int tomoyo_add_domain_keeper_policy(char *data, const _Bool is_not)
{
	char *cp = strstr(data, " from ");
	if (cp) {
		*cp = '\0';
		return tomoyo_add_domain_keeper_entry(cp + 6, data, is_not);
	} else {
		return tomoyo_add_domain_keeper_entry(data, NULL, is_not);
	}
}

static int tomoyo_add_path_group_policy(char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return tomoyo_add_path_group_entry(data, cp, is_delete);
}

static void tomoyo_assign_domain_initializer_source(struct tomoyo_domain_policy *dp,
						 const struct tomoyo_path_info *domainname,
						 const char *program)
{
	if (tomoyo_domain_initializer(domainname, program)) {
		char *line;
		tomoyo_get();
		line = tomoyo_shprintf("%s %s", domainname->name, program);
		tomoyo_normalize_line(line);
		if (tomoyo_find_or_assign_new_domain(dp, line, true, false) == EOF)
			tomoyo_out_of_memory();
		tomoyo_put();
	}
}

static int tomoyo_domainname_attribute_compare(const void *a, const void *b)
{
	const struct tomoyo_domain_info *a0 = a;
	const struct tomoyo_domain_info *b0 = b;
	const int k = strcmp(a0->domainname->name, b0->domainname->name);
	if ((k > 0) || (!k && !a0->is_dis && b0->is_dis))
		return 1;
	return k;
}


static int tomoyo_show_domain_line(struct tomoyo_domain_policy *dp, const int index)
{
	int tmp_col = 0;
	const struct tomoyo_domain_initializer_entry *domain_initializer;
	const struct tomoyo_domain_keeper_entry *domain_keeper;
	char *line;
	const char *sp;
	const int number = dp->list[index].number;
	int redirect_index;
	if (number >= 0) {
		printw("%c%4d:", dp->list_selected[index] ? '&' : ' ', number);
		if (dp->list[index].profile_assigned)
			printw("%3u", dp->list[index].profile);
		else
			printw("???");
		printw(" %c%c%c ", tomoyo_keeper_domain(dp, index) ? '#' : ' ',
		       tomoyo_initializer_target(dp, index) ? '*' : ' ',
		       tomoyo_domain_unreachable(dp, index) ? '!' : ' ');
	} else
		printw("              ");
	tmp_col += 14;
	sp = tomoyo_domain_name(dp, index);
	while (true) {
		const char *cp = strchr(sp, ' ');
		if (!cp)
			break;
		printw("%s", tomoyo_eat("    "));
		tmp_col += 4;
		sp = cp + 1;
	}
	if (tomoyo_deleted_domain(dp, index)) {
		printw("%s", tomoyo_eat("( "));
		tmp_col += 2;
	}
	printw("%s", tomoyo_eat(sp));
	tmp_col += strlen(sp);
	if (tomoyo_deleted_domain(dp, index)) {
		printw("%s", tomoyo_eat(" )"));
		tmp_col += 2;
	}
	domain_initializer = dp->list[index].d_i;
	if (!domain_initializer)
		goto not_domain_initializer;
	tomoyo_get();
	if (domain_initializer->domainname)
		line = tomoyo_shprintf(" ( " CCS_KEYWORD_INITIALIZE_DOMAIN "%s from %s )",
				    domain_initializer->program->name,
				    domain_initializer->domainname->name);
	else
		line = tomoyo_shprintf(" ( " CCS_KEYWORD_INITIALIZE_DOMAIN "%s )",
				    domain_initializer->program->name);
	printw("%s", tomoyo_eat(line));
	tmp_col += strlen(line);
	tomoyo_put();
	goto done;
not_domain_initializer:
	domain_keeper = dp->list[index].d_k;
	if (!domain_keeper)
		goto not_domain_keeper;
	tomoyo_get();
	if (domain_keeper->program)
		line = tomoyo_shprintf(" ( " CCS_KEYWORD_KEEP_DOMAIN "%s from %s )",
				    domain_keeper->program->name,
				    domain_keeper->domainname->name);
	else
		line = tomoyo_shprintf(" ( " CCS_KEYWORD_KEEP_DOMAIN "%s )",
				    domain_keeper->domainname->name);
	printw("%s", tomoyo_eat(line));
	tmp_col += strlen(line);
	tomoyo_put();
	goto done;
not_domain_keeper:
	if (!tomoyo_initializer_source(dp, index))
		goto done;
	tomoyo_get();
	line = tomoyo_shprintf(CCS_ROOT_NAME "%s", strrchr(tomoyo_domain_name(dp, index), ' '));
	redirect_index = tomoyo_find_domain(dp, line, false, false);
	if (redirect_index >= 0)
		line = tomoyo_shprintf(" ( -> %d )", dp->list[redirect_index].number);
	else
		line = tomoyo_shprintf(" ( -> Not Found )");
	printw("%s", tomoyo_eat(line));
	tmp_col += strlen(line);
	tomoyo_put();
done:
	return tmp_col;
}

static int tomoyo_show_acl_line(const int index, const int list_indent)
{
	u8 directive = tomoyo_generic_acl_list[index].directive;
	const char *cp1 = tomoyo_directives[directive].alias;
	const char *cp2 = tomoyo_generic_acl_list[index].operand;
	int len = list_indent - tomoyo_directives[directive].alias_len;
	printw("%c%4d: %s ",
	       tomoyo_generic_acl_list[index].selected ? '&' : ' ',
	       index, tomoyo_eat(cp1));
	while (len-- > 0)
		printw("%s", tomoyo_eat(" "));
	printw("%s", tomoyo_eat(cp2));
	return strlen(cp1) + strlen(cp2) + 8 + list_indent;
}

static int tomoyo_show_profile_line(const int index)
{
	const char *cp = tomoyo_generic_acl_list[index].operand;
	const u16 profile = tomoyo_generic_acl_list[index].directive;
	char number[8] = "";
	if (profile <= 256)
		snprintf(number, sizeof(number) - 1, "%3u-", profile);
	printw("%c%4d: %s", tomoyo_generic_acl_list[index].selected ? '&' : ' ',
	       index, tomoyo_eat(number));
	printw("%s ", tomoyo_eat(cp));
	return strlen(number) + strlen(cp) + 8;
}

static int tomoyo_show_literal_line(const int index)
{
	const char *cp = tomoyo_generic_acl_list[index].operand;
	printw("%c%4d: %s ",
	       tomoyo_generic_acl_list[index].selected ? '&' : ' ',
	       index, tomoyo_eat(cp));
	return strlen(cp) + 8;
}

static int tomoyo_show_meminfo_line(const int index)
{
	char *line;
	unsigned int now = 0;
	unsigned int quota = -1;
	const char *data = tomoyo_generic_acl_list[index].operand;
	tomoyo_get();
	if (sscanf(data, "Policy: %u (Quota: %u)", &now, &quota) >= 1)
		line = tomoyo_shprintf("Memory used for policy      = %10u bytes   "
				    "(Quota: %10u bytes)", now, quota);
	else if (sscanf(data, "Audit logs: %u (Quota: %u)", &now, &quota) >= 1)
		line = tomoyo_shprintf("Memory used for audit logs  = %10u bytes   "
				    "(Quota: %10u bytes)", now, quota);
	else if (sscanf(data, "Query lists: %u (Quota: %u)", &now, &quota) >= 1)
		line = tomoyo_shprintf("Memory used for query lists = %10u bytes   "
				    "(Quota: %10u bytes)", now, quota);
	else if (sscanf(data, "Total: %u", &now) == 1)
		line = tomoyo_shprintf("Total memory in use         = %10u bytes",
				    now);
	else if (sscanf(data, "Shared: %u (Quota: %u)", &now, &quota) >= 1)
		line = tomoyo_shprintf("Memory for string data      = %10u bytes    "
				    "Quota = %10u bytes", now, quota);
	else if (sscanf(data, "Private: %u (Quota: %u)", &now, &quota) >= 1)
		line = tomoyo_shprintf("Memory for numeric data     = %10u bytes    "
				    "Quota = %10u bytes", now, quota);
	else if (sscanf(data, "Dynamic: %u (Quota: %u)", &now, &quota) >= 1)
		line = tomoyo_shprintf("Memory for temporary data   = %10u bytes    "
				    "Quota = %10u bytes", now, quota);
	else
		line = tomoyo_shprintf("%s", data);
	if (line[0])
		printw("%s", tomoyo_eat(line));
	now = strlen(line);
	tomoyo_put();
	return now;
}

static int tomoyo_domain_sort_type = 0;

static _Bool tomoyo_show_command_key(const int screen, const _Bool readonly)
{
	int c;
	clear();
	printw("Commands available for this screen are:\n\n");
	printw("Q/q        Quit this editor.\n");
	printw("R/r        Refresh to the latest information.\n");
	switch (screen) {
	case CCS_SCREEN_MEMINFO_LIST:
		break;
	default:
		printw("F/f        Find first.\n");
		printw("N/n        Find next.\n");
		printw("P/p        Find previous.\n");
	}
	printw("W/w        Switch to selected screen.\n");
	/* printw("Tab        Switch to next screen.\n"); */
	switch (screen) {
	case CCS_SCREEN_MEMINFO_LIST:
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
		if (tomoyo_domain_sort_type) {
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
	case CCS_SCREEN_MEMINFO_LIST:
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
		if (!tomoyo_offline_mode)
			printw("@          Switch domain/process list.\n");
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

/* Main Functions */

static void tomoyo_close_write(FILE *fp)
{
	if (tomoyo_network_mode) {
		fputc(0, fp);
		fflush(fp);
		fgetc(fp);
	}
	fclose(fp);
}

static void tomoyo_set_error(const char *filename)
{
	if (filename) {
		const int len = strlen(filename) + 128;
		tomoyo_last_error = realloc(tomoyo_last_error, len);
		if (!tomoyo_last_error)
			tomoyo_out_of_memory();
		memset(tomoyo_last_error, 0, len);
		snprintf(tomoyo_last_error, len - 1, "Can't open %s .", filename);
	} else {
		free(tomoyo_last_error);
		tomoyo_last_error = NULL;
	}
}

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

static int tomoyo_open2(const char *filename, int mode)
{
	const int fd = open(filename, mode);
	if (fd == EOF && errno != ENOENT)
		tomoyo_set_error(filename);
	return fd;
}

static void tomoyo_sigalrm_handler(int sig)
{
	tomoyo_need_reload = true;
	alarm(tomoyo_refresh_interval);
}

static const char *tomoyo_eat(const char *str)
{
	while (*str && tomoyo_eat_col) {
		str++;
		tomoyo_eat_col--;
	}
	return str;
}

static const struct tomoyo_domain_keeper_entry *
tomoyo_domain_keeper(const struct tomoyo_path_info *domainname, const char *program)
{
	int i;
	const struct tomoyo_domain_keeper_entry *flag = NULL;
	struct tomoyo_path_info last_name;
	last_name.name = strrchr(domainname->name, ' ');
	if (last_name.name)
		last_name.name++;
	else
		last_name.name = domainname->name;
	tomoyo_fill_path_info(&last_name);
	for (i = 0; i < tomoyo_domain_keeper_list_len; i++) {
		struct tomoyo_domain_keeper_entry *ptr = &tomoyo_domain_keeper_list[i];
		if (!ptr->is_last_name) {
			if (tomoyo_pathcmp(ptr->domainname, domainname))
				continue;
		} else {
			if (tomoyo_pathcmp(ptr->domainname, &last_name))
				continue;
		}
		if (ptr->program && strcmp(ptr->program->name, program))
			continue;
		if (ptr->is_not)
			return NULL;
		flag = ptr;
	}
	return flag;
}

static const struct tomoyo_domain_initializer_entry *
tomoyo_domain_initializer(const struct tomoyo_path_info *domainname, const char *program)
{
	int i;
	const struct tomoyo_domain_initializer_entry *flag = NULL;
	struct tomoyo_path_info last_name;
	last_name.name = strrchr(domainname->name, ' ');
	if (last_name.name)
		last_name.name++;
	else
		last_name.name = domainname->name;
	tomoyo_fill_path_info(&last_name);
	for (i = 0; i < tomoyo_domain_initializer_list_len; i++) {
		struct tomoyo_domain_initializer_entry *ptr
			= &tomoyo_domain_initializer_list[i];
		if (ptr->domainname) {
			if (!ptr->is_last_name) {
				if (tomoyo_pathcmp(ptr->domainname, domainname))
					continue;
			} else {
				if (tomoyo_pathcmp(ptr->domainname, &last_name))
					continue;
			}
		}
		if (strcmp(ptr->program->name, program))
			continue;
		if (ptr->is_not)
			return NULL;
		flag = ptr;
	}
	return flag;
}

static int tomoyo_profile_entry_compare(const void *a, const void *b)
{
	const struct tomoyo_generic_acl *a0 = (struct tomoyo_generic_acl *) a;
	const struct tomoyo_generic_acl *b0 = (struct tomoyo_generic_acl *) b;
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
	if (tomoyo_profile_sort_type == 0) {
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

static void tomoyo_read_generic_policy(void)
{
	FILE *fp = NULL;
	_Bool flag = false;
	while (tomoyo_generic_acl_list_count)
		free((void *)
		     tomoyo_generic_acl_list[--tomoyo_generic_acl_list_count].operand);
	if (tomoyo_current_screen == CCS_SCREEN_ACL_LIST) {
		if (tomoyo_network_mode)
			/* We can read after write. */
			fp = tomoyo_editpolicy_open_write(tomoyo_policy_file);
		else if (!tomoyo_offline_mode)
			/* Don't set error message if failed. */
			fp = fopen(tomoyo_policy_file, "r+");
		if (fp) {
			if (tomoyo_domain_sort_type)
				fprintf(fp, "select pid=%u\n", tomoyo_current_pid);
			else
				fprintf(fp, "select domain=%s\n",
					tomoyo_current_domain);
			if (tomoyo_network_mode)
				fputc(0, fp);
			fflush(fp);
		}
	}
	if (!fp)
		fp = tomoyo_editpolicy_open_read(tomoyo_policy_file);
	if (!fp) {
		tomoyo_set_error(tomoyo_policy_file);
		return;
	}
	tomoyo_get();
	while (true) {
		char *line = tomoyo_freadline(fp);
		u16 directive;
		char *cp;
		if (!line)
			break;
		if (tomoyo_current_screen == CCS_SCREEN_ACL_LIST) {
			if (tomoyo_domain_def(line)) {
				flag = !strcmp(line, tomoyo_current_domain);
				continue;
			}
			if (!flag || !line[0] ||
			    !strncmp(line, CCS_KEYWORD_USE_PROFILE,
				     CCS_KEYWORD_USE_PROFILE_LEN))
				continue;
		} else {
			if (!line[0])
				continue;
		}
		switch (tomoyo_current_screen) {
		case CCS_SCREEN_EXCEPTION_LIST:
			directive = tomoyo_find_directive(true, line);
			if (directive == CCS_DIRECTIVE_NONE)
				continue;
			/*
			 * Remember path_group for
			 * tomoyo_editpolicy_try_optimize().
			 */
			if (directive != CCS_DIRECTIVE_PATH_GROUP)
				break;
			cp = strdup(line);
			if (!cp)
				tomoyo_out_of_memory();
			tomoyo_add_path_group_policy(cp, false);
			free(cp);
			break;
		case CCS_SCREEN_ACL_LIST:
			directive = tomoyo_find_directive(true, line);
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
		tomoyo_generic_acl_list = realloc(tomoyo_generic_acl_list,
					       (tomoyo_generic_acl_list_count + 1) *
					       sizeof(struct tomoyo_generic_acl));
		if (!tomoyo_generic_acl_list)
			tomoyo_out_of_memory();
		cp = strdup(line);
		if (!cp)
			tomoyo_out_of_memory();
		tomoyo_generic_acl_list[tomoyo_generic_acl_list_count].directive = directive;
		tomoyo_generic_acl_list[tomoyo_generic_acl_list_count].selected = 0;
		tomoyo_generic_acl_list[tomoyo_generic_acl_list_count++].operand = cp;
	}
	tomoyo_put();
	fclose(fp);
	switch (tomoyo_current_screen) {
	case CCS_SCREEN_ACL_LIST:
		qsort(tomoyo_generic_acl_list, tomoyo_generic_acl_list_count,
		      sizeof(struct tomoyo_generic_acl), tomoyo_generic_acl_compare);
		break;
	case CCS_SCREEN_EXCEPTION_LIST:
		qsort(tomoyo_generic_acl_list, tomoyo_generic_acl_list_count,
		      sizeof(struct tomoyo_generic_acl), tomoyo_generic_acl_compare0);
		break;
	case CCS_SCREEN_PROFILE_LIST:
		qsort(tomoyo_generic_acl_list, tomoyo_generic_acl_list_count,
		      sizeof(struct tomoyo_generic_acl), tomoyo_profile_entry_compare);
		break;
	default:
		qsort(tomoyo_generic_acl_list, tomoyo_generic_acl_list_count,
		      sizeof(struct tomoyo_generic_acl), tomoyo_string_acl_compare);
	}
}

static int tomoyo_add_domain_initializer_entry(const char *domainname,
					    const char *program, const _Bool is_not)
{
	void *vp;
	struct tomoyo_domain_initializer_entry *ptr;
	_Bool is_last_name = false;
	if (!tomoyo_correct_path(program))
		return -EINVAL;
	if (domainname) {
		if (tomoyo_correct_path(domainname))
			is_last_name = true;
		else if (!tomoyo_correct_domain(domainname))
			return -EINVAL;
	}
	vp = realloc(tomoyo_domain_initializer_list,
		     (tomoyo_domain_initializer_list_len + 1) *
		     sizeof(struct tomoyo_domain_initializer_entry));
	if (!vp)
		tomoyo_out_of_memory();
	tomoyo_domain_initializer_list = vp;
	ptr = &tomoyo_domain_initializer_list[tomoyo_domain_initializer_list_len++];
	memset(ptr, 0, sizeof(struct tomoyo_domain_initializer_entry));
	ptr->program = tomoyo_savename(program);
	if (!ptr->program)
		tomoyo_out_of_memory();
	if (domainname) {
		ptr->domainname = tomoyo_savename(domainname);
		if (!ptr->domainname)
			tomoyo_out_of_memory();
	}
	ptr->is_not = is_not;
	ptr->is_last_name = is_last_name;
	return 0;
}

static int tomoyo_add_domain_keeper_entry(const char *domainname, const char *program,
				       const _Bool is_not)
{
	struct tomoyo_domain_keeper_entry *ptr;
	_Bool is_last_name = false;
	if (tomoyo_correct_path(domainname))
		is_last_name = true;
	else if (!tomoyo_correct_domain(domainname))
		return -EINVAL;
	if (program && !tomoyo_correct_path(program))
		return -EINVAL;
	tomoyo_domain_keeper_list = realloc(tomoyo_domain_keeper_list,
					 (tomoyo_domain_keeper_list_len + 1) *
					 sizeof(struct tomoyo_domain_keeper_entry));
	if (!tomoyo_domain_keeper_list)
		tomoyo_out_of_memory();
	ptr = &tomoyo_domain_keeper_list[tomoyo_domain_keeper_list_len++];
	memset(ptr, 0, sizeof(struct tomoyo_domain_keeper_entry));
	ptr->domainname = tomoyo_savename(domainname);
	if (!ptr->domainname)
		tomoyo_out_of_memory();
	if (program) {
		ptr->program = tomoyo_savename(program);
		if (!ptr->program)
			tomoyo_out_of_memory();
	}
	ptr->is_not = is_not;
	ptr->is_last_name = is_last_name;
	return 0;
}

static int tomoyo_add_path_group_entry(const char *group_name, const char *member_name,
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
	if (!saved_group_name || !saved_member_name)
		return -ENOMEM;
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
		tomoyo_path_group_list = realloc(tomoyo_path_group_list,
					  (tomoyo_path_group_list_len + 1) *
					  sizeof(struct tomoyo_path_group_entry));
		if (!tomoyo_path_group_list)
			tomoyo_out_of_memory();
		group = &tomoyo_path_group_list[tomoyo_path_group_list_len++];
		memset(group, 0, sizeof(struct tomoyo_path_group_entry));
		group->group_name = saved_group_name;
	}
	group->member_name = realloc(group->member_name,
				     (group->member_name_len + 1)
				     * sizeof(const struct tomoyo_path_info *));
	if (!group->member_name)
		tomoyo_out_of_memory();
	group->member_name[group->member_name_len++] = saved_member_name;
	return 0;
}

static void tomoyo_read_domain_and_exception_policy(struct tomoyo_domain_policy *dp)
{
	FILE *fp;
	int i;
	int j;
	int index;
	int max_index;
	tomoyo_clear_domain_policy(dp);
	tomoyo_domain_keeper_list_len = 0;
	tomoyo_domain_initializer_list_len = 0;
	while (tomoyo_path_group_list_len)
		free(tomoyo_path_group_list[--tomoyo_path_group_list_len].member_name);
	/*
	while (tomoyo_address_group_list_len)
		free(tomoyo_address_group_list[--tomoyo_address_group_list_len].member_name);
	*/
	tomoyo_address_group_list_len = 0;
	tomoyo_number_group_list_len = 0;
	tomoyo_find_or_assign_new_domain(dp, CCS_ROOT_NAME, false, false);

	/* Load all domain list. */
	fp = NULL;
	if (tomoyo_network_mode)
		/* We can read after write. */
		fp = tomoyo_editpolicy_open_write(tomoyo_policy_file);
	else if (!tomoyo_offline_mode)
		/* Don't set error message if failed. */
		fp = fopen(tomoyo_policy_file, "r+");
	if (fp) {
		fprintf(fp, "select allow_execute\n");
		if (tomoyo_network_mode)
			fputc(0, fp);
		fflush(fp);
	}
	if (!fp)
		fp = tomoyo_editpolicy_open_read(CCS_PROC_POLICY_DOMAIN_POLICY);
	if (!fp) {
		tomoyo_set_error(CCS_PROC_POLICY_DOMAIN_POLICY);
		goto no_domain;
	}
	index = EOF;
	tomoyo_get();
	while (true) {
		char *line = tomoyo_freadline(fp);
		unsigned int profile;
		if (!line)
			break;
		if (tomoyo_domain_def(line)) {
			index = tomoyo_find_or_assign_new_domain(dp, line, false,
							      false);
			continue;
		} else if (index == EOF) {
			continue;
		}
		if (tomoyo_str_starts(line, CCS_KEYWORD_EXECUTE_HANDLER)) {
			tomoyo_add_string_entry(dp, line, index);
		} else if (tomoyo_str_starts(line, CCS_KEYWORD_DENIED_EXECUTE_HANDLER)) {
			tomoyo_add_string_entry(dp, line, index);
		} else if (tomoyo_str_starts(line, CCS_KEYWORD_ALLOW_EXECUTE)) {
			char *cp = strchr(line, ' ');
			if (cp)
				*cp = '\0';
			if (*line == '@' || tomoyo_correct_path(line))
				tomoyo_add_string_entry(dp, line, index);
		} else if (sscanf(line, CCS_KEYWORD_USE_PROFILE "%u", &profile)
			   == 1) {
			dp->list[index].profile = (u8) profile;
			dp->list[index].profile_assigned = 1;
		}
	}
	tomoyo_put();
	fclose(fp);
no_domain:

	max_index = dp->list_len;

	/* Load domain_initializer list, domain_keeper list. */
	fp = tomoyo_editpolicy_open_read(CCS_PROC_POLICY_EXCEPTION_POLICY);
	if (!fp) {
		tomoyo_set_error(CCS_PROC_POLICY_EXCEPTION_POLICY);
		goto no_exception;
	}
	tomoyo_get();
	while (true) {
		char *line = tomoyo_freadline(fp);
		if (!line)
			break;
		if (tomoyo_str_starts(line, CCS_KEYWORD_INITIALIZE_DOMAIN))
			tomoyo_add_domain_initializer_policy(line, false);
		else if (tomoyo_str_starts(line, CCS_KEYWORD_NO_INITIALIZE_DOMAIN))
			tomoyo_add_domain_initializer_policy(line, true);
		else if (tomoyo_str_starts(line, CCS_KEYWORD_KEEP_DOMAIN))
			tomoyo_add_domain_keeper_policy(line, false);
		else if (tomoyo_str_starts(line, CCS_KEYWORD_NO_KEEP_DOMAIN))
			tomoyo_add_domain_keeper_policy(line, true);
		else if (tomoyo_str_starts(line, CCS_KEYWORD_PATH_GROUP))
			tomoyo_add_path_group_policy(line, false);
		else if (tomoyo_str_starts(line, CCS_KEYWORD_ADDRESS_GROUP))
			tomoyo_add_address_group_policy(line, false);
		else if (tomoyo_str_starts(line, CCS_KEYWORD_NUMBER_GROUP))
			tomoyo_add_number_group_policy(line, false);
		else if (tomoyo_str_starts(line, CCS_KEYWORD_EXECUTE_HANDLER))
			for (index = 0; index < max_index; index++)
				tomoyo_add_string_entry(dp, line, index);
		else if (tomoyo_str_starts(line, CCS_KEYWORD_DENIED_EXECUTE_HANDLER))
			for (index = 0; index < max_index; index++)
				tomoyo_add_string_entry(dp, line, index);
		else if (tomoyo_str_starts(line, CCS_KEYWORD_ALLOW_EXECUTE)) {
			char *cp = strchr(line, ' ');
			if (cp)
				*cp = '\0';
			if (*line == '@' || tomoyo_correct_path(line))
				for (index = 0; index < max_index; index++)
					tomoyo_add_string_entry(dp, line, index);
		}
	}
	tomoyo_put();
	fclose(fp);
no_exception:

	/* Find unreachable domains. */
	for (index = 0; index < max_index; index++) {
		char *line;
		tomoyo_get();
		line = tomoyo_shprintf("%s", tomoyo_domain_name(dp, index));
		while (true) {
			const struct tomoyo_domain_initializer_entry *d_i;
			const struct tomoyo_domain_keeper_entry *d_k;
			struct tomoyo_path_info parent;
			char *cp = strrchr(line, ' ');
			if (!cp)
				break;
			*cp++ = '\0';
			parent.name = line;
			tomoyo_fill_path_info(&parent);
			d_i = tomoyo_domain_initializer(&parent, cp);
			if (d_i) {
				/* Initializer under <kernel> is reachable. */
				if (parent.total_len == CCS_ROOT_NAME_LEN)
					break;
				dp->list[index].d_i = d_i;
				dp->list[index].d_k = NULL;
				continue;
			}
			d_k = tomoyo_domain_keeper(&parent, cp);
			if (d_k) {
				dp->list[index].d_i = NULL;
				dp->list[index].d_k = d_k;
			}
		}
		tomoyo_put();
		if (dp->list[index].d_i || dp->list[index].d_k)
			dp->list[index].is_du = true;
	}

	/* Find domain initializer target domains. */
	for (index = 0; index < max_index; index++) {
		char *cp = strchr(tomoyo_domain_name(dp, index), ' ');
		if (!cp || strchr(cp + 1, ' '))
			continue;
		for (i = 0; i < tomoyo_domain_initializer_list_len; i++) {
			struct tomoyo_domain_initializer_entry *ptr
				= &tomoyo_domain_initializer_list[i];
			if (ptr->is_not)
				continue;
			if (strcmp(ptr->program->name, cp + 1))
				continue;
			dp->list[index].is_dit = true;
		}
	}

	/* Find domain keeper domains. */
	for (index = 0; index < max_index; index++) {
		for (i = 0; i < tomoyo_domain_keeper_list_len; i++) {
			struct tomoyo_domain_keeper_entry *ptr
				= &tomoyo_domain_keeper_list[i];
			char *cp;
			if (ptr->is_not)
				continue;
			if (!ptr->is_last_name) {
				if (tomoyo_pathcmp(ptr->domainname,
					    dp->list[index].domainname))
					continue;
				dp->list[index].is_dk = true;
				continue;
			}
			cp = strrchr(dp->list[index].domainname->name,
				     ' ');
			if (!cp || strcmp(ptr->domainname->name, cp + 1))
				continue;
			dp->list[index].is_dk = true;
		}
	}

	/* Create domain initializer source domains. */
	for (index = 0; index < max_index; index++) {
		const struct tomoyo_path_info *domainname
			= dp->list[index].domainname;
		const struct tomoyo_path_info **string_ptr
			= dp->list[index].string_ptr;
		const int max_count = dp->list[index].string_count;
		/* Don't create source domain under <kernel> because
		   they will become tomoyo_target domains. */
		if (domainname->total_len == CCS_ROOT_NAME_LEN)
			continue;
		for (i = 0; i < max_count; i++) {
			const struct tomoyo_path_info *cp = string_ptr[i];
			struct tomoyo_path_group_entry *group;
			if (cp->name[0] != '@') {
				tomoyo_assign_domain_initializer_source(dp, domainname,
								     cp->name);
				continue;
			}
			group = tomoyo_find_path_group(cp->name + 1);
			if (!group)
				continue;
			for (j = 0; j < group->member_name_len; j++) {
				cp = group->member_name[j];
				tomoyo_assign_domain_initializer_source(dp, domainname,
								     cp->name);
			}
		}
	}

	/* Create missing parent domains. */
	for (index = 0; index < max_index; index++) {
		char *line;
		tomoyo_get();
		line = tomoyo_shprintf("%s", tomoyo_domain_name(dp, index));
		while (true) {
			char *cp = strrchr(line, ' ');
			if (!cp)
				break;
			*cp = '\0';
			if (tomoyo_find_domain(dp, line, false, false) != EOF)
				continue;
			if (tomoyo_find_or_assign_new_domain(dp, line, false, true)
			    == EOF)
				tomoyo_out_of_memory();
		}
		tomoyo_put();
	}

	/* Sort by domain name. */
	qsort(dp->list, dp->list_len, sizeof(struct tomoyo_domain_info),
	      tomoyo_domainname_attribute_compare);

	/* Assign domain numbers. */
	{
		int number = 0;
		int index;
		tomoyo_unnumbered_domain_count = 0;
		for (index = 0; index < dp->list_len; index++) {
			if (tomoyo_deleted_domain(dp, index) ||
			    tomoyo_initializer_source(dp, index)) {
				dp->list[index].number = -1;
				tomoyo_unnumbered_domain_count++;
			} else {
				dp->list[index].number = number++;
			}
		}
	}

	dp->list_selected = realloc(dp->list_selected, dp->list_len);
	if (dp->list_len && !dp->list_selected)
		tomoyo_out_of_memory();
	memset(dp->list_selected, 0, dp->list_len);
}

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
			    tomoyo_task_list[index].pid, tomoyo_task_list[index].domain);
	printw("%s", tomoyo_eat(line));
	tmp_col += strlen(line);
	tomoyo_put();
	return tmp_col;
}

static void tomoyo_show_list(struct tomoyo_domain_policy *dp)
{
	const int offset = tomoyo_current_item_index[tomoyo_current_screen];
	int i;
	int tmp_col;
	if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST)
		tomoyo_list_item_count[CCS_SCREEN_DOMAIN_LIST] = tomoyo_domain_sort_type ?
			tomoyo_task_list_len : dp->list_len;
	else
		tomoyo_list_item_count[tomoyo_current_screen] = tomoyo_generic_acl_list_count;
	clear();
	move(0, 0);
	if (tomoyo_window_height < CCS_HEADER_LINES + 1) {
		printw("Please enlarge window.");
		clrtobot();
		refresh();
		return;
	}
	/* add color */
	tomoyo_editpolicy_color_change(tomoyo_editpolicy_color_head(tomoyo_current_screen), true);
	if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (tomoyo_domain_sort_type) {
			printw("<<< Process State Viewer >>>"
			       "      %d process%s    '?' for help",
			       tomoyo_task_list_len, tomoyo_task_list_len > 1 ? "es" : "");
		} else {
			int i = tomoyo_list_item_count[CCS_SCREEN_DOMAIN_LIST]
				- tomoyo_unnumbered_domain_count;
			printw("<<< Domain Transition Editor >>>"
			       "      %d domain%c    '?' for help",
			       i, i > 1 ? 's' : ' ');
		}
	} else {
		int i = tomoyo_list_item_count[tomoyo_current_screen];
		printw("<<< %s >>>"
		       "      %d entr%s    '?' for help", tomoyo_list_caption,
		       i, i > 1 ? "ies" : "y");
	}
	/* add color */
	tomoyo_editpolicy_color_change(tomoyo_editpolicy_color_head(tomoyo_current_screen), false);
	tomoyo_eat_col = tomoyo_max_eat_col[tomoyo_current_screen];
	tomoyo_max_col = 0;
	if (tomoyo_current_screen == CCS_SCREEN_ACL_LIST) {
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
	case CCS_SCREEN_EXCEPTION_LIST:
	case CCS_SCREEN_ACL_LIST:
		for (i = 0; i < tomoyo_list_item_count[tomoyo_current_screen]; i++) {
			const u8 directive = tomoyo_generic_acl_list[i].directive;
			const int len = tomoyo_directives[directive].alias_len;
			if (len > tomoyo_list_indent)
				tomoyo_list_indent = len;
		}
		break;
	}
	for (i = 0; i < tomoyo_body_lines; i++) {
		const int index = offset + i;
		tomoyo_eat_col = tomoyo_max_eat_col[tomoyo_current_screen];
		if (index >= tomoyo_list_item_count[tomoyo_current_screen])
			break;
		move(CCS_HEADER_LINES + i, 0);
		switch (tomoyo_current_screen) {
		case CCS_SCREEN_DOMAIN_LIST:
			if (!tomoyo_domain_sort_type)
				tmp_col = tomoyo_show_domain_line(dp, index);
			else
				tmp_col = tomoyo_show_process_line(index);
			break;
		case CCS_SCREEN_EXCEPTION_LIST:
		case CCS_SCREEN_ACL_LIST:
			tmp_col = tomoyo_show_acl_line(index, tomoyo_list_indent);
			break;
		case CCS_SCREEN_PROFILE_LIST:
			tmp_col = tomoyo_show_profile_line(index);
			break;
		case CCS_SCREEN_MEMINFO_LIST:
			tmp_col = tomoyo_show_meminfo_line(index);
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
	tomoyo_show_current(dp);
}

static void tomoyo_resize_window(void)
{
	getmaxyx(stdscr, tomoyo_window_height, tomoyo_window_width);
	tomoyo_body_lines = tomoyo_window_height - CCS_HEADER_LINES;
	if (tomoyo_body_lines <= tomoyo_current_y[tomoyo_current_screen])
		tomoyo_current_y[tomoyo_current_screen] = tomoyo_body_lines - 1;
	if (tomoyo_current_y[tomoyo_current_screen] < 0)
		tomoyo_current_y[tomoyo_current_screen] = 0;
}

static void tomoyo_up_arrow_key(struct tomoyo_domain_policy *dp)
{
	if (tomoyo_current_y[tomoyo_current_screen] > 0) {
		tomoyo_current_y[tomoyo_current_screen]--;
		tomoyo_show_current(dp);
	} else if (tomoyo_current_item_index[tomoyo_current_screen] > 0) {
		tomoyo_current_item_index[tomoyo_current_screen]--;
		tomoyo_show_list(dp);
	}
}

static void tomoyo_down_arrow_key(struct tomoyo_domain_policy *dp)
{
	if (tomoyo_current_y[tomoyo_current_screen] < tomoyo_body_lines - 1) {
		if (tomoyo_current_item_index[tomoyo_current_screen]
		    + tomoyo_current_y[tomoyo_current_screen]
		    < tomoyo_list_item_count[tomoyo_current_screen] - 1) {
			tomoyo_current_y[tomoyo_current_screen]++;
			tomoyo_show_current(dp);
		}
	} else if (tomoyo_current_item_index[tomoyo_current_screen]
		   + tomoyo_current_y[tomoyo_current_screen]
		   < tomoyo_list_item_count[tomoyo_current_screen] - 1) {
		tomoyo_current_item_index[tomoyo_current_screen]++;
		tomoyo_show_list(dp);
	}
}

static void tomoyo_page_up_key(struct tomoyo_domain_policy *dp)
{
	int p0 = tomoyo_current_item_index[tomoyo_current_screen];
	int p1 = tomoyo_current_y[tomoyo_current_screen];
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
	refresh = (tomoyo_current_item_index[tomoyo_current_screen] != p0);
	tomoyo_current_item_index[tomoyo_current_screen] = p0;
	tomoyo_current_y[tomoyo_current_screen] = p1;
	if (refresh)
		tomoyo_show_list(dp);
	else
		tomoyo_show_current(dp);
}

static void tomoyo_page_down_key(struct tomoyo_domain_policy *dp)
{
	int tomoyo_count = tomoyo_list_item_count[tomoyo_current_screen] - 1;
	int p0 = tomoyo_current_item_index[tomoyo_current_screen];
	int p1 = tomoyo_current_y[tomoyo_current_screen];
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
	refresh = (tomoyo_current_item_index[tomoyo_current_screen] != p0);
	tomoyo_current_item_index[tomoyo_current_screen] = p0;
	tomoyo_current_y[tomoyo_current_screen] = p1;
	if (refresh)
		tomoyo_show_list(dp);
	else
		tomoyo_show_current(dp);
}

int tomoyo_editpolicy_get_current(void)
{
	int tomoyo_count = tomoyo_list_item_count[tomoyo_current_screen];
	const int p0 = tomoyo_current_item_index[tomoyo_current_screen];
	const int p1 = tomoyo_current_y[tomoyo_current_screen];
	if (!tomoyo_count)
		return EOF;
	if (p0 + p1 < 0 || p0 + p1 >= tomoyo_count) {
		fprintf(stderr, "ERROR: tomoyo_current_item_index=%d tomoyo_current_y=%d\n",
			p0, p1);
		exit(127);
	}
	return p0 + p1;
}

static void tomoyo_show_current(struct tomoyo_domain_policy *dp)
{
	if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST && !tomoyo_domain_sort_type) {
		char *line;
		const int index = tomoyo_editpolicy_get_current();
		tomoyo_get();
		tomoyo_eat_col = tomoyo_max_eat_col[tomoyo_current_screen];
		line = tomoyo_shprintf("%s", tomoyo_eat(tomoyo_domain_name(dp, index)));
		if (tomoyo_window_width < strlen(line))
			line[tomoyo_window_width] = '\0';
		move(2, 0);
		clrtoeol();
		tomoyo_editpolicy_attr_change(A_REVERSE, true);  /* add color */
		printw("%s", line);
		tomoyo_editpolicy_attr_change(A_REVERSE, false); /* add color */
		tomoyo_put();
	}
	move(CCS_HEADER_LINES + tomoyo_current_y[tomoyo_current_screen], 0);
	tomoyo_editpolicy_line_draw(tomoyo_current_screen);     /* add color */
	refresh();
}

static void tomoyo_adjust_cursor_pos(const int item_count)
{
	if (item_count == 0) {
		tomoyo_current_item_index[tomoyo_current_screen] = 0;
		tomoyo_current_y[tomoyo_current_screen] = 0;
	} else {
		while (tomoyo_current_item_index[tomoyo_current_screen]
		       + tomoyo_current_y[tomoyo_current_screen] >= item_count) {
			if (tomoyo_current_y[tomoyo_current_screen] > 0)
				tomoyo_current_y[tomoyo_current_screen]--;
			else if (tomoyo_current_item_index[tomoyo_current_screen] > 0)
				tomoyo_current_item_index[tomoyo_current_screen]--;
		}
	}
}

static void tomoyo_set_cursor_pos(const int index)
{
	while (index < tomoyo_current_y[tomoyo_current_screen]
	       + tomoyo_current_item_index[tomoyo_current_screen]) {
		if (tomoyo_current_y[tomoyo_current_screen] > 0)
			tomoyo_current_y[tomoyo_current_screen]--;
		else
			tomoyo_current_item_index[tomoyo_current_screen]--;
	}
	while (index > tomoyo_current_y[tomoyo_current_screen]
	       + tomoyo_current_item_index[tomoyo_current_screen]) {
		if (tomoyo_current_y[tomoyo_current_screen] < tomoyo_body_lines - 1)
			tomoyo_current_y[tomoyo_current_screen]++;
		else
			tomoyo_current_item_index[tomoyo_current_screen]++;
	}
}

static _Bool tomoyo_select_item(struct tomoyo_domain_policy *dp, const int index)
{
	int x;
	int y;
	if (index < 0)
		return false;
	if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (!tomoyo_domain_sort_type) {
			if (tomoyo_deleted_domain(dp, index) ||
			    tomoyo_initializer_source(dp, index))
				return false;
			dp->list_selected[index] ^= 1;
		} else {
			tomoyo_task_list[index].selected ^= 1;
		}
	} else {
		tomoyo_generic_acl_list[index].selected ^= 1;
	}
	getyx(stdscr, y, x);
	tomoyo_editpolicy_sttr_save();    /* add color */
	tomoyo_show_list(dp);
	tomoyo_editpolicy_sttr_restore(); /* add color */
	move(y, x);
	return true;
}

static int tomoyo_generic_acl_compare(const void *a, const void *b)
{
	const struct tomoyo_generic_acl *a0 = (struct tomoyo_generic_acl *) a;
	const struct tomoyo_generic_acl *b0 = (struct tomoyo_generic_acl *) b;
	const char *a1 = tomoyo_directives[a0->directive].alias;
	const char *b1 = tomoyo_directives[b0->directive].alias;
	const char *a2 = a0->operand;
	const char *b2 = b0->operand;
	if (tomoyo_acl_sort_type == 0) {
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

static void tomoyo_delete_entry(struct tomoyo_domain_policy *dp, const int index)
{
	int c;
	move(1, 0);
	tomoyo_editpolicy_color_change(CCS_DISP_ERR, true);	/* add color */
	if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		c = tomoyo_count(dp->list_selected, dp->list_len);
		if (!c && index < dp->list_len)
			c = tomoyo_select_item(dp, index);
		if (!c)
			printw("Select domain using Space key first.");
		else
			printw("Delete selected domain%s? ('Y'es/'N'o)",
			       c > 1 ? "s" : "");
	} else {
		c = tomoyo_count2(tomoyo_generic_acl_list, tomoyo_generic_acl_list_count);
		if (!c)
			c = tomoyo_select_item(dp, index);
		if (!c)
			printw("Select entry using Space key first.");
		else
			printw("Delete selected entr%s? ('Y'es/'N'o)",
			       c > 1 ? "ies" : "y");
	}
	tomoyo_editpolicy_color_change(CCS_DISP_ERR, false);	/* add color */
	clrtoeol();
	refresh();
	if (!c)
		return;
	do {
		c = tomoyo_getch2();
	} while (!(c == 'Y' || c == 'y' || c == 'N' || c == 'n' || c == EOF));
	tomoyo_resize_window();
	if (c != 'Y' && c != 'y') {
		tomoyo_show_list(dp);
		return;
	}
	if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		int i;
		FILE *fp = tomoyo_editpolicy_open_write(CCS_PROC_POLICY_DOMAIN_POLICY);
		if (!fp)
			return;
		for (i = 1; i < dp->list_len; i++) {
			if (!dp->list_selected[i])
				continue;
			fprintf(fp, "delete %s\n", tomoyo_domain_name(dp, i));
		}
		tomoyo_close_write(fp);
	} else {
		int i;
		FILE *fp = tomoyo_editpolicy_open_write(tomoyo_policy_file);
		if (!fp)
			return;
		if (tomoyo_current_screen == CCS_SCREEN_ACL_LIST) {
			if (tomoyo_domain_sort_type)
				fprintf(fp, "select pid=%u\n", tomoyo_current_pid);
			else
				fprintf(fp, "select domain=%s\n",
					tomoyo_current_domain);
		}
		for (i = 0; i < tomoyo_generic_acl_list_count; i++) {
			u8 directive;
			if (!tomoyo_generic_acl_list[i].selected)
				continue;
			directive = tomoyo_generic_acl_list[i].directive;
			fprintf(fp, "delete %s %s\n",
				tomoyo_directives[directive].original,
				tomoyo_generic_acl_list[i].operand);
		}
		tomoyo_close_write(fp);
	}
}

static void tomoyo_add_entry(struct tomoyo_readline_data *rl)
{
	FILE *fp;
	char *line;
	tomoyo_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = tomoyo_readline(tomoyo_window_height - 1, 0, "Enter new entry> ",
			    rl->history, rl->count, 128000, 8);
	tomoyo_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	rl->count = tomoyo_add_history(line, rl->history, rl->count, rl->max);
	fp = tomoyo_editpolicy_open_write(tomoyo_policy_file);
	if (!fp)
		goto out;
	switch (tomoyo_current_screen) {
		u8 directive;
	case CCS_SCREEN_DOMAIN_LIST:
		if (!tomoyo_correct_domain(line)) {
			const int len = strlen(line) + 128;
			tomoyo_last_error = realloc(tomoyo_last_error, len);
			if (!tomoyo_last_error)
				tomoyo_out_of_memory();
			memset(tomoyo_last_error, 0, len);
			snprintf(tomoyo_last_error, len - 1,
				 "%s is an invalid domainname.", line);
			line[0] = '\0';
		}
		break;
	case CCS_SCREEN_ACL_LIST:
		if (tomoyo_domain_sort_type)
			fprintf(fp, "select pid=%u\n", tomoyo_current_pid);
		else
			fprintf(fp, "select domain=%s\n", tomoyo_current_domain);
		/* Fall through. */
	case CCS_SCREEN_EXCEPTION_LIST:
		directive = tomoyo_find_directive(false, line);
		if (directive != CCS_DIRECTIVE_NONE)
			fprintf(fp, "%s ",
				tomoyo_directives[directive].original);
		break;
	case CCS_SCREEN_PROFILE_LIST:
		if (!strchr(line, '='))
			fprintf(fp, "%s-COMMENT=\n", line);
		break;
	}
	fprintf(fp, "%s\n", line);
	tomoyo_close_write(fp);
out:
	free(line);
}

static void tomoyo_find_entry(struct tomoyo_domain_policy *dp, _Bool input, _Bool forward,
			   const int current, struct tomoyo_readline_data *rl)
{
	int index = current;
	char *line = NULL;
	if (current == EOF)
		return;
	if (!input)
		goto start_search;
	tomoyo_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = tomoyo_readline(tomoyo_window_height - 1, 0, "Search> ",
			    rl->history, rl->count, 128000, 8);
	tomoyo_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	rl->count = tomoyo_add_history(line, rl->history, rl->count, rl->max);
	free(rl->search_buffer[tomoyo_current_screen]);
	rl->search_buffer[tomoyo_current_screen] = line;
	line = NULL;
	index = -1;
start_search:
	tomoyo_get();
	while (true) {
		const char *cp;
		if (forward) {
			if (++index >= tomoyo_list_item_count[tomoyo_current_screen])
				break;
		} else {
			if (--index < 0)
				break;
		}
		if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST) {
			if (tomoyo_domain_sort_type)
				cp = tomoyo_task_list[index].name;
			else
				cp = tomoyo_get_last_name(dp, index);
		} else if (tomoyo_current_screen == CCS_SCREEN_PROFILE_LIST) {
			cp = tomoyo_shprintf("%u-%s",
					  tomoyo_generic_acl_list[index].directive,
					  tomoyo_generic_acl_list[index].operand);
		} else {
			const u8 directive = tomoyo_generic_acl_list[index].directive;
			cp = tomoyo_shprintf("%s %s", tomoyo_directives[directive].alias,
					  tomoyo_generic_acl_list[index].operand);
		}
		if (!strstr(cp, rl->search_buffer[tomoyo_current_screen]))
			continue;
		tomoyo_set_cursor_pos(index);
		break;
	}
	tomoyo_put();
out:
	free(line);
	tomoyo_show_list(dp);
}

static void tomoyo_set_profile(struct tomoyo_domain_policy *dp, const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!tomoyo_domain_sort_type) {
		if (!tomoyo_count(dp->list_selected, dp->list_len) &&
		    !tomoyo_select_item(dp, current)) {
			move(1, 0);
			printw("Select domain using Space key first.");
			clrtoeol();
			refresh();
			return;
		}
	} else {
		if (!tomoyo_count3(tomoyo_task_list, tomoyo_task_list_len) &&
		    !tomoyo_select_item(dp, current)) {
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
	fp = tomoyo_editpolicy_open_write(CCS_PROC_POLICY_DOMAIN_POLICY);
	if (!fp)
		goto out;
	if (!tomoyo_domain_sort_type) {
		for (index = 0; index < dp->list_len; index++) {
			if (!dp->list_selected[index])
				continue;
			fprintf(fp, "select domain=%s\n" CCS_KEYWORD_USE_PROFILE
				"%s\n", tomoyo_domain_name(dp, index), line);
		}
	} else {
		for (index = 0; index < tomoyo_task_list_len; index++) {
			if (!tomoyo_task_list[index].selected)
				continue;
			fprintf(fp, "select pid=%u\n" CCS_KEYWORD_USE_PROFILE
				"%s\n", tomoyo_task_list[index].pid, line);
		}
	}
	tomoyo_close_write(fp);
out:
	free(line);
}

static void tomoyo_set_level(struct tomoyo_domain_policy *dp, const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!tomoyo_count2(tomoyo_generic_acl_list, tomoyo_generic_acl_list_count))
		tomoyo_select_item(dp, current);
	tomoyo_editpolicy_attr_change(A_BOLD, true);  /* add color */
	tomoyo_initial_readline_data = NULL;
	for (index = 0; index < tomoyo_generic_acl_list_count; index++) {
		char *cp;
		if (!tomoyo_generic_acl_list[index].selected)
			continue;
		cp = strchr(tomoyo_generic_acl_list[index].operand, '=');
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
	fp = tomoyo_editpolicy_open_write(CCS_PROC_POLICY_PROFILE);
	if (!fp)
		goto out;
	for (index = 0; index < tomoyo_generic_acl_list_count; index++) {
		char *buf;
		char *cp;
		u16 directive;
		if (!tomoyo_generic_acl_list[index].selected)
			continue;
		tomoyo_get();
		buf = tomoyo_shprintf("%s", tomoyo_generic_acl_list[index].operand);
		cp = strchr(buf, '=');
		if (cp)
			*cp = '\0';
		directive = tomoyo_generic_acl_list[index].directive;
		if (directive < 256)
			fprintf(fp, "%u-", directive);
		fprintf(fp, "%s=%s\n", buf, line);
		tomoyo_put();
	}
	tomoyo_close_write(fp);
out:
	free(line);
}

static void tomoyo_set_quota(struct tomoyo_domain_policy *dp, const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!tomoyo_count2(tomoyo_generic_acl_list, tomoyo_generic_acl_list_count))
		tomoyo_select_item(dp, current);
	tomoyo_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = tomoyo_readline(tomoyo_window_height - 1, 0, "Enter new value> ",
			    NULL, 0, 20, 1);
	tomoyo_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = tomoyo_editpolicy_open_write(CCS_PROC_POLICY_MEMINFO);
	if (!fp)
		goto out;
	for (index = 0; index < tomoyo_generic_acl_list_count; index++) {
		char *buf;
		char *cp;
		if (!tomoyo_generic_acl_list[index].selected)
			continue;
		tomoyo_get();
		buf = tomoyo_shprintf("%s", tomoyo_generic_acl_list[index].operand);
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

static _Bool tomoyo_select_acl_window(struct tomoyo_domain_policy *dp, const int current,
				   const _Bool may_refresh)
{
	if (tomoyo_current_screen != CCS_SCREEN_DOMAIN_LIST || current == EOF)
		return false;
	tomoyo_current_pid = 0;
	if (tomoyo_domain_sort_type) {
		tomoyo_current_pid = tomoyo_task_list[current].pid;
	} else if (tomoyo_initializer_source(dp, current)) {
		char *buf;
		int redirect_index;
		if (!may_refresh)
			return false;
		tomoyo_get();
		buf = tomoyo_shprintf(CCS_ROOT_NAME "%s",
			       strrchr(tomoyo_domain_name(dp, current), ' '));
		redirect_index = tomoyo_find_domain(dp, buf, false, false);
		tomoyo_put();
		if (redirect_index == EOF)
			return false;
		tomoyo_current_item_index[tomoyo_current_screen]
			= redirect_index - tomoyo_current_y[tomoyo_current_screen];
		while (tomoyo_current_item_index[tomoyo_current_screen] < 0) {
			tomoyo_current_item_index[tomoyo_current_screen]++;
			tomoyo_current_y[tomoyo_current_screen]--;
		}
		tomoyo_show_list(dp);
		return false;
	} else if (tomoyo_deleted_domain(dp, current)) {
		return false;
	}
	free(tomoyo_current_domain);
	if (tomoyo_domain_sort_type)
		tomoyo_current_domain = strdup(tomoyo_task_list[current].domain);
	else
		tomoyo_current_domain = strdup(tomoyo_domain_name(dp, current));
	if (!tomoyo_current_domain)
		tomoyo_out_of_memory();
	return true;
}

static int tomoyo_select_window(struct tomoyo_domain_policy *dp, const int current)
{
	move(0, 0);
	printw("Press one of below keys to switch window.\n\n");
	printw("e     <<< Exception Policy Editor >>>\n");
	printw("d     <<< Domain Transition Editor >>>\n");
	if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST && current != EOF &&
	    !tomoyo_initializer_source(dp, current) &&
	    !tomoyo_deleted_domain(dp, current))
		printw("a     <<< Domain Policy Editor >>>\n");
	printw("p     <<< Profile Editor >>>\n");
	printw("m     <<< Manager Policy Editor >>>\n");
	if (!tomoyo_offline_mode) {
		/* printw("i     <<< Interactive Enforcing Mode >>>\n"); */
		printw("u     <<< Memory Usage >>>\n");
	}
	printw("q     Quit this editor.\n");
	clrtobot();
	refresh();
	while (true) {
		int c = tomoyo_getch2();
		if (c == 'E' || c == 'e')
			return CCS_SCREEN_EXCEPTION_LIST;
		if (c == 'D' || c == 'd')
			return CCS_SCREEN_DOMAIN_LIST;
		if (c == 'A' || c == 'a')
			if (tomoyo_select_acl_window(dp, current, false))
				return CCS_SCREEN_ACL_LIST;
		if (c == 'P' || c == 'p')
			return CCS_SCREEN_PROFILE_LIST;
		if (c == 'M' || c == 'm')
			return CCS_SCREEN_MANAGER_LIST;
		if (!tomoyo_offline_mode) {
			/*
			if (c == 'I' || c == 'i')
				return CCS_SCREEN_QUERY_LIST;
			*/
			if (c == 'U' || c == 'u')
				return CCS_SCREEN_MEMINFO_LIST;
		}
		if (c == 'Q' || c == 'q')
			return CCS_MAXSCREEN;
		if (c == EOF)
			return CCS_MAXSCREEN;
	}
}

static void tomoyo_copy_mark_state(struct tomoyo_domain_policy *dp, const int current)
{
	int index;
	if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (tomoyo_domain_sort_type) {
			const u8 selected = tomoyo_task_list[current].selected;
			for (index = current; index < tomoyo_task_list_len; index++)
				tomoyo_task_list[index].selected = selected;
		} else {
			const u8 selected = dp->list_selected[current];
			if (tomoyo_deleted_domain(dp, current) ||
			    tomoyo_initializer_source(dp, current))
				return;
			for (index = current;
			     index < dp->list_len; index++) {
				if (tomoyo_deleted_domain(dp, index) ||
				    tomoyo_initializer_source(dp, index))
					continue;
				dp->list_selected[index] = selected;
			}
		}
	} else {
		const u8 selected = tomoyo_generic_acl_list[current].selected;
		for (index = current; index < tomoyo_generic_acl_list_count; index++)
			tomoyo_generic_acl_list[index].selected = selected;
	}
	tomoyo_show_list(dp);
}

static void tomoyo_copy_to_history(struct tomoyo_domain_policy *dp, const int current,
				struct tomoyo_readline_data *rl)
{
	const char *line;
	if (current == EOF)
		return;
	tomoyo_get();
	switch (tomoyo_current_screen) {
		u8 directive;
	case CCS_SCREEN_DOMAIN_LIST:
		line = tomoyo_domain_name(dp, current);
		break;
	case CCS_SCREEN_EXCEPTION_LIST:
	case CCS_SCREEN_ACL_LIST:
		directive = tomoyo_generic_acl_list[current].directive;
		line = tomoyo_shprintf("%s %s", tomoyo_directives[directive].alias,
				tomoyo_generic_acl_list[current].operand);
		break;
	case CCS_SCREEN_MEMINFO_LIST:
		line = NULL;
		break;
	default:
		line = tomoyo_shprintf("%s", tomoyo_generic_acl_list[current].operand);
	}
	rl->count = tomoyo_add_history(line, rl->history, rl->count, rl->max);
	tomoyo_put();
}

static int tomoyo_generic_list_loop(struct tomoyo_domain_policy *dp)
{
	static struct tomoyo_readline_data rl;
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
	if (tomoyo_current_screen == CCS_SCREEN_EXCEPTION_LIST) {
		tomoyo_policy_file = CCS_PROC_POLICY_EXCEPTION_POLICY;
		tomoyo_list_caption = "Exception Policy Editor";
	} else if (tomoyo_current_screen == CCS_SCREEN_ACL_LIST) {
		tomoyo_policy_file = CCS_PROC_POLICY_DOMAIN_POLICY;
		tomoyo_list_caption = "Domain Policy Editor";
	} else if (tomoyo_current_screen == CCS_SCREEN_QUERY_LIST) {
		tomoyo_policy_file = CCS_PROC_POLICY_QUERY;
		tomoyo_list_caption = "Interactive Enforcing Mode";
	} else if (tomoyo_current_screen == CCS_SCREEN_PROFILE_LIST) {
		tomoyo_policy_file = CCS_PROC_POLICY_PROFILE;
		tomoyo_list_caption = "Profile Editor";
	} else if (tomoyo_current_screen == CCS_SCREEN_MANAGER_LIST) {
		tomoyo_policy_file = CCS_PROC_POLICY_MANAGER;
		tomoyo_list_caption = "Manager Policy Editor";
	} else if (tomoyo_current_screen == CCS_SCREEN_MEMINFO_LIST) {
		tomoyo_policy_file = CCS_PROC_POLICY_MEMINFO;
		tomoyo_list_caption = "Memory Usage";
	} else {
		tomoyo_policy_file = CCS_PROC_POLICY_DOMAIN_POLICY;
		/* tomoyo_list_caption = "Domain Transition Editor"; */
	}
	tomoyo_current_item_index[tomoyo_current_screen]
		= saved_current_item_index[tomoyo_current_screen];
	tomoyo_current_y[tomoyo_current_screen] = saved_current_y[tomoyo_current_screen];
start:
	if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (tomoyo_domain_sort_type == 0) {
			tomoyo_read_domain_and_exception_policy(dp);
			tomoyo_adjust_cursor_pos(dp->list_len);
		} else {
			tomoyo_read_process_list(true);
			tomoyo_adjust_cursor_pos(tomoyo_task_list_len);
		}
	} else {
		tomoyo_read_generic_policy();
		tomoyo_adjust_cursor_pos(tomoyo_generic_acl_list_count);
	}
start2:
	tomoyo_show_list(dp);
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
		saved_current_item_index[tomoyo_current_screen]
			= tomoyo_current_item_index[tomoyo_current_screen];
		saved_current_y[tomoyo_current_screen] = tomoyo_current_y[tomoyo_current_screen];
		if (c == 'q' || c == 'Q')
			return CCS_MAXSCREEN;
		if ((c == '\r' || c == '\n') &&
		    tomoyo_current_screen == CCS_SCREEN_ACL_LIST)
			return CCS_SCREEN_DOMAIN_LIST;
		if (c == '\t') {
			if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST)
				return CCS_SCREEN_EXCEPTION_LIST;
			else
				return CCS_SCREEN_DOMAIN_LIST;
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
			tomoyo_show_list(dp);
			break;
		case KEY_UP:
			tomoyo_up_arrow_key(dp);
			break;
		case KEY_DOWN:
			tomoyo_down_arrow_key(dp);
			break;
		case KEY_PPAGE:
			tomoyo_page_up_key(dp);
			break;
		case KEY_NPAGE:
			tomoyo_page_down_key(dp);
			break;
		case ' ':
			tomoyo_select_item(dp, current);
			break;
		case 'c':
		case 'C':
			if (current == EOF)
				break;
			tomoyo_copy_mark_state(dp, current);
			tomoyo_show_list(dp);
			break;
		case 'f':
		case 'F':
			if (tomoyo_current_screen != CCS_SCREEN_MEMINFO_LIST)
				tomoyo_find_entry(dp, true, true, current, &rl);
			break;
		case 'p':
		case 'P':
			if (tomoyo_current_screen == CCS_SCREEN_MEMINFO_LIST)
				break;
			if (!rl.search_buffer[tomoyo_current_screen])
				tomoyo_find_entry(dp, true, false, current, &rl);
			else
				tomoyo_find_entry(dp, false, false, current, &rl);
			break;
		case 'n':
		case 'N':
			if (tomoyo_current_screen == CCS_SCREEN_MEMINFO_LIST)
				break;
			if (!rl.search_buffer[tomoyo_current_screen])
				tomoyo_find_entry(dp, true, true, current, &rl);
			else
				tomoyo_find_entry(dp, false, true, current, &rl);
			break;
		case 'd':
		case 'D':
			if (tomoyo_readonly_mode)
				break;
			switch (tomoyo_current_screen) {
			case CCS_SCREEN_DOMAIN_LIST:
				if (tomoyo_domain_sort_type)
					break;
			case CCS_SCREEN_EXCEPTION_LIST:
			case CCS_SCREEN_ACL_LIST:
			case CCS_SCREEN_MANAGER_LIST:
				tomoyo_delete_entry(dp, current);
				goto start;
			}
			break;
		case 'a':
		case 'A':
			if (tomoyo_readonly_mode)
				break;
			switch (tomoyo_current_screen) {
			case CCS_SCREEN_DOMAIN_LIST:
				if (tomoyo_domain_sort_type)
					break;
			case CCS_SCREEN_EXCEPTION_LIST:
			case CCS_SCREEN_ACL_LIST:
			case CCS_SCREEN_PROFILE_LIST:
			case CCS_SCREEN_MANAGER_LIST:
				tomoyo_add_entry(&rl);
				goto start;
			}
			break;
		case '\r':
		case '\n':
			if (tomoyo_select_acl_window(dp, current, true))
				return CCS_SCREEN_ACL_LIST;
			break;
		case 's':
		case 'S':
			if (tomoyo_readonly_mode)
				break;
			switch (tomoyo_current_screen) {
			case CCS_SCREEN_DOMAIN_LIST:
				tomoyo_set_profile(dp, current);
				goto start;
			case CCS_SCREEN_PROFILE_LIST:
				tomoyo_set_level(dp, current);
				goto start;
			case CCS_SCREEN_MEMINFO_LIST:
				tomoyo_set_quota(dp, current);
				goto start;
			}
			break;
		case 'r':
		case 'R':
			goto start;
		case KEY_LEFT:
			if (!tomoyo_max_eat_col[tomoyo_current_screen])
				break;
			tomoyo_max_eat_col[tomoyo_current_screen]--;
			goto start2;
		case KEY_RIGHT:
			tomoyo_max_eat_col[tomoyo_current_screen]++;
			goto start2;
		case KEY_HOME:
			tomoyo_max_eat_col[tomoyo_current_screen] = 0;
			goto start2;
		case KEY_END:
			tomoyo_max_eat_col[tomoyo_current_screen] = tomoyo_max_col;
			goto start2;
		case KEY_IC:
			tomoyo_copy_to_history(dp, current, &rl);
			break;
		case 'o':
		case 'O':
			if (tomoyo_current_screen == CCS_SCREEN_ACL_LIST ||
			    tomoyo_current_screen ==
			    CCS_SCREEN_EXCEPTION_LIST) {
				tomoyo_editpolicy_try_optimize(dp, current,
							    tomoyo_current_screen);
				tomoyo_show_list(dp);
			}
			break;
		case '@':
			if (tomoyo_current_screen == CCS_SCREEN_ACL_LIST) {
				tomoyo_acl_sort_type = (tomoyo_acl_sort_type + 1) % 2;
				goto start;
			} else if (tomoyo_current_screen == CCS_SCREEN_PROFILE_LIST) {
				tomoyo_profile_sort_type = (tomoyo_profile_sort_type + 1) % 2;
				goto start;
			} else if (tomoyo_current_screen == CCS_SCREEN_DOMAIN_LIST &&
				   !tomoyo_offline_mode) {
				tomoyo_domain_sort_type = (tomoyo_domain_sort_type + 1) % 2;
				goto start;
			}
			break;
		case 'w':
		case 'W':
			return tomoyo_select_window(dp, current);
		case '?':
			if (tomoyo_show_command_key(tomoyo_current_screen, tomoyo_readonly_mode))
				goto start;
			return CCS_MAXSCREEN;
		}
	}
}

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

int main(int argc, char *argv[])
{
	struct tomoyo_domain_policy dp = { NULL, 0, NULL };
	struct tomoyo_domain_policy bp = { NULL, 0, NULL };
	memset(tomoyo_current_y, 0, sizeof(tomoyo_current_y));
	memset(tomoyo_current_item_index, 0, sizeof(tomoyo_current_item_index));
	memset(tomoyo_list_item_count, 0, sizeof(tomoyo_list_item_count));
	memset(tomoyo_max_eat_col, 0, sizeof(tomoyo_max_eat_col));
	if (argc > 1) {
		int i;
		for (i = 1; i < argc; i++) {
			char *ptr = argv[i];
			char *cp = strchr(ptr, ':');
			if (*ptr == '/') {
				if (tomoyo_network_mode || tomoyo_offline_mode)
					goto usage;
				tomoyo_policy_dir = ptr;
				tomoyo_offline_mode = true;
			} else if (cp) {
				*cp++ = '\0';
				if (tomoyo_network_mode || tomoyo_offline_mode)
					goto usage;
				tomoyo_network_ip = inet_addr(ptr);
				tomoyo_network_port = htons(atoi(cp));
				tomoyo_network_mode = true;
				if (!tomoyo_check_remote_host())
					return 1;
			} else if (!strcmp(ptr, "e"))
				tomoyo_current_screen = CCS_SCREEN_EXCEPTION_LIST;
			else if (!strcmp(ptr, "d"))
				tomoyo_current_screen = CCS_SCREEN_DOMAIN_LIST;
			else if (!strcmp(ptr, "p"))
				tomoyo_current_screen = CCS_SCREEN_PROFILE_LIST;
			else if (!strcmp(ptr, "m"))
				tomoyo_current_screen = CCS_SCREEN_MANAGER_LIST;
			else if (!strcmp(ptr, "u"))
				tomoyo_current_screen = CCS_SCREEN_MEMINFO_LIST;
			else if (!strcmp(ptr, "readonly"))
				tomoyo_readonly_mode = true;
			else if (sscanf(ptr, "refresh=%u", &tomoyo_refresh_interval)
				 != 1) {
usage:
				printf("Usage: %s [e|d|p|m|u] [readonly] "
				       "[refresh=interval] "
				       "[{policy_dir|remote_ip:remote_port}]\n",
				       argv[0]);
				return 1;
			}
		}
	}
	tomoyo_editpolicy_init_keyword_map();
	if (tomoyo_offline_mode) {
		int fd[2] = { EOF, EOF };
		if (chdir(tomoyo_policy_dir)) {
			printf("Directory %s doesn't exist.\n",
			       tomoyo_policy_dir);
			return 1;
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
		tomoyo_copy_file(CCS_DISK_POLICY_EXCEPTION_POLICY,
			      CCS_PROC_POLICY_EXCEPTION_POLICY);
		tomoyo_copy_file(CCS_DISK_POLICY_DOMAIN_POLICY, CCS_PROC_POLICY_DOMAIN_POLICY);
		tomoyo_copy_file(CCS_DISK_POLICY_PROFILE, CCS_PROC_POLICY_PROFILE);
		tomoyo_copy_file(CCS_DISK_POLICY_MANAGER, CCS_PROC_POLICY_MANAGER);
	} else if (!tomoyo_network_mode) {
		tomoyo_mount_securityfs();
		if (chdir(CCS_PROC_POLICY_DIR)) {
			fprintf(stderr,
				"You can't use this editor for this kernel.\n");
			return 1;
		}
		if (!tomoyo_readonly_mode) {
			const int fd1 = tomoyo_open2(CCS_PROC_POLICY_EXCEPTION_POLICY,
						  O_RDWR);
			const int fd2 = tomoyo_open2(CCS_PROC_POLICY_DOMAIN_POLICY,
						  O_RDWR);
			if ((fd1 != EOF && write(fd1, "", 0) != 0) ||
			    (fd2 != EOF && write(fd2, "", 0) != 0)) {
				fprintf(stderr,
					"You need to register this program to "
					"%s to run this program.\n",
					CCS_PROC_POLICY_MANAGER);
				return 1;
			}
			close(fd1);
			close(fd2);
		}
	}
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
	while (tomoyo_current_screen < CCS_MAXSCREEN) {
		tomoyo_resize_window();
		tomoyo_current_screen = tomoyo_generic_list_loop(&dp);
	}
	alarm(0);
	clear();
	move(0, 0);
	refresh();
	endwin();
	if (tomoyo_offline_mode && !tomoyo_readonly_mode) {
		time_t now = time(NULL);
		const char *filename = tomoyo_make_filename("exception_policy", now);
		if (tomoyo_save_to_file(CCS_PROC_POLICY_EXCEPTION_POLICY, filename)) {
			if (tomoyo_identical_file("exception_policy.conf",
						  filename)) {
				unlink(filename);
			} else {
				unlink("exception_policy.conf");
				symlink(filename, "exception_policy.conf");
			}
		}
		tomoyo_clear_domain_policy(&dp);
		filename = tomoyo_make_filename("domain_policy", now);
		if (tomoyo_save_to_file(CCS_PROC_POLICY_DOMAIN_POLICY, filename)) {
			if (tomoyo_identical_file("domain_policy.conf", filename)) {
				unlink(filename);
			} else {
				unlink("domain_policy.conf");
				symlink(filename, "domain_policy.conf");
			}
		}
		filename = tomoyo_make_filename("profile", now);
		if (tomoyo_save_to_file(CCS_PROC_POLICY_PROFILE, filename)) {
			if (tomoyo_identical_file("profile.conf", filename)) {
				unlink(filename);
			} else {
				unlink("profile.conf");
				symlink(filename, "profile.conf");
			}
		}
		filename = tomoyo_make_filename("manager", now);
		if (tomoyo_save_to_file(CCS_PROC_POLICY_MANAGER, filename)) {
			if (tomoyo_identical_file("manager.conf", filename)) {
				unlink(filename);
			} else {
				unlink("manager.conf");
				symlink(filename, "manager.conf");
			}
		}
	}
	tomoyo_clear_domain_policy(&bp);
	tomoyo_clear_domain_policy(&dp);
	return 0;
}
