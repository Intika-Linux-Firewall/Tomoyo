/*
 * editpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 2.5.0+   2017/01/02
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

/* Window information */
static struct window {
	/* Domain policy. */
	struct domain_policy dp;
	/* Policy directory. */
	const char *policy_dir;
	/* Policy file's name. */
	const char *policy_file;
	/*
	 * Array of "reset_domain"/"no_reset_domain"/"initialize_domain"/
	 * "no_initialize_domain"/"keep_domain"/"no_keep_domain" entries.
	 */
	struct transition_entry *transition_list;
	/* Structure for holding domain transition preference. */
	struct transition_preference *preference_list;
	/*
	 * List of
	 * "task manual_domain_transition"/"auto_domain_transition=" part.
	 */
	char **jump_list;
	/* Last error message. */
	char *last_error;
	/* Caption of the current screen. */
	const char *caption;
	/* Currently selected domain. */
	char *current_domain;
	/* Currently selected PID. */
	unsigned int current_pid;
	/* Number of domain jump source domains. */
	int unnumbered_domains;
	/* Length of transition_list array. */
	int transition_list_len;
	/* Length of preference_list array. */
	int preference_list_len;
	/* Length of jump_list array. */
	int jump_list_len;
	/* Width of CUI screen. */
	int width;
	/* Height of CUI screen. */
	int height;
	/* Number of entries available on current screen. */
	int list_items;
	/* Lines available for displaying ACL entries. */
	int body_lines;
	/* Columns to shift. */
	int eat_col;
	/* Max columns. */
	int max_col;
	/* Refresh interval in second. 0 means no auto refresh. */
	unsigned int refresh_interval;
	/* Previously active screen's index. */
	enum screen_type previous_screen;
	/* Sort ACL by operand first? */
	_Bool sort_acl;
	/* Sort profiles by value? */
	_Bool sort_profile;
	/*
	 * Domain screen is dealing with process list rather than domain list?
	 */
	_Bool show_tasklist;
	/* Start from the first line when showing ACL screen? */
	_Bool no_restore_cursor;
	_Bool force_move_cursor;
	/* Need to reload the screen due to auto refresh? */
	_Bool need_reload;
	/* Use ccs-editpolicy-agent program? */
	_Bool offline_mode;
	/* Use readonly mode? */
	_Bool readonly_mode;
} w;

/* Cursor info for CUI screen. */
struct ccs_screen screen[MAX_SCREEN_TYPE] = { };
/* Currently active screen's index. */
enum screen_type active = SCREEN_DOMAIN_LIST;
/* Currently loaded policy. */
struct policy p;
/* Namespace to use. */
const struct ccs_path_info *current_ns = NULL;

/* Readline history. */
static struct ccs_readline_data rl = { };

/* Domain transition coltrol keywords. */
static const char *transition_type[MAX_TRANSITION_TYPE] = {
	[TRANSITION_RESET]         = "reset_domain ",
	[TRANSITION_NO_RESET]      = "no_reset_domain ",
	[TRANSITION_INITIALIZE]    = "initialize_domain ",
	[TRANSITION_NO_INITIALIZE] = "no_initialize_domain ",
	[TRANSITION_KEEP]          = "keep_domain ",
	[TRANSITION_NO_KEEP]       = "no_keep_domain ",
};

static _Bool is_deleted_domain(const int index);
static _Bool is_jump_source(const int index);
static _Bool is_jump_target(const int index);
static _Bool is_keeper_domain(const int index);
static _Bool is_unreachable_domain(const int index);
static _Bool select_item(void);
static _Bool show_command_key(const enum screen_type screen,
			      const _Bool readonly);
static const char *shift(const char *str);
static const char *get_last_name(const int index);
static const struct transition_entry *find_transition
(const struct ccs_path_info *ns, const char *domainname, const char *program);
static enum screen_type generic_list_loop(void);
static enum screen_type select_window(void);
static FILE *editpolicy_open_write(const char *filename);
static int add_address_group(const char *group_name, const char *member_name);
static int add_address_group_policy(char *data);
static int add_number_group(const char *group_name, const char *member_name);
static int add_number_group_policy(char *data);
static int add_path_group(const struct ccs_path_info *ns,
			  const char *group_name, const char *member_name);
static int add_path_group_policy(const struct ccs_path_info *ns, char *data);
static int add_transition_entry(const struct ccs_path_info *ns,
				const char *domainname, const char *program,
				const enum transition_type type);
static int add_transition_policy(const struct ccs_path_info *ns, char *data,
				 const enum transition_type type);
static int count_domainlist(void);
static int count_generic(void);
static int count_tasklist(void);
static int domain_compare(const void *a, const void *b);
static int generic_compare(const void *a, const void *b);
static int profile_compare(const void *a, const void *b);
static int show_acl_line(const int index, const int list_indent);
static int show_domain_line(const int index);
static int show_literal_line(const int index);
static int show_profile_line(const int index);
static int show_stat_line(const int index);
static int string_compare(const void *a, const void *b);
static void add_acl_group_policy(const int group, const char *data);
static void add_entry(void);
static void adjust_cursor_pos(const int item_count);
static void assign_djs(const struct ccs_path_info *ns, const char *domainname,
		       const char *program);
static void copy_file(const char *source, const char *dest);
static void delete_entry(void);
static void down_arrow_key(void);
static void editpolicy_clear_groups(void);
static void find_entry(const _Bool input, const _Bool forward);
static void page_down_key(void);
static void page_up_key(void);
static void read_domain_and_exception_policy(void);
static void read_generic_policy(void);
static void resize_window(void);
static void set_cursor_pos(const int index);
static void set_level(void);
static void set_profile(void);
static void set_quota(void);
static void show_current(void);
static void show_list(void);
static void sigalrm_handler(int sig);
static void up_arrow_key(void);

#define ccs_alloc(ptr, size, count)					\
	({								\
		ptr = ccs_realloc((ptr), (size) * ((count) + 1));	\
		memset(&ptr[(count)], 0, size);				\
		&ptr[(count)++];					\
	})

/**
 * find_domain - Find a domain by name and other attributes.
 *
 * @domainname: Name of domain to find.
 * @target:     Name of target to find. Maybe NULL.
 * @is_dd:      True if the domain is marked as deleted, false otherwise.
 *
 * Returns index number (>= 0) if found, EOF otherwise.
 */
static int find_domain(const char *domainname, const char *target,
		       const _Bool is_dd)
{
	int i;
	for (i = 0; i < w.dp.list_len; i++) {
		const struct ccs_domain *ptr = &w.dp.list[i];
		if (ptr->is_dd == is_dd &&
		    ((!ptr->target && !target) ||
		     (ptr->target && target &&
		      !strcmp(ptr->target->name, target))) &&
		    !strcmp(ptr->domainname->name, domainname))
			return i;
	}
	return EOF;
}

/**
 * find_domain_by_name - Find a domain by name.
 *
 * @domainname: Name of domain to find.
 *
 * Returns pointer to "struct ccs_domain" if found, NULL otherwise.
 */
static struct ccs_domain *find_domain_by_name(const char *domainname)
{
	int i;
	for (i = 0; i < w.dp.list_len; i++) {
		struct ccs_domain *ptr = &w.dp.list[i];
		if (!ptr->target && !strcmp(ptr->domainname->name, domainname))
			return ptr;
	}
	return NULL;
}

/**
 * assign_domain - Create a domain by name and other attributes.
 *
 * @domainname: Name of domain to find.
 * @target:     Name of target domain if the domain acts as domain jump source,
 *              NULL otherwise.
 * @is_dd:      True if the domain is marked as deleted, false otherwise.
 *
 * Returns index number (>= 0) if created or already exists, abort otherwise.
 */
static int assign_domain(const char *domainname, const char *target,
			 const _Bool is_dd)
{
	struct ccs_domain *ptr;
	int index = find_domain(domainname, target, is_dd);
	if (index >= 0)
		return index;
	ptr = ccs_alloc(w.dp.list, sizeof(*ptr), w.dp.list_len);
	ptr->domainname = ccs_savename(domainname);
	if (target)
		ptr->target = ccs_savename(target);
	ptr->is_dd = is_dd;
	return w.dp.list_len - 1;
}

/**
 * add_string_entry - Add string entry to a domain.
 *
 * @entry: String to add.
 * @index: Index in the @dp array.
 *
 * Returns 0 if successfully added or already exists, -EINVAL otherwise.
 */
static int add_string_entry(const char *entry, const int index)
{
	const struct ccs_path_info **acl_ptr;
	int acl_count;
	const struct ccs_path_info *cp;
	int i;
	if (index < 0 || index >= w.dp.list_len) {
		fprintf(stderr, "ERROR: domain is out of range.\n");
		return -EINVAL;
	}
	if (!entry || !*entry)
		return -EINVAL;
	cp = ccs_savename(entry);

	acl_ptr = w.dp.list[index].string_ptr;
	acl_count = w.dp.list[index].string_count;

	/* Check for the same entry. */
	for (i = 0; i < acl_count; i++)
		/* Faster comparison, for they are ccs_savename'd. */
		if (cp == acl_ptr[i])
			return 0;

	*ccs_alloc(w.dp.list[index].string_ptr, sizeof(*acl_ptr),
		   w.dp.list[index].string_count) = cp;
	return 0;
}

/**
 * clear_domain_policy - Clean up domain policy.
 *
 * Returns nothing.
 */
static void clear_domain_policy(void)
{
	int index;
	for (index = 0; index < w.dp.list_len; index++) {
		free(w.dp.list[index].string_ptr);
		w.dp.list[index].string_ptr = NULL;
		w.dp.list[index].string_count = 0;
	}
	free(w.dp.list);
	w.dp.list = NULL;
	w.dp.list_len = 0;
}

/**
 * is_same_namespace - Check namespace.
 *
 * @domain: Domainname.
 * @ns:     Namespace.
 *
 * Returns true if same namespace, false otherwise.
 */
static _Bool is_same_namespace(const char *domain,
			       const struct ccs_path_info *ns)
{
	return !strncmp(domain, ns->name, ns->total_len) &&
		(domain[ns->total_len] == ' ' || !domain[ns->total_len]);
}

/**
 * is_current_namespace - Check namespace.
 *
 * @line: Line to check namespace.
 *
 * Returns true if this line deals current namespace, false otherwise.
 */
static _Bool is_current_namespace(const char *line)
{
	return is_same_namespace(line, current_ns);
}

/**
 * copy_file - Copy local file to local or remote file.
 *
 * @source: Local file.
 * @dest:   Local or remote file name.
 *
 * Returns nothing.
 */
static void copy_file(const char *source, const char *dest)
{
	FILE *fp_in = fopen(source, "r");
	FILE *fp_out = fp_in ? editpolicy_open_write(dest) : NULL;
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
 * get_ns - Get namespace component from domainname.
 *
 * @domainname: A domainname.
 *
 * Returns the namespace component of @domainname.
 */
static const struct ccs_path_info *get_ns(const char *domainname)
{
	const struct ccs_path_info *ns;
	char *line = ccs_strdup(domainname);
	char *cp;
	cp = strchr(line, ' ');
	if (cp)
		*cp = '\0';
	ns = ccs_savename(line);
	free(line);
	return ns;
}

/**
 * get_last_word - Get last component of a line.
 *
 * @line: A line of words.
 *
 * Returns the last component of the line.
 */
static const char *get_last_word(const char *line)
{
	const char *cp = strrchr(line, ' ');
	if (cp)
		return cp + 1;
	return line;
}

/**
 * get_last_name - Get last component of a domainname.
 *
 * @index: Index in the domain policy.
 *
 * Returns the last component of the domainname.
 */
static const char *get_last_name(const int index)
{
	return get_last_word(w.dp.list[index].domainname->name);
}

/**
 * count_domainlist - Count non-zero elements in an array.
 *
 * Returns number of non-zero elements.
 */
static int count_domainlist(void)
{
	int i;
	int c = 0;
	for (i = 0; i < w.dp.list_len; i++)
		if (w.dp.list_selected[i])
			c++;
	return c;
}

/**
 * count_generic - Count non-zero elements in a "struct generic_entry" array.
 *
 * Returns number of non-zero elements.
 */
static int count_generic(void)
{
	int i;
	int c = 0;
	for (i = 0; i < p.generic_len; i++)
		if (p.generic[i].selected)
			c++;
	return c;
}

/**
 * count_tasklist - Count non-zero elements in a "struct ccs_task_entry" array.
 *
 * Returns number of non-zero elements.
 */
static int count_tasklist(void)
{
	int i;
	int c = 0;
	for (i = 0; i < ccs_task_list_len; i++)
		if (ccs_task_list[i].selected)
			c++;
	return c;
}

/**
 * is_keeper_domain - Check whether the given domain is marked as keeper or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is marked as "keep_domain",
 * false otherwise.
 */
static _Bool is_keeper_domain(const int index)
{
	return w.dp.list[index].is_dk;
}

/**
 * is_jump_source - Check whether the given domain is marked as jump source or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is marked as domain jump source,
 * false otherwise.
 */
static _Bool is_jump_source(const int index)
{
	return w.dp.list[index].target != NULL;
}

/**
 * is_jump_target - Check whether the given domain is marked as jump target or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is a domain jump target, false otherwise.
 */
static _Bool is_jump_target(const int index)
{
	return w.dp.list[index].is_djt;
}

/**
 * is_unreachable_domain - Check whether the given domain is marked as unreachable or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is unreachable, false otherwise.
 */
static _Bool is_unreachable_domain(const int index)
{
	return w.dp.list[index].is_du;
}

/**
 * is_deleted_domain - Check whether the given domain is marked as deleted or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is marked as deleted, false otherwise.
 */
static _Bool is_deleted_domain(const int index)
{
	return w.dp.list[index].is_dd;
}

/**
 * string_compare - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int string_compare(const void *a, const void *b)
{
	const struct generic_entry *a0 = (struct generic_entry *) a;
	const struct generic_entry *b0 = (struct generic_entry *) b;
	const char *a1 = a0->operand;
	const char *b1 = b0->operand;
	return strcmp(a1, b1);
}

/**
 * add_transition_policy - Add "reset_domain"/"no_reset_domain"/"initialize_domain"/"no_initialize_domain"/"keep_domain"/"no_keep_domain" entries.
 *
 * @ns:   Pointer to "const struct ccs_path_info".
 * @data: Line to parse.
 * @type: One of values in "enum transition_type".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int add_transition_policy
(const struct ccs_path_info *ns, char *data, const enum transition_type type)
{
	char *domainname = strstr(data, " from ");
	if (domainname) {
		*domainname = '\0';
		domainname += 6;
	} else if (type == TRANSITION_NO_KEEP || type == TRANSITION_KEEP) {
		domainname = data;
		data = NULL;
	}
	return add_transition_entry(ns, domainname, data, type);
}

/**
 * add_path_group_policy - Add "path_group" entry.
 *
 * @ns:   Pointer to "const struct ccs_path_info".
 * @data: Line to parse.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int add_path_group_policy(const struct ccs_path_info *ns, char *data)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return add_path_group(ns, data, cp);
}

/**
 * add_number_group_policy - Add "number_group" entry.
 *
 * @data: Line to parse.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int add_number_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return add_number_group(data, cp);
}

/**
 * add_address_group_policy - Add "address_group" entry.
 *
 * @data: Line to parse.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int add_address_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return add_address_group(data, cp);
}

/**
 * add_acl_group_policys - Add "acl_group" entry.
 *
 * @group: Group number.
 * @data:  Line to parse.
 *
 * Returns nothing.
 */
static void add_acl_group_policy(const int group, const char *data)
{
	char **ptr = p.acl_group[group];
	const int len = p.acl_group_len[group];
	int i;
	for (i = 0; i < len; i++)
		if (!strcmp(ptr[i], data))
			return;
	*ccs_alloc(p.acl_group[group], sizeof(char *),
		   p.acl_group_len[group]) = ccs_strdup(data);
}

/**
 * editpolicy_clear_groups - Clear path_group/number_group/address_group/acl_group for reloading policy.
 *
 * Returns nothing.
 */
static void editpolicy_clear_groups(void)
{
	int i;
	for (i = 0; i < 256; i++)
		while (p.acl_group_len[i])
			free(p.acl_group[i][--p.acl_group_len[i]]);
	while (p.path_group_len)
		free(p.path_group[--p.path_group_len].
		     member_name);
	while (p.number_group_len)
		free(p.number_group[--p.number_group_len].member_name);
	while (p.address_group_len)
		free(p.address_group[--p.address_group_len].member_name);
}

/**
 * find_path_group_ns - Find "path_group" entry.
 *
 * @ns:         Pointer to "const struct ccs_path_info".
 * @group_name: Name of path group.
 *
 * Returns pointer to "struct path_group" if found, NULL otherwise.
 */
struct path_group *find_path_group_ns
(const struct ccs_path_info *ns, const char *group_name)
{
	int i;
	for (i = 0; i < p.path_group_len; i++)
		if (!ccs_pathcmp(p.path_group[i].ns, ns) &&
		    !strcmp(group_name, p.path_group[i].group_name->name))
			return &p.path_group[i];
	return NULL;
}

/**
 * assign_djs - Assign domain jump source domain.
 *
 * @ns:         Pointer to "const struct ccs_path_info".
 * @domainname: Domainname.
 * @program:    Program name.
 */
static void assign_djs(const struct ccs_path_info *ns,
		       const char *domainname, const char *program)
{
	const struct transition_entry *d_t =
		find_transition(ns, domainname, program);
	if (!d_t)
		return;
	if (d_t->type == TRANSITION_INITIALIZE ||
	    d_t->type == TRANSITION_RESET) {
		char *line;
		char *cp;
		ccs_get();
		if (d_t->type == TRANSITION_INITIALIZE)
			line = ccs_shprintf("%s %s", domainname, program);
		else
			line = ccs_shprintf("%s <%s>", domainname, program);
		ccs_normalize_line(line);
		cp = ccs_strdup(line);
		if (d_t->type == TRANSITION_INITIALIZE)
			line = ccs_shprintf("%s %s", ns->name, program);
		else
			line = ccs_shprintf("<%s>", program);
		assign_domain(cp, line, false);
		free(cp);
		ccs_put();
	}
}

/**
 * domain_compare - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int domain_compare(const void *a, const void *b)
{
	const struct ccs_domain *a0 = a;
	const struct ccs_domain *b0 = b;
	char *name1;
	char *name2;
	char *line;
	char *cp;
	int k;
	if (!a0->target && !b0->target)
		return strcmp(a0->domainname->name, b0->domainname->name);
	name1 = ccs_strdup(a0->domainname->name);
	if (a0->target) {
		cp = strrchr(name1, ' ');
		if (cp)
			*cp = '\0';
	}
	name2 = ccs_strdup(b0->domainname->name);
	if (b0->target) {
		cp = strrchr(name2, ' ');
		if (cp)
			*cp = '\0';
	}
	k = strcmp(name1, name2);
	if (k)
		goto done;
	ccs_get();
	if (a0->target)
		line = ccs_shprintf("%s %s", name1, a0->target->name);
	else
		line = ccs_shprintf("%s", name1);
	free(name1);
	name1 = ccs_strdup(line);
	if (b0->target)
		line = ccs_shprintf("%s %s", name2, b0->target->name);
	else
		line = ccs_shprintf("%s", name2);
	free(name2);
	name2 = ccs_strdup(line);
	ccs_put();
	k = strcmp(name1, name2);
done:
	free(name1);
	free(name2);
	return k;
}

/**
 * find_target_domain - Find the domain jump target domain.
 *
 * @index: Index in the domain policy.
 *
 * Returns index of the domain if found in a current namespace,
 * -2 if found in a different namespace, EOF otherwise.
 */
static int find_target_domain(const int index)
{
	const char *cp = w.dp.list[index].target->name;
	if (!is_current_namespace(cp)) {
		if (w.dp.list[index].is_du)
			return EOF;
		return -2;
	}
	return find_domain(cp, NULL, false);
}

/**
 * show_domain_line - Show a line of the domain transition tree.
 *
 * @index: Index in the domain policy.
 *
 * Returns length of the printed line.
 */
static int show_domain_line(const int index)
{
	int tmp_col = 0;
	const struct transition_entry *transition;
	char *line;
	const char *sp;
	const int number = w.dp.list[index].number;
	int redirect_index;
	const bool is_djs = is_jump_source(index);
	const bool is_deleted = is_deleted_domain(index);
	if (number >= 0)
		printw("%c%4d:%3u %c%c%c ", w.dp.list_selected[index] ? '&' :
		       ' ', number, w.dp.list[index].profile,
		       is_keeper_domain(index) ? '#' : ' ',
		       is_jump_target(index) ? '*' : ' ',
		       is_unreachable_domain(index) ? '!' : ' ');
	else if (w.dp.list[index].is_djt)
		printw("          %c*%c ",
		       is_keeper_domain(index) ? '#' : ' ',
		       is_unreachable_domain(index) ? '!' : ' ');
	else
		printw("              ");
	tmp_col += 14;
	sp = w.dp.list[index].domainname->name;
	while (true) {
		const char *cp = strchr(sp, ' ');
		if (!cp)
			break;
		printw("%s", shift("    "));
		tmp_col += 4;
		sp = cp + 1;
	}
	if (is_djs) {
		printw("%s", shift("=> "));
		tmp_col += 3;
		sp = w.dp.list[index].target->name;
	}
	if (is_deleted) {
		printw("%s", shift("( "));
		tmp_col += 2;
	}
	printw("%s", shift(sp));
	tmp_col += strlen(sp);
	if (is_deleted) {
		printw("%s", shift(" )"));
		tmp_col += 2;
	}
	transition = w.dp.list[index].d_t;
	if (!transition || is_djs)
		goto no_transition_control;
	ccs_get();
	line = ccs_shprintf(" ( %s%s from %s )",
			    transition_type[transition->type],
			    transition->program ?
			    transition->program->name : "any",
			    transition->domainname ?
			    transition->domainname->name : "any");
	printw("%s", shift(line));
	tmp_col += strlen(line);
	ccs_put();
	goto done;
no_transition_control:
	if (!is_djs)
		goto done;
	ccs_get();
	redirect_index = find_target_domain(index);
	if (redirect_index >= 0)
		line = ccs_shprintf(" ( -> %d )",
				    w.dp.list[redirect_index].number);
	else if (redirect_index == EOF)
		line = ccs_shprintf(" ( -> Not Found )");
	else
		line = ccs_shprintf(" ( -> Namespace jump )");
	printw("%s", shift(line));
	tmp_col += strlen(line);
	ccs_put();
done:
	return tmp_col;
}

/**
 * show_acl_line - Print an ACL line.
 *
 * @index:       Index in the generic list.
 * @list_indent: Indent size.
 *
 * Returns length of the printed line.
 */
static int show_acl_line(const int index, const int list_indent)
{
	const enum directive_type directive =
		p.generic[index].directive;
	const char *cp1 = directive_map[directive].alias;
	const char *cp2 = p.generic[index].operand;
	int len = list_indent - directive_map[directive].alias_len;
	printw("%c%4d: %s ",
	       p.generic[index].selected ? '&' : ' ',
	       index, shift(cp1));
	while (len-- > 0)
		printw("%s", shift(" "));
	printw("%s", shift(cp2));
	return strlen(cp1) + strlen(cp2) + 8 + list_indent;
}

/**
 * show_profile_line - Print a profile line.
 *
 * @index: Index in the generic list.
 *
 * Returns length of the printed line.
 */
static int show_profile_line(const int index)
{
	const char *cp = p.generic[index].operand;
	const u16 profile = p.generic[index].directive;
	char number[8] = "";
	if (profile <= 256)
		snprintf(number, sizeof(number) - 1, "%3u-", profile);
	printw("%c%4d: %s", p.generic[index].selected ? '&' : ' ',
	       index, shift(number));
	printw("%s ", shift(cp));
	return strlen(number) + strlen(cp) + 8;
}

/**
 * show_literal_line - Print a literal line.
 *
 * @index: Index in the generic list.
 *
 * Returns length of the printed line.
 */
static int show_literal_line(const int index)
{
	const char *cp = p.generic[index].operand;
	printw("%c%4d: %s ",
	       p.generic[index].selected ? '&' : ' ',
	       index, shift(cp));
	return strlen(cp) + 8;
}

/**
 * show_stat_line - Print a statistics line.
 *
 * @index: Index in the generic list.
 *
 * Returns length of the printed line.
 */
static int show_stat_line(const int index)
{
	char *line;
	unsigned int now;
	ccs_get();
	line = ccs_shprintf("%s", p.generic[index].operand);
	if (line[0])
		printw("%s", shift(line));
	now = strlen(line);
	ccs_put();
	return now;
}

/**
 * show_command_key - Print help screen.
 *
 * @screen:   Currently selected screen.
 * @readonly: True if readonly_mopde, false otherwise.
 *
 * Returns true to continue, false to quit.
 */
static _Bool show_command_key(const enum screen_type screen,
			      const _Bool readonly)
{
	int c;
	clear();
	printw("Commands available for this screen are:\n\n");
	printw("Q/q        Quit this editor.\n");
	printw("R/r        Refresh to the latest information.\n");
	switch (screen) {
	case SCREEN_STAT_LIST:
		break;
	default:
		printw("F/f        Find first.\n");
		printw("N/n        Find next.\n");
		printw("P/p        Find previous.\n");
	}
	printw("W/w        Switch to selected screen.\n");
	/* printw("Tab        Switch to next screen.\n"); */
	switch (screen) {
	case SCREEN_STAT_LIST:
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
	case SCREEN_NS_LIST:
		if (!readonly)
			printw("A/a        Add a new namespace.\n");
		break;
	case SCREEN_DOMAIN_LIST:
		if (w.show_tasklist) {
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
	case SCREEN_STAT_LIST:
		if (!readonly)
			printw("S/s        Set memory quota of selected "
			       "items.\n");
		break;
	case SCREEN_PROFILE_LIST:
		if (!readonly)
			printw("S/s        Set mode of selected items.\n");
		break;
	default:
		break;
	}
	switch (screen) {
	case SCREEN_EXCEPTION_LIST:
	case SCREEN_ACL_LIST:
	case SCREEN_MANAGER_LIST:
		if (!readonly) {
			printw("A/a        Add a new entry.\n");
			printw("D/d        Delete selected entries.\n");
		}
	default:
		break;
	}
	switch (screen) {
	case SCREEN_PROFILE_LIST:
		if (!readonly)
			printw("A/a        Define a new profile.\n");
	default:
		break;
	}
	switch (screen) {
	case SCREEN_ACL_LIST:
		printw("O/o        Set selection state to other entries "
		       "included in an entry at the cursor position.\n");
		/* Fall through. */
	case SCREEN_PROFILE_LIST:
		printw("@          Switch sort type.\n");
		break;
	case SCREEN_DOMAIN_LIST:
		if (!w.offline_mode)
			printw("@          Switch domain/process list.\n");
	default:
		break;
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

/**
 * set_error - Set error line's caption.
 *
 * @filename: Filename to print. Maybe NULL.
 *
 * Returns nothing.
 */
static void set_error(const char *filename)
{
	if (filename) {
		const int len = strlen(filename) + 128;
		w.last_error = ccs_realloc2(w.last_error, len);
		snprintf(w.last_error, len - 1, "Can't open %s .", filename);
	} else {
		free(w.last_error);
		w.last_error = NULL;
	}
}

/**
 * editpolicy_open_write - Wrapper for ccs_open_write().
 *
 * @filename: File to open for writing.
 *
 * Returns pointer to "FILE" on success, NULL otherwise.
 *
 * Since CUI policy editor screen provides a line for printing error message,
 * this function sets error line if failed. Also, this function returns NULL if
 * readonly mode.
 */
static FILE *editpolicy_open_write(const char *filename)
{
	FILE *fp = ccs_open_write(filename);
	if (!fp)
		set_error(filename);
	return fp;
}

/**
 * editpolicy_open_read - Wrapper for ccs_open_read().
 *
 * @filename: File to open for reading.
 *
 * Returns pointer to "FILE" on success, NULL otherwise.
 *
 * Since CUI policy editor screen provides a line for printing error message,
 * this function sets error line if failed.
 */
static FILE *editpolicy_open_read(const char *filename)
{
	FILE *fp = ccs_open_read(filename);
	if (!fp)
		set_error(filename);
	return fp;
}

/**
 * open2 - Wrapper for open().
 *
 * @filename: File to open.
 * @mode:     Flags to passed to open().
 *
 * Returns file descriptor on success, EOF otherwise.
 *
 * Since CUI policy editor screen provides a line for printing error message,
 * this function sets error line if failed.
 */
static int open2(const char *filename, int mode)
{
	const int fd = open(filename, mode);
	if (fd == EOF && errno != ENOENT)
		set_error(filename);
	return fd;
}

/**
 * sigalrm_handler - Callback routine for timer interrupt.
 *
 * @sig: Signal number. Not used.
 *
 * Returns nothing.
 *
 * This function is called when w.refresh_interval is non-zero. This function
 * marks current screen to reload. Also, this function reenables timer event.
 */
static void sigalrm_handler(int sig)
{
	w.need_reload = true;
	alarm(w.refresh_interval);
}

/**
 * shift - Shift string data before displaying.
 *
 * @str: String to be displayed.
 *
 * Returns shifted string.
 */
static const char *shift(const char *str)
{
	while (*str && w.eat_col) {
		str++;
		w.eat_col--;
	}
	return str;
}

/**
 * transition_control - Find domain transition control.
 *
 * @ns:         Pointer to "const struct ccs_path_info".
 * @domainname: Domainname.
 * @program:    Program name.
 *
 * Returns pointer to "const struct ccs_transition_entry" if found one,
 * NULL otherwise.
 */
static const struct transition_entry *find_transition
(const struct ccs_path_info *ns, const char *domainname, const char *program)
{
	int i;
	u8 type;
	struct ccs_path_info domain;
	struct ccs_path_info last_name;
	domain.name = domainname;
	last_name.name = get_last_word(domainname);
	ccs_fill_path_info(&domain);
	ccs_fill_path_info(&last_name);
	for (type = 0; type < MAX_TRANSITION_TYPE; type++) {
next:
		for (i = 0; i < w.transition_list_len; i++) {
			struct transition_entry *ptr = &w.transition_list[i];
			if (ptr->type != type)
				continue;
			if (ccs_pathcmp(ptr->ns, ns))
				continue;
			if (ptr->domainname &&
			    ccs_pathcmp(ptr->domainname, &domain) &&
			    ccs_pathcmp(ptr->domainname, &last_name))
				continue;
			if (ptr->program &&
			    strcmp(ptr->program->name, program))
				continue;
			if (type == TRANSITION_NO_RESET) {
				/*
				 * Do not check for reset_domain if
				 * no_reset_domain matched.
				 */
				type = TRANSITION_NO_INITIALIZE;
				goto next;
			}
			if (type == TRANSITION_NO_INITIALIZE) {
				/*
				 * Do not check for initialize_domain if
				 * no_initialize_domain matched.
				 */
				type = TRANSITION_NO_KEEP;
				goto next;
			}
			if (type == TRANSITION_RESET ||
			    type == TRANSITION_INITIALIZE ||
			    type == TRANSITION_KEEP)
				return ptr;
			else
				return NULL;
		}
	}
	return NULL;
}

/**
 * profile_compare -  strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int profile_compare(const void *a, const void *b)
{
	const struct generic_entry *a0 = (struct generic_entry *) a;
	const struct generic_entry *b0 = (struct generic_entry *) b;
	const enum directive_type a0_d = a0->directive;
	const enum directive_type b0_d = b0->directive;
	const char *a1 = a0->operand;
	const char *b1 = b0->operand;
	if (a0_d >= DIRECTIVE_ADDRESS_GROUP ||
	    b0_d >= DIRECTIVE_ADDRESS_GROUP) {
		if (a1[0] == 'P')
			return -1;
		if (b1[0] == 'P')
			return 1;
	}
	if (!w.sort_profile) {
		if (a0_d == b0_d)
			return strcmp(a1, b1);
		else
			return a0_d - b0_d;
	} else {
		const int a3 = strcspn(a1, "=");
		const int b3 = strcspn(b1, "=");
		const int c = strncmp(a1, b1, a3 >= b3 ? b3 : a3);
		if (c)
			return c;
		if (a3 != b3)
			return a3 - b3;
		else
			return a0_d - b0_d;
	}
}

/**
 * add_generic_entry - Add text lines.
 *
 * @line:      Line to add.
 * @directive: One of values in "enum directive_type".
 *
 * Returns nothing.
 */
static void add_generic_entry(const char *line, const enum directive_type
			      directive)
{
	struct generic_entry *ptr;
	int i;
	for (i = 0; i < p.generic_len; i++)
		if (p.generic[i].directive == directive &&
		    !strcmp(line, p.generic[i].operand))
			return;
	ptr = ccs_alloc(p.generic, sizeof(*ptr), p.generic_len);
	ptr->directive = directive;
	ptr->operand = ccs_strdup(line);
}

/**
 * read_generic_policy - Read policy data other than domain policy.
 *
 * Returns nothing.
 */
static void read_generic_policy(void)
{
	FILE *fp = NULL;
	_Bool flag = false;
	const _Bool is_kernel_ns = !strcmp(current_ns->name, "<kernel>");
	while (p.generic_len)
		free((void *) p.generic[--p.generic_len].operand);
	if (active == SCREEN_ACL_LIST) {
		if (ccs_network_mode)
			/* We can read after write. */
			fp = editpolicy_open_write(w.policy_file);
		else
			/* Don't set error message if failed. */
			fp = fopen(w.policy_file, "r+");
		if (fp) {
			if (w.show_tasklist)
				fprintf(fp, "select pid=%u\n",
					w.current_pid);
			else
				fprintf(fp, "select domain=%s\n",
					w.current_domain);
			if (ccs_network_mode)
				fputc(0, fp);
			fflush(fp);
		}
	} else if (active == SCREEN_NS_LIST) {
		add_generic_entry("<kernel>", DIRECTIVE_NONE);
	}
	if (!fp)
		fp = editpolicy_open_read(w.policy_file);
	if (!fp) {
		set_error(w.policy_file);
		return;
	}
	ccs_freadline_raw = active == SCREEN_STAT_LIST;
	ccs_get();
	while (true) {
		char *line = ccs_freadline_unpack(fp);
		enum directive_type directive;
		char *cp;
		if (!line)
			break;
		if (active == SCREEN_ACL_LIST) {
			if (ccs_domain_def(line)) {
				flag = !strcmp(line, w.current_domain);
				continue;
			}
			if (!flag || !line[0] ||
			    !strncmp(line, "use_profile ", 12))
				continue;
		} else {
			if (!line[0])
				continue;
		}
		if (active == SCREEN_EXCEPTION_LIST ||
		    active == SCREEN_PROFILE_LIST) {
			if (*line == '<') {
				cp = strchr(line, ' ');
				if (!cp++ || !is_current_namespace(line))
					continue;
				memmove(line, cp, strlen(cp) + 1);
			} else if (!is_kernel_ns)
				continue;
		}
		switch (active) {
		case SCREEN_EXCEPTION_LIST:
			directive = find_directive(true, line);
			if (directive == DIRECTIVE_NONE)
				continue;
			/* Remember groups for editpolicy_optimize(). */
			if (directive != DIRECTIVE_PATH_GROUP &&
			    directive != DIRECTIVE_NUMBER_GROUP &&
			    directive != DIRECTIVE_ADDRESS_GROUP &&
			    (directive < DIRECTIVE_ACL_GROUP_000 ||
			     directive > DIRECTIVE_ACL_GROUP_255))
				break;
			cp = ccs_strdup(line);
			if (directive == DIRECTIVE_PATH_GROUP)
				add_path_group_policy(current_ns, cp);
			else if (directive == DIRECTIVE_NUMBER_GROUP)
				add_number_group_policy(cp);
			else if (directive == DIRECTIVE_ADDRESS_GROUP)
				add_address_group_policy(cp);
			else
				add_acl_group_policy
					(directive - DIRECTIVE_ACL_GROUP_000,
					 cp);
			free(cp);
			break;
		case SCREEN_ACL_LIST:
			directive = find_directive(true, line);
			if (directive == DIRECTIVE_NONE)
				continue;
			break;
		case SCREEN_PROFILE_LIST:
			cp = strchr(line, '-');
			if (cp) {
				*cp++ = '\0';
				directive = atoi(line);
				memmove(line, cp, strlen(cp) + 1);
			} else
				directive = (u16) -1;
			break;
		case SCREEN_NS_LIST:
			if (*line != '<')
				continue;
			cp = strchr(line, ' ');
			if (!cp)
				continue;
			*cp = '\0';
			if (!ccs_domain_def(line))
				continue;
			/* Fall through. */
		default:
			directive = DIRECTIVE_NONE;
			break;
		}
		add_generic_entry(line, directive);
	}
	ccs_put();
	ccs_freadline_raw = false;
	fclose(fp);
	switch (active) {
	case SCREEN_ACL_LIST:
	case SCREEN_EXCEPTION_LIST:
		qsort(p.generic, p.generic_len, sizeof(struct generic_entry),
		      generic_compare);
		break;
	case SCREEN_PROFILE_LIST:
		qsort(p.generic, p.generic_len, sizeof(struct generic_entry),
		      profile_compare);
		break;
	case SCREEN_STAT_LIST:
		break;
	default:
		qsort(p.generic, p.generic_len, sizeof(struct generic_entry),
		      string_compare);
	}
}

/**
 * add_transition_entry - Add "reset_domain"/"no_reset_domain"/"initialize_domain"/"no_initialize_domain"/"keep_domain"/"no_keep_domain" entries.
 *
 * @ns:         Pointer to "const struct ccs_path_info".
 * @domainname: Domainname.
 * @program:    Program name.
 * @type:       One of values in "enum transition_type".
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int add_transition_entry(const struct ccs_path_info *ns,
				const char *domainname, const char *program,
				const enum transition_type type)
{
	struct transition_entry *ptr;
	if (program && strcmp(program, "any"))
		if (!ccs_correct_path(program))
			return -EINVAL;
	if (domainname && strcmp(domainname, "any"))
		if (!ccs_correct_domain(domainname))
			if (!ccs_correct_path(domainname))
				return -EINVAL;
	ptr = ccs_alloc(w.transition_list, sizeof(*ptr),
			w.transition_list_len);
	ptr->ns = ns;
	if (program && strcmp(program, "any"))
		ptr->program = ccs_savename(program);
	if (domainname && strcmp(domainname, "any"))
		ptr->domainname = ccs_savename(domainname);
	ptr->type = type;
	return 0;
}

/**
 * add_path_group - Add "path_group" entry.
 *
 * @ns:          Pointer to "const struct ccs_path_info".
 * @group_name:  Name of address group.
 * @member_name: Address string.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int add_path_group(const struct ccs_path_info *ns,
			  const char *group_name, const char *member_name)
{
	const struct ccs_path_info *saved_group_name;
	const struct ccs_path_info *saved_member_name;
	int i;
	int j;
	struct path_group *group = NULL;
	if (!ccs_correct_word(group_name) || !ccs_correct_word(member_name))
		return -EINVAL;
	saved_group_name = ccs_savename(group_name);
	saved_member_name = ccs_savename(member_name);
	for (i = 0; i < p.path_group_len; i++) {
		group = &p.path_group[i];
		if (group->ns != ns)
			continue;
		if (saved_group_name != group->group_name)
			continue;
		for (j = 0; j < group->member_name_len; j++)
			if (group->member_name[j] == saved_member_name)
				return 0;
		break;
	}
	if (i == p.path_group_len) {
		group = ccs_alloc(p.path_group, sizeof(*group),
				  p.path_group_len);
		group->ns = ns;
		group->group_name = saved_group_name;
	}
	*ccs_alloc(group->member_name, sizeof(saved_member_name),
		   group->member_name_len) = saved_member_name;
	return 0;
}

/**
 * add_number_group - Add "number_group" entry.
 *
 * @group_name:  Name of number group.
 * @member_name: Number string.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int add_number_group(const char *group_name, const char *member_name)
{
	const struct ccs_path_info *saved_group_name;
	int i;
	int j;
	struct ccs_number_entry entry;
	struct number_group *group = NULL;
	if (ccs_parse_number(member_name, &entry))
		return -EINVAL;
	if (!ccs_correct_word(group_name))
		return -EINVAL;
	saved_group_name = ccs_savename(group_name);
	for (i = 0; i < p.number_group_len; i++) {
		group = &p.number_group[i];
		if (saved_group_name != group->group_name)
			continue;
		for (j = 0; j < group->member_name_len; j++)
			if (!memcmp(&group->member_name[j], &entry,
				    sizeof(entry)))
				return 0;
		break;
	}
	if (i == p.number_group_len) {
		group = ccs_alloc(p.number_group, sizeof(*group),
				  p.number_group_len);
		group->group_name = saved_group_name;
	}
	*ccs_alloc(group->member_name, sizeof(entry), group->member_name_len) =
		entry;
	return 0;
}

/**
 * add_address_group - Add "address_group" entry.
 *
 * @group_name:  Name of address group.
 * @member_name: Address string.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int add_address_group(const char *group_name, const char *member_name)
{
	const struct ccs_path_info *saved_group_name;
	int i;
	int j;
	struct ccs_ip_address_entry entry;
	struct address_group *group = NULL;
	if (ccs_parse_ip(member_name, &entry))
		return -EINVAL;
	if (!ccs_correct_word(group_name))
		return -EINVAL;
	saved_group_name = ccs_savename(group_name);
	for (i = 0; i < p.address_group_len; i++) {
		group = &p.address_group[i];
		if (saved_group_name != group->group_name)
			continue;
		for (j = 0; j < group->member_name_len; j++)
			if (!memcmp(&group->member_name[j], &entry,
				    sizeof(entry)))
				return 0;
		break;
	}
	if (i == p.address_group_len) {
		group = ccs_alloc(p.address_group, sizeof(*group),
				  p.address_group_len);
		group->group_name = saved_group_name;
	}
	*ccs_alloc(group->member_name, sizeof(entry), group->member_name_len) =
		entry;
	return 0;
}

/**
 * add_condition_domain_transition - Add auto_domain_transition= part.
 *
 * @line:  Line to parse.
 * @index: Current domain's index.
 *
 * Returns nothing.
 */
static void add_condition_domain_transition(char *line, const int index)
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
	snprintf(domainname, sizeof(domainname) - 1, "%s  %s",
		 w.dp.list[index].domainname->name, cp);
	domainname[sizeof(domainname) - 1] = '\0';
	ccs_normalize_line(domainname);
	*ccs_alloc(w.jump_list, sizeof(char *), w.jump_list_len) =
		ccs_strdup(domainname);
	assign_domain(domainname, *cp == '<' ? cp : domainname, false);
}

/**
 * add_acl_domain_transition - Add task acl.
 *
 * @line:  Line to parse.
 * @index: Current domain's index.
 *
 * Returns nothing.
 */
static void add_acl_domain_transition(char *line, const int index)
{
	static char domainname[4096];
	
	int pos;
	/* Chop off condition part which follows domainname. */
	for (pos = 0; line[pos]; pos++)
		if (line[pos] == ' ' && line[pos + 1] != '/') {
			line[pos] = '\0';
			break;
		}
	if (!ccs_correct_domain(line))
		return;
	*ccs_alloc(w.jump_list, sizeof(char *), w.jump_list_len) =
		ccs_strdup(line);
	snprintf(domainname, sizeof(domainname) - 1, "%s  %s",
		 w.dp.list[index].domainname->name, get_last_word(line));
	domainname[sizeof(domainname) - 1] = '\0';
	ccs_normalize_line(domainname);
	assign_domain(domainname, line, false);
}

/**
 * parse_preference - Parse transition preference.
 *
 * @program:    Pathname or path_group.
 * @domainname: Domainname or transition preference.
 * @index:      Current domain's index.
 *
 * Returns true if transition preference was found, false otherwise.
 */
static _Bool parse_preference(char *program, char *domainname, const int index)
{
	struct transition_preference *ptr;
	char *cp = strchr(domainname, ' ');
	if (*domainname == '<')
		goto add;
	if (cp)
		*cp = '\0';
	if (ccs_correct_path(domainname) || !strcmp(domainname, "keep") ||
	    !strcmp(domainname, "reset") || !strcmp(domainname, "initialize")
	    || !strcmp(domainname, "child") || !strcmp(domainname, "parent"))
		goto add;
	return false;
add:
	ptr = ccs_alloc(w.preference_list, sizeof(*ptr),
			w.preference_list_len);
	ptr->index = index;
	ptr->domainname = ccs_strdup(domainname);
	ptr->program = ccs_strdup(program);
	return true;

}

/**
 * make_preference - Create transition preference.
 *
 * @ptr: Pointer to "struct transition_preference".
 *
 * Returns nothing.
 */
static void make_preference(struct transition_preference *ptr)
{
	static char buffer[4096];
	char *program = ptr->program;
	char *domainname = ptr->domainname;
	const int index = ptr->index;
	const char *self = w.dp.list[index].domainname->name;
	int i;
	struct path_group *group = *program == '@' ?
		find_path_group_ns(get_ns(self), program + 1) : NULL;
	const int j = group ? group->member_name_len : 0;
	buffer[sizeof(buffer) - 1] = '\0';
	if (*domainname == '<')
		snprintf(buffer, sizeof(buffer) - 1, "%s", domainname);
	else if (!strcmp(domainname, "keep"))
		snprintf(buffer, sizeof(buffer) - 1, "%s", self);
	else if (!strcmp(domainname, "reset")) {
		if (*program == '@') {
			for (i = 0; i < j; i++) {
				snprintf(buffer, sizeof(buffer) - 1, "<%s>",
					 group->member_name[i]->name);
				add_acl_domain_transition(buffer, index);
			}
			return;
		}
		snprintf(buffer, sizeof(buffer) - 1, "<%s>", program);
	} else if (!strcmp(domainname, "initialize")) {
		char *tmp = ccs_strdup(self);
		char *cp = strchr(tmp, ' ');
		if (cp)
			*cp = '\0';
		if (*program == '@') {
			for (i = 0; i < j; i++) {
				const char *cp2 = group->member_name[i]->name;
				if (*cp2 != '/')
					continue;
				snprintf(buffer, sizeof(buffer) - 1, "%s %s",
					 tmp, cp2);
				add_acl_domain_transition(buffer, index);
			}
			free(tmp);
			return;
		}
		snprintf(buffer, sizeof(buffer) - 1, "%s %s", tmp, program);
		free(tmp);
	} else if (!strcmp(domainname, "child")) {
		if (*program == '@') {
			for (i = 0; i < j; i++) {
				const char *cp = group->member_name[i]->name;
				if (*cp != '/')
					continue;
				snprintf(buffer, sizeof(buffer) - 1, "%s %s",
					 self, cp);
				add_acl_domain_transition(buffer, index);
			}
			return;
		}
		snprintf(buffer, sizeof(buffer) - 1, "%s %s", self, program);
	} else if (!strcmp(domainname, "parent")) {
		char *cp;
		snprintf(buffer, sizeof(buffer) - 1, "%s", self);
		cp = strrchr(buffer, ' ');
		if (cp)
			*cp = '\0';
	} else
		snprintf(buffer, sizeof(buffer) - 1, "%s %s", self,
			 domainname);
	add_acl_domain_transition(buffer, index);
}

/**
 * parse_domain_line - Parse an ACL entry in domain policy.
 *
 * @ns:          Pointer to "const struct ccs_path_info".
 * @line:        Line to parse.
 * @index:       Current domain's index.
 * @parse_flags: True if parse use_profile and use_group lines, false
 *               otherwise.
 *
 * Returns nothing.
 */
static void parse_domain_line(const struct ccs_path_info *ns, char *line,
			      const int index, const bool parse_flags)
{
	add_condition_domain_transition(line, index);
	if (ccs_str_starts(line, "file execute ")) {
		/*
		 * Chop off condition part which follows pathname.
		 * But check for domain transition preference.
		 */
		char *cp = strchr(line, ' ');
		if (cp) {
			*cp++ = '\0';
			if (parse_preference(line, cp, index))
				return;
		}
		if (*line == '@' || ccs_correct_path(line))
			add_string_entry(line, index);
	} else if (ccs_str_starts(line, "task manual_domain_transition ")) {
		add_acl_domain_transition(line, index);
	} else if (parse_flags) {
		unsigned int idx;
		if (sscanf(line, "use_profile %u", &idx) == 1 && idx < 256)
			w.dp.list[index].profile = (u8) idx;
		else if (sscanf(line, "use_group %u", &idx) == 1 && idx < 256)
			w.dp.list[index].group[idx] = 1;
	}
}

/**
 * parse_exception_line - Parse an ACL entry in exception policy.
 *
 * @ns:   Pointer to "const struct ccs_path_info".
 * @line: Line to parse.
 *
 * Returns nothing.
 */
static void parse_exception_line(const struct ccs_path_info *ns, char *line)
{
	int index;
	unsigned int group;
	for (index = 0; index < MAX_TRANSITION_TYPE; index++) {
		if (!ccs_str_starts(line, transition_type[index]))
			continue;
		add_transition_policy(ns, line, index);
		return;
	}
	if (ccs_str_starts(line, "path_group "))
		add_path_group_policy(ns, line);
	else if (ccs_str_starts(line, "address_group "))
		add_address_group_policy(line);
	else if (ccs_str_starts(line, "number_group "))
		add_number_group_policy(line);
	else if (sscanf(line, "acl_group %u", &group) == 1 && group < 256) {
		int index;
		line = strchr(line + 10, ' ');
		if (!line++)
			return;
		add_acl_group_policy(group, line);
		for (index = 0; index < w.dp.list_len; index++) {
			char *cp;
			const struct ccs_domain *ptr = &w.dp.list[index];
			if (!ptr->group[group] || ptr->target || ptr->is_dd)
				continue;
			cp = ccs_strdup(line);
			parse_domain_line(ns, cp, index, false);
			free(cp);
		}
	}
}

/**
 * read_domain_and_exception_policy - Read domain policy and exception policy.
 *
 * Returns nothing.
 *
 * Since CUI policy editor screen shows domain jump source domains and
 * unreachable domains, we need to read not only the domain policy but also
 * the exception policy for printing the domain transition tree.
 */
static void read_domain_and_exception_policy(void)
{
	FILE *fp;
	int i;
	int j;
	int index;
	int max_index;
	static const struct ccs_path_info *kernel_ns = NULL;
	const struct ccs_path_info *ns;

	while (w.jump_list_len)
		free(w.jump_list[--w.jump_list_len]);
	clear_domain_policy();
	w.transition_list_len = 0;
	editpolicy_clear_groups();
	if (!kernel_ns)
		kernel_ns = ccs_savename("<kernel>");
	ns = kernel_ns;

	/* Load all domain transition related entries. */
	fp = NULL;
	if (ccs_network_mode)
		/* We can read after write. */
		fp = editpolicy_open_write(CCS_PROC_POLICY_DOMAIN_POLICY);
	else
		/* Don't set error message if failed. */
		fp = fopen(CCS_PROC_POLICY_DOMAIN_POLICY, "r+");
	if (fp) {
		fprintf(fp, "select transition_only\n");
		if (ccs_network_mode)
			fputc(0, fp);
		fflush(fp);
	} else {
		fp = editpolicy_open_read(CCS_PROC_POLICY_DOMAIN_POLICY);
	}
	if (fp) {
		index = EOF;
		ccs_get();
		while (true) {
			char *line = ccs_freadline_unpack(fp);
			if (!line)
				break;
			if (*line == '<') {
				ns = get_ns(line);
				index = assign_domain(line, NULL, false);
				continue;
			} else if (index == EOF) {
				continue;
			}
			parse_domain_line(ns, line, index, true);
		}
		ccs_put();
		fclose(fp);
	}

	/* Load domain transition related entries and group entries. */
	fp = editpolicy_open_read(CCS_PROC_POLICY_EXCEPTION_POLICY);
	if (fp) {
		ccs_get();
		while (true) {
			char *line = ccs_freadline_unpack(fp);
			if (!line)
				break;
			if (*line == '<') {
				char *cp = strchr(line, ' ');
				if (!cp)
					continue;
				*cp++ = '\0';
				ns = ccs_savename(line);
				memmove(line, cp, strlen(cp) + 1);
			} else
				ns = kernel_ns;
			parse_exception_line(ns, line);
		}
		ccs_put();
		fclose(fp);
	}

	/* Create domain transition preference. */
	for (i = 0; i < w.preference_list_len; i++) {
		struct transition_preference *ptr = &w.preference_list[i];
		make_preference(&w.preference_list[i]);
		free(ptr->domainname);
		free(ptr->program);
	}
	free(w.preference_list);
	w.preference_list = NULL;
	w.preference_list_len = 0;

	/*
	 * Domain jump sources by "task manual_domain_transition" keyword or
	 * "auto_domain_transition="
	 * part of conditional ACL have been created by now because these
	 * keywords do not depend on domain transition control directives
	 * defined in the exception policy.
	 *
	 * Create domain jump sources for "file execute" keyword
	 * now because these keywords depend on domain transition control
	 * directives defined in the exception policy. Note that "file execute"
	 * allows referring "path_group" directives.
	 */
	max_index = w.dp.list_len;
	for (index = 0; index < max_index; index++) {
		const char *domainname = w.dp.list[index].domainname->name;
		const struct ccs_path_info **string_ptr
			= w.dp.list[index].string_ptr;
		const int max_count = w.dp.list[index].string_count;
		/* Do not recursively create domain jump source. */
		if (w.dp.list[index].target)
			continue;
		ns = get_ns(domainname);
		for (i = 0; i < max_count; i++) {
			const char *name = string_ptr[i]->name;
			struct path_group *group;
			if (name[0] != '@') {
				assign_djs(ns, domainname, name);
				continue;
			}
			group = find_path_group_ns(ns, name + 1);
			if (!group)
				continue;
			for (j = 0; j < group->member_name_len; j++) {
				name = group->member_name[j]->name;
				assign_djs(ns, domainname, name);
			}
		}
	}

	/* Create missing parent domains. */
	max_index = w.dp.list_len;
	for (index = 0; index < max_index; index++) {
		char *line;
		ccs_get();
		line = ccs_shprintf("%s", w.dp.list[index].domainname->name);
		while (true) {
			char *cp = strrchr(line, ' ');
			if (!cp)
				break;
			*cp = '\0';
			if (find_domain(line, NULL, false) == EOF)
				assign_domain(line, NULL, true);
		}
		ccs_put();
	}

	/*
	 * All domains and jump sources have been created by now.
	 * Let's markup domain jump targets and unreachable domains.
	 */
	max_index = w.dp.list_len;

	/*
	 * Find domains that might be reachable via
	 * "task manual_domain_transition" keyword or
	 * "auto_domain_transition=" part of conditional ACL.
	 * Such domains are marked with '*'.
	 */
	for (i = 0; i < w.jump_list_len; i++) {
		struct ccs_domain *ptr = find_domain_by_name(w.jump_list[i]);
		if (ptr)
			ptr->is_djt = true;
	}

	/*
	 * Find domains that might be reachable via "initialize_domain"
	 * keyword. Such domains are marked with '*'.
	 */
	for (index = 0; index < max_index; index++) {
		const struct ccs_domain *domain = &w.dp.list[index];
		const char *domainname = domain->domainname->name;
		char *cp;
		/* Ignore domain jump sources. */
		if (domain->target)
			continue;
		/* Ignore if already marked as domain jump targets. */
		if (domain->is_djt)
			continue;
		/* Ignore if not a namespace's root's child domain. */
		cp = strchr(domainname, ' ');
		if (!cp++ || strchr(cp, ' '))
			continue;
		/* Check "no_initialize_domain $program from any" entry. */
		for (i = 0; i < w.transition_list_len; i++) {
			struct transition_entry *ptr = &w.transition_list[i];
			if (ptr->type != TRANSITION_NO_INITIALIZE)
				continue;
			if (!is_same_namespace(domainname, ptr->ns))
				continue;
			if (ptr->domainname)
				continue;
			if (ptr->program && strcmp(ptr->program->name, cp))
				continue;
			break;
		}
		if (i < w.transition_list_len)
			continue;
		/*
		 * Check "initialize_domain $program from $domainname" entry.
		 */
		for (i = 0; i < w.transition_list_len; i++) {
			struct transition_entry *ptr = &w.transition_list[i];
			if (ptr->type != TRANSITION_INITIALIZE)
				continue;
			if (!is_same_namespace(domainname, ptr->ns))
				continue;
			if (ptr->program && strcmp(ptr->program->name, cp))
				continue;
			break;
		}
		if (i < w.transition_list_len)
			w.dp.list[index].is_djt = true;
	}

	/*
	 * Find domains that might suppress domain transition via "keep_domain"
	 * keyword. Such domains are marked with '#'.
	 */
	for (index = 0; index < max_index; index++) {
		const struct ccs_domain *domain = &w.dp.list[index];
		const struct ccs_path_info *name = domain->domainname;
		const char *last_name = get_last_word(name->name);
		/* Ignore domain jump sources. */
		if (domain->target)
			continue;
		/* Check "no_keep_domain any from $domainname" entry. */
		for (i = 0; i < w.transition_list_len; i++) {
			struct transition_entry *ptr = &w.transition_list[i];
			if (ptr->type != TRANSITION_NO_KEEP)
				continue;
			if (!is_same_namespace(name->name, ptr->ns))
				continue;
			if (ptr->program)
				continue;
			if (!ptr->domainname ||
			    !ccs_pathcmp(ptr->domainname, name) ||
			    !strcmp(ptr->domainname->name, last_name))
				break;
		}
		if (i < w.transition_list_len)
			continue;
		/* Check "keep_domain $program from $domainname" entry. */
		for (i = 0; i < w.transition_list_len; i++) {
			struct transition_entry *ptr = &w.transition_list[i];
			if (ptr->type != TRANSITION_KEEP)
				continue;
			if (!is_same_namespace(name->name, ptr->ns))
				continue;
			if (!ptr->domainname ||
			    !ccs_pathcmp(ptr->domainname, name) ||
			    !strcmp(ptr->domainname->name, last_name))
				break;
		}
		if (i < w.transition_list_len)
			w.dp.list[index].is_dk = true;
	}

	/*
	 * Find unreachable domains. Such domains are marked with '!'.
	 * Unreachable domains are caused by one of "initialize_domain" keyword
	 * or "keep_domain" keyword or "reset_domain" keyword.
	 */
	for (index = 0; index < max_index; index++) {
		char *line;
		struct ccs_domain * const domain = &w.dp.list[index];
		/*
		 * Mark domain jump source as unreachable if domain jump target
		 * does not exist. Note that such domains are not marked with
		 * '!'.
		 */
		if (domain->target) {
			if (find_domain(domain->target->name, NULL, false) ==
			    EOF)
				domain->is_du = true;
			continue;
		}
		/* Ignore if domain jump targets. */
		if (domain->is_djt)
			continue;
		/* Ignore if deleted domain. */
		if (domain->is_dd)
			continue;
		ns = get_ns(domain->domainname->name);
		ccs_get();
		line = ccs_shprintf("%s", domain->domainname->name);
		while (true) {
			const struct ccs_domain *ptr =
				find_domain_by_name(line);
			const struct transition_entry *d_t;
			char *cp;
			/* Stop traversal if current is domain jump target. */
			if (ptr && ptr->is_djt)
				break;
			cp = strrchr(line, ' ');
			if (cp)
				*cp++ = '\0';
			else
				break;
			d_t = find_transition(ns, line, cp);
			if (d_t)
				domain->d_t = d_t;
		}
		ccs_put();
		if (domain->d_t)
			domain->is_du = true;
	}

	/* Sort by domain name. */
	qsort(w.dp.list, w.dp.list_len, sizeof(struct ccs_domain),
	      domain_compare);

	/*
	 * Since this screen shows domain transition tree within current
	 * namespace, purge domains that are not in current namespace.
	 */
	for (index = 0; index < w.dp.list_len; index++) {
		int i;
		if (is_current_namespace(w.dp.list[index].domainname->name))
			continue;
		free(w.dp.list[index].string_ptr);
		w.dp.list_len--;
		for (i = index; i < w.dp.list_len; i++)
			w.dp.list[i] = w.dp.list[i + 1];
		index--;
	}

	/* Assign domain numbers. */
	{
		int number = 0;
		int index;
		w.unnumbered_domains = 0;
		for (index = 0; index < w.dp.list_len; index++) {
			if (is_deleted_domain(index) ||
			    is_jump_source(index)) {
				w.dp.list[index].number = -1;
				w.unnumbered_domains++;
			} else {
				w.dp.list[index].number = number++;
			}
		}
	}

	if (!w.dp.list_len)
		return;
	w.dp.list_selected = ccs_realloc2(w.dp.list_selected, w.dp.list_len);
}

/**
 * show_process_line - Print a process line.
 *
 * @index: Index in the ccs_task_list array.
 *
 * Returns length of the printed line.
 */
static int show_process_line(const int index)
{
	char *line;
	int tmp_col = 0;
	int i;
	printw("%c%4d:%3u ", ccs_task_list[index].selected ? '&' : ' ', index,
	       ccs_task_list[index].profile);
	tmp_col += 10;
	for (i = 0; i < ccs_task_list[index].depth - 1; i++) {
		printw("%s", shift("    "));
		tmp_col += 4;
	}
	ccs_get();
	line = ccs_shprintf("%s%s (%u) %s", ccs_task_list[index].depth ?
			    " +- " : "", ccs_task_list[index].name,
			    ccs_task_list[index].pid,
			    ccs_task_list[index].domain);
	printw("%s", shift(line));
	tmp_col += strlen(line);
	ccs_put();
	return tmp_col;
}

/**
 * show_list - Print list on the screen.
 *
 * Returns nothing.
 */
static void show_list(void)
{
	struct ccs_screen *ptr = &screen[active];
	int list_indent;
	const int offset = ptr->current;
	int i;
	int tmp_col;
	if (active == SCREEN_DOMAIN_LIST)
		w.list_items = w.show_tasklist ?
			ccs_task_list_len : w.dp.list_len;
	else
		w.list_items = p.generic_len;
	clear();
	move(0, 0);
	if (w.height < CCS_HEADER_LINES + 1) {
		printw("Please enlarge window.");
		clrtobot();
		refresh();
		return;
	}
	/* add color */
	editpolicy_color_change(editpolicy_color_head(), true);
	if (active == SCREEN_DOMAIN_LIST) {
		if (w.show_tasklist) {
			i = ccs_task_list_len;
			printw("<<< Process State Viewer >>>"
			       "      %d process%s ", i, i > 1 ? "es" : "");
			i = count_tasklist();
		} else {
			i = w.list_items - w.unnumbered_domains;
			printw("<<< Domain Transition Editor >>>"
			       "      %d domain%c ", i, i > 1 ? 's' : ' ');
			i = count_domainlist();
		}
	} else {
		i = w.list_items;
		printw("<<< %s >>>      %d entr%s ", w.caption, i,
		       i > 1 ? "ies" : "y");
		i = count_generic();
	}
	if (i)
		printw("(%u selected)", i);
	printw("   '?' for help");
	/* add color */
	editpolicy_color_change(editpolicy_color_head(), false);
	w.eat_col = ptr->x;
	w.max_col = 0;
	if (active == SCREEN_ACL_LIST) {
		char *line;
		ccs_get();
		line = ccs_shprintf("%s", shift(w.current_domain));
		editpolicy_attr_change(A_REVERSE, true);  /* add color */
		move(2, 0);
		printw("%s", line);
		editpolicy_attr_change(A_REVERSE, false); /* add color */
		ccs_put();
	}
	list_indent = 0;
	switch (active) {
	case SCREEN_EXCEPTION_LIST:
	case SCREEN_ACL_LIST:
		for (i = 0; i < w.list_items; i++) {
			const enum directive_type directive =
				p.generic[i].directive;
			const int len = directive_map[directive].alias_len;
			if (len > list_indent)
				list_indent = len;
		}
		break;
	default:
		break;
	}
	for (i = 0; i < w.body_lines; i++) {
		const int index = offset + i;
		w.eat_col = ptr->x;
		if (index >= w.list_items)
			break;
		move(CCS_HEADER_LINES + i, 0);
		switch (active) {
		case SCREEN_DOMAIN_LIST:
			if (!w.show_tasklist)
				tmp_col = show_domain_line(index);
			else
				tmp_col = show_process_line(index);
			break;
		case SCREEN_EXCEPTION_LIST:
		case SCREEN_ACL_LIST:
			tmp_col = show_acl_line(index, list_indent);
			break;
		case SCREEN_PROFILE_LIST:
			tmp_col = show_profile_line(index);
			break;
		case SCREEN_STAT_LIST:
			tmp_col = show_stat_line(index);
			break;
		default:
			tmp_col = show_literal_line(index);
			break;
		}
		clrtoeol();
		tmp_col -= w.width;
		if (tmp_col > w.max_col)
			w.max_col = tmp_col;
	}
	show_current();
}

/**
 * resize_window - Callback for resize event.
 *
 * Returns nothing.
 */
static void resize_window(void)
{
	struct ccs_screen *ptr = &screen[active];
	getmaxyx(stdscr, w.height, w.width);
	w.body_lines = w.height - CCS_HEADER_LINES;
	if (w.body_lines <= ptr->y)
		ptr->y = w.body_lines - 1;
	if (ptr->y < 0)
		ptr->y = 0;
}

/**
 * up_arrow_key - Callback event for pressing up-arrow key.
 *
 * Returns nothing.
 */
static void up_arrow_key(void)
{
	struct ccs_screen *ptr = &screen[active];
	if (ptr->y > 0) {
		ptr->y--;
		show_current();
	} else if (ptr->current > 0) {
		ptr->current--;
		show_list();
	}
}

/**
 * down_arrow_key - Callback event for pressing down-arrow key.
 *
 * Returns nothing.
 */
static void down_arrow_key(void)
{
	struct ccs_screen *ptr = &screen[active];
	if (ptr->y < w.body_lines - 1) {
		if (ptr->current + ptr->y < w.list_items - 1) {
			ptr->y++;
			show_current();
		}
	} else if (ptr->current + ptr->y < w.list_items - 1) {
		ptr->current++;
		show_list();
	}
}

/**
 * page_up_key - Callback event for pressing page-up key.
 *
 * Returns nothing.
 */
static void page_up_key(void)
{
	struct ccs_screen *ptr = &screen[active];
	int p0 = ptr->current;
	int p1 = ptr->y;
	_Bool refresh;
	if (p0 + p1 > w.body_lines) {
		p0 -= w.body_lines;
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
		show_list();
	else
		show_current();
}

/**
 * page_down_key - Callback event for pressing page-down key.
 *
 * Returns nothing.
 */
static void page_down_key(void)
{
	struct ccs_screen *ptr = &screen[active];
	int count = w.list_items - 1;
	int p0 = ptr->current;
	int p1 = ptr->y;
	_Bool refresh;
	if (p0 + p1 + w.body_lines < count) {
		p0 += w.body_lines;
	} else if (p0 + p1 < count) {
		while (p0 + p1 < count) {
			if (p1 + 1 < w.body_lines)
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
		show_list();
	else
		show_current();
}

/**
 * editpolicy_get_current - Get currently selected line's index.
 *
 * Returns index for currently selected line on success, EOF otherwise.
 *
 * If current screen has no entry, this function returns EOF.
 */
int editpolicy_get_current(void)
{
	struct ccs_screen *ptr = &screen[active];
	if (!w.list_items)
		return EOF;
	return ptr->current + ptr->y;
}

/**
 * show_current - Show current cursor line.
 *
 * Returns nothing.
 */
static void show_current(void)
{
	struct ccs_screen *ptr = &screen[active];
	if (active == SCREEN_DOMAIN_LIST &&
	    !w.show_tasklist) {
		char *line;
		const int index = editpolicy_get_current();
		ccs_get();
		w.eat_col = ptr->x;
		if (index >= 0) {
			line = ccs_shprintf("%s", shift(w.dp.list[index].
							domainname->name));
			if (is_jump_source(index)) {
				char *cp = strrchr(line, ' ');
				if (cp)
					*cp = '\0';
			}
		} else
			line = ccs_shprintf("%s", current_ns->name);
		if (w.width < strlen(line))
			line[w.width] = '\0';
		move(2, 0);
		clrtoeol();
		editpolicy_attr_change(A_REVERSE, true);  /* add color */
		printw("%s", line);
		editpolicy_attr_change(A_REVERSE, false); /* add color */
		ccs_put();
	}
	if (active == SCREEN_EXCEPTION_LIST || active == SCREEN_PROFILE_LIST) {
		char *line;
		ccs_get();
		w.eat_col = ptr->x;
		line = ccs_shprintf("%s", current_ns->name);
		if (w.width < strlen(line))
			line[w.width] = '\0';
		move(2, 0);
		clrtoeol();
		editpolicy_attr_change(A_REVERSE, true);  /* add color */
		printw("%s", line);
		editpolicy_attr_change(A_REVERSE, false); /* add color */
		ccs_put();
	}
	move(CCS_HEADER_LINES + ptr->y, 0);
	editpolicy_line_draw();     /* add color */
	refresh();
}

/**
 * adjust_cursor_pos - Adjust cursor position if needed.
 *
 * @item_count: Available item count in this screen.
 *
 * Returns nothing.
 */
static void adjust_cursor_pos(const int item_count)
{
	struct ccs_screen *ptr = &screen[active];
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
 * set_cursor_pos - Move cursor position if needed.
 *
 * @index: Index in the domain policy or currently selected line in the generic
 *         list.
 *
 * Returns nothing.
 */
static void set_cursor_pos(const int index)
{
	struct ccs_screen *ptr = &screen[active];
	while (index < ptr->y + ptr->current) {
		if (ptr->y > 0)
			ptr->y--;
		else
			ptr->current--;
	}
	while (index > ptr->y + ptr->current) {
		if (ptr->y < w.body_lines - 1)
			ptr->y++;
		else
			ptr->current++;
	}
}

/**
 * select_item - Select an item.
 *
 * Returns true if selected, false otherwise.
 *
 * Domain transition source and deleted domains are not selectable.
 */
static _Bool select_item(void)
{
	int x;
	int y;
	const int index = editpolicy_get_current();
	if (index < 0)
		return false;
	if (active == SCREEN_DOMAIN_LIST) {
		if (!w.show_tasklist) {
			if (is_deleted_domain(index) || is_jump_source(index))
				return false;
			w.dp.list_selected[index] ^= 1;
		} else {
			ccs_task_list[index].selected ^= 1;
		}
	} else {
		p.generic[index].selected ^= 1;
	}
	getyx(stdscr, y, x);
	editpolicy_sttr_save();    /* add color */
	show_list();
	editpolicy_sttr_restore(); /* add color */
	move(y, x);
	return true;
}

/**
 * generic_compare - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int generic_compare(const void *a, const void *b)
{
	const struct generic_entry *a0 = (struct generic_entry *) a;
	const struct generic_entry *b0 = (struct generic_entry *) b;
	const enum directive_type a0_d = a0->directive;
	const enum directive_type b0_d = b0->directive;
	const char *a1 = directive_map[a0_d].alias;
	const char *b1 = directive_map[b0_d].alias;
	const char *a2 = a0->operand;
	const char *b2 = b0->operand;
	if (active == SCREEN_EXCEPTION_LIST) {
		int ret;
		if (a0_d >= DIRECTIVE_ACL_GROUP_000 &&
		    a0_d <= DIRECTIVE_ACL_GROUP_255 &&
		    b0_d >= DIRECTIVE_ACL_GROUP_000 &&
		    b0_d <= DIRECTIVE_ACL_GROUP_255 && a0_d != b0_d)
			return a0_d - b0_d;
		ret = strcmp(a1, b1);
		if (ret)
			return ret;
		return strcmp(a2, b2);
	}
	if (a0_d == DIRECTIVE_USE_GROUP && b0_d == DIRECTIVE_USE_GROUP)
		return atoi(a2) - atoi(b2);
	if (!w.sort_acl) {
		const int ret = strcmp(a1, b1);
		if (ret)
			return ret;
		return strcmp(a2, b2);
	} else if (a0_d == DIRECTIVE_USE_GROUP) {
		return 1;
	} else if (b0_d == DIRECTIVE_USE_GROUP) {
		return -1;
	} else if (a0_d == DIRECTIVE_TRANSITION_FAILED) {
		return 2;
	} else if (b0_d == DIRECTIVE_TRANSITION_FAILED) {
		return -2;
	} else if (a0_d == DIRECTIVE_QUOTA_EXCEEDED) {
		return 3;
	} else if (b0_d == DIRECTIVE_QUOTA_EXCEEDED) {
		return -3;
	} else {
		const int ret = strcmp(a2, b2);
		if (ret)
			return ret;
		return strcmp(a1, b1);
	}
}

/**
 * delete_entry - Delete an entry.
 *
 * Returns nothing.
 */
static void delete_entry(void)
{
	int c;
	move(1, 0);
	editpolicy_color_change(COLOR_DISP_ERR, true);	/* add color */
	if (active == SCREEN_DOMAIN_LIST) {
		c = count_domainlist();
		if (!c)
			c = select_item();
		if (!c)
			printw("Select domain using Space key first.");
		else
			printw("Delete selected domain%s? ('Y'es/'N'o)",
			       c > 1 ? "s" : "");
	} else {
		c = count_generic();
		if (!c)
			c = select_item();
		if (!c)
			printw("Select entry using Space key first.");
		else
			printw("Delete selected entr%s? ('Y'es/'N'o)",
			       c > 1 ? "ies" : "y");
	}
	editpolicy_color_change(COLOR_DISP_ERR, false);	/* add color */
	clrtoeol();
	refresh();
	if (!c)
		return;
	do {
		c = ccs_getch2();
	} while (!(c == 'Y' || c == 'y' || c == 'N' || c == 'n' || c == EOF));
	resize_window();
	if (c != 'Y' && c != 'y') {
		show_list();
		return;
	}
	if (active == SCREEN_DOMAIN_LIST) {
		int i;
		FILE *fp = editpolicy_open_write
			(CCS_PROC_POLICY_DOMAIN_POLICY);
		if (!fp)
			return;
		for (i = 0; i < w.dp.list_len; i++) {
			if (!w.dp.list_selected[i])
				continue;
			fprintf(fp, "delete %s\n",
				w.dp.list[i].domainname->name);
		}
		ccs_close_write(fp);
	} else {
		int i;
		const _Bool is_kernel_ns = !strcmp(current_ns->name,
						   "<kernel>");
		FILE *fp = editpolicy_open_write(w.policy_file);
		if (!fp)
			return;
		if (active == SCREEN_ACL_LIST) {
			if (w.show_tasklist)
				fprintf(fp, "select pid=%u\n", w.current_pid);
			else
				fprintf(fp, "select domain=%s\n",
					w.current_domain);
		}
		for (i = 0; i < p.generic_len; i++) {
			enum directive_type directive;
			if (!p.generic[i].selected)
				continue;
			directive = p.generic[i].directive;
			fprintf(fp, "delete %s %s %s\n",
				active == SCREEN_EXCEPTION_LIST
				&& !is_kernel_ns ? current_ns->name : "",
				directive_map[directive].original,
				p.generic[i].operand);
		}
		ccs_close_write(fp);
	}
}

/**
 * add_entry - Add an entry.
 *
 * Returns nothing.
 */
static void add_entry(void)
{
	FILE *fp;
	char *line;
	const _Bool is_kernel_ns = !strcmp(current_ns->name, "<kernel>");
	editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(w.height - 1, 0, "Enter new entry> ", rl.history,
			    rl.count, 128000, 8);
	editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	rl.count = ccs_add_history(line, rl.history, rl.count, rl.max);
	fp = editpolicy_open_write(w.policy_file);
	if (!fp)
		goto out;
	switch (active) {
		enum directive_type directive;
	case SCREEN_DOMAIN_LIST:
		if (!ccs_correct_domain(line)) {
			const int len = strlen(line) + 128;
			w.last_error = ccs_realloc2(w.last_error, len);
			snprintf(w.last_error, len - 1,
				 "%s is an invalid domainname.", line);
			line[0] = '\0';
		}
		break;
	case SCREEN_ACL_LIST:
		if (w.show_tasklist)
			fprintf(fp, "select pid=%u\n", w.current_pid);
		else
			fprintf(fp, "select domain=%s\n", w.current_domain);
		/* Fall through. */
	case SCREEN_EXCEPTION_LIST:
		if (active == SCREEN_EXCEPTION_LIST && !is_kernel_ns)
			fprintf(fp, "%s ", current_ns->name);
		directive = find_directive(false, line);
		if (directive != DIRECTIVE_NONE)
			fprintf(fp, "%s ", directive_map[directive].original);
		break;
	case SCREEN_PROFILE_LIST:
		if (!strchr(line, '='))
			fprintf(fp, "%s %s-COMMENT=\n", !is_kernel_ns ?
				current_ns->name : "", line);
		if (!is_kernel_ns)
			fprintf(fp, "%s ", current_ns->name);
		break;
	case SCREEN_NS_LIST:
		fprintf(fp, "%s PROFILE_VERSION=20100903\n", line);
		line[0] = '\0';
		break;
	default:
		break;
	}
	fprintf(fp, "%s\n", line);
	ccs_close_write(fp);
out:
	free(line);
}

/**
 * find_entry - Find an entry by user's key input.
 *
 * @input:   True if find next/previous, false if find first.
 * @forward: True if find next, false if find previous.
 *
 * Returns nothing.
 */
static void find_entry(const _Bool input, const _Bool forward)
{
	int index = editpolicy_get_current();
	char *line = NULL;
	if (index == EOF)
		return;
	if (!input)
		goto start_search;
	editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(w.height - 1, 0, "Search> ", rl.history, rl.count,
			    128000, 8);
	editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	rl.count = ccs_add_history(line, rl.history, rl.count, rl.max);
	free(rl.search_buffer[active]);
	rl.search_buffer[active] = line;
	line = NULL;
	index = -1;
start_search:
	ccs_get();
	while (true) {
		const char *cp;
		if (forward) {
			if (++index >= w.list_items)
				break;
		} else {
			if (--index < 0)
				break;
		}
		if (active == SCREEN_DOMAIN_LIST) {
			if (w.show_tasklist)
				cp = ccs_task_list[index].name;
			else
				cp = get_last_name(index);
		} else if (active == SCREEN_PROFILE_LIST) {
			cp = ccs_shprintf("%u-%s", p.generic[index].directive,
					  p.generic[index].operand);
		} else {
			const enum directive_type directive =
				p.generic[index].directive;
			cp = ccs_shprintf("%s %s",
					  directive_map[directive].alias,
					  p.generic[index].operand);
		}
		if (!strstr(cp, rl.search_buffer[active]))
			continue;
		set_cursor_pos(index);
		break;
	}
	ccs_put();
out:
	free(line);
	show_list();
}

/**
 * set_profile - Change profile number.
 *
 * Returns nothing.
 */
static void set_profile(void)
{
	int index;
	FILE *fp;
	char *line;
	if (!w.show_tasklist) {
		if (!count_domainlist() && !select_item()) {
			move(1, 0);
			printw("Select domain using Space key first.");
			clrtoeol();
			refresh();
			return;
		}
	} else {
		if (!count_tasklist() && !select_item()) {
			move(1, 0);
			printw("Select processes using Space key first.");
			clrtoeol();
			refresh();
			return;
		}
	}
	editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(w.height - 1, 0, "Enter profile number> ", NULL, 0,
			    8, 1);
	editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = editpolicy_open_write(CCS_PROC_POLICY_DOMAIN_POLICY);
	if (!fp)
		goto out;
	if (!w.show_tasklist) {
		for (index = 0; index < w.dp.list_len; index++) {
			if (!w.dp.list_selected[index])
				continue;
			fprintf(fp, "select domain=%s\nuse_profile %s\n",
				w.dp.list[index].domainname->name, line);
		}
	} else {
		for (index = 0; index < ccs_task_list_len; index++) {
			if (!ccs_task_list[index].selected)
				continue;
			fprintf(fp, "select pid=%u\nuse_profile %s\n",
				ccs_task_list[index].pid, line);
		}
	}
	ccs_close_write(fp);
out:
	free(line);
}

/**
 * set_level - Change profiles.
 *
 * Returns nothing.
 */
static void set_level(void)
{
	int index;
	FILE *fp;
	char *line;
	if (!count_generic())
		select_item();
	editpolicy_attr_change(A_BOLD, true);  /* add color */
	ccs_initial_readline_data = NULL;
	for (index = 0; index < p.generic_len; index++) {
		char *cp;
		if (!p.generic[index].selected)
			continue;
		cp = strchr(p.generic[index].operand, '=');
		if (!cp)
			continue;
		ccs_initial_readline_data = cp + 1;
		break;
	}
	line = ccs_readline(w.height - 1, 0, "Enter new value> ", NULL, 0,
			    128000, 1);
	ccs_initial_readline_data = NULL;
	editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = editpolicy_open_write(CCS_PROC_POLICY_PROFILE);
	if (!fp)
		goto out;
	for (index = 0; index < p.generic_len; index++) {
		char *buf;
		char *cp;
		enum directive_type directive;
		if (!p.generic[index].selected)
			continue;
		ccs_get();
		buf = ccs_shprintf("%s", p.generic[index].operand);
		cp = strchr(buf, '=');
		if (cp)
			*cp = '\0';
		directive = p.generic[index].directive;
		fprintf(fp, "%s ", current_ns->name);
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
 * set_quota - Set memory quota.
 *
 * Returns nothing.
 */
static void set_quota(void)
{
	int index;
	FILE *fp;
	char *line;
	if (!count_generic())
		select_item();
	editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(w.height - 1, 0, "Enter new value> ", NULL, 0, 20,
			    1);
	editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = editpolicy_open_write(CCS_PROC_POLICY_STAT);
	if (!fp)
		goto out;
	for (index = 0; index < p.generic_len; index++) {
		char *buf;
		char *cp;
		if (!p.generic[index].selected)
			continue;
		ccs_get();
		buf = ccs_shprintf("%s", p.generic[index].operand);
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
 * select_ns_window - Check whether to switch to ACL list or not.
 *
 * Returns next window to display if valid, MAX_SCREEN_TYPE otherwise.
 */
static enum screen_type select_ns_window(void)
{
	const int current = editpolicy_get_current();
	if (current != EOF) {
		const char *namespace = p.generic[current].operand;
		enum screen_type next = w.previous_screen;
		if (next == SCREEN_ACL_LIST &&
		    strcmp(current_ns->name, namespace))
			next = SCREEN_DOMAIN_LIST;
		current_ns = ccs_savename(namespace);
		return next;
	}
	return MAX_SCREEN_TYPE;
}

/**
 * select_acl_window - Check whether to switch to ACL list or not.
 *
 * Returns next window to display if valid, MAX_SCREEN_TYPE otherwise.
 */
static enum screen_type select_acl_window(void)
{
	const int current = editpolicy_get_current();
	const char *old_domain = w.current_domain;
	const char *new_domain;
	enum screen_type next = SCREEN_ACL_LIST;
	if (active != SCREEN_DOMAIN_LIST || current == EOF)
		return MAX_SCREEN_TYPE;
	w.current_pid = 0;
	if (w.show_tasklist) {
		w.current_pid = ccs_task_list[current].pid;
		new_domain = ccs_strdup(ccs_task_list[current].domain);
	} else if (is_deleted_domain(current)) {
		return MAX_SCREEN_TYPE;
	} else if (is_jump_source(current)) {
		if (find_target_domain(current) == EOF)
			return MAX_SCREEN_TYPE;
		new_domain = w.dp.list[current].target->name;
		current_ns = get_ns(new_domain);
		w.force_move_cursor = true;
		next = SCREEN_DOMAIN_LIST;
	} else {
		new_domain = w.dp.list[current].domainname->name;
	}
	w.no_restore_cursor = old_domain && strcmp(old_domain, new_domain);
	free((char *) old_domain);
	w.current_domain = ccs_strdup(new_domain);
	return next;
}

/**
 * select_window - Switch window.
 *
 * Returns next window to display.
 */
static enum screen_type select_window(void)
{
	const int current = editpolicy_get_current();
	const _Bool allow_acl = active == SCREEN_DOMAIN_LIST && current != EOF
		&& !is_jump_source(current) && !is_deleted_domain(current);
	move(0, 0);
	printw("Press one of below keys to switch window.\n\n");
	printw("e     <<< Exception Policy Editor >>>\n");
	printw("d     <<< Domain Transition Editor >>>\n");
	if (allow_acl)
		printw("a     <<< Domain Policy Editor >>>\n");
	printw("p     <<< Profile Editor >>>\n");
	printw("m     <<< Manager Policy Editor >>>\n");
	printw("n     <<< Namespace Selector >>>\n");
	if (!w.offline_mode) {
		/* printw("i     <<< Interactive Enforcing Mode >>>\n"); */
		printw("s     <<< Statistics >>>\n");
	}
	printw("q     Quit this editor.\n");
	clrtobot();
	refresh();
	while (true) {
		enum screen_type next;
		int c = ccs_getch2();
		switch (c) {
		case 'E':
		case 'e':
			return SCREEN_EXCEPTION_LIST;
		case 'D':
		case 'd':
			return SCREEN_DOMAIN_LIST;
		case 'A':
		case 'a':
			if (!allow_acl)
				break;
			next = select_acl_window();
			if (next == MAX_SCREEN_TYPE)
				break;
			return next;
		case 'P':
		case 'p':
			return SCREEN_PROFILE_LIST;
		case 'M':
		case 'm':
			return SCREEN_MANAGER_LIST;
		case 'N':
		case 'n':
			return SCREEN_NS_LIST;
			/*
		case 'I':
		case 'i':
			if (w.offline_mode)
				break;
			return SCREEN_QUERY_LIST;
			*/
		case 'S':
		case 's':
			if (w.offline_mode)
				break;
			return SCREEN_STAT_LIST;
		case 'Q':
		case 'q':
		case EOF:
			return MAX_SCREEN_TYPE;
		}
	}
}

/**
 * copy_mark_state - Copy selected state to lines under the current line.
 *
 * Returns nothing.
 */
static void copy_mark_state(void)
{
	const int current = editpolicy_get_current();
	int index;
	if (current == EOF)
		return;
	if (active == SCREEN_DOMAIN_LIST) {
		if (w.show_tasklist) {
			const u8 selected = ccs_task_list[current].selected;
			for (index = current; index < ccs_task_list_len;
			     index++)
				ccs_task_list[index].selected = selected;
		} else {
			const u8 selected = w.dp.list_selected[current];
			if (is_deleted_domain(current) ||
			    is_jump_source(current))
				return;
			for (index = current; index < w.dp.list_len;
			     index++) {
				if (is_deleted_domain(index) ||
				    is_jump_source(index))
					continue;
				w.dp.list_selected[index] = selected;
			}
		}
	} else {
		const _Bool selected = p.generic[current].selected;
		for (index = current; index < p.generic_len; index++)
			p.generic[index].selected = selected;
	}
	show_list();
}

/**
 * copy_to_history - Copy line to histoy buffer.
 *
 * Returns nothing.
 */
static void copy_to_history(void)
{
	const int current = editpolicy_get_current();
	const char *line;
	unsigned int profile;
	if (current == EOF)
		return;
	ccs_get();
	switch (active) {
		enum directive_type directive;
	case SCREEN_DOMAIN_LIST:
		if (!w.show_tasklist) {
			const struct ccs_domain *domain = &w.dp.list[current];
			if (domain->target)
				line = domain->target->name;
			else
				line = domain->domainname->name;
		} else
			line = ccs_task_list[current].domain;
		break;
	case SCREEN_EXCEPTION_LIST:
	case SCREEN_ACL_LIST:
		directive = p.generic[current].directive;
		line = ccs_shprintf("%s %s", directive_map[directive].alias,
				    p.generic[current].operand);
		break;
	case SCREEN_STAT_LIST:
		line = NULL;
		break;
	case SCREEN_PROFILE_LIST:
		profile = p.generic[current].directive;
		if (profile < 256) {
			line = ccs_shprintf("%u-%s", profile,
					    p.generic[current].operand);
			break;
		}
		/* Fall through. */
	default:
		line = ccs_shprintf("%s", p.generic[current].operand);
	}
	rl.count = ccs_add_history(line, rl.history, rl.count, rl.max);
	ccs_put();
}

/**
 * generic_list_loop - Main loop.
 *
 * Returns next screen to display.
 */
static enum screen_type generic_list_loop(void)
{
	struct ccs_screen *ptr;
	static struct {
		int y;
		int current;
	} saved_cursor[MAX_SCREEN_TYPE] = { };
	if (active == SCREEN_EXCEPTION_LIST) {
		w.policy_file = CCS_PROC_POLICY_EXCEPTION_POLICY;
		w.caption = "Exception Policy Editor";
	} else if (active == SCREEN_ACL_LIST) {
		w.policy_file = CCS_PROC_POLICY_DOMAIN_POLICY;
		w.caption = "Domain Policy Editor";
		/*
		  } else if (active == SCREEN_QUERY_LIST) {
		  w.policy_file = CCS_PROC_POLICY_QUERY;
		  w.caption = "Interactive Enforcing Mode";
		*/
	} else if (active == SCREEN_NS_LIST) {
		w.policy_file = CCS_PROC_POLICY_PROFILE;
		w.caption = "Namespace Selector";
	} else if (active == SCREEN_PROFILE_LIST) {
		w.policy_file = CCS_PROC_POLICY_PROFILE;
		w.caption = "Profile Editor";
	} else if (active == SCREEN_MANAGER_LIST) {
		w.policy_file = CCS_PROC_POLICY_MANAGER;
		w.caption = "Manager Policy Editor";
	} else if (active == SCREEN_STAT_LIST) {
		w.policy_file = CCS_PROC_POLICY_STAT;
		w.caption = "Statistics";
	} else {
		w.policy_file = CCS_PROC_POLICY_DOMAIN_POLICY;
		/* w.caption = "Domain Transition Editor"; */
	}
	ptr = &screen[active];
	if (w.no_restore_cursor || w.force_move_cursor) {
		ptr->current = 0;
		ptr->y = 0;
		w.no_restore_cursor = false;
	} else {
		ptr->current = saved_cursor[active].current;
		ptr->y = saved_cursor[active].y;
	}
start:
	if (active == SCREEN_DOMAIN_LIST) {
		if (!w.show_tasklist) {
			read_domain_and_exception_policy();
			if (w.force_move_cursor) {
				const int redirect_index =
					find_domain(w.current_domain, NULL,
						    false);
				if (redirect_index >= 0) {
					ptr->current = redirect_index - ptr->y;
					while (ptr->current < 0) {
						ptr->current++;
						ptr->y--;
					}
				}
				w.force_move_cursor = false;
			}
			adjust_cursor_pos(w.dp.list_len);
		} else {
			ccs_read_process_list(true);
			adjust_cursor_pos(ccs_task_list_len);
		}
	} else {
		read_generic_policy();
		adjust_cursor_pos(p.generic_len);
	}
start2:
	show_list();
	if (w.last_error) {
		move(1, 0);
		printw("ERROR: %s", w.last_error);
		clrtoeol();
		refresh();
		free(w.last_error);
		w.last_error = NULL;
	}
	while (true) {
		const int c = ccs_getch2();
		enum screen_type next;
		saved_cursor[active].current = ptr->current;
		saved_cursor[active].y = ptr->y;
		if (c == 'q' || c == 'Q')
			return MAX_SCREEN_TYPE;
		if ((c == '\r' || c == '\n') &&
		    active == SCREEN_ACL_LIST)
			return SCREEN_DOMAIN_LIST;
		if (c == '\t')
			return w.previous_screen;
		if (w.need_reload) {
			w.need_reload = false;
			goto start;
		}
		if (c == ERR)
			continue; /* Ignore invalid key. */
		switch (c) {
		case KEY_RESIZE:
			resize_window();
			show_list();
			break;
		case KEY_UP:
			up_arrow_key();
			break;
		case KEY_DOWN:
			down_arrow_key();
			break;
		case KEY_PPAGE:
			page_up_key();
			break;
		case KEY_NPAGE:
			page_down_key();
			break;
		case ' ':
			select_item();
			break;
		case 'c':
		case 'C':
			copy_mark_state();
			break;
		case 'f':
		case 'F':
			if (active != SCREEN_STAT_LIST)
				find_entry(true, true);
			break;
		case 'p':
		case 'P':
			if (active == SCREEN_STAT_LIST)
				break;
			if (!rl.search_buffer[active])
				find_entry(true, false);
			else
				find_entry(false, false);
			break;
		case 'n':
		case 'N':
			if (active == SCREEN_STAT_LIST)
				break;
			if (!rl.search_buffer[active])
				find_entry(true, true);
			else
				find_entry(false, true);
			break;
		case 'd':
		case 'D':
			if (w.readonly_mode)
				break;
			switch (active) {
			case SCREEN_DOMAIN_LIST:
				if (w.show_tasklist)
					break;
			case SCREEN_EXCEPTION_LIST:
			case SCREEN_ACL_LIST:
			case SCREEN_MANAGER_LIST:
				delete_entry();
				goto start;
			default:
				break;
			}
			break;
		case 'a':
		case 'A':
			if (w.readonly_mode)
				break;
			switch (active) {
			case SCREEN_DOMAIN_LIST:
				if (w.show_tasklist)
					break;
			case SCREEN_EXCEPTION_LIST:
			case SCREEN_ACL_LIST:
			case SCREEN_PROFILE_LIST:
			case SCREEN_MANAGER_LIST:
			case SCREEN_NS_LIST:
				add_entry();
				goto start;
			default:
				break;
			}
			break;
		case '\r':
		case '\n':
			if (active == SCREEN_NS_LIST)
				next = select_ns_window();
			else
				next = select_acl_window();
			if (next == MAX_SCREEN_TYPE)
				break;
			return next;
		case 's':
		case 'S':
			if (w.readonly_mode)
				break;
			switch (active) {
			case SCREEN_DOMAIN_LIST:
				set_profile();
				goto start;
			case SCREEN_PROFILE_LIST:
				set_level();
				goto start;
			case SCREEN_STAT_LIST:
				set_quota();
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
			ptr->x = w.max_col;
			goto start2;
		case KEY_IC:
			copy_to_history();
			break;
		case 'o':
		case 'O':
			if (active == SCREEN_ACL_LIST ||
			    active == SCREEN_EXCEPTION_LIST) {
				editpolicy_optimize();
				show_list();
			}
			break;
		case '@':
			switch (active) {
			case SCREEN_ACL_LIST:
				w.sort_acl = !w.sort_acl;
				goto start;
			case SCREEN_PROFILE_LIST:
				w.sort_profile = !w.sort_profile;
				goto start;
			case SCREEN_DOMAIN_LIST:
				if (w.offline_mode)
					break;
				w.show_tasklist = !w.show_tasklist;
				goto start;
			default:
				break;
			}
			break;
		case 'w':
		case 'W':
			return select_window();
		case '?':
			if (show_command_key(active, w.readonly_mode))
				goto start;
			return MAX_SCREEN_TYPE;
		}
	}
}

/**
 * save_to_file - Save policy to file.
 *
 * @src:  Filename to read from.
 * @dest: Filename to write to.
 *
 * Returns true on success, false otherwise.
 */
static _Bool save_to_file(const char *src, const char *dest)
{
	FILE *proc_fp = editpolicy_open_read(src);
	FILE *file_fp = fopen(dest, "w");
	int c;
	if (!file_fp || !proc_fp) {
		fprintf(stderr, "Can't open %s\n", dest);
		if (file_fp)
			fclose(file_fp);
		if (proc_fp)
			fclose(proc_fp);
		return false;
	}
	while (true) {
		c = fgetc(proc_fp);
		if (!c || c == EOF)
			break;
		if (fputc(c, file_fp) == EOF) {
			c = EOF;
			break;
		}
	}
	fclose(proc_fp);
	fclose(file_fp);
	return !c;
}

/**
 * parse_args - Parse command line arguments.
 *
 * @argc: argc passed to main().
 * @argv: argv passed to main().
 *
 * Returns nothing.
 */
static void parse_args(int argc, char *argv[])
{
	int i;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];
		char *cp = strchr(ptr, ':');
		if (*ptr == '/') {
			if (ccs_network_mode || w.offline_mode)
				goto usage;
			w.policy_dir = ptr;
			w.offline_mode = true;
		} else if (*ptr == '<') {
			if (current_ns || strchr(ptr, ' ') ||
			    !ccs_domain_def(ptr))
				goto usage;
			current_ns = ccs_savename(ptr);
		} else if (cp) {
			*cp++ = '\0';
			if (ccs_network_mode || w.offline_mode)
				goto usage;
			ccs_network_ip = inet_addr(ptr);
			ccs_network_port = htons(atoi(cp));
			ccs_network_mode = true;
			if (!ccs_check_remote_host())
				exit(1);
		} else if (!strcmp(ptr, "e"))
			active = SCREEN_EXCEPTION_LIST;
		else if (!strcmp(ptr, "d"))
			active = SCREEN_DOMAIN_LIST;
		else if (!strcmp(ptr, "p"))
			active = SCREEN_PROFILE_LIST;
		else if (!strcmp(ptr, "m"))
			active = SCREEN_MANAGER_LIST;
		else if (!strcmp(ptr, "s"))
			active = SCREEN_STAT_LIST;
		else if (!strcmp(ptr, "n"))
			active = SCREEN_NS_LIST;
		else if (!strcmp(ptr, "readonly"))
			w.readonly_mode = true;
		else if (sscanf(ptr, "refresh=%u", &w.refresh_interval) != 1) {
usage:
			printf("Usage: %s [e|d|p|m|s|n] [readonly] "
			       "[refresh=interval] [<namespace>]"
			       "[{policy_dir|remote_ip:remote_port}]\n",
			       argv[0]);
			exit(1);
		}
	}
	if (!current_ns)
		current_ns = ccs_savename("<kernel>");
	w.previous_screen = active;
}

/**
 * load_offline - Load policy for offline mode.
 *
 * Returns nothing.
 */
static void load_offline(void)
{
	int pipe_fd[2] = { EOF, EOF };
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = { };
	socklen_t size = sizeof(addr);
	/*
	 * Use PF_INET socket as a method for communicating with child task
	 * so that we can use same method for child task and
	 * ccs-editpolicy-agent.
	 */
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (chdir(w.policy_dir) || chdir("policy/current/")) {
		fprintf(stderr, "Directory %s/policy/current/ doesn't "
			"exist.\n", w.policy_dir);
		exit(1);
	}
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) || listen(fd, 5)
	    || getsockname(fd, (struct sockaddr *) &addr, &size)) {
		fprintf(stderr, "Can't create listener socket.\n");
		exit(1);
	}
	ccs_network_ip = addr.sin_addr.s_addr;
	ccs_network_port = addr.sin_port;
	ccs_network_mode = true;
	/*
	 * Use pipe as a notifier for termination.
	 *
	 * Sending signals by remembering child task's PID would be possible.
	 * But such approach will not work if main task exited unexpectedly
	 * (e.g. SIGKILL). Since pipe_fd[1] is guaranteed to be closed no
	 * matter how main task exits, pipe approach is more reliable for
	 * telling the child task to exit.
	 */
	if (pipe(pipe_fd)) {
		fprintf(stderr, "Can't create pipe.\n");
		exit(1);
	}
	switch (fork()) {
	case 0:
		if (close(pipe_fd[1]) ||
		    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK))
			_exit(1);
		editpolicy_offline_daemon(fd, pipe_fd[0]);
		_exit(1);
	case -1:
		fprintf(stderr, "fork()\n");
		exit(1);
	}
	if (close(fd) || close(pipe_fd[0]))
		exit(1);
	copy_file("profile.conf", CCS_PROC_POLICY_PROFILE);
	copy_file("exception_policy.conf",
		  CCS_PROC_POLICY_EXCEPTION_POLICY);
	copy_file("domain_policy.conf", CCS_PROC_POLICY_DOMAIN_POLICY);
	copy_file("manager.conf", CCS_PROC_POLICY_MANAGER);
	if (chdir("..")) {
		fprintf(stderr, "Directory %s/policy/ doesn't exist.\n",
			w.policy_dir);
		exit(1);
	}
}

/**
 * load_readwrite - Check that this program can write to /sys/kernel/security/tomoyo/ interface.
 *
 * Returns nothing.
 */
static void load_readwrite(void)
{
	const int fd1 = open2(CCS_PROC_POLICY_EXCEPTION_POLICY, O_RDWR);
	const int fd2 = open2(CCS_PROC_POLICY_DOMAIN_POLICY, O_RDWR);
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

/**
 * save_offline - Save policy for offline mode.
 *
 * Returns nothing.
 */
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
			fprintf(stderr, "Can't create %s/%s .\n", w.policy_dir,
				stamp);
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
	    !save_to_file(CCS_PROC_POLICY_PROFILE, "profile.conf") ||
	    !save_to_file(CCS_PROC_POLICY_MANAGER, "manager.conf") ||
	    !save_to_file(CCS_PROC_POLICY_EXCEPTION_POLICY,
			      "exception_policy.conf") ||
	    !save_to_file(CCS_PROC_POLICY_DOMAIN_POLICY,
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
	memset(&w, 0, sizeof(w));
	memset(&p, 0, sizeof(p));
	parse_args(argc, argv);
	editpolicy_init_keyword_map();
	if (w.offline_mode)
		load_offline();
	if (ccs_network_mode)
		goto start;
	ccs_mount_securityfs();
	if (chdir(CCS_PROC_POLICY_DIR)) {
		fprintf(stderr,
			"You can't use this editor for this kernel.\n");
		return 1;
	}
	if (!w.readonly_mode)
		load_readwrite();
start:
	initscr();
	editpolicy_color_init();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	getmaxyx(stdscr, w.height, w.width);
	if (w.refresh_interval) {
		signal(SIGALRM, sigalrm_handler);
		alarm(w.refresh_interval);
		timeout(1000);
	}
	rl.max = 20;
	rl.history = ccs_malloc(rl.max * sizeof(const char *));
	while (active < MAX_SCREEN_TYPE) {
		enum screen_type next;
		resize_window();
		next = generic_list_loop();
		if (next != active)
			w.previous_screen = active;
		active = next;
	}
	alarm(0);
	clear();
	move(0, 0);
	refresh();
	endwin();
	if (w.offline_mode && !w.readonly_mode)
		save_offline();
	clear_domain_policy();
	return 0;
}
