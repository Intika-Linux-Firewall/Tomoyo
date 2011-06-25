/*
 * editpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.2   2011/06/20
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

/* Domain policy. */
struct ccs_domain_policy3 ccs_dp = { };

/* Readline history. */
static struct ccs_readline_data ccs_rl = { };

/* Array of "path_group" entries. */
struct ccs_path_group_entry *ccs_path_group_list = NULL;
/* Length of ccs_path_group_list array. */
int ccs_path_group_list_len = 0;
/* Array of string ACL entries. */
struct ccs_generic_acl *ccs_gacl_list = NULL;
/* Length of ccs_generic_list array. */
static int ccs_gacl_list_count = 0;

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
enum ccs_screen_type ccs_current_screen = CCS_SCREEN_DOMAIN_LIST;
/* Previously active screen's index. */
static enum ccs_screen_type ccs_previous_screen = CCS_SCREEN_DOMAIN_LIST;
/*
 * Array of "initialize_domain"/"no_initialize_domain"/"keep_domain"/
 * "no_keep_domain" entries.
 */
static struct ccs_transition_control_entry *ccs_transition_control_list = NULL;
/* Length of ccs_transition_control_list array. */
static int ccs_transition_control_list_len = 0;
/* Sort profiles by value? */
static _Bool ccs_profile_sort_type = false;
/* Number of domain jump source domains. */
static int ccs_unnumbered_domain_count = 0;
/* Width of CUI screen. */
static int ccs_window_width = 0;
/* Height of CUI screen. */
static int ccs_window_height = 0;
/* Cursor info for CUI screen. */
struct ccs_screen ccs_screen[CCS_MAXSCREEN] = { };
/* Number of entries available on current screen. */
int ccs_list_item_count = 0;
/* Lines available for displaying ACL entries.  */
static int ccs_body_lines = 0;
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
/* Start from the first line when showing ACL screen? */
static _Bool ccs_no_restore_cursor = false;
static _Bool ccs_force_move_cursor = false;

/* Namespace to use. */
const struct ccs_path_info *ccs_current_ns = NULL;

/* Domain transition coltrol keywords. */
static const char *ccs_transition_type[CCS_MAX_TRANSITION_TYPE] = {
	[CCS_TRANSITION_CONTROL_RESET]         = "reset_domain ",
	[CCS_TRANSITION_CONTROL_NO_RESET]      = "no_reset_domain ",
	[CCS_TRANSITION_CONTROL_INITIALIZE]    = "initialize_domain ",
	[CCS_TRANSITION_CONTROL_NO_INITIALIZE] = "no_initialize_domain ",
	[CCS_TRANSITION_CONTROL_KEEP]          = "keep_domain ",
	[CCS_TRANSITION_CONTROL_NO_KEEP]       = "no_keep_domain ",
};

static FILE *ccs_editpolicy_open_write(const char *filename);
static _Bool ccs_deleted_domain(const int index);
static _Bool ccs_domain_unreachable(const int index);
static _Bool ccs_jump_source(const int index);
static _Bool ccs_jump_target(const int index);
static _Bool ccs_keeper_domain(const int index);
static _Bool ccs_select_item(const int index);
static _Bool ccs_show_command_key(const enum ccs_screen_type screen,
				  const _Bool readonly);
static const char *ccs_eat(const char *str);
static const char *ccs_get_last_name(const int index);
static const struct ccs_transition_control_entry *ccs_transition_control
(const struct ccs_path_info *ns, const char *domainname, const char *program);
static enum ccs_screen_type ccs_generic_list_loop(void);
static enum ccs_screen_type ccs_select_window(const int current);
static int ccs_add_path_group_entry(const struct ccs_path_info *ns,
				    const char *group_name,
				    const char *member_name,
				    const _Bool is_delete);
static int ccs_add_path_group_policy(const struct ccs_path_info *ns,
				     char *data, const _Bool is_delete);
static int ccs_add_transition_control_entry(const struct ccs_path_info *ns,
					    const char *domainname,
					    const char *program, const enum
					    ccs_transition_type type);
static int ccs_add_transition_control_policy(const struct ccs_path_info *ns,
					     char *data, const enum
					     ccs_transition_type type);
static int ccs_count(const unsigned char *array, const int len);
static int ccs_count2(const struct ccs_generic_acl *array, int len);
static int ccs_domainname_attribute_compare(const void *a, const void *b);
static int ccs_gacl_compare(const void *a, const void *b);
static int ccs_gacl_compare0(const void *a, const void *b);
static int ccs_profile_entry_compare(const void *a, const void *b);
static int ccs_show_acl_line(const int index, const int list_indent);
static int ccs_show_domain_line(const int index);
static int ccs_show_literal_line(const int index);
static int ccs_show_profile_line(const int index);
static int ccs_show_stat_line(const int index);
static int ccs_string_acl_compare(const void *a, const void *b);
static void ccs_add_entry(void);
static void ccs_adjust_cursor_pos(const int item_count);
static void ccs_assign_djs(const struct ccs_path_info *ns,
			   const char *domainname, const char *program,
			   const bool is_root);
static void ccs_copy_file(const char *source, const char *dest);
static void ccs_delete_entry(const int index);
static void ccs_down_arrow_key(void);
static void ccs_find_entry(const _Bool input, const _Bool forward,
			   const int current);
static void ccs_page_down_key(void);
static void ccs_page_up_key(void);
static void ccs_read_domain_and_exception_policy(void);
static void ccs_read_generic_policy(void);
static void ccs_resize_window(void);
static void ccs_set_cursor_pos(const int index);
static void ccs_set_level(const int current);
static void ccs_set_profile(const int current);
static void ccs_set_quota(const int current);
static void ccs_show_current(void);
static void ccs_show_list(void);
static void ccs_sigalrm_handler(int sig);
static void ccs_up_arrow_key(void);

/**
 * ccs_find_domain3 - Find a domain by name and other attributes.
 *
 * @domainname: Name of domain to find.
 * @target:     Name of target to find. Maybe NULL.
 * @is_dd:      True if the domain is marked as deleted, false otherwise.
 *
 * Returns index number (>= 0) if found, EOF otherwise.
 */
static int ccs_find_domain3(const char *domainname, const char *target,
			    const _Bool is_dd)
{
	int i;
	for (i = 0; i < ccs_dp.list_len; i++) {
		const struct ccs_domain *ptr = &ccs_dp.list[i];
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
 * ccs_assign_domain3 - Create a domain by name and other attributes.
 *
 * @domainname: Name of domain to find.
 * @target:     Name of target domain if the domain acts as domain jump source,
 *              NULL otherwise.
 * @is_dd:      True if the domain is marked as deleted, false otherwise.
 *
 * Returns index number (>= 0) if created or already exists, abort otherwise.
 */
static int ccs_assign_domain3(const char *domainname, const char *target,
			      const _Bool is_dd)
{
	struct ccs_domain *ptr;
	int index = ccs_find_domain3(domainname, target, is_dd);
	if (index >= 0)
		return index;
	index = ccs_dp.list_len++;
	ccs_dp.list = ccs_realloc(ccs_dp.list, ccs_dp.list_len *
				  sizeof(struct ccs_domain));
	ptr = &ccs_dp.list[index];
	memset(ptr, 0, sizeof(*ptr));
	ptr->domainname = ccs_savename(domainname);
	if (target)
		ptr->target = ccs_savename(target);
	ptr->is_dd = is_dd;
	return index;
}

/**
 * ccs_add_string_entry - Add string entry to a domain.
 *
 * @entry: String to add.
 * @index: Index in the @dp array.
 *
 * Returns 0 if successfully added or already exists, -EINVAL otherwise.
 */
static int ccs_add_string_entry3(const char *entry, const int index)
{
	const struct ccs_path_info **acl_ptr;
	int acl_count;
	const struct ccs_path_info *cp;
	int i;
	if (index < 0 || index >= ccs_dp.list_len) {
		fprintf(stderr, "ERROR: domain is out of range.\n");
		return -EINVAL;
	}
	if (!entry || !*entry)
		return -EINVAL;
	cp = ccs_savename(entry);

	acl_ptr = ccs_dp.list[index].string_ptr;
	acl_count = ccs_dp.list[index].string_count;

	/* Check for the same entry. */
	for (i = 0; i < acl_count; i++)
		/* Faster comparison, for they are ccs_savename'd. */
		if (cp == acl_ptr[i])
			return 0;

	acl_ptr = ccs_realloc(acl_ptr, (acl_count + 1) *
			      sizeof(const struct ccs_path_info *));
	acl_ptr[acl_count++] = cp;
	ccs_dp.list[index].string_ptr = acl_ptr;
	ccs_dp.list[index].string_count = acl_count;
	return 0;
}

/**
 * ccs_clear_domain_policy3 - Clean up domain policy.
 *
 * Returns nothing.
 */
static void ccs_clear_domain_policy3(void)
{
	int index;
	for (index = 0; index < ccs_dp.list_len; index++) {
		free(ccs_dp.list[index].string_ptr);
		ccs_dp.list[index].string_ptr = NULL;
		ccs_dp.list[index].string_count = 0;
	}
	free(ccs_dp.list);
	ccs_dp.list = NULL;
	ccs_dp.list_len = 0;
}

/**
 * ccs_is_same_namespace - Check namespace.
 *
 * @domain: Domainname.
 * @ns:     Namespace.
 *
 * Returns true if same namespace, false otherwise.
 */
static _Bool ccs_is_same_namespace(const char *domain,
				   const struct ccs_path_info *ns)
{
	return !strncmp(domain, ns->name, ns->total_len) &&
		(domain[ns->total_len] == ' ' || !domain[ns->total_len]);
}

/**
 * ccs_is_current_namespace - Check namespace.
 *
 * @line: Line to check namespace.
 *
 * Returns true if this line deals current namespace, false otherwise.
 */
static _Bool ccs_is_current_namespace(const char *line)
{
	return ccs_is_same_namespace(line, ccs_current_ns);
}

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
 * ccs_get_ns - Get namespace component from domainname.
 *
 * @domainname: A domainname.
 *
 * Returns the namespace component of @domainname.
 */
static const struct ccs_path_info *ccs_get_ns(const char *domainname)
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
 * ccs_get_last_word - Get last component of a line.
 *
 * @line: A line of words.
 *
 * Returns the last component of the line.
 */
static const char *ccs_get_last_word(const char *line)
{
	const char *cp = strrchr(line, ' ');
	if (cp)
		return cp + 1;
	return line;
}

/**
 * ccs_get_last_name - Get last component of a domainname.
 *
 * @index: Index in the domain policy.
 *
 * Returns the last component of the domainname.
 */
static const char *ccs_get_last_name(const int index)
{
	return ccs_get_last_word(ccs_dp.list[index].domainname->name);
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
 * ccs_keeper_domain - Check whether the given domain is marked as keeper or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is marked as "keep_domain",
 * false otherwise.
 */
static _Bool ccs_keeper_domain(const int index)
{
	return ccs_dp.list[index].is_dk;
}

/**
 * ccs_jump_source - Check whether the given domain is marked as jump source or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is marked as domain jump source,
 * false otherwise.
 */
static _Bool ccs_jump_source(const int index)
{
	return ccs_dp.list[index].target != NULL;
}

/**
 * ccs_jump_target - Check whether the given domain is marked as jump target or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is a domain jump target, false otherwise.
 */
static _Bool ccs_jump_target(const int index)
{
	return ccs_dp.list[index].is_djt;
}

/**
 * ccs_domain_unreachable - Check whether the given domain is marked as unreachable or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is unreachable, false otherwise.
 *
 * TODO: Check "task auto_domain_transition" and
 * "task manual_domain_transition" which allow other domains to reach
 * the given domain.
 */
static _Bool ccs_domain_unreachable(const int index)
{
	return ccs_dp.list[index].is_du;
}

/**
 * ccs_deleted_domain - Check whether the given domain is marked as deleted or not.
 *
 * @index: Index in the domain policy.
 *
 * Returns true if the given domain is marked as deleted, false otherwise.
 */
static _Bool ccs_deleted_domain(const int index)
{
	return ccs_dp.list[index].is_dd;
}

/**
 * ccs_gacl_compare0 - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int ccs_gacl_compare0(const void *a, const void *b)
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

/**
 * ccs_string_acl_compare - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int ccs_string_acl_compare(const void *a, const void *b)
{
	const struct ccs_generic_acl *a0 = (struct ccs_generic_acl *) a;
	const struct ccs_generic_acl *b0 = (struct ccs_generic_acl *) b;
	const char *a1 = a0->operand;
	const char *b1 = b0->operand;
	return strcmp(a1, b1);
}

/**
 * ccs_add_transition_control_policy - Add "reset_domain"/"no_reset_domain"/"initialize_domain"/"no_initialize_domain"/"keep_domain"/"no_keep_domain" entries.
 *
 * @ns:   Pointer to "const struct ccs_path_info".
 * @data: Line to parse.
 * @type: One of values in "enum ccs_transition_type".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_add_transition_control_policy
(const struct ccs_path_info *ns, char *data,
 const enum ccs_transition_type type)
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
	return ccs_add_transition_control_entry(ns, domainname, data, type);
}

/**
 * ccs_add_path_group_policy - Add "path_group" entry.
 *
 * @ns:        Pointer to "const struct ccs_path_info".
 * @data:      Line to parse.
 * @is_delete: True if it is delete request, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_add_path_group_policy(const struct ccs_path_info *ns,
				     char *data, const _Bool is_delete)
{
	char *cp = strchr(data, ' ');
	if (!cp)
		return -EINVAL;
	*cp++ = '\0';
	return ccs_add_path_group_entry(ns, data, cp, is_delete);
}

/**
 * ccs_assign_djs - Assign domain jump source domain.
 *
 * @ns:         Pointer to "const struct ccs_path_info".
 * @domainname: Domainname.
 * @program:    Program name.
 * @is_root:    True if root of namespace, false otherwise.
 */
static void ccs_assign_djs(const struct ccs_path_info *ns,
			   const char *domainname, const char *program,
			   const bool is_root)
{
	const struct ccs_transition_control_entry *d_t =
		ccs_transition_control(ns, domainname, program);
	/*
	 * Don't create source domains under root of namespace because they
	 * will become target domains. However, create them under root of
	 * namespace anyway if namespace jump, for we need to indicate it.
	 */
	if (!d_t)
		return;
	if ((!is_root && d_t->type == CCS_TRANSITION_CONTROL_INITIALIZE) ||
	    d_t->type == CCS_TRANSITION_CONTROL_RESET) {
		char *line;
		char *cp;
		ccs_get();
		if (d_t->type == CCS_TRANSITION_CONTROL_INITIALIZE)
			line = ccs_shprintf("%s %s", domainname, program);
		else
			line = ccs_shprintf("%s <%s>", domainname, program);
		ccs_normalize_line(line);
		cp = ccs_strdup(line);
		if (d_t->type == CCS_TRANSITION_CONTROL_INITIALIZE)
			line = ccs_shprintf("%s %s", ns->name, program);
		else
			line = ccs_shprintf("<%s>", program);
		ccs_assign_domain3(cp, line, false);
		free(cp);
		ccs_put();
	}
}

static inline unsigned int ccs_depth(const char *domain)
{
	unsigned int depth = 0;
	while (*domain)
		if (*domain++ == ' ')
			depth++;
	return depth;
}

static inline int ccs_sign(const int v)
{
	if (v > 0)
		return 1;
	if (v < 0)
		return -1;
	return 0;
}

/**
 * ccs_domainname_attribute_compare - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int ccs_domainname_attribute_compare(const void *a, const void *b)
{
#if 1
	const struct ccs_domain *a0 = a;
	const struct ccs_domain *b0 = b;
	char *name1 = NULL;
	char *name2 = NULL;
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
	if (k) {
		free(name1);
		free(name2);
		return k;
	}
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
	free(name1);
	free(name2);
	return k;
#elif 1
	const struct ccs_domain *a0 = a;
	const struct ccs_domain *b0 = b;
	char *name1 = NULL;
	char *name2 = NULL;
	char *line;
	char *cp;
	int k;
	ccs_get();
	if (a0->target) {
		name1 = ccs_strdup(a0->domainname->name);
		cp = strrchr(name1, ' ');
		*cp = '\0';
		line = ccs_shprintf("%s %s", name1, a0->target->name);
		free(name1);
	} else
		line = ccs_shprintf("%s", a0->domainname->name);
	name1 = ccs_strdup(line);
	if (b0->target) {
		name2 = ccs_strdup(b0->domainname->name);
		cp = strrchr(name2, ' ');
		*cp = '\0';
		line = ccs_shprintf("%s %s", name2, b0->target->name);
		free(name2);
	} else
		line = ccs_shprintf("%s", b0->domainname->name);
	name2 = ccs_strdup(line);
	ccs_put();
	k = strcmp(name1, name2);
	free(name1);
	free(name2);
	return k;
#endif
}

/**
 * ccs_find_target_domain - Find the domain jump target domain.
 *
 * @index: Index in the domain policy.
 *
 * Returns index of the domain if found in a current namespace,
 * -2 if found in a different namespace, EOF otherwise.
 */
static int ccs_find_target_domain(const int index)
{
	const char *cp = ccs_dp.list[index].target->name;
	if (!ccs_is_current_namespace(cp)) {
		if (ccs_dp.list[index].is_du)
			return EOF;
		return -2;
	}
	return ccs_find_domain3(cp, NULL, false);
}

/**
 * ccs_show_domain_line - Show a line of the domain transition tree.
 *
 * @index: Index in the domain policy.
 *
 * Returns length of the printed line.
 */
static int ccs_show_domain_line(const int index)
{
	int tmp_col = 0;
	const struct ccs_transition_control_entry *transition_control;
	char *line;
	const char *sp;
	const int number = ccs_dp.list[index].number;
	int redirect_index;
	const bool is_djs = ccs_jump_source(index);
	const bool is_deleted = ccs_deleted_domain(index);
	if (number >= 0) {
		printw("%c%4d:%3u %c%c%c ", ccs_dp.list_selected[index] ? '&' :
		       ' ', number, ccs_dp.list[index].profile,
		       ccs_keeper_domain(index) ? '#' : ' ',
		       ccs_jump_target(index) ? '*' : ' ',
		       ccs_domain_unreachable(index) ? '!' : ' ');
	} else
		printw("              ");
	tmp_col += 14;
	sp = ccs_dp.list[index].domainname->name;
	while (true) {
		const char *cp = strchr(sp, ' ');
		if (!cp)
			break;
		printw("%s", ccs_eat("    "));
		tmp_col += 4;
		sp = cp + 1;
	}
	if (is_djs) {
		printw("%s", ccs_eat("=> "));
		tmp_col += 3;
		sp = ccs_dp.list[index].target->name;
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
	/*
	if (is_djs) {
		printw("%s", ccs_eat(" [ "));
		printw("%s", ccs_dp.list[index].domainname->name);
		printw("%s", ccs_eat(" ] "));
		tmp_col += 6 + ccs_dp.list[index].domainname->total_len;
	}
	*/
	transition_control = ccs_dp.list[index].d_t;
	if (!transition_control || is_djs)
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
	if (!is_djs)
		goto done;
	ccs_get();
	redirect_index = ccs_find_target_domain(index);
	if (redirect_index >= 0)
		line = ccs_shprintf(" ( -> %d )",
				    ccs_dp.list[redirect_index].number);
	else if (redirect_index == EOF)
		line = ccs_shprintf(" ( -> Not Found )");
	else
		line = ccs_shprintf(" ( -> Namespace jump )");
	printw("%s", ccs_eat(line));
	tmp_col += strlen(line);
	ccs_put();
done:
	return tmp_col;
}

/**
 * ccs_show_acl_line - Print an ACL line.
 *
 * @index:       Index in the generic list.
 * @list_indent: Indent size.
 *
 * Returns length of the printed line.
 */
static int ccs_show_acl_line(const int index, const int list_indent)
{
	const enum ccs_editpolicy_directives directive =
		ccs_gacl_list[index].directive;
	const char *cp1 = ccs_directives[directive].alias;
	const char *cp2 = ccs_gacl_list[index].operand;
	int len = list_indent - ccs_directives[directive].alias_len;
	printw("%c%4d: %s ",
	       ccs_gacl_list[index].selected ? '&' : ' ',
	       index, ccs_eat(cp1));
	while (len-- > 0)
		printw("%s", ccs_eat(" "));
	printw("%s", ccs_eat(cp2));
	return strlen(cp1) + strlen(cp2) + 8 + list_indent;
}

/**
 * ccs_show_profile_line - Print a profile line.
 *
 * @index: Index in the generic list.
 *
 * Returns length of the printed line.
 */
static int ccs_show_profile_line(const int index)
{
	const char *cp = ccs_gacl_list[index].operand;
	const u16 profile = ccs_gacl_list[index].directive;
	char number[8] = "";
	if (profile <= 256)
		snprintf(number, sizeof(number) - 1, "%3u-", profile);
	printw("%c%4d: %s", ccs_gacl_list[index].selected ? '&' : ' ',
	       index, ccs_eat(number));
	printw("%s ", ccs_eat(cp));
	return strlen(number) + strlen(cp) + 8;
}

/**
 * ccs_show_literal_line - Print a literal line.
 *
 * @index: Index in the generic list.
 *
 * Returns length of the printed line.
 */
static int ccs_show_literal_line(const int index)
{
	const char *cp = ccs_gacl_list[index].operand;
	printw("%c%4d: %s ",
	       ccs_gacl_list[index].selected ? '&' : ' ',
	       index, ccs_eat(cp));
	return strlen(cp) + 8;
}

/**
 * ccs_show_stat_line - Print a statistics line.
 *
 * @index: Index in the generic list.
 *
 * Returns length of the printed line.
 */
static int ccs_show_stat_line(const int index)
{
	char *line;
	unsigned int now;
	ccs_get();
	line = ccs_shprintf("%s", ccs_gacl_list[index].operand);
	if (line[0])
		printw("%s", ccs_eat(line));
	now = strlen(line);
	ccs_put();
	return now;
}

/**
 * ccs_show_command_key - Print help screen.
 *
 * @screen:   Currently selected screen.
 * @readonly: True if readonly_mopde, false otherwise.
 *
 * Returns true to continue, false to quit.
 */
static _Bool ccs_show_command_key(const enum ccs_screen_type screen,
				  const _Bool readonly)
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
	case CCS_SCREEN_NS_LIST:
		if (!readonly)
			printw("A/a        Add a new namespace.\n");
		break;
	case CCS_SCREEN_DOMAIN_LIST:
		if (ccs_domain_sort_type) {
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
	case CCS_SCREEN_STAT_LIST:
		if (!readonly)
			printw("S/s        Set memory quota of selected "
			       "items.\n");
		break;
	case CCS_SCREEN_PROFILE_LIST:
		if (!readonly)
			printw("S/s        Set mode of selected items.\n");
		break;
	default:
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
	default:
		break;
	}
	switch (screen) {
	case CCS_SCREEN_PROFILE_LIST:
		if (!readonly)
			printw("A/a        Define a new profile.\n");
	default:
		break;
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
 * ccs_set_error - Set error line's caption.
 *
 * @filename: Filename to print. Maybe NULL.
 *
 * Returns nothing.
 */
static void ccs_set_error(const char *filename)
{
	if (filename) {
		const int len = strlen(filename) + 128;
		ccs_last_error = ccs_realloc2(ccs_last_error, len);
		snprintf(ccs_last_error, len - 1, "Can't open %s .", filename);
	} else {
		free(ccs_last_error);
		ccs_last_error = NULL;
	}
}

/**
 * ccs_editpolicy_open_write - Wrapper for ccs_open_write().
 *
 * @filename: File to open for writing.
 *
 * Returns pointer to "FILE" on success, NULL otherwise.
 *
 * Since CUI policy editor screen provides a line for printing error message,
 * this function sets error line if failed. Also, this function returns NULL if
 * readonly mode.
 */
static FILE *ccs_editpolicy_open_write(const char *filename)
{
	FILE *fp = ccs_open_write(filename);
	if (!fp)
		ccs_set_error(filename);
	return fp;
}

/**
 * ccs_editpolicy_open_read - Wrapper for ccs_open_read().
 *
 * @filename: File to open for reading.
 *
 * Returns pointer to "FILE" on success, NULL otherwise.
 *
 * Since CUI policy editor screen provides a line for printing error message,
 * this function sets error line if failed.
 */
static FILE *ccs_editpolicy_open_read(const char *filename)
{
	FILE *fp = ccs_open_read(filename);
	if (!fp)
		ccs_set_error(filename);
	return fp;
}

/**
 * ccs_open2 - Wrapper for open().
 *
 * @filename: File to open.
 * @mode:     Flags to passed to open().
 *
 * Returns file descriptor on success, EOF otherwise.
 *
 * Since CUI policy editor screen provides a line for printing error message,
 * this function sets error line if failed.
 */
static int ccs_open2(const char *filename, int mode)
{
	const int fd = open(filename, mode);
	if (fd == EOF && errno != ENOENT)
		ccs_set_error(filename);
	return fd;
}

/**
 * ccs_sigalrm_handler - Callback routine for timer interrupt.
 *
 * @sig: Signal number. Not used.
 *
 * Returns nothing.
 *
 * This function is called when ccs_refresh_interval is non-zero. This function
 * marks current screen to reload. Also, this function reenables timer event.
 */
static void ccs_sigalrm_handler(int sig)
{
	ccs_need_reload = true;
	alarm(ccs_refresh_interval);
}

/**
 * ccs_eat - Shift string data before displaying.
 *
 * @str: String to be displayed.
 *
 * Returns shifted string.
 */
static const char *ccs_eat(const char *str)
{
	while (*str && ccs_eat_col) {
		str++;
		ccs_eat_col--;
	}
	return str;
}

/**
 * ccs_transition_control - Find domain transition control.
 *
 * @ns:         Pointer to "const struct ccs_path_info".
 * @domainname: Domainname.
 * @program:    Program name.
 *
 * Returns pointer to "const struct ccs_transition_control_entry" if found one,
 * NULL otherwise.
 */
static const struct ccs_transition_control_entry *ccs_transition_control
(const struct ccs_path_info *ns, const char *domainname, const char *program)
{
	int i;
	u8 type;
	struct ccs_path_info domain;
	struct ccs_path_info last_name;
	domain.name = domainname;
	last_name.name = ccs_get_last_word(domainname);
	ccs_fill_path_info(&domain);
	ccs_fill_path_info(&last_name);
	for (type = 0; type < CCS_MAX_TRANSITION_TYPE; type++) {
next:
		for (i = 0; i < ccs_transition_control_list_len; i++) {
			struct ccs_transition_control_entry *ptr
				= &ccs_transition_control_list[i];
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
			if (type == CCS_TRANSITION_CONTROL_NO_RESET) {
				/*
				 * Do not check for reset_domain if
				 * no_reset_domain matched.
				 */
				type = CCS_TRANSITION_CONTROL_NO_INITIALIZE;
				goto next;
			}
			if (type == CCS_TRANSITION_CONTROL_NO_INITIALIZE) {
				/*
				 * Do not check for initialize_domain if
				 * no_initialize_domain matched.
				 */
				type = CCS_TRANSITION_CONTROL_NO_KEEP;
				goto next;
			}
			if (type == CCS_TRANSITION_CONTROL_RESET ||
			    type == CCS_TRANSITION_CONTROL_INITIALIZE ||
			    type == CCS_TRANSITION_CONTROL_KEEP)
				return ptr;
			else
				return NULL;
		}
	}
	return NULL;
}

/**
 * ccs_profile_entry_compare -  strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int ccs_profile_entry_compare(const void *a, const void *b)
{
	const struct ccs_generic_acl *a0 = (struct ccs_generic_acl *) a;
	const struct ccs_generic_acl *b0 = (struct ccs_generic_acl *) b;
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

/**
 * ccs_add_generic_entry - Add text lines.
 *
 * @line:      Line to add.
 * @directive: One of values in "enum ccs_editpolicy_directives".
 *
 * Returns true if this line deals current namespace, false otherwise.
 */
static void ccs_add_generic_entry(const char *line, const enum
				  ccs_editpolicy_directives directive)
{
	int i;
	for (i = 0; i < ccs_gacl_list_count; i++)
		if (ccs_gacl_list[i].directive == directive &&
		    !strcmp(line, ccs_gacl_list[i].operand))
			return;
	i = ccs_gacl_list_count++;
	ccs_gacl_list = ccs_realloc(ccs_gacl_list, ccs_gacl_list_count *
				    sizeof(struct ccs_generic_acl));
	ccs_gacl_list[i].directive = directive;
	ccs_gacl_list[i].selected = 0;
	ccs_gacl_list[i].operand = ccs_strdup(line);
}

/**
 * ccs_read_generic_policy - Read policy data other than domain policy.
 *
 * Returns nothing.
 */
static void ccs_read_generic_policy(void)
{
	FILE *fp = NULL;
	_Bool flag = false;
	const _Bool is_kernel_ns = !strcmp(ccs_current_ns->name, "<kernel>");
	while (ccs_gacl_list_count)
		free((void *) ccs_gacl_list[--ccs_gacl_list_count].operand);
	if (ccs_current_screen == CCS_SCREEN_ACL_LIST) {
		if (ccs_network_mode)
			/* We can read after write. */
			fp = ccs_editpolicy_open_write(ccs_policy_file);
		else
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
	} else if (ccs_current_screen == CCS_SCREEN_NS_LIST) {
		ccs_add_generic_entry("<kernel>", CCS_DIRECTIVE_NONE);
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
		char *line = ccs_freadline_unpack(fp);
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
		if (ccs_current_screen == CCS_SCREEN_EXCEPTION_LIST ||
		    ccs_current_screen == CCS_SCREEN_PROFILE_LIST) {
			if (*line == '<') {
				cp = strchr(line, ' ');
				if (!cp++ || !ccs_is_current_namespace(line))
					continue;
				memmove(line, cp, strlen(cp) + 1);
			} else if (!is_kernel_ns)
				continue;
		}
		switch (ccs_current_screen) {
		case CCS_SCREEN_EXCEPTION_LIST:
			directive = ccs_find_directive(true, line);
			if (directive == CCS_DIRECTIVE_NONE)
				continue;
			/* Remember groups for ccs_editpolicy_optimize(). */
			if (directive != CCS_DIRECTIVE_PATH_GROUP &&
			    directive != CCS_DIRECTIVE_NUMBER_GROUP &&
			    directive != CCS_DIRECTIVE_ADDRESS_GROUP)
				break;
			cp = ccs_strdup(line);
			if (directive == CCS_DIRECTIVE_PATH_GROUP)
				ccs_add_path_group_policy(ccs_current_ns, cp,
							  false);
			else if (directive == CCS_DIRECTIVE_NUMBER_GROUP)
				ccs_add_number_group_policy(cp, false);
			else
				ccs_add_address_group_policy(cp, false);
			free(cp);
			break;
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
		case CCS_SCREEN_NS_LIST:
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
			directive = CCS_DIRECTIVE_NONE;
			break;
		}
		ccs_add_generic_entry(line, directive);
	}
	ccs_put();
	ccs_freadline_raw = false;
	fclose(fp);
	switch (ccs_current_screen) {
	case CCS_SCREEN_ACL_LIST:
		qsort(ccs_gacl_list, ccs_gacl_list_count,
		      sizeof(struct ccs_generic_acl), ccs_gacl_compare);
		break;
	case CCS_SCREEN_EXCEPTION_LIST:
		qsort(ccs_gacl_list, ccs_gacl_list_count,
		      sizeof(struct ccs_generic_acl),
		      ccs_gacl_compare0);
		break;
	case CCS_SCREEN_PROFILE_LIST:
		qsort(ccs_gacl_list, ccs_gacl_list_count,
		      sizeof(struct ccs_generic_acl),
		      ccs_profile_entry_compare);
		break;
	case CCS_SCREEN_STAT_LIST:
		break;
	default:
		qsort(ccs_gacl_list, ccs_gacl_list_count,
		      sizeof(struct ccs_generic_acl), ccs_string_acl_compare);
	}
}

/**
 * ccs_add_transition_control_entry - Add "reset_domain"/"no_reset_domain"/"initialize_domain"/"no_initialize_domain"/"keep_domain"/ "no_keep_domain" entries.
 *
 * @ns:         Pointer to "const struct ccs_path_info".
 * @domainname: Domainname.
 * @program:    Program name.
 * @type:       One of values in "enum ccs_transition_type".
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int ccs_add_transition_control_entry
(const struct ccs_path_info *ns, const char *domainname, const char *program,
 const enum ccs_transition_type type)
{
	struct ccs_transition_control_entry *ptr;
	if (program && strcmp(program, "any"))
		if (!ccs_correct_path(program))
			return -EINVAL;
	if (domainname && strcmp(domainname, "any"))
		if (!ccs_correct_domain(domainname))
			if (!ccs_correct_path(domainname))
				return -EINVAL;
	ccs_transition_control_list =
		ccs_realloc(ccs_transition_control_list,
			    (ccs_transition_control_list_len + 1) *
			    sizeof(struct ccs_transition_control_entry));
	ptr = &ccs_transition_control_list[ccs_transition_control_list_len++];
	memset(ptr, 0, sizeof(*ptr));
	ptr->ns = ns;
	if (program && strcmp(program, "any"))
		ptr->program = ccs_savename(program);
	if (domainname && strcmp(domainname, "any"))
		ptr->domainname = ccs_savename(domainname);
	ptr->type = type;
	return 0;
}

/**
 * ccs_add_path_group_entry - Add "path_group" entry.
 *
 * @ns:          Pointer to "const struct ccs_path_info".
 * @group_name:  Name of address group.
 * @member_name: Address string.
 * @is_delete:   True if it is delete request, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_add_path_group_entry(const struct ccs_path_info *ns,
				    const char *group_name,
				    const char *member_name,
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
	for (i = 0; i < ccs_path_group_list_len; i++) {
		group = &ccs_path_group_list[i];
		if (group->ns != ns)
			continue;
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
		ccs_path_group_list =
			ccs_realloc(ccs_path_group_list,
				    (ccs_path_group_list_len + 1) *
				    sizeof(struct ccs_path_group_entry));
		group = &ccs_path_group_list[ccs_path_group_list_len++];
		memset(group, 0, sizeof(*group));
		group->ns = ns;
		group->group_name = saved_group_name;
	}
	group->member_name =
		ccs_realloc(group->member_name, (group->member_name_len + 1) *
			    sizeof(const struct ccs_path_info *));
	group->member_name[group->member_name_len++] = saved_member_name;
	return 0;
}

/*
 * List of "task auto_domain_transition" "task manual_domain_transition"
 * "auto_domain_transition=" part.
 */
static char **ccs_jump_list = NULL;
static int ccs_jump_list_len = 0;

/**
 * ccs_add_condition_domain_transition - Add auto_domain_transition= part.
 *
 * @line:  Line to parse.
 * @index: Current domain's index.
 *
 * Returns nothing.
 */
static void ccs_add_condition_domain_transition(char *line, const int index)
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
		 ccs_dp.list[index].domainname->name, cp);
	domainname[sizeof(domainname) - 1] = '\0';
	ccs_normalize_line(domainname);
	ccs_jump_list = ccs_realloc(ccs_jump_list,
				    (ccs_jump_list_len + 1) * sizeof(char *));
	ccs_jump_list[ccs_jump_list_len++] = ccs_strdup(domainname);
	ccs_assign_domain3(domainname, *cp == '<' ? cp : domainname, false);
}

/**
 * ccs_add_acl_domain_transition - Add task acl.
 *
 * @line:  Line to parse.
 * @index: Current domain's index.
 *
 * Returns nothing.
 */
static void ccs_add_acl_domain_transition(char *line, const int index)
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
	ccs_jump_list = ccs_realloc(ccs_jump_list,
				    (ccs_jump_list_len + 1) * sizeof(char *));
	ccs_jump_list[ccs_jump_list_len++] = ccs_strdup(line);
	snprintf(domainname, sizeof(domainname) - 1, "%s  %s",
		 ccs_dp.list[index].domainname->name, ccs_get_last_word(line));
	domainname[sizeof(domainname) - 1] = '\0';
	ccs_normalize_line(domainname);
	ccs_assign_domain3(domainname, line, false);
}

/**
 * ccs_parse_domain_line - Parse an ACL entry in domain policy.
 *
 * @ns:          Pointer to "const struct ccs_path_info".
 * @line:        Line to parse.
 * @index:       Current domain's index.
 * @parse_flags: True if parse use_profile and use_group lines, false
 *               otherwise.
 *
 * Returns nothing.
 */
static void ccs_parse_domain_line(const struct ccs_path_info *ns, char *line,
				  const int index, const bool parse_flags)
{
	ccs_add_condition_domain_transition(line, index);
	if (ccs_str_starts(line, "task auto_execute_handler ") ||
	    ccs_str_starts(line, "task denied_execute_handler ") ||
	    ccs_str_starts(line, "file execute ")) {
		/* Chop off condition part which follows pathname. */
		char *cp = strchr(line, ' ');
		if (cp)
			*cp = '\0';
		if (*line == '@' || ccs_correct_path(line))
			ccs_add_string_entry3(line, index);
	} else if (ccs_str_starts(line, "task auto_domain_transition ") ||
		   ccs_str_starts(line, "task manual_domain_transition ")) {
		ccs_add_acl_domain_transition(line, index);
	} else if (parse_flags) {
		unsigned int profile;
		if (sscanf(line, "use_profile %u", &profile) == 1)
			ccs_dp.list[index].profile = (u8) profile;
		else if (sscanf(line, "use_group %u", &profile) == 1)
			ccs_dp.list[index].group = (u8) profile;
	}
}

/**
 * ccs_parse_exception_line - Parse an ACL entry in exception policy.
 *
 * @ns:   Pointer to "const struct ccs_path_info".
 * @line: Line to parse.
 *
 * Returns nothing.
 */
static void ccs_parse_exception_line(const struct ccs_path_info *ns,
				     char *line)
{
	unsigned int group;
	for (group = 0; group < CCS_MAX_TRANSITION_TYPE; group++) {
		if (!ccs_str_starts(line, ccs_transition_type[group]))
			continue;
		ccs_add_transition_control_policy(ns, line, group);
		return;
	}
	if (ccs_str_starts(line, "path_group "))
		ccs_add_path_group_policy(ns, line, false);
	else if (ccs_str_starts(line, "address_group "))
		ccs_add_address_group_policy(line, false);
	else if (ccs_str_starts(line, "number_group "))
		ccs_add_number_group_policy(line, false);
	else if (sscanf(line, "acl_group %u", &group) == 1 && group < 256) {
		int index;
		line = strchr(line + 10, ' ');
		if (!line++)
			return;
		for (index = 0; index < ccs_dp.list_len; index++) {
			char *cp;
			if (ccs_dp.list[index].group != group)
				continue;
			cp = ccs_strdup(line);
			ccs_parse_domain_line(ns, cp, index, false);
			free(cp);
		}
	}
}

/**
 * ccs_read_domain_and_exception_policy - Read domain policy and exception policy.
 *
 * Returns nothing.
 *
 * Since CUI policy editor screen shows domain jump source domains and
 * unreachable domains, we need to read not only the domain policy but also
 * the exception policy for printing the domain transition tree.
 */
static void ccs_read_domain_and_exception_policy(void)
{
	FILE *fp;
	int i;
	int j;
	int index;
	int max_index;
	static const struct ccs_path_info *ccs_kernel_ns = NULL;
	const struct ccs_path_info *ns;

	while (ccs_jump_list_len)
		free(ccs_jump_list[--ccs_jump_list_len]);
	ccs_clear_domain_policy3();
	ccs_transition_control_list_len = 0;
	ccs_editpolicy_clear_groups();
	if (!ccs_kernel_ns)
		ccs_kernel_ns = ccs_savename("<kernel>");
	ns = ccs_kernel_ns;

	/* Load all domain transition related entries. */
	fp = NULL;
	if (ccs_network_mode)
		/* We can read after write. */
		fp = ccs_editpolicy_open_write(CCS_PROC_POLICY_DOMAIN_POLICY);
	else
		/* Don't set error message if failed. */
		fp = fopen(CCS_PROC_POLICY_DOMAIN_POLICY, "r+");
	if (fp) {
		fprintf(fp, "select transition_only\n");
		if (ccs_network_mode)
			fputc(0, fp);
		fflush(fp);
	} else {
		fp = ccs_editpolicy_open_read(CCS_PROC_POLICY_DOMAIN_POLICY);
	}
	if (fp) {
		index = EOF;
		ccs_get();
		while (true) {
			char *line = ccs_freadline_unpack(fp);
			if (!line)
				break;
			if (*line == '<') {
				ns = ccs_get_ns(line);
				index = ccs_assign_domain3(line, NULL, false);
				continue;
			} else if (index == EOF) {
				continue;
			}
			ccs_parse_domain_line(ns, line, index, true);
		}
		ccs_put();
		fclose(fp);
	}

	/* Load domain transition related entries and group entries. */
	fp = NULL;
	if (ccs_network_mode)
		/* We can read after write. */
		fp = ccs_editpolicy_open_write
			(CCS_PROC_POLICY_EXCEPTION_POLICY);
	else
		/* Don't set error message if failed. */
		fp = fopen(CCS_PROC_POLICY_EXCEPTION_POLICY, "r+");
	if (fp) {
		fprintf(fp, "select transition_only\n");
		if (ccs_network_mode)
			fputc(0, fp);
		fflush(fp);
	} else {
		fp = ccs_editpolicy_open_read
			(CCS_PROC_POLICY_EXCEPTION_POLICY);
	}
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
				ns = ccs_kernel_ns;
			ccs_parse_exception_line(ns, line);
		}
		ccs_put();
		fclose(fp);
	}

	/*
	 * Domain jump sources by "task manual_domain_transition" keyword or
	 * "task auto_domain_transition" keyword or "auto_domain_transition="
	 * part of conditional ACL have been created by now because these
	 * keywords must not refer "path_group" keyword.
	 *
	 * Create domain jump sources for "task auto_execute_handler" keyword
	 * or "task denied_execute_handler" keyword or "file execute" keyword
	 * now because these keywords may refer "path_group" keyword.
	 */
	max_index = ccs_dp.list_len;
	for (index = 0; index < max_index; index++) {
		const char *domainname = ccs_dp.list[index].domainname->name;
		const struct ccs_path_info **string_ptr
			= ccs_dp.list[index].string_ptr;
		const int max_count = ccs_dp.list[index].string_count;
		const bool is_root = !strchr(domainname, ' ');
		/* Do not recursively create domain jump source. */
		if (ccs_dp.list[index].target)
			continue;
		ns = ccs_get_ns(domainname);
		for (i = 0; i < max_count; i++) {
			const struct ccs_path_info *cp = string_ptr[i];
			struct ccs_path_group_entry *group;
			if (cp->name[0] != '@') {
				ccs_assign_djs(ns, domainname, cp->name,
					       is_root);
				continue;
			}
			group = ccs_find_path_group_ns(ns, cp->name + 1);
			if (!group)
				continue;
			for (j = 0; j < group->member_name_len; j++) {
				cp = group->member_name[j];
				ccs_assign_djs(ns, domainname, cp->name,
					       is_root);
			}
		}
	}

	/*
	 * Real domains and domain jump sources have been created by now. Let's
	 * calculate domain jump targets and unreachable domains and missing
	 * domains.
	 */
	max_index = ccs_dp.list_len;

	/*
	 * Find real domains that might be reachable via
	 * "task manual_domain_transition" keyword or
	 * "task auto_domain_transition" keyword or
	 * "auto_domain_transition=" part of conditional ACL.
	 * Such domains are marked with '*'.
	 */
	for (i = 0; i < ccs_jump_list_len; i++) {
		const int index = ccs_find_domain3(ccs_jump_list[i], NULL,
						   false);
		if (index >= 0)
			ccs_dp.list[index].is_djt = true;
	}

	/*
	 * Find real domains that might be reachable via "initialize_domain"
	 * keyword. Such domains are marked with '*'.
	 */
	for (index = 0; index < max_index; index++) {
		const struct ccs_domain *domain = &ccs_dp.list[index];
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
		for (i = 0; i < ccs_transition_control_list_len; i++) {
			struct ccs_transition_control_entry *ptr
				= &ccs_transition_control_list[i];
			if (ptr->type != CCS_TRANSITION_CONTROL_NO_INITIALIZE)
				continue;
			if (!ccs_is_same_namespace(domainname, ptr->ns))
				continue;
			if (ptr->domainname)
				continue;
			if (ptr->program && strcmp(ptr->program->name, cp))
				continue;
			break;
		}
		if (i < ccs_transition_control_list_len)
			continue;
		/*
		 * Check "initialize_domain $program from $domainname" entry.
		 */
		for (i = 0; i < ccs_transition_control_list_len; i++) {
			struct ccs_transition_control_entry *ptr
				= &ccs_transition_control_list[i];
			if (ptr->type != CCS_TRANSITION_CONTROL_INITIALIZE)
				continue;
			if (!ccs_is_same_namespace(domainname, ptr->ns))
				continue;
			if (ptr->program && strcmp(ptr->program->name, cp))
				continue;
			break;
		}
		if (i < ccs_transition_control_list_len)
			ccs_dp.list[index].is_djt = true;
	}

	/*
	 * Find real domains that might suppress domain transition via
	 * "keep_domain" keyword. Such domains are marked with '#'.
	 */
	for (index = 0; index < max_index; index++) {
		const struct ccs_domain *domain = &ccs_dp.list[index];
		const struct ccs_path_info *name = domain->domainname;
		const char *last_name = ccs_get_last_word(name->name);
		/* Ignore domain jump sources. */
		if (domain->target)
			continue;
		/* Check "no_keep_domain any from $domainname" entry. */
		for (i = 0; i < ccs_transition_control_list_len; i++) {
			struct ccs_transition_control_entry *ptr
				= &ccs_transition_control_list[i];
			if (ptr->type != CCS_TRANSITION_CONTROL_NO_KEEP)
				continue;
			if (!ccs_is_same_namespace(name->name, ptr->ns))
				continue;
			if (ptr->program)
				continue;
			if (!ptr->domainname ||
			    !ccs_pathcmp(ptr->domainname, name) ||
			    !strcmp(ptr->domainname->name, last_name))
				break;
		}
		if (i < ccs_transition_control_list_len)
			continue;
		/* Check "keep_domain $program from $domainname" entry. */
		for (i = 0; i < ccs_transition_control_list_len; i++) {
			struct ccs_transition_control_entry *ptr
				= &ccs_transition_control_list[i];
			if (ptr->type != CCS_TRANSITION_CONTROL_KEEP)
				continue;
			if (!ccs_is_same_namespace(name->name, ptr->ns))
				continue;
			if (!ptr->domainname ||
			    !ccs_pathcmp(ptr->domainname, name) ||
			    !strcmp(ptr->domainname->name, last_name))
				break;
		}
		if (i < ccs_transition_control_list_len)
			ccs_dp.list[index].is_dk = true;
	}

	/* Find unreachable domains. Such domains are marked with '!'. */
	for (index = 0; index < max_index; index++) {
		char *line;
		struct ccs_domain *domain = &ccs_dp.list[index];
		/*
		 * Mark domain jump source as unreachable if domain jump target
		 * does not exist.
		 */
		if (domain->target) {
			if (ccs_find_domain3(domain->target->name, NULL,
					     false) == EOF)
				domain->is_du = true;
			continue;
		}
		/* Ignore if domain jump targets. */
		if (domain->is_djt)
			continue;
		ns = ccs_get_ns(ccs_dp.list[index].domainname->name);
		ccs_get();
		line = ccs_shprintf("%s", ccs_dp.list[index].domainname->name);
		while (true) {
			const int index2 = ccs_find_domain3(line, NULL, false);
			const struct ccs_transition_control_entry *d_t;
			char *cp;
			/* Stop traversal if current is jump target. */
			if (index2 >= 0 && ccs_dp.list[index2].is_djt)
				break;
			cp = strrchr(line, ' ');
			if (cp)
				*cp++ = '\0';
			else
				break;
			d_t = ccs_transition_control(ns, line, cp);
			if (d_t)
				domain->d_t = d_t;
		}
		ccs_put();
		if (domain->d_t)
			domain->is_du = true;
	}

	/* Create missing parent domains. */
	for (index = 0; index < max_index; index++) {
		char *line;
		ccs_get();
		line = ccs_shprintf("%s", ccs_dp.list[index].domainname->name);
		while (true) {
			char *cp = strrchr(line, ' ');
			if (!cp)
				break;
			*cp = '\0';
			if (ccs_find_domain3(line, NULL, false) == EOF)
				ccs_assign_domain3(line, NULL, true);
		}
		ccs_put();
	}

	/* Sort by domain name. */
	qsort(ccs_dp.list, ccs_dp.list_len, sizeof(struct ccs_domain),
	      ccs_domainname_attribute_compare);

	/*
	 * Since this screen shows domain transition tree within current
	 * namespace, purge domains that are not in current namespace.
	 */
	for (index = 0; index < ccs_dp.list_len; index++) {
		int i;
		if (ccs_is_current_namespace(ccs_dp.list[index].
					     domainname->name))
			continue;
		free(ccs_dp.list[index].string_ptr);
		ccs_dp.list_len--;
		for (i = index; i < ccs_dp.list_len; i++)
			ccs_dp.list[i] = ccs_dp.list[i + 1];
		index--;
	}

	/* Assign domain numbers. */
	{
		int number = 0;
		int index;
		ccs_unnumbered_domain_count = 0;
		for (index = 0; index < ccs_dp.list_len; index++) {
			if (ccs_deleted_domain(index) ||
			    ccs_jump_source(index)) {
				ccs_dp.list[index].number = -1;
				ccs_unnumbered_domain_count++;
			} else {
				ccs_dp.list[index].number = number++;
			}
		}
	}

	if (!ccs_dp.list_len)
		return;
	ccs_dp.list_selected = ccs_realloc2(ccs_dp.list_selected,
					    ccs_dp.list_len);
}

/**
 * ccs_show_process_line - Print a process line.
 *
 * @index: Index in the ccs_task_list array.
 *
 * Returns length of the printed line.
 */
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
			    ccs_task_list[index].pid,
			    ccs_task_list[index].domain);
	printw("%s", ccs_eat(line));
	tmp_col += strlen(line);
	ccs_put();
	return tmp_col;
}

/**
 * ccs_show_list - Print list on the screen.
 *
 * Returns nothing.
 */
static void ccs_show_list(void)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
	int ccs_list_indent;
	const int offset = ptr->current;
	int i;
	int tmp_col;
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST)
		ccs_list_item_count = ccs_domain_sort_type ?
			ccs_task_list_len : ccs_dp.list_len;
	else
		ccs_list_item_count = ccs_gacl_list_count;
	clear();
	move(0, 0);
	if (ccs_window_height < CCS_HEADER_LINES + 1) {
		printw("Please enlarge window.");
		clrtobot();
		refresh();
		return;
	}
	/* add color */
	ccs_editpolicy_color_change(ccs_editpolicy_color_head(), true);
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (ccs_domain_sort_type) {
			printw("<<< Process State Viewer >>>"
			       "      %d process%s    '?' for help",
			       ccs_task_list_len,
			       ccs_task_list_len > 1 ? "es" : "");
		} else {
			int i = ccs_list_item_count
				- ccs_unnumbered_domain_count;
			printw("<<< Domain Transition Editor >>>"
			       "      %d domain%c    '?' for help",
			       i, i > 1 ? 's' : ' ');
		}
	} else {
		int i = ccs_list_item_count;
		printw("<<< %s >>>"
		       "      %d entr%s    '?' for help", ccs_list_caption,
		       i, i > 1 ? "ies" : "y");
	}
	/* add color */
	ccs_editpolicy_color_change(ccs_editpolicy_color_head(), false);
	ccs_eat_col = ptr->x;
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
		for (i = 0; i < ccs_list_item_count; i++) {
			const enum ccs_editpolicy_directives directive =
				ccs_gacl_list[i].directive;
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
		ccs_eat_col = ptr->x;
		if (index >= ccs_list_item_count)
			break;
		move(CCS_HEADER_LINES + i, 0);
		switch (ccs_current_screen) {
		case CCS_SCREEN_DOMAIN_LIST:
			if (!ccs_domain_sort_type)
				tmp_col = ccs_show_domain_line(index);
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
	ccs_show_current();
}

/**
 * ccs_resize_window - Callback for resize event.
 *
 * Returns nothing.
 */
static void ccs_resize_window(void)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
	getmaxyx(stdscr, ccs_window_height, ccs_window_width);
	ccs_body_lines = ccs_window_height - CCS_HEADER_LINES;
	if (ccs_body_lines <= ptr->y)
		ptr->y = ccs_body_lines - 1;
	if (ptr->y < 0)
		ptr->y = 0;
}

/**
 * ccs_up_arrow_key - Callback event for pressing up-arrow key.
 *
 * Returns nothing.
 */
static void ccs_up_arrow_key(void)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
	if (ptr->y > 0) {
		ptr->y--;
		ccs_show_current();
	} else if (ptr->current > 0) {
		ptr->current--;
		ccs_show_list();
	}
}

/**
 * ccs_down_arrow_key - Callback event for pressing down-arrow key.
 *
 * Returns nothing.
 */
static void ccs_down_arrow_key(void)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
	if (ptr->y < ccs_body_lines - 1) {
		if (ptr->current + ptr->y < ccs_list_item_count - 1) {
			ptr->y++;
			ccs_show_current();
		}
	} else if (ptr->current + ptr->y < ccs_list_item_count - 1) {
		ptr->current++;
		ccs_show_list();
	}
}

/**
 * ccs_page_up_key - Callback event for pressing page-up key.
 *
 * Returns nothing.
 */
static void ccs_page_up_key(void)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
	int p0 = ptr->current;
	int p1 = ptr->y;
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
	refresh = (ptr->current != p0);
	ptr->current = p0;
	ptr->y = p1;
	if (refresh)
		ccs_show_list();
	else
		ccs_show_current();
}

/**
 * ccs_page_down_key - Callback event for pressing page-down key.
 *
 * Returns nothing.
 */
static void ccs_page_down_key(void)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
	int ccs_count = ccs_list_item_count - 1;
	int p0 = ptr->current;
	int p1 = ptr->y;
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
	refresh = (ptr->current != p0);
	ptr->current = p0;
	ptr->y = p1;
	if (refresh)
		ccs_show_list();
	else
		ccs_show_current();
}

/**
 * ccs_editpolicy_get_current - Get currently selected line's index.
 *
 * Returns index for currently selected line on success, EOF otherwise.
 *
 * If current screen has no entry, this function returns EOF.
 */
int ccs_editpolicy_get_current(void)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
	int ccs_count = ccs_list_item_count;
	const int p0 = ptr->current;
	const int p1 = ptr->y;
	if (!ccs_count)
		return EOF;
	if (p0 + p1 < 0 || p0 + p1 >= ccs_count) {
		fprintf(stderr,
			"ERROR: ccs_current_item_index=%d ccs_current_y=%d\n",
			p0, p1);
		exit(127);
	}
	return p0 + p1;
}

/**
 * ccs_show_current - Show current cursor line.
 *
 * Returns nothing.
 */
static void ccs_show_current(void)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST &&
	    !ccs_domain_sort_type) {
		char *line;
		const int index = ccs_editpolicy_get_current();
		ccs_get();
		ccs_eat_col = ptr->x;
		if (index >= 0)
			line = ccs_shprintf
				("%s", ccs_eat(ccs_dp.list[index].
					       domainname->name));
		else
			line = ccs_shprintf("%s", ccs_current_ns->name);
		if (ccs_window_width < strlen(line))
			line[ccs_window_width] = '\0';
		move(2, 0);
		clrtoeol();
		ccs_editpolicy_attr_change(A_REVERSE, true);  /* add color */
		printw("%s", line);
		ccs_editpolicy_attr_change(A_REVERSE, false); /* add color */
		ccs_put();
	}
	if (ccs_current_screen == CCS_SCREEN_EXCEPTION_LIST ||
	    ccs_current_screen == CCS_SCREEN_PROFILE_LIST) {
		char *line;
		ccs_get();
		ccs_eat_col = ptr->x;
		line = ccs_shprintf("%s", ccs_current_ns->name);
		if (ccs_window_width < strlen(line))
			line[ccs_window_width] = '\0';
		move(2, 0);
		clrtoeol();
		ccs_editpolicy_attr_change(A_REVERSE, true);  /* add color */
		printw("%s", line);
		ccs_editpolicy_attr_change(A_REVERSE, false); /* add color */
		ccs_put();
	}
	move(CCS_HEADER_LINES + ptr->y, 0);
	ccs_editpolicy_line_draw();     /* add color */
	refresh();
}

/**
 * ccs_adjust_cursor_pos - Adjust cursor position if needed.
 *
 * @item_count: Available item count in this screen.
 *
 * Returns nothing.
 */
static void ccs_adjust_cursor_pos(const int item_count)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
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
 * ccs_set_cursor_pos - Move cursor position if needed.
 *
 * @index: Index in the domain policy or currently selected line in the generic
 *         list.
 *
 * Returns nothing.
 */
static void ccs_set_cursor_pos(const int index)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
	while (index < ptr->y + ptr->current) {
		if (ptr->y > 0)
			ptr->y--;
		else
			ptr->current--;
	}
	while (index > ptr->y + ptr->current) {
		if (ptr->y < ccs_body_lines - 1)
			ptr->y++;
		else
			ptr->current++;
	}
}

/**
 * ccs_select_item - Select an item.
 *
 * @index: Index in the domain policy or currently selected line in the generic
 *         list.
 *
 * Returns true if selected, false otherwise.
 *
 * Domain transition source and deleted domains are not selectable.
 */
static _Bool ccs_select_item(const int index)
{
	int x;
	int y;
	if (index < 0)
		return false;
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (!ccs_domain_sort_type) {
			if (ccs_deleted_domain(index) ||
			    ccs_jump_source(index))
				return false;
			ccs_dp.list_selected[index] ^= 1;
		} else {
			ccs_task_list[index].selected ^= 1;
		}
	} else {
		ccs_gacl_list[index].selected ^= 1;
	}
	getyx(stdscr, y, x);
	ccs_editpolicy_sttr_save();    /* add color */
	ccs_show_list();
	ccs_editpolicy_sttr_restore(); /* add color */
	move(y, x);
	return true;
}

/**
 * ccs_gacl_compare - strcmp() for qsort() callback.
 *
 * @a: Pointer to "void".
 * @b: Pointer to "void".
 *
 * Returns return value of strcmp().
 */
static int ccs_gacl_compare(const void *a, const void *b)
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
	} else if (a0->directive == CCS_DIRECTIVE_USE_GROUP) {
		return 1;
	} else if (b0->directive == CCS_DIRECTIVE_USE_GROUP) {
		return -1;
	} else if (a0->directive == CCS_DIRECTIVE_TRANSITION_FAILED) {
		return 2;
	} else if (b0->directive == CCS_DIRECTIVE_TRANSITION_FAILED) {
		return -2;
	} else if (a0->directive == CCS_DIRECTIVE_QUOTA_EXCEEDED) {
		return 3;
	} else if (b0->directive == CCS_DIRECTIVE_QUOTA_EXCEEDED) {
		return -3;
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
 * @index: Index in the domain policy.
 *
 * Returns nothing.
 */
static void ccs_delete_entry(const int index)
{
	int c;
	move(1, 0);
	ccs_editpolicy_color_change(CCS_DISP_ERR, true);	/* add color */
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		c = ccs_count(ccs_dp.list_selected, ccs_dp.list_len);
		if (!c && index < ccs_dp.list_len)
			c = ccs_select_item(index);
		if (!c)
			printw("Select domain using Space key first.");
		else
			printw("Delete selected domain%s? ('Y'es/'N'o)",
			       c > 1 ? "s" : "");
	} else {
		c = ccs_count2(ccs_gacl_list,
			       ccs_gacl_list_count);
		if (!c)
			c = ccs_select_item(index);
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
		ccs_show_list();
		return;
	}
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		int i;
		FILE *fp = ccs_editpolicy_open_write
			(CCS_PROC_POLICY_DOMAIN_POLICY);
		if (!fp)
			return;
		for (i = 0; i < ccs_dp.list_len; i++) {
			if (!ccs_dp.list_selected[i])
				continue;
			fprintf(fp, "delete %s\n",
				ccs_dp.list[i].domainname->name);
		}
		ccs_close_write(fp);
	} else {
		int i;
		const _Bool is_kernel_ns = !strcmp(ccs_current_ns->name,
						   "<kernel>");
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
		for (i = 0; i < ccs_gacl_list_count; i++) {
			enum ccs_editpolicy_directives directive;
			if (!ccs_gacl_list[i].selected)
				continue;
			directive = ccs_gacl_list[i].directive;
			fprintf(fp, "delete %s %s %s\n",
				ccs_current_screen == CCS_SCREEN_EXCEPTION_LIST
				&& !is_kernel_ns ? ccs_current_ns->name : "",
				ccs_directives[directive].original,
				ccs_gacl_list[i].operand);
		}
		ccs_close_write(fp);
	}
}

/**
 * ccs_add_entry - Add an entry.
 *
 * Returns nothing.
 */
static void ccs_add_entry(void)
{
	FILE *fp;
	char *line;
	const _Bool is_kernel_ns = !strcmp(ccs_current_ns->name, "<kernel>");
	ccs_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(ccs_window_height - 1, 0, "Enter new entry> ",
			    ccs_rl.history, ccs_rl.count, 128000, 8);
	ccs_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	ccs_rl.count = ccs_add_history(line, ccs_rl.history, ccs_rl.count,
				       ccs_rl.max);
	fp = ccs_editpolicy_open_write(ccs_policy_file);
	if (!fp)
		goto out;
	switch (ccs_current_screen) {
		enum ccs_editpolicy_directives directive;
	case CCS_SCREEN_DOMAIN_LIST:
		if (!ccs_correct_domain(line)) {
			const int len = strlen(line) + 128;
			ccs_last_error = ccs_realloc2(ccs_last_error, len);
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
		if (ccs_current_screen == CCS_SCREEN_EXCEPTION_LIST &&
		    !is_kernel_ns)
			fprintf(fp, "%s ", ccs_current_ns->name);
		directive = ccs_find_directive(false, line);
		if (directive != CCS_DIRECTIVE_NONE)
			fprintf(fp, "%s ", ccs_directives[directive].original);
		break;
	case CCS_SCREEN_PROFILE_LIST:
		if (!strchr(line, '='))
			fprintf(fp, "%s %s-COMMENT=\n",
				!is_kernel_ns ? ccs_current_ns->name : "",
				line);
		if (!is_kernel_ns)
			fprintf(fp, "%s ", ccs_current_ns->name);
		break;
	case CCS_SCREEN_NS_LIST:
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
 * ccs_find_entry - Find an entry by user's key input.
 *
 * @input:   True if find next/previous, false if find first.
 * @forward: True if find next, false if find previous.
 * @current: Current position.
 *
 * Returns nothing.
 */
static void ccs_find_entry(const _Bool input, const _Bool forward,
			   const int current)
{
	int index = current;
	char *line = NULL;
	if (current == EOF)
		return;
	if (!input)
		goto start_search;
	ccs_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(ccs_window_height - 1, 0, "Search> ",
			    ccs_rl.history, ccs_rl.count, 128000, 8);
	ccs_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	ccs_rl.count = ccs_add_history(line, ccs_rl.history, ccs_rl.count,
				       ccs_rl.max);
	free(ccs_rl.search_buffer[ccs_current_screen]);
	ccs_rl.search_buffer[ccs_current_screen] = line;
	line = NULL;
	index = -1;
start_search:
	ccs_get();
	while (true) {
		const char *cp;
		if (forward) {
			if (++index >= ccs_list_item_count)
				break;
		} else {
			if (--index < 0)
				break;
		}
		if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
			if (ccs_domain_sort_type)
				cp = ccs_task_list[index].name;
			else
				cp = ccs_get_last_name(index);
		} else if (ccs_current_screen == CCS_SCREEN_PROFILE_LIST) {
			cp = ccs_shprintf("%u-%s",
					  ccs_gacl_list[index].directive,
					  ccs_gacl_list[index].operand);
		} else {
			const enum ccs_editpolicy_directives directive =
				ccs_gacl_list[index].directive;
			cp = ccs_shprintf("%s %s",
					  ccs_directives[directive].alias,
					  ccs_gacl_list[index].operand);
		}
		if (!strstr(cp, ccs_rl.search_buffer[ccs_current_screen]))
			continue;
		ccs_set_cursor_pos(index);
		break;
	}
	ccs_put();
out:
	free(line);
	ccs_show_list();
}

/**
 * ccs_set_profile - Change profile number.
 *
 * @current: Currently selected line in the generic list.
 *
 * Returns nothing.
 */
static void ccs_set_profile(const int current)
{
	int index;
	FILE *fp;
	char *line;
	if (!ccs_domain_sort_type) {
		if (!ccs_count(ccs_dp.list_selected, ccs_dp.list_len) &&
		    !ccs_select_item(current)) {
			move(1, 0);
			printw("Select domain using Space key first.");
			clrtoeol();
			refresh();
			return;
		}
	} else {
		if (!ccs_count3(ccs_task_list, ccs_task_list_len) &&
		    !ccs_select_item(current)) {
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
		for (index = 0; index < ccs_dp.list_len; index++) {
			if (!ccs_dp.list_selected[index])
				continue;
			fprintf(fp, "select domain=%s\n" "use_profile %s\n",
				ccs_dp.list[index].domainname->name, line);
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
	if (!ccs_count2(ccs_gacl_list, ccs_gacl_list_count))
		ccs_select_item(current);
	ccs_editpolicy_attr_change(A_BOLD, true);  /* add color */
	ccs_initial_readline_data = NULL;
	for (index = 0; index < ccs_gacl_list_count; index++) {
		char *cp;
		if (!ccs_gacl_list[index].selected)
			continue;
		cp = strchr(ccs_gacl_list[index].operand, '=');
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
	for (index = 0; index < ccs_gacl_list_count; index++) {
		char *buf;
		char *cp;
		enum ccs_editpolicy_directives directive;
		if (!ccs_gacl_list[index].selected)
			continue;
		ccs_get();
		buf = ccs_shprintf("%s", ccs_gacl_list[index].operand);
		cp = strchr(buf, '=');
		if (cp)
			*cp = '\0';
		directive = ccs_gacl_list[index].directive;
		fprintf(fp, "%s ", ccs_current_ns->name);
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
	if (!ccs_count2(ccs_gacl_list, ccs_gacl_list_count))
		ccs_select_item(current);
	ccs_editpolicy_attr_change(A_BOLD, true);  /* add color */
	line = ccs_readline(ccs_window_height - 1, 0, "Enter new value> ",
			    NULL, 0, 20, 1);
	ccs_editpolicy_attr_change(A_BOLD, false); /* add color */
	if (!line || !*line)
		goto out;
	fp = ccs_editpolicy_open_write(CCS_PROC_POLICY_STAT);
	if (!fp)
		goto out;
	for (index = 0; index < ccs_gacl_list_count; index++) {
		char *buf;
		char *cp;
		if (!ccs_gacl_list[index].selected)
			continue;
		ccs_get();
		buf = ccs_shprintf("%s", ccs_gacl_list[index].operand);
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
 * @current: Index in the domain policy.
 *
 * Returns true if next window is ACL list or namespace list, false otherwise.
 */
static _Bool ccs_select_acl_window(const int current)
{
	char *old_domain;
	if (current == EOF)
		return false;
	if (ccs_current_screen == CCS_SCREEN_NS_LIST) {
		const char *namespace = ccs_gacl_list[current].operand;
		if (ccs_previous_screen == CCS_SCREEN_ACL_LIST &&
		    strcmp(ccs_current_ns->name, namespace))
			ccs_previous_screen = CCS_SCREEN_DOMAIN_LIST;
		ccs_current_ns = ccs_savename(namespace);
		ccs_current_screen = ccs_previous_screen;
		return true;
	}
	if (ccs_current_screen != CCS_SCREEN_DOMAIN_LIST)
		return false;
	ccs_current_pid = 0;
	if (ccs_domain_sort_type) {
		ccs_current_pid = ccs_task_list[current].pid;
	} else if (ccs_jump_source(current)) {
		struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
		const int redirect_index = ccs_find_target_domain(current);
		if (redirect_index >= 0) {
			ptr->current = redirect_index - ptr->y;
			while (ptr->current < 0) {
				ptr->current++;
				ptr->y--;
			}
			ccs_show_list();
		}
		if (redirect_index == -2) {
			const char *domainname =
				ccs_dp.list[current].target->name;
			ccs_current_ns = ccs_get_ns(domainname);
			free(ccs_current_domain);
			ccs_current_domain = ccs_strdup(domainname);
			ccs_current_screen = CCS_SCREEN_DOMAIN_LIST;
			ccs_force_move_cursor = true;
			return true;
		}
		return false;
	} else if (ccs_deleted_domain(current)) {
		return false;
	}
	old_domain = ccs_current_domain;
	if (ccs_domain_sort_type)
		ccs_current_domain = ccs_strdup(ccs_task_list[current].domain);
	else
		ccs_current_domain = ccs_strdup(ccs_dp.list[current].
						domainname->name);
	ccs_no_restore_cursor = old_domain &&
		strcmp(old_domain, ccs_current_domain);
	free(old_domain);
	ccs_current_screen = CCS_SCREEN_ACL_LIST;
	return true;
}

/**
 * ccs_select_window - Switch window.
 *
 * @current: Index in the domain policy.
 *
 * Returns next window to display.
 */
static enum ccs_screen_type ccs_select_window(const int current)
{
	move(0, 0);
	printw("Press one of below keys to switch window.\n\n");
	printw("e     <<< Exception Policy Editor >>>\n");
	printw("d     <<< Domain Transition Editor >>>\n");
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST && current != EOF &&
	    !ccs_jump_source(current) && !ccs_deleted_domain(current))
		printw("a     <<< Domain Policy Editor >>>\n");
	printw("p     <<< Profile Editor >>>\n");
	printw("m     <<< Manager Policy Editor >>>\n");
	printw("n     <<< Namespace Selector >>>\n");
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
			if (ccs_select_acl_window(current))
				return ccs_current_screen;
		if (c == 'P' || c == 'p')
			return CCS_SCREEN_PROFILE_LIST;
		if (c == 'M' || c == 'm')
			return CCS_SCREEN_MANAGER_LIST;
		if (c == 'N' || c == 'n') {
			ccs_previous_screen = ccs_current_screen;
			return CCS_SCREEN_NS_LIST;
		}
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
 * @current: Index in the domain policy.
 *
 * Returns nothing.
 */
static void ccs_copy_mark_state(const int current)
{
	int index;
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (ccs_domain_sort_type) {
			const u8 selected = ccs_task_list[current].selected;
			for (index = current; index < ccs_task_list_len;
			     index++)
				ccs_task_list[index].selected = selected;
		} else {
			const u8 selected = ccs_dp.list_selected[current];
			if (ccs_deleted_domain(current) ||
			    ccs_jump_source(current))
				return;
			for (index = current; index < ccs_dp.list_len;
			     index++) {
				if (ccs_deleted_domain(index) ||
				    ccs_jump_source(index))
					continue;
				ccs_dp.list_selected[index] = selected;
			}
		}
	} else {
		const u8 selected = ccs_gacl_list[current].selected;
		for (index = current; index < ccs_gacl_list_count;
		     index++)
			ccs_gacl_list[index].selected = selected;
	}
	ccs_show_list();
}

/**
 * ccs_copy_to_history - Copy line to histoy buffer.
 *
 * @current: Index in the domain policy.
 *
 * Returns nothing.
 */
static void ccs_copy_to_history(const int current)
{
	const char *line;
	if (current == EOF)
		return;
	ccs_get();
	switch (ccs_current_screen) {
		enum ccs_editpolicy_directives directive;
	case CCS_SCREEN_DOMAIN_LIST:
		if (!ccs_domain_sort_type)
			line = ccs_dp.list[current].domainname->name;
		else
			line = ccs_task_list[current].domain;
		break;
	case CCS_SCREEN_EXCEPTION_LIST:
	case CCS_SCREEN_ACL_LIST:
		directive = ccs_gacl_list[current].directive;
		line = ccs_shprintf("%s %s", ccs_directives[directive].alias,
				ccs_gacl_list[current].operand);
		break;
	case CCS_SCREEN_STAT_LIST:
		line = NULL;
		break;
	default:
		line = ccs_shprintf("%s",
				    ccs_gacl_list[current].operand);
	}
	ccs_rl.count = ccs_add_history(line, ccs_rl.history, ccs_rl.count,
				       ccs_rl.max);
	ccs_put();
}

/**
 * ccs_generic_list_loop - Main loop.
 *
 * Returns next screen to display.
 */
static enum ccs_screen_type ccs_generic_list_loop(void)
{
	struct ccs_screen *ptr;
	static struct {
		int y;
		int current;
	} saved_cursor[CCS_MAXSCREEN] = { };
	if (ccs_current_screen == CCS_SCREEN_EXCEPTION_LIST) {
		ccs_policy_file = CCS_PROC_POLICY_EXCEPTION_POLICY;
		ccs_list_caption = "Exception Policy Editor";
	} else if (ccs_current_screen == CCS_SCREEN_ACL_LIST) {
		ccs_policy_file = CCS_PROC_POLICY_DOMAIN_POLICY;
		ccs_list_caption = "Domain Policy Editor";
		/*
	} else if (ccs_current_screen == CCS_SCREEN_QUERY_LIST) {
		ccs_policy_file = CCS_PROC_POLICY_QUERY;
		ccs_list_caption = "Interactive Enforcing Mode";
		*/
	} else if (ccs_current_screen == CCS_SCREEN_NS_LIST) {
		ccs_policy_file = CCS_PROC_POLICY_PROFILE;
		ccs_list_caption = "Namespace Selector";
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
	ptr = &ccs_screen[ccs_current_screen];
	if (ccs_no_restore_cursor || ccs_force_move_cursor) {
		ptr->current = 0;
		ptr->y = 0;
		ccs_no_restore_cursor = false;
	} else {
		ptr->current = saved_cursor[ccs_current_screen].current;
		ptr->y = saved_cursor[ccs_current_screen].y;
	}
start:
	if (ccs_current_screen == CCS_SCREEN_DOMAIN_LIST) {
		if (!ccs_domain_sort_type) {
			ccs_read_domain_and_exception_policy();
			if (ccs_force_move_cursor) {
				const int redirect_index =
					ccs_find_domain3(ccs_current_domain,
							 NULL, false);
				if (redirect_index >= 0) {
					ptr->current = redirect_index - ptr->y;
					while (ptr->current < 0) {
						ptr->current++;
						ptr->y--;
					}
				}
				ccs_force_move_cursor = false;
			}
			ccs_adjust_cursor_pos(ccs_dp.list_len);
		} else {
			ccs_read_process_list(true);
			ccs_adjust_cursor_pos(ccs_task_list_len);
		}
	} else {
		ccs_read_generic_policy();
		ccs_adjust_cursor_pos(ccs_gacl_list_count);
	}
start2:
	ccs_show_list();
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
		saved_cursor[ccs_current_screen].current = ptr->current;
		saved_cursor[ccs_current_screen].y = ptr->y;
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
			ccs_show_list();
			break;
		case KEY_UP:
			ccs_up_arrow_key();
			break;
		case KEY_DOWN:
			ccs_down_arrow_key();
			break;
		case KEY_PPAGE:
			ccs_page_up_key();
			break;
		case KEY_NPAGE:
			ccs_page_down_key();
			break;
		case ' ':
			ccs_select_item(current);
			break;
		case 'c':
		case 'C':
			if (current == EOF)
				break;
			ccs_copy_mark_state(current);
			ccs_show_list();
			break;
		case 'f':
		case 'F':
			if (ccs_current_screen != CCS_SCREEN_STAT_LIST)
				ccs_find_entry(true, true, current);
			break;
		case 'p':
		case 'P':
			if (ccs_current_screen == CCS_SCREEN_STAT_LIST)
				break;
			if (!ccs_rl.search_buffer[ccs_current_screen])
				ccs_find_entry(true, false, current);
			else
				ccs_find_entry(false, false, current);
			break;
		case 'n':
		case 'N':
			if (ccs_current_screen == CCS_SCREEN_STAT_LIST)
				break;
			if (!ccs_rl.search_buffer[ccs_current_screen])
				ccs_find_entry(true, true, current);
			else
				ccs_find_entry(false, true, current);
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
				ccs_delete_entry(current);
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
			case CCS_SCREEN_NS_LIST:
				ccs_add_entry();
				goto start;
			default:
				break;
			}
			break;
		case '\r':
		case '\n':
			if (ccs_select_acl_window(current))
				return ccs_current_screen;
			break;
		case 's':
		case 'S':
			if (ccs_readonly_mode)
				break;
			switch (ccs_current_screen) {
			case CCS_SCREEN_DOMAIN_LIST:
				ccs_set_profile(current);
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
			ptr->x = ccs_max_col;
			goto start2;
		case KEY_IC:
			ccs_copy_to_history(current);
			break;
		case 'o':
		case 'O':
			if (ccs_current_screen == CCS_SCREEN_ACL_LIST ||
			    ccs_current_screen == CCS_SCREEN_EXCEPTION_LIST) {
				ccs_editpolicy_optimize(current);
				ccs_show_list();
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
			return ccs_select_window(current);
		case '?':
			if (ccs_show_command_key(ccs_current_screen,
						 ccs_readonly_mode))
				goto start;
			return CCS_MAXSCREEN;
		}
	}
}

/**
 * ccs_save_to_file - Save policy to file.
 *
 * @src: Filename to read from.
 * @dest: Filename to write to.
 *
 * Returns true on success, false otherwise.
 */
static _Bool ccs_save_to_file(const char *src, const char *dest)
{
	FILE *proc_fp = ccs_editpolicy_open_read(src);
	FILE *file_fp = fopen(dest, "w");
	int c;
	if (!file_fp) {
		fprintf(stderr, "Can't open %s\n", dest);
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
 * ccs_parse_args - Parse command line arguments.
 *
 * @argc: argc passed to main().
 * @argv: argv passed to main().
 *
 * Returns nothing.
 */
static void ccs_parse_args(int argc, char *argv[])
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
		} else if (*ptr == '<') {
			if (ccs_current_ns || strchr(ptr, ' ') ||
			    !ccs_domain_def(ptr))
				goto usage;
			ccs_current_ns = ccs_savename(ptr);
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
		else if (!strcmp(ptr, "n"))
			ccs_current_screen = CCS_SCREEN_NS_LIST;
		else if (!strcmp(ptr, "readonly"))
			ccs_readonly_mode = true;
		else if (sscanf(ptr, "refresh=%u", &ccs_refresh_interval)
			 != 1) {
usage:
			printf("Usage: %s [e|d|p|m|s|n] [readonly] "
			       "[refresh=interval] [<namespace>]"
			       "[{policy_dir|remote_ip:remote_port}]\n",
			       argv[0]);
			exit(1);
		}
	}
	if (!ccs_current_ns)
		ccs_current_ns = ccs_savename("<kernel>");
}

/**
 * ccs_load_offline - Load policy for offline mode.
 *
 * Returns nothing.
 */
static void ccs_load_offline(void)
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
	if (chdir(ccs_policy_dir) || chdir("policy/current/")) {
		fprintf(stderr, "Directory %s/policy/current/ doesn't "
			"exist.\n", ccs_policy_dir);
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
		ccs_editpolicy_offline_daemon(fd, pipe_fd[0]);
		_exit(1);
	case -1:
		fprintf(stderr, "fork()\n");
		exit(1);
	}
	if (close(fd) || close(pipe_fd[0]))
		exit(1);
	ccs_copy_file("profile.conf", CCS_PROC_POLICY_PROFILE);
	ccs_copy_file("exception_policy.conf",
		      CCS_PROC_POLICY_EXCEPTION_POLICY);
	ccs_copy_file("domain_policy.conf", CCS_PROC_POLICY_DOMAIN_POLICY);
	ccs_copy_file("manager.conf", CCS_PROC_POLICY_MANAGER);
	if (chdir("..")) {
		fprintf(stderr, "Directory %s/policy/ doesn't exist.\n",
			ccs_policy_dir);
		exit(1);
	}
}

/**
 * ccs_load_readwrite - Check that this program can write to /proc/ccs/ interface.
 *
 * Returns nothing.
 */
static void ccs_load_readwrite(void)
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

/**
 * ccs_save_offline - Save policy for offline mode.
 *
 * Returns nothing.
 */
static void ccs_save_offline(void)
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
	ccs_parse_args(argc, argv);
	ccs_editpolicy_init_keyword_map();
	if (ccs_offline_mode)
		ccs_load_offline();
	if (ccs_network_mode)
		goto start;
	if (chdir(CCS_PROC_POLICY_DIR)) {
		fprintf(stderr,
			"You can't use this editor for this kernel.\n");
		return 1;
	}
	if (!ccs_readonly_mode)
		ccs_load_readwrite();
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
	ccs_rl.max = 20;
	ccs_rl.history = ccs_malloc(ccs_rl.max * sizeof(const char *));
	while (ccs_current_screen < CCS_MAXSCREEN) {
		ccs_resize_window();
		ccs_current_screen = ccs_generic_list_loop();
	}
	alarm(0);
	clear();
	move(0, 0);
	refresh();
	endwin();
	if (ccs_offline_mode && !ccs_readonly_mode)
		ccs_save_offline();
	ccs_clear_domain_policy3();
	return 0;
}
