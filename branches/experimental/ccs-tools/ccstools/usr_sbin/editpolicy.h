/*
 * editpolicy.h
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
#include <signal.h>
#include <curses.h>

enum ccs_screen_type {
	CCS_SCREEN_EXCEPTION_LIST,
	CCS_SCREEN_DOMAIN_LIST,
	CCS_SCREEN_ACL_LIST,
	CCS_SCREEN_PROFILE_LIST,
	CCS_SCREEN_MANAGER_LIST,
	/* CCS_SCREEN_QUERY_LIST, */
	CCS_SCREEN_NS_LIST,
	CCS_SCREEN_STAT_LIST,
	CCS_MAXSCREEN
};

enum ccs_editpolicy_directives {
	CCS_DIRECTIVE_NONE,
	CCS_DIRECTIVE_ACL_GROUP,
	CCS_DIRECTIVE_ADDRESS_GROUP,
	CCS_DIRECTIVE_AGGREGATOR,
	CCS_DIRECTIVE_CAPABILITY,
	CCS_DIRECTIVE_DEFAULT_TRANSITION,
	CCS_DIRECTIVE_FILE_APPEND,
	CCS_DIRECTIVE_FILE_CHGRP,
	CCS_DIRECTIVE_FILE_CHMOD,
	CCS_DIRECTIVE_FILE_CHOWN,
	CCS_DIRECTIVE_FILE_CHROOT,
	CCS_DIRECTIVE_FILE_CREATE,
	CCS_DIRECTIVE_FILE_EXECUTE,
	CCS_DIRECTIVE_FILE_GETATTR,
	CCS_DIRECTIVE_FILE_IOCTL,
	CCS_DIRECTIVE_FILE_LINK,
	CCS_DIRECTIVE_FILE_MKBLOCK,
	CCS_DIRECTIVE_FILE_MKCHAR,
	CCS_DIRECTIVE_FILE_MKDIR,
	CCS_DIRECTIVE_FILE_MKFIFO,
	CCS_DIRECTIVE_FILE_MKSOCK,
	CCS_DIRECTIVE_FILE_MOUNT,
	CCS_DIRECTIVE_FILE_PIVOT_ROOT,
	CCS_DIRECTIVE_FILE_READ,
	CCS_DIRECTIVE_FILE_RENAME,
	CCS_DIRECTIVE_FILE_RMDIR,
	CCS_DIRECTIVE_FILE_SYMLINK,
	CCS_DIRECTIVE_FILE_TRUNCATE,
	CCS_DIRECTIVE_FILE_UNLINK,
	CCS_DIRECTIVE_FILE_UNMOUNT,
	CCS_DIRECTIVE_FILE_WRITE,
	CCS_DIRECTIVE_IPC_PTRACE,
	CCS_DIRECTIVE_MISC_ENV,
	CCS_DIRECTIVE_NETWORK_INET,
	CCS_DIRECTIVE_NETWORK_UNIX,
	CCS_DIRECTIVE_NUMBER_GROUP,
	CCS_DIRECTIVE_PATH_GROUP,
	CCS_DIRECTIVE_QUOTA_EXCEEDED,
	CCS_DIRECTIVE_TASK_AUTO_DOMAIN_TRANSITION,
	CCS_DIRECTIVE_TASK_AUTO_EXECUTE_HANDLER,
	CCS_DIRECTIVE_TASK_DENIED_EXECUTE_HANDLER,
	CCS_DIRECTIVE_TASK_MANUAL_DOMAIN_TRANSITION,
	CCS_DIRECTIVE_TRANSITION_FAILED,
	CCS_DIRECTIVE_USE_GROUP,
	CCS_DIRECTIVE_USE_PROFILE,
	CCS_MAX_DIRECTIVE_INDEX
};

enum ccs_color_pair {
	CCS_NORMAL,
	CCS_DOMAIN_HEAD,
	CCS_DOMAIN_CURSOR,
	CCS_EXCEPTION_HEAD,
	CCS_EXCEPTION_CURSOR,
	CCS_ACL_HEAD,
	CCS_ACL_CURSOR,
	CCS_PROFILE_HEAD,
	CCS_PROFILE_CURSOR,
	CCS_MANAGER_HEAD,
	CCS_MANAGER_CURSOR,
	CCS_STAT_HEAD,
	CCS_STAT_CURSOR,
	CCS_DEFAULT_COLOR,
	CCS_DISP_ERR
};

struct ccs_generic_acl {
	enum ccs_editpolicy_directives directive;
	u8 selected;
	const char *operand;
};

struct ccs_editpolicy_directive {
	const char *original;
	const char *alias;
	int original_len;
	int alias_len;
};

struct ccs_misc_policy {
	const struct ccs_path_info **list;
	int list_len;
};

struct ccs_path_group_entry {
	const struct ccs_path_info *ns;
	const struct ccs_path_info *group_name;
	const struct ccs_path_info **member_name;
	int member_name_len;
};

struct ccs_readline_data {
	const char **history;
	int count;
	int max;
	char *search_buffer[CCS_MAXSCREEN];
};

struct ccs_screen {
	/* Index of currently selected line on each screen. */
	int current;
	/* Current cursor position on CUI screen. */
	int y;
	/* Columns to shift when displaying. */
	int x;
	/* For ccs_editpolicy_line_draw(). */
	int saved_color_current; /* Initialized to -1 */
	int saved_color_y;
};

#define CCS_HEADER_LINES 3

#define CCS_EDITPOLICY_CONF "/etc/ccs/tools/editpolicy.conf"

enum ccs_color_pair ccs_editpolicy_color_head(void);
enum ccs_editpolicy_directives ccs_find_directive(const _Bool forward,
						  char *line);
int ccs_add_address_group_policy(char *data, const _Bool is_delete);
int ccs_add_number_group_policy(char *data, const _Bool is_delete);
int ccs_editpolicy_get_current(void);
void ccs_editpolicy_attr_change(const attr_t attr, const _Bool flg);
void ccs_editpolicy_clear_groups(void);
void ccs_editpolicy_color_change(const attr_t attr, const _Bool flg);
void ccs_editpolicy_color_init(void);
void ccs_editpolicy_init_keyword_map(void);
void ccs_editpolicy_line_draw(void);
void ccs_editpolicy_offline_daemon(const int listener, const int notifier);
void ccs_editpolicy_optimize(const int current);
void ccs_editpolicy_sttr_restore(void);
void ccs_editpolicy_sttr_save(void);
struct ccs_path_group_entry *ccs_find_path_group_ns
(const struct ccs_path_info *ns, const char *group_name);

struct ccs_domain {
	const struct ccs_path_info *domainname;
	const struct ccs_path_info *target; /* This may be NULL */
	//const struct ccs_default_transition *d_t; /* This may be NULL */
	//const struct ccs_path_info **string_ptr;
	//int string_count;
	int number;   /* domain number (-1 if target or is_dd) */
	u8 profile;
	//u8 group;
	_Bool is_djt; /* domain jump target */
	_Bool is_dk;  /* domain keeper */
	_Bool is_du;  /* unreachable domain */
	_Bool is_dd;  /* deleted domain */
};

struct ccs_domain_policy3 {
	struct ccs_domain *list;
	int list_len;
	unsigned char *list_selected;
};

extern enum ccs_screen_type ccs_current_screen;
extern int ccs_list_item_count;
extern int ccs_path_group_list_len;
extern struct ccs_domain_policy3 ccs_dp;
extern struct ccs_editpolicy_directive ccs_directives[CCS_MAX_DIRECTIVE_INDEX];
extern struct ccs_generic_acl *ccs_gacl_list;
extern struct ccs_path_group_entry *ccs_path_group_list;
extern struct ccs_screen ccs_screen[CCS_MAXSCREEN];
extern const struct ccs_path_info *ccs_current_ns;
