/*
 * editpolicy.h
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
#include <signal.h>
#include <curses.h>

enum tomoyo_screen_type {
	CCS_SCREEN_EXCEPTION_LIST,
	CCS_SCREEN_DOMAIN_LIST,
	CCS_SCREEN_ACL_LIST,
	CCS_SCREEN_PROFILE_LIST,
	CCS_SCREEN_MANAGER_LIST,
	CCS_SCREEN_QUERY_LIST,
	CCS_SCREEN_MEMINFO_LIST,
	CCS_MAXSCREEN
};

struct tomoyo_domain_initializer_entry {
	const struct tomoyo_path_info *domainname;    /* This may be NULL */
	const struct tomoyo_path_info *program;
	_Bool is_not;
	_Bool is_last_name;
};

struct tomoyo_domain_keeper_entry {
	const struct tomoyo_path_info *domainname;
	const struct tomoyo_path_info *program;       /* This may be NULL */
	_Bool is_not;
	_Bool is_last_name;
};

struct tomoyo_generic_acl {
	u16 directive;
	u8 selected;
	const char *operand;
};

struct tomoyo_editpolicy_directive {
	const char *original;
	const char *alias;
	int original_len;
	int alias_len;
};

struct tomoyo_misc_policy {
	const struct tomoyo_path_info **list;
	int list_len;
};

struct tomoyo_path_group_entry {
	const struct tomoyo_path_info *group_name;
	const struct tomoyo_path_info **member_name;
	int member_name_len;
};

struct tomoyo_readline_data {
	const char **history;
	int count;
	int max;
	char *search_buffer[CCS_MAXSCREEN];
};

enum tomoyo_editpolicy_directives {
	CCS_DIRECTIVE_NONE,
	CCS_DIRECTIVE_ALLOW_EXECUTE,
	CCS_DIRECTIVE_ALLOW_READ,
	CCS_DIRECTIVE_ALLOW_WRITE,
	CCS_DIRECTIVE_ALLOW_READ_WRITE,
	CCS_DIRECTIVE_ALLOW_CREATE,
	CCS_DIRECTIVE_ALLOW_UNLINK,
	CCS_DIRECTIVE_ALLOW_MKDIR,
	CCS_DIRECTIVE_ALLOW_RMDIR,
	CCS_DIRECTIVE_ALLOW_MKFIFO,
	CCS_DIRECTIVE_ALLOW_MKSOCK,
	CCS_DIRECTIVE_ALLOW_MKBLOCK,
	CCS_DIRECTIVE_ALLOW_MKCHAR,
	CCS_DIRECTIVE_ALLOW_TRUNCATE,
	CCS_DIRECTIVE_ALLOW_SYMLINK,
	CCS_DIRECTIVE_ALLOW_LINK,
	CCS_DIRECTIVE_ALLOW_RENAME,
	CCS_DIRECTIVE_ALLOW_REWRITE,
	CCS_DIRECTIVE_ALLOW_TRANSIT,
	CCS_DIRECTIVE_ALLOW_SIGNAL,
	CCS_DIRECTIVE_ALLOW_NETWORK,
	CCS_DIRECTIVE_ALLOW_IOCTL,
	CCS_DIRECTIVE_ALLOW_ENV,
	CCS_DIRECTIVE_ADDRESS_GROUP,
	CCS_DIRECTIVE_AGGREGATOR,
	CCS_DIRECTIVE_ALLOW_CAPABILITY,
	CCS_DIRECTIVE_ALLOW_CHROOT,
	CCS_DIRECTIVE_ALLOW_MOUNT,
	CCS_DIRECTIVE_ALLOW_PIVOT_ROOT,
	CCS_DIRECTIVE_DENY_AUTOBIND,
	CCS_DIRECTIVE_DENY_REWRITE,
	CCS_DIRECTIVE_ALLOW_UNMOUNT,
	CCS_DIRECTIVE_ALLOW_CHMOD,
	CCS_DIRECTIVE_ALLOW_CHOWN,
	CCS_DIRECTIVE_ALLOW_CHGRP,
	CCS_DIRECTIVE_FILE_PATTERN,
	CCS_DIRECTIVE_EXECUTE_HANDLER,
	CCS_DIRECTIVE_DENIED_EXECUTE_HANDLER,
	CCS_DIRECTIVE_IGNORE_GLOBAL_ALLOW_ENV,
	CCS_DIRECTIVE_IGNORE_GLOBAL_ALLOW_READ,
	CCS_DIRECTIVE_INITIALIZE_DOMAIN,
	CCS_DIRECTIVE_KEEP_DOMAIN,
	CCS_DIRECTIVE_NO_INITIALIZE_DOMAIN,
	CCS_DIRECTIVE_NO_KEEP_DOMAIN,
	CCS_DIRECTIVE_PATH_GROUP,
	CCS_DIRECTIVE_NUMBER_GROUP,
	CCS_DIRECTIVE_QUOTA_EXCEEDED,
	CCS_DIRECTIVE_USE_PROFILE,
	CCS_DIRECTIVE_TRANSITION_FAILED,
	CCS_MAX_DIRECTIVE_INDEX
};

enum tomoyo_color_pair {
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
	CCS_MEMORY_HEAD,
	CCS_MEMORY_CURSOR,
	CCS_DEFAULT_COLOR,
	CCS_DISP_ERR
};

#define CCS_HEADER_LINES 3

#define CCS_CONFIG_FILE "/usr/lib/tomoyo/tomoyotools.conf"

int tomoyo_add_address_group_policy(char *data, const _Bool is_delete);
int tomoyo_add_number_group_policy(char *data, const _Bool is_delete);
int tomoyo_editpolicy_color_head(const int screen);
int tomoyo_editpolicy_get_current(void);
void tomoyo_editpolicy_attr_change(const attr_t attr, const _Bool flg);
void tomoyo_editpolicy_color_change(const attr_t attr, const _Bool flg);
void tomoyo_editpolicy_color_init(void);
void tomoyo_editpolicy_init_keyword_map(void);
void tomoyo_editpolicy_line_draw(const int screen);
void tomoyo_editpolicy_offline_daemon(void);
void tomoyo_editpolicy_sttr_restore(void);
void tomoyo_editpolicy_sttr_save(void);
void tomoyo_editpolicy_try_optimize(struct tomoyo_domain_policy *dp, const int current, const int screen);
void tomoyo_send_fd(char *data, int *fd);

extern int tomoyo_address_group_list_len;
extern int tomoyo_current_y[CCS_MAXSCREEN];
extern int tomoyo_generic_acl_list_count;
extern int tomoyo_list_item_count[CCS_MAXSCREEN];
extern int tomoyo_number_group_list_len;
extern int tomoyo_path_group_list_len;
extern int tomoyo_persistent_fd;
extern struct tomoyo_editpolicy_directive tomoyo_directives[CCS_MAX_DIRECTIVE_INDEX];
extern struct tomoyo_generic_acl *tomoyo_generic_acl_list;
extern struct tomoyo_path_group_entry *tomoyo_path_group_list;
