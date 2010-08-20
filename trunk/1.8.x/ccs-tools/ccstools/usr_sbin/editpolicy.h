/*
 * editpolicy.h
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.8.0-pre   2010/08/01
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
	CCS_SCREEN_QUERY_LIST,
	CCS_SCREEN_MEMINFO_LIST,
	CCS_MAXSCREEN
};

enum ccs_transition_type {
	/* Do not change this order, */
	CCS_TRANSITION_CONTROL_NO_INITIALIZE,
	CCS_TRANSITION_CONTROL_INITIALIZE,
	CCS_TRANSITION_CONTROL_NO_KEEP,
	CCS_TRANSITION_CONTROL_KEEP,
	CCS_MAX_TRANSITION_TYPE
};

struct ccs_transition_control_entry {
	const struct ccs_path_info *domainname;    /* This may be NULL */
	const struct ccs_path_info *program;       /* This may be NULL */
	u8 type;
	_Bool is_last_name;
};

struct ccs_generic_acl {
	u16 directive;
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

enum ccs_editpolicy_directives {
	CCS_DIRECTIVE_NONE,
	CCS_DIRECTIVE_FILE_EXECUTE,
	CCS_DIRECTIVE_FILE_READ,
	CCS_DIRECTIVE_FILE_WRITE,
	CCS_DIRECTIVE_FILE_CREATE,
	CCS_DIRECTIVE_FILE_UNLINK,
	CCS_DIRECTIVE_FILE_MKDIR,
	CCS_DIRECTIVE_FILE_RMDIR,
	CCS_DIRECTIVE_FILE_MKFIFO,
	CCS_DIRECTIVE_FILE_MKSOCK,
	CCS_DIRECTIVE_FILE_MKBLOCK,
	CCS_DIRECTIVE_FILE_MKCHAR,
	CCS_DIRECTIVE_FILE_TRUNCATE,
	CCS_DIRECTIVE_FILE_SYMLINK,
	CCS_DIRECTIVE_FILE_LINK,
	CCS_DIRECTIVE_FILE_RENAME,
	CCS_DIRECTIVE_FILE_APPEND,
	CCS_DIRECTIVE_FILE_TRANSIT,
	CCS_DIRECTIVE_IPC_SIGNAL,
	CCS_DIRECTIVE_NETWORK,
	CCS_DIRECTIVE_FILE_IOCTL,
	CCS_DIRECTIVE_MISC_ENV,
	CCS_DIRECTIVE_ADDRESS_GROUP,
	CCS_DIRECTIVE_AGGREGATOR,
	CCS_DIRECTIVE_CAPABILITY,
	CCS_DIRECTIVE_FILE_CHROOT,
	CCS_DIRECTIVE_FILE_MOUNT,
	CCS_DIRECTIVE_FILE_PIVOT_ROOT,
	CCS_DIRECTIVE_DENY_AUTOBIND,
	CCS_DIRECTIVE_FILE_UNMOUNT,
	CCS_DIRECTIVE_FILE_CHMOD,
	CCS_DIRECTIVE_FILE_CHOWN,
	CCS_DIRECTIVE_FILE_CHGRP,
	CCS_DIRECTIVE_FILE_PATTERN,
	CCS_DIRECTIVE_EXECUTE_HANDLER,
	CCS_DIRECTIVE_DENIED_EXECUTE_HANDLER,
	CCS_DIRECTIVE_USE_GROUP,
	CCS_DIRECTIVE_ACL_GROUP,
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
	CCS_MEMORY_HEAD,
	CCS_MEMORY_CURSOR,
	CCS_DISP_ERR
};

#define CCS_HEADER_LINES 3

#define CCS_CONFIG_FILE "/usr/lib/ccs/ccstools.conf"

int ccs_add_address_group_policy(char *data, const _Bool is_delete);
int ccs_add_number_group_policy(char *data, const _Bool is_delete);
int ccs_editpolicy_color_cursor(const int screen);
int ccs_editpolicy_color_head(const int screen);
int ccs_editpolicy_get_current(void);
void ccs_editpolicy_attr_change(const attr_t attr, const _Bool flg);
void ccs_editpolicy_color_change(const attr_t attr, const _Bool flg);
void ccs_editpolicy_color_init(void);
void ccs_editpolicy_init_keyword_map(void);
void ccs_editpolicy_line_draw(const int screen);
void ccs_editpolicy_offline_daemon(void);
void ccs_editpolicy_sttr_restore(void);
void ccs_editpolicy_sttr_save(void);
void ccs_editpolicy_try_optimize(struct ccs_domain_policy *dp, const int current, const int screen);
void ccs_send_fd(char *data, int *fd);

extern int ccs_address_group_list_len;
extern int ccs_current_y[CCS_MAXSCREEN];
extern int ccs_generic_acl_list_count;
extern int ccs_list_item_count[CCS_MAXSCREEN];
extern int ccs_number_group_list_len;
extern int ccs_path_group_list_len;
extern int ccs_persistent_fd;
extern struct ccs_editpolicy_directive ccs_directives[CCS_MAX_DIRECTIVE_INDEX];
extern struct ccs_generic_acl *ccs_generic_acl_list;
extern struct ccs_path_group_entry *ccs_path_group_list;
