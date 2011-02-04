/*
 * editpolicy.h
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
#include <signal.h>
#include <curses.h>

enum ccs_screen_type {
	CCS_SCREEN_EXCEPTION_LIST,
	CCS_SCREEN_DOMAIN_LIST,
	CCS_SCREEN_ACL_LIST,
	CCS_SCREEN_PROFILE_LIST,
	CCS_SCREEN_MANAGER_LIST,
	CCS_SCREEN_QUERY_LIST,
	CCS_SCREEN_STAT_LIST,
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

enum ccs_editpolicy_directives {
	CCS_DIRECTIVE_NONE,
	CCS_DIRECTIVE_ACL_GROUP_000,
	CCS_DIRECTIVE_ACL_GROUP_001,
	CCS_DIRECTIVE_ACL_GROUP_002,
	CCS_DIRECTIVE_ACL_GROUP_003,
	CCS_DIRECTIVE_ACL_GROUP_004,
	CCS_DIRECTIVE_ACL_GROUP_005,
	CCS_DIRECTIVE_ACL_GROUP_006,
	CCS_DIRECTIVE_ACL_GROUP_007,
	CCS_DIRECTIVE_ACL_GROUP_008,
	CCS_DIRECTIVE_ACL_GROUP_009,
	CCS_DIRECTIVE_ACL_GROUP_010,
	CCS_DIRECTIVE_ACL_GROUP_011,
	CCS_DIRECTIVE_ACL_GROUP_012,
	CCS_DIRECTIVE_ACL_GROUP_013,
	CCS_DIRECTIVE_ACL_GROUP_014,
	CCS_DIRECTIVE_ACL_GROUP_015,
	CCS_DIRECTIVE_ACL_GROUP_016,
	CCS_DIRECTIVE_ACL_GROUP_017,
	CCS_DIRECTIVE_ACL_GROUP_018,
	CCS_DIRECTIVE_ACL_GROUP_019,
	CCS_DIRECTIVE_ACL_GROUP_020,
	CCS_DIRECTIVE_ACL_GROUP_021,
	CCS_DIRECTIVE_ACL_GROUP_022,
	CCS_DIRECTIVE_ACL_GROUP_023,
	CCS_DIRECTIVE_ACL_GROUP_024,
	CCS_DIRECTIVE_ACL_GROUP_025,
	CCS_DIRECTIVE_ACL_GROUP_026,
	CCS_DIRECTIVE_ACL_GROUP_027,
	CCS_DIRECTIVE_ACL_GROUP_028,
	CCS_DIRECTIVE_ACL_GROUP_029,
	CCS_DIRECTIVE_ACL_GROUP_030,
	CCS_DIRECTIVE_ACL_GROUP_031,
	CCS_DIRECTIVE_ACL_GROUP_032,
	CCS_DIRECTIVE_ACL_GROUP_033,
	CCS_DIRECTIVE_ACL_GROUP_034,
	CCS_DIRECTIVE_ACL_GROUP_035,
	CCS_DIRECTIVE_ACL_GROUP_036,
	CCS_DIRECTIVE_ACL_GROUP_037,
	CCS_DIRECTIVE_ACL_GROUP_038,
	CCS_DIRECTIVE_ACL_GROUP_039,
	CCS_DIRECTIVE_ACL_GROUP_040,
	CCS_DIRECTIVE_ACL_GROUP_041,
	CCS_DIRECTIVE_ACL_GROUP_042,
	CCS_DIRECTIVE_ACL_GROUP_043,
	CCS_DIRECTIVE_ACL_GROUP_044,
	CCS_DIRECTIVE_ACL_GROUP_045,
	CCS_DIRECTIVE_ACL_GROUP_046,
	CCS_DIRECTIVE_ACL_GROUP_047,
	CCS_DIRECTIVE_ACL_GROUP_048,
	CCS_DIRECTIVE_ACL_GROUP_049,
	CCS_DIRECTIVE_ACL_GROUP_050,
	CCS_DIRECTIVE_ACL_GROUP_051,
	CCS_DIRECTIVE_ACL_GROUP_052,
	CCS_DIRECTIVE_ACL_GROUP_053,
	CCS_DIRECTIVE_ACL_GROUP_054,
	CCS_DIRECTIVE_ACL_GROUP_055,
	CCS_DIRECTIVE_ACL_GROUP_056,
	CCS_DIRECTIVE_ACL_GROUP_057,
	CCS_DIRECTIVE_ACL_GROUP_058,
	CCS_DIRECTIVE_ACL_GROUP_059,
	CCS_DIRECTIVE_ACL_GROUP_060,
	CCS_DIRECTIVE_ACL_GROUP_061,
	CCS_DIRECTIVE_ACL_GROUP_062,
	CCS_DIRECTIVE_ACL_GROUP_063,
	CCS_DIRECTIVE_ACL_GROUP_064,
	CCS_DIRECTIVE_ACL_GROUP_065,
	CCS_DIRECTIVE_ACL_GROUP_066,
	CCS_DIRECTIVE_ACL_GROUP_067,
	CCS_DIRECTIVE_ACL_GROUP_068,
	CCS_DIRECTIVE_ACL_GROUP_069,
	CCS_DIRECTIVE_ACL_GROUP_070,
	CCS_DIRECTIVE_ACL_GROUP_071,
	CCS_DIRECTIVE_ACL_GROUP_072,
	CCS_DIRECTIVE_ACL_GROUP_073,
	CCS_DIRECTIVE_ACL_GROUP_074,
	CCS_DIRECTIVE_ACL_GROUP_075,
	CCS_DIRECTIVE_ACL_GROUP_076,
	CCS_DIRECTIVE_ACL_GROUP_077,
	CCS_DIRECTIVE_ACL_GROUP_078,
	CCS_DIRECTIVE_ACL_GROUP_079,
	CCS_DIRECTIVE_ACL_GROUP_080,
	CCS_DIRECTIVE_ACL_GROUP_081,
	CCS_DIRECTIVE_ACL_GROUP_082,
	CCS_DIRECTIVE_ACL_GROUP_083,
	CCS_DIRECTIVE_ACL_GROUP_084,
	CCS_DIRECTIVE_ACL_GROUP_085,
	CCS_DIRECTIVE_ACL_GROUP_086,
	CCS_DIRECTIVE_ACL_GROUP_087,
	CCS_DIRECTIVE_ACL_GROUP_088,
	CCS_DIRECTIVE_ACL_GROUP_089,
	CCS_DIRECTIVE_ACL_GROUP_090,
	CCS_DIRECTIVE_ACL_GROUP_091,
	CCS_DIRECTIVE_ACL_GROUP_092,
	CCS_DIRECTIVE_ACL_GROUP_093,
	CCS_DIRECTIVE_ACL_GROUP_094,
	CCS_DIRECTIVE_ACL_GROUP_095,
	CCS_DIRECTIVE_ACL_GROUP_096,
	CCS_DIRECTIVE_ACL_GROUP_097,
	CCS_DIRECTIVE_ACL_GROUP_098,
	CCS_DIRECTIVE_ACL_GROUP_099,
	CCS_DIRECTIVE_ACL_GROUP_100,
	CCS_DIRECTIVE_ACL_GROUP_101,
	CCS_DIRECTIVE_ACL_GROUP_102,
	CCS_DIRECTIVE_ACL_GROUP_103,
	CCS_DIRECTIVE_ACL_GROUP_104,
	CCS_DIRECTIVE_ACL_GROUP_105,
	CCS_DIRECTIVE_ACL_GROUP_106,
	CCS_DIRECTIVE_ACL_GROUP_107,
	CCS_DIRECTIVE_ACL_GROUP_108,
	CCS_DIRECTIVE_ACL_GROUP_109,
	CCS_DIRECTIVE_ACL_GROUP_110,
	CCS_DIRECTIVE_ACL_GROUP_111,
	CCS_DIRECTIVE_ACL_GROUP_112,
	CCS_DIRECTIVE_ACL_GROUP_113,
	CCS_DIRECTIVE_ACL_GROUP_114,
	CCS_DIRECTIVE_ACL_GROUP_115,
	CCS_DIRECTIVE_ACL_GROUP_116,
	CCS_DIRECTIVE_ACL_GROUP_117,
	CCS_DIRECTIVE_ACL_GROUP_118,
	CCS_DIRECTIVE_ACL_GROUP_119,
	CCS_DIRECTIVE_ACL_GROUP_120,
	CCS_DIRECTIVE_ACL_GROUP_121,
	CCS_DIRECTIVE_ACL_GROUP_122,
	CCS_DIRECTIVE_ACL_GROUP_123,
	CCS_DIRECTIVE_ACL_GROUP_124,
	CCS_DIRECTIVE_ACL_GROUP_125,
	CCS_DIRECTIVE_ACL_GROUP_126,
	CCS_DIRECTIVE_ACL_GROUP_127,
	CCS_DIRECTIVE_ACL_GROUP_128,
	CCS_DIRECTIVE_ACL_GROUP_129,
	CCS_DIRECTIVE_ACL_GROUP_130,
	CCS_DIRECTIVE_ACL_GROUP_131,
	CCS_DIRECTIVE_ACL_GROUP_132,
	CCS_DIRECTIVE_ACL_GROUP_133,
	CCS_DIRECTIVE_ACL_GROUP_134,
	CCS_DIRECTIVE_ACL_GROUP_135,
	CCS_DIRECTIVE_ACL_GROUP_136,
	CCS_DIRECTIVE_ACL_GROUP_137,
	CCS_DIRECTIVE_ACL_GROUP_138,
	CCS_DIRECTIVE_ACL_GROUP_139,
	CCS_DIRECTIVE_ACL_GROUP_140,
	CCS_DIRECTIVE_ACL_GROUP_141,
	CCS_DIRECTIVE_ACL_GROUP_142,
	CCS_DIRECTIVE_ACL_GROUP_143,
	CCS_DIRECTIVE_ACL_GROUP_144,
	CCS_DIRECTIVE_ACL_GROUP_145,
	CCS_DIRECTIVE_ACL_GROUP_146,
	CCS_DIRECTIVE_ACL_GROUP_147,
	CCS_DIRECTIVE_ACL_GROUP_148,
	CCS_DIRECTIVE_ACL_GROUP_149,
	CCS_DIRECTIVE_ACL_GROUP_150,
	CCS_DIRECTIVE_ACL_GROUP_151,
	CCS_DIRECTIVE_ACL_GROUP_152,
	CCS_DIRECTIVE_ACL_GROUP_153,
	CCS_DIRECTIVE_ACL_GROUP_154,
	CCS_DIRECTIVE_ACL_GROUP_155,
	CCS_DIRECTIVE_ACL_GROUP_156,
	CCS_DIRECTIVE_ACL_GROUP_157,
	CCS_DIRECTIVE_ACL_GROUP_158,
	CCS_DIRECTIVE_ACL_GROUP_159,
	CCS_DIRECTIVE_ACL_GROUP_160,
	CCS_DIRECTIVE_ACL_GROUP_161,
	CCS_DIRECTIVE_ACL_GROUP_162,
	CCS_DIRECTIVE_ACL_GROUP_163,
	CCS_DIRECTIVE_ACL_GROUP_164,
	CCS_DIRECTIVE_ACL_GROUP_165,
	CCS_DIRECTIVE_ACL_GROUP_166,
	CCS_DIRECTIVE_ACL_GROUP_167,
	CCS_DIRECTIVE_ACL_GROUP_168,
	CCS_DIRECTIVE_ACL_GROUP_169,
	CCS_DIRECTIVE_ACL_GROUP_170,
	CCS_DIRECTIVE_ACL_GROUP_171,
	CCS_DIRECTIVE_ACL_GROUP_172,
	CCS_DIRECTIVE_ACL_GROUP_173,
	CCS_DIRECTIVE_ACL_GROUP_174,
	CCS_DIRECTIVE_ACL_GROUP_175,
	CCS_DIRECTIVE_ACL_GROUP_176,
	CCS_DIRECTIVE_ACL_GROUP_177,
	CCS_DIRECTIVE_ACL_GROUP_178,
	CCS_DIRECTIVE_ACL_GROUP_179,
	CCS_DIRECTIVE_ACL_GROUP_180,
	CCS_DIRECTIVE_ACL_GROUP_181,
	CCS_DIRECTIVE_ACL_GROUP_182,
	CCS_DIRECTIVE_ACL_GROUP_183,
	CCS_DIRECTIVE_ACL_GROUP_184,
	CCS_DIRECTIVE_ACL_GROUP_185,
	CCS_DIRECTIVE_ACL_GROUP_186,
	CCS_DIRECTIVE_ACL_GROUP_187,
	CCS_DIRECTIVE_ACL_GROUP_188,
	CCS_DIRECTIVE_ACL_GROUP_189,
	CCS_DIRECTIVE_ACL_GROUP_190,
	CCS_DIRECTIVE_ACL_GROUP_191,
	CCS_DIRECTIVE_ACL_GROUP_192,
	CCS_DIRECTIVE_ACL_GROUP_193,
	CCS_DIRECTIVE_ACL_GROUP_194,
	CCS_DIRECTIVE_ACL_GROUP_195,
	CCS_DIRECTIVE_ACL_GROUP_196,
	CCS_DIRECTIVE_ACL_GROUP_197,
	CCS_DIRECTIVE_ACL_GROUP_198,
	CCS_DIRECTIVE_ACL_GROUP_199,
	CCS_DIRECTIVE_ACL_GROUP_200,
	CCS_DIRECTIVE_ACL_GROUP_201,
	CCS_DIRECTIVE_ACL_GROUP_202,
	CCS_DIRECTIVE_ACL_GROUP_203,
	CCS_DIRECTIVE_ACL_GROUP_204,
	CCS_DIRECTIVE_ACL_GROUP_205,
	CCS_DIRECTIVE_ACL_GROUP_206,
	CCS_DIRECTIVE_ACL_GROUP_207,
	CCS_DIRECTIVE_ACL_GROUP_208,
	CCS_DIRECTIVE_ACL_GROUP_209,
	CCS_DIRECTIVE_ACL_GROUP_210,
	CCS_DIRECTIVE_ACL_GROUP_211,
	CCS_DIRECTIVE_ACL_GROUP_212,
	CCS_DIRECTIVE_ACL_GROUP_213,
	CCS_DIRECTIVE_ACL_GROUP_214,
	CCS_DIRECTIVE_ACL_GROUP_215,
	CCS_DIRECTIVE_ACL_GROUP_216,
	CCS_DIRECTIVE_ACL_GROUP_217,
	CCS_DIRECTIVE_ACL_GROUP_218,
	CCS_DIRECTIVE_ACL_GROUP_219,
	CCS_DIRECTIVE_ACL_GROUP_220,
	CCS_DIRECTIVE_ACL_GROUP_221,
	CCS_DIRECTIVE_ACL_GROUP_222,
	CCS_DIRECTIVE_ACL_GROUP_223,
	CCS_DIRECTIVE_ACL_GROUP_224,
	CCS_DIRECTIVE_ACL_GROUP_225,
	CCS_DIRECTIVE_ACL_GROUP_226,
	CCS_DIRECTIVE_ACL_GROUP_227,
	CCS_DIRECTIVE_ACL_GROUP_228,
	CCS_DIRECTIVE_ACL_GROUP_229,
	CCS_DIRECTIVE_ACL_GROUP_230,
	CCS_DIRECTIVE_ACL_GROUP_231,
	CCS_DIRECTIVE_ACL_GROUP_232,
	CCS_DIRECTIVE_ACL_GROUP_233,
	CCS_DIRECTIVE_ACL_GROUP_234,
	CCS_DIRECTIVE_ACL_GROUP_235,
	CCS_DIRECTIVE_ACL_GROUP_236,
	CCS_DIRECTIVE_ACL_GROUP_237,
	CCS_DIRECTIVE_ACL_GROUP_238,
	CCS_DIRECTIVE_ACL_GROUP_239,
	CCS_DIRECTIVE_ACL_GROUP_240,
	CCS_DIRECTIVE_ACL_GROUP_241,
	CCS_DIRECTIVE_ACL_GROUP_242,
	CCS_DIRECTIVE_ACL_GROUP_243,
	CCS_DIRECTIVE_ACL_GROUP_244,
	CCS_DIRECTIVE_ACL_GROUP_245,
	CCS_DIRECTIVE_ACL_GROUP_246,
	CCS_DIRECTIVE_ACL_GROUP_247,
	CCS_DIRECTIVE_ACL_GROUP_248,
	CCS_DIRECTIVE_ACL_GROUP_249,
	CCS_DIRECTIVE_ACL_GROUP_250,
	CCS_DIRECTIVE_ACL_GROUP_251,
	CCS_DIRECTIVE_ACL_GROUP_252,
	CCS_DIRECTIVE_ACL_GROUP_253,
	CCS_DIRECTIVE_ACL_GROUP_254,
	CCS_DIRECTIVE_ACL_GROUP_255,
	CCS_DIRECTIVE_ADDRESS_GROUP,
	CCS_DIRECTIVE_AGGREGATOR,
	CCS_DIRECTIVE_CAPABILITY,
	CCS_DIRECTIVE_DENY_AUTOBIND,
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
	CCS_DIRECTIVE_INITIALIZE_DOMAIN,
	CCS_DIRECTIVE_IPC_SIGNAL,
	CCS_DIRECTIVE_KEEP_DOMAIN,
	CCS_DIRECTIVE_MISC_ENV,
	CCS_DIRECTIVE_NETWORK_INET,
	CCS_DIRECTIVE_NETWORK_UNIX,
	CCS_DIRECTIVE_NO_INITIALIZE_DOMAIN,
	CCS_DIRECTIVE_NO_KEEP_DOMAIN,
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
	CCS_DISP_ERR
};

struct ccs_transition_control_entry {
	const struct ccs_path_info *domainname;    /* This may be NULL */
	const struct ccs_path_info *program;       /* This may be NULL */
	u8 type;
	_Bool is_last_name;
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
enum ccs_screen_type ccs_find_directive(const _Bool forward, char *line);
int ccs_add_address_group_policy(char *data, const _Bool is_delete);
int ccs_add_number_group_policy(char *data, const _Bool is_delete);
int ccs_editpolicy_get_current(void);
void ccs_editpolicy_attr_change(const attr_t attr, const _Bool flg);
void ccs_editpolicy_clear_groups(void);
void ccs_editpolicy_color_change(const attr_t attr, const _Bool flg);
void ccs_editpolicy_color_init(void);
void ccs_editpolicy_init_keyword_map(void);
void ccs_editpolicy_line_draw(void);
void ccs_editpolicy_offline_daemon(void);
void ccs_editpolicy_sttr_restore(void);
void ccs_editpolicy_sttr_save(void);
void ccs_editpolicy_optimize(const int current);

extern enum ccs_screen_type ccs_current_screen;
extern struct ccs_screen ccs_screen[CCS_MAXSCREEN];
extern int ccs_gacl_list_count;
extern int ccs_list_item_count;
extern int ccs_path_group_list_len;
extern int ccs_persistent_fd;
extern struct ccs_domain_policy ccs_dp;
extern struct ccs_editpolicy_directive ccs_directives[CCS_MAX_DIRECTIVE_INDEX];
extern struct ccs_generic_acl *ccs_gacl_list;
extern struct ccs_path_group_entry *ccs_path_group_list;
