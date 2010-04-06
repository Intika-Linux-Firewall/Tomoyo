/*
 * ccstools.h
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.2+   2010/04/06
 *
 */

/***** CONSTANTS DEFINITION START *****/

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define s8 __s8
#define u8 __u8
#define u16 __u16
#define u32 __u32
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <asm/types.h>
#include <curses.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define true     1
#define false    0

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

enum ccs_policy_type {
	CCS_POLICY_TYPE_UNKNOWN,
	CCS_POLICY_TYPE_DOMAIN_POLICY,
	CCS_POLICY_TYPE_EXCEPTION_POLICY,
};

#define CCS_VALUE_TYPE_DECIMAL     1
#define CCS_VALUE_TYPE_OCTAL       2
#define CCS_VALUE_TYPE_HEXADECIMAL 3

enum ccs_socket_operation_type {
	CCS_NETWORK_ACL_UDP_BIND,
	CCS_NETWORK_ACL_UDP_CONNECT,
	CCS_NETWORK_ACL_TCP_BIND,
	CCS_NETWORK_ACL_TCP_LISTEN,
	CCS_NETWORK_ACL_TCP_CONNECT,
	CCS_NETWORK_ACL_TCP_ACCEPT,
	CCS_NETWORK_ACL_RAW_BIND,
	CCS_NETWORK_ACL_RAW_CONNECT
};

#define CCS_KEYWORD_AGGREGATOR               "aggregator "
#define CCS_KEYWORD_ALLOW_ENV                "allow_env "
#define CCS_KEYWORD_ALLOW_IOCTL              "allow_ioctl "
#define CCS_KEYWORD_ALLOW_CAPABILITY         "allow_capability "
#define CCS_KEYWORD_ALLOW_CHROOT             "allow_chroot "
#define CCS_KEYWORD_ALLOW_MOUNT              "allow_mount "
#define CCS_KEYWORD_ALLOW_NETWORK            "allow_network "
#define CCS_KEYWORD_ALLOW_PIVOT_ROOT         "allow_pivot_root "
#define CCS_KEYWORD_ALLOW_READ               "allow_read "
#define CCS_KEYWORD_ALLOW_SIGNAL             "allow_signal "
#define CCS_KEYWORD_DELETE                   "delete "
#define CCS_KEYWORD_DENY_AUTOBIND            "deny_autobind "
#define CCS_KEYWORD_DENY_REWRITE             "deny_rewrite "
#define CCS_KEYWORD_ALLOW_UNMOUNT            "allow_unmount "
#define CCS_KEYWORD_ALLOW_CHMOD              "allow_chmod "
#define CCS_KEYWORD_ALLOW_CHOWN              "allow_chown "
#define CCS_KEYWORD_ALLOW_CHGRP              "allow_chgrp "
#define CCS_KEYWORD_FILE_PATTERN             "file_pattern "
#define CCS_KEYWORD_MAC_FOR_CAPABILITY       "MAC_FOR_CAPABILITY::"
#define CCS_KEYWORD_SELECT                   "select "
#define CCS_KEYWORD_UNDELETE                 "undelete "
#define CCS_KEYWORD_USE_PROFILE              "use_profile "
#define CCS_KEYWORD_USE_PROFILE_LEN          (sizeof(CCS_KEYWORD_USE_PROFILE) - 1)
#define CCS_KEYWORD_INITIALIZE_DOMAIN        "initialize_domain "
#define CCS_KEYWORD_KEEP_DOMAIN              "keep_domain "
#define CCS_KEYWORD_PATH_GROUP               "path_group "
#define CCS_KEYWORD_ADDRESS_GROUP            "address_group "
#define CCS_KEYWORD_NUMBER_GROUP             "number_group "
#define CCS_KEYWORD_NO_INITIALIZE_DOMAIN     "no_" CCS_KEYWORD_INITIALIZE_DOMAIN
#define CCS_KEYWORD_NO_KEEP_DOMAIN           "no_" CCS_KEYWORD_KEEP_DOMAIN
#define CCS_KEYWORD_EXECUTE_HANDLER          "execute_handler "
#define CCS_KEYWORD_DENIED_EXECUTE_HANDLER   "denied_execute_handler "
#define CCS_KEYWORD_ALLOW_EXECUTE            "allow_execute "

#define CCS_AUDITD_MAX_FILES             2
#define CCS_SAVENAME_MAX_HASH            256
#define CCS_PAGE_SIZE                    4096
#define CCS_MAX_PATHNAME_LEN             4000
#define CCS_ROOT_NAME                    "<kernel>"
#define CCS_ROOT_NAME_LEN            (sizeof(CCS_ROOT_NAME) - 1)

#define CCSTOOLS_CONFIG_FILE "/usr/lib/ccs/ccstools.conf"

#define CCS_DISK_POLICY_DOMAIN_POLICY    "domain_policy.conf"
#define CCS_DISK_POLICY_EXCEPTION_POLICY "exception_policy.conf"
#define CCS_DISK_POLICY_PROFILE          "profile.conf"
#define CCS_DISK_POLICY_MANAGER          "manager.conf"
#define CCS_DISK_POLICY_MEMINFO          "meminfo.conf"

enum ccs_editpolicy_directives {
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

enum ccs_color_pair {
	CCS_NORMAL, CCS_DOMAIN_HEAD, CCS_DOMAIN_CURSOR,
	CCS_EXCEPTION_HEAD, CCS_EXCEPTION_CURSOR, CCS_ACL_HEAD, CCS_ACL_CURSOR,
	CCS_PROFILE_HEAD, CCS_PROFILE_CURSOR, CCS_MANAGER_HEAD, CCS_MANAGER_CURSOR,
	CCS_MEMORY_HEAD, CCS_MEMORY_CURSOR, CCS_DISP_ERR
};

static const int ccs_header_lines = 3;

/***** CONSTANTS DEFINITION END *****/

/***** STRUCTURES DEFINITION START *****/

struct ccs_path_info {
	const char *name;
	u32 hash;           /* = ccs_full_name_hash(name, total_len) */
	u16 total_len;      /* = strlen(name)                        */
	u16 const_len;      /* = ccs_const_part_length(name)         */
	_Bool is_dir;       /* = ccs_strendswith(name, "/")          */
	_Bool is_patterned; /* = const_len < total_len               */
};

struct ccs_path_group_entry {
	const struct ccs_path_info *group_name;
	const struct ccs_path_info **member_name;
	int member_name_len;
};

struct ccs_ip_address_entry {
	u8 min[16];
	u8 max[16];
	_Bool is_ipv6;
};

struct ccs_address_group_entry {
	const struct ccs_path_info *group_name;
	struct ccs_ip_address_entry *member_name;
	int member_name_len;
};

struct ccs_number_entry {
	unsigned long min;
	unsigned long max;
};

struct ccs_number_group_entry {
	const struct ccs_path_info *group_name;
	struct ccs_number_entry *member_name;
	int member_name_len;
};

struct ccs_savename_entry {
	struct ccs_savename_entry *next;
	struct ccs_path_info entry;
};

struct ccs_free_memory_block_list {
	struct ccs_free_memory_block_list *next;
	char *ptr;
	int len;
};

struct ccs_dll_pathname_entry {
	char *pathname;
	char *real_pathname;
};

struct ccs_domain_initializer_entry {
	const struct ccs_path_info *domainname;    /* This may be NULL */
	const struct ccs_path_info *program;
	_Bool is_not;
	_Bool is_last_name;
};

struct ccs_domain_keeper_entry {
	const struct ccs_path_info *domainname;
	const struct ccs_path_info *program;       /* This may be NULL */
	_Bool is_not;
	_Bool is_last_name;
};

struct ccs_domain_info {
	const struct ccs_path_info *domainname;
	const struct ccs_domain_initializer_entry *d_i; /* This may be NULL */
	const struct ccs_domain_keeper_entry *d_k; /* This may be NULL */
	const struct ccs_path_info **string_ptr;
	int string_count;
	int number;   /* domain number (-1 if is_dis or is_dd) */
	u8 profile;
	_Bool is_dis; /* domain initializer source */
	_Bool is_dit; /* domain initializer target */
	_Bool is_dk;  /* domain keeper */
	_Bool is_du;  /* unreachable domain */
	_Bool is_dd;  /* deleted domain */
	_Bool profile_assigned;
};

struct ccs_domain_policy {
	struct ccs_domain_info *list;
	int list_len;
	unsigned char *list_selected;
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

struct ccs_task_entry {
	pid_t pid;
	pid_t ppid;
	char *name;
	char *domain;
	u8 profile;
	_Bool selected;
	int index;
	int depth;
};

/***** STRUCTURES DEFINITION END *****/

/***** PROTOTYPES DEFINITION START *****/

_Bool ccs_check_remote_host(void);
void ccs_out_of_memory(void);
void ccs_normalize_line(unsigned char *line);
_Bool ccs_is_domain_def(const unsigned char *domainname);
_Bool ccs_is_correct_domain(const unsigned char *domainname);
void ccs_fprintf_encoded(FILE *fp, const char *ccs_pathname);
_Bool ccs_decode(const char *ascii, char *bin);
_Bool ccs_is_correct_path(const char *filename, const s8 start_type,
			  const s8 pattern_type, const s8 end_type);
int ccs_string_compare(const void *a, const void *b);
_Bool ccs_pathcmp(const struct ccs_path_info *a, const struct ccs_path_info *b);
void ccs_fill_path_info(struct ccs_path_info *ptr);
const struct ccs_path_info *ccs_savename(const char *name);
_Bool ccs_str_starts(char *str, const char *begin);
_Bool ccs_path_matches_pattern(const struct ccs_path_info *pathname0,
			       const struct ccs_path_info *pattern0);
char *ccs_make_filename(const char *prefix, const time_t time);

int ccs_sortpolicy_main(int argc, char *argv[]);
int ccs_setprofile_main(int argc, char *argv[]);
int ccs_setlevel_main(int argc, char *argv[]);
int ccs_selectpolicy_main(int argc, char *argv[]);
int ccs_diffpolicy_main(int argc, char *argv[]);
int ccs_savepolicy_main(int argc, char *argv[]);
int ccs_pathmatch_main(int argc, char *argv[]);
int ccs_loadpolicy_main(int argc, char *argv[]);
int ccs_ldwatch_main(int argc, char *argv[]);
int ccs_findtemp_main(int argc, char *argv[]);
int ccs_editpolicy_main(int argc, char *argv[]);
int ccs_checkpolicy_main(int argc, char *argv[]);
int ccs_pstree_main(int argc, char *argv[]);
int ccs_queryd_main(int argc, char *argv[]);
int ccs_auditd_main(int argc, char *argv[]);
int ccs_patternize_main(int argc, char *argv[]);
_Bool ccs_move_proc_to_file(const char *src, const char *dest);
_Bool ccs_is_identical_file(const char *file1, const char *file2);
FILE *ccs_open_read(const char *filename);
FILE *ccs_open_write(const char *filename);
int ccs_open_stream(const char *filename);
void ccs_clear_domain_policy(struct ccs_domain_policy *dp);
int ccs_find_domain_by_ptr(struct ccs_domain_policy *dp,
			   const struct ccs_path_info *domainname);
void ccs_read_domain_policy(struct ccs_domain_policy *dp, const char *filename);
void ccs_delete_domain(struct ccs_domain_policy *dp, const int index);
void ccs_handle_domain_policy(struct ccs_domain_policy *dp, FILE *fp, _Bool is_write);
int ccs_del_string_entry(struct ccs_domain_policy *dp, const char *entry,
			 const int index);
int ccs_add_string_entry(struct ccs_domain_policy *dp, const char *entry,
			 const int index);
int ccs_find_domain(struct ccs_domain_policy *dp, const char *domainname0,
		    const _Bool is_dis, const _Bool is_dd);
int ccs_find_or_assign_new_domain(struct ccs_domain_policy *dp, const char *domainname,
				  const _Bool is_dis, const _Bool is_dd);
const char *ccs_domain_name(const struct ccs_domain_policy *dp, const int index);
void ccs_send_fd(char *data, int *fd);
void ccs_read_process_list(_Bool show_all);
void ccs_editpolicy_offline_daemon(void);
void ccs_editpolicy_init_keyword_map(void);
void ccs_editpolicy_line_draw(const int screen);
void ccs_editpolicy_try_optimize(struct ccs_domain_policy *dp, const int current,
				 const int screen);
struct ccs_path_group_entry *ccs_find_path_group(const char *group_name);
int ccs_add_address_group_policy(char *data, const _Bool is_delete);
int ccs_add_number_group_policy(char *data, const _Bool is_delete);
u8 ccs_find_directive(const _Bool forward, char *line);
void ccs_editpolicy_color_init(void);
void ccs_editpolicy_color_change(const attr_t attr, const _Bool flg);
void ccs_editpolicy_attr_change(const attr_t attr, const _Bool flg);
void ccs_editpolicy_sttr_save(void);
void ccs_editpolicy_sttr_restore(void);
int ccs_editpolicy_color_head(const int screen);
int ccs_editpolicy_color_cursor(const int screen);
int ccs_editpolicy_get_current(void);
int ccs_parse_number(const char *number, struct ccs_number_entry *entry);
int ccs_parse_ip(const char *address, struct ccs_ip_address_entry *entry);

void ccs_get(void);
void ccs_put(void);
char *ccs_freadline(FILE *fp);
char *ccs_shprintf(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));

char *ccs_simple_readline(const int start_y, const int start_x, const char *prompt,
			  const char *history[], const int history_count,
			  const int max_length, const int scroll_width);
int ccs_simple_add_history(const char *buffer, const char **history,
			   const int history_count, const int max_history);
int ccs_getch2(void);

extern _Bool ccs_offline_mode;
extern const char *ccs_policy_dir;
extern _Bool ccs_network_mode;
extern u32 ccs_network_ip;
extern u16 ccs_network_port;
extern int ccs_persistent_fd;
extern int ccs_query_fd;
extern int ccs_path_group_list_len;
extern int ccs_address_group_list_len;
extern int ccs_number_group_list_len;
extern struct ccs_generic_acl *ccs_generic_acl_list;
extern int ccs_generic_acl_list_count;
extern char *ccs_initial_readline_data;
extern struct ccs_path_group_entry *ccs_path_group_list;
extern int ccs_path_group_list_len;
extern int ccs_current_y[CCS_MAXSCREEN];
extern int ccs_list_item_count[CCS_MAXSCREEN];
extern struct ccs_editpolicy_directive ccs_directives[CCS_MAX_DIRECTIVE_INDEX];
extern struct ccs_task_entry *ccs_task_list;
extern int ccs_task_list_len;

#define ccs_proc_policy_dir              "/proc/ccs/"
#define ccs_disk_policy_dir              "/etc/ccs/"
#define ccs_proc_policy_domain_policy    "/proc/ccs/domain_policy"
#define ccs_proc_policy_exception_policy "/proc/ccs/exception_policy"
#define ccs_proc_policy_profile          "/proc/ccs/profile"
#define ccs_proc_policy_manager          "/proc/ccs/manager"
#define ccs_proc_policy_meminfo          "/proc/ccs/meminfo"
#define ccs_proc_policy_query            "/proc/ccs/query"
#define ccs_proc_policy_grant_log        "/proc/ccs/grant_log"
#define ccs_proc_policy_reject_log       "/proc/ccs/reject_log"
#define ccs_proc_policy_domain_status    "/proc/ccs/.domain_status"
#define ccs_proc_policy_process_status   "/proc/ccs/.process_status"

/***** PROTOTYPES DEFINITION END *****/
