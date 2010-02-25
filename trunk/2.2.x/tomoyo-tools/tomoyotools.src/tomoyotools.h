/*
 * tomoyotools.h
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 2.2.0+   2010/02/25
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
#include <sched.h>

#define true     1
#define false    0

enum screen_type {
	SCREEN_EXCEPTION_LIST,
	SCREEN_DOMAIN_LIST,
	SCREEN_ACL_LIST,
	SCREEN_PROFILE_LIST,
	SCREEN_MANAGER_LIST,
	SCREEN_MEMINFO_LIST,
	MAXSCREEN
};

enum policy_type {
	POLICY_TYPE_UNKNOWN,
	POLICY_TYPE_DOMAIN_POLICY,
	POLICY_TYPE_EXCEPTION_POLICY,
};

#define KEYWORD_AGGREGATOR               "aggregator "
#define KEYWORD_ALIAS                    "alias "
#define KEYWORD_ALLOW_READ               "allow_read "
#define KEYWORD_DELETE                   "delete "
#define KEYWORD_DENY_REWRITE             "deny_rewrite "
#define KEYWORD_FILE_PATTERN             "file_pattern "
#define KEYWORD_SELECT                   "select "
#define KEYWORD_USE_PROFILE              "use_profile "
#define KEYWORD_USE_PROFILE_LEN          (sizeof(KEYWORD_USE_PROFILE) - 1)
#define KEYWORD_INITIALIZE_DOMAIN        "initialize_domain "
#define KEYWORD_KEEP_DOMAIN              "keep_domain "
#define KEYWORD_NO_INITIALIZE_DOMAIN     "no_" KEYWORD_INITIALIZE_DOMAIN
#define KEYWORD_NO_KEEP_DOMAIN           "no_" KEYWORD_KEEP_DOMAIN
#define KEYWORD_ALLOW_EXECUTE            "allow_execute "

#define SAVENAME_MAX_HASH                256
#define PAGE_SIZE                        4096
#define CCS_MAX_PATHNAME_LEN             4000
#define ROOT_NAME                        "<kernel>"
#define ROOT_NAME_LEN                    (sizeof(ROOT_NAME) - 1)

#define CCSTOOLS_CONFIG_FILE "/usr/lib/tomoyo/tomoyotools.conf"

#define DISK_POLICY_DOMAIN_POLICY    "domain_policy.conf"
#define BASE_POLICY_DOMAIN_POLICY    "domain_policy.base"
#define DISK_POLICY_EXCEPTION_POLICY "exception_policy.conf"
#define BASE_POLICY_EXCEPTION_POLICY "exception_policy.base"
#define DISK_POLICY_PROFILE          "profile.conf"
#define BASE_POLICY_PROFILE          "profile.base"
#define DISK_POLICY_MANAGER          "manager.conf"
#define BASE_POLICY_MANAGER          "manager.base"
#define DISK_POLICY_MEMINFO          "meminfo.conf"
#define BASE_POLICY_MEMINFO          "meminfo.base"

enum editpolicy_directives {
	DIRECTIVE_NONE,
	DIRECTIVE_1,
	DIRECTIVE_2,
	DIRECTIVE_3,
	DIRECTIVE_4,
	DIRECTIVE_5,
	DIRECTIVE_6,
	DIRECTIVE_7,
	DIRECTIVE_ALLOW_EXECUTE,
	DIRECTIVE_ALLOW_READ,
	DIRECTIVE_ALLOW_WRITE,
	DIRECTIVE_ALLOW_READ_WRITE,
	DIRECTIVE_ALLOW_CREATE,
	DIRECTIVE_ALLOW_UNLINK,
	DIRECTIVE_ALLOW_MKDIR,
	DIRECTIVE_ALLOW_RMDIR,
	DIRECTIVE_ALLOW_MKFIFO,
	DIRECTIVE_ALLOW_MKSOCK,
	DIRECTIVE_ALLOW_MKBLOCK,
	DIRECTIVE_ALLOW_MKCHAR,
	DIRECTIVE_ALLOW_TRUNCATE,
	DIRECTIVE_ALLOW_SYMLINK,
	DIRECTIVE_ALLOW_LINK,
	DIRECTIVE_ALLOW_RENAME,
	DIRECTIVE_ALLOW_REWRITE,
	DIRECTIVE_ALLOW_IOCTL,
	DIRECTIVE_ALLOW_CHMOD,
	DIRECTIVE_ALLOW_CHOWN,
	DIRECTIVE_ALLOW_CHGRP,
	DIRECTIVE_ALLOW_MOUNT,
	DIRECTIVE_ALLOW_UNMOUNT,
	DIRECTIVE_ALLOW_CHROOT,
	DIRECTIVE_ALLOW_PIVOT_ROOT,
	DIRECTIVE_AGGREGATOR,
	DIRECTIVE_ALIAS,
	DIRECTIVE_DENY_REWRITE,
	DIRECTIVE_FILE_PATTERN,
	DIRECTIVE_IGNORE_GLOBAL_ALLOW_READ,
	DIRECTIVE_INITIALIZE_DOMAIN,
	DIRECTIVE_KEEP_DOMAIN,
	DIRECTIVE_NO_INITIALIZE_DOMAIN,
	DIRECTIVE_NO_KEEP_DOMAIN,
	DIRECTIVE_QUOTA_EXCEEDED,
	DIRECTIVE_USE_PROFILE,
	DIRECTIVE_TRANSITION_FAILED,
	MAX_DIRECTIVE_INDEX
};

enum color_pair {
	NORMAL, DOMAIN_HEAD, DOMAIN_CURSOR,
	EXCEPTION_HEAD, EXCEPTION_CURSOR, ACL_HEAD, ACL_CURSOR,
	PROFILE_HEAD, PROFILE_CURSOR, MANAGER_HEAD, MANAGER_CURSOR,
	MEMORY_HEAD, MEMORY_CURSOR, DISP_ERR
};

static const int header_lines = 3;

/***** CONSTANTS DEFINITION END *****/

/***** STRUCTURES DEFINITION START *****/

struct path_info {
	const char *name;
	u32 hash;           /* = full_name_hash(name, strlen(name)) */
	u16 total_len;      /* = strlen(name)                       */
	u16 const_len;      /* = const_part_length(name)            */
	_Bool is_dir;       /* = strendswith(name, "/")             */
	_Bool is_patterned; /* = path_contains_pattern(name)        */
};

struct savename_entry {
	struct savename_entry *next;
	struct path_info entry;
};

struct free_memory_block_list {
	struct free_memory_block_list *next;
	char *ptr;
	int len;
};

struct dll_pathname_entry {
	char *pathname;
	char *real_pathname;
};

struct domain_initializer_entry {
	const struct path_info *domainname;    /* This may be NULL */
	const struct path_info *program;
	_Bool is_not;
	_Bool is_last_name;
};

struct domain_keeper_entry {
	const struct path_info *domainname;
	const struct path_info *program;       /* This may be NULL */
	_Bool is_not;
	_Bool is_last_name;
};

struct domain_info {
	const struct path_info *domainname;
	const struct domain_initializer_entry *d_i; /* This may be NULL */
	const struct domain_keeper_entry *d_k; /* This may be NULL */
	const struct path_info **string_ptr;
	int string_count;
	int number;   /* domain number (-1 if is_dis or is_dd) */
	u8 profile;
	_Bool is_dis; /* domain initializer source */
	_Bool is_dit; /* domain initializer target */
	_Bool is_dk;  /* domain keeper */
	_Bool is_du;  /* unreachable domain */
	_Bool is_dd;  /* deleted domain */
};

struct domain_policy {
	struct domain_info *list;
	int list_len;
	unsigned char *list_selected;
};

struct generic_acl {
	u8 directive;
	u8 selected;
	const char *operand;
};

struct editpolicy_directive {
	const char *original;
	const char *alias;
	int original_len;
	int alias_len;
};

struct task_entry {
	pid_t pid;
	pid_t ppid;
	char *name;
	char *domain;
	u8 profile;
	_Bool done;
};

/***** STRUCTURES DEFINITION END *****/

/***** PROTOTYPES DEFINITION START *****/

_Bool check_remote_host(void);
void out_of_memory(void);
void normalize_line(unsigned char *line);
_Bool is_domain_def(const unsigned char *domainname);
_Bool is_correct_domain(const unsigned char *domainname);
void fprintf_encoded(FILE *fp, const char *pathname);
_Bool decode(const char *ascii, char *bin);
_Bool is_correct_path(const char *filename, const s8 start_type,
		      const s8 pattern_type, const s8 end_type);
int string_compare(const void *a, const void *b);
_Bool pathcmp(const struct path_info *a, const struct path_info *b);
void fill_path_info(struct path_info *ptr);
const struct path_info *savename(const char *name);
_Bool str_starts(char *str, const char *begin);
_Bool path_matches_pattern(const struct path_info *pathname0,
			   const struct path_info *pattern0);
char *make_filename(const char *prefix, const time_t time);

int sortpolicy_main(int argc, char *argv[]);
int setprofile_main(int argc, char *argv[]);
int setlevel_main(int argc, char *argv[]);
int diffpolicy_main(int argc, char *argv[]);
int savepolicy_main(int argc, char *argv[]);
int pathmatch_main(int argc, char *argv[]);
int loadpolicy_main(int argc, char *argv[]);
int ldwatch_main(int argc, char *argv[]);
int findtemp_main(int argc, char *argv[]);
int editpolicy_main(int argc, char *argv[]);
int checkpolicy_main(int argc, char *argv[]);
int pstree_main(int argc, char *argv[]);
int patternize_main(int argc, char *argv[]);
int domainmatch_main(int argc, char *argv[]);
void shprintf(const char *fmt, ...)
	__attribute__ ((format(printf, 1, 2)));
_Bool move_proc_to_file(const char *src, const char *base, const char *dest);
_Bool is_identical_file(const char *file1, const char *file2);
FILE *open_read(const char *filename);
FILE *open_write(const char *filename);
void clear_domain_policy(struct domain_policy *dp);
_Bool save_domain_policy_with_diff(struct domain_policy *dp,
				   struct domain_policy *bp,
				   const char *proc, const char *base,
				   const char *diff);
int find_domain_by_ptr(struct domain_policy *dp,
		       const struct path_info *domainname);
void read_domain_policy(struct domain_policy *dp, const char *filename);
void delete_domain(struct domain_policy *dp, const int index);
void handle_domain_policy(struct domain_policy *dp, FILE *fp, _Bool is_write);
int del_string_entry(struct domain_policy *dp, const char *entry,
		     const int index);
int add_string_entry(struct domain_policy *dp, const char *entry,
		     const int index);
int find_domain(struct domain_policy *dp, const char *domainname0,
		const _Bool is_dis, const _Bool is_dd);
int find_or_assign_new_domain(struct domain_policy *dp, const char *domainname,
			      const _Bool is_dis, const _Bool is_dd);
const char *domain_name(const struct domain_policy *dp, const int index);
void send_fd(char *data, int *fd);
void editpolicy_offline_daemon(void);
void editpolicy_init_keyword_map(void);
void editpolicy_line_draw(const int screen);
void editpolicy_try_optimize(struct domain_policy *dp, const int current,
			     const int screen);
u8 find_directive(const _Bool forward, char *line);
void editpolicy_color_init(void);
void editpolicy_color_change(const attr_t attr, const _Bool flg);
void editpolicy_attr_change(const attr_t attr, const _Bool flg);
void editpolicy_sttr_save(void);
void editpolicy_sttr_restore(void);
int editpolicy_color_head(const int screen);
int editpolicy_color_cursor(const int screen);
int editpolicy_get_current(void);

extern char shared_buffer[8192];
void get(void);
void put(void);
_Bool freadline(FILE *fp);

char *simple_readline(const int start_y, const int start_x, const char *prompt,
		      const char *history[], const int history_count,
		      const int max_length, const int scroll_width);
int simple_add_history(const char *buffer, const char **history,
		       const int history_count, const int max_history);
int getch2(void);

extern _Bool offline_mode;
extern const char *policy_dir;
extern _Bool network_mode;
extern u32 network_ip;
extern u16 network_port;
extern int persistent_fd;
extern struct generic_acl *generic_acl_list;
extern int generic_acl_list_count;
extern char *initial_readline_data;
extern int current_y[MAXSCREEN];
extern int list_item_count[MAXSCREEN];
extern struct editpolicy_directive directives[MAX_DIRECTIVE_INDEX];

#define proc_policy_dir              "/sys/kernel/security/tomoyo/"
#define disk_policy_dir              "/etc/tomoyo/"
#define proc_policy_domain_policy    "/sys/kernel/security/tomoyo/domain_policy"
#define proc_policy_exception_policy "/sys/kernel/security/tomoyo/exception_policy"
#define proc_policy_profile          "/sys/kernel/security/tomoyo/profile"
#define proc_policy_manager          "/sys/kernel/security/tomoyo/manager"
#define proc_policy_meminfo          "/sys/kernel/security/tomoyo/meminfo"
#define proc_policy_domain_status    "/sys/kernel/security/tomoyo/.domain_status"
#define proc_policy_process_status   "/sys/kernel/security/tomoyo/.process_status"


/***** PROTOTYPES DEFINITION END *****/
