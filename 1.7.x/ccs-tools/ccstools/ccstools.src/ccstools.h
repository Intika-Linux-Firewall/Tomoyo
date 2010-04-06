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

#define CCS_MAX_PATHNAME_LEN             4000
#define CCS_ROOT_NAME                    "<kernel>"
#define CCS_ROOT_NAME_LEN            (sizeof(CCS_ROOT_NAME) - 1)

#define CCSTOOLS_CONFIG_FILE "/usr/lib/ccs/ccstools.conf"

#define CCS_DISK_POLICY_DOMAIN_POLICY    "domain_policy.conf"
#define CCS_DISK_POLICY_EXCEPTION_POLICY "exception_policy.conf"
#define CCS_DISK_POLICY_PROFILE          "profile.conf"
#define CCS_DISK_POLICY_MANAGER          "manager.conf"
#define CCS_DISK_POLICY_MEMINFO          "meminfo.conf"

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

struct ccs_ip_address_entry {
	u8 min[16];
	u8 max[16];
	_Bool is_ipv6;
};

struct ccs_number_entry {
	unsigned long min;
	unsigned long max;
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
_Bool ccs_is_correct_path(const char *filename, const s8 start_type, const s8 pattern_type, const s8 end_type);
int ccs_string_compare(const void *a, const void *b);
_Bool ccs_pathcmp(const struct ccs_path_info *a, const struct ccs_path_info *b);
void ccs_fill_path_info(struct ccs_path_info *ptr);
const struct ccs_path_info *ccs_savename(const char *name);
_Bool ccs_str_starts(char *str, const char *begin);
_Bool ccs_path_matches_pattern(const struct ccs_path_info *pathname0, const struct ccs_path_info *pattern0);
char *ccs_make_filename(const char *prefix, const time_t time);
_Bool ccs_move_proc_to_file(const char *src, const char *dest);
_Bool ccs_is_identical_file(const char *file1, const char *file2);
FILE *ccs_open_read(const char *filename);
FILE *ccs_open_write(const char *filename);
int ccs_open_stream(const char *filename);
void ccs_clear_domain_policy(struct ccs_domain_policy *dp);
int ccs_find_domain_by_ptr(struct ccs_domain_policy *dp, const struct ccs_path_info *domainname);
void ccs_read_domain_policy(struct ccs_domain_policy *dp, const char *filename);
int ccs_write_domain_policy(struct ccs_domain_policy *dp, const int fd);
void ccs_delete_domain(struct ccs_domain_policy *dp, const int index);
void ccs_handle_domain_policy(struct ccs_domain_policy *dp, FILE *fp, _Bool is_write);
int ccs_del_string_entry(struct ccs_domain_policy *dp, const char *entry, const int index);
int ccs_add_string_entry(struct ccs_domain_policy *dp, const char *entry, const int index);
int ccs_find_domain(struct ccs_domain_policy *dp, const char *domainname0, const _Bool is_dis, const _Bool is_dd);
int ccs_find_or_assign_new_domain(struct ccs_domain_policy *dp, const char *domainname, const _Bool is_dis, const _Bool is_dd);
const char *ccs_domain_name(const struct ccs_domain_policy *dp, const int index);
void ccs_send_fd(char *data, int *fd);
void ccs_read_process_list(_Bool show_all);
struct ccs_path_group_entry *ccs_find_path_group(const char *group_name);
u8 ccs_find_directive(const _Bool forward, char *line);
int ccs_parse_number(const char *number, struct ccs_number_entry *entry);
int ccs_parse_ip(const char *address, struct ccs_ip_address_entry *entry);
void ccs_get(void);
void ccs_put(void);
char *ccs_freadline(FILE *fp);
char *ccs_shprintf(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));

extern const char *ccs_policy_dir;
extern _Bool ccs_network_mode;
extern u32 ccs_network_ip;
extern u16 ccs_network_port;
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
