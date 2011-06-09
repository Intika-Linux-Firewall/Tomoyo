/*
 * tomoyotools.h
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.4.0-pre   2011/06/09
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
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <asm/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <sched.h>
#include <sys/mount.h>

#define s8 __s8
#define u8 __u8
#define u16 __u16
#define u32 __u32
#define true  1
#define false 0

/***** CONSTANTS DEFINITION START *****/

#define TOMOYO_PROC_POLICY_DIR              "/sys/kernel/security/tomoyo/"
#define TOMOYO_PROC_POLICY_DOMAIN_POLICY    "/sys/kernel/security/tomoyo/domain_policy"
#define TOMOYO_PROC_POLICY_DOMAIN_STATUS    "/sys/kernel/security/tomoyo/.domain_status"
#define TOMOYO_PROC_POLICY_EXCEPTION_POLICY "/sys/kernel/security/tomoyo/exception_policy"
#define TOMOYO_PROC_POLICY_AUDIT            "/sys/kernel/security/tomoyo/audit"
#define TOMOYO_PROC_POLICY_MANAGER          "/sys/kernel/security/tomoyo/manager"
#define TOMOYO_PROC_POLICY_STAT             "/sys/kernel/security/tomoyo/stat"
#define TOMOYO_PROC_POLICY_PROCESS_STATUS   "/sys/kernel/security/tomoyo/.process_status"
#define TOMOYO_PROC_POLICY_PROFILE          "/sys/kernel/security/tomoyo/profile"
#define TOMOYO_PROC_POLICY_QUERY            "/sys/kernel/security/tomoyo/query"

/***** CONSTANTS DEFINITION END *****/

/***** STRUCTURES DEFINITION START *****/

struct tomoyo_path_info {
	const char *name;
	u32 hash;           /* = tomoyo_full_name_hash(name, total_len) */
	u16 total_len;      /* = strlen(name)                        */
	u16 const_len;      /* = tomoyo_const_part_length(name)         */
	_Bool is_dir;       /* = tomoyo_strendswith(name, "/")          */
	_Bool is_patterned; /* = const_len < total_len               */
};

struct tomoyo_ip_address_entry {
	u8 min[16];
	u8 max[16];
	_Bool is_ipv6;
};

struct tomoyo_number_entry {
	unsigned long min;
	unsigned long max;
};

struct tomoyo_domain_info {
	const struct tomoyo_path_info *domainname;
	const char *target_domainname; /* This may be NULL */
	const struct tomoyo_transition_control_entry *d_t; /* This may be NULL */
	const struct tomoyo_path_info **string_ptr;
	int string_count;
	int number;   /* domain number (-1 if is_dis or is_dd) */
	u8 profile;
	_Bool is_dis; /* domain initializer source */
	_Bool is_dit; /* domain initializer target */
	_Bool is_dk;  /* domain keeper */
	_Bool is_du;  /* unreachable domain */
	_Bool is_dd;  /* deleted domain */
	_Bool profile_assigned;
	u8 group;
};

struct tomoyo_domain_policy {
	struct tomoyo_domain_info *list;
	int list_len;
	unsigned char *list_selected;
};

struct tomoyo_task_entry {
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

FILE *tomoyo_open_read(const char *filename);
FILE *tomoyo_open_write(const char *filename);
_Bool tomoyo_check_remote_host(void);
_Bool tomoyo_close_write(FILE *fp);
_Bool tomoyo_correct_domain(const char *domainname);
_Bool tomoyo_correct_path(const char *filename);
_Bool tomoyo_correct_word(const char *string);
_Bool tomoyo_decode(const char *ascii, char *bin);
_Bool tomoyo_domain_def(const char *domainname);
_Bool tomoyo_move_proc_to_file(const char *src, const char *dest);
_Bool tomoyo_path_matches_pattern(const struct tomoyo_path_info *pathname0,
			       const struct tomoyo_path_info *pattern0);
_Bool tomoyo_pathcmp(const struct tomoyo_path_info *a,
		  const struct tomoyo_path_info *b);
_Bool tomoyo_str_starts(char *str, const char *begin);
char *tomoyo_freadline(FILE *fp);
char *tomoyo_freadline_unpack(FILE *fp);
char *tomoyo_shprintf(const char *fmt, ...)
	__attribute__ ((format(printf, 1, 2)));
char *tomoyo_strdup(const char *string);
const char *tomoyo_domain_name(const struct tomoyo_domain_policy *dp,
			    const int index);
const struct tomoyo_path_info *tomoyo_savename(const char *name);
int tomoyo_add_string_entry(struct tomoyo_domain_policy *dp, const char *entry,
			 const int index);
int tomoyo_assign_domain(struct tomoyo_domain_policy *dp, const char *domainname,
		      const _Bool is_dis, const _Bool is_dd);
int tomoyo_del_string_entry(struct tomoyo_domain_policy *dp, const char *entry,
			 const int index);
int tomoyo_find_domain(const struct tomoyo_domain_policy *dp,
		    const char *domainname0, const _Bool is_dis,
		    const _Bool is_dd);
int tomoyo_find_domain_by_ptr(struct tomoyo_domain_policy *dp,
			   const struct tomoyo_path_info *domainname);
int tomoyo_open_stream(const char *filename);
int tomoyo_parse_ip(const char *address, struct tomoyo_ip_address_entry *entry);
int tomoyo_parse_number(const char *number, struct tomoyo_number_entry *entry);
int tomoyo_string_compare(const void *a, const void *b);
int tomoyo_write_domain_policy(struct tomoyo_domain_policy *dp, const int fd);
struct tomoyo_path_group_entry *tomoyo_find_path_group(const char *group_name);
void *tomoyo_malloc(const size_t size);
void *tomoyo_realloc(void *ptr, const size_t size);
void *tomoyo_realloc2(void *ptr, const size_t size);
void tomoyo_clear_domain_policy(struct tomoyo_domain_policy *dp);
void tomoyo_delete_domain(struct tomoyo_domain_policy *dp, const int index);
void tomoyo_fill_path_info(struct tomoyo_path_info *ptr);
void tomoyo_fprintf_encoded(FILE *fp, const char *tomoyo_pathname);
void tomoyo_get(void);
void tomoyo_handle_domain_policy(struct tomoyo_domain_policy *dp, FILE *fp,
			      _Bool is_write);
void tomoyo_mount_securityfs(void);
void tomoyo_normalize_line(char *buffer);
void tomoyo_put(void);
void tomoyo_read_domain_policy(struct tomoyo_domain_policy *dp,
			    const char *filename);
void tomoyo_read_process_list(_Bool show_all);

extern _Bool tomoyo_freadline_raw;
extern _Bool tomoyo_network_mode;
extern int tomoyo_task_list_len;
extern struct tomoyo_task_entry *tomoyo_task_list;
extern u16 tomoyo_network_port;
extern u32 tomoyo_network_ip;

/***** PROTOTYPES DEFINITION END *****/
