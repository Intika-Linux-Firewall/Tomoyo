/*
 * ccstools.h
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

#define s8 __s8
#define u8 __u8
#define u16 __u16
#define u32 __u32
#define true  1
#define false 0

/***** CONSTANTS DEFINITION START *****/

#define CCS_PROC_POLICY_DIR            "/proc/ccs/"
#define CCS_PROC_POLICY_POLICY         "/proc/ccs/policy"
#define CCS_PROC_POLICY_AUDIT          "/proc/ccs/audit"
#define CCS_PROC_POLICY_PROCESS_STATUS "/proc/ccs/.process_status"
#define CCS_PROC_POLICY_QUERY          "/proc/ccs/query"

/***** CONSTANTS DEFINITION END *****/

/***** STRUCTURES DEFINITION START *****/

struct ccs_task_entry {
	pid_t pid;
	pid_t ppid;
	char *name;
	char *domain;
	_Bool selected;
	int index;
	int depth;
};

/***** STRUCTURES DEFINITION END *****/

/***** PROTOTYPES DEFINITION START *****/

FILE *ccs_open_read(const char *filename);
FILE *ccs_open_write(const char *filename);
_Bool ccs_check_remote_host(void);
_Bool ccs_close_write(FILE *fp);
_Bool ccs_decode(const char *ascii, char *bin);
_Bool ccs_move_proc_to_file(const char *src, const char *dest);
_Bool ccs_str_starts(char *str, const char *begin);
char *ccs_freadline(FILE *fp);
char *ccs_strdup(const char *string);
int ccs_open_stream(const char *filename);
void *ccs_malloc(const size_t size);
void *ccs_realloc(void *ptr, const size_t size);
void ccs_get(void);
void ccs_normalize_line(char *buffer);
void ccs_put(void);
void ccs_read_process_list(_Bool show_all);

extern _Bool ccs_network_mode;
extern int ccs_task_list_len;
extern struct ccs_task_entry *ccs_task_list;
extern u16 ccs_network_port;
extern u32 ccs_network_ip;

/***** PROTOTYPES DEFINITION END *****/
