/*
 * ccs-checkpolicy.c
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
#include "ccstools.h"

#define CCS_MAX_PATHNAME_LEN             4000

enum ccs_policy_type {
	CCS_POLICY_TYPE_UNKNOWN,
	CCS_POLICY_TYPE_DOMAIN_POLICY,
	CCS_POLICY_TYPE_EXCEPTION_POLICY,
};

#define CCS_VALUE_TYPE_DECIMAL     1
#define CCS_VALUE_TYPE_OCTAL       2
#define CCS_VALUE_TYPE_HEXADECIMAL 3

static int ccs_parse_ulong(unsigned long *result, char **str)
{
	const char *cp = *str;
	char *ep;
	int base = 10;
	if (*cp == '0') {
		char c = *(cp + 1);
		if (c == 'x' || c == 'X') {
			base = 16;
			cp += 2;
		} else if (c >= '0' && c <= '7') {
			base = 8;
			cp++;
		}
	}
	*result = strtoul(cp, &ep, base);
	if (cp == ep)
		return 0;
	*str = ep;
	return base == 16 ? CCS_VALUE_TYPE_HEXADECIMAL :
		(base == 8 ? CCS_VALUE_TYPE_OCTAL : CCS_VALUE_TYPE_DECIMAL);
}

static char *ccs_find_condition_part(char *data)
{
	char *cp = strstr(data, " if ");
	if (cp) {
		while (1) {
			char *cp2 = strstr(cp + 3, " if ");
			if (!cp2)
				break;
			cp = cp2;
		}
		*cp = '\0';
		cp += 4;
	}
	return cp;
}

static unsigned int ccs_line = 0;
static unsigned int ccs_errors = 0;
static unsigned int ccs_warnings = 0;

static _Bool ccs_check_condition(char *condition)
{
	enum ccs_conditions_index {
		CCS_TASK_UID,             /* current_uid()   */
		CCS_TASK_EUID,            /* current_euid()  */
		CCS_TASK_SUID,            /* current_suid()  */
		CCS_TASK_FSUID,           /* current_fsuid() */
		CCS_TASK_GID,             /* current_gid()   */
		CCS_TASK_EGID,            /* current_egid()  */
		CCS_TASK_SGID,            /* current_sgid()  */
		CCS_TASK_FSGID,           /* current_fsgid() */
		CCS_TASK_PID,             /* sys_getpid()   */
		CCS_TASK_PPID,            /* sys_getppid()  */
		CCS_EXEC_ARGC,            /* "struct linux_binprm *"->argc */
		CCS_EXEC_ENVC,            /* "struct linux_binprm *"->envc */
		CCS_TYPE_IS_SOCKET,       /* S_IFSOCK */
		CCS_TYPE_IS_SYMLINK,      /* S_IFLNK */
		CCS_TYPE_IS_FILE,         /* S_IFREG */
		CCS_TYPE_IS_BLOCK_DEV,    /* S_IFBLK */
		CCS_TYPE_IS_DIRECTORY,    /* S_IFDIR */
		CCS_TYPE_IS_CHAR_DEV,     /* S_IFCHR */
		CCS_TYPE_IS_FIFO,         /* S_IFIFO */
		CCS_MODE_SETUID,          /* S_ISUID */
		CCS_MODE_SETGID,          /* S_ISGID */
		CCS_MODE_STICKY,          /* S_ISVTX */
		CCS_MODE_OWNER_READ,      /* S_IRUSR */
		CCS_MODE_OWNER_WRITE,     /* S_IWUSR */
		CCS_MODE_OWNER_EXECUTE,   /* S_IXUSR */
		CCS_MODE_GROUP_READ,      /* S_IRGRP */
		CCS_MODE_GROUP_WRITE,     /* S_IWGRP */
		CCS_MODE_GROUP_EXECUTE,   /* S_IXGRP */
		CCS_MODE_OTHERS_READ,     /* S_IROTH */
		CCS_MODE_OTHERS_WRITE,    /* S_IWOTH */
		CCS_MODE_OTHERS_EXECUTE,  /* S_IXOTH */
		CCS_TASK_TYPE,            /* ((u8) task->ccs_flags) &
					     CCS_TASK_IS_EXECUTE_HANDLER */
		CCS_TASK_EXECUTE_HANDLER, /* CCS_TASK_IS_EXECUTE_HANDLER */
		CCS_EXEC_REALPATH,
		CCS_SYMLINK_TARGET,
		CCS_PATH1_UID,
		CCS_PATH1_GID,
		CCS_PATH1_INO,
		CCS_PATH1_MAJOR,
		CCS_PATH1_MINOR,
		CCS_PATH1_PERM,
		CCS_PATH1_TYPE,
		CCS_PATH1_DEV_MAJOR,
		CCS_PATH1_DEV_MINOR,
		CCS_PATH2_UID,
		CCS_PATH2_GID,
		CCS_PATH2_INO,
		CCS_PATH2_MAJOR,
		CCS_PATH2_MINOR,
		CCS_PATH2_PERM,
		CCS_PATH2_TYPE,
		CCS_PATH2_DEV_MAJOR,
		CCS_PATH2_DEV_MINOR,
		CCS_PATH1_PARENT_UID,
		CCS_PATH1_PARENT_GID,
		CCS_PATH1_PARENT_INO,
		CCS_PATH1_PARENT_PERM,
		CCS_PATH2_PARENT_UID,
		CCS_PATH2_PARENT_GID,
		CCS_PATH2_PARENT_INO,
		CCS_PATH2_PARENT_PERM,
		CCS_MAX_CONDITION_KEYWORD,
		CCS_NUMBER_UNION,
		CCS_NAME_UNION,
		CCS_ARGV_ENTRY,
		CCS_ENVP_ENTRY
	};
	static const char *ccs_condition_keyword[CCS_MAX_CONDITION_KEYWORD] = {
		[CCS_TASK_UID]             = "task.uid",
		[CCS_TASK_EUID]            = "task.euid",
		[CCS_TASK_SUID]            = "task.suid",
		[CCS_TASK_FSUID]           = "task.fsuid",
		[CCS_TASK_GID]             = "task.gid",
		[CCS_TASK_EGID]            = "task.egid",
		[CCS_TASK_SGID]            = "task.sgid",
		[CCS_TASK_FSGID]           = "task.fsgid",
		[CCS_TASK_PID]             = "task.pid",
		[CCS_TASK_PPID]            = "task.ppid",
		[CCS_EXEC_ARGC]            = "exec.argc",
		[CCS_EXEC_ENVC]            = "exec.envc",
		[CCS_TYPE_IS_SOCKET]       = "socket",
		[CCS_TYPE_IS_SYMLINK]      = "symlink",
		[CCS_TYPE_IS_FILE]         = "file",
		[CCS_TYPE_IS_BLOCK_DEV]    = "block",
		[CCS_TYPE_IS_DIRECTORY]    = "directory",
		[CCS_TYPE_IS_CHAR_DEV]     = "char",
		[CCS_TYPE_IS_FIFO]         = "fifo",
		[CCS_MODE_SETUID]          = "setuid",
		[CCS_MODE_SETGID]          = "setgid",
		[CCS_MODE_STICKY]          = "sticky",
		[CCS_MODE_OWNER_READ]      = "owner_read",
		[CCS_MODE_OWNER_WRITE]     = "owner_write",
		[CCS_MODE_OWNER_EXECUTE]   = "owner_execute",
		[CCS_MODE_GROUP_READ]      = "group_read",
		[CCS_MODE_GROUP_WRITE]     = "group_write",
		[CCS_MODE_GROUP_EXECUTE]   = "group_execute",
		[CCS_MODE_OTHERS_READ]     = "others_read",
		[CCS_MODE_OTHERS_WRITE]    = "others_write",
		[CCS_MODE_OTHERS_EXECUTE]  = "others_execute",
		[CCS_TASK_TYPE]            = "task.type",
		[CCS_TASK_EXECUTE_HANDLER] = "execute_handler",
		[CCS_EXEC_REALPATH]        = "exec.realpath",
		[CCS_SYMLINK_TARGET]       = "symlink.target",
		[CCS_PATH1_UID]            = "path1.uid",
		[CCS_PATH1_GID]            = "path1.gid",
		[CCS_PATH1_INO]            = "path1.ino",
		[CCS_PATH1_MAJOR]          = "path1.major",
		[CCS_PATH1_MINOR]          = "path1.minor",
		[CCS_PATH1_PERM]           = "path1.perm",
		[CCS_PATH1_TYPE]           = "path1.type",
		[CCS_PATH1_DEV_MAJOR]      = "path1.dev_major",
		[CCS_PATH1_DEV_MINOR]      = "path1.dev_minor",
		[CCS_PATH2_UID]            = "path2.uid",
		[CCS_PATH2_GID]            = "path2.gid",
		[CCS_PATH2_INO]            = "path2.ino",
		[CCS_PATH2_MAJOR]          = "path2.major",
		[CCS_PATH2_MINOR]          = "path2.minor",
		[CCS_PATH2_PERM]           = "path2.perm",
		[CCS_PATH2_TYPE]           = "path2.type",
		[CCS_PATH2_DEV_MAJOR]      = "path2.dev_major",
		[CCS_PATH2_DEV_MINOR]      = "path2.dev_minor",
		[CCS_PATH1_PARENT_UID]     = "path1.parent.uid",
		[CCS_PATH1_PARENT_GID]     = "path1.parent.gid",
		[CCS_PATH1_PARENT_INO]     = "path1.parent.ino",
		[CCS_PATH1_PARENT_PERM]    = "path1.parent.perm",
		[CCS_PATH2_PARENT_UID]     = "path2.parent.uid",
		[CCS_PATH2_PARENT_GID]     = "path2.parent.gid",
		[CCS_PATH2_PARENT_INO]     = "path2.parent.ino",
		[CCS_PATH2_PARENT_PERM]    = "path2.parent.perm",
	};
	//char *const start = condition;
	char *pos = condition;
	u8 left;
	u8 right;
	//int i;
	unsigned long left_min = 0;
	unsigned long left_max = 0;
	unsigned long right_min = 0;
	unsigned long right_max = 0;
	if (*condition && condition[strlen(condition) - 1] == ' ')
		condition[strlen(condition) - 1] = '\0';
	if (!*condition)
		return true;
	pos = condition;
	while (pos) {
		char *eq;
		char *next = strchr(pos, ' ');
		int r_len;
		if (next)
			*next++ = '\0';
		if (!ccs_correct_word(pos))
			goto out;
		eq = strchr(pos, '=');
		if (!eq)
			goto out;
		*eq = '\0';
		if (eq > pos && *(eq - 1) == '!')
			*(eq - 1) = '\0';
		r_len = strlen(eq + 1);
		if (!strncmp(pos, "exec.argv[", 10)) {
			pos += 10;
			if (!ccs_parse_ulong(&left_min, &pos) || strcmp(pos, "]"))
				goto out;
			pos = eq + 1;
			if (r_len < 2)
				goto out;
			if (pos[0] == '"' && pos[r_len - 1] == '"')
				goto next;
			goto out;
		} else if (!strncmp(pos, "exec.envp[\"", 11)) {
			if (strcmp(pos + strlen(pos) - 2, "\"]"))
				goto out;
			pos = eq + 1;
			if (!strcmp(pos, "NULL"))
				goto next;
			if (r_len < 2)
				goto out;
			if (pos[0] == '"' && pos[r_len - 1] == '"')
				goto next;
			goto out;
		}
		for (left = 0; left < CCS_MAX_CONDITION_KEYWORD; left++) {
			const char *keyword = ccs_condition_keyword[left];
			if (strcmp(pos, keyword))
				continue;
			break;
		}
		if (left == CCS_MAX_CONDITION_KEYWORD) {
			if (!ccs_parse_ulong(&left_min, &pos))
				goto out;
			if (pos[0] == '-') {
				pos++;
				if (!ccs_parse_ulong(&left_max, &pos) || pos[0] ||
				    left_min > left_max)
					goto out;
			} else if (pos[0])
				goto out;
		}
		pos = eq + 1;
		if (left == CCS_EXEC_REALPATH || left == CCS_SYMLINK_TARGET) {
			if (r_len < 2)
				goto out;
			if (pos[0] == '@')
				goto next;
			if (pos[0] == '"' && pos[r_len - 1] == '"')
				goto next;
			goto out;
		}
		for (right = 0; right < CCS_MAX_CONDITION_KEYWORD; right++) {
			const char *keyword = ccs_condition_keyword[right];
			if (strcmp(pos, keyword))
				continue;
			break;
		}
		if (right < CCS_MAX_CONDITION_KEYWORD)
			goto next;
		if (pos[0] == '@' && pos[1])
			goto next;
		if (!ccs_parse_ulong(&right_min, &pos))
			goto out;
		if (pos[0] == '-') {
			pos++;
			if (!ccs_parse_ulong(&right_max, &pos) || pos[0] ||
			    right_min > right_max)
				goto out;
		} else if (pos[0])
			goto out;
next:
		pos = next;
	}
	return true;
out:
	printf("%u: ERROR: '%s' is an illegal condition.\n", ccs_line, pos);
	ccs_errors++;
	return false;
}

static void ccs_check_capability_policy(char *data)
{
	static const char *capability_keywords[] = {
		"use_route", "use_packet", "SYS_REBOOT", "SYS_VHANGUP",
		"SYS_TIME", "SYS_NICE", "SYS_SETHOSTNAME", "use_kernel_module",
		"SYS_KEXEC_LOAD", "SYS_PTRACE", NULL
	};
	int i;
	for (i = 0; capability_keywords[i]; i++) {
		if (!strcmp(data, capability_keywords[i]))
			return;
	}
	printf("%u: ERROR: '%s' is a bad capability name.\n", ccs_line, data);
	ccs_errors++;
}

static void ccs_check_signal_policy(char *data)
{
	int sig;
	char *cp;
	cp = strchr(data, ' ');
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", ccs_line);
		ccs_errors++;
		return;
	}
	*cp++ = '\0';
	if (sscanf(data, "%d", &sig) != 1) {
		printf("%u: ERROR: '%s' is a bad signal number.\n", ccs_line, data);
		ccs_errors++;
	}
	if (!ccs_correct_domain(cp)) {
		printf("%u: ERROR: '%s' is a bad domainname.\n", ccs_line, cp);
		ccs_errors++;
	}
}

static void ccs_check_env_policy(char *data)
{
	if (!ccs_correct_word(data)) {
		printf("%u: ERROR: '%s' is a bad variable name.\n", ccs_line, data);
		ccs_errors++;
	}
}

static void ccs_check_inet_network_policy(char *data)
{
	u16 min_address[8];
	u16 max_address[8];
	unsigned int min_port;
	unsigned int max_port;
	int count;
	static const char *types[3] = { "stream ", "dgram ", "raw " };
	static const char *ops[6] = { "bind ", "connect ", "listen ",
				      "accept ", "send ", "recv " };
	int i;
	for (i = 0; i < 3; i++)
		if (ccs_str_starts(data, types[i]))
			break;
	if (i == 3)
		goto out;
	for (i = 0; i < 6; i++)
		if (ccs_str_starts(data, ops[i]))
			break;
	if (i == 6)
		goto out;
	count = sscanf(data, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx-"
		       "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &min_address[4], &min_address[5],
		       &min_address[6], &min_address[7], &max_address[0],
		       &max_address[1], &max_address[2], &max_address[3],
		       &max_address[4], &max_address[5], &max_address[6],
		       &max_address[7]);
	if (count == 8 || count == 16)
		goto next;
	count = sscanf(data, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &max_address[0], &max_address[1],
		       &max_address[2], &max_address[3]);
	if (count == 4 || count == 8)
		goto next;
	if (*data != '@') /* Don't reject address_group. */
		goto out;
 next:
	data = strchr(data, ' ');
	if (!data)
		goto out;
	count = sscanf(data, "%u-%u", &min_port, &max_port);
	if (count == 1 || count == 2) {
		if (count == 1)
			max_port = min_port;
		if (min_port <= max_port && max_port < 65536)
			return;
	}
out:
	printf("%u: ERROR: Bad network address.\n", ccs_line);
	ccs_errors++;
}

static void ccs_check_unix_network_policy(char *data)
{
	static const char *types[3] = { "stream ", "dgram ", "seqpaket " };
	static const char *ops[6] = { "bind ", "connect ", "listen ",
				      "accept ", "send ", "recv " };
	int i;
	for (i = 0; i < 3; i++)
		if (ccs_str_starts(data, types[i]))
			break;
	if (i == 3)
		goto out;
	for (i = 0; i < 6; i++)
		if (ccs_str_starts(data, ops[i]))
			break;
	if (i == 6)
		goto out;
	if (*data == '@' || ccs_correct_path(data))
		/* Don't reject path_group. */
		return;
out:
	printf("%u: ERROR: Bad network address.\n", ccs_line);
	ccs_errors++;
}

static void ccs_check_file_policy(char *data)
{
	static const struct {
		const char * const keyword;
		const int paths;
	} acl_type_array[] = {
		{ "append",     1 },
		{ "chgrp",      2 },
		{ "chmod",      2 },
		{ "chown",      2 },
		{ "chroot",     1 },
		{ "create",     2 },
		{ "execute",    1 },
		{ "ioctl",      2 },
		{ "link",       2 },
		{ "mkblock",    4 },
		{ "mkchar",     4 },
		{ "mkdir",      2 },
		{ "mkfifo",     2 },
		{ "mksock",     2 },
		{ "mount",      4 },
		{ "pivot_root", 2 },
		{ "read",       1 },
		{ "rename",     2 },
		{ "rmdir",      1 },
		{ "symlink",    1 },
		{ "transit",    1 },
		{ "truncate",   1 },
		{ "unlink",     1 },
		{ "unmount",    1 },
		{ "write",      1 },
		{ NULL, 0 }
	};
	char *filename = strchr(data, ' ');
	char *cp;
	int type;
	if (!filename) {
		printf("%u: ERROR: Unknown command '%s'\n", ccs_line, data);
		ccs_errors++;
		return;
	}
	*filename++ = '\0';
	for (type = 0; acl_type_array[type].keyword; type++) {
		if (strcmp(data, acl_type_array[type].keyword))
			continue;
		if (acl_type_array[type].paths == 4) {
			cp = strrchr(filename, ' ');
			if (!cp) {
				printf("%u: ERROR: Too few arguments.\n",
				       ccs_line);
				break;
			}
			if (!ccs_correct_word(cp + 1)) {
				printf("%u: ERROR: '%s' is a bad argument\n",
				       ccs_line, cp + 1);
				break;
			}
			*cp = '\0';
			cp = strrchr(filename, ' ');
			if (!cp) {
				printf("%u: ERROR: Too few arguments.\n",
				       ccs_line);
				break;
			}
			if (!ccs_correct_word(cp + 1)) {
				printf("%u: ERROR: '%s' is a bad argument.\n",
				       ccs_line, cp + 1);
				break;
			}
			*cp = '\0';
		}
		if (acl_type_array[type].paths >= 2) {
			cp = strrchr(filename, ' ');
			if (!cp) {
				printf("%u: ERROR: Too few arguments.\n",
				       ccs_line);
				break;
			}
			if (!ccs_correct_word(cp + 1)) {
				printf("%u: ERROR: '%s' is a bad argument.\n",
				       ccs_line, cp + 1);
				break;
			}
			*cp = '\0';
		}
		if (!ccs_correct_word(filename)) {
			printf("%u: ERROR: '%s' is a bad argument.\n", ccs_line,
			       filename);
			break;
		}
		return;
	}
	if (!acl_type_array[type].keyword)
		printf("%u: ERROR: Invalid permission '%s %s'\n", ccs_line, data,
		       filename);
	ccs_errors++;
}

static void ccs_check_reserved_port_policy(char *data)
{
	unsigned int from;
	unsigned int to;
	if (strchr(data, ' '))
		goto out;
	if (sscanf(data, "%u-%u", &from, &to) == 2) {
		if (from <= to && to < 65536)
			return;
	} else if (sscanf(data, "%u", &from) == 1) {
		if (from < 65536)
			return;
	} else {
		printf("%u: ERROR: Too few parameters.\n", ccs_line);
		ccs_errors++;
		return;
	}
out:
	printf("%u: ERROR: '%s' is a bad port number.\n", ccs_line, data);
	ccs_errors++;
}

static void ccs_check_domain_transition_policy(char *program)
{
	char *domainname = strstr(program, " from ");
	if (!domainname) {
		printf("%u: ERROR: Too few parameters.\n", ccs_line);
		ccs_errors++;
		return;
	}
	*domainname = '\0';
	domainname += 6;
	if (strcmp(program, "any") && !ccs_correct_path(program)) {
		printf("%u: ERROR: '%s' is a bad pathname.\n", ccs_line,
		       program);
		ccs_errors++;
	}
	if (strcmp(domainname, "any") && !ccs_correct_path(domainname) &&
	    !ccs_correct_domain(domainname)) {
		printf("%u: ERROR: '%s' is a bad domainname.\n",
		       ccs_line, domainname);
		ccs_errors++;
	}
}

static void ccs_check_path_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", ccs_line);
		ccs_errors++;
		return;
	}
	*cp++ = '\0';
	if (!ccs_correct_word(data)) {
		printf("%u: ERROR: '%s' is a bad group name.\n", ccs_line, data);
		ccs_errors++;
	}
	if (!ccs_correct_word(cp)) {
		printf("%u: ERROR: '%s' is a bad pathname.\n", ccs_line, cp);
		ccs_errors++;
	}
}

static void ccs_check_number_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	unsigned long v;
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", ccs_line);
		ccs_errors++;
		return;
	}
	*cp++ = '\0';
	if (!ccs_correct_word(data)) {
		printf("%u: ERROR: '%s' is a bad group name.\n", ccs_line, data);
		ccs_errors++;
	}
	data = cp;
	cp = strchr(data, '-');
	if (cp)
		*cp = '\0';
	if (!ccs_parse_ulong(&v, &data) || *data) {
		printf("%u: ERROR: '%s' is a bad number.\n", ccs_line, data);
		ccs_errors++;
	}
	if (cp && !ccs_parse_ulong(&v, &cp)) {
		printf("%u: ERROR: '%s' is a bad number.\n", ccs_line, cp);
		ccs_errors++;
	}
}

static void ccs_check_address_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	u16 min_address[8];
	u16 max_address[8];
	int count;
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", ccs_line);
		ccs_errors++;
		return;
	}
	*cp++ = '\0';
	if (!ccs_correct_word(data)) {
		printf("%u: ERROR: '%s' is a bad group name.\n", ccs_line, data);
		ccs_errors++;
	}
	count = sscanf(cp, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx-"
		       "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &min_address[4], &min_address[5],
		       &min_address[6], &min_address[7], &max_address[0],
		       &max_address[1], &max_address[2], &max_address[3],
		       &max_address[4], &max_address[5], &max_address[6],
		       &max_address[7]);
	if (count == 8 || count == 16)
		return;
	count = sscanf(cp, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &max_address[0], &max_address[1],
		       &max_address[2], &max_address[3]);
	if (count == 4 || count == 8)
		return;
	printf("%u: ERROR: '%s' is a bad address.\n", ccs_line, cp);
	ccs_errors++;
}

static void ccs_check_task_policy(char *data)
{
	if (ccs_str_starts(data, "auto_execute_handler ") ||
	    ccs_str_starts(data, "denied_execute_handler ")) {
		if (!ccs_correct_path(data)) {
			printf("%u: ERROR: '%s' is a bad pathname.\n",
			       ccs_line, data);
			ccs_errors++;
		}
	} else if (ccs_str_starts(data, "auto_domain_transition ") ||
		   ccs_str_starts(data, "manual_domain_transition ")) {
		if (!ccs_correct_domain(data)) {
			printf("%u: ERROR: '%s' is a bad domainname.\n",
			       ccs_line, data);
			ccs_errors++;
		}
	}
}

static void ccs_check_domain_policy(char *policy)
{
	static int domain = EOF;
	_Bool is_delete = false;
	_Bool is_select = false;
	if (ccs_str_starts(policy, "delete "))
		is_delete = true;
	else if (ccs_str_starts(policy, "select "))
		is_select = true;
	if (!strncmp(policy, "<kernel>", 8)) {
		if (!ccs_correct_domain(policy) ||
		    strlen(policy) >= CCS_MAX_PATHNAME_LEN) {
			printf("%u: ERROR: '%s' is a bad domainname.\n",
			       ccs_line, policy);
			ccs_errors++;
		} else {
			if (is_delete)
				domain = EOF;
			else
				domain = 0;
		}
	} else if (is_select) {
		printf("%u: ERROR: Command 'select' is valid for selecting "
		       "domains only.\n", ccs_line);
		ccs_errors++;
	} else if (domain == EOF) {
		printf("%u: WARNING: '%s' is unprocessed because domain is not "
		       "selected.\n", ccs_line, policy);
		ccs_warnings++;
	} else if (ccs_str_starts(policy, "use_profile ")) {
		unsigned int profile;
		if (sscanf(policy, "%u", &profile) != 1 ||
		    profile >= 256) {
			printf("%u: ERROR: '%s' is a bad profile.\n",
			       ccs_line, policy);
			ccs_errors++;
		}
	} else if (!strcmp(policy, "transition_failed")) {
		/* Nothing to do. */
	} else if (!strcmp(policy, "quota_exceeded")) {
		/* Nothing to do. */
	} else {
		char *cp = ccs_find_condition_part(policy);
		if (cp && !ccs_check_condition(cp))
			return;
		if (ccs_str_starts(policy, "file "))
			ccs_check_file_policy(policy);
		else if (ccs_str_starts(policy, "network inet "))
			ccs_check_inet_network_policy(policy);
		else if (ccs_str_starts(policy, "network unix "))
			ccs_check_unix_network_policy(policy);
		else if (ccs_str_starts(policy, "misc env "))
			ccs_check_env_policy(policy);
		else if (ccs_str_starts(policy, "capability "))
			ccs_check_capability_policy(policy);
		else if (ccs_str_starts(policy, "ipc signal "))
			ccs_check_signal_policy(policy);
		else if (ccs_str_starts(policy, "task "))
			ccs_check_task_policy(policy);
		else {
			printf("%u: ERROR: Invalid permission '%s'\n",
			       ccs_line, policy);
			ccs_errors++;
		}
	}
}

static void ccs_check_exception_policy(char *policy)
{
	ccs_str_starts(policy, "delete ");
	if (ccs_str_starts(policy, "initialize_domain ") ||
	    ccs_str_starts(policy, "no_initialize_domain ") ||
	    ccs_str_starts(policy, "keep_domain ") ||
	    ccs_str_starts(policy, "no_keep_domain ")) {
		ccs_check_domain_transition_policy(policy);
	} else if (ccs_str_starts(policy, "path_group ")) {
		ccs_check_path_group_policy(policy);
	} else if (ccs_str_starts(policy, "number_group ")) {
		ccs_check_number_group_policy(policy);
	} else if (ccs_str_starts(policy, "address_group ")) {
		ccs_check_address_group_policy(policy);
	} else if (ccs_str_starts(policy, "aggregator ")) {
		char *cp = strchr(policy, ' ');
		if (!cp) {
			printf("%u: ERROR: Too few parameters.\n", ccs_line);
			ccs_errors++;
		} else {
			*cp++ = '\0';
			if (!ccs_correct_word(policy)) {
				printf("%u: ERROR: '%s' is a bad pattern.\n",
				       ccs_line, policy);
				ccs_errors++;
			}
			if (!ccs_correct_path(cp)) {
				printf("%u: ERROR: '%s' is a bad pathname.\n",
				       ccs_line, cp);
				ccs_errors++;
			}
		}
	} else if (ccs_str_starts(policy, "file_pattern ")) {
		if (!ccs_correct_word(policy)) {
			printf("%u: ERROR: '%s' is a bad pattern.\n",
			       ccs_line, policy);
			ccs_errors++;
		}
	} else if (ccs_str_starts(policy, "deny_autobind ")) {
		ccs_check_reserved_port_policy(policy);
	} else if (ccs_str_starts(policy, "acl_group ")) {
		unsigned int group;
		char *cp = strchr(policy, ' ');
		if (cp && sscanf(policy, "%u", &group) == 1 && group < 256) {
			ccs_check_domain_policy(cp + 1);
		} else {
			printf("%u: ERROR: Bad group '%s'.\n", ccs_line,
			       policy);
			ccs_errors++;
		}
	} else {
		printf("%u: ERROR: Unknown command '%s'.\n", ccs_line, policy);
		ccs_errors++;
	}
}

int main(int argc, char *argv[])
{
	char *policy = NULL;
	int policy_type = CCS_POLICY_TYPE_UNKNOWN;
	if (argc > 1) {
		switch (argv[1][0]) {
		case 'e':
			policy_type = CCS_POLICY_TYPE_EXCEPTION_POLICY;
			break;
		case 'd':
			policy_type = CCS_POLICY_TYPE_DOMAIN_POLICY;
			break;
		}
	}
	if (policy_type == CCS_POLICY_TYPE_UNKNOWN) {
		fprintf(stderr, "%s e|d < policy_to_check\n", argv[0]);
		return 0;
	}
	while (true) {
		_Bool badchar_warned = false;
		int pos = 0;
		ccs_line++;
		while (true) {
			static int max_policy_len = 0;
			int c = getchar();
			if (c == EOF)
				goto out;
			if (pos == max_policy_len) {
				char *cp;
				max_policy_len += 4096;
				cp = realloc(policy, max_policy_len);
				if (!cp)
					ccs_out_of_memory();
				policy = cp;
			}
			policy[pos++] = (char) c;
			if (c == '\n') {
				policy[--pos] = '\0';
				break;
			}
			if (badchar_warned ||
			    c == '\t' || (c >= ' ' && c < 127))
				continue;
			printf("%u: WARNING: Line contains illegal "
			       "character (\\%03o).\n", ccs_line, c);
			ccs_warnings++;
			badchar_warned = true;
		}
		ccs_normalize_line(policy);
		if (!policy[0] || policy[0] == '#')
			continue;
		switch (policy_type) {
		case CCS_POLICY_TYPE_DOMAIN_POLICY:
			ccs_check_domain_policy(policy);
			break;
		case CCS_POLICY_TYPE_EXCEPTION_POLICY:
			ccs_check_exception_policy(policy);
			break;
		}
	}
 out:
	free(policy);
	policy = NULL;
	ccs_line--;
	printf("Total:   %u Line%s   %u Error%s   %u Warning%s\n",
	       ccs_line, ccs_line > 1 ? "s" : "", ccs_errors, ccs_errors > 1 ? "s" : "",
	       ccs_warnings, ccs_warnings > 1 ? "s" : "");
	return ccs_errors ? 2 : (ccs_warnings ? 1 : 0);
}
