/*
 * tomoyo-checkpolicy.c
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
#include "tomoyotools.h"

#define TOMOYO_MAX_DOMAINNAME_LEN             (4096 - 10)

static unsigned int tomoyo_line = 0;
static unsigned int tomoyo_errors = 0;

static _Bool tomoyo_parse_ulong(unsigned long *result, char **str)
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
		return false;
	*str = ep;
	return true;
}

static _Bool tomoyo_check_number_range(char *pos)
{
	unsigned long min_value;
	unsigned long max_value;
	if (!tomoyo_parse_ulong(&min_value, &pos))
		return false;
	if (*pos == '-') {
		pos++;
		if (!tomoyo_parse_ulong(&max_value, &pos) || *pos ||
		    min_value > max_value)
			return false;
	} else if (*pos)
		return false;
	return true;
}

static void tomoyo_check_condition(char *condition)
{
	enum tomoyo_conditions_index {
		TOMOYO_TASK_UID,             /* current_uid()   */
		TOMOYO_TASK_EUID,            /* current_euid()  */
		TOMOYO_TASK_SUID,            /* current_suid()  */
		TOMOYO_TASK_FSUID,           /* current_fsuid() */
		TOMOYO_TASK_GID,             /* current_gid()   */
		TOMOYO_TASK_EGID,            /* current_egid()  */
		TOMOYO_TASK_SGID,            /* current_sgid()  */
		TOMOYO_TASK_FSGID,           /* current_fsgid() */
		TOMOYO_TASK_PID,             /* sys_getpid()   */
		TOMOYO_TASK_PPID,            /* sys_getppid()  */
		TOMOYO_EXEC_ARGC,            /* "struct linux_binprm *"->argc */
		TOMOYO_EXEC_ENVC,            /* "struct linux_binprm *"->envc */
		TOMOYO_TYPE_IS_SOCKET,       /* S_IFSOCK */
		TOMOYO_TYPE_IS_SYMLINK,      /* S_IFLNK */
		TOMOYO_TYPE_IS_FILE,         /* S_IFREG */
		TOMOYO_TYPE_IS_BLOCK_DEV,    /* S_IFBLK */
		TOMOYO_TYPE_IS_DIRECTORY,    /* S_IFDIR */
		TOMOYO_TYPE_IS_CHAR_DEV,     /* S_IFCHR */
		TOMOYO_TYPE_IS_FIFO,         /* S_IFIFO */
		TOMOYO_MODE_SETUID,          /* S_ISUID */
		TOMOYO_MODE_SETGID,          /* S_ISGID */
		TOMOYO_MODE_STICKY,          /* S_ISVTX */
		TOMOYO_MODE_OWNER_READ,      /* S_IRUSR */
		TOMOYO_MODE_OWNER_WRITE,     /* S_IWUSR */
		TOMOYO_MODE_OWNER_EXECUTE,   /* S_IXUSR */
		TOMOYO_MODE_GROUP_READ,      /* S_IRGRP */
		TOMOYO_MODE_GROUP_WRITE,     /* S_IWGRP */
		TOMOYO_MODE_GROUP_EXECUTE,   /* S_IXGRP */
		TOMOYO_MODE_OTHERS_READ,     /* S_IROTH */
		TOMOYO_MODE_OTHERS_WRITE,    /* S_IWOTH */
		TOMOYO_MODE_OTHERS_EXECUTE,  /* S_IXOTH */
		TOMOYO_TASK_TYPE,            /* ((u8) task->tomoyo_flags) &
					     TOMOYO_TASK_IS_EXECUTE_HANDLER */
		TOMOYO_TASK_EXECUTE_HANDLER, /* TOMOYO_TASK_IS_EXECUTE_HANDLER */
		TOMOYO_EXEC_REALPATH,
		TOMOYO_SYMLINK_TARGET,
		TOMOYO_PATH1_UID,
		TOMOYO_PATH1_GID,
		TOMOYO_PATH1_INO,
		TOMOYO_PATH1_MAJOR,
		TOMOYO_PATH1_MINOR,
		TOMOYO_PATH1_PERM,
		TOMOYO_PATH1_TYPE,
		TOMOYO_PATH1_DEV_MAJOR,
		TOMOYO_PATH1_DEV_MINOR,
		TOMOYO_PATH2_UID,
		TOMOYO_PATH2_GID,
		TOMOYO_PATH2_INO,
		TOMOYO_PATH2_MAJOR,
		TOMOYO_PATH2_MINOR,
		TOMOYO_PATH2_PERM,
		TOMOYO_PATH2_TYPE,
		TOMOYO_PATH2_DEV_MAJOR,
		TOMOYO_PATH2_DEV_MINOR,
		TOMOYO_PATH1_PARENT_UID,
		TOMOYO_PATH1_PARENT_GID,
		TOMOYO_PATH1_PARENT_INO,
		TOMOYO_PATH1_PARENT_PERM,
		TOMOYO_PATH2_PARENT_UID,
		TOMOYO_PATH2_PARENT_GID,
		TOMOYO_PATH2_PARENT_INO,
		TOMOYO_PATH2_PARENT_PERM,
		TOMOYO_MAX_CONDITION_KEYWORD,
		TOMOYO_NUMBER_UNION,
		TOMOYO_NAME_UNION,
		TOMOYO_ARGV_ENTRY,
		TOMOYO_ENVP_ENTRY
	};
	static const char *tomoyo_condition_keyword[TOMOYO_MAX_CONDITION_KEYWORD] = {
		[TOMOYO_TASK_UID]             = "task.uid",
		[TOMOYO_TASK_EUID]            = "task.euid",
		[TOMOYO_TASK_SUID]            = "task.suid",
		[TOMOYO_TASK_FSUID]           = "task.fsuid",
		[TOMOYO_TASK_GID]             = "task.gid",
		[TOMOYO_TASK_EGID]            = "task.egid",
		[TOMOYO_TASK_SGID]            = "task.sgid",
		[TOMOYO_TASK_FSGID]           = "task.fsgid",
		[TOMOYO_TASK_PID]             = "task.pid",
		[TOMOYO_TASK_PPID]            = "task.ppid",
		[TOMOYO_EXEC_ARGC]            = "exec.argc",
		[TOMOYO_EXEC_ENVC]            = "exec.envc",
		[TOMOYO_TYPE_IS_SOCKET]       = "socket",
		[TOMOYO_TYPE_IS_SYMLINK]      = "symlink",
		[TOMOYO_TYPE_IS_FILE]         = "file",
		[TOMOYO_TYPE_IS_BLOCK_DEV]    = "block",
		[TOMOYO_TYPE_IS_DIRECTORY]    = "directory",
		[TOMOYO_TYPE_IS_CHAR_DEV]     = "char",
		[TOMOYO_TYPE_IS_FIFO]         = "fifo",
		[TOMOYO_MODE_SETUID]          = "setuid",
		[TOMOYO_MODE_SETGID]          = "setgid",
		[TOMOYO_MODE_STICKY]          = "sticky",
		[TOMOYO_MODE_OWNER_READ]      = "owner_read",
		[TOMOYO_MODE_OWNER_WRITE]     = "owner_write",
		[TOMOYO_MODE_OWNER_EXECUTE]   = "owner_execute",
		[TOMOYO_MODE_GROUP_READ]      = "group_read",
		[TOMOYO_MODE_GROUP_WRITE]     = "group_write",
		[TOMOYO_MODE_GROUP_EXECUTE]   = "group_execute",
		[TOMOYO_MODE_OTHERS_READ]     = "others_read",
		[TOMOYO_MODE_OTHERS_WRITE]    = "others_write",
		[TOMOYO_MODE_OTHERS_EXECUTE]  = "others_execute",
		[TOMOYO_TASK_TYPE]            = "task.type",
		[TOMOYO_TASK_EXECUTE_HANDLER] = "execute_handler",
		[TOMOYO_EXEC_REALPATH]        = "exec.realpath",
		[TOMOYO_SYMLINK_TARGET]       = "symlink.target",
		[TOMOYO_PATH1_UID]            = "path1.uid",
		[TOMOYO_PATH1_GID]            = "path1.gid",
		[TOMOYO_PATH1_INO]            = "path1.ino",
		[TOMOYO_PATH1_MAJOR]          = "path1.major",
		[TOMOYO_PATH1_MINOR]          = "path1.minor",
		[TOMOYO_PATH1_PERM]           = "path1.perm",
		[TOMOYO_PATH1_TYPE]           = "path1.type",
		[TOMOYO_PATH1_DEV_MAJOR]      = "path1.dev_major",
		[TOMOYO_PATH1_DEV_MINOR]      = "path1.dev_minor",
		[TOMOYO_PATH2_UID]            = "path2.uid",
		[TOMOYO_PATH2_GID]            = "path2.gid",
		[TOMOYO_PATH2_INO]            = "path2.ino",
		[TOMOYO_PATH2_MAJOR]          = "path2.major",
		[TOMOYO_PATH2_MINOR]          = "path2.minor",
		[TOMOYO_PATH2_PERM]           = "path2.perm",
		[TOMOYO_PATH2_TYPE]           = "path2.type",
		[TOMOYO_PATH2_DEV_MAJOR]      = "path2.dev_major",
		[TOMOYO_PATH2_DEV_MINOR]      = "path2.dev_minor",
		[TOMOYO_PATH1_PARENT_UID]     = "path1.parent.uid",
		[TOMOYO_PATH1_PARENT_GID]     = "path1.parent.gid",
		[TOMOYO_PATH1_PARENT_INO]     = "path1.parent.ino",
		[TOMOYO_PATH1_PARENT_PERM]    = "path1.parent.perm",
		[TOMOYO_PATH2_PARENT_UID]     = "path2.parent.uid",
		[TOMOYO_PATH2_PARENT_GID]     = "path2.parent.gid",
		[TOMOYO_PATH2_PARENT_INO]     = "path2.parent.ino",
		[TOMOYO_PATH2_PARENT_PERM]    = "path2.parent.perm",
	};
	char *pos = condition;
	u8 left;
	u8 right;
	if (*pos && pos[strlen(pos) - 1] == ' ')
		condition[strlen(pos) - 1] = '\0';
	if (!*pos)
		return;
	while (pos) {
		char *eq;
		char *next = strchr(pos, ' ');
		int r_len;
		if (next)
			*next++ = '\0';
		if (!tomoyo_correct_word(pos))
			goto out;
		eq = strchr(pos, '=');
		if (!eq)
			goto out;
		*eq = '\0';
		if (eq > pos && *(eq - 1) == '!')
			*(eq - 1) = '\0';
		r_len = strlen(eq + 1);
		if (!strncmp(pos, "exec.argv[", 10)) {
			unsigned long value;
			pos += 10;
			if (!tomoyo_parse_ulong(&value, &pos) || strcmp(pos, "]"))
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
			if (r_len < 2 || pos[0] != '"' ||
			    pos[r_len - 1] != '"')
				goto out;
			goto next;
		} else if (!strcmp(pos, "auto_domain_transition")) {
			pos = eq + 1;
			if (r_len < 2 || pos[0] != '"' ||
			    pos[r_len - 1] != '"')
				goto out;
			pos[r_len - 1] = '\0';
			if (pos[1] != '/' && !tomoyo_domain_def(pos + 1))
				goto out;
			goto next;
		} else if (!strcmp(pos, "grant_log")) {
			pos = eq + 1;
			if (!strcmp(pos, "yes") || !strcmp(pos, "no"))
				goto next;
			goto out;
		}
		for (left = 0; left < TOMOYO_MAX_CONDITION_KEYWORD; left++) {
			const char *keyword = tomoyo_condition_keyword[left];
			if (strcmp(pos, keyword))
				continue;
			break;
		}
		if (left == TOMOYO_MAX_CONDITION_KEYWORD) {
			if (!tomoyo_check_number_range(pos))
				goto out;
		}
		pos = eq + 1;
		if (left == TOMOYO_EXEC_REALPATH || left == TOMOYO_SYMLINK_TARGET) {
			if (r_len < 2)
				goto out;
			if (pos[0] == '@')
				goto next;
			if (pos[0] == '"' && pos[r_len - 1] == '"')
				goto next;
			goto out;
		}
		for (right = 0; right < TOMOYO_MAX_CONDITION_KEYWORD; right++) {
			const char *keyword = tomoyo_condition_keyword[right];
			if (strcmp(pos, keyword))
				continue;
			goto next;
		}
		if (pos[0] == '@' && pos[1])
			goto next;
		if (!tomoyo_check_number_range(pos))
			goto out;
next:
		pos = next;
	}
	return;
out:
	printf("%u: ERROR: '%s' is an illegal condition.\n", tomoyo_line, pos);
	tomoyo_errors++;
}

static _Bool tomoyo_prune_word(char *arg, const char *cp)
{
	if (cp)
		memmove(arg, cp, strlen(cp) + 1);
	else
		*arg = '\0';
	return true;
}

static _Bool tomoyo_check_path(char *arg)
{
	char *cp = strchr(arg, ' ');
	if (cp)
		*cp++ = '\0';
	if (!tomoyo_correct_word(arg))
		return false;
	return tomoyo_prune_word(arg, cp);
}

static _Bool tomoyo_check_number(char *arg)
{
	char *cp = strchr(arg, ' ');
	char *start = arg;
	unsigned long min_value;
	unsigned long max_value;
	if (cp)
		*cp++ = '\0';
	if (*arg == '@')
		goto ok;
	if (!tomoyo_parse_ulong(&min_value, &arg))
		return false;
	if (!*arg)
		goto ok;
	if (*arg++ != '-' || !tomoyo_parse_ulong(&max_value, &arg) || *arg ||
	    min_value > max_value)
		return false;
ok:
	return tomoyo_prune_word(start, cp);
}

static _Bool tomoyo_check_domain(char *arg)
{
	char *cp = arg;
	while (*cp) {
		if (*cp++ != ' ' || *cp++ == '/')
			continue;
		cp -= 2;
		*cp++ = '\0';
		break;
	}
	if (!tomoyo_correct_domain(arg))
		return false;
	return tomoyo_prune_word(arg, cp);
}

static _Bool tomoyo_check_capability(char *arg)
{
	static const char * const list[] = {
		"use_route", "use_packet", "SYS_REBOOT", "SYS_VHANGUP",
		"SYS_TIME", "SYS_NICE", "SYS_SETHOSTNAME", "use_kernel_module",
		"SYS_KEXEC_LOAD", "SYS_PTRACE", NULL
	};
	int i;
	char *cp = strchr(arg, ' ');
	if (cp)
		*cp++ = '\0';
	for (i = 0; list[i]; i++)
		if (!strcmp(arg, list[i]))
			return tomoyo_prune_word(arg, cp);
	return false;
}

static _Bool tomoyo_check_u8(char *arg)
{
	char *cp = strchr(arg, ' ');
	unsigned int value;
	if (cp)
		*cp++ = '\0';
	if (sscanf(arg, "%u", &value) != 1 || value >= 256)
		return false;
	return tomoyo_prune_word(arg, cp);
}

static _Bool tomoyo_check_u16(char *arg)
{
	char *cp = strchr(arg, ' ');
	unsigned int value;
	if (cp)
		*cp++ = '\0';
	if (sscanf(arg, "%u", &value) != 1 || value >= 65536)
		return false;
	return tomoyo_prune_word(arg, cp);
}

static _Bool tomoyo_check_ip_address(char *arg)
{
	char *cp = strchr(arg, ' ');
	unsigned int min_address[8];
	unsigned int max_address[8];
	int count;
	if (cp)
		*cp++ = '\0';
	if (*arg == '@') /* Don't reject address_group. */
		goto found;
	count = sscanf(arg, "%x:%x:%x:%x:%x:%x:%x:%x-%x:%x:%x:%x:%x:%x:%x:%x",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &min_address[4], &min_address[5],
		       &min_address[6], &min_address[7], &max_address[0],
		       &max_address[1], &max_address[2], &max_address[3],
		       &max_address[4], &max_address[5], &max_address[6],
		       &max_address[7]);
	if (count == 8) {
		memmove(max_address, min_address, sizeof(max_address));
		count = 16;
	}
	if (count == 16) {
		for (count = 0; count < 4; count++)
			if (min_address[count] >= 65536 ||
			    max_address[count] >= 65536)
				return false;
		goto found;
	}
	count = sscanf(arg, "%u.%u.%u.%u-%u.%u.%u.%u",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &max_address[0], &max_address[1],
		       &max_address[2], &max_address[3]);
	if (count == 4) {
		memmove(max_address, min_address, sizeof(max_address));
		count = 8;
	}
	if (count == 8) {
		for (count = 0; count < 4; count++) {
			if (min_address[count] >= 256 ||
			    max_address[count] >= 256)
				return false;
			goto found;
		}
	}
	return false;
found:
	for (count = 0; count < 8; count++)
		if (htonl(min_address[count]) > htonl(max_address[count]))
			return false;
	return tomoyo_prune_word(arg, cp);
}

static _Bool tomoyo_check_port(char *arg)
{
	char *cp = strchr(arg, ' ');
	unsigned int min_value;
	unsigned int max_value;
	if (cp)
		*cp++ = '\0';
	switch (sscanf(arg, "%u-%u", &min_value, &max_value)) {
	case 2:
	case 1:
		break;
	default:
		return false;
	}
	return tomoyo_prune_word(arg, cp);
}


static _Bool tomoyo_check_network(char *arg)
{
	static const struct {
		const char *directive;
		u8 flags;
	} list[] = {
		{ "bind", 1 },
		{ "listen", 2 },
		{ "connect", 2 },
		{ "accept", 2 },
		{ "send", 4 },
		{ "recv", 4 },
	};
	_Bool inet;
	u8 mask;
	u8 flags = 0;
	char *start = arg;
	if (tomoyo_str_starts(arg, "inet "))
		inet = true;
	else if (tomoyo_str_starts(arg, "unix "))
		inet = false;
	else
		return false;
	if ((inet && tomoyo_str_starts(arg, "stream ")) ||
	    (!inet && (tomoyo_str_starts(arg, "stream ") ||
		       tomoyo_str_starts(arg, "seqpacket "))))
		mask = 2;
	else if ((inet && (tomoyo_str_starts(arg, "dgram ") ||
			   tomoyo_str_starts(arg, "raw "))) ||
		 (!inet && tomoyo_str_starts(arg, "dgram ")))
		mask = 4;
	else
		return false;
	while (1) {
		u8 type;
		while (tomoyo_str_starts(arg, "/"));
		if (tomoyo_str_starts(arg, " "))
			break;
		for (type = 0; list[type].directive; type++) {
			if (((list[type].flags | mask) & 6) == 6)
				continue;
			if (!tomoyo_str_starts(arg, list[type].directive))
				continue;
			flags |= list[type].flags;
			break;
		}
		if (!list[type].directive) {
			while (*arg && *arg != ' ' && *arg != '/')
				arg++;
			*arg = '\0';
			goto out;
		}
	}
	if (!flags)
		goto out;
	tomoyo_prune_word(start, arg);
	return inet ? tomoyo_check_ip_address(start) && tomoyo_check_number(start) :
		tomoyo_check_path(start);
out:
	return false;

}

static _Bool tomoyo_check_path_domain(char *arg)
{
	if (!strncmp(arg, "any ", 4))
		tomoyo_prune_word(arg, arg + 4);
	else if (*arg != '/' || !tomoyo_check_path(arg))
		return false;
	if (!strncmp(arg, "from ", 5))
		tomoyo_prune_word(arg, arg + 5);
	else if (!*arg)
		return true;
	else
		return false;
	if (!strncmp(arg, "any", 3)) {
		tomoyo_prune_word(arg, arg + 3);
	} else if (*arg == '/') {
		if (!tomoyo_check_path(arg))
			return false;
	} else {
		if (!tomoyo_check_domain(arg))
			return false;
	}
	return !*arg;
}

static _Bool tomoyo_check_path2(char *arg)
{
	return tomoyo_check_path(arg) && tomoyo_check_path(arg);
}

static _Bool tomoyo_check_path_number(char *arg)
{
	return tomoyo_check_path(arg) && tomoyo_check_number(arg);
}

static _Bool tomoyo_check_path_number3(char *arg)
{
	return tomoyo_check_path(arg) && tomoyo_check_number(arg) &&
		tomoyo_check_number(arg) && tomoyo_check_number(arg);
}

static _Bool tomoyo_check_path3_number(char *arg)
{
	return tomoyo_check_path(arg) && tomoyo_check_path(arg) &&
		tomoyo_check_path(arg) && tomoyo_check_number(arg);
}

static _Bool tomoyo_check_file(char *arg)
{
	static const struct {
		const char *directive;
		_Bool (*func) (char *arg);
	} list[] = {
		{ "append", tomoyo_check_path },
		{ "chgrp", tomoyo_check_path_number },
		{ "chmod", tomoyo_check_path_number },
		{ "chown", tomoyo_check_path_number },
		{ "chroot", tomoyo_check_path },
		{ "create", tomoyo_check_path_number },
		{ "execute", tomoyo_check_path },
		{ "getattr", tomoyo_check_path },
		{ "ioctl", tomoyo_check_path_number },
		{ "link", tomoyo_check_path2 },
		{ "mkblock", tomoyo_check_path_number3 },
		{ "mkchar", tomoyo_check_path_number3 },
		{ "mkdir", tomoyo_check_path_number },
		{ "mkfifo", tomoyo_check_path_number },
		{ "mksock", tomoyo_check_path_number },
		{ "mount", tomoyo_check_path3_number },
		{ "pivot_root", tomoyo_check_path2 },
		{ "read", tomoyo_check_path },
		{ "rename", tomoyo_check_path2 },
		{ "rmdir", tomoyo_check_path },
		{ "symlink", tomoyo_check_path },
		{ "truncate", tomoyo_check_path },
		{ "unlink", tomoyo_check_path },
		{ "unmount", tomoyo_check_path },
		{ "write", tomoyo_check_path },
		{ }
	};
	_Bool (*func) (char *) = NULL;
	char *start = arg;
	while (1) {
		u8 type;
		while (tomoyo_str_starts(arg, "/"));
		if (tomoyo_str_starts(arg, " "))
			break;
		for (type = 0; list[type].directive; type++) {
			if (func && func != list[type].func)
				continue;
			if (!tomoyo_str_starts(arg, list[type].directive))
				continue;
			func = list[type].func;
			break;
		}
		if (!list[type].directive) {
			while (*arg && *arg != ' ' && *arg != '/')
				arg++;
			*arg = '\0';
			goto out;
		}
	}
	if (!func || !func(arg))
		goto out;
	return tomoyo_prune_word(start, arg);
out:
	return false;
}

static _Bool tomoyo_check_domain_policy2(char *policy)
{
	u8 type;
	static const struct {
		const char *directive;
		_Bool (*arg1) (char *arg);
		_Bool (*arg2) (char *arg);
	} list[] = {
		{ "capability ", tomoyo_check_capability },
		{ "file ", tomoyo_check_file },
		{ "ipc signal ", tomoyo_check_u16, tomoyo_check_domain },
		{ "misc env ", tomoyo_check_path },
		{ "network ", tomoyo_check_network },
		{ "task auto_domain_transition ", tomoyo_check_domain },
		{ "task auto_execute_handler ", tomoyo_check_path },
		{ "task denied_execute_handler ", tomoyo_check_path },
		{ "task manual_domain_transition ", tomoyo_check_domain },
		{ }
	};
	for (type = 0; list[type].directive; type++) {
		if (!tomoyo_str_starts(policy, list[type].directive))
			continue;
		if (!list[type].arg1(policy))
			break;
		if (list[type].arg2 && !list[type].arg2(policy))
			break;
		tomoyo_check_condition(policy);
		return true;
	}
	return false;
}


static void tomoyo_check_domain_policy(char *policy)
{
	if (tomoyo_domain_def(policy)) {
		if (!tomoyo_correct_domain(policy) ||
		    strlen(policy) >= TOMOYO_MAX_DOMAINNAME_LEN) {
			printf("%u: ERROR: '%s' is a bad domainname.\n",
			       tomoyo_line, policy);
			tomoyo_errors++;
		}
		return;
	} else if (!strcmp(policy, "quota_exceeded") ||
		   !strcmp(policy, "transition_failed")) {
		return;
	} else if (tomoyo_str_starts(policy, "use_group ") ||
		   tomoyo_str_starts(policy, "use_profile ")) {
		if (tomoyo_check_u8(policy))
			return;
	} else if (tomoyo_check_domain_policy2(policy))
		return;
	{
		char *cp = policy;
		while (*cp && *cp != ' ')
			cp++;
		*cp = '\0';
	}
	printf("%u: ERROR: '%s' is a bad argument.\n", tomoyo_line, policy);
	tomoyo_errors++;
}

static void tomoyo_check_exception_policy(char *policy)
{
	static const struct {
		const char *directive;
		_Bool (*arg1) (char *arg);
		_Bool (*arg2) (char *arg);
	} list[] = {
		{ "acl_group ", tomoyo_check_u8, tomoyo_check_domain_policy2 },
		{ "address_group ", tomoyo_check_path, tomoyo_check_ip_address },
		{ "aggregator ", tomoyo_check_path, tomoyo_check_path },
		{ "deny_autobind ", tomoyo_check_port },
		{ "initialize_domain ", tomoyo_check_path_domain },
		{ "keep_domain ", tomoyo_check_path_domain },
		{ "no_initialize_domain ", tomoyo_check_path_domain },
		{ "no_keep_domain ", tomoyo_check_path_domain },
		{ "no_reset_domain ", tomoyo_check_path_domain },
		{ "number_group ", tomoyo_check_path, tomoyo_check_number },
		{ "path_group ", tomoyo_check_path, tomoyo_check_path },
		{ "reset_domain ", tomoyo_check_path_domain },
		{ }
	};
	u8 type;
	for (type = 0; list[type].directive; type++) {
		const int len = strlen(list[type].directive);
		if (strncmp(policy, list[type].directive, len))
			continue;
		policy += len;
		if (!list[type].arg1(policy))
			break;
		if (list[type].arg2 && !list[type].arg2(policy))
			break;
		return;
	}
	{
		char *cp = policy;
		while (*cp && *cp != ' ')
			cp++;
		*cp = '\0';
	}
	printf("%u: ERROR: '%s' is a bad argument.\n", tomoyo_line, policy);
	tomoyo_errors++;
}

int main(int argc, char *argv[])
{
	unsigned int tomoyo_warnings = 0;
	char *policy = NULL;
	enum tomoyo_policy_type {
		TOMOYO_POLICY_TYPE_UNKNOWN,
		TOMOYO_POLICY_TYPE_DOMAIN_POLICY,
		TOMOYO_POLICY_TYPE_EXCEPTION_POLICY,
	};
	enum tomoyo_policy_type policy_type = TOMOYO_POLICY_TYPE_UNKNOWN;
	if (argc > 1) {
		switch (argv[1][0]) {
		case 'e':
			policy_type = TOMOYO_POLICY_TYPE_EXCEPTION_POLICY;
			break;
		case 'd':
			policy_type = TOMOYO_POLICY_TYPE_DOMAIN_POLICY;
			break;
		}
	}
	if (policy_type == TOMOYO_POLICY_TYPE_UNKNOWN) {
		fprintf(stderr, "%s e|d < policy_to_check\n", argv[0]);
		return 0;
	}
	while (true) {
		_Bool badchar_warned = false;
		int pos = 0;
		tomoyo_line++;
		while (true) {
			static int max_policy_len = 0;
			int c = getchar();
			if (c == EOF)
				goto out;
			if (pos == max_policy_len) {
				max_policy_len += 4096;
				policy = tomoyo_realloc(policy, max_policy_len);
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
			       "character (\\%03o).\n", tomoyo_line, c);
			tomoyo_warnings++;
			badchar_warned = true;
		}
		tomoyo_normalize_line(policy);
		if (!policy[0] || policy[0] == '#')
			continue;
		switch (policy_type) {
		case TOMOYO_POLICY_TYPE_DOMAIN_POLICY:
			tomoyo_check_domain_policy(policy);
			break;
		case TOMOYO_POLICY_TYPE_EXCEPTION_POLICY:
			tomoyo_check_exception_policy(policy);
			break;
		default:
			break;
		}
	}
out:
	free(policy);
	policy = NULL;
	tomoyo_line--;
	printf("Total:   %u Line%s   %u Error%s   %u Warning%s\n",
	       tomoyo_line, tomoyo_line > 1 ? "s" : "", tomoyo_errors, tomoyo_errors > 1 ?
	       "s" : "", tomoyo_warnings, tomoyo_warnings > 1 ? "s" : "");
	return tomoyo_errors ? 2 : (tomoyo_warnings ? 1 : 0);
}
