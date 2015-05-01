/*
 * ccs-checkpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.8.4   2015/05/05
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

#define CCS_MAX_DOMAINNAME_LEN             (4096 - 10)

static unsigned int ccs_line = 0;
static unsigned int ccs_errors = 0;

static _Bool ccs_parse_ulong(unsigned long *result, char **str)
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

static _Bool ccs_check_number_range(char *pos)
{
	unsigned long min_value;
	unsigned long max_value;
	if (!ccs_parse_ulong(&min_value, &pos))
		return false;
	if (*pos == '-') {
		pos++;
		if (!ccs_parse_ulong(&max_value, &pos) || *pos ||
		    min_value > max_value)
			return false;
	} else if (*pos)
		return false;
	return true;
}

static void ccs_check_condition(char *condition)
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
			unsigned long value;
			pos += 10;
			if (!ccs_parse_ulong(&value, &pos) || strcmp(pos, "]"))
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
			if (pos[1] != '/' && !ccs_domain_def(pos + 1))
				goto out;
			goto next;
		} else if (!strcmp(pos, "grant_log")) {
			pos = eq + 1;
			if (!strcmp(pos, "yes") || !strcmp(pos, "no"))
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
			if (!ccs_check_number_range(pos))
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
			goto next;
		}
		if (pos[0] == '@' && pos[1])
			goto next;
		if (!ccs_check_number_range(pos))
			goto out;
next:
		pos = next;
	}
	return;
out:
	printf("%u: ERROR: '%s' is an illegal condition.\n", ccs_line, pos);
	ccs_errors++;
}

static _Bool ccs_prune_word(char *arg, const char *cp)
{
	if (cp)
		memmove(arg, cp, strlen(cp) + 1);
	else
		*arg = '\0';
	return true;
}

static _Bool ccs_check_path(char *arg)
{
	char *cp = strchr(arg, ' ');
	if (cp)
		*cp++ = '\0';
	if (!ccs_correct_word(arg))
		return false;
	return ccs_prune_word(arg, cp);
}

static _Bool ccs_check_number(char *arg)
{
	char *cp = strchr(arg, ' ');
	char *start = arg;
	unsigned long min_value;
	unsigned long max_value;
	if (cp)
		*cp++ = '\0';
	if (*arg == '@')
		goto ok;
	if (!ccs_parse_ulong(&min_value, &arg))
		return false;
	if (!*arg)
		goto ok;
	if (*arg++ != '-' || !ccs_parse_ulong(&max_value, &arg) || *arg ||
	    min_value > max_value)
		return false;
ok:
	return ccs_prune_word(start, cp);
}

static _Bool ccs_check_domain(char *arg)
{
	char *cp = arg;
	while (*cp) {
		if (*cp++ != ' ' || *cp++ == '/')
			continue;
		cp -= 2;
		*cp++ = '\0';
		break;
	}
	if (!ccs_correct_domain(arg))
		return false;
	return ccs_prune_word(arg, cp);
}

static _Bool ccs_check_transition(char *arg)
{
	char *cp;
	_Bool conflict = strstr(arg, " auto_domain_transition=") != NULL;
	if (*arg == '<')
		return !conflict && ccs_check_domain(arg);
	cp = strchr(arg, ' ');
	if (cp)
		*cp++ = '\0';
	if (ccs_correct_path(arg) || !strcmp(arg, "keep") ||
	    !strcmp(arg, "initialize") || !strcmp(arg, "reset") ||
	    !strcmp(arg, "child") || !strcmp(arg, "parent"))
		return !conflict && ccs_prune_word(arg, cp);
	if (cp)
		*--cp = ' ';
	return true;
}

static _Bool ccs_check_path_transition(char *arg)
{
	if (!ccs_check_path(arg))
		return false;
	return ccs_check_transition(arg);
}

static _Bool ccs_check_capability(char *arg)
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
			return ccs_prune_word(arg, cp);
	return false;
}

static _Bool ccs_check_u8(char *arg)
{
	char *cp = strchr(arg, ' ');
	unsigned int value;
	if (cp)
		*cp++ = '\0';
	if (sscanf(arg, "%u", &value) != 1 || value >= 256)
		return false;
	return ccs_prune_word(arg, cp);
}

static _Bool ccs_check_u16(char *arg)
{
	char *cp = strchr(arg, ' ');
	unsigned int value;
	if (cp)
		*cp++ = '\0';
	if (sscanf(arg, "%u", &value) != 1 || value >= 65536)
		return false;
	return ccs_prune_word(arg, cp);
}

static _Bool ccs_check_ip_address(char *arg)
{
	char *cp = strchr(arg, ' ');
	struct ccs_ip_address_entry entry = { };
	if (cp)
		*cp++ = '\0';
	if (*arg == '@') /* Don't reject address_group. */
		goto found;
	if (ccs_parse_ip(arg, &entry) ||
	    memcmp(entry.min, entry.max, 16) > 0)
		return false;
found:
	return ccs_prune_word(arg, cp);
}

static _Bool ccs_check_port(char *arg)
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
	return ccs_prune_word(arg, cp);
}


static _Bool ccs_check_network(char *arg)
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
	if (ccs_str_starts(arg, "inet "))
		inet = true;
	else if (ccs_str_starts(arg, "unix "))
		inet = false;
	else
		return false;
	if ((inet && ccs_str_starts(arg, "stream ")) ||
	    (!inet && (ccs_str_starts(arg, "stream ") ||
		       ccs_str_starts(arg, "seqpacket "))))
		mask = 2;
	else if ((inet && (ccs_str_starts(arg, "dgram ") ||
			   ccs_str_starts(arg, "raw "))) ||
		 (!inet && ccs_str_starts(arg, "dgram ")))
		mask = 4;
	else
		return false;
	while (1) {
		u8 type;
		while (ccs_str_starts(arg, "/"));
		if (ccs_str_starts(arg, " "))
			break;
		for (type = 0; list[type].directive; type++) {
			if (((list[type].flags | mask) & 6) == 6)
				continue;
			if (!ccs_str_starts(arg, list[type].directive))
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
	ccs_prune_word(start, arg);
	return inet ? ccs_check_ip_address(start) && ccs_check_number(start) :
		ccs_check_path(start);
out:
	return false;

}

static _Bool ccs_check_path_domain(char *arg)
{
	if (!strncmp(arg, "any ", 4))
		ccs_prune_word(arg, arg + 4);
	else if (*arg != '/' || !ccs_check_path(arg))
		return false;
	if (!strncmp(arg, "from ", 5))
		ccs_prune_word(arg, arg + 5);
	else if (!*arg)
		return true;
	else
		return false;
	if (!strncmp(arg, "any", 3)) {
		ccs_prune_word(arg, arg + 3);
	} else if (*arg == '/') {
		if (!ccs_check_path(arg))
			return false;
	} else {
		if (!ccs_check_domain(arg))
			return false;
	}
	return !*arg;
}

static _Bool ccs_check_path2(char *arg)
{
	return ccs_check_path(arg) && ccs_check_path(arg);
}

static _Bool ccs_check_path_number(char *arg)
{
	return ccs_check_path(arg) && ccs_check_number(arg);
}

static _Bool ccs_check_path_number3(char *arg)
{
	return ccs_check_path(arg) && ccs_check_number(arg) &&
		ccs_check_number(arg) && ccs_check_number(arg);
}

static _Bool ccs_check_path3_number(char *arg)
{
	return ccs_check_path(arg) && ccs_check_path(arg) &&
		ccs_check_path(arg) && ccs_check_number(arg);
}

static _Bool ccs_check_file(char *arg)
{
	static const struct {
		const char *directive;
		_Bool (*func) (char *arg);
	} list[] = {
		{ "append", ccs_check_path },
		{ "chgrp", ccs_check_path_number },
		{ "chmod", ccs_check_path_number },
		{ "chown", ccs_check_path_number },
		{ "chroot", ccs_check_path },
		{ "create", ccs_check_path_number },
		{ "execute", ccs_check_path_transition },
		{ "getattr", ccs_check_path },
		{ "ioctl", ccs_check_path_number },
		{ "link", ccs_check_path2 },
		{ "mkblock", ccs_check_path_number3 },
		{ "mkchar", ccs_check_path_number3 },
		{ "mkdir", ccs_check_path_number },
		{ "mkfifo", ccs_check_path_number },
		{ "mksock", ccs_check_path_number },
		{ "mount", ccs_check_path3_number },
		{ "pivot_root", ccs_check_path2 },
		{ "read", ccs_check_path },
		{ "rename", ccs_check_path2 },
		{ "rmdir", ccs_check_path },
		{ "symlink", ccs_check_path },
		{ "truncate", ccs_check_path },
		{ "unlink", ccs_check_path },
		{ "unmount", ccs_check_path },
		{ "write", ccs_check_path },
		{ }
	};
	_Bool (*func) (char *) = NULL;
	char *start = arg;
	while (1) {
		u8 type;
		while (ccs_str_starts(arg, "/"));
		if (ccs_str_starts(arg, " "))
			break;
		for (type = 0; list[type].directive; type++) {
			if (func && func != list[type].func)
				continue;
			if (!ccs_str_starts(arg, list[type].directive))
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
	return ccs_prune_word(start, arg);
out:
	return false;
}

static _Bool ccs_check_domain_policy2(char *policy)
{
	u8 type;
	static const struct {
		const char *directive;
		_Bool (*arg1) (char *arg);
		_Bool (*arg2) (char *arg);
	} list[] = {
		{ "capability ", ccs_check_capability },
		{ "file ", ccs_check_file },
		{ "ipc signal ", ccs_check_u16, ccs_check_domain },
		{ "misc env ", ccs_check_path },
		{ "network ", ccs_check_network },
		{ "task auto_domain_transition ", ccs_check_domain },
		{ "task auto_execute_handler ", ccs_check_path_transition },
		{ "task denied_execute_handler ", ccs_check_path_transition },
		{ "task manual_domain_transition ", ccs_check_domain },
		{ }
	};
	for (type = 0; list[type].directive; type++) {
		if (!ccs_str_starts(policy, list[type].directive))
			continue;
		if (!list[type].arg1(policy))
			break;
		if (list[type].arg2 && !list[type].arg2(policy))
			break;
		ccs_check_condition(policy);
		return true;
	}
	return false;
}


static void ccs_check_domain_policy(char *policy)
{
	if (ccs_domain_def(policy)) {
		if (!ccs_correct_domain(policy) ||
		    strlen(policy) >= CCS_MAX_DOMAINNAME_LEN) {
			printf("%u: ERROR: '%s' is a bad domainname.\n",
			       ccs_line, policy);
			ccs_errors++;
		}
		return;
	} else if (!strcmp(policy, "quota_exceeded") ||
		   !strcmp(policy, "transition_failed")) {
		return;
	} else if (ccs_str_starts(policy, "use_group ") ||
		   ccs_str_starts(policy, "use_profile ")) {
		if (ccs_check_u8(policy))
			return;
	} else if (ccs_check_domain_policy2(policy))
		return;
	{
		char *cp = policy;
		while (*cp && *cp != ' ')
			cp++;
		*cp = '\0';
	}
	printf("%u: ERROR: '%s' is a bad argument.\n", ccs_line, policy);
	ccs_errors++;
}

static void ccs_check_exception_policy(char *policy)
{
	static const struct {
		const char *directive;
		_Bool (*arg1) (char *arg);
		_Bool (*arg2) (char *arg);
	} list[] = {
		{ "acl_group ", ccs_check_u8, ccs_check_domain_policy2 },
		{ "address_group ", ccs_check_path, ccs_check_ip_address },
		{ "aggregator ", ccs_check_path, ccs_check_path },
		{ "deny_autobind ", ccs_check_port },
		{ "initialize_domain ", ccs_check_path_domain },
		{ "keep_domain ", ccs_check_path_domain },
		{ "no_initialize_domain ", ccs_check_path_domain },
		{ "no_keep_domain ", ccs_check_path_domain },
		{ "no_reset_domain ", ccs_check_path_domain },
		{ "number_group ", ccs_check_path, ccs_check_number },
		{ "path_group ", ccs_check_path, ccs_check_path },
		{ "reset_domain ", ccs_check_path_domain },
		{ }
	};
	u8 type;
	if (*policy == '<') {
		char *ns = strchr(policy, ' ');
		if (ns) {
			*ns++= '\0';
			if (!ccs_domain_def(policy)) {
				printf("%u: ERROR: '%s' is a bad namespace\n",
				       ccs_line, policy);
				ccs_errors++;
			}
			policy = ns;
		}
	}
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
	printf("%u: ERROR: '%s' is a bad argument.\n", ccs_line, policy);
	ccs_errors++;
}

int main(int argc, char *argv[])
{
	unsigned int ccs_warnings = 0;
	char *policy = NULL;
	enum ccs_policy_type {
		CCS_POLICY_TYPE_UNKNOWN,
		CCS_POLICY_TYPE_DOMAIN_POLICY,
		CCS_POLICY_TYPE_EXCEPTION_POLICY,
	};
	enum ccs_policy_type policy_type = CCS_POLICY_TYPE_UNKNOWN;
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
				max_policy_len += 4096;
				policy = ccs_realloc(policy, max_policy_len);
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
		default:
			break;
		}
	}
out:
	free(policy);
	policy = NULL;
	ccs_line--;
	printf("Total:   %u Line%s   %u Error%s   %u Warning%s\n",
	       ccs_line, ccs_line > 1 ? "s" : "", ccs_errors, ccs_errors > 1 ?
	       "s" : "", ccs_warnings, ccs_warnings > 1 ? "s" : "");
	return ccs_errors ? 2 : (ccs_warnings ? 1 : 0);
}
