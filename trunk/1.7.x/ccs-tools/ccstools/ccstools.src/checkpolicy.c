/*
 * checkpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include "ccstools.h"

static int parse_ulong(unsigned long *result, char **str)
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
	return base == 16 ? VALUE_TYPE_HEXADECIMAL :
		(base == 8 ? VALUE_TYPE_OCTAL : VALUE_TYPE_DECIMAL);
}

static char *find_condition_part(char *data)
{
	char *cp = strstr(data, " if ");
	if (!cp)
		cp = strstr(data, " ; set ");
	if (cp)
		*cp++ = '\0';
	return cp;
}

static unsigned int line = 0;
static unsigned int errors = 0;
static unsigned int warnings = 0;

static _Bool check_condition(char *condition)
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
		CCS_TASK_STATE_0,         /* (u8) (current->ccs_flags >> 24) */
		CCS_TASK_STATE_1,         /* (u8) (current->ccs_flags >> 16) */
		CCS_TASK_STATE_2,         /* (u8) (task->ccs_flags >> 8)     */
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
		[CCS_TASK_STATE_0]         = "task.state[0]",
		[CCS_TASK_STATE_1]         = "task.state[1]",
		[CCS_TASK_STATE_2]         = "task.state[2]",
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
	char *const start = condition;
	char *pos = condition;
	u8 left;
	u8 right;
	int i;
	unsigned long left_min = 0;
	unsigned long left_max = 0;
	unsigned long right_min = 0;
	unsigned long right_max = 0;
	u8 post_state[4] = { 0, 0, 0, 0 };
	condition = strstr(condition, "; set ");
	if (condition) {
		*condition = '\0';
		condition += 6;
		while (true) {
			while (*condition == ' ')
				condition++;
			if (!*condition)
				break;
			pos = condition;
			if (!strncmp(condition, "task.state[0]=", 14))
				i = 0;
			else if (!strncmp(condition, "task.state[1]=", 14))
				i = 1;
			else if (!strncmp(condition, "task.state[2]=", 14))
				i = 2;
			else
				goto out;
			condition += 14;
			if (post_state[3] & (1 << i))
				goto out;
			post_state[3] |= 1 << i;
			if (!parse_ulong(&right_min, &condition) ||
			    right_min > 255)
				goto out;
			post_state[i] = (u8) right_min;
		}
	}
	condition = start;
	if (*condition && condition[strlen(condition) - 1] == ' ')
		condition[strlen(condition) - 1] = '\0';
	if (!*condition)
		return true;
	if (strncmp(condition, "if ", 3))
		goto out;
	condition += 3;

	pos = condition;
	while (pos) {
		char *eq;
		char *next = strchr(pos, ' ');
		int r_len;
		if (next)
			*next++ = '\0';
		if (!is_correct_path(pos, 0, 0, 0))
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
			if (!parse_ulong(&left_min, &pos) || strcmp(pos, "]"))
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
			if (!parse_ulong(&left_min, &pos))
				goto out;
			if (pos[0] == '-') {
				pos++;
				if (!parse_ulong(&left_max, &pos) || pos[0] ||
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
		if (!parse_ulong(&right_min, &pos))
			goto out;
		if (pos[0] == '-') {
			pos++;
			if (!parse_ulong(&right_max, &pos) || pos[0] ||
			    right_min > right_max)
				goto out;
		} else if (pos[0])
			goto out;
next:
		pos = next;
	}
	return true;
out:
	printf("%u: ERROR: '%s' is an illegal condition.\n", line, pos);
	errors++;
	return false;
}

static void check_capability_policy(char *data)
{
	static const char * const capability_keywords[] = {
		"inet_tcp_create", "inet_tcp_listen", "inet_tcp_connect",
		"use_inet_udp", "use_inet_ip", "use_route", "use_packet",
		"SYS_MOUNT", "SYS_UMOUNT", "SYS_REBOOT", "SYS_CHROOT",
		"SYS_KILL", "SYS_VHANGUP", "SYS_TIME", "SYS_NICE",
		"SYS_SETHOSTNAME", "use_kernel_module", "create_fifo",
		"create_block_dev", "create_char_dev", "create_unix_socket",
		"SYS_LINK", "SYS_SYMLINK", "SYS_RENAME", "SYS_UNLINK",
		"SYS_CHMOD", "SYS_CHOWN", "SYS_IOCTL", "SYS_KEXEC_LOAD",
		"SYS_PIVOT_ROOT", "SYS_PTRACE", "conceal_mount", NULL
	};
	int i;
	for (i = 0; capability_keywords[i]; i++) {
		if (!strcmp(data, capability_keywords[i]))
			return;
	}
	printf("%u: ERROR: '%s' is a bad capability name.\n", line, data);
	errors++;
}

static void check_signal_policy(char *data)
{
	int sig;
	char *cp;
	cp = strchr(data, ' ');
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", line);
		errors++;
		return;
	}
	*cp++ = '\0';
	if (sscanf(data, "%d", &sig) != 1) {
		printf("%u: ERROR: '%s' is a bad signal number.\n", line, data);
		errors++;
	}
	if (!is_correct_domain(cp)) {
		printf("%u: ERROR: '%s' is a bad domainname.\n", line, cp);
		errors++;
	}
}

static void check_env_policy(char *data)
{
	if (!is_correct_path(data, 0, 0, 0)) {
		printf("%u: ERROR: '%s' is a bad variable name.\n", line, data);
		errors++;
	}
}

static void check_network_policy(char *data)
{
	int sock_type;
	int operation;
	u16 min_address[8];
	u16 max_address[8];
	unsigned int min_port;
	unsigned int max_port;
	int count;
	char *cp1 = NULL;
	char *cp2 = NULL;
	cp1 = strchr(data, ' ');
	if (!cp1)
		goto out;
	cp1++;
	if (!strncmp(data, "TCP ", 4))
		sock_type = SOCK_STREAM;
	else if (!strncmp(data, "UDP ", 4))
		sock_type = SOCK_DGRAM;
	else if (!strncmp(data, "RAW ", 4))
		sock_type = SOCK_RAW;
	else
		goto out;
	cp2 = strchr(cp1, ' ');
	if (!cp2)
		goto out;
	cp2++;
	if (!strncmp(cp1, "bind ", 5)) {
		operation = (sock_type == SOCK_STREAM) ? NETWORK_ACL_TCP_BIND :
			(sock_type == SOCK_DGRAM) ? NETWORK_ACL_UDP_BIND :
			NETWORK_ACL_RAW_BIND;
	} else if (!strncmp(cp1, "connect ", 8)) {
		operation = (sock_type == SOCK_STREAM) ?
			NETWORK_ACL_TCP_CONNECT : (sock_type == SOCK_DGRAM) ?
			NETWORK_ACL_UDP_CONNECT : NETWORK_ACL_RAW_CONNECT;
	} else if (sock_type == SOCK_STREAM && !strncmp(cp1, "listen ", 7)) {
		operation = NETWORK_ACL_TCP_LISTEN;
	} else if (sock_type == SOCK_STREAM && !strncmp(cp1, "accept ", 7)) {
		operation = NETWORK_ACL_TCP_ACCEPT;
	} else {
		goto out;
	}
	cp1 = strchr(cp2, ' ');
	if (!cp1)
		goto out;
	cp1++;
	count = sscanf(cp2, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx-"
		       "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &min_address[4], &min_address[5],
		       &min_address[6], &min_address[7], &max_address[0],
		       &max_address[1], &max_address[2], &max_address[3],
		       &max_address[4], &max_address[5], &max_address[6],
		       &max_address[7]);
	if (count == 8 || count == 16) {
		int i;
		for (i = 0; i < 8; i++) {
			min_address[i] = htons(min_address[i]);
			max_address[i] = htons(max_address[i]);
		}
		if (count == 8)
			memmove(max_address, min_address, sizeof(min_address));
		goto next;
	}
	count = sscanf(cp2, "%hu.%hu.%hu.%hu-%hu.%hu.%hu.%hu",
		       &min_address[0], &min_address[1], &min_address[2],
		       &min_address[3], &max_address[0], &max_address[1],
		       &max_address[2], &max_address[3]);
	if (count == 4 || count == 8) {
		u32 ip = htonl((((u8) min_address[0]) << 24) +
			       (((u8) min_address[1]) << 16) +
			       (((u8) min_address[2]) << 8) +
			       (u8) min_address[3]);
		memmove(min_address, &ip, sizeof(ip));
		if (count == 8)
			ip = htonl((((u8) max_address[0]) << 24) +
				   (((u8) max_address[1]) << 16) +
				   (((u8) max_address[2]) << 8) +
				   (u8) max_address[3]);
		memmove(max_address, &ip, sizeof(ip));
		goto next;
	}
	if (*cp2 != '@') /* Don't reject address_group. */
		goto out;
next:
	if (strchr(cp1, ' '))
		goto out;
	count = sscanf(cp1, "%u-%u", &min_port, &max_port);
	if (count == 1 || count == 2) {
		if (count == 1)
			max_port = min_port;
		if (min_port <= max_port && max_port < 65536)
			return;
	}
out:
	printf("%u: ERROR: Bad network address.\n", line);
	errors++;
}

static void check_file_policy(char *data)
{
	static const struct {
		const char * const keyword;
		const int paths;
	} acl_type_array[] = {
		{ "execute",    1 },
		{ "transit",    1 },
		{ "read/write", 1 },
		{ "read",       1 },
		{ "write",      1 },
		{ "create",     2 },
		{ "unlink",     1 },
		{ "mkdir",      2 },
		{ "rmdir",      1 },
		{ "mkfifo",     2 },
		{ "mksock",     2 },
		{ "mkblock",    4 },
		{ "mkchar",     4 },
		{ "truncate",   1 },
		{ "symlink",    1 },
		{ "link",       2 },
		{ "rename",     2 },
		{ "rewrite",    1 },
		{ "chmod",      2 },
		{ "chown",      2 },
		{ "chgrp",      2 },
		{ "ioctl",      2 },
		{ "mount",      4 },
		{ "unmount",    1 },
		{ "chroot",     1 },
		{ "pivot_root", 2 },
		{ NULL, 0 }
	};
	char *filename = strchr(data, ' ');
	char *cp;
	int type;
	if (!filename) {
		printf("%u: ERROR: Unknown command '%s'\n", line, data);
		errors++;
		return;
	}
	*filename++ = '\0';
	if (strncmp(data, "allow_", 6))
		goto out;
	data += 6;
	for (type = 0; acl_type_array[type].keyword; type++) {
		if (strcmp(data, acl_type_array[type].keyword))
			continue;
		if (acl_type_array[type].paths == 4) {
			cp = strrchr(filename, ' ');
			if (!cp) {
				printf("%u: ERROR: Too few arguments.\n",
				       line);
				break;
			}
			if (!is_correct_path(cp + 1, 0, 0, 0)) {
				printf("%u: ERROR: '%s' is a bad argument\n",
				       line, cp + 1);
				break;
			}
			*cp = '\0';
			cp = strrchr(filename, ' ');
			if (!cp) {
				printf("%u: ERROR: Too few arguments.\n",
				       line);
				break;
			}
			if (!is_correct_path(cp + 1, 0, 0, 0)) {
				printf("%u: ERROR: '%s' is a bad argument.\n",
				       line, cp + 1);
				break;
			}
			*cp = '\0';
		}
		if (acl_type_array[type].paths >= 2) {
			cp = strrchr(filename, ' ');
			if (!cp) {
				printf("%u: ERROR: Too few arguments.\n",
				       line);
				break;
			}
			if (!is_correct_path(cp + 1, 0, 0, 0)) {
				printf("%u: ERROR: '%s' is a bad argument.\n",
				       line, cp + 1);
				break;
			}
			*cp = '\0';
		}
		if (!is_correct_path(filename, 0, 0, 0)) {
			printf("%u: ERROR: '%s' is a bad argument.\n", line,
			       filename);
			break;
		}
		/* "allow_execute"/"allow_transit" don't accept patterns. */
		if (type <= 1 && filename[0] != '@' &&
		    !is_correct_path(filename, 1, -1, -1)) {
			printf("%u: ERROR: Patterns not allowed for "
			       "execute/transit permission.\n", line);
			break;
		}
		return;
	}
	if (!acl_type_array[type].keyword)
		goto out;
	errors++;
	return;
out:
	printf("%u: ERROR: Invalid permission '%s %s'\n", line, data, filename);
	errors++;
}

static void check_reserved_port_policy(char *data)
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
		printf("%u: ERROR: Too few parameters.\n", line);
		errors++;
		return;
	}
out:
	printf("%u: ERROR: '%s' is a bad port number.\n", line, data);
	errors++;
}

static void check_domain_initializer_entry(const char *domainname,
					const char *program)
{
	if (!is_correct_path(program, 1, 0, -1)) {
		printf("%u: ERROR: '%s' is a bad pathname.\n", line, program);
		errors++;
	}
	if (domainname && !is_correct_path(domainname, 1, -1, -1) &&
	    !is_correct_domain(domainname)) {
		printf("%u: ERROR: '%s' is a bad domainname.\n",
		       line, domainname);
		errors++;
	}
}

static void check_domain_initializer_policy(char *data)
{
	char *cp = strstr(data, " from ");
	if (cp) {
		*cp = '\0';
		check_domain_initializer_entry(cp + 6, data);
	} else {
		check_domain_initializer_entry(NULL, data);
	}
}

static void check_domain_keeper_entry(const char *domainname,
				      const char *program)
{
	if (!is_correct_path(domainname, 1, -1, -1) &&
	    !is_correct_domain(domainname)) {
		printf("%u: ERROR: '%s' is a bad domainname.\n",
		       line, domainname);
		errors++;
	}
	if (program && !is_correct_path(program, 1, 0, -1)) {
		printf("%u: ERROR: '%s' is a bad pathname.\n", line, program);
		errors++;
	}
}

static void check_domain_keeper_policy(char *data)
{
	char *cp = strstr(data, " from ");
	if (cp) {
		*cp = '\0';
		check_domain_keeper_entry(cp + 6, data);
	} else {
		check_domain_keeper_entry(data, NULL);
	}
}

static void check_path_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", line);
		errors++;
		return;
	}
	*cp++ = '\0';
	if (!is_correct_path(data, 0, 0, 0)) {
		printf("%u: ERROR: '%s' is a bad group name.\n", line, data);
		errors++;
	}
	if (!is_correct_path(cp, 0, 0, 0)) {
		printf("%u: ERROR: '%s' is a bad pathname.\n", line, cp);
		errors++;
	}
}

static void check_number_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	unsigned long v;
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", line);
		errors++;
		return;
	}
	*cp++ = '\0';
	if (!is_correct_path(data, 0, 0, 0)) {
		printf("%u: ERROR: '%s' is a bad group name.\n", line, data);
		errors++;
	}
	data = cp;
	cp = strchr(data, '-');
	if (cp)
		*cp++ = '\0';
	if (!parse_ulong(&v, &data) || *data) {
		printf("%u: ERROR: '%s' is a bad number.\n", line, data);
		errors++;
	}
	if (cp && !parse_ulong(&v, &cp)) {
		printf("%u: ERROR: '%s' is a bad number.\n", line, cp);
		errors++;
	}
}

static void check_address_group_policy(char *data)
{
	char *cp = strchr(data, ' ');
	u16 min_address[8];
	u16 max_address[8];
	int count;
	if (!cp) {
		printf("%u: ERROR: Too few parameters.\n", line);
		errors++;
		return;
	}
	*cp++ = '\0';
	if (!is_correct_path(data, 0, 0, 0)) {
		printf("%u: ERROR: '%s' is a bad group name.\n", line, data);
		errors++;
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
	printf("%u: ERROR: '%s' is a bad address.\n", line, cp);
	errors++;
}

static void check_domain_policy(char *policy)
{
	static int domain = EOF;
	_Bool is_delete = false;
	_Bool is_select = false;
	if (str_starts(policy, KEYWORD_DELETE))
		is_delete = true;
	else if (str_starts(policy, KEYWORD_SELECT))
		is_select = true;
	if (!strncmp(policy, "<kernel>", 8)) {
		if (!is_correct_domain(policy) ||
		    strlen(policy) >= CCS_MAX_PATHNAME_LEN) {
			printf("%u: ERROR: '%s' is a bad domainname.\n",
			       line, policy);
			errors++;
		} else {
			if (is_delete)
				domain = EOF;
			else
				domain = 0;
		}
	} else if (is_select) {
		printf("%u: ERROR: Command 'select' is valid for selecting "
		       "domains only.\n", line);
		errors++;
	} else if (domain == EOF) {
		printf("%u: WARNING: '%s' is unprocessed because domain is not "
		       "selected.\n", line, policy);
		warnings++;
	} else if (str_starts(policy, KEYWORD_USE_PROFILE)) {
		unsigned int profile;
		if (sscanf(policy, "%u", &profile) != 1 ||
		    profile >= 256) {
			printf("%u: ERROR: '%s' is a bad profile.\n",
			       line, policy);
			errors++;
		}
	} else if (!strcmp(policy, "ignore_global_allow_read")) {
		/* Nothing to do. */
	} else if (!strcmp(policy, "ignore_global_allow_env")) {
		/* Nothing to do. */
	} else if (str_starts(policy, "execute_handler ") ||
		   str_starts(policy, "denied_execute_handler")) {
		if (!is_correct_path(policy, 1, -1, -1)) {
			printf("%u: ERROR: '%s' is a bad pathname.\n",
			       line, policy);
			errors++;
		}
	} else if (!strcmp(policy, "transition_failed")) {
		/* Nothing to do. */
	} else if (!strcmp(policy, "quota_exceeded")) {
		/* Nothing to do. */
	} else {
		char *cp = find_condition_part(policy);
		if (cp && !check_condition(cp))
			return;
		if (str_starts(policy, KEYWORD_ALLOW_CAPABILITY))
			check_capability_policy(policy);
		else if (str_starts(policy, KEYWORD_ALLOW_NETWORK))
			check_network_policy(policy);
		else if (str_starts(policy, KEYWORD_ALLOW_SIGNAL))
			check_signal_policy(policy);
		else if (str_starts(policy, KEYWORD_ALLOW_ENV))
			check_env_policy(policy);
		else
			check_file_policy(policy);
	}
}

static void check_exception_policy(char *policy)
{
	str_starts(policy, KEYWORD_DELETE);
	if (str_starts(policy, KEYWORD_ALLOW_READ)) {
		if (!is_correct_path(policy, 1, 0, -1)) {
			printf("%u: ERROR: '%s' is a bad pathname.\n",
			       line, policy);
			errors++;
		}
	} else if (str_starts(policy, KEYWORD_INITIALIZE_DOMAIN)) {
		check_domain_initializer_policy(policy);
	} else if (str_starts(policy, KEYWORD_NO_INITIALIZE_DOMAIN)) {
		check_domain_initializer_policy(policy);
	} else if (str_starts(policy, KEYWORD_KEEP_DOMAIN)) {
		check_domain_keeper_policy(policy);
	} else if (str_starts(policy, KEYWORD_NO_KEEP_DOMAIN)) {
		check_domain_keeper_policy(policy);
	} else if (str_starts(policy, KEYWORD_PATH_GROUP)) {
		check_path_group_policy(policy);
	} else if (str_starts(policy, KEYWORD_NUMBER_GROUP)) {
		check_number_group_policy(policy);
	} else if (str_starts(policy, KEYWORD_ADDRESS_GROUP)) {
		check_address_group_policy(policy);
	} else if (str_starts(policy, KEYWORD_AGGREGATOR)) {
		char *cp = strchr(policy, ' ');
		if (!cp) {
			printf("%u: ERROR: Too few parameters.\n", line);
			errors++;
		} else {
			*cp++ = '\0';
			if (!is_correct_path(policy, 1, 0, -1)) {
				printf("%u: ERROR: '%s' is a bad pattern.\n",
				       line, policy);
				errors++;
			}
			if (!is_correct_path(cp, 1, -1, -1)) {
				printf("%u: ERROR: '%s' is a bad pathname.\n",
				       line, cp);
				errors++;
			}
		}
	} else if (str_starts(policy, KEYWORD_FILE_PATTERN)) {
		if (!is_correct_path(policy, 0, 1, 0)) {
			printf("%u: ERROR: '%s' is a bad pattern.\n",
			       line, policy);
			errors++;
		}
	} else if (str_starts(policy, KEYWORD_DENY_REWRITE)) {
		if (!is_correct_path(policy, 0, 0, 0)) {
			printf("%u: ERROR: '%s' is a bad pattern.\n",
			       line, policy);
			errors++;
		}
	} else if (str_starts(policy, KEYWORD_ALLOW_ENV)) {
		if (!is_correct_path(policy, 0, 0, 0)) {
			printf("%u: ERROR: '%s' is a bad variable name.\n",
			       line, policy);
			errors++;
		}
	} else if (str_starts(policy, KEYWORD_DENY_AUTOBIND)) {
		check_reserved_port_policy(policy);
	} else {
		printf("%u: ERROR: Unknown command '%s'.\n",
		       line, policy);
		errors++;
	}
}

int checkpolicy_main(int argc, char *argv[])
{
	char *policy = NULL;
	int policy_type = POLICY_TYPE_UNKNOWN;
	if (argc > 1) {
		switch (argv[1][0]) {
		case 'e':
			policy_type = POLICY_TYPE_EXCEPTION_POLICY;
			break;
		case 'd':
			policy_type = POLICY_TYPE_DOMAIN_POLICY;
			break;
		}
	}
	if (policy_type == POLICY_TYPE_UNKNOWN) {
		fprintf(stderr, "%s e|d < policy_to_check\n", argv[0]);
		return 0;
	}
	while (true) {
		bool badchar_warned = false;
		int pos = 0;
		line++;
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
					out_of_memory();
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
			       "character (\\%03o).\n", line, c);
			warnings++;
			badchar_warned = true;
		}
		normalize_line(policy);
		if (!policy[0] || policy[0] == '#')
			continue;
		switch (policy_type) {
		case POLICY_TYPE_DOMAIN_POLICY:
			check_domain_policy(policy);
			break;
		case POLICY_TYPE_EXCEPTION_POLICY:
			check_exception_policy(policy);
			break;
		}
	}
 out:
	free(policy);
	policy = NULL;
	line--;
	printf("Total:   %u Line%s   %u Error%s   %u Warning%s\n",
	       line, line > 1 ? "s" : "", errors, errors > 1 ? "s" : "",
	       warnings, warnings > 1 ? "s" : "");
	return errors ? 2 : (warnings ? 1 : 0);
}
