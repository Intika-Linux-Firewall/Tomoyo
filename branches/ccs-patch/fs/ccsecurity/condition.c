/*
 * fs/ccsecurity/condition.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/07/03
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/slab.h>
#include "ccs_common.h"
#include <linux/ccsecurity.h>

/**
 * ccs_check_argv - Check argv[] in "struct linux_binbrm".
 *
 * @index:   Index number of @arg_ptr.
 * @arg_ptr: Contents of argv[@index].
 * @argc:    Length of @argv.
 * @argv:    Pointer to "struct ccs_argv_entry".
 * @checked: Set to true if @argv[@index] was found.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_check_argv(const unsigned int index, const char *arg_ptr,
			   const int argc, const struct ccs_argv_entry *argv,
			   u8 *checked)
{
	int i;
	struct ccs_path_info arg;
	arg.name = arg_ptr;
	for (i = 0; i < argc; argv++, checked++, i++) {
		bool result;
		if (index != argv->index)
			continue;
		*checked = 1;
		ccs_fill_path_info(&arg);
		result = ccs_path_matches_pattern(&arg, argv->value);
		if (argv->is_not)
			result = !result;
		if (!result)
			return false;
	}
	return true;
}

/**
 * ccs_check_envp - Check envp[] in "struct linux_binbrm".
 *
 * @env_name:  The name of environment variable.
 * @env_value: The value of environment variable.
 * @envc:      Length of @envp.
 * @envp:      Pointer to "struct ccs_envp_entry".
 * @checked:   Set to true if @envp[@env_name] was found.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_check_envp(const char *env_name, const char *env_value,
			   const int envc, const struct ccs_envp_entry *envp,
			   u8 *checked)
{
	int i;
	struct ccs_path_info name;
	struct ccs_path_info value;
	name.name = env_name;
	ccs_fill_path_info(&name);
	value.name = env_value;
	ccs_fill_path_info(&value);
	for (i = 0; i < envc; envp++, checked++, i++) {
		bool result;
		if (!ccs_path_matches_pattern(&name, envp->name))
			continue;
		*checked = 1;
		if (envp->value) {
			result = ccs_path_matches_pattern(&value, envp->value);
			if (envp->is_not)
				result = !result;
		} else {
			result = true;
			if (!envp->is_not)
				result = !result;
		}
		if (!result)
			return false;
	}
	return true;
}

/**
 * ccs_scan_bprm - Scan "struct linux_binprm".
 *
 * @ee:   Pointer to "struct ccs_execve_entry".
 * @argc: Length of @argc.
 * @argv: Pointer to "struct ccs_argv_entry".
 * @envc: Length of @envp.
 * @envp: Poiner to "struct ccs_envp_entry".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_scan_bprm(struct ccs_execve_entry *ee,
			  const u16 argc, const struct ccs_argv_entry *argv,
			  const u16 envc, const struct ccs_envp_entry *envp)
{
	/*
	  if exec.argc=3
	  if (argc == 3)
	  if exec.argv[1]="-c"
	  if (argc >= 2 && !strcmp(argv[1], "-c"))
	  if exec.argv[1]!="-c"
	  if (argc < 2 || strcmp(argv[1], "-c"))
	  if exec.envc=10-20
	  if (envc >= 10 && envc <= 20)
	  if exec.envc!=10-20
	  if (envc < 10 || envc > 20)
	  if exec.envp["HOME"]!=NULL
	  if (getenv("HOME"))
	  if exec.envp["HOME"]=NULL
	  if (!getenv("HOME"))
	  if exec.envp["HOME"]="/"
	  if (getenv("HOME") && !strcmp(getenv("HOME"), "/"))
	  if exec.envp["HOME"]!="/"
	  if (!getenv("HOME") || strcmp(getenv("HOME", "/"))
	*/
	struct linux_binprm *bprm = ee->bprm;
	struct ccs_page_dump *dump = &ee->dump;
	char *arg_ptr = ee->tmp;
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	bool result = true;
	u8 local_checked[32];
	u8 *checked;
	if (argc + envc <= sizeof(local_checked)) {
		checked = local_checked;
		memset(local_checked, 0, sizeof(local_checked));
	} else {
		checked = kzalloc(argc + envc, GFP_KERNEL);
		if (!checked)
			return false;
	}
	while (argv_count || envp_count) {
		if (!ccs_dump_page(bprm, pos, dump)) {
			result = false;
			goto out;
		}
		pos += PAGE_SIZE - offset;
		while (offset < PAGE_SIZE) {
			/* Read. */
			struct ccs_path_info arg;
			const char *kaddr = dump->data;
			const unsigned char c = kaddr[offset++];
			arg.name = arg_ptr;
			if (c && arg_len < CCS_MAX_PATHNAME_LEN - 10) {
				if (c == '\\') {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = '\\';
				} else if (c > ' ' && c < 127) {
					arg_ptr[arg_len++] = c;
				} else {
					arg_ptr[arg_len++] = '\\';
					arg_ptr[arg_len++] = (c >> 6) + '0';
					arg_ptr[arg_len++] =
						((c >> 3) & 7) + '0';
					arg_ptr[arg_len++] = (c & 7) + '0';
				}
			} else {
				arg_ptr[arg_len] = '\0';
			}
			if (c)
				continue;
			/* Check. */
			if (argv_count) {
				if (!ccs_check_argv(bprm->argc - argv_count,
						    arg_ptr, argc, argv,
						    checked)) {
					result = false;
					break;
				}
				argv_count--;
			} else if (envp_count) {
				char *cp = strchr(arg_ptr, '=');
				if (cp) {
					*cp = '\0';
					if (!ccs_check_envp(arg_ptr, cp + 1,
							    envc, envp,
							    checked + argc)) {
						result = false;
						break;
					}
				}
				envp_count--;
			} else {
				break;
			}
			arg_len = 0;
		}
		offset = 0;
		if (!result)
			break;
	}
 out:
	if (result) {
		int i;
		/* Check not-yet-checked entries. */
		for (i = 0; i < argc; i++) {
			if (checked[i])
				continue;
			/*
			 * Return true only if all unchecked indexes in
			 * bprm->argv[] are not matched.
			 */
			if (argv[i].is_not)
				continue;
			result = false;
			break;
		}
		for (i = 0; i < envc; envp++, i++) {
			if (checked[argc + i])
				continue;
			/*
			 * Return true only if all unchecked environ variables
			 * in bprm->envp[] are either undefined or not matched.
			 */
			if ((!envp->value && !envp->is_not) ||
			    (envp->value && envp->is_not))
				continue;
			result = false;
			break;
		}
	}
	if (checked != local_checked)
		kfree(checked);
	return result;
}

static bool ccs_scan_symlink_target(const struct ccs_path_info *symlink_target,
				    const struct ccs_path_info *path,
				    const struct ccs_path_group_entry *group,
				    const bool match)
{
	if (!symlink_target)
		return false;
	if (path)
		return ccs_path_matches_pattern(symlink_target, path) == match;
	else if (group)
		return ccs_path_matches_group(symlink_target, group, true) == match;
	return false;
}

static bool ccs_scan_exec_realpath(const struct file *file,
				   const struct ccs_path_info *path,
				   const struct ccs_path_group_entry *group,
				   const bool match)
{
	bool result;
	struct ccs_path_info exe;
	if (!file)
		return false;
	exe.name = ccs_realpath_from_dentry(file->f_dentry, file->f_vfsmnt);
	if (!exe.name)
		return false;
	ccs_fill_path_info(&exe);
	if (path)
		result = ccs_path_matches_pattern(&exe, path) == match;
	else if (group)
		result = ccs_path_matches_group(&exe, group, true) == match;
	else
		result = false;
	kfree(exe.name);
	return result;
}

struct ccs_condition_element {
	/*
	 * Left hand operand. A "struct ccs_argv_entry" for ARGV_ENTRY, a
	 * "struct ccs_envp_entry" for ENVP_ENTRY is attached to the tail of
	 * the array of this struct.
	 */
	u8 left;
	/*
	 * Right hand operand.  An "unsigned long" for CONSTANT_VALUE,
	 * two "unsigned long" for CONSTANT_VALUE_RANGE,
	 * a "struct ccs_number_group *" for NUMBER_GROUP,
	 * a "struct ccs_path_info *" for PATH_INFO,
	 * a "struct ccs_group_info *" for PATH_GROUP is attached to the tail
	 * of the array of this struct.
	 */
	u8 right;
	/* Equation operator. 1 if equals or overlaps, 0 otherwise. */
	u8 equals;
	/*
	 * Radix types for constant value .
	 * 
	 * Bit 3 and 2: Right hand operand's min value
	 * Bit 1 and 0: Right hand operand's max value
	 *
	 * 01 is for decimal, 10 is for octal, 11 is for hexadecimal,
	 * 00 is for invalid (i.e. not a value) expression.
	 */
	u8 type;
};

/* Value type definition. */
#define VALUE_TYPE_DECIMAL     1
#define VALUE_TYPE_OCTAL       2
#define VALUE_TYPE_HEXADECIMAL 3

/**
 * ccs_parse_ulong - Parse an "unsigned long" value.
 *
 * @result: Pointer to "unsigned long".
 * @str:    Pointer to string to parse.
 *
 * Returns value type on success, 0 otherwise.
 *
 * The @src is updated to point the first character after the value
 * on success.
 */
static u8 ccs_parse_ulong(unsigned long *result, char **str)
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
	*result = simple_strtoul(cp, &ep, base);
	if (cp == ep)
		return 0;
	*str = ep;
	switch (base) {
	case 16:
		return VALUE_TYPE_HEXADECIMAL;
	case 8:
		return VALUE_TYPE_OCTAL;
	default:
		return VALUE_TYPE_DECIMAL;
	}
}

/**
 * ccs_print_ulong - Print an "unsigned long" value.
 *
 * @buffer:     Pointer to buffer.
 * @buffer_len: Size of @buffer.
 * @value:      An "unsigned long" value.
 * @type:       Type of @value.
 *
 * Returns nothing.
 */
static void ccs_print_ulong(char *buffer, const int buffer_len,
			    const unsigned long value, const int type)
{
	if (type == VALUE_TYPE_DECIMAL)
		snprintf(buffer, buffer_len, "%lu", value);
	else if (type == VALUE_TYPE_OCTAL)
		snprintf(buffer, buffer_len, "0%lo", value);
	else if (type == VALUE_TYPE_HEXADECIMAL)
		snprintf(buffer, buffer_len, "0x%lX", value);
	else
		snprintf(buffer, buffer_len, "type(%u)", type);
}

/**
 * ccs_get_dqword - ccs_get_name() for a quoted string.
 *
 * @start: String to save.
 *
 * Returns pointer to "struct ccs_path_info" on success, NULL otherwise.
 */
static const struct ccs_path_info *ccs_get_dqword(char *start)
{
	char *cp;
	if (*start++ != '"')
		return NULL;
	cp = start;
	while (1) {
		const char c = *cp++;
		if (!c)
			return NULL;
		if (c != '"' || *cp)
			continue;
		*(cp - 1) = '\0';
		break;
	}
	if (!ccs_is_correct_path(start, 0, 0, 0))
		return NULL;
	return ccs_get_name(start);
}

/**
 * ccs_parse_argv - Parse an argv[] condition part.
 *
 * @start: String to parse.
 * @argv:  Pointer to "struct ccs_argv_entry".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_parse_argv(char *start, struct ccs_argv_entry *argv)
{
	unsigned long index;
	const struct ccs_path_info *value;
	bool is_not;
	char c;
	if (ccs_parse_ulong(&index, &start) != VALUE_TYPE_DECIMAL)
		goto out;
	if (*start++ != ']')
		goto out;
	c = *start++;
	if (c == '=')
		is_not = false;
	else if (c == '!' && *start++ == '=')
		is_not = true;
	else
		goto out;
	value = ccs_get_dqword(start);
	if (!value)
		goto out;
	argv->index = index;
	argv->is_not = is_not;
	argv->value = value;
	return true;
 out:
	return false;
}

/**
 * ccs_parse_envp - Parse an envp[] condition part.
 *
 * @start: String to parse.
 * @envp:  Pointer to "struct ccs_envp_entry".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_parse_envp(char *start, struct ccs_envp_entry *envp)
{
	const struct ccs_path_info *name;
	const struct ccs_path_info *value;
	bool is_not;
	char *cp = start;
	/*
	 * Since environment variable names don't
	 * contain '=', I can treat '"]=' and '"]!='
	 * sequences as delimiters.
	 */
	while (1) {
		if (!strncmp(start, "\"]=", 3)) {
			is_not = false;
			*start = '\0';
			start += 3;
			break;
		} else if (!strncmp(start, "\"]!=", 4)) {
			is_not = true;
			*start = '\0';
			start += 4;
			break;
		} else if (!*start++) {
			goto out;
		}
	}
	if (!*cp || !ccs_is_correct_path(cp, 0, 0, 0))
		goto out;
	name = ccs_get_name(cp);
	if (!name)
		goto out;
	if (!strcmp(start, "NULL")) {
		value = NULL;
	} else {
		value = ccs_get_dqword(start);
		if (!value)
			goto out;
	}
	envp->name = name;
	envp->is_not = is_not;
	envp->value = value;
	return true;
 out:
	return false;
}

/* The list for "struct ccs_condition". */
LIST_HEAD(ccs_condition_list);

enum ccs_conditions_index {
	TASK_UID,             /* current_uid()   */
	TASK_EUID,            /* current_euid()  */
	TASK_SUID,            /* current_suid()  */
	TASK_FSUID,           /* current_fsuid() */
	TASK_GID,             /* current_gid()   */
	TASK_EGID,            /* current_egid()  */
	TASK_SGID,            /* current_sgid()  */
	TASK_FSGID,           /* current_fsgid() */
	TASK_PID,             /* sys_getpid()   */
	TASK_PPID,            /* sys_getppid()  */
	EXEC_ARGC,            /* "struct linux_binprm *"->argc */
	EXEC_ENVC,            /* "struct linux_binprm *"->envc */
	TASK_STATE_0,         /* (u8) (current->ccs_flags >> 24) */
	TASK_STATE_1,         /* (u8) (current->ccs_flags >> 16) */
	TASK_STATE_2,         /* (u8) (task->ccs_flags >> 8)     */
	TYPE_SOCKET,          /* S_IFSOCK */
	TYPE_SYMLINK,         /* S_IFLNK */
	TYPE_FILE,            /* S_IFREG */
	TYPE_BLOCK_DEV,       /* S_IFBLK */
	TYPE_DIRECTORY,       /* S_IFDIR */
	TYPE_CHAR_DEV,        /* S_IFCHR */
	TYPE_FIFO,            /* S_IFIFO */
	MODE_SETUID,          /* S_ISUID */
	MODE_SETGID,          /* S_ISGID */
	MODE_STICKY,          /* S_ISVTX */
	MODE_OWNER_READ,      /* S_IRUSR */
	MODE_OWNER_WRITE,     /* S_IWUSR */
	MODE_OWNER_EXECUTE,   /* S_IXUSR */
	MODE_GROUP_READ,      /* S_IRGRP */
	MODE_GROUP_WRITE,     /* S_IWGRP */
	MODE_GROUP_EXECUTE,   /* S_IXGRP */
	MODE_OTHERS_READ,     /* S_IROTH */
	MODE_OTHERS_WRITE,    /* S_IWOTH */
	MODE_OTHERS_EXECUTE,  /* S_IXOTH */
	TASK_TYPE,            /* ((u8) task->ccs_flags) &
				 CCS_TASK_IS_EXECUTE_HANDLER */
	TASK_EXECUTE_HANDLER, /* CCS_TASK_IS_EXECUTE_HANDLER */
	EXEC_REALPATH,
	SYMLINK_TARGET,
	PATH1_UID,
	PATH1_GID,
	PATH1_INO,
	PATH1_MAJOR,
	PATH1_MINOR,
	PATH1_PERM,
	PATH1_TYPE,
	PATH1_DEV_MAJOR,
	PATH1_DEV_MINOR,
	PATH2_UID,
	PATH2_GID,
	PATH2_INO,
	PATH2_MAJOR,
	PATH2_MINOR,
	PATH2_PERM,
	PATH2_TYPE,
	PATH2_DEV_MAJOR,
	PATH2_DEV_MINOR,
	PATH1_PARENT_UID,
	PATH1_PARENT_GID,
	PATH1_PARENT_INO,
	PATH1_PARENT_PERM,
	PATH2_PARENT_UID,
	PATH2_PARENT_GID,
	PATH2_PARENT_INO,
	PATH2_PARENT_PERM,
	MAX_KEYWORD,
	CONSTANT_VALUE,
	CONSTANT_VALUE_RANGE,
	ARGV_ENTRY,
	ENVP_ENTRY,
	PATH_INFO,
	PATH_GROUP,
	NUMBER_GROUP,
};

static const char *ccs_condition_keyword[MAX_KEYWORD] = {
	[TASK_UID]             = "task.uid",
	[TASK_EUID]            = "task.euid",
	[TASK_SUID]            = "task.suid",
	[TASK_FSUID]           = "task.fsuid",
	[TASK_GID]             = "task.gid",
	[TASK_EGID]            = "task.egid",
	[TASK_SGID]            = "task.sgid",
	[TASK_FSGID]           = "task.fsgid",
	[TASK_PID]             = "task.pid",
	[TASK_PPID]            = "task.ppid",
	[EXEC_ARGC]            = "exec.argc",
	[EXEC_ENVC]            = "exec.envc",
	[TASK_STATE_0]         = "task.state[0]",
	[TASK_STATE_1]         = "task.state[1]",
	[TASK_STATE_2]         = "task.state[2]",
	[TYPE_SOCKET]          = "socket",
	[TYPE_SYMLINK]         = "symlink",
	[TYPE_FILE]            = "file",
	[TYPE_BLOCK_DEV]       = "block",
	[TYPE_DIRECTORY]       = "directory",
	[TYPE_CHAR_DEV]        = "char",
	[TYPE_FIFO]            = "fifo",
	[MODE_SETUID]          = "setuid",
	[MODE_SETGID]          = "setgid",
	[MODE_STICKY]          = "sticky",
	[MODE_OWNER_READ]      = "owner_read",
	[MODE_OWNER_WRITE]     = "owner_write",
	[MODE_OWNER_EXECUTE]   = "owner_execute",
	[MODE_GROUP_READ]      = "group_read",
	[MODE_GROUP_WRITE]     = "group_write",
	[MODE_GROUP_EXECUTE]   = "group_execute",
	[MODE_OTHERS_READ]     = "others_read",
	[MODE_OTHERS_WRITE]    = "others_write",
	[MODE_OTHERS_EXECUTE]  = "others_execute",
	[TASK_TYPE]            = "task.type",
	[TASK_EXECUTE_HANDLER] = "execute_handler",
	[EXEC_REALPATH]        = "exec.realpath",
	[SYMLINK_TARGET]       = "symlink.target",
	[PATH1_UID]            = "path1.uid",
	[PATH1_GID]            = "path1.gid",
	[PATH1_INO]            = "path1.ino",
	[PATH1_MAJOR]          = "path1.major",
	[PATH1_MINOR]          = "path1.minor",
	[PATH1_PERM]           = "path1.perm",
	[PATH1_TYPE]           = "path1.type",
	[PATH1_DEV_MAJOR]      = "path1.dev_major",
	[PATH1_DEV_MINOR]      = "path1.dev_minor",
	[PATH2_UID]            = "path2.uid",
	[PATH2_GID]            = "path2.gid",
	[PATH2_INO]            = "path2.ino",
	[PATH2_MAJOR]          = "path2.major",
	[PATH2_MINOR]          = "path2.minor",
	[PATH2_PERM]           = "path2.perm",
	[PATH2_TYPE]           = "path2.type",
	[PATH2_DEV_MAJOR]      = "path2.dev_major",
	[PATH2_DEV_MINOR]      = "path2.dev_minor",
	[PATH1_PARENT_UID]     = "path1.parent.uid",
	[PATH1_PARENT_GID]     = "path1.parent.gid",
	[PATH1_PARENT_INO]     = "path1.parent.ino",
	[PATH1_PARENT_PERM]    = "path1.parent.perm",
	[PATH2_PARENT_UID]     = "path2.parent.uid",
	[PATH2_PARENT_GID]     = "path2.parent.gid",
	[PATH2_PARENT_INO]     = "path2.parent.ino",
	[PATH2_PARENT_PERM]    = "path2.parent.perm",
};

/**
 * ccs_parse_post_condition - Parse post-condition part.
 *
 * @condition:  String to parse.
 * @post_state: Buffer to store post-condition part.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_parse_post_condition(char * const condition, u8 post_state[4])
{
	char *start = strstr(condition, "; set ");
	if (!start)
		return true;
	*start = '\0';
	start += 6;
	while (1) {
		int i;
		unsigned long value;
		while (*start == ' ')
			start++;
		if (!*start)
			break;
		if (!strncmp(start, "task.state[0]=", 14))
			i = 0;
		else if (!strncmp(start, "task.state[1]=", 14))
			i = 1;
		else if (!strncmp(start, "task.state[2]=", 14))
			i = 2;
		else
			goto out;
		start += 14;
		if (post_state[3] & (1 << i))
			goto out;
		post_state[3] |= 1 << i;
		if (!ccs_parse_ulong(&value, &start) || value > 255)
			goto out;
		post_state[i] = (u8) value;
	}
	return true;
 out:
	return false;
}

/**
 * ccs_get_condition - Parse condition part.
 *
 * @condition: Pointer to string to parse.
 *
 * Returns pointer to "struct ccs_condition" on success, NULL otherwise.
 */
struct ccs_condition *ccs_get_condition(char * const condition)
{
	static const bool debug = 0;
	static const u8 offset = offsetof(struct ccs_condition, size);
	char *start = condition;
	struct ccs_condition *entry = NULL;
	struct ccs_condition *ptr;
	struct ccs_condition_element *condp;
	unsigned long *ulong_p;
	struct ccs_number_group_entry **number_group_p;
	const struct ccs_path_info **path_info_p;
	struct ccs_path_group_entry **path_group_p;
	struct ccs_argv_entry *argv;
	struct ccs_envp_entry *envp;
	u32 size;
	u8 i;
	bool found = false;
	unsigned long left_min = 0;
	unsigned long left_max = 0;
	unsigned long right_min = 0;
	unsigned long right_max = 0;
	u16 condc = 0;
	u16 ulong_count = 0;
	u16 number_group_count = 0;
	u16 path_info_count = 0;
	u16 path_group_count = 0;
	u16 argc = 0;
	u16 envc = 0;
	u8 post_state[4] = { 0, 0, 0, 0 };
	/* Calculate at runtime. */
	static u8 ccs_condition_keyword_len[MAX_KEYWORD];
	if (!ccs_condition_keyword_len[MAX_KEYWORD - 1]) {
		for (i = 0; i < MAX_KEYWORD; i++)
			ccs_condition_keyword_len[i]
				= strlen(ccs_condition_keyword[i]);
	}
	if (!ccs_parse_post_condition(start, post_state))
		goto out;
	start = condition;
	if (!strncmp(start, "if ", 3))
		start += 3;
	else if (*start)
		return NULL;
	while (1) {
		u8 left;
		u8 right;
		while (*start == ' ')
			start++;
		if (!*start)
			break;
		if (debug)
			printk(KERN_WARNING "%u: start=<%s>\n", __LINE__,
			       start);
		if (!strncmp(start, "exec.argv[", 10)) {
			argc++;
			condc++;
			start = strchr(start + 10, ' ');
			if (!start)
				break;
			continue;
		} else if (!strncmp(start, "exec.envp[\"", 11)) {
			envc++;
			condc++;
			start = strchr(start + 11, ' ');
			if (!start)
				break;
			continue;
		}
		for (left = 0; left < MAX_KEYWORD; left++) {
			const int len =
				ccs_condition_keyword_len[left];
			if (strncmp(start, ccs_condition_keyword[left],
				    len) ||
			    (start[len] != '!' && start[len] != '='))
				continue;
			start += len;
			break;
		}
		if (debug)
			printk(KERN_WARNING "%u: start=<%s> left=%u\n",
			       __LINE__, start, left);
		if (left < MAX_KEYWORD)
			goto check_operator_1;
		if (!ccs_parse_ulong(&left_min, &start))
			goto out;
		ulong_count++;
		if (*start != '-')
			goto check_operator_1;
		start++;
		if (!ccs_parse_ulong(&left_max, &start) ||
		    left_min > left_max)
			goto out;
		ulong_count++;
 check_operator_1:
		if (strncmp(start, "!=", 2) == 0)
			start += 2;
		else if (*start == '=')
			start++;
		else
			goto out;
		condc++;
		if (debug)
			printk(KERN_WARNING "%u: start=<%s> left=%u\n",
			       __LINE__, start, left);
		if (*start == '@') {
			while (*start && *start != ' ')
				start++;
			if (left == EXEC_REALPATH || left == SYMLINK_TARGET)
				path_group_count++;
			else
				number_group_count++;
			continue;
		} else if (*start == '"') {
			while (*start && *start != ' ')
				start++;
			if (left != EXEC_REALPATH && left != SYMLINK_TARGET)
				goto out;
			path_info_count++;
			continue;
		}
		for (right = 0; right < MAX_KEYWORD; right++) {
			const int len =
				ccs_condition_keyword_len[right];
			if (strncmp(start, ccs_condition_keyword[right],
				    len) || (start[len] && start[len] != ' '))
				continue;
			start += len;
			break;
		}
		if (debug)
			printk(KERN_WARNING "%u: start=<%s> right=%u\n",
			       __LINE__, start, right);
		if (right < MAX_KEYWORD)
			continue;
		if (!ccs_parse_ulong(&right_min, &start))
			goto out;
		ulong_count++;
		if (*start != '-')
			continue;
		start++;
		if (!ccs_parse_ulong(&right_max, &start) ||
		    right_min > right_max)
			goto out;
		ulong_count++;
	}
	if (debug)
		printk(KERN_DEBUG "%u: cond=%u ul=%u ng=%u pi=%i pg=%u ac=%u "
		       "ec=%u\n", __LINE__, condc, ulong_count,
		       number_group_count, path_info_count, path_group_count,
		       argc, envc);
	size = sizeof(*entry)
		+ condc * sizeof(struct ccs_condition_element)
		+ ulong_count * sizeof(unsigned long)
		+ number_group_count * sizeof(struct ccs_number_group_entry *)
		+ path_info_count * sizeof(struct ccs_path_info *)
		+ path_group_count * sizeof(struct ccs_path_group_entry *)
		+ argc * sizeof(struct ccs_argv_entry)
		+ envc * sizeof(struct ccs_envp_entry);
	entry = kzalloc(size, GFP_KERNEL);
	if (!entry)
		return NULL;
	atomic_set(&entry->users, 1);
	INIT_LIST_HEAD(&entry->list);
	entry->size = size;
	for (i = 0; i < 4; i++)
		entry->post_state[i] = post_state[i];
	entry->condc = condc;
	entry->ulong_count = ulong_count;
	entry->number_group_count = number_group_count;
	entry->path_info_count = path_info_count;
	entry->path_group_count = path_group_count;
	entry->argc = argc;
	entry->envc = envc;
	condp = (struct ccs_condition_element *) (entry + 1);
	ulong_p = (unsigned long *) (condp + condc);
	number_group_p = (struct ccs_number_group_entry **)
		(ulong_p + ulong_count);
	path_info_p = (const struct ccs_path_info **)
		(number_group_p + number_group_count);
	path_group_p = (struct ccs_path_group_entry **)
		(path_info_p + path_info_count);
	argv = (struct ccs_argv_entry *) (path_group_p + path_group_count);
	envp = (struct ccs_envp_entry *) (argv + argc);
	start = condition;
	if (!strncmp(start, "if ", 3))
		start += 3;
	else if (*start)
		goto out;
	while (1) {
		u8 left = 0;
		u8 right = 0;
		u8 match = 0;
		u8 left_1_type = 0;
		u8 left_2_type = 0;
		u8 right_1_type = 0;
		u8 right_2_type = 0;
		struct ccs_number_group_entry *number_group = NULL;
		const struct ccs_path_info *path_info = NULL;
		struct ccs_path_group_entry *path_group = NULL;
		while (*start == ' ')
			start++;
		if (!*start)
			break;
		if (debug)
			printk(KERN_WARNING "%u: start=<%s>\n", __LINE__,
			       start);
		if (!strncmp(start, "exec.argv[", 10)) {
			char *cp = strchr(start + 10, ' ');
			if (cp)
				*cp++ = '\0';
			if (!ccs_parse_argv(start + 10, argv))
				goto out;
			argv++;
			argc--;
			condc--;
			if (cp)
				start = cp;
			else
				start = "";
			left = ARGV_ENTRY;
			goto store_value;
		} else if (!strncmp(start, "exec.envp[\"", 11)) {
			char *cp = strchr(start + 11, ' ');
			if (cp)
				*cp++ = '\0';
			if (!ccs_parse_envp(start + 11, envp))
				goto out;
			envp++;
			envc--;
			condc--;
			if (cp)
				start = cp;
			else
				start = "";
			left = ENVP_ENTRY;
			goto store_value;
		}
		for (left = 0; left < MAX_KEYWORD; left++) {
			const int len =
				ccs_condition_keyword_len[left];
			if (strncmp(start, ccs_condition_keyword[left],
				    len) ||
			    (start[len] != '!' && start[len] != '='))
				continue;
			start += len;
			goto check_operator_2;
		}
		left_1_type = ccs_parse_ulong(&left_min, &start);
		left = CONSTANT_VALUE;
		if (*start != '-')
			goto check_operator_2;
		start++;
		left_2_type = ccs_parse_ulong(&left_max, &start);
		left = CONSTANT_VALUE_RANGE;
 check_operator_2:
		if (!strncmp(start, "!=", 2)) {
			start += 2;
		} else if (*start == '=') {
			match = 1;
			start++;
		} else {
			break; /* This shouldn't happen. */
		}
		condc--;
		if (*start == '@') {
			char *cp = strchr(start + 1, ' ');
			if (cp)
				*cp++ = '\0';
			if (left == EXEC_REALPATH || left == SYMLINK_TARGET) {
				right = PATH_GROUP;
				path_group = ccs_get_path_group(start + 1);
				if (!path_group)
					goto out;
			} else {
				right = NUMBER_GROUP;
				number_group = ccs_get_number_group(start + 1);
				if (!number_group)
					goto out;
			}
			if (cp)
				start = cp;
			else
				start = "";
			goto store_value;
		} else if (*start == '"') {
			char *cp = strchr(start + 1, ' ');
			if (cp)
				*cp++ = '\0';
			path_info = ccs_get_dqword(start);
			if (!path_info)
				goto out;
			if (cp)
				start = cp;
			else
				start = "";
			right = PATH_INFO;
			goto store_value;
		}
		for (right = 0; right < MAX_KEYWORD; right++) {
			const int len =
				ccs_condition_keyword_len[right];
			if (strncmp(start, ccs_condition_keyword[right],
				    len) || (start[len] && start[len] != ' '))
				continue;
			start += len;
			goto store_value;
		}
		right_1_type = ccs_parse_ulong(&right_min, &start);
		right = CONSTANT_VALUE;
		if (*start != '-')
			goto store_value;
		start++;
		right_2_type = ccs_parse_ulong(&right_max, &start);
		right = CONSTANT_VALUE_RANGE;
 store_value:
		condp->left = left;
		condp->right = right;
		condp->equals = match;
		condp->type = (left_1_type << 6) | (left_2_type << 4)
			| (right_1_type << 2) | right_2_type;
		if (debug)
			printk(KERN_WARNING "%u: left=%u right=%u match=%u "
			       "type=%u\n", __LINE__, condp->left,
			       condp->right, condp->equals, condp->type);
		condp++;
		if (left_1_type) {
			*ulong_p++ = left_min;
			ulong_count--;
		}
		if (left_2_type) {
			*ulong_p++ = left_max;
			ulong_count--;
		}
		if (right_1_type) {
			*ulong_p++ = right_min;
			ulong_count--;
		}
		if (right_2_type) {
			*ulong_p++ = right_max;
			ulong_count--;
		}
		if (number_group) {
			*number_group_p++ = number_group;
			number_group_count--;
		}
		if (path_info) {
			*path_info_p++ = path_info;
			path_info_count--;
		}
		if (path_group) {
			*path_group_p++ = path_group;
			path_group_count--;
		}
	}
	if (debug)
		printk(KERN_DEBUG "%u: cond=%u ul=%u ng=%u pi=%i pg=%u ac=%u "
		       "ec=%u\n", __LINE__, condc, ulong_count,
		       number_group_count, path_info_count, path_group_count,
		       argc, envc);
	BUG_ON(path_group_count);
	BUG_ON(number_group_count);
	BUG_ON(path_info_count);
	BUG_ON(ulong_count);
	BUG_ON(argc);
	BUG_ON(envc);
	BUG_ON(condc);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(ptr, &ccs_condition_list, list) {
		if (memcmp(((u8 *) ptr) + offset, ((u8 *) entry) + offset,
			   size - offset))
			continue;
		/* Same entry found. Share this entry. */
		atomic_inc(&ptr->users);
		found = true;
		break;
	}
	if (!found) {
		if (ccs_memory_ok(entry, size)) {
			list_add_rcu(&entry->list, &ccs_condition_list);
		} else {
			found = true;
			ptr = NULL;
		}
	}
	mutex_unlock(&ccs_policy_lock);
	if (found) {
		ccs_put_condition(entry);
		entry = ptr;
	}
	return entry;
 out:
	if (debug)
		printk(KERN_WARNING "%u: %s failed\n", __LINE__, __func__);
	ccs_put_condition(entry);
	return NULL;
}

/**
 * ccs_get_attributes - Revalidate "struct inode".
 *
 * @obj: Pointer to "struct ccs_obj_info".
 *
 * Returns nothing.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
static void ccs_get_attributes(struct ccs_obj_info *obj)
{
	struct dentry *dentry;
	struct inode *inode;

	/* Get information on "path1". */
	dentry = obj->path1_dentry;
	inode = dentry->d_inode;
	if (inode) {
		if (inode->i_op && inode->i_op->revalidate &&
		    inode->i_op->revalidate(dentry)) {
			/* Nothing to do. */
		} else {
			obj->path1_stat.uid = inode->i_uid;
			obj->path1_stat.gid = inode->i_gid;
			obj->path1_stat.ino = inode->i_ino;
			obj->path1_stat.mode = inode->i_mode;
			obj->path1_stat.dev = inode->i_dev;
			obj->path1_stat.rdev = inode->i_rdev;
			obj->path1_valid = true;
		}
	}

	/* Get information on "path1.parent". */
	/***** CRITICAL SECTION START *****/
	spin_lock(&dcache_lock);
	dentry = dget(obj->path1_dentry->d_parent);
	spin_unlock(&dcache_lock);
	/***** CRITICAL SECTION END *****/
	inode = dentry->d_inode;
	if (inode) {
		if (inode->i_op && inode->i_op->revalidate &&
		    inode->i_op->revalidate(dentry)) {
			/* Nothing to do. */
		} else {
			obj->path1_parent_stat.uid = inode->i_uid;
			obj->path1_parent_stat.gid = inode->i_gid;
			obj->path1_parent_stat.ino = inode->i_ino;
			obj->path1_parent_stat.mode = inode->i_mode;
			obj->path1_parent_stat.dev = inode->i_dev;
			obj->path1_parent_stat.rdev = inode->i_rdev;
			obj->path1_parent_valid = true;
		}
	}
	dput(dentry);

	if (!obj->path2_vfsmnt)
		return;
	
	/* Get information on "path2". */
	dentry = obj->path2_dentry;
	inode = dentry->d_inode;
	if (inode) {
		if (inode->i_op && inode->i_op->revalidate &&
		    inode->i_op->revalidate(dentry)) {
			/* Nothing to do. */
		} else {
			obj->path2_stat.uid = inode->i_uid;
			obj->path2_stat.gid = inode->i_gid;
			obj->path2_stat.ino = inode->i_ino;
			obj->path2_stat.mode = inode->i_mode;
			obj->path2_stat.dev = inode->i_dev;
			obj->path2_stat.rdev = inode->i_rdev;
			obj->path2_valid = true;
		}
	}

	/* Get information on "path2.parent". */
	/***** CRITICAL SECTION START *****/
	spin_lock(&dcache_lock);
	dentry = dget(obj->path2_dentry->d_parent);
	spin_unlock(&dcache_lock);
	/***** CRITICAL SECTION END *****/
	inode = dentry->d_inode;
	if (inode) {
		if (inode->i_op && inode->i_op->revalidate &&
		    inode->i_op->revalidate(dentry)) {
			/* Nothing to do. */
		} else {
			obj->path2_parent_stat.uid = inode->i_uid;
			obj->path2_parent_stat.gid = inode->i_gid;
			obj->path2_parent_stat.ino = inode->i_ino;
			obj->path2_parent_stat.mode = inode->i_mode;
			obj->path2_parent_stat.dev = inode->i_dev;
			obj->path2_parent_stat.rdev = inode->i_rdev;
			obj->path2_parent_valid = true;
		}
	}
	dput(dentry);
}
#else
static void ccs_get_attributes(struct ccs_obj_info *obj)
{
	struct vfsmount *mnt;
	struct dentry *dentry;
	struct inode *inode;
	struct kstat stat;

	/* Get information on "path1". */
	mnt = obj->path1_vfsmnt;
	dentry = obj->path1_dentry;
	inode = dentry->d_inode;
	if (inode) {
		if (!inode->i_op || vfs_getattr(mnt, dentry, &stat)) {
			/* Nothing to do. */
		} else {
			obj->path1_stat.uid = stat.uid;
			obj->path1_stat.gid = stat.gid;
			obj->path1_stat.ino = stat.ino;
			obj->path1_stat.mode = stat.mode;
			obj->path1_stat.dev = stat.dev;
			obj->path1_stat.rdev = stat.rdev;
			obj->path1_valid = true;
		}
	}

	/* Get information on "path1.parent". */
	dentry = dget_parent(obj->path1_dentry);
	inode = dentry->d_inode;
	if (inode) {
		if (!inode->i_op || vfs_getattr(mnt, dentry, &stat)) {
			/* Nothing to do. */
		} else {
			obj->path1_parent_stat.uid = stat.uid;
			obj->path1_parent_stat.gid = stat.gid;
			obj->path1_parent_stat.ino = stat.ino;
			obj->path1_parent_stat.mode = stat.mode;
			obj->path1_parent_stat.dev = stat.dev;
			obj->path1_parent_stat.rdev = stat.rdev;
			obj->path1_parent_valid = true;
		}
	}
	dput(dentry);

	mnt = obj->path2_vfsmnt;
	if (!mnt)
		return;
	
	/* Get information on "path2". */
	dentry = obj->path2_dentry;
	inode = dentry->d_inode;
	if (inode) {
		if (!inode->i_op || vfs_getattr(mnt, dentry, &stat)) {
			/* Nothing to do. */
		} else {
			obj->path2_stat.uid = stat.uid;
			obj->path2_stat.gid = stat.gid;
			obj->path2_stat.ino = stat.ino;
			obj->path2_stat.mode = stat.mode;
			obj->path2_stat.dev = stat.dev;
			obj->path2_stat.rdev = stat.rdev;
			obj->path2_valid = true;
		}
	}

	/* Get information on "path2.parent". */
	dentry = dget_parent(obj->path2_dentry);
	inode = dentry->d_inode;
	if (inode) {
		if (!inode->i_op || vfs_getattr(mnt, dentry, &stat)) {
			/* Nothing to do. */
		} else {
			obj->path2_parent_stat.uid = stat.uid;
			obj->path2_parent_stat.gid = stat.gid;
			obj->path2_parent_stat.ino = stat.ino;
			obj->path2_parent_stat.mode = stat.mode;
			obj->path2_parent_stat.dev = stat.dev;
			obj->path2_parent_stat.rdev = stat.rdev;
			obj->path2_parent_valid = true;
		}
	}
	dput(dentry);
}
#endif

/**
 * ccs_check_condition - Check condition part.
 *
 * @r:    Pointer to "struct ccs_request_info".
 * @acl: Pointer to "struct ccs_acl_info".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_check_condition(struct ccs_request_info *r,
			 const struct ccs_acl_info *acl)
{
	const struct task_struct *task = current;
	u32 i;
	unsigned long left_min = 0;
	unsigned long left_max = 0;
	unsigned long right_min = 0;
	unsigned long right_max = 0;
	const struct ccs_condition_element *condp;
	const unsigned long *ulong_p;
	const struct ccs_number_group_entry **number_group_p;
	const struct ccs_path_info **path_info_p;
	const struct ccs_path_group_entry **path_group_p;
	const struct ccs_argv_entry *argv;
	const struct ccs_envp_entry *envp;
	struct ccs_obj_info *obj;
	u16 condc;
	u16 argc;
	u16 envc;
	struct linux_binprm *bprm = NULL;
	const struct ccs_condition *cond = acl->cond;
	ccs_check_read_lock();
	if (!cond)
		return true;
	condc = cond->condc;
	argc = cond->argc;
	envc = cond->envc;
	obj = r->obj;
	if (r->ee)
		bprm = r->ee->bprm;
	if (!bprm && (argc || envc))
		return false;
	condp = (struct ccs_condition_element *) (cond + 1);
	ulong_p = (const unsigned long *) (condp + condc);
	number_group_p = (const struct ccs_number_group_entry **)
		(ulong_p + cond->ulong_count);
	path_info_p = (const struct ccs_path_info **)
		(number_group_p + cond->number_group_count);
	path_group_p = (const struct ccs_path_group_entry **)
		(path_info_p + cond->path_info_count);
	argv = (const struct ccs_argv_entry *)
		(path_group_p + cond->path_group_count);
	envp = (const struct ccs_envp_entry *) (argv + argc);
	for (i = 0; i < condc; i++) {
		const bool match = condp->equals;
		const u8 left = condp->left;
		const u8 right = condp->right;
		bool left_is_bitop = false;
		bool right_is_bitop = false;
		u8 j;
		condp++;
		/* Check argv[] and envp[] later. */
		if (left == ARGV_ENTRY || left == ENVP_ENTRY)
			continue;
		/* Check string expressions. */
		if (right == PATH_INFO || right == PATH_GROUP) {
			const struct ccs_path_info *path = NULL;
			const struct ccs_path_group_entry *group = NULL;
			if (right == PATH_INFO)
				path = *path_info_p++;
			else
				group = *path_group_p++;
			switch (left) {
				struct ccs_path_info *symlink;
				struct ccs_execve_entry *ee;
				struct file *file;
			case SYMLINK_TARGET:
				symlink = obj->symlink_target;
				if (!ccs_scan_symlink_target(symlink, path,
							     group, match))
					goto out;
				break;
			case EXEC_REALPATH:
				ee = r->ee;
				file = ee ? ee->bprm->file : NULL;
				if (!ccs_scan_exec_realpath(file, path, group,
							    match))
					goto out;
				break;
			}
			continue;
		}
		/* Check numeric or bit-op expressions. */
		for (j = 0; j < 2; j++) {
			const u8 index = j ? right : left;
			unsigned long min_v = 0;
			unsigned long max_v = 0;
			bool is_bitop = false;
			switch (index) {
			case TASK_UID:
				max_v = current_uid();
				break;
			case TASK_EUID:
				max_v = current_euid();
				break;
			case TASK_SUID:
				max_v = current_suid();
				break;
			case TASK_FSUID:
				max_v = current_fsuid();
				break;
			case TASK_GID:
				max_v = current_gid();
				break;
			case TASK_EGID:
				max_v = current_egid();
				break;
			case TASK_SGID:
				max_v = current_sgid();
				break;
			case TASK_FSGID:
				max_v = current_fsgid();
				break;
			case TASK_PID:
				max_v = sys_getpid();
				break;
			case TASK_PPID:
				max_v = sys_getppid();
				break;
			case TYPE_SOCKET:
				max_v = S_IFSOCK;
				break;
			case TYPE_SYMLINK:
				max_v = S_IFLNK;
				break;
			case TYPE_FILE:
				max_v = S_IFREG;
				break;
			case TYPE_BLOCK_DEV:
				max_v = S_IFBLK;
				break;
			case TYPE_DIRECTORY:
				max_v = S_IFDIR;
				break;
			case TYPE_CHAR_DEV:
				max_v = S_IFCHR;
				break;
			case TYPE_FIFO:
				max_v = S_IFIFO;
				break;
			case MODE_SETUID:
				max_v = S_ISUID;
				is_bitop = true;
				break;
			case MODE_SETGID:
				max_v = S_ISGID;
				is_bitop = true;
				break;
			case MODE_STICKY:
				max_v = S_ISVTX;
				is_bitop = true;
				break;
			case MODE_OWNER_READ:
				max_v = S_IRUSR;
				is_bitop = true;
				break;
			case MODE_OWNER_WRITE:
				max_v = S_IWUSR;
				is_bitop = true;
				break;
			case MODE_OWNER_EXECUTE:
				max_v = S_IXUSR;
				is_bitop = true;
				break;
			case MODE_GROUP_READ:
				max_v = S_IRGRP;
				is_bitop = true;
				break;
			case MODE_GROUP_WRITE:
				max_v = S_IWGRP;
				is_bitop = true;
				break;
			case MODE_GROUP_EXECUTE:
				max_v = S_IXGRP;
				is_bitop = true;
				break;
			case MODE_OTHERS_READ:
				max_v = S_IROTH;
				is_bitop = true;
				break;
			case MODE_OTHERS_WRITE:
				max_v = S_IWOTH;
				is_bitop = true;
				break;
			case MODE_OTHERS_EXECUTE:
				max_v = S_IXOTH;
				is_bitop = true;
				break;
			case EXEC_ARGC:
				if (!bprm)
					goto out;
				max_v = bprm->argc;
				break;
			case EXEC_ENVC:
				if (!bprm)
					goto out;
				max_v = bprm->envc;
				break;
			case TASK_STATE_0:
				max_v = (u8) (task->ccs_flags >> 24);
				break;
			case TASK_STATE_1:
				max_v = (u8) (task->ccs_flags >> 16);
				break;
			case TASK_STATE_2:
				max_v = (u8) (task->ccs_flags >> 8);
				break;
			case TASK_TYPE:
				max_v = ((u8) task->ccs_flags)
					& CCS_TASK_IS_EXECUTE_HANDLER;
				break;
			case TASK_EXECUTE_HANDLER:
				max_v = CCS_TASK_IS_EXECUTE_HANDLER;
				break;
			case CONSTANT_VALUE:
				max_v = *ulong_p++;
				break;
			case CONSTANT_VALUE_RANGE:
				min_v = *ulong_p++;
				max_v = *ulong_p++;
				break;
			case NUMBER_GROUP:
				/* Fetch values later. */
				break;
			default:
				if (!obj)
					goto out;
				if (!obj->validate_done) {
					ccs_get_attributes(obj);
					obj->validate_done = true;
				}
				switch (index) {
				case PATH1_UID:
					if (!obj->path1_valid)
						goto out;
					max_v = obj->path1_stat.uid;
					break;
				case PATH1_GID:
					if (!obj->path1_valid)
						goto out;
					max_v = obj->path1_stat.gid;
					break;
				case PATH1_INO:
					if (!obj->path1_valid)
						goto out;
					max_v = obj->path1_stat.ino;
					break;
				case PATH1_MAJOR:
					if (!obj->path1_valid)
						goto out;
					max_v = MAJOR(obj->path1_stat.dev);
					break;
				case PATH1_MINOR:
					if (!obj->path1_valid)
						goto out;
					max_v = MINOR(obj->path1_stat.dev);
					break;
				case PATH1_TYPE:
					if (!obj->path1_valid)
						goto out;
					max_v = obj->path1_stat.mode & S_IFMT;
					break;
				case PATH1_DEV_MAJOR:
					if (!obj->path1_valid)
						goto out;
					max_v = MAJOR(obj->path1_stat.rdev);
					break;
				case PATH1_DEV_MINOR:
					if (!obj->path1_valid)
						goto out;
					max_v = MINOR(obj->path1_stat.rdev);
					break;
				case PATH1_PERM:
					if (!obj->path1_valid)
						goto out;
					max_v = obj->path1_stat.mode
						& S_IALLUGO;
					break;
				case PATH2_UID:
					if (!obj->path2_valid)
						goto out;
					max_v = obj->path2_stat.uid;
					break;
				case PATH2_GID:
					if (!obj->path2_valid)
						goto out;
					max_v = obj->path2_stat.gid;
					break;
				case PATH2_INO:
					if (!obj->path2_valid)
						goto out;
					max_v = obj->path2_stat.ino;
					break;
				case PATH2_MAJOR:
					if (!obj->path2_valid)
						goto out;
					max_v = MAJOR(obj->path2_stat.dev);
					break;
				case PATH2_MINOR:
					if (!obj->path2_valid)
						goto out;
					max_v = MINOR(obj->path2_stat.dev);
					break;
				case PATH2_TYPE:
					if (!obj->path2_valid)
						goto out;
					max_v = obj->path2_stat.mode & S_IFMT;
					break;
				case PATH2_DEV_MAJOR:
					if (!obj->path2_valid)
						goto out;
					max_v = MAJOR(obj->path2_stat.rdev);
					break;
				case PATH2_DEV_MINOR:
					if (!obj->path2_valid)
						goto out;
					max_v = MINOR(obj->path2_stat.rdev);
					break;
				case PATH2_PERM:
					if (!obj->path2_valid)
						goto out;
					max_v = obj->path2_stat.mode
						& S_IALLUGO;
					break;
				case PATH1_PARENT_UID:
					if (!obj->path1_parent_valid)
						goto out;
					max_v = obj->path1_parent_stat.uid;
					break;
				case PATH1_PARENT_GID:
					if (!obj->path1_parent_valid)
						goto out;
					max_v = obj->path1_parent_stat.gid;
					break;
				case PATH1_PARENT_INO:
					if (!obj->path1_parent_valid)
						goto out;
					max_v = obj->path1_parent_stat.ino;
					break;
				case PATH1_PARENT_PERM:
					if (!obj->path1_parent_valid)
						goto out;
					max_v = obj->path1_parent_stat.mode
						& S_IALLUGO;
					break;
				case PATH2_PARENT_UID:
					if (!obj->path2_parent_valid)
						goto out;
					max_v = obj->path2_parent_stat.uid;
					break;
				case PATH2_PARENT_GID:
					if (!obj->path2_parent_valid)
						goto out;
					max_v = obj->path2_parent_stat.gid;
					break;
				case PATH2_PARENT_INO:
					if (!obj->path2_parent_valid)
						goto out;
					max_v = obj->path2_parent_stat.ino;
					break;
				case PATH2_PARENT_PERM:
					if (!obj->path2_parent_valid)
						goto out;
					max_v = obj->path2_parent_stat.mode
						& S_IALLUGO;
					break;
				}
				break;
			}
			if (index != CONSTANT_VALUE_RANGE)
				min_v = max_v;
			if (j) {
				right_max = max_v;
				right_min = min_v;
				right_is_bitop = is_bitop;
			} else {
				left_max = max_v;
				left_min = min_v;
				left_is_bitop = is_bitop;
			}
		}
		/*
		 * Bit operation is valid only when counterpart value
		 * represents permission.
		 */
		if (left_is_bitop && right_is_bitop)
			goto out;
		if (left_is_bitop) {
			if (right == PATH1_PERM || right == PATH1_PARENT_PERM
			    || right == PATH2_PARENT_PERM) {
				if (match) {
					if ((right_max & left_max))
						continue;
				} else {
					if (!(right_max & left_max))
						continue;
				}
			}
			goto out;
		}
		if (right_is_bitop) {
			if (left == PATH1_PERM || left == PATH1_PARENT_PERM
			    || left == PATH2_PARENT_PERM) {
				if (match) {
					if ((left_max & right_max))
						continue;
				} else {
					if (!(left_max & right_max))
						continue;
				}
			}
			goto out;
		}
		if (right == NUMBER_GROUP) {
			/* Fetch values now. */
			const struct ccs_number_group_entry *group
				= *number_group_p++;
			if (ccs_number_matches_group(left_min, left_max, group)
			    == match)
				continue;
			goto out;
		}
		/* Normal value range comparison. */
		if (match) {
			if (left_min <= right_max && left_max >= right_min)
				continue;
		} else {
			if (left_min > right_max || left_max < right_min)
				continue;
		}
 out:
		return false;
	}
	/* Check argv[] and envp[] now. */
	if (r->ee && (argc || envc))
		return ccs_scan_bprm(r->ee, argc, argv, envc, envp);
	return true;
}

/**
 * ccs_print_condition - Print condition part.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @cond: Pointer to "struct ccs_condition". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
bool ccs_print_condition(struct ccs_io_buffer *head,
			 const struct ccs_condition *cond)
{
	const struct ccs_condition_element *condp;
	const unsigned long *ulong_p;
	const struct ccs_number_group_entry **number_group_p;
	const struct ccs_path_info **path_info_p;
	const struct ccs_path_group_entry **path_group_p;
	const struct ccs_argv_entry *argv;
	const struct ccs_envp_entry *envp;
	u16 condc;
	u16 i;
	u16 j;
	char buffer[32];
	if (!cond)
		goto no_condition;
	condc = cond->condc;
	condp = (const struct ccs_condition_element *) (cond + 1);
	ulong_p = (const unsigned long *) (condp + condc);
	number_group_p = (const struct ccs_number_group_entry **)
		(ulong_p + cond->ulong_count);
	path_info_p = (const struct ccs_path_info **)
		(number_group_p + cond->number_group_count);
	path_group_p = (const struct ccs_path_group_entry **)
		(path_info_p + cond->path_info_count);
	argv = (const struct ccs_argv_entry *)
		(path_group_p + cond->path_group_count);
	envp = (const struct ccs_envp_entry *) (argv + cond->argc);
	memset(buffer, 0, sizeof(buffer));
	for (i = 0; i < condc; i++) {
		const u8 match = condp->equals;
		const u8 left_1_type = (condp->type >> 6) & 3;
		const u8 left_2_type = (condp->type >> 4) & 3;
		const u8 right_1_type = (condp->type >> 2) & 3;
		const u8 right_2_type = condp->type & 3;
		const u8 left = condp->left;
		const u8 right = condp->right;
		condp++;
		if (!ccs_io_printf(head, "%s", i ? " " : " if "))
			goto out;
		switch (left) {
		case ARGV_ENTRY:
			if (!ccs_io_printf(head, "exec.argv[%u]%s\"%s\"",
					   argv->index, argv->is_not ?
					   "!=" : "=", argv->value->name))
				goto out;
			argv++;
			continue;
		case ENVP_ENTRY:
			if (!ccs_io_printf(head, "exec.envp[\"%s\"]%s",
					   envp->name->name, envp->is_not ?
					   "!=" : "="))
				goto out;
			if (envp->value) {
				if (!ccs_io_printf(head, "\"%s\"",
						   envp->value->name))
					goto out;
			} else {
				if (!ccs_io_printf(head, "NULL"))
					goto out;
			}
			envp++;
			continue;
		case CONSTANT_VALUE:
		case CONSTANT_VALUE_RANGE:
			ccs_print_ulong(buffer, sizeof(buffer) - 1,
					*ulong_p++, left_1_type);
			if (!ccs_io_printf(head, "%s", buffer))
				goto out;
			if (left == CONSTANT_VALUE)
				break;
			ccs_print_ulong(buffer, sizeof(buffer) - 1,
					*ulong_p++, left_2_type);
			if (!ccs_io_printf(head, "-%s", buffer))
				goto out;
			break;
		default:
			if (left >= MAX_KEYWORD)
				goto out;
			if (!ccs_io_printf(head, "%s",
					  ccs_condition_keyword[left]))
				goto out;
			break;
		}
		if (!ccs_io_printf(head, "%s", match ? "=" : "!="))
			goto out;
		switch (right) {
		case PATH_INFO:
			if (!ccs_io_printf(head, "\"%s\"",
					   (*path_info_p)->name))
				goto out;
			path_info_p++;
			break;
		case PATH_GROUP:
			if (!ccs_io_printf(head, "@%s", (*path_group_p)->
					   group_name->name))
				goto out;
			path_group_p++;
			break;
		case NUMBER_GROUP:
			if (!ccs_io_printf(head, "@%s", (*number_group_p)->
					   group_name->name))
				goto out;
			number_group_p++;
			break;
		case CONSTANT_VALUE:
		case CONSTANT_VALUE_RANGE:
			ccs_print_ulong(buffer, sizeof(buffer) - 1,
					*ulong_p++, right_1_type);
			if (!ccs_io_printf(head, "%s", buffer))
				goto out;
			if (right == CONSTANT_VALUE)
				break;
			ccs_print_ulong(buffer, sizeof(buffer) - 1,
					*ulong_p++, right_2_type);
			if (!ccs_io_printf(head, "-%s", buffer))
				goto out;
			break;
		default:
			if (right >= MAX_KEYWORD)
				goto out;
			if (!ccs_io_printf(head, "%s",
					   ccs_condition_keyword[right]))
				goto out;
			break;
		}
	}
	i = cond->post_state[3];
	if (!i)
		goto no_condition;
	if (!ccs_io_printf(head, " ; set"))
		goto out;
	for (j = 0; j < 3; j++) {
		if (!(i & (1 << j)))
			continue;
		if (!ccs_io_printf(head, " task.state[%u]=%u", j,
				   cond->post_state[j]))
			goto out;
	}
 no_condition:
	if (ccs_io_printf(head, "\n"))
		return true;
 out:
	return false;
}

/**
 * ccs_handler_cond - Create conditional part for execute_handler process.
 *
 * Returns pointer to "struct ccs_condition" if current process is an
 * execute handler, NULL otherwise.
 */
struct ccs_condition *ccs_handler_cond(void)
{
	char str[] = "if task.type=execute_handler";
	if (!(current->ccs_flags & CCS_TASK_IS_EXECUTE_HANDLER))
		return NULL;
	return ccs_get_condition(str);
}

/* The list for "struct ccs_number_group_entry". */
LIST_HEAD(ccs_number_group_list);

/**
 * ccs_get_number_group - Allocate memory for "struct ccs_number_group_entry".
 *
 * @group_name: The name of number group.
 *
 * Returns pointer to "struct ccs_number_group_entry" on success,
 * NULL otherwise.
 */
struct ccs_number_group_entry *ccs_get_number_group(const char *group_name)
{
	struct ccs_number_group_entry *entry = NULL;
	struct ccs_number_group_entry *group;
	const struct ccs_path_info *saved_group_name;
	int error = -ENOMEM;
	if (!ccs_is_correct_path(group_name, 0, 0, 0) ||
	    !group_name[0])
		return NULL;
	saved_group_name = ccs_get_name(group_name);
	if (!saved_group_name)
		return NULL;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(group, &ccs_number_group_list, list) {
		if (saved_group_name != group->group_name)
			continue;
		atomic_inc(&group->users);
		error = 0;
		break;
	}
	if (error && ccs_memory_ok(entry, sizeof(*entry))) {
		INIT_LIST_HEAD(&entry->number_group_member_list);
		entry->group_name = saved_group_name;
		saved_group_name = NULL;
		atomic_set(&entry->users, 1);
		list_add_tail_rcu(&entry->list, &ccs_number_group_list);
		group = entry;
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_name(saved_group_name);
	kfree(entry);
	return !error ? group : NULL;
}

/**
 * ccs_update_number_group_entry - Update "struct ccs_number_group_entry" list.
 *
 * @group_name: The name of pathname group.
 * @min:        Min value.
 * @max:        Max value.
 * @is_delete:  True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_number_group_entry(const char *group_name,
					 unsigned long min, unsigned long max,
					 const bool is_delete)
{
	struct ccs_number_group_entry *group;
	struct ccs_number_group_member *entry = NULL;
	struct ccs_number_group_member *member;
	int error = is_delete ? -ENOENT : -ENOMEM;
	if (min > max)
		return -EINVAL;
	group = ccs_get_number_group(group_name);
	if (!group)
		return -ENOMEM;
	if (!is_delete)
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	mutex_lock(&ccs_policy_lock);
	list_for_each_entry_rcu(member, &group->number_group_member_list,
				list) {
		if (member->min != min || member->max != max)
			continue;
		member->is_deleted = is_delete;
		error = 0;
		break;
	}
	if (!is_delete && error && ccs_memory_ok(entry, sizeof(*entry))) {
		entry->min = min;
		entry->max = max;
		list_add_tail_rcu(&entry->list,
				  &group->number_group_member_list);
		entry = NULL;
		error = 0;
	}
	mutex_unlock(&ccs_policy_lock);
	ccs_put_number_group(group);
	kfree(entry);
	return error;
}

/**
 * ccs_write_number_group_policy - Write "struct ccs_number_group_entry" list.
 *
 * @data:      String to parse.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, nagative value otherwise.
 */
int ccs_write_number_group_policy(char *data, const bool is_delete)
{
	char *w[2];
	unsigned long min;
	unsigned long max;
	if (!ccs_tokenize(data, w, sizeof(w)))
		return -EINVAL;
	switch(sscanf(w[1], "%lu-%lu", &min, &max)) {
	case 1:
		max = min;
		break;
	case 2:
		break;
	default:
		return -EINVAL;
	}
	return ccs_update_number_group_entry(w[0], min, max, is_delete);
}

/**
 * ccs_read_number_group_policy - Read "struct ccs_number_group_entry" list.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_read_number_group_policy(struct ccs_io_buffer *head)
{
	struct list_head *gpos;
	struct list_head *mpos;
	bool done = true;
	ccs_check_read_lock();
	list_for_each_cookie(gpos, head->read_var1, &ccs_number_group_list) {
		struct ccs_number_group_entry *group;
		const char *name;
		group = list_entry(gpos, struct ccs_number_group_entry, list);
		name = group->group_name->name;
		list_for_each_cookie(mpos, head->read_var2,
				     &group->number_group_member_list) {
			const struct ccs_number_group_member *member
				= list_entry(mpos,
					     struct ccs_number_group_member,
					     list);
			const unsigned long min = member->min;
			const unsigned long max = member->max;
			if (member->is_deleted)
				continue;
			if (min == max)
				done = ccs_io_printf(head, KEYWORD_NUMBER_GROUP
						     "%s %lu\n", name, min);
			else
				done = ccs_io_printf(head, KEYWORD_NUMBER_GROUP
						     "%s %lu-%lu\n", name,
						     min, max);
			if (!done)
				break;
		}
	}
	return done;
}

/**
 * ccs_number_matches_group - Check whether the given number matches members of the given number group.
 *
 * @min:   Min number.
 * @max:   Max number.
 * @group: Pointer to "struct ccs_number_group_entry".
 *
 * Returns true if @min and @max partially overlaps @group, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_number_matches_group(const unsigned long min, const unsigned long max,
			      const struct ccs_number_group_entry *group)
{
	struct ccs_number_group_member *member;
	bool matched = false;
	ccs_check_read_lock();
	list_for_each_entry_rcu(member, &group->number_group_member_list,
				list) {
		if (member->is_deleted)
			continue;
		if (min > member->max || max < member->min)
			continue;
		matched = true;
		break;
	}
	return matched;
}
