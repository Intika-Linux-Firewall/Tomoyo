/*
 * fs/tomoyo_cond.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2012/05/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/ccs_common.h>
#include <linux/realpath.h>
#include <linux/version.h>

#include <linux/tomoyo.h>
#include <linux/highmem.h>

/* Structure for argv[]. */
struct ccs_argv_entry {
	unsigned int index;
	const struct ccs_path_info *value;
	bool is_not;
};

/* Structure for envp[]. */
struct ccs_envp_entry {
	const struct ccs_path_info *name;
	const struct ccs_path_info *value;
	bool is_not;
};

/* Structure for symlink's target. */
struct ccs_symlinkp_entry {
	const struct ccs_path_info *value;
	bool is_not;
};

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
		checked = ccs_alloc(argc + envc, false);
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
		ccs_free(checked);
	return result;
}

/**
 * ccs_scan_symlink - Scan symlink's target.
 *
 * @target:   Pointer to "struct ccs_path_info".
 * @symlinkc: Length of @symlinkp.
 * @symlinkp: Poiner to "struct ccs_symlinkp_entry".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_scan_symlink(struct ccs_path_info *target,
			     u16 symlinkc,
			     const struct ccs_symlinkp_entry *symlinkp)
{
	if (!target)
		return false;
	while (symlinkc) {
		const bool bool1 =
			ccs_path_matches_pattern(target, symlinkp->value);
		const bool bool2 = symlinkp->is_not;
		if (bool1 == bool2)
			return false;
		symlinkp++;
		symlinkc--;
	}
	return true;
}

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
	else
		snprintf(buffer, buffer_len, "0x%lX", value);
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
	char *cp;
	start += 10;
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
	if (*start++ != '"')
		goto out;
	cp = start + strlen(start) - 1;
	if (cp < start || *cp != '"')
		goto out;
	*cp = '\0';
	if (!ccs_is_correct_path(start, 0, 0, 0, __func__))
		goto out;
	value = ccs_save_name(start);
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
	char *cp;
	start += 11;
	cp = start;
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
	if (!*cp || !ccs_is_correct_path(cp, 0, 0, 0, __func__))
		goto out;
	name = ccs_save_name(cp);
	if (!name)
		goto out;
	if (!strcmp(start, "NULL")) {
		value = NULL;
	} else {
		if (*start++ != '"')
			goto out;
		cp = start + strlen(start) - 1;
		if (cp < start || *cp != '"')
			goto out;
		*cp = '\0';
		if (!ccs_is_correct_path(start, 0, 0, 0, __func__))
			goto out;
		value = ccs_save_name(start);
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

/**
 * ccs_parse_symlinkp - Parse an symlink.target condition part.
 *
 * @start:    String to parse.
 * @symlinkp: Pointer to "struct ccs_symlinkp_entry".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_parse_symlinkp(char *start, struct ccs_symlinkp_entry *symlinkp)
{
	const struct ccs_path_info *value;
	bool is_not;
	char c;
	char *cp;
	start += 14;
	c = *start++;
	if (c == '=')
		is_not = false;
	else if (c == '!' && *start++ == '=')
		is_not = true;
	else
		goto out;
	if (*start++ != '"')
		goto out;
	cp = start + strlen(start) - 1;
	if (cp < start || *cp != '"')
		goto out;
	*cp = '\0';
	if (!ccs_is_correct_path(start, 0, 0, 0, __func__))
		goto out;
	value = ccs_save_name(start);
	if (!value)
		goto out;
	symlinkp->is_not = is_not;
	symlinkp->value = value;
	return true;
 out:
	return false;
}

/* The list for "struct ccs_condition_list". */
static LIST1_HEAD(ccs_condition_list);

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
	PATH1_UID,
	PATH1_GID,
	PATH1_INO,
	PATH1_MAJOR,
	PATH1_MINOR,
	PATH1_PERM,
	PATH1_TYPE,
	PATH1_DEV_MAJOR,
	PATH1_DEV_MINOR,
	PATH1_PARENT_UID,
	PATH1_PARENT_GID,
	PATH1_PARENT_INO,
	PATH1_PARENT_PERM,
	PATH2_PARENT_UID,
	PATH2_PARENT_GID,
	PATH2_PARENT_INO,
	PATH2_PARENT_PERM,
	MAX_KEYWORD
};

static const char *ccs_condition_control_keyword[MAX_KEYWORD] = {
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
	[PATH1_UID]            = "path1.uid",
	[PATH1_GID]            = "path1.gid",
	[PATH1_INO]            = "path1.ino",
	[PATH1_MAJOR]          = "path1.major",
	[PATH1_MINOR]          = "path1.minor",
	[PATH1_PERM]           = "path1.perm",
	[PATH1_TYPE]           = "path1.type",
	[PATH1_DEV_MAJOR]      = "path1.dev_major",
	[PATH1_DEV_MINOR]      = "path1.dev_minor",
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
 * ccs_find_same_condition - Search for same condition list.
 *
 * @new_ptr: Pointer to "struct ccs_condition_list".
 * @size:    Size of @new_ptr.
 *
 * Returns existing pointer to "struct ccs_condition_list" if the same entry was
 * found, NULL if memory allocation failed, @new_ptr otherwise.
 */
static struct ccs_condition_list *
ccs_find_same_condition(struct ccs_condition_list *new_ptr, const u32 size)
{
	static DEFINE_MUTEX(lock);
	struct ccs_condition_list *ptr;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_condition_list, list) {
		/* Don't compare if size differs. */
		if (ptr->condc != new_ptr->condc ||
		    ptr->argc != new_ptr->argc ||
		    ptr->envc != new_ptr->envc ||
		    ptr->symlinkc != new_ptr->symlinkc)
			continue;
		/*
		 * Compare ptr and new_ptr
		 * except ptr->list and new_ptr->list.
		 */
		if (memcmp(((u8 *) ptr) + sizeof(ptr->list),
			   ((u8 *) new_ptr) + sizeof(new_ptr->list),
			   size - sizeof(ptr->list)))
			continue;
		/* Same entry found. Share this entry. */
		ccs_free(new_ptr);
		new_ptr = ptr;
		goto ok;
	}
	/* Same entry not found. Save this entry. */
	ptr = ccs_alloc_element(size);
	if (ptr) {
		memmove(ptr, new_ptr, size);
		/* Append to chain. */
		list1_add_tail_mb(&ptr->list, &ccs_condition_list);
	}
	ccs_free(new_ptr);
	new_ptr = ptr;
 ok:
	mutex_unlock(&lock);
	return new_ptr;
}

/**
 * ccs_find_or_assign_new_condition - Parse condition part.
 *
 * @condition: Pointer to string to parse.
 *
 * Returns pointer to "struct ccs_condition_list" on success, NULL otherwise.
 */
const struct ccs_condition_list *
ccs_find_or_assign_new_condition(char * const condition)
{
	char *start = condition;
	struct ccs_condition_list *new_ptr = NULL;
	unsigned long *ptr;
	struct ccs_argv_entry *argv;
	struct ccs_envp_entry *envp;
	struct ccs_symlinkp_entry *symlinkp;
	u32 size;
	u8 left;
	u8 right;
	u8 i;
	unsigned long left_min = 0;
	unsigned long left_max = 0;
	unsigned long right_min = 0;
	unsigned long right_max = 0;
	u16 condc = 0;
	u16 argc = 0;
	u16 envc = 0;
	u16 symlinkc = 0;
	u8 post_state[4] = { 0, 0, 0, 0 };
	/* Calculate at runtime. */
	static u8 ccs_condition_control_keyword_len[MAX_KEYWORD];
	if (!ccs_condition_control_keyword_len[MAX_KEYWORD - 1]) {
		for (i = 0; i < MAX_KEYWORD; i++)
			ccs_condition_control_keyword_len[i]
				= strlen(ccs_condition_control_keyword[i]);
	}
	if (!ccs_parse_post_condition(start, post_state))
		goto out;
	start = condition;
	if (!strncmp(start, "if ", 3))
		start += 3;
	else if (*start)
		return NULL;
	while (1) {
		while (*start == ' ')
			start++;
		if (!*start)
			break;
		if (!strncmp(start, "exec.argv[", 10)) {
			argc++;
			start = strchr(start + 10, ' ');
			if (!start)
				break;
			continue;
		} else if (!strncmp(start, "exec.envp[\"", 11)) {
			envc++;
			start = strchr(start + 11, ' ');
			if (!start)
				break;
			continue;
		} else if (!strncmp(start, "symlink.target", 14)) {
			symlinkc++;
			start = strchr(start + 14, ' ');
			if (!start)
				break;
			continue;
		}
		for (left = 0; left < MAX_KEYWORD; left++) {
			const int len =
				ccs_condition_control_keyword_len[left];
			if (strncmp(start, ccs_condition_control_keyword[left],
				    len))
				continue;
			start += len;
			break;
		}
		if (left < MAX_KEYWORD)
			goto check_operator_1;
		if (!ccs_parse_ulong(&left_min, &start))
			goto out;
		condc++; /* body */
		if (*start != '-')
			goto check_operator_1;
		start++;
		if (!ccs_parse_ulong(&left_max, &start) || left_min > left_max)
			goto out;
		condc++; /* body */
 check_operator_1:
		if (strncmp(start, "!=", 2) == 0)
			start += 2;
		else if (*start == '=')
			start++;
		else
			goto out;
		condc++; /* header */
		for (right = 0; right < MAX_KEYWORD; right++) {
			const int len =
				ccs_condition_control_keyword_len[right];
			if (strncmp(start, ccs_condition_control_keyword[right],
				    len))
				continue;
			start += len;
			break;
		}
		if (right < MAX_KEYWORD)
			continue;
		if (!ccs_parse_ulong(&right_min, &start))
			goto out;
		condc++; /* body */
		if (*start != '-')
			continue;
		start++;
		if (!ccs_parse_ulong(&right_max, &start) ||
		    right_min > right_max)
			goto out;
		condc++; /* body */
	}
	size = sizeof(*new_ptr)
		+ condc * sizeof(unsigned long)
		+ argc * sizeof(struct ccs_argv_entry)
		+ envc * sizeof(struct ccs_envp_entry)
		+ symlinkc * sizeof(struct ccs_symlinkp_entry);
	new_ptr = ccs_alloc(size, false);
	if (!new_ptr)
		return NULL;
	for (i = 0; i < 4; i++)
		new_ptr->post_state[i] = post_state[i];
	new_ptr->condc = condc;
	new_ptr->argc = argc;
	new_ptr->envc = envc;
	new_ptr->symlinkc = symlinkc;
	ptr = (unsigned long *) (new_ptr + 1);
	argv = (struct ccs_argv_entry *) (ptr + condc);
	envp = (struct ccs_envp_entry *) (argv + argc);
	symlinkp = (struct ccs_symlinkp_entry *) (envp + envc);
	start = condition;
	if (!strncmp(start, "if ", 3))
		start += 3;
	else if (*start)
		goto out;
	while (1) {
		u8 match = 0;
		u8 left_1_type = 0;
		u8 left_2_type = 0;
		u8 right_1_type = 0;
		u8 right_2_type = 0;
		while (*start == ' ')
			start++;
		if (!*start)
			break;
		if (!strncmp(start, "exec.argv[", 10)) {
			char *cp = strchr(start + 10, ' ');
			if (cp)
				*cp = '\0';
			if (!ccs_parse_argv(start, argv))
				goto out;
			argv++;
			argc--;
			if (cp)
				*cp = ' ';
			else
				break;
			start = cp;
			continue;
		} else if (!strncmp(start, "exec.envp[\"", 11)) {
			char *cp = strchr(start + 11, ' ');
			if (cp)
				*cp = '\0';
			if (!ccs_parse_envp(start, envp))
				goto out;
			envp++;
			envc--;
			if (cp)
				*cp = ' ';
			else
				break;
			start = cp;
			continue;
		} else if (!strncmp(start, "symlink.target", 14)) {
			char *cp = strchr(start + 14, ' ');
			if (cp)
				*cp = '\0';
			if (!ccs_parse_symlinkp(start, symlinkp))
				goto out;
			symlinkp++;
			symlinkc--;
			if (cp)
				*cp = ' ';
			else
				break;
			start = cp;
			continue;
		}
		for (left = 0; left < MAX_KEYWORD; left++) {
			const int len =
				ccs_condition_control_keyword_len[left];
			if (strncmp(start, ccs_condition_control_keyword[left],
				    len))
				continue;
			start += len;
			break;
		}
		if (left < MAX_KEYWORD)
			goto check_operator_2;
		left_1_type = ccs_parse_ulong(&left_min, &start);
		condc--; /* body */
		if (*start != '-')
			goto check_operator_2;
		start++;
		left_2_type = ccs_parse_ulong(&left_max, &start);
		condc--; /* body */
		left++;
 check_operator_2:
		if (!strncmp(start, "!=", 2)) {
			start += 2;
		} else if (*start == '=') {
			match |= 1;
			start++;
		} else {
			break; /* This shouldn't happen. */
		}
		condc--; /* header */
		for (right = 0; right < MAX_KEYWORD; right++) {
			const int len =
				ccs_condition_control_keyword_len[right];
			if (strncmp(start, ccs_condition_control_keyword[right],
				    len))
				continue;
			start += len;
			break;
		}
		if (right < MAX_KEYWORD)
			goto store_value;
		right_1_type = ccs_parse_ulong(&right_min, &start);
		condc--; /* body */
		if (*start != '-')
			goto store_value;
		start++;
		right_2_type = ccs_parse_ulong(&right_max, &start);
		condc--; /* body */
		right++;
 store_value:
		*ptr = (((u32) match) << 16) |
			(((u32) left_1_type) << 18) |
			(((u32) left_2_type) << 20) |
			(((u32) right_1_type) << 22) |
			(((u32) right_2_type) << 24) |
			(((u32) left) << 8) |
			((u32) right);
		ptr++;
		if (left >= MAX_KEYWORD) {
			*ptr = left_min;
			ptr++;
		}
		if (left == MAX_KEYWORD + 1) {
			*ptr = left_max;
			ptr++;
		}
		if (right >= MAX_KEYWORD) {
			*ptr = right_min;
			ptr++;
		}
		if (right == MAX_KEYWORD + 1) {
			*ptr = right_max;
			ptr++;
		}
	}
	/*
	  printk(KERN_DEBUG "argc=%u envc=%u symlinkc=%u condc=%u\n",
	  argc, envc, symlinkc, condc);
	*/
	BUG_ON(argc);
	BUG_ON(envc);
	BUG_ON(symlinkc);
	BUG_ON(condc);
	return ccs_find_same_condition(new_ptr, size);
 out:
	ccs_free(new_ptr);
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

	if (obj->path2_vfsmnt) {
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
}
#else
static void ccs_get_attributes(struct ccs_obj_info *obj)
{
	struct vfsmount *mnt;
	struct dentry *dentry;
	struct inode *inode;
	struct kstat stat;

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
	if (mnt) {
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
}
#endif

/**
 * ccs_check_condition - Check condition part.
 *
 * @r:   Pointer to "struct ccs_request_info".
 * @acl: Pointer to "struct ccs_acl_info".
 *
 * Returns true on success, false otherwise.
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
	const unsigned long *ptr;
	const struct ccs_argv_entry *argv;
	const struct ccs_envp_entry *envp;
	const struct ccs_symlinkp_entry *symlinkp;
	struct ccs_obj_info *obj;
	u16 condc;
	u16 argc;
	u16 envc;
	u16 symlinkc;
	const struct ccs_condition_list *cond = ccs_get_condition_part(acl);
	struct linux_binprm *bprm = NULL;
	if (!cond)
		return true;
	condc = cond->condc;
	argc = cond->argc;
	envc = cond->envc;
	symlinkc = cond->symlinkc;
	obj = r->obj;
	if (r->ee)
		bprm = r->ee->bprm;
	if (!bprm && (argc || envc))
		return false;
	ptr = (unsigned long *) (cond + 1);
	argv = (const struct ccs_argv_entry *) (ptr + condc);
	envp = (const struct ccs_envp_entry *) (argv + argc);
	symlinkp = (const struct ccs_symlinkp_entry *) (envp + envc); 
	for (i = 0; i < condc; i++) {
		const u32 header = *ptr;
		const bool match = (header >> 16) & 1;
		const u8 left = header >> 8;
		const u8 right = header;
		bool left_is_bitop = false;
		bool right_is_bitop = false;
		u8 j;
		ptr++;
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
				i++;
				break;
			case EXEC_ENVC:
				if (!bprm)
					goto out;
				max_v = bprm->envc;
				i++;
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
			case MAX_KEYWORD:
				max_v = *ptr;
				ptr++;
				i++;
				break;
			case MAX_KEYWORD + 1:
				min_v = *ptr;
				ptr++;
				max_v = *ptr;
				ptr++;
				i += 2;
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
				case PATH1_PARENT_PERM:
					if (!obj->path1_parent_valid)
						goto out;
					max_v = obj->path1_parent_stat.mode
						& S_IALLUGO;
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
			if (index != MAX_KEYWORD + 1)
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
	if (symlinkc) {
		if (!obj || !ccs_scan_symlink(obj->symlink_target,
					      symlinkc, symlinkp))
			return false;
	}
	if (r->ee && (argc || envc))
		return ccs_scan_bprm(r->ee, argc, argv, envc, envp);
	return true;
}

/**
 * ccs_print_condition - Print condition part.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @cond: Pointer to "struct ccs_condition_list". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
bool ccs_print_condition(struct ccs_io_buffer *head,
			 const struct ccs_condition_list *cond)
{
	const unsigned long *ptr;
	const struct ccs_argv_entry *argv;
	const struct ccs_envp_entry *envp;
	const struct ccs_symlinkp_entry *symlinkp;
	u16 condc;
	u16 argc;
	u16 envc;
	u16 symlinkc;
	u16 i;
	u16 j;
	char buffer[32];
	if (!cond)
		goto no_condition;
	condc = cond->condc;
	argc = cond->argc;
	envc = cond->envc;
	symlinkc = cond->symlinkc;
	ptr = (const unsigned long *) (cond + 1);
	argv = (const struct ccs_argv_entry *) (ptr + condc);
	envp = (const struct ccs_envp_entry *) (argv + argc);
	symlinkp = (const struct ccs_symlinkp_entry *) (envp + envc);
	memset(buffer, 0, sizeof(buffer));
	for (i = 0; i < condc; i++) {
		const u32 header = *ptr;
		const u8 match = (header >> 16) & 1;
		const u8 left_1_type = (header >> 18) & 3;
		const u8 left_2_type = (header >> 20) & 3;
		const u8 right_1_type = (header >> 22) & 3;
		const u8 right_2_type = (header >> 24) & 3;
		const u8 left = header >> 8;
		const u8 right = header;
		ptr++;
		if (!ccs_io_printf(head, "%s", i ? " " : " if "))
			goto out;
		if (left < MAX_KEYWORD) {
			const char *keyword =
				ccs_condition_control_keyword[left];
			if (!ccs_io_printf(head, "%s", keyword))
				goto out;
			goto print_operator;
		}
		ccs_print_ulong(buffer, sizeof(buffer) - 1, *ptr, left_1_type);
		ptr++;
		if (!ccs_io_printf(head, "%s", buffer))
			goto out;
		i++;
		if (left == MAX_KEYWORD)
			goto print_operator;
		ccs_print_ulong(buffer, sizeof(buffer) - 1, *ptr, left_2_type);
		ptr++;
		if (!ccs_io_printf(head, "-%s", buffer))
			goto out;
		i++;
 print_operator:
		if (!ccs_io_printf(head, "%s", match ? "=" : "!="))
			goto out;
		if (right < MAX_KEYWORD) {
			const char *keyword =
				ccs_condition_control_keyword[right];
			if (!ccs_io_printf(head, "%s", keyword))
				goto out;
			continue;
		}
		ccs_print_ulong(buffer, sizeof(buffer) - 1, *ptr, right_1_type);
		ptr++;
		if (!ccs_io_printf(head, "%s", buffer))
			goto out;
		i++;
		if (right == MAX_KEYWORD)
			continue;
		ccs_print_ulong(buffer, sizeof(buffer) - 1, *ptr, right_2_type);
		ptr++;
		if (!ccs_io_printf(head, "-%s", buffer))
			goto out;
		i++;
	}

	if (!argc && !envc && !symlinkc)
		goto post_condition;
	if (!condc && !ccs_io_printf(head, " if"))
		goto out;
	for (i = 0; i < argc; argv++, i++) {
		const char *op = argv->is_not ? "!=" : "=";
		if (!ccs_io_printf(head, " exec.argv[%u]%s\"%s\"", argv->index,
				   op, argv->value->name))
			goto out;
	}
	/* buffer[1] = '\0'; */
	for (i = 0; i < envc; envp++, i++) {
		const char *op = envp->is_not ? "!=" : "=";
		const char *value = envp->value ? envp->value->name : NULL;
		if (!ccs_io_printf(head, " exec.envp[\"%s\"]%s",
				   envp->name->name, op))
			goto out;
		if (value) {
			if (!ccs_io_printf(head, "\"%s\"", value))
				goto out;
		} else {
			if (!ccs_io_printf(head, "NULL"))
				goto out;
		}
	}
	for (i = 0; i < symlinkc; symlinkp++, i++) {
		const char *op = symlinkp->is_not ? "!=" : "=";
		if (!ccs_io_printf(head, " symlink.target%s\"%s\"", op,
				   symlinkp->value->name))
			goto out;
	}
 post_condition:
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
 * Returns pointer to "struct ccs_condition_list" if current process is an
 * execute handler, NULL otherwise.
 */
const struct ccs_condition_list *ccs_handler_cond(void)
{
	static const struct ccs_condition_list *ccs_cond;
	if (!(current->ccs_flags & CCS_TASK_IS_EXECUTE_HANDLER))
		return NULL;
	if (!ccs_cond) {
		static u8 counter = 20;
		const char *str = "if task.type=execute_handler";
		const int len = strlen(str) + 1;
		char *tmp = kzalloc(len, GFP_KERNEL);
		if (tmp) {
			memmove(tmp, str, len);
			ccs_cond = ccs_find_or_assign_new_condition(tmp);
			kfree(tmp);
		}
		if (!ccs_cond && counter) {
			counter--;
			printk(KERN_WARNING "TOMOYO-WARNING: Failed to create "
			       "condition for execute_handler.\n");
		}
	}
	return ccs_cond;
}
