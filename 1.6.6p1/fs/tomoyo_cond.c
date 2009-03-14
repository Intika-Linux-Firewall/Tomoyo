/*
 * fs/tomoyo_cond.c
 *
 * Implementation of the Domain-Based Mandatory Access Control.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.6.6   2009/02/02
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
#include <linux/binfmts.h>

/* Structure for argv[]. */
struct argv_entry {
	unsigned int index;
	const struct path_info *value;
	bool is_not;
};

/* Structure for envp[]. */
struct envp_entry {
	const struct path_info *name;
	const struct path_info *value;
	bool is_not;
};

/**
 * check_argv - Check argv[] in "struct linux_binbrm".
 *
 * @index:   Index number of @arg_ptr.
 * @arg_ptr: Contents of argv[@index].
 * @argc:    Length of @argv.
 * @argv:    Pointer to "struct argv_entry".
 * @checked: Set to true if @argv[@index] was found.
 *
 * Returns true on success, false otherwise.
 */
static bool check_argv(const unsigned int index, const char *arg_ptr,
		       const int argc, const struct argv_entry *argv,
		       u8 *checked)
{
	int i;
	struct path_info arg;
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
 * check_envp - Check envp[] in "struct linux_binbrm".
 *
 * @env_name:  The name of environment variable.
 * @env_value: The value of environment variable.
 * @envc:      Length of @envp.
 * @envp:      Pointer to "struct envp_entry".
 * @checked:   Set to true if @envp[@env_name] was found.
 *
 * Returns true on success, false otherwise.
 */
static bool check_envp(const char *env_name, const char *env_value,
		       const int envc, const struct envp_entry *envp,
		       u8 *checked)
{
	int i;
	struct path_info name;
	struct path_info value;
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
 * scan_bprm - Scan "struct linux_binprm".
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @argc: Length of @argc.
 * @argv: Pointer to "struct argv_entry".
 * @envc: Length of @envp.
 * @envp: Poiner to "struct envp_entry".
 * @tmp:  Buffer for temporary use.
 *
 * Returns true on success, false otherwise.
 */
static bool scan_bprm(const struct linux_binprm *bprm,
		      const u16 argc, const struct argv_entry *argv,
		      const u16 envc, const struct envp_entry *envp,
		      struct ccs_page_buffer *tmp)
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
	char *arg_ptr = tmp->buffer;
	int arg_len = 0;
	unsigned long pos = bprm->p;
	int i = pos / PAGE_SIZE;
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
		checked = ccs_alloc(argc + envc);
		if (!checked)
			return false;
	}
	while (argv_count || envp_count) {
		struct page *page;
		const char *kaddr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
		if (get_user_pages(current, bprm->mm, pos, 1, 0, 1, &page,
				   NULL) <= 0) {
			printk(KERN_DEBUG "get_user_pages() failed\n");
			result = false;
			goto out;
		}
		pos += PAGE_SIZE - offset;
#else
		page = bprm->page[i];
#endif
		/* Map. */
		kaddr = kmap(page);
		while (offset < PAGE_SIZE) {
			/* Read. */
			struct path_info arg;
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
				if (!check_argv(bprm->argc - argv_count,
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
					if (!check_envp(arg_ptr, cp + 1,
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
		/* Unmap. */
		kunmap(page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
		put_page(page);
#endif
		i++;
		offset = 0;
		if (!result)
			break;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23) && defined(CONFIG_MMU)
 out:
#endif
	if (result) {
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

/* Value type definition. */
#define VALUE_TYPE_DECIMAL     1
#define VALUE_TYPE_OCTAL       2
#define VALUE_TYPE_HEXADECIMAL 3

/**
 * parse_ulong - Parse an "unsigned long" value.
 *
 * @result: Pointer to "unsigned long".
 * @str:    Pointer to string to parse.
 *
 * Returns value type on success, 0 otherwise.
 *
 * The @src is updated to point the first character after the value
 * on success.
 */
static u8 parse_ulong(unsigned long *result, char **str)
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
 * print_ulong - Print an "unsigned long" value.
 *
 * @buffer:     Pointer to buffer.
 * @buffer_len: Size of @buffer.
 * @value:      An "unsigned long" value.
 * @type:       Type of @value.
 *
 * Returns nothing.
 */
static void print_ulong(char *buffer, const int buffer_len,
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
 * parse_argv - Parse an argv[] condition part.
 *
 * @start: String to parse.
 * @argv:  Pointer to "struct argv_entry".
 *
 * Returns true on success, false otherwise.
 */
static bool parse_argv(char *start, struct argv_entry *argv)
{
	unsigned long index;
	const struct path_info *value;
	bool is_not;
	char c;
	char *cp;
	start += 10;
	if (parse_ulong(&index, &start) != VALUE_TYPE_DECIMAL)
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
 * parse_envp - Parse an envp[] condition part.
 *
 * @start: String to parse.
 * @envp:  Pointer to "struct envp_entry".
 *
 * Returns true on success, false otherwise.
 */
static bool parse_envp(char *start, struct envp_entry *envp)
{
	const struct path_info *name;
	const struct path_info *value;
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

/* The list for "struct condition_list". */
static LIST1_HEAD(condition_list);

#define TASK_UID          0
#define TASK_EUID         1
#define TASK_SUID         2
#define TASK_FSUID        3
#define TASK_GID          4
#define TASK_EGID         5
#define TASK_SGID         6
#define TASK_FSGID        7
#define TASK_PID          8
#define TASK_PPID         9
#define PATH1_UID        10
#define PATH1_GID        11
#define PATH1_INO        12
#define PATH1_PARENT_UID 13
#define PATH1_PARENT_GID 14
#define PATH1_PARENT_INO 15
#define PATH2_PARENT_UID 16
#define PATH2_PARENT_GID 17
#define PATH2_PARENT_INO 18
#define EXEC_ARGC        19
#define EXEC_ENVC        20
#define TASK_STATE_0     21
#define TASK_STATE_1     22
#define TASK_STATE_2     23
#define MAX_KEYWORD      24

static struct {
	const char *keyword;
	const int keyword_len; /* strlen(keyword) */
} condition_control_keyword[MAX_KEYWORD] = {
	[TASK_UID]         = { "task.uid",           8 },
	[TASK_EUID]        = { "task.euid",          9 },
	[TASK_SUID]        = { "task.suid",          9 },
	[TASK_FSUID]       = { "task.fsuid",        10 },
	[TASK_GID]         = { "task.gid",           8 },
	[TASK_EGID]        = { "task.egid",          9 },
	[TASK_SGID]        = { "task.sgid",          9 },
	[TASK_FSGID]       = { "task.fsgid",        10 },
	[TASK_PID]         = { "task.pid",           8 },
	[TASK_PPID]        = { "task.ppid",          9 },
	[PATH1_UID]        = { "path1.uid",          9 },
	[PATH1_GID]        = { "path1.gid",          9 },
	[PATH1_INO]        = { "path1.ino",          9 },
	[PATH1_PARENT_UID] = { "path1.parent.uid",  16 },
	[PATH1_PARENT_GID] = { "path1.parent.gid",  16 },
	[PATH1_PARENT_INO] = { "path1.parent.ino",  16 },
	[PATH2_PARENT_UID] = { "path2.parent.uid",  16 },
	[PATH2_PARENT_GID] = { "path2.parent.gid",  16 },
	[PATH2_PARENT_INO] = { "path2.parent.ino",  16 },
	[EXEC_ARGC]        = { "exec.argc",          9 },
	[EXEC_ENVC]        = { "exec.envc",          9 },
	[TASK_STATE_0]     = { "task.state[0]",     13 },
	[TASK_STATE_1]     = { "task.state[1]",     13 },
	[TASK_STATE_2]     = { "task.state[2]",     13 },
};

/**
 * parse_post_condition - Parse post-condition part.
 *
 * @condition:  String to parse.
 * @post_state: Buffer to store post-condition part.
 *
 * Returns true on success, false otherwise.
 */
static bool parse_post_condition(char * const condition, u8 post_state[4])
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
		if (!parse_ulong(&value, &start) || value > 255)
			goto out;
		post_state[i] = (u8) value;
	}
	return true;
 out:
	return false;
}

/**
 * find_same_condition - Search for same condition list.
 *
 * @new_ptr: Pointer to "struct condition_list".
 * @size:    Size of @new_ptr.
 *
 * Returns existing pointer to "struct condition_list" if the same entry was
 * found, NULL if memory allocation failed, @new_ptr otherwise.
 */
static struct condition_list *
find_same_condition(struct condition_list *new_ptr, const u32 size)
{
	static DEFINE_MUTEX(lock);
	struct condition_list *ptr;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &condition_list, list) {
		/* Don't compare if size differs. */
		if (ptr->condc != new_ptr->condc ||
		    ptr->argc != new_ptr->argc ||
		    ptr->envc != new_ptr->envc)
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
		list1_add_tail_mb(&ptr->list, &condition_list);
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
 * Returns pointer to "struct condition_list" on success, NULL otherwise.
 */
const struct condition_list *
ccs_find_or_assign_new_condition(char * const condition)
{
	char *start = condition;
	struct condition_list *new_ptr = NULL;
	unsigned long *ptr;
	struct argv_entry *argv;
	struct envp_entry *envp;
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
	u8 post_state[4] = { 0, 0, 0, 0 };
	if (!parse_post_condition(start, post_state))
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
		}
		for (left = 0; left < MAX_KEYWORD; left++) {
			const int len =
				condition_control_keyword[left].keyword_len;
			if (strncmp(start,
				    condition_control_keyword[left].keyword,
				    len))
				continue;
			start += len;
			break;
		}
		if (left < MAX_KEYWORD)
			goto check_operator_1;
		if (!parse_ulong(&left_min, &start))
			goto out;
		condc++; /* body */
		if (*start != '-')
			goto check_operator_1;
		start++;
		if (!parse_ulong(&left_max, &start) || left_min > left_max)
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
				condition_control_keyword[right].keyword_len;
			if (strncmp(start,
				    condition_control_keyword[right].keyword,
				    len))
				continue;
			start += len;
			break;
		}
		if (right < MAX_KEYWORD)
			continue;
		if (!parse_ulong(&right_min, &start))
			goto out;
		condc++; /* body */
		if (*start != '-')
			continue;
		start++;
		if (!parse_ulong(&right_max, &start) || right_min > right_max)
			goto out;
		condc++; /* body */
	}
	size = sizeof(*new_ptr)
		+ condc * sizeof(unsigned long)
		+ argc * sizeof(struct argv_entry)
		+ envc * sizeof(struct envp_entry);
	new_ptr = ccs_alloc(size);
	if (!new_ptr)
		return NULL;
	for (i = 0; i < 4; i++)
		new_ptr->post_state[i] = post_state[i];
	new_ptr->condc = condc;
	new_ptr->argc = argc;
	new_ptr->envc = envc;
	ptr = (unsigned long *) (new_ptr + 1);
	argv = (struct argv_entry *) (ptr + condc);
	envp = (struct envp_entry *) (argv + argc);
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
			if (!parse_argv(start, argv))
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
			if (!parse_envp(start, envp))
				goto out;
			envp++;
			envc--;
			if (cp)
				*cp = ' ';
			else
				break;
			start = cp;
			continue;
		}
		for (left = 0; left < MAX_KEYWORD; left++) {
			const int len =
				condition_control_keyword[left].keyword_len;
			if (strncmp(start,
				    condition_control_keyword[left].keyword,
				    len))
				continue;
			start += len;
			break;
		}
		if (left < MAX_KEYWORD)
			goto check_operator_2;
		left_1_type = parse_ulong(&left_min, &start);
		condc--; /* body */
		if (*start != '-')
			goto check_operator_2;
		start++;
		left_2_type = parse_ulong(&left_max, &start);
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
				condition_control_keyword[right].keyword_len;
			if (strncmp(start,
				    condition_control_keyword[right].keyword,
				    len))
				continue;
			start += len;
			break;
		}
		if (right < MAX_KEYWORD)
			goto store_value;
		right_1_type = parse_ulong(&right_min, &start);
		condc--; /* body */
		if (*start != '-')
			goto store_value;
		start++;
		right_2_type = parse_ulong(&right_max, &start);
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
	  printk(KERN_DEBUG "argc=%u envc=%u condc=%u\n", argc, envc, condc);
	*/
	BUG_ON(argc);
	BUG_ON(envc);
	BUG_ON(condc);
	return find_same_condition(new_ptr, size);
 out:
	ccs_free(new_ptr);
	return NULL;
}

/**
 * get_attributes - Revalidate "struct inode".
 *
 * @obj: Pointer to "struct obj_info".
 *
 * Returns nothing.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
static void get_attributes(struct obj_info *obj)
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
				obj->path2_parent_valid = true;
			}
		}
		dput(dentry);
	}
}
#else
static void get_attributes(struct obj_info *obj)
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
 * @acl: Pointer to "struct acl_info".
 *
 * Returns true on success, false otherwise.
 */
bool ccs_check_condition(struct ccs_request_info *r,
			 const struct acl_info *acl)
{
	const struct task_struct *task = current;
	u32 i;
	unsigned long left_min = 0;
	unsigned long left_max = 0;
	unsigned long right_min = 0;
	unsigned long right_max = 0;
	const unsigned long *ptr;
	const struct argv_entry *argv;
	const struct envp_entry *envp;
	struct obj_info *obj;
	u16 condc;
	u16 argc;
	u16 envc;
	const struct condition_list *cond = ccs_get_condition_part(acl);
	const struct linux_binprm *bprm;
	if (!cond)
		return true;
	condc = cond->condc;
	argc = cond->argc;
	envc = cond->envc;
	bprm = r->bprm;
	obj = r->obj;
	if (!bprm && (argc || envc))
		return false;
	ptr = (unsigned long *) (cond + 1);
	argv = (const struct argv_entry *) (ptr + condc);
	envp = (const struct envp_entry *) (argv + argc);
	for (i = 0; i < condc; i++) {
		const u32 header = *ptr;
		const bool match = (header >> 16) & 1;
		const u8 left = header >> 8;
		const u8 right = header;
		ptr++;
		if ((left >= PATH1_UID && left < EXEC_ARGC) ||
		    (right >= PATH1_UID && right < EXEC_ARGC)) {
			if (!obj)
				goto out;
			if (!obj->validate_done) {
				get_attributes(obj);
				obj->validate_done = true;
			}
		}
		switch (left) {
		case TASK_UID:
			left_max = current_uid();
			break;
		case TASK_EUID:
			left_max = current_euid();
			break;
		case TASK_SUID:
			left_max = current_suid();
			break;
		case TASK_FSUID:
			left_max = current_fsuid();
			break;
		case TASK_GID:
			left_max = current_gid();
			break;
		case TASK_EGID:
			left_max = current_egid();
			break;
		case TASK_SGID:
			left_max = current_sgid();
			break;
		case TASK_FSGID:
			left_max = current_fsgid();
			break;
		case TASK_PID:
			left_max = sys_getpid();
			break;
		case TASK_PPID:
			left_max = sys_getppid();
			break;
		case PATH1_UID:
			if (!obj->path1_valid)
				goto out;
			left_max = obj->path1_stat.uid;
			break;
		case PATH1_GID:
			if (!obj->path1_valid)
				goto out;
			left_max = obj->path1_stat.gid;
			break;
		case PATH1_INO:
			if (!obj->path1_valid)
				goto out;
			left_max = obj->path1_stat.ino;
			break;
		case PATH1_PARENT_UID:
			if (!obj->path1_parent_valid)
				goto out;
			left_max = obj->path1_parent_stat.uid;
			break;
		case PATH1_PARENT_GID:
			if (!obj->path1_parent_valid)
				goto out;
			left_max = obj->path1_parent_stat.gid;
			break;
		case PATH1_PARENT_INO:
			if (!obj->path1_parent_valid)
				goto out;
			left_max = obj->path1_parent_stat.ino;
			break;
		case PATH2_PARENT_UID:
			if (!obj->path2_parent_valid)
				goto out;
			left_max = obj->path2_parent_stat.uid;
			break;
		case PATH2_PARENT_GID:
			if (!obj->path2_parent_valid)
				goto out;
			left_max = obj->path2_parent_stat.gid;
			break;
		case PATH2_PARENT_INO:
			if (!obj->path2_parent_valid)
				goto out;
			left_max = obj->path2_parent_stat.ino;
			break;
		case EXEC_ARGC:
			if (!bprm)
				goto out;
			left_max = bprm->argc;
			i++;
			break;
		case EXEC_ENVC:
			if (!bprm)
				goto out;
			left_max = bprm->envc;
			i++;
			break;
		case TASK_STATE_0:
			left_max = (u8) (task->tomoyo_flags >> 24);
			break;
		case TASK_STATE_1:
			left_max = (u8) (task->tomoyo_flags >> 16);
			break;
		case TASK_STATE_2:
			left_max = (u8) (task->tomoyo_flags >> 8);
			break;
		case MAX_KEYWORD:
			left_max = *ptr;
			ptr++;
			i++;
			break;
		case MAX_KEYWORD + 1:
			left_min = *ptr;
			ptr++;
			left_max = *ptr;
			ptr++;
			i += 2;
			break;
		}
		if (left != MAX_KEYWORD + 1)
			left_min = left_max;
		switch (right) {
		case TASK_UID:
			right_max = current_uid();
			break;
		case TASK_EUID:
			right_max = current_euid();
			break;
		case TASK_SUID:
			right_max = current_suid();
			break;
		case TASK_FSUID:
			right_max = current_fsuid();
			break;
		case TASK_GID:
			right_max = current_gid();
			break;
		case TASK_EGID:
			right_max = current_egid();
			break;
		case TASK_SGID:
			right_max = current_sgid();
			break;
		case TASK_FSGID:
			right_max = current_fsgid();
			break;
		case TASK_PID:
			right_max = sys_getpid();
			break;
		case TASK_PPID:
			right_max = sys_getppid();
			break;
		case PATH1_UID:
			if (!obj->path1_valid)
				goto out;
			right_max = obj->path1_stat.uid;
			break;
		case PATH1_GID:
			if (!obj->path1_valid)
				goto out;
			right_max = obj->path1_stat.gid;
			break;
		case PATH1_INO:
			if (!obj->path1_valid)
				goto out;
			right_max = obj->path1_stat.ino;
			break;
		case PATH1_PARENT_UID:
			if (!obj->path1_parent_valid)
				goto out;
			right_max = obj->path1_parent_stat.uid;
			break;
		case PATH1_PARENT_GID:
			if (!obj->path1_parent_valid)
				goto out;
			right_max = obj->path1_parent_stat.gid;
			break;
		case PATH1_PARENT_INO:
			if (!obj->path1_parent_valid)
				goto out;
			right_max = obj->path1_parent_stat.ino;
			break;
		case PATH2_PARENT_UID:
			if (!obj->path2_parent_valid)
				goto out;
			right_max = obj->path2_parent_stat.uid;
			break;
		case PATH2_PARENT_GID:
			if (!obj->path2_parent_valid)
				goto out;
			right_max = obj->path2_parent_stat.gid;
			break;
		case PATH2_PARENT_INO:
			if (!obj->path2_parent_valid)
				goto out;
			right_max = obj->path2_parent_stat.ino;
			break;
		case EXEC_ARGC:
			if (!bprm)
				goto out;
			right_max = bprm->argc;
			i++;
			break;
		case EXEC_ENVC:
			if (!bprm)
				goto out;
			right_max = bprm->envc;
			i++;
			break;
		case TASK_STATE_0:
			right_max = (u8) (task->tomoyo_flags >> 24);
			break;
		case TASK_STATE_1:
			right_max = (u8) (task->tomoyo_flags >> 16);
			break;
		case TASK_STATE_2:
			right_max = (u8) (task->tomoyo_flags >> 8);
			break;
		case MAX_KEYWORD:
			right_max = *ptr;
			ptr++;
			i++;
			break;
		case MAX_KEYWORD + 1:
			right_min = *ptr;
			ptr++;
			right_max = *ptr;
			ptr++;
			i += 2;
			break;
		}
		if (right != MAX_KEYWORD + 1)
			right_min = right_max;
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
	if (bprm && (argc || envc))
		return scan_bprm(bprm, argc, argv, envc, envp, obj->tmp);
	return true;
}

/**
 * ccs_print_condition - Print condition part.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @cond: Pointer to "struct condition_list". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
bool ccs_print_condition(struct ccs_io_buffer *head,
			 const struct condition_list *cond)
{
	const unsigned long *ptr;
	const struct argv_entry *argv;
	const struct envp_entry *envp;
	u16 condc;
	u16 argc;
	u16 envc;
	u16 i;
	u16 j;
	char buffer[32];
	if (!cond)
		goto no_condition;
	condc = cond->condc;
	argc = cond->argc;
	envc = cond->envc;
	ptr = (const unsigned long *) (cond + 1);
	argv = (const struct argv_entry *) (ptr + condc);
	envp = (const struct envp_entry *) (argv + argc);
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
			const char *keyword
				= condition_control_keyword[left].keyword;
			if (!ccs_io_printf(head, "%s", keyword))
				goto out;
			goto print_operator;
		}
		print_ulong(buffer, sizeof(buffer) - 1, *ptr, left_1_type);
		ptr++;
		if (!ccs_io_printf(head, "%s", buffer))
			goto out;
		i++;
		if (left == MAX_KEYWORD)
			goto print_operator;
		print_ulong(buffer, sizeof(buffer) - 1, *ptr, left_2_type);
		ptr++;
		if (!ccs_io_printf(head, "-%s", buffer))
			goto out;
		i++;
 print_operator:
		if (!ccs_io_printf(head, "%s", match ? "=" : "!="))
			goto out;
		if (right < MAX_KEYWORD) {
			const char *keyword
				= condition_control_keyword[right].keyword;
			if (!ccs_io_printf(head, "%s", keyword))
				goto out;
			continue;
		}
		print_ulong(buffer, sizeof(buffer) - 1, *ptr, right_1_type);
		ptr++;
		if (!ccs_io_printf(head, "%s", buffer))
			goto out;
		i++;
		if (right == MAX_KEYWORD)
			continue;
		print_ulong(buffer, sizeof(buffer) - 1, *ptr, right_2_type);
		ptr++;
		if (!ccs_io_printf(head, "-%s", buffer))
			goto out;
		i++;
	}

	if (!argc && !envc)
		goto post_condition;
	if (!condc && !ccs_io_printf(head, " if"))
		goto out;
	for (i = 0; i < argc; argv++, i++) {
		const char *op = argv->is_not ? "!=" : "=";
		if (!ccs_io_printf(head, " exec.argv[%u]%s\"%s\"", argv->index,
				   op, argv->value->name))
			goto out;
	}
	buffer[1] = '\0';
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
