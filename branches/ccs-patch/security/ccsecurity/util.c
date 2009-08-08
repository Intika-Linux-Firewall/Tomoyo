/*
 * security/ccsecurity/util.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/08
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include "internal.h"

DEFINE_MUTEX(ccs_policy_lock);

/* Has /sbin/init started? */
bool ccs_policy_loaded;

/* Capability name used by domain policy. */
const char *ccs_capability_control_keyword[CCS_MAX_CAPABILITY_INDEX]
= {
	[CCS_INET_STREAM_SOCKET_CREATE]  = "inet_tcp_create",
	[CCS_INET_STREAM_SOCKET_LISTEN]  = "inet_tcp_listen",
	[CCS_INET_STREAM_SOCKET_CONNECT] = "inet_tcp_connect",
	[CCS_USE_INET_DGRAM_SOCKET]      = "use_inet_udp",
	[CCS_USE_INET_RAW_SOCKET]        = "use_inet_ip",
	[CCS_USE_ROUTE_SOCKET]           = "use_route",
	[CCS_USE_PACKET_SOCKET]          = "use_packet",
	[CCS_SYS_MOUNT]                  = "SYS_MOUNT",
	[CCS_SYS_UMOUNT]                 = "SYS_UMOUNT",
	[CCS_SYS_REBOOT]                 = "SYS_REBOOT",
	[CCS_SYS_CHROOT]                 = "SYS_CHROOT",
	[CCS_SYS_KILL]                   = "SYS_KILL",
	[CCS_SYS_VHANGUP]                = "SYS_VHANGUP",
	[CCS_SYS_SETTIME]                = "SYS_TIME",
	[CCS_SYS_NICE]                   = "SYS_NICE",
	[CCS_SYS_SETHOSTNAME]            = "SYS_SETHOSTNAME",
	[CCS_USE_KERNEL_MODULE]          = "use_kernel_module",
	[CCS_CREATE_FIFO]                = "create_fifo",
	[CCS_CREATE_BLOCK_DEV]           = "create_block_dev",
	[CCS_CREATE_CHAR_DEV]            = "create_char_dev",
	[CCS_CREATE_UNIX_SOCKET]         = "create_unix_socket",
	[CCS_SYS_LINK]                   = "SYS_LINK",
	[CCS_SYS_SYMLINK]                = "SYS_SYMLINK",
	[CCS_SYS_RENAME]                 = "SYS_RENAME",
	[CCS_SYS_UNLINK]                 = "SYS_UNLINK",
	[CCS_SYS_CHMOD]                  = "SYS_CHMOD",
	[CCS_SYS_CHOWN]                  = "SYS_CHOWN",
	[CCS_SYS_IOCTL]                  = "SYS_IOCTL",
	[CCS_SYS_KEXEC_LOAD]             = "SYS_KEXEC_LOAD",
	[CCS_SYS_PIVOT_ROOT]             = "SYS_PIVOT_ROOT",
	[CCS_SYS_PTRACE]                 = "SYS_PTRACE",
	[CCS_CONCEAL_MOUNT]              = "conceal_mount",
};

/* Profile table. Memory is allocated as needed. */
struct ccs_profile *ccs_profile_ptr[MAX_PROFILES];

/* Utility functions. */

/**
 * ccs_is_byte_range - Check whether the string isa \ooo style octal value.
 *
 * @str: Pointer to the string.
 *
 * Returns true if @str is a \ooo style octal value, false otherwise.
 */
static inline bool ccs_is_byte_range(const char *str)
{
	return *str >= '0' && *str++ <= '3' &&
		*str >= '0' && *str++ <= '7' &&
		*str >= '0' && *str <= '7';
}

/**
 * ccs_is_decimal - Check whether the character is a decimal character.
 *
 * @c: The character to check.
 *
 * Returns true if @c is a decimal character, false otherwise.
 */
static inline bool ccs_is_decimal(const char c)
{
	return c >= '0' && c <= '9';
}

/**
 * ccs_is_hexadecimal - Check whether the character is a hexadecimal character.
 *
 * @c: The character to check.
 *
 * Returns true if @c is a hexadecimal character, false otherwise.
 */
static inline bool ccs_is_hexadecimal(const char c)
{
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f');
}

/**
 * ccs_is_alphabet_char - Check whether the character is an alphabet.
 *
 * @c: The character to check.
 *
 * Returns true if @c is an alphabet character, false otherwise.
 */
static inline bool ccs_is_alphabet_char(const char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/**
 * ccs_make_byte - Make byte value from three octal characters.
 *
 * @c1: The first character.
 * @c2: The second character.
 * @c3: The third character.
 *
 * Returns byte value.
 */
static inline u8 ccs_make_byte(const u8 c1, const u8 c2, const u8 c3)
{
	return ((c1 - '0') << 6) + ((c2 - '0') << 3) + (c3 - '0');
}

/**
 * ccs_str_starts - Check whether the given string starts with the given keyword.
 *
 * @src:  Pointer to pointer to the string.
 * @find: Pointer to the keyword.
 *
 * Returns true if @src starts with @find, false otherwise.
 *
 * The @src is updated to point the first character after the @find
 * if @src starts with @find.
 */
bool ccs_str_starts(char **src, const char *find)
{
	const int len = strlen(find);
	char *tmp = *src;
	if (strncmp(tmp, find, len))
		return false;
	tmp += len;
	*src = tmp;
	return true;
}

/**
 * ccs_normalize_line - Format string.
 *
 * @buffer: The line to normalize.
 *
 * Leading and trailing whitespaces are removed.
 * Multiple whitespaces are packed into single space.
 *
 * Returns nothing.
 */
void ccs_normalize_line(unsigned char *buffer)
{
	unsigned char *sp = buffer;
	unsigned char *dp = buffer;
	bool first = true;
	while (*sp && (*sp <= ' ' || *sp >= 127))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (*sp > ' ' && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || *sp >= 127))
			sp++;
	}
	*dp = '\0';
}

/**
 * ccs_tokenize - Tokenize string.
 *
 * @buffer: The line to tokenize.
 * @w:      Pointer to "char *".
 * @size:   Sizeof @w .
 *
 * Returns true on success, false otherwise.
 */
bool ccs_tokenize(char *buffer, char *w[], size_t size)
{
	int count = size / sizeof(char *);
	int i;
	for (i = 0; i < count; i++)
		w[i] = "";
	for (i = 0; i < count; i++) {
		char *cp = strchr(buffer, ' ');
		if (cp)
			*cp = '\0';
		w[i] = buffer;
		if (!cp)
			break;
		buffer = cp + 1;
	}
	return i < count || !*buffer;
}

/**
 * ccs_is_correct_path - Validate a pathname.
 * @filename:     The pathname to check.
 * @start_type:   Should the pathname start with '/'?
 *                1 = must / -1 = must not / 0 = don't care
 * @pattern_type: Can the pathname contain a wildcard?
 *                1 = must / -1 = must not / 0 = don't care
 * @end_type:     Should the pathname end with '/'?
 *                1 = must / -1 = must not / 0 = don't care
 *
 * Check whether the given filename follows the naming rules.
 * Returns true if @filename follows the naming rules, false otherwise.
 */
bool ccs_is_correct_path(const char *filename, const s8 start_type,
			 const s8 pattern_type, const s8 end_type)
{
	bool contains_pattern = false;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	const char *original_filename = filename;
	if (!filename)
		goto out;
	c = *filename;
	if (start_type == 1) { /* Must start with '/' */
		if (c != '/')
			goto out;
	} else if (start_type == -1) { /* Must not start with '/' */
		if (c == '/')
			goto out;
	}
	if (c)
		c = *(filename + strlen(filename) - 1);
	if (end_type == 1) { /* Must end with '/' */
		if (c != '/')
			goto out;
	} else if (end_type == -1) { /* Must not end with '/' */
		if (c == '/')
			goto out;
	}
	while (1) {
		c = *filename++;
		if (!c)
			break;
		if (c == '\\') {
			c = *filename++;
			switch (c) {
			case '\\':  /* "\\" */
				continue;
			case '$':   /* "\$" */
			case '+':   /* "\+" */
			case '?':   /* "\?" */
			case '*':   /* "\*" */
			case '@':   /* "\@" */
			case 'x':   /* "\x" */
			case 'X':   /* "\X" */
			case 'a':   /* "\a" */
			case 'A':   /* "\A" */
			case '-':   /* "\-" */
				if (pattern_type == -1)
					break; /* Must not contain pattern */
				contains_pattern = true;
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				d = *filename++;
				if (d < '0' || d > '7')
					break;
				e = *filename++;
				if (e < '0' || e > '7')
					break;
				c = ccs_make_byte(c, d, e);
				if (c && (c <= ' ' || c >= 127))
					continue; /* pattern is not \000 */
			}
			goto out;
		} else if (c <= ' ' || c >= 127) {
			goto out;
		}
	}
	if (pattern_type == 1) { /* Must contain pattern */
		if (!contains_pattern)
			goto out;
	}
	return true;
 out:
	printk(KERN_DEBUG "Invalid pathname '%s'\n", original_filename);
	return false;
}

/**
 * ccs_is_correct_domain - Check whether the given domainname follows the naming rules.
 * @domainname:   The domainname to check.
 *
 * Returns true if @domainname follows the naming rules, false otherwise.
 */
bool ccs_is_correct_domain(const unsigned char *domainname)
{
	unsigned char c;
	unsigned char d;
	unsigned char e;
	const char *org_domainname = domainname;
	if (!domainname || strncmp(domainname, ROOT_NAME, ROOT_NAME_LEN))
		goto out;
	domainname += ROOT_NAME_LEN;
	if (!*domainname)
		return true;
	do {
		if (*domainname++ != ' ')
			goto out;
		if (*domainname++ != '/')
			goto out;
		while (1) {
			c = *domainname;
			if (!c || c == ' ')
				break;
			domainname++;
			if (c == '\\') {
				c = *domainname++;
				switch ((c)) {
				case '\\':  /* "\\" */
					continue;
				case '0':   /* "\ooo" */
				case '1':
				case '2':
				case '3':
					d = *domainname++;
					if (d < '0' || d > '7')
						break;
					e = *domainname++;
					if (e < '0' || e > '7')
						break;
					c = ccs_make_byte(c, d, e);
					if (c && (c <= ' ' || c >= 127))
						/* pattern is not \000 */
						continue;
				}
				goto out;
			} else if (c < ' ' || c >= 127) {
				goto out;
			}
		}
	} while (*domainname);
	return true;
 out:
	printk(KERN_DEBUG "Invalid domainname '%s'\n", org_domainname);
	return false;
}

/**
 * ccs_is_domain_def - Check whether the given token can be a domainname.
 *
 * @buffer: The token to check.
 *
 * Returns true if @buffer possibly be a domainname, false otherwise.
 */
bool ccs_is_domain_def(const unsigned char *buffer)
{
	return !strncmp(buffer, ROOT_NAME, ROOT_NAME_LEN);
}

/**
 * ccs_find_domain - Find a domain by the given name.
 *
 * @domainname: The domainname to find.
 *
 * Returns pointer to "struct ccs_domain_info" if found, NULL otherwise.
 *
 * Caller holds ccs_read_lock().
 */
struct ccs_domain_info *ccs_find_domain(const char *domainname)
{
	struct ccs_domain_info *domain;
	struct ccs_path_info name;
	ccs_check_read_lock();
	name.name = domainname;
	ccs_fill_path_info(&name);
	list_for_each_entry_rcu(domain, &ccs_domain_list, list) {
		if (!domain->is_deleted &&
		    !ccs_pathcmp(&name, domain->domainname))
			return domain;
	}
	return NULL;
}

/**
 * ccs_path_depth - Evaluate the number of '/' in a string.
 *
 * @pathname: The string to evaluate.
 *
 * Returns path depth of the string.
 *
 * I score 2 for each of the '/' in the @pathname
 * and score 1 if the @pathname ends with '/'.
 */
static int ccs_path_depth(const char *pathname)
{
	int i = 0;
	if (pathname) {
		const char *ep = pathname + strlen(pathname);
		if (pathname < ep--) {
			if (*ep != '/')
				i++;
			while (pathname <= ep)
				if (*ep-- == '/')
					i += 2;
		}
	}
	return i;
}

/**
 * ccs_const_part_length - Evaluate the initial length without a pattern in a token.
 *
 * @filename: The string to evaluate.
 *
 * Returns the initial length without a pattern in @filename.
 */
static int ccs_const_part_length(const char *filename)
{
	char c;
	int len = 0;
	if (!filename)
		return 0;
	while (1) {
		c = *filename++;
		if (!c)
			break;
		if (c != '\\') {
			len++;
			continue;
		}
		c = *filename++;
		switch (c) {
		case '\\':  /* "\\" */
			len += 2;
			continue;
		case '0':   /* "\ooo" */
		case '1':
		case '2':
		case '3':
			c = *filename++;
			if (c < '0' || c > '7')
				break;
			c = *filename++;
			if (c < '0' || c > '7')
				break;
			len += 4;
			continue;
		}
		break;
	}
	return len;
}

/**
 * ccs_fill_path_info - Fill in "struct ccs_path_info" members.
 *
 * @ptr: Pointer to "struct ccs_path_info" to fill in.
 *
 * The caller sets "struct ccs_path_info"->name.
 */
void ccs_fill_path_info(struct ccs_path_info *ptr)
{
	const char *name = ptr->name;
	const int len = strlen(name);
	ptr->total_len = len;
	ptr->const_len = ccs_const_part_length(name);
	ptr->is_dir = len && (name[len - 1] == '/');
	ptr->is_patterned = (ptr->const_len < len);
	ptr->hash = full_name_hash(name, len);
	ptr->depth = ccs_path_depth(name);
}

/**
 * ccs_file_matches_pattern2 - Pattern matching without '/' character
 * and "\-" pattern.
 *
 * @filename:     The start of string to check.
 * @filename_end: The end of string to check.
 * @pattern:      The start of pattern to compare.
 * @pattern_end:  The end of pattern to compare.
 *
 * Returns true if @filename matches @pattern, false otherwise.
 */
static bool ccs_file_matches_pattern2(const char *filename,
				      const char *filename_end,
				      const char *pattern,
				      const char *pattern_end)
{
	while (filename < filename_end && pattern < pattern_end) {
		char c;
		if (*pattern != '\\') {
			if (*filename++ != *pattern++)
				return false;
			continue;
		}
		c = *filename;
		pattern++;
		switch (*pattern) {
			int i;
			int j;
		case '?':
			if (c == '/') {
				return false;
			} else if (c == '\\') {
				if (filename[1] == '\\')
					filename++;
				else if (ccs_is_byte_range(filename + 1))
					filename += 3;
				else
					return false;
			}
			break;
		case '\\':
			if (c != '\\')
				return false;
			if (*++filename != '\\')
				return false;
			break;
		case '+':
			if (!ccs_is_decimal(c))
				return false;
			break;
		case 'x':
			if (!ccs_is_hexadecimal(c))
				return false;
			break;
		case 'a':
			if (!ccs_is_alphabet_char(c))
				return false;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
			if (c == '\\' && ccs_is_byte_range(filename + 1)
			    && strncmp(filename + 1, pattern, 3) == 0) {
				filename += 3;
				pattern += 2;
				break;
			}
			return false; /* Not matched. */
		case '*':
		case '@':
			for (i = 0; i <= filename_end - filename; i++) {
				if (ccs_file_matches_pattern2(filename + i,
							      filename_end,
							      pattern + 1,
							      pattern_end))
					return true;
				c = filename[i];
				if (c == '.' && *pattern == '@')
					break;
				if (c != '\\')
					continue;
				if (filename[i + 1] == '\\')
					i++;
				else if (ccs_is_byte_range(filename + i + 1))
					i += 3;
				else
					break; /* Bad pattern. */
			}
			return false; /* Not matched. */
		default:
			j = 0;
			c = *pattern;
			if (c == '$') {
				while (ccs_is_decimal(filename[j]))
					j++;
			} else if (c == 'X') {
				while (ccs_is_hexadecimal(filename[j]))
					j++;
			} else if (c == 'A') {
				while (ccs_is_alphabet_char(filename[j]))
					j++;
			}
			for (i = 1; i <= j; i++) {
				if (ccs_file_matches_pattern2(filename + i,
							      filename_end,
							      pattern + 1,
							      pattern_end))
					return true;
			}
			return false; /* Not matched or bad pattern. */
		}
		filename++;
		pattern++;
	}
	while (*pattern == '\\' &&
	       (*(pattern + 1) == '*' || *(pattern + 1) == '@'))
		pattern += 2;
	return filename == filename_end && pattern == pattern_end;
}

/**
 * ccs_file_matches_pattern - Pattern matching without without '/' character.
 *
 * @filename:     The start of string to check.
 * @filename_end: The end of string to check.
 * @pattern:      The start of pattern to compare.
 * @pattern_end:  The end of pattern to compare.
 *
 * Returns true if @filename matches @pattern, false otherwise.
 */
static bool ccs_file_matches_pattern(const char *filename,
				     const char *filename_end,
				     const char *pattern,
				     const char *pattern_end)
{
	const char *pattern_start = pattern;
	bool first = true;
	bool result;
	while (pattern < pattern_end - 1) {
		/* Split at "\-" pattern. */
		if (*pattern++ != '\\' || *pattern++ != '-')
			continue;
		result = ccs_file_matches_pattern2(filename, filename_end,
						   pattern_start, pattern - 2);
		if (first)
			result = !result;
		if (result)
			return false;
		first = false;
		pattern_start = pattern;
	}
	result = ccs_file_matches_pattern2(filename, filename_end,
					   pattern_start, pattern_end);
	return first ? result : !result;
}

/**
 * ccs_path_matches_pattern - Check whether the given filename matches the given pattern.
 * @filename: The filename to check.
 * @pattern:  The pattern to compare.
 *
 * Returns true if matches, false otherwise.
 *
 * The following patterns are available.
 *   \\     \ itself.
 *   \ooo   Octal representation of a byte.
 *   \*     More than or equals to 0 character other than '/'.
 *   \@     More than or equals to 0 character other than '/' or '.'.
 *   \?     1 byte character other than '/'.
 *   \$     More than or equals to 1 decimal digit.
 *   \+     1 decimal digit.
 *   \X     More than or equals to 1 hexadecimal digit.
 *   \x     1 hexadecimal digit.
 *   \A     More than or equals to 1 alphabet character.
 *   \a     1 alphabet character.
 *   \-     Subtraction operator.
 */
bool ccs_path_matches_pattern(const struct ccs_path_info *filename,
			      const struct ccs_path_info *pattern)
{
	/*
	  if (!filename || !pattern)
	  return false;
	*/
	const char *f = filename->name;
	const char *p = pattern->name;
	const int len = pattern->const_len;
	/* If @pattern doesn't contain pattern, I can use strcmp(). */
	if (!pattern->is_patterned)
		return !ccs_pathcmp(filename, pattern);
	/* Dont compare if the number of '/' differs. */
	if (filename->depth != pattern->depth)
		return false;
	/* Compare the initial length without patterns. */
	if (strncmp(f, p, len))
		return false;
	f += len;
	p += len;
	/* Main loop. Compare each directory component. */
	while (*f && *p) {
		const char *f_delimiter = strchr(f, '/');
		const char *p_delimiter = strchr(p, '/');
		if (!f_delimiter)
			f_delimiter = f + strlen(f);
		if (!p_delimiter)
			p_delimiter = p + strlen(p);
		if (!ccs_file_matches_pattern(f, f_delimiter, p, p_delimiter))
			return false;
		f = f_delimiter;
		if (*f)
			f++;
		p = p_delimiter;
		if (*p)
			p++;
	}
	/* Ignore trailing "\*" and "\@" in @pattern. */
	while (*p == '\\' &&
	       (*(p + 1) == '*' || *(p + 1) == '@'))
		p += 2;
	return !*f && !*p;
}

/**
 * ccs_get_exe - Get ccs_realpath() of current process.
 *
 * Returns the ccs_realpath() of current process on success, NULL otherwise.
 *
 * This function uses kzalloc(), so the caller must kfree()
 * if this function didn't return NULL.
 */
const char *ccs_get_exe(void)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	const char *cp = NULL;
	if (!mm)
		return NULL;
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
			cp = ccs_realpath_from_dentry(vma->vm_file->f_dentry,
						      vma->vm_file->f_vfsmnt);
			break;
		}
	}
	up_read(&mm->mmap_sem);
	return cp;
}

/**
 * ccs_get_msg - Get warning message.
 *
 * @is_enforce: Is it enforcing mode?
 *
 * Returns "ERROR" or "WARNING".
 */
const char *ccs_get_msg(const bool is_enforce)
{
	if (is_enforce)
		return "ERROR";
	else
		return "WARNING";
}

/**
 * ccs_can_sleep - Check whether it is permitted to do operations that may sleep.
 *
 * Returns true if it is permitted to do operations that may sleep,
 * false otherwise.
 *
 * TOMOYO Linux supports interactive enforcement that lets processes
 * wait for the administrator's decision.
 * All hooks but the one for ccs_may_autobind() are inserted where
 * it is permitted to do operations that may sleep.
 * Thus, this warning should not happen.
 */
bool ccs_can_sleep(void)
{
	static u8 count = 20;
	if (likely(!in_interrupt()))
		return true;
	if (count) {
		count--;
		printk(KERN_ERR "BUG: sleeping function called "
		       "from invalid context.\n");
		dump_stack();
	}
	return false;
}

/**
 * ccs_check_flags - Check mode for specified functionality.
 *
 * @domain: Pointer to "struct ccs_domain_info". NULL for ccs_current_domain().
 * @index:  The functionality to check mode.
 *
 * Returns the mode of specified functionality.
 */
unsigned int ccs_check_flags(const struct ccs_domain_info *domain,
			     const u8 index)
{
	u8 profile;
	if (!domain)
		domain = ccs_current_domain();
	profile = domain->profile;
	return ccs_policy_loaded && index < CCS_MAX_CONTROL_INDEX
#if MAX_PROFILES != 256
		&& profile < MAX_PROFILES
#endif
		&& ccs_profile_ptr[profile] ?
		ccs_profile_ptr[profile]->value[index] : 0;
}

/**
 * ccs_check_capability_flags - Check mode for specified capability.
 *
 * @domain: Pointer to "struct ccs_domain_info". NULL for ccs_current_domain().
 * @index:  The capability to check mode.
 *
 * Returns the mode of specified capability.
 */
static u8 ccs_check_capability_flags(const struct ccs_domain_info *domain,
				     const u8 index)
{
	const u8 profile = domain ? domain->profile :
		ccs_current_domain()->profile;
	return ccs_policy_loaded && index < CCS_MAX_CAPABILITY_INDEX
#if MAX_PROFILES != 256
		&& profile < MAX_PROFILES
#endif
		&& ccs_profile_ptr[profile] ?
		ccs_profile_ptr[profile]->capability_value[index] : 0;
}

/**
 * ccs_cap2keyword - Convert capability operation to capability name.
 *
 * @operation: The capability index.
 *
 * Returns the name of the specified capability's name.
 */
const char *ccs_cap2keyword(const u8 operation)
{
	return operation < CCS_MAX_CAPABILITY_INDEX
		? ccs_capability_control_keyword[operation] : NULL;
}

/**
 * ccs_init_request_info - Initialize "struct ccs_request_info" members.
 *
 * @r:      Pointer to "struct ccs_request_info" to initialize.
 * @domain: Pointer to "struct ccs_domain_info". NULL for ccs_current_domain().
 * @index:  Index number of functionality.
 */
void ccs_init_request_info(struct ccs_request_info *r,
			   struct ccs_domain_info *domain, const u8 index)
{
	memset(r, 0, sizeof(*r));
	if (!domain)
		domain = ccs_current_domain();
	r->domain = domain;
	r->profile = domain->profile;
	if (index < CCS_MAX_CONTROL_INDEX)
		r->mode = ccs_check_flags(domain, index);
	else
		r->mode = ccs_check_capability_flags(domain, index
						     - CCS_MAX_CONTROL_INDEX);
}

/**
 * ccs_verbose_mode - Check whether TOMOYO is verbose mode.
 *
 * @domain: Pointer to "struct ccs_domain_info". NULL for ccs_current_domain().
 *
 * Returns true if domain policy violation warning should be printed to
 * console.
 */
bool ccs_verbose_mode(const struct ccs_domain_info *domain)
{
	return ccs_check_flags(domain, CCS_VERBOSE) != 0;
}

/**
 * ccs_domain_quota_ok - Check for domain's quota.
 *
 * @r: Pointer to "struct ccs_request_info".
 *
 * Returns true if the domain is not exceeded quota, false otherwise.
 *
 * Caller holds ccs_read_lock().
 */
bool ccs_domain_quota_ok(struct ccs_request_info *r)
{
	unsigned int count = 0;
	struct ccs_domain_info *domain = r->domain;
	struct ccs_acl_info *ptr;
	ccs_check_read_lock();
	if (r->mode != 1)
		return false;
	if (!domain)
		return true;
	list_for_each_entry_rcu(ptr, &domain->acl_info_list, list) {
		if (ptr->type & ACL_DELETED)
			continue;
		switch (ccs_acl_type2(ptr)) {
			struct ccs_single_path_acl_record *acl1;
			struct ccs_double_path_acl_record *acl2;
			u16 perm;
		case TYPE_SINGLE_PATH_ACL:
			acl1 = container_of(ptr,
					    struct ccs_single_path_acl_record,
					    head);
			perm = acl1->perm;
			if (perm & (1 << TYPE_EXECUTE_ACL))
				count++;
			if (perm &
			    ((1 << TYPE_READ_ACL) | (1 << TYPE_WRITE_ACL)))
				count++;
			if (perm & (1 << TYPE_CREATE_ACL))
				count++;
			if (perm & (1 << TYPE_UNLINK_ACL))
				count++;
			if (perm & (1 << TYPE_MKDIR_ACL))
				count++;
			if (perm & (1 << TYPE_RMDIR_ACL))
				count++;
			if (perm & (1 << TYPE_MKFIFO_ACL))
				count++;
			if (perm & (1 << TYPE_MKSOCK_ACL))
				count++;
			if (perm & (1 << TYPE_MKBLOCK_ACL))
				count++;
			if (perm & (1 << TYPE_MKCHAR_ACL))
				count++;
			if (perm & (1 << TYPE_TRUNCATE_ACL))
				count++;
			if (perm & (1 << TYPE_SYMLINK_ACL))
				count++;
			if (perm & (1 << TYPE_REWRITE_ACL))
				count++;
			break;
		case TYPE_DOUBLE_PATH_ACL:
			acl2 = container_of(ptr,
					    struct ccs_double_path_acl_record,
					    head);
			perm = acl2->perm;
			if (perm & (1 << TYPE_LINK_ACL))
				count++;
			if (perm & (1 << TYPE_RENAME_ACL))
				count++;
			break;
		case TYPE_EXECUTE_HANDLER:
		case TYPE_DENIED_EXECUTE_HANDLER:
			break;
		default:
			count++;
		}
	}
	if (count < ccs_check_flags(domain, CCS_MAX_ACCEPT_ENTRY))
		return true;
	if (!domain->quota_warned) {
		domain->quota_warned = true;
		printk(KERN_WARNING "TOMOYO-WARNING: "
		       "Domain '%s' has so many ACLs to hold. "
		       "Stopped learning mode.\n", domain->domainname->name);
	}
	return false;
}
