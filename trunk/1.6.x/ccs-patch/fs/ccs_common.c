/*
 * fs/ccs_common.c
 *
 * Common functions for SAKURA and TOMOYO.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.6.9+   2011/05/05
 *
 * This file is applicable to both 2.4.30 and 2.6.11 and later.
 * See README.ccs for ChangeLog.
 *
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define __KERNEL_SYSCALLS__
#endif
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <stdarg.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#include <linux/namei.h>
#include <linux/mount.h>
static const int ccs_lookup_flags = LOOKUP_FOLLOW;
#else
static const int ccs_lookup_flags = LOOKUP_FOLLOW | LOOKUP_POSITIVE;
#endif
#include <linux/realpath.h>
#include <linux/ccs_common.h>
#include <linux/ccs_proc.h>
#include <linux/tomoyo.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#include <linux/unistd.h>
#endif

/* To support PID namespace. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#define find_task_by_pid find_task_by_vpid
#endif

/* Set default specified by the kernel config. */
#ifdef CONFIG_TOMOYO
#define MAX_ACCEPT_ENTRY (CONFIG_TOMOYO_MAX_ACCEPT_ENTRY)
#define MAX_GRANT_LOG    (CONFIG_TOMOYO_MAX_GRANT_LOG)
#define MAX_REJECT_LOG   (CONFIG_TOMOYO_MAX_REJECT_LOG)
#else
#define MAX_ACCEPT_ENTRY 0
#define MAX_GRANT_LOG    0
#define MAX_REJECT_LOG   0
#endif

/* Has /sbin/init started? */
bool ccs_policy_loaded;

/* Log level for SAKURA's printk(). */
const char *ccs_log_level = KERN_DEBUG;

/* String table for functionality that takes 4 modes. */
static const char *ccs_mode_4[4] = {
	"disabled", "learning", "permissive", "enforcing"
};
/* String table for functionality that takes 2 modes. */
static const char *ccs_mode_2[4] = {
	"disabled", "enabled", "enabled", "enabled"
};

/* Table for profile. */
static struct {
	const char *keyword;
	unsigned int current_value;
	const unsigned int max_value;
} ccs_control_array[CCS_MAX_CONTROL_INDEX] = {
	[CCS_MAC_FOR_FILE]        = { "MAC_FOR_FILE",        0, 3 },
	[CCS_MAC_FOR_IOCTL]       = { "MAC_FOR_IOCTL",       0, 3 },
	[CCS_MAC_FOR_ARGV0]       = { "MAC_FOR_ARGV0",       0, 3 },
	[CCS_MAC_FOR_ENV]         = { "MAC_FOR_ENV",         0, 3 },
	[CCS_MAC_FOR_NETWORK]     = { "MAC_FOR_NETWORK",     0, 3 },
	[CCS_MAC_FOR_SIGNAL]      = { "MAC_FOR_SIGNAL",      0, 3 },
	[CCS_DENY_CONCEAL_MOUNT]  = { "DENY_CONCEAL_MOUNT",  0, 3 },
	[CCS_RESTRICT_CHROOT]     = { "RESTRICT_CHROOT",     0, 3 },
	[CCS_RESTRICT_MOUNT]      = { "RESTRICT_MOUNT",      0, 3 },
	[CCS_RESTRICT_UNMOUNT]    = { "RESTRICT_UNMOUNT",    0, 3 },
	[CCS_RESTRICT_PIVOT_ROOT] = { "RESTRICT_PIVOT_ROOT", 0, 3 },
	[CCS_RESTRICT_AUTOBIND]   = { "RESTRICT_AUTOBIND",   0, 1 },
	[CCS_MAX_ACCEPT_ENTRY]
	= { "MAX_ACCEPT_ENTRY",    MAX_ACCEPT_ENTRY, INT_MAX },
#ifdef CONFIG_TOMOYO_AUDIT
	[CCS_MAX_GRANT_LOG]
	= { "MAX_GRANT_LOG",       MAX_GRANT_LOG, INT_MAX },
	[CCS_MAX_REJECT_LOG]
	= { "MAX_REJECT_LOG",      MAX_REJECT_LOG, INT_MAX },
#endif
	[CCS_VERBOSE]             = { "TOMOYO_VERBOSE",      1, 1 },
	[CCS_SLEEP_PERIOD]
	= { "SLEEP_PERIOD",        0, 3000 }, /* in 0.1 second */
};

#ifdef CONFIG_TOMOYO
/* Capability name used by domain policy. */
static const char *ccs_capability_control_keyword[CCS_MAX_CAPABILITY_INDEX]
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
};
#endif

#ifdef CONFIG_TOMOYO
static bool ccs_profile_entry_used[CCS_MAX_CONTROL_INDEX +
				   CCS_MAX_CAPABILITY_INDEX + 1];
#else
static bool ccs_profile_entry_used[CCS_MAX_CONTROL_INDEX + 1];
#endif

/* Profile table. Memory is allocated as needed. */
static struct ccs_profile {
	unsigned int value[CCS_MAX_CONTROL_INDEX];
	const struct ccs_path_info *comment;
#ifdef CONFIG_TOMOYO
	unsigned char capability_value[CCS_MAX_CAPABILITY_INDEX];
#endif
} *ccs_profile_ptr[MAX_PROFILES];

/* Permit policy management by non-root user? */
static bool ccs_manage_by_non_root;

/* Utility functions. */

#ifdef CONFIG_TOMOYO
/**
 * ccs_quiet_setup - Set CCS_VERBOSE=0 by default.
 *
 * @str: Unused.
 *
 * Returns 0.
 */
static int __init ccs_quiet_setup(char *str)
{
	ccs_control_array[CCS_VERBOSE].current_value = 0;
	return 0;
}

__setup("CCS_QUIET", ccs_quiet_setup);
#endif

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
static bool ccs_str_starts(char **src, const char *find)
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
 * ccs_is_correct_path - Validate a pathname.
 * @filename:     The pathname to check.
 * @start_type:   Should the pathname start with '/'?
 *                1 = must / -1 = must not / 0 = don't care
 * @pattern_type: Can the pathname contain a wildcard?
 *                1 = must / -1 = must not / 0 = don't care
 * @end_type:     Should the pathname end with '/'?
 *                1 = must / -1 = must not / 0 = don't care
 * @function:     The name of function calling me.
 *
 * Check whether the given filename follows the naming rules.
 * Returns true if @filename follows the naming rules, false otherwise.
 */
bool ccs_is_correct_path(const char *filename, const s8 start_type,
			 const s8 pattern_type, const s8 end_type,
			 const char *function)
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
	printk(KERN_DEBUG "%s: Invalid pathname '%s'\n", function,
	       original_filename);
	return false;
}

/**
 * ccs_is_correct_domain - Check whether the given domainname follows the naming rules.
 * @domainname:   The domainname to check.
 * @function:     The name of function calling me.
 *
 * Returns true if @domainname follows the naming rules, false otherwise.
 */
bool ccs_is_correct_domain(const unsigned char *domainname,
			   const char *function)
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
	printk(KERN_DEBUG "%s: Invalid domainname '%s'\n", function,
	       org_domainname);
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
 */
struct ccs_domain_info *ccs_find_domain(const char *domainname)
{
	struct ccs_domain_info *domain;
	struct ccs_path_info name;
	name.name = domainname;
	ccs_fill_path_info(&name);
	list1_for_each_entry(domain, &ccs_domain_list, list) {
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
 * ccs_io_printf - Transactional printf() to "struct ccs_io_buffer" structure.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @fmt:  The printf()'s format string, followed by parameters.
 *
 * Returns true on success, false otherwise.
 *
 * The snprintf() will truncate, but ccs_io_printf() won't.
 */
bool ccs_io_printf(struct ccs_io_buffer *head, const char *fmt, ...)
{
	va_list args;
	int len;
	int pos = head->read_avail;
	int size = head->readbuf_size - pos;
	if (size <= 0)
		return false;
	va_start(args, fmt);
	len = vsnprintf(head->read_buf + pos, size, fmt, args);
	va_end(args);
	if (pos + len >= head->readbuf_size)
		return false;
	head->read_avail += len;
	return true;
}

/**
 * ccs_get_exe - Get ccs_realpath() of current process.
 *
 * Returns the ccs_realpath() of current process on success, NULL otherwise.
 *
 * This function uses ccs_alloc(), so the caller must ccs_free()
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

#ifdef CONFIG_TOMOYO
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

#endif

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
#ifdef CONFIG_TOMOYO
	else
		r->mode = ccs_check_capability_flags(domain, index
						     - CCS_MAX_CONTROL_INDEX);
#endif
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
 * @domain: Pointer to "struct ccs_domain_info".
 *
 * Returns true if the domain is not exceeded quota, false otherwise.
 */
bool ccs_domain_quota_ok(struct ccs_domain_info * const domain)
{
	unsigned int count = 0;
	struct ccs_acl_info *ptr;
	if (!domain)
		return true;
	list1_for_each_entry(ptr, &domain->acl_info_list, list) {
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

/**
 * ccs_find_or_assign_new_profile - Create a new profile.
 *
 * @profile: Profile number to create.
 *
 * Returns pointer to "struct ccs_profile" on success, NULL otherwise.
 */
static struct ccs_profile *ccs_find_or_assign_new_profile(const unsigned int
							  profile)
{
	static DEFINE_MUTEX(lock);
	struct ccs_profile *ptr = NULL;
	mutex_lock(&lock);
	if (profile < MAX_PROFILES) {
		ptr = ccs_profile_ptr[profile];
		if (ptr)
			goto ok;
		ptr = ccs_alloc_element(sizeof(*ptr));
		if (ptr) {
			int i;
			for (i = 0; i < CCS_MAX_CONTROL_INDEX; i++)
				ptr->value[i]
					= ccs_control_array[i].current_value;
			/*
			 * Needn't to initialize "ptr->capability_value"
			 * because they are always 0.
			 */
			mb(); /* Avoid out-of-order execution. */
			ccs_profile_ptr[profile] = ptr;
		}
	}
 ok:
	mutex_unlock(&lock);
	return ptr;
}

/**
 * ccs_write_profile - Write profile table.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_profile(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	unsigned int i;
	unsigned int value;
	char *cp;
	struct ccs_profile *ccs_profile;
	i = simple_strtoul(data, &cp, 10);
	if (data != cp) {
		if (*cp != '-')
			return -EINVAL;
		data = cp + 1;
	}
	ccs_profile = ccs_find_or_assign_new_profile(i);
	if (!ccs_profile)
		return -EINVAL;
	cp = strchr(data, '=');
	if (!cp)
		return -EINVAL;
	*cp = '\0';
	ccs_update_counter(CCS_UPDATES_COUNTER_PROFILE);
	if (!strcmp(data, "COMMENT")) {
		const struct ccs_path_info *new_comment
			= ccs_save_name(cp + 1);
		if (!new_comment)
			return -ENOMEM;
		ccs_profile->comment = new_comment;
		ccs_profile_entry_used[0] = true;
		return 0;
	}
#ifdef CONFIG_TOMOYO
	if (ccs_str_starts(&data, KEYWORD_MAC_FOR_CAPABILITY)) {
		if (sscanf(cp + 1, "%u", &value) != 1) {
			for (i = 0; i < 4; i++) {
				if (strcmp(cp + 1, ccs_mode_4[i]))
					continue;
				value = i;
				break;
			}
			if (i == 4)
				return -EINVAL;
		}
		if (value > 3)
			value = 3;
		for (i = 0; i < CCS_MAX_CAPABILITY_INDEX; i++) {
			if (strcmp(data, ccs_capability_control_keyword[i]))
				continue;
			ccs_profile->capability_value[i] = value;
			ccs_profile_entry_used[i + 1 + CCS_MAX_CONTROL_INDEX]
				= true;
			return 0;
		}
		return -EINVAL;
	}
#endif
	for (i = 0; i < CCS_MAX_CONTROL_INDEX; i++) {
		if (strcmp(data, ccs_control_array[i].keyword))
			continue;
		if (sscanf(cp + 1, "%u", &value) != 1) {
			int j;
			const char **modes;
			switch (i) {
			case CCS_RESTRICT_AUTOBIND:
			case CCS_VERBOSE:
				modes = ccs_mode_2;
				break;
			default:
				modes = ccs_mode_4;
				break;
			}
			for (j = 0; j < 4; j++) {
				if (strcmp(cp + 1, modes[j]))
					continue;
				value = j;
				break;
			}
			if (j == 4)
				return -EINVAL;
		} else if (value > ccs_control_array[i].max_value) {
			value = ccs_control_array[i].max_value;
		}
		switch (i) {
		case CCS_DENY_CONCEAL_MOUNT:
		case CCS_RESTRICT_UNMOUNT:
			if (value == 1)
				value = 2; /* learning mode is not supported. */
		}
		ccs_profile->value[i] = value;
		ccs_profile_entry_used[i + 1] = true;
		return 0;
	}
	return -EINVAL;
}

/**
 * ccs_read_profile - Read profile table.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
static int ccs_read_profile(struct ccs_io_buffer *head)
{
	static const int ccs_total
		= CCS_MAX_CONTROL_INDEX + CCS_MAX_CAPABILITY_INDEX + 1;
	int step;
	if (head->read_eof)
		return 0;
	for (step = head->read_step; step < MAX_PROFILES * ccs_total; step++) {
		const u8 index = step / ccs_total;
		u8 type = step % ccs_total;
		const struct ccs_profile *ccs_profile = ccs_profile_ptr[index];
		head->read_step = step;
		if (!ccs_profile)
			continue;
#if !defined(CONFIG_SAKURA) || !defined(CONFIG_TOMOYO)
		switch (type - 1) {
#ifndef CONFIG_SAKURA
		case CCS_DENY_CONCEAL_MOUNT:
		case CCS_RESTRICT_CHROOT:
		case CCS_RESTRICT_MOUNT:
		case CCS_RESTRICT_UNMOUNT:
		case CCS_RESTRICT_PIVOT_ROOT:
		case CCS_RESTRICT_AUTOBIND:
#endif
#ifndef CONFIG_TOMOYO
		case CCS_MAC_FOR_FILE:
		case CCS_MAC_FOR_IOCTL:
		case CCS_MAC_FOR_ARGV0:
		case CCS_MAC_FOR_ENV:
		case CCS_MAC_FOR_NETWORK:
		case CCS_MAC_FOR_SIGNAL:
		case CCS_MAX_ACCEPT_ENTRY:
		case CCS_VERBOSE:
#endif
			continue;
		}
#endif
		if (!ccs_profile_entry_used[type])
			continue;
		if (!type) { /* Print profile' comment tag. */
			if (!ccs_io_printf(head, "%u-COMMENT=%s\n",
					   index, ccs_profile->comment ?
					   ccs_profile->comment->name : ""))
				break;
			continue;
		}
		type--;
		if (type >= CCS_MAX_CONTROL_INDEX) {
#ifdef CONFIG_TOMOYO
			const int i = type - CCS_MAX_CONTROL_INDEX;
			const u8 value = ccs_profile->capability_value[i];
			if (!ccs_io_printf(head,
					   "%u-" KEYWORD_MAC_FOR_CAPABILITY
					   "%s=%s\n", index,
					   ccs_capability_control_keyword[i],
					   ccs_mode_4[value]))
				break;
#endif
		} else {
			const unsigned int value = ccs_profile->value[type];
			const char **modes = NULL;
			const char *keyword = ccs_control_array[type].keyword;
			switch (ccs_control_array[type].max_value) {
			case 3:
				modes = ccs_mode_4;
				break;
			case 1:
				modes = ccs_mode_2;
				break;
			}
			if (modes) {
				if (!ccs_io_printf(head, "%u-%s=%s\n", index,
						   keyword, modes[value]))
					break;
			} else {
				if (!ccs_io_printf(head, "%u-%s=%u\n", index,
						   keyword, value))
					break;
			}
		}
	}
	if (step == MAX_PROFILES * ccs_total)
		head->read_eof = true;
	return 0;
}

/* Structure for policy manager. */
struct ccs_policy_manager_entry {
	struct list1_head list;
	/* A path to program or a domainname. */
	const struct ccs_path_info *manager;
	bool is_domain;  /* True if manager is a domainname. */
	bool is_deleted; /* True if this entry is deleted. */
};

/* The list for "struct ccs_policy_manager_entry". */
static LIST1_HEAD(ccs_policy_manager_list);

/**
 * ccs_update_manager_entry - Add a manager entry.
 *
 * @manager:   The path to manager or the domainnamme.
 * @is_delete: True if it is a delete request.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_update_manager_entry(const char *manager, const bool is_delete)
{
	struct ccs_policy_manager_entry *new_entry;
	struct ccs_policy_manager_entry *ptr;
	static DEFINE_MUTEX(lock);
	const struct ccs_path_info *saved_manager;
	int error = -ENOMEM;
	bool is_domain = false;
	if (ccs_is_domain_def(manager)) {
		if (!ccs_is_correct_domain(manager, __func__))
			return -EINVAL;
		is_domain = true;
	} else {
		if (!ccs_is_correct_path(manager, 1, -1, -1, __func__))
			return -EINVAL;
	}
	saved_manager = ccs_save_name(manager);
	if (!saved_manager)
		return -ENOMEM;
	mutex_lock(&lock);
	list1_for_each_entry(ptr, &ccs_policy_manager_list, list) {
		if (ptr->manager != saved_manager)
			continue;
		ptr->is_deleted = is_delete;
		error = 0;
		goto out;
	}
	if (is_delete) {
		error = -ENOENT;
		goto out;
	}
	new_entry = ccs_alloc_element(sizeof(*new_entry));
	if (!new_entry)
		goto out;
	new_entry->manager = saved_manager;
	new_entry->is_domain = is_domain;
	list1_add_tail_mb(&new_entry->list, &ccs_policy_manager_list);
	error = 0;
 out:
	mutex_unlock(&lock);
	if (!error)
		ccs_update_counter(CCS_UPDATES_COUNTER_MANAGER);
	return error;
}

/**
 * ccs_write_manager_policy - Write manager policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_manager_policy(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	bool is_delete = ccs_str_starts(&data, KEYWORD_DELETE);
	if (!strcmp(data, "manage_by_non_root")) {
		ccs_manage_by_non_root = !is_delete;
		return 0;
	}
	return ccs_update_manager_entry(data, is_delete);
}

/**
 * ccs_read_manager_policy - Read manager policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
static int ccs_read_manager_policy(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	if (head->read_eof)
		return 0;
	list1_for_each_cookie(pos, head->read_var2, &ccs_policy_manager_list) {
		struct ccs_policy_manager_entry *ptr;
		ptr = list1_entry(pos, struct ccs_policy_manager_entry, list);
		if (ptr->is_deleted)
			continue;
		if (!ccs_io_printf(head, "%s\n", ptr->manager->name))
			return 0;
	}
	head->read_eof = true;
	return 0;
}

/**
 * ccs_is_policy_manager - Check whether the current process is a policy manager.
 *
 * Returns true if the current process is permitted to modify policy
 * via /proc/ccs/ interface.
 */
static bool ccs_is_policy_manager(void)
{
	struct ccs_policy_manager_entry *ptr;
	const char *exe;
	struct task_struct *task = current;
	const struct ccs_path_info *domainname
		= ccs_current_domain()->domainname;
	bool found = false;
	if (!ccs_policy_loaded)
		return true;
	if (task->ccs_flags & CCS_TASK_IS_POLICY_MANAGER)
		return true;
	if (!ccs_manage_by_non_root && (current_uid() || current_euid()))
		return false;
	list1_for_each_entry(ptr, &ccs_policy_manager_list, list) {
		if (!ptr->is_deleted && ptr->is_domain
		    && !ccs_pathcmp(domainname, ptr->manager)) {
			/* Set manager flag. */
			task->ccs_flags |= CCS_TASK_IS_POLICY_MANAGER;
			return true;
		}
	}
	exe = ccs_get_exe();
	if (!exe)
		return false;
	list1_for_each_entry(ptr, &ccs_policy_manager_list, list) {
		if (!ptr->is_deleted && !ptr->is_domain
		    && !strcmp(exe, ptr->manager->name)) {
			found = true;
			/* Set manager flag. */
			task->ccs_flags |= CCS_TASK_IS_POLICY_MANAGER;
			break;
		}
	}
	if (!found) { /* Reduce error messages. */
		static pid_t ccs_last_pid;
		const pid_t pid = current->pid;
		if (ccs_last_pid != pid) {
			printk(KERN_WARNING "%s ( %s ) is not permitted to "
			       "update policies.\n", domainname->name, exe);
			ccs_last_pid = pid;
		}
	}
	ccs_free(exe);
	return found;
}

#ifdef CONFIG_TOMOYO

/**
 * ccs_find_condition_part - Find condition part from the statement.
 *
 * @data: String to parse.
 *
 * Returns pointer to the condition part if it was found in the statement,
 * NULL otherwise.
 */
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
		*cp++ = '\0';
	} else {
		cp = strstr(data, " ; set ");
		if (cp)
			*cp++ = '\0';
	}
	return cp;
}

/**
 * ccs_is_select_one - Parse select command.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @data: String to parse.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_is_select_one(struct ccs_io_buffer *head, const char *data)
{
	unsigned int pid;
	struct ccs_domain_info *domain = NULL;
	if (!strcmp(data, "allow_execute")) {
		head->read_execute_only = true;
		return true;
	}
	if (sscanf(data, "pid=%u", &pid) == 1) {
		struct task_struct *p;
		/***** CRITICAL SECTION START *****/
		ccs_tasklist_lock();
		p = find_task_by_pid(pid);
		if (p)
			domain = ccs_task_domain(p);
		ccs_tasklist_unlock();
		/***** CRITICAL SECTION END *****/
	} else if (!strncmp(data, "domain=", 7)) {
		if (ccs_is_domain_def(data + 7))
			domain = ccs_find_domain(data + 7);
	} else
		return false;
	head->write_var1 = domain;
	/* Accessing read_buf is safe because head->io_sem is held. */
	if (!head->read_buf)
		return true; /* Do nothing if open(O_WRONLY). */
	head->read_avail = 0;
	ccs_io_printf(head, "# select %s\n", data);
	head->read_single_domain = true;
	head->read_eof = !domain;
	if (domain) {
		struct ccs_domain_info *d;
		head->read_var1 = NULL;
		list1_for_each_entry(d, &ccs_domain_list, list) {
			if (d == domain)
				break;
			head->read_var1 = &d->list;
		}
		head->read_var2 = NULL;
		head->read_bit = 0;
		head->read_step = 0;
		if (domain->is_deleted)
			ccs_io_printf(head, "# This is a deleted domain.\n");
	}
	return true;
}

/**
 * ccs_write_domain_policy - Write domain policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_domain_policy(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	struct ccs_domain_info *domain = head->write_var1;
	bool is_delete = false;
	bool is_select = false;
	unsigned int profile;
	const struct ccs_condition_list *cond = NULL;
	char *cp;
	if (ccs_str_starts(&data, KEYWORD_DELETE))
		is_delete = true;
	else if (ccs_str_starts(&data, KEYWORD_SELECT))
		is_select = true;
	if (is_select && ccs_is_select_one(head, data))
		return 0;
	/* Don't allow updating policies by non manager programs. */
	if (!ccs_is_policy_manager())
		return -EPERM;
	if (ccs_is_domain_def(data)) {
		domain = NULL;
		if (is_delete)
			ccs_delete_domain(data);
		else if (is_select)
			domain = ccs_find_domain(data);
		else
			domain = ccs_find_or_assign_new_domain(data, 0);
		head->write_var1 = domain;
		ccs_update_counter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
		return 0;
	}
	if (!domain)
		return -EINVAL;

	if (sscanf(data, KEYWORD_USE_PROFILE "%u", &profile) == 1
	    && profile < MAX_PROFILES) {
		if (ccs_profile_ptr[profile] || !ccs_policy_loaded)
			domain->profile = (u8) profile;
		return 0;
	}
	if (!strcmp(data, KEYWORD_IGNORE_GLOBAL_ALLOW_READ)) {
		ccs_set_domain_flag(domain, is_delete,
				    DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_READ);
		return 0;
	}
	if (!strcmp(data, KEYWORD_IGNORE_GLOBAL_ALLOW_ENV)) {
		ccs_set_domain_flag(domain, is_delete,
				    DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_ENV);
		return 0;
	}
	cp = ccs_find_condition_part(data);
	if (cp) {
		cond = ccs_find_or_assign_new_condition(cp);
		if (!cond)
			return -EINVAL;
	}
	if (ccs_str_starts(&data, KEYWORD_ALLOW_CAPABILITY))
		return ccs_write_capability_policy(data, domain, cond,
						   is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_NETWORK))
		return ccs_write_network_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_SIGNAL))
		return ccs_write_signal_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_ARGV0))
		return ccs_write_argv0_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_ENV))
		return ccs_write_env_policy(data, domain, cond, is_delete);
	else if (ccs_str_starts(&data, KEYWORD_ALLOW_IOCTL))
		return ccs_write_ioctl_policy(data, domain, cond, is_delete);
	else
		return ccs_write_file_policy(data, domain, cond, is_delete);
}

/**
 * ccs_print_single_path_acl - Print a single path ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_single_path_acl_record".
 * @cond: Pointer to "struct ccs_condition_list". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_single_path_acl(struct ccs_io_buffer *head,
				      struct ccs_single_path_acl_record *ptr,
				      const struct ccs_condition_list *cond)
{
	int pos;
	u8 bit;
	const char *atmark = "";
	const char *filename;
	const u16 perm = ptr->perm;
	if (ptr->u_is_group) {
		atmark = "@";
		filename = ptr->u.group->group_name->name;
	} else {
		filename = ptr->u.filename->name;
	}
	for (bit = head->read_bit; bit < MAX_SINGLE_PATH_OPERATION; bit++) {
		const char *msg;
		if (!(perm & (1 << bit)))
			continue;
		if (head->read_execute_only && bit != TYPE_EXECUTE_ACL)
			continue;
		/* Print "read/write" instead of "read" and "write". */
		if ((bit == TYPE_READ_ACL || bit == TYPE_WRITE_ACL)
		    && (perm & (1 << TYPE_READ_WRITE_ACL)))
			continue;
		msg = ccs_sp2keyword(bit);
		pos = head->read_avail;
		if (!ccs_io_printf(head, "allow_%s %s%s", msg,
				   atmark, filename) ||
		    !ccs_print_condition(head, cond))
			goto out;
	}
	head->read_bit = 0;
	return true;
 out:
	head->read_bit = bit;
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_double_path_acl - Print a double path ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_double_path_acl_record".
 * @cond: Pointer to "struct ccs_condition_list". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_double_path_acl(struct ccs_io_buffer *head,
				      struct ccs_double_path_acl_record *ptr,
				      const struct ccs_condition_list *cond)
{
	int pos;
	const char *atmark1 = "";
	const char *atmark2 = "";
	const char *filename1;
	const char *filename2;
	const u8 perm = ptr->perm;
	u8 bit;
	if (ptr->u1_is_group) {
		atmark1 = "@";
		filename1 = ptr->u1.group1->group_name->name;
	} else {
		filename1 = ptr->u1.filename1->name;
	}
	if (ptr->u2_is_group) {
		atmark2 = "@";
		filename2 = ptr->u2.group2->group_name->name;
	} else {
		filename2 = ptr->u2.filename2->name;
	}
	for (bit = head->read_bit; bit < MAX_DOUBLE_PATH_OPERATION; bit++) {
		const char *msg;
		if (!(perm & (1 << bit)))
			continue;
		msg = ccs_dp2keyword(bit);
		pos = head->read_avail;
		if (!ccs_io_printf(head, "allow_%s %s%s %s%s", msg,
				   atmark1, filename1, atmark2, filename2) ||
		    !ccs_print_condition(head, cond))
			goto out;
	}
	head->read_bit = 0;
	return true;
 out:
	head->read_bit = bit;
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_ioctl_acl - Print an ioctl ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_ioctl_acl_record".
 * @cond: Pointer to "struct ccs_condition_list". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_ioctl_acl(struct ccs_io_buffer *head,
				struct ccs_ioctl_acl_record *ptr,
				const struct ccs_condition_list *cond)
{
	int pos = head->read_avail;
	const char *atmark = "";
	const char *filename;
	const unsigned int cmd_min = ptr->cmd_min;
	const unsigned int cmd_max = ptr->cmd_max;
	if (ptr->u_is_group) {
		atmark = "@";
		filename = ptr->u.group->group_name->name;
	} else {
		filename = ptr->u.filename->name;
	}
	if (!ccs_io_printf(head, KEYWORD_ALLOW_IOCTL "%s%s ", atmark, filename))
		goto out;
	if (!ccs_io_printf(head, "%u", cmd_min))
		goto out;
	if (cmd_min != cmd_max && !ccs_io_printf(head, "-%u", cmd_max))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_argv0_acl - Print an argv[0] ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_argv0_acl_record".
 * @cond: Pointer to "struct ccs_condition_list". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_argv0_acl(struct ccs_io_buffer *head,
				struct ccs_argv0_acl_record *ptr,
				const struct ccs_condition_list *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_ARGV0 "%s %s",
			   ptr->filename->name, ptr->argv0->name))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_env_acl - Print an evironment variable name's ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_env_acl_record".
 * @cond: Pointer to "struct ccs_condition_list". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_env_acl(struct ccs_io_buffer *head,
			      struct ccs_env_acl_record *ptr,
			      const struct ccs_condition_list *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_ENV "%s", ptr->env->name))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_capability_acl - Print a capability ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_capability_acl_record".
 * @cond: Pointer to "struct ccs_condition_list". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_capability_acl(struct ccs_io_buffer *head,
				     struct ccs_capability_acl_record *ptr,
				     const struct ccs_condition_list *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_CAPABILITY "%s",
			   ccs_cap2keyword(ptr->operation)))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_ipv4_entry - Print IPv4 address of a network ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_ip_network_acl_record".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_ipv4_entry(struct ccs_io_buffer *head,
				 struct ccs_ip_network_acl_record *ptr)
{
	const u32 min_address = ptr->u.ipv4.min;
	const u32 max_address = ptr->u.ipv4.max;
	if (!ccs_io_printf(head, "%u.%u.%u.%u", HIPQUAD(min_address)))
		return false;
	if (min_address != max_address
	    && !ccs_io_printf(head, "-%u.%u.%u.%u", HIPQUAD(max_address)))
		return false;
	return true;
}

/**
 * ccs_print_ipv6_entry - Print IPv6 address of a network ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_ip_network_acl_record".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_ipv6_entry(struct ccs_io_buffer *head,
				 struct ccs_ip_network_acl_record *ptr)
{
	char buf[64];
	const struct in6_addr *min_address = ptr->u.ipv6.min;
	const struct in6_addr *max_address = ptr->u.ipv6.max;
	ccs_print_ipv6(buf, sizeof(buf), min_address);
	if (!ccs_io_printf(head, "%s", buf))
		return false;
	if (min_address != max_address) {
		ccs_print_ipv6(buf, sizeof(buf), max_address);
		if (!ccs_io_printf(head, "-%s", buf))
			return false;
	}
	return true;
}

/**
 * ccs_print_port_entry - Print port number of a network ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_ip_network_acl_record".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_port_entry(struct ccs_io_buffer *head,
				 struct ccs_ip_network_acl_record *ptr)
{
	const u16 min_port = ptr->min_port;
	const u16 max_port = ptr->max_port;
	if (!ccs_io_printf(head, " %u", min_port))
		return false;
	if (min_port != max_port && !ccs_io_printf(head, "-%u", max_port))
		return false;
	return true;
}

/**
 * ccs_print_network_acl - Print a network ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct ccs_ip_network_acl_record".
 * @cond: Pointer to "struct ccs_condition_list". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_network_acl(struct ccs_io_buffer *head,
				  struct ccs_ip_network_acl_record *ptr,
				  const struct ccs_condition_list *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_NETWORK "%s ",
			   ccs_net2keyword(ptr->operation_type)))
		goto out;
	switch (ptr->record_type) {
	case IP_RECORD_TYPE_ADDRESS_GROUP:
		if (!ccs_io_printf(head, "@%s", ptr->u.group->group_name->name))
			goto out;
		break;
	case IP_RECORD_TYPE_IPv4:
		if (!ccs_print_ipv4_entry(head, ptr))
			goto out;
		break;
	case IP_RECORD_TYPE_IPv6:
		if (!ccs_print_ipv6_entry(head, ptr))
			goto out;
		break;
	}
	if (!ccs_print_port_entry(head, ptr))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_signal_acl - Print a signal ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to "struct signale_acl_record".
 * @cond: Pointer to "struct ccs_condition_list". May be NULL.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_signal_acl(struct ccs_io_buffer *head,
				 struct ccs_signal_acl_record *ptr,
				 const struct ccs_condition_list *cond)
{
	int pos = head->read_avail;
	if (!ccs_io_printf(head, KEYWORD_ALLOW_SIGNAL "%u %s",
			   ptr->sig, ptr->domainname->name))
		goto out;
	if (!ccs_print_condition(head, cond))
		goto out;
	return true;
 out:
	head->read_avail = pos;
	return false;
}

/**
 * ccs_print_execute_handler_record - Print an execute handler ACL entry.
 *
 * @head:    Pointer to "struct ccs_io_buffer".
 * @keyword: Name of the keyword.
 * @ptr:     Pointer to "struct ccs_execute_handler_record".
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_execute_handler_record(struct ccs_io_buffer *head,
					     const char *keyword,
					     struct ccs_execute_handler_record *
					     ptr)
{
	return ccs_io_printf(head, "%s %s\n", keyword, ptr->handler->name);
}

/**
 * ccs_print_entry - Print an ACL entry.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 * @ptr:  Pointer to an ACL entry.
 *
 * Returns true on success, false otherwise.
 */
static bool ccs_print_entry(struct ccs_io_buffer *head,
			    struct ccs_acl_info *ptr)
{
	const struct ccs_condition_list *cond = ccs_get_condition_part(ptr);
	const u8 acl_type = ccs_acl_type2(ptr);
	if (acl_type & ACL_DELETED)
		return true;
	if (acl_type == TYPE_SINGLE_PATH_ACL) {
		struct ccs_single_path_acl_record *acl
			= container_of(ptr, struct ccs_single_path_acl_record,
				       head);
		return ccs_print_single_path_acl(head, acl, cond);
	}
	if (acl_type == TYPE_EXECUTE_HANDLER) {
		struct ccs_execute_handler_record *acl
			= container_of(ptr, struct ccs_execute_handler_record,
				       head);
		const char *keyword = KEYWORD_EXECUTE_HANDLER;
		return ccs_print_execute_handler_record(head, keyword, acl);
	}
	if (acl_type == TYPE_DENIED_EXECUTE_HANDLER) {
		struct ccs_execute_handler_record *acl
			= container_of(ptr, struct ccs_execute_handler_record,
				       head);
		const char *keyword = KEYWORD_DENIED_EXECUTE_HANDLER;
		return ccs_print_execute_handler_record(head, keyword, acl);
	}
	if (head->read_execute_only)
		return true;
	if (acl_type == TYPE_DOUBLE_PATH_ACL) {
		struct ccs_double_path_acl_record *acl
			= container_of(ptr, struct ccs_double_path_acl_record,
				       head);
		return ccs_print_double_path_acl(head, acl, cond);
	}
	if (acl_type == TYPE_IOCTL_ACL) {
		struct ccs_ioctl_acl_record *acl
			= container_of(ptr, struct ccs_ioctl_acl_record, head);
		return ccs_print_ioctl_acl(head, acl, cond);
	}
	if (acl_type == TYPE_ARGV0_ACL) {
		struct ccs_argv0_acl_record *acl
			= container_of(ptr, struct ccs_argv0_acl_record, head);
		return ccs_print_argv0_acl(head, acl, cond);
	}
	if (acl_type == TYPE_ENV_ACL) {
		struct ccs_env_acl_record *acl
			= container_of(ptr, struct ccs_env_acl_record, head);
		return ccs_print_env_acl(head, acl, cond);
	}
	if (acl_type == TYPE_CAPABILITY_ACL) {
		struct ccs_capability_acl_record *acl
			= container_of(ptr, struct ccs_capability_acl_record,
				       head);
		return ccs_print_capability_acl(head, acl, cond);
	}
	if (acl_type == TYPE_IP_NETWORK_ACL) {
		struct ccs_ip_network_acl_record *acl
			= container_of(ptr, struct ccs_ip_network_acl_record,
				       head);
		return ccs_print_network_acl(head, acl, cond);
	}
	if (acl_type == TYPE_SIGNAL_ACL) {
		struct ccs_signal_acl_record *acl
			= container_of(ptr, struct ccs_signal_acl_record, head);
		return ccs_print_signal_acl(head, acl, cond);
	}
	/* Workaround for gcc 3.2.2's inline bug. */
	if (acl_type & ACL_DELETED)
		return true;
	BUG(); /* This must not happen. */
	return false;
}

/**
 * ccs_read_domain_policy - Read domain policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
static int ccs_read_domain_policy(struct ccs_io_buffer *head)
{
	struct list1_head *dpos;
	struct list1_head *apos;
	if (head->read_eof)
		return 0;
	if (head->read_step == 0)
		head->read_step = 1;
	list1_for_each_cookie(dpos, head->read_var1, &ccs_domain_list) {
		struct ccs_domain_info *domain;
		const char *quota_exceeded = "";
		const char *transition_failed = "";
		const char *ignore_global_allow_read = "";
		const char *ignore_global_allow_env = "";
		domain = list1_entry(dpos, struct ccs_domain_info, list);
		if (head->read_step != 1)
			goto acl_loop;
		if (domain->is_deleted && !head->read_single_domain)
			continue;
		/* Print domainname and flags. */
		if (domain->quota_warned)
			quota_exceeded = "quota_exceeded\n";
		if (domain->flags & DOMAIN_FLAGS_TRANSITION_FAILED)
			transition_failed = "transition_failed\n";
		if (domain->flags & DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_READ)
			ignore_global_allow_read
				= KEYWORD_IGNORE_GLOBAL_ALLOW_READ "\n";
		if (domain->flags & DOMAIN_FLAGS_IGNORE_GLOBAL_ALLOW_ENV)
			ignore_global_allow_env
				= KEYWORD_IGNORE_GLOBAL_ALLOW_ENV "\n";
		if (!ccs_io_printf(head, "%s\n" KEYWORD_USE_PROFILE "%u\n"
				   "%s%s%s%s\n", domain->domainname->name,
				   domain->profile, quota_exceeded,
				   transition_failed,
				   ignore_global_allow_read,
				   ignore_global_allow_env))
			return 0;
		head->read_step = 2;
 acl_loop:
		if (head->read_step == 3)
			goto tail_mark;
		/* Print ACL entries in the domain. */
		list1_for_each_cookie(apos, head->read_var2,
				      &domain->acl_info_list) {
			struct ccs_acl_info *ptr
				= list1_entry(apos, struct ccs_acl_info, list);
			if (!ccs_print_entry(head, ptr))
				return 0;
		}
		head->read_step = 3;
 tail_mark:
		if (!ccs_io_printf(head, "\n"))
			return 0;
		head->read_step = 1;
		if (head->read_single_domain)
			break;
	}
	head->read_eof = true;
	return 0;
}

#endif

/**
 * ccs_write_domain_profile - Assign profile for specified domain.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, -EINVAL otherwise.
 *
 * This is equivalent to doing
 *
 *     ( echo "select " $domainname; echo "use_profile " $profile ) |
 *     /usr/lib/ccs/loadpolicy -d
 */
static int ccs_write_domain_profile(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	char *cp = strchr(data, ' ');
	struct ccs_domain_info *domain;
	unsigned int profile;
	if (!cp)
		return -EINVAL;
	*cp = '\0';
	domain = ccs_find_domain(cp + 1);
	profile = simple_strtoul(data, NULL, 10);
	if (domain && profile < MAX_PROFILES
	    && (ccs_profile_ptr[profile] || !ccs_policy_loaded))
		domain->profile = (u8) profile;
	ccs_update_counter(CCS_UPDATES_COUNTER_DOMAIN_POLICY);
	return 0;
}

/**
 * ccs_read_domain_profile - Read only domainname and profile.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns list of profile number and domainname pairs.
 *
 * This is equivalent to doing
 *
 *     grep -A 1 '^<kernel>' /proc/ccs/domain_policy |
 *     awk ' { if ( domainname == "" ) { if ( $1 == "<kernel>" )
 *     domainname = $0; } else if ( $1 == "use_profile" ) {
 *     print $2 " " domainname; domainname = ""; } } ; '
 */
static int ccs_read_domain_profile(struct ccs_io_buffer *head)
{
	struct list1_head *pos;
	if (head->read_eof)
		return 0;
	list1_for_each_cookie(pos, head->read_var1, &ccs_domain_list) {
		struct ccs_domain_info *domain;
		domain = list1_entry(pos, struct ccs_domain_info, list);
		if (domain->is_deleted)
			continue;
		if (!ccs_io_printf(head, "%u %s\n", domain->profile,
				   domain->domainname->name))
			return 0;
	}
	head->read_eof = true;
	return 0;
}

/**
 * ccs_write_pid: Specify PID to obtain domainname.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
static int ccs_write_pid(struct ccs_io_buffer *head)
{
	head->read_eof = false;
	return 0;
}

/**
 * ccs_read_pid - Read information of a process.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns the domainname which the specified PID is in or
 * process information of the specified PID on success,
 * empty string otherwise.
 */
static int ccs_read_pid(struct ccs_io_buffer *head)
{
	char *buf = head->write_buf;
	bool task_info = false;
	unsigned int pid;
	struct task_struct *p;
	struct ccs_domain_info *domain = NULL;
	u32 ccs_flags = 0;
	/* Accessing write_buf is safe because head->io_sem is held. */
	if (!buf)
		goto done; /* Do nothing if open(O_RDONLY). */
	if (head->read_avail || head->read_eof)
		goto done;
	head->read_eof = true;
	if (ccs_str_starts(&buf, "info "))
		task_info = true;
	pid = (unsigned int) simple_strtoul(buf, NULL, 10);
	/***** CRITICAL SECTION START *****/
	ccs_tasklist_lock();
	p = find_task_by_pid(pid);
	if (p) {
		domain = ccs_task_domain(p);
		ccs_flags = p->ccs_flags;
	}
	ccs_tasklist_unlock();
	/***** CRITICAL SECTION END *****/
	if (!domain)
		goto done;
	if (!task_info)
		ccs_io_printf(head, "%u %u %s", pid, domain->profile,
			      domain->domainname->name);
	else
		ccs_io_printf(head, "%u manager=%s execute_handler=%s "
			      "state[0]=%u state[1]=%u state[2]=%u", pid,
			      ccs_flags & CCS_TASK_IS_POLICY_MANAGER ?
			      "yes" : "no",
			      ccs_flags & CCS_TASK_IS_EXECUTE_HANDLER ?
			      "yes" : "no",
			      (u8) (ccs_flags >> 24),
			      (u8) (ccs_flags >> 16),
			      (u8) (ccs_flags >> 8));
 done:
	return 0;
}

#ifdef CONFIG_TOMOYO

/**
 * ccs_write_exception_policy - Write exception policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_exception_policy(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	bool is_delete = ccs_str_starts(&data, KEYWORD_DELETE);
	if (ccs_str_starts(&data, KEYWORD_KEEP_DOMAIN))
		return ccs_write_domain_keeper_policy(data, false, is_delete);
	if (ccs_str_starts(&data, KEYWORD_NO_KEEP_DOMAIN))
		return ccs_write_domain_keeper_policy(data, true, is_delete);
	if (ccs_str_starts(&data, KEYWORD_INITIALIZE_DOMAIN))
		return ccs_write_domain_initializer_policy(data, false,
							   is_delete);
	if (ccs_str_starts(&data, KEYWORD_NO_INITIALIZE_DOMAIN))
		return ccs_write_domain_initializer_policy(data, true,
							   is_delete);
	if (ccs_str_starts(&data, KEYWORD_ALIAS))
		return ccs_write_alias_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_AGGREGATOR))
		return ccs_write_aggregator_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_ALLOW_READ))
		return ccs_write_globally_readable_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_ALLOW_ENV))
		return ccs_write_globally_usable_env_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_FILE_PATTERN))
		return ccs_write_pattern_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_PATH_GROUP))
		return ccs_write_path_group_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_DENY_REWRITE))
		return ccs_write_no_rewrite_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_ADDRESS_GROUP))
		return ccs_write_address_group_policy(data, is_delete);
	return -EINVAL;
}

/**
 * ccs_read_exception_policy - Read exception policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int ccs_read_exception_policy(struct ccs_io_buffer *head)
{
	if (!head->read_eof) {
		switch (head->read_step) {
		case 0:
			head->read_var2 = NULL;
			head->read_step = 1;
		case 1:
			if (!ccs_read_domain_keeper_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 2;
		case 2:
			if (!ccs_read_globally_readable_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 3;
		case 3:
			if (!ccs_read_globally_usable_env_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 4;
		case 4:
			if (!ccs_read_domain_initializer_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 5;
		case 5:
			if (!ccs_read_alias_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 6;
		case 6:
			if (!ccs_read_aggregator_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 7;
		case 7:
			if (!ccs_read_file_pattern(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 8;
		case 8:
			if (!ccs_read_no_rewrite_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 9;
		case 9:
			if (!ccs_read_path_group_policy(head))
				break;
			head->read_var1 = NULL;
			head->read_var2 = NULL;
			head->read_step = 10;
		case 10:
			if (!ccs_read_address_group_policy(head))
				break;
			head->read_eof = true;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

#endif

#ifdef CONFIG_SAKURA

/**
 * ccs_write_system_policy - Write system policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_write_system_policy(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	bool is_delete = false;
	if (ccs_str_starts(&data, KEYWORD_DELETE))
		is_delete = true;
	if (ccs_str_starts(&data, KEYWORD_ALLOW_MOUNT))
		return ccs_write_mount_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_DENY_UNMOUNT))
		return ccs_write_no_umount_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_ALLOW_CHROOT))
		return ccs_write_chroot_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_ALLOW_PIVOT_ROOT))
		return ccs_write_pivot_root_policy(data, is_delete);
	if (ccs_str_starts(&data, KEYWORD_DENY_AUTOBIND))
		return ccs_write_reserved_port_policy(data, is_delete);
	return -EINVAL;
}

/**
 * ccs_read_system_policy - Read system policy.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int ccs_read_system_policy(struct ccs_io_buffer *head)
{
	if (!head->read_eof) {
		switch (head->read_step) {
		case 0:
			head->read_var2 = NULL;
			head->read_step = 1;
		case 1:
			if (!ccs_read_mount_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 2;
		case 2:
			if (!ccs_read_no_umount_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 3;
		case 3:
			if (!ccs_read_chroot_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 4;
		case 4:
			if (!ccs_read_pivot_root_policy(head))
				break;
			head->read_var2 = NULL;
			head->read_step = 5;
		case 5:
			if (!ccs_read_reserved_port_policy(head))
				break;
			head->read_eof = true;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

#endif

/* Path to the policy loader. The default is /sbin/ccs-init. */
static const char *ccs_loader;

/**
 * ccs_loader_setup - Specify the policy loader to use.
 *
 * @str: Path to the policy loader.
 *
 * Returns 0.
 */
static int __init ccs_loader_setup(char *str)
{
	ccs_loader = str;
	return 0;
}

__setup("CCS_loader=", ccs_loader_setup);

/**
 * ccs_policy_loader_exists - Check whether /sbin/ccs-init exists.
 *
 * Returns true if /sbin/ccs-init exists, false otherwise.
 */
static bool ccs_policy_loader_exists(void)
{
	/*
	 * Don't activate MAC if the path given by 'CCS_loader=' option doesn't
	 * exist. If the initrd includes /sbin/init but real-root-dev has not
	 * mounted on / yet, activating MAC will block the system since
	 * policies are not loaded yet.
	 * Thus, let do_execve() call this function every time.
	 */
	struct nameidata nd;
	if (!ccs_loader)
		ccs_loader = "/sbin/ccs-init";
	if (path_lookup(ccs_loader, ccs_lookup_flags, &nd)) {
		printk(KERN_INFO "Not activating Mandatory Access Control now "
		       "since %s doesn't exist.\n", ccs_loader);
		return false;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
	path_put(&nd.path);
#else
	path_release(&nd);
#endif
	return true;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
/**
 * ccs_run_loader - Start /sbin/ccs-init .
 *
 * @unused: Not used.
 *
 * Returns PID of /sbin/ccs-init on success, negative value otherwise.
 */
static int ccs_run_loader(void *unused)
{
	char *argv[2];
	char *envp[3];
	printk(KERN_INFO "Calling %s to load policy. Please wait.\n",
	       ccs_loader);
	argv[0] = (char *) ccs_loader;
	argv[1] = NULL;
	envp[0] = "HOME=/";
	envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	envp[2] = NULL;
	return exec_usermodehelper(argv[0], argv, envp);
}
#endif

/**
 * ccs_load_policy - Run external policy loader to load policy.
 *
 * @filename: The program about to start.
 *
 * This function checks whether @filename is /sbin/init , and if so
 * invoke /sbin/ccs-init and wait for the termination of /sbin/ccs-init
 * and then continues invocation of /sbin/init.
 * /sbin/ccs-init reads policy files in /etc/ccs/ directory and
 * writes to /proc/ccs/ interfaces.
 *
 * Returns nothing.
 */
void ccs_load_policy(const char *filename)
{
	if (ccs_policy_loaded)
		return;
	/*
	 * Check filename is /sbin/init or /sbin/ccs-start.
	 * /sbin/ccs-start is a dummy filename in case where /sbin/init can't
	 * be passed.
	 * You can create /sbin/ccs-start by "ln -s /bin/true /sbin/ccs-start".
	 */
	if (strcmp(filename, "/sbin/init") &&
	    strcmp(filename, "/sbin/ccs-start"))
		return;
	if (!ccs_policy_loader_exists())
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	{
		char *argv[2];
		char *envp[3];
		printk(KERN_INFO "Calling %s to load policy. Please wait.\n",
		       ccs_loader);
		argv[0] = (char *) ccs_loader;
		argv[1] = NULL;
		envp[0] = "HOME=/";
		envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
		envp[2] = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)|| defined(UMH_WAIT_PROC)
		call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
#else
		call_usermodehelper(argv[0], argv, envp, 1);
#endif
	}
#elif defined(TASK_DEAD)
	{
		/* Copied from kernel/kmod.c */
		struct task_struct *task = current;
		pid_t pid = kernel_thread(ccs_run_loader, NULL, 0);
		sigset_t tmpsig;
		spin_lock_irq(&task->sighand->siglock);
		tmpsig = task->blocked;
		siginitsetinv(&task->blocked,
			      sigmask(SIGKILL) | sigmask(SIGSTOP));
		recalc_sigpending();
		spin_unlock_irq(&current->sighand->siglock);
		if (pid >= 0)
			waitpid(pid, NULL, __WCLONE);
		spin_lock_irq(&task->sighand->siglock);
		task->blocked = tmpsig;
		recalc_sigpending();
		spin_unlock_irq(&task->sighand->siglock);
	}
#else
	{
		/* Copied from kernel/kmod.c */
		struct task_struct *task = current;
		pid_t pid = kernel_thread(ccs_run_loader, NULL, 0);
		sigset_t tmpsig;
		spin_lock_irq(&task->sigmask_lock);
		tmpsig = task->blocked;
		siginitsetinv(&task->blocked,
			      sigmask(SIGKILL) | sigmask(SIGSTOP));
		recalc_sigpending(task);
		spin_unlock_irq(&task->sigmask_lock);
		if (pid >= 0)
			waitpid(pid, NULL, __WCLONE);
		spin_lock_irq(&task->sigmask_lock);
		task->blocked = tmpsig;
		recalc_sigpending(task);
		spin_unlock_irq(&task->sigmask_lock);
	}
#endif
#ifdef CONFIG_SAKURA
	printk(KERN_INFO "SAKURA: 1.6.9+   2011/05/05\n");
#endif
#ifdef CONFIG_TOMOYO
	printk(KERN_INFO "TOMOYO: 1.6.9+   2011/05/05\n");
#endif
	printk(KERN_INFO "Mandatory Access Control activated.\n");
	ccs_policy_loaded = true;
	ccs_log_level = KERN_WARNING;
	{ /* Check all profiles currently assigned to domains are defined. */
		struct ccs_domain_info *domain;
		list1_for_each_entry(domain, &ccs_domain_list, list) {
			const u8 profile = domain->profile;
			if (ccs_profile_ptr[profile])
				continue;
			panic("Profile %u (used by '%s') not defined.\n",
			      profile, domain->domainname->name);
		}
	}
}

/* Wait queue for ccs_query_list. */
static DECLARE_WAIT_QUEUE_HEAD(ccs_query_wait);

/* Lock for manipulating ccs_query_list. */
static DEFINE_SPINLOCK(ccs_query_list_lock);

/* Structure for query. */
struct ccs_query_entry {
	struct list_head list;
	char *query;
	int query_len;
	unsigned int serial;
	int timer;
	int answer;
};

/* The list for "struct ccs_query_entry". */
static LIST_HEAD(ccs_query_list);

/* Number of "struct file" referring /proc/ccs/query interface. */
static atomic_t ccs_query_observers = ATOMIC_INIT(0);

/**
 * ccs_check_supervisor - Ask for the supervisor's decision.
 *
 * @r:       Pointer to "struct ccs_request_info".
 * @fmt:     The printf()'s format string, followed by parameters.
 *
 * Returns 0 if the supervisor decided to permit the access request which
 * violated the policy in enforcing mode, 1 if the supervisor decided to
 * retry the access request which violated the policy in enforcing mode,
 * -EPERM otherwise.
 */
int ccs_check_supervisor(struct ccs_request_info *r, const char *fmt, ...)
{
	va_list args;
	int error = -EPERM;
	int pos;
	int len;
	static unsigned int ccs_serial;
	struct ccs_query_entry *ccs_query_entry = NULL;
	char *header;
	if (!r->domain)
		r->domain = ccs_current_domain();
	if (!atomic_read(&ccs_query_observers)) {
		int i;
		if (current->ccs_flags & CCS_DONT_SLEEP_ON_ENFORCE_ERROR)
			return -EPERM;
		for (i = 0; i < ccs_check_flags(r->domain, CCS_SLEEP_PERIOD);
		     i++) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ / 10);
		}
		return -EPERM;
	}
	va_start(args, fmt);
	len = vsnprintf((char *) &pos, sizeof(pos) - 1, fmt, args) + 32;
	va_end(args);
#ifdef CONFIG_TOMOYO
	header = ccs_init_audit_log(&len, r);
#else
	header = ccs_alloc(1, true);
#endif
	if (!header)
		goto out;
	ccs_query_entry = ccs_alloc(sizeof(*ccs_query_entry), true);
	if (!ccs_query_entry)
		goto out;
	ccs_query_entry->query = ccs_alloc(len, true);
	if (!ccs_query_entry->query)
		goto out;
	INIT_LIST_HEAD(&ccs_query_entry->list);
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	ccs_query_entry->serial = ccs_serial++;
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	pos = snprintf(ccs_query_entry->query, len - 1, "Q%u-%hu\n%s",
		       ccs_query_entry->serial, r->retry, header);
	ccs_free(header);
	header = NULL;
	va_start(args, fmt);
	vsnprintf(ccs_query_entry->query + pos, len - 1 - pos, fmt, args);
	ccs_query_entry->query_len = strlen(ccs_query_entry->query) + 1;
	va_end(args);
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_add_tail(&ccs_query_entry->list, &ccs_query_list);
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	ccs_update_counter(CCS_UPDATES_COUNTER_QUERY);
	/* Give 10 seconds for supervisor's opinion. */
	for (ccs_query_entry->timer = 0;
	     atomic_read(&ccs_query_observers) && ccs_query_entry->timer < 100;
	     ccs_query_entry->timer++) {
		wake_up(&ccs_query_wait);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ / 10);
		if (ccs_query_entry->answer)
			break;
	}
	ccs_update_counter(CCS_UPDATES_COUNTER_QUERY);
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_del(&ccs_query_entry->list);
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	switch (ccs_query_entry->answer) {
	case 3: /* Asked to retry by administrator. */
		error = 1;
		r->retry++;
		break;
	case 1:
		/* Granted by administrator. */
		error = 0;
		break;
	case 0:
		/* Timed out. */
		break;
	default:
		/* Rejected by administrator. */
		break;
	}
 out:
	if (ccs_query_entry)
		ccs_free(ccs_query_entry->query);
	ccs_free(ccs_query_entry);
	ccs_free(header);
	return error;
}

/**
 * ccs_poll_query - poll() for /proc/ccs/query.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Returns POLLIN | POLLRDNORM when ready to read, 0 otherwise.
 *
 * Waits for access requests which violated policy in enforcing mode.
 */
static int ccs_poll_query(struct file *file, poll_table *wait)
{
	struct list_head *tmp;
	bool found = false;
	u8 i;
	for (i = 0; i < 2; i++) {
		/***** CRITICAL SECTION START *****/
		spin_lock(&ccs_query_list_lock);
		list_for_each(tmp, &ccs_query_list) {
			struct ccs_query_entry *ptr
				= list_entry(tmp, struct ccs_query_entry, list);
			if (ptr->answer)
				continue;
			found = true;
			break;
		}
		spin_unlock(&ccs_query_list_lock);
		/***** CRITICAL SECTION END *****/
		if (found)
			return POLLIN | POLLRDNORM;
		if (i)
			break;
		poll_wait(file, &ccs_query_wait, wait);
	}
	return 0;
}

/**
 * ccs_read_query - Read access requests which violated policy in enforcing mode.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0.
 */
static int ccs_read_query(struct ccs_io_buffer *head)
{
	struct list_head *tmp;
	int pos = 0;
	int len = 0;
	char *buf;
	if (head->read_avail)
		return 0;
	if (head->read_buf) {
		ccs_free(head->read_buf);
		head->read_buf = NULL;
		head->readbuf_size = 0;
	}
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query_entry *ptr
			= list_entry(tmp, struct ccs_query_entry, list);
		if (ptr->answer)
			continue;
		if (pos++ != head->read_step)
			continue;
		len = ptr->query_len;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	if (!len) {
		head->read_step = 0;
		return 0;
	}
	buf = ccs_alloc(len, false);
	if (!buf)
		return 0;
	pos = 0;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query_entry *ptr
			= list_entry(tmp, struct ccs_query_entry, list);
		if (ptr->answer)
			continue;
		if (pos++ != head->read_step)
			continue;
		/*
		 * Some query can be skipped because ccs_query_list
		 * can change, but I don't care.
		 */
		if (len == ptr->query_len)
			memmove(buf, ptr->query, len);
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	if (buf[0]) {
		head->read_avail = len;
		head->readbuf_size = head->read_avail;
		head->read_buf = buf;
		head->read_step++;
	} else {
		ccs_free(buf);
	}
	return 0;
}

/**
 * ccs_write_answer - Write the supervisor's decision.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int ccs_write_answer(struct ccs_io_buffer *head)
{
	char *data = head->write_buf;
	struct list_head *tmp;
	unsigned int serial;
	unsigned int answer;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query_entry *ptr
			= list_entry(tmp, struct ccs_query_entry, list);
		ptr->timer = 0;
	}
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	if (sscanf(data, "A%u=%u", &serial, &answer) != 2)
		return -EINVAL;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_query_list_lock);
	list_for_each(tmp, &ccs_query_list) {
		struct ccs_query_entry *ptr
			= list_entry(tmp, struct ccs_query_entry, list);
		if (ptr->serial != serial)
			continue;
		if (!ptr->answer)
			ptr->answer = answer;
		break;
	}
	spin_unlock(&ccs_query_list_lock);
	/***** CRITICAL SECTION END *****/
	return 0;
}

#if !defined(atomic_xchg) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)

/* Policy updates counter. */
static unsigned int ccs_updates_counter[MAX_CCS_UPDATES_COUNTER];

/* Policy updates counter lock. */
static DEFINE_SPINLOCK(ccs_updates_counter_lock);

/**
 * ccs_update_counter - Increment policy change counter.
 *
 * @index: Type of policy.
 *
 * Returns nothing.
 */
void ccs_update_counter(const unsigned char index)
{
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_updates_counter_lock);
	if (index < MAX_CCS_UPDATES_COUNTER)
		ccs_updates_counter[index]++;
	spin_unlock(&ccs_updates_counter_lock);
	/***** CRITICAL SECTION END *****/
}

/**
 * ccs_read_updates_counter - Check for policy change counter.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns how many times policy has changed since the previous check.
 */
static int ccs_read_updates_counter(struct ccs_io_buffer *head)
{
	unsigned int counter[MAX_CCS_UPDATES_COUNTER];
	if (head->read_eof)
		return 0;
	/***** CRITICAL SECTION START *****/
	spin_lock(&ccs_updates_counter_lock);
	memmove(counter, ccs_updates_counter, sizeof(ccs_updates_counter));
	memset(ccs_updates_counter, 0, sizeof(ccs_updates_counter));
	spin_unlock(&ccs_updates_counter_lock);
	/***** CRITICAL SECTION END *****/
	ccs_io_printf(head,
		      "/proc/ccs/system_policy:    %10u\n"
		      "/proc/ccs/domain_policy:    %10u\n"
		      "/proc/ccs/exception_policy: %10u\n"
		      "/proc/ccs/profile:          %10u\n"
		      "/proc/ccs/query:            %10u\n"
		      "/proc/ccs/manager:          %10u\n"
#ifdef CONFIG_TOMOYO_AUDIT
		      "/proc/ccs/grant_log:        %10u\n"
		      "/proc/ccs/reject_log:       %10u\n"
#endif
		      , counter[CCS_UPDATES_COUNTER_SYSTEM_POLICY]
		      , counter[CCS_UPDATES_COUNTER_DOMAIN_POLICY]
		      , counter[CCS_UPDATES_COUNTER_EXCEPTION_POLICY]
		      , counter[CCS_UPDATES_COUNTER_PROFILE]
		      , counter[CCS_UPDATES_COUNTER_QUERY]
		      , counter[CCS_UPDATES_COUNTER_MANAGER]
#ifdef CONFIG_TOMOYO_AUDIT
		      , counter[CCS_UPDATES_COUNTER_GRANT_LOG]
		      , counter[CCS_UPDATES_COUNTER_REJECT_LOG]
#endif
		      );
	head->read_eof = true;
	return 0;
}

#else

/* Policy updates counter. */
static atomic_t ccs_updates_counter[MAX_CCS_UPDATES_COUNTER];

/**
 * ccs_update_counter - Increment policy change counter.
 *
 * @index: Type of policy.
 *
 * Returns nothing.
 */
void ccs_update_counter(const unsigned char index)
{
	if (index < MAX_CCS_UPDATES_COUNTER)
		atomic_inc(&ccs_updates_counter[index]);
}

/**
 * ccs_read_updates_counter - Check for policy change counter.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns how many times policy has changed since the previous check.
 */
static int ccs_read_updates_counter(struct ccs_io_buffer *head)
{
	if (head->read_eof)
		return 0;
	ccs_io_printf(head,
		      "/proc/ccs/system_policy:    %10u\n"
		      "/proc/ccs/domain_policy:    %10u\n"
		      "/proc/ccs/exception_policy: %10u\n"
		      "/proc/ccs/profile:          %10u\n"
		      "/proc/ccs/query:            %10u\n"
		      "/proc/ccs/manager:          %10u\n"
#ifdef CONFIG_TOMOYO_AUDIT
		      "/proc/ccs/grant_log:        %10u\n"
		      "/proc/ccs/reject_log:       %10u\n"
#endif
		      , atomic_xchg(&ccs_updates_counter
				    [CCS_UPDATES_COUNTER_SYSTEM_POLICY], 0)
		      , atomic_xchg(&ccs_updates_counter
				    [CCS_UPDATES_COUNTER_DOMAIN_POLICY], 0)
		      , atomic_xchg(&ccs_updates_counter
				    [CCS_UPDATES_COUNTER_EXCEPTION_POLICY], 0)
		      , atomic_xchg(&ccs_updates_counter
				    [CCS_UPDATES_COUNTER_PROFILE], 0)
		      , atomic_xchg(&ccs_updates_counter
				    [CCS_UPDATES_COUNTER_QUERY], 0)
		      , atomic_xchg(&ccs_updates_counter
				    [CCS_UPDATES_COUNTER_MANAGER], 0)
#ifdef CONFIG_TOMOYO_AUDIT
		      , atomic_xchg(&ccs_updates_counter
				    [CCS_UPDATES_COUNTER_GRANT_LOG], 0)
		      , atomic_xchg(&ccs_updates_counter
				    [CCS_UPDATES_COUNTER_REJECT_LOG], 0)
#endif
		      );
	head->read_eof = true;
	return 0;
}

#endif

/**
 * ccs_read_version: Get version.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns version information.
 */
static int ccs_read_version(struct ccs_io_buffer *head)
{
	if (!head->read_eof) {
		ccs_io_printf(head, "1.6.9");
		head->read_eof = true;
	}
	return 0;
}

/**
 * ccs_read_self_domain - Get the current process's domainname.
 *
 * @head: Pointer to "struct ccs_io_buffer".
 *
 * Returns the current process's domainname.
 */
static int ccs_read_self_domain(struct ccs_io_buffer *head)
{
	if (!head->read_eof) {
		/*
		 * ccs_current_domain()->domainname != NULL
		 * because every process belongs to a domain and
		 * the domain's name cannot be NULL.
		 */
		ccs_io_printf(head, "%s",
			      ccs_current_domain()->domainname->name);
		head->read_eof = true;
	}
	return 0;
}

/**
 * ccs_open_control - open() for /proc/ccs/ interface.
 *
 * @type: Type of interface.
 * @file: Pointer to "struct file".
 *
 * Associates policy handler and returns 0 on success, -ENOMEM otherwise.
 */
int ccs_open_control(const u8 type, struct file *file)
{
	struct ccs_io_buffer *head = ccs_alloc(sizeof(*head), false);
	if (!head)
		return -ENOMEM;
	mutex_init(&head->io_sem);
	switch (type) {
#ifdef CONFIG_SAKURA
	case CCS_SYSTEMPOLICY: /* /proc/ccs/system_policy */
		head->write = ccs_write_system_policy;
		head->read = ccs_read_system_policy;
		break;
#endif
#ifdef CONFIG_TOMOYO
	case CCS_DOMAINPOLICY: /* /proc/ccs/domain_policy */
		head->write = ccs_write_domain_policy;
		head->read = ccs_read_domain_policy;
		break;
	case CCS_EXCEPTIONPOLICY: /* /proc/ccs/exception_policy */
		head->write = ccs_write_exception_policy;
		head->read = ccs_read_exception_policy;
		break;
#ifdef CONFIG_TOMOYO_AUDIT
	case CCS_GRANTLOG: /* /proc/ccs/grant_log */
		head->poll = ccs_poll_grant_log;
		head->read = ccs_read_grant_log;
		break;
	case CCS_REJECTLOG: /* /proc/ccs/reject_log */
		head->poll = ccs_poll_reject_log;
		head->read = ccs_read_reject_log;
		break;
#endif
#endif
	case CCS_SELFDOMAIN: /* /proc/ccs/self_domain */
		head->read = ccs_read_self_domain;
		break;
	case CCS_DOMAIN_STATUS: /* /proc/ccs/.domain_status */
		head->write = ccs_write_domain_profile;
		head->read = ccs_read_domain_profile;
		break;
	case CCS_EXECUTE_HANDLER: /* /proc/ccs/.execute_handler */
		/* Allow execute_handler to read process's status. */
		if (!(current->ccs_flags & CCS_TASK_IS_EXECUTE_HANDLER)) {
			ccs_free(head);
			return -EPERM;
		}
		/* fall through */
	case CCS_PROCESS_STATUS: /* /proc/ccs/.process_status */
		head->write = ccs_write_pid;
		head->read = ccs_read_pid;
		break;
	case CCS_VERSION: /* /proc/ccs/version */
		head->read = ccs_read_version;
		head->readbuf_size = 128;
		break;
	case CCS_MEMINFO: /* /proc/ccs/meminfo */
		head->write = ccs_write_memory_quota;
		head->read = ccs_read_memory_counter;
		head->readbuf_size = 512;
		break;
	case CCS_PROFILE: /* /proc/ccs/profile */
		head->write = ccs_write_profile;
		head->read = ccs_read_profile;
		break;
	case CCS_QUERY: /* /proc/ccs/query */
		head->poll = ccs_poll_query;
		head->write = ccs_write_answer;
		head->read = ccs_read_query;
		break;
	case CCS_MANAGER: /* /proc/ccs/manager */
		head->write = ccs_write_manager_policy;
		head->read = ccs_read_manager_policy;
		break;
	case CCS_UPDATESCOUNTER: /* /proc/ccs/.ccs_updates_counter */
		head->read = ccs_read_updates_counter;
		break;
	}
	if (!(file->f_mode & FMODE_READ)) {
		/*
		 * No need to allocate read_buf since it is not opened
		 * for reading.
		 */
		head->read = NULL;
		head->poll = NULL;
	} else if (type != CCS_QUERY
#ifdef CONFIG_TOMOYO_AUDIT
		   && type != CCS_GRANTLOG && type != CCS_REJECTLOG
#endif
		   ) {
		/*
		 * Don't allocate buffer for reading if the file is one of
		 * /proc/ccs/grant_log , /proc/ccs/reject_log , /proc/ccs/query.
		 */
		if (!head->readbuf_size)
			head->readbuf_size = 4096 * 2;
		head->read_buf = ccs_alloc(head->readbuf_size, false);
		if (!head->read_buf) {
			ccs_free(head);
			return -ENOMEM;
		}
	}
	if (!(file->f_mode & FMODE_WRITE)) {
		/*
		 * No need to allocate write_buf since it is not opened
		 * for writing.
		 */
		head->write = NULL;
	} else if (head->write) {
		head->writebuf_size = 4096 * 2;
		head->write_buf = ccs_alloc(head->writebuf_size, false);
		if (!head->write_buf) {
			ccs_free(head->read_buf);
			ccs_free(head);
			return -ENOMEM;
		}
	}
	file->private_data = head;
	/*
	 * Call the handler now if the file is /proc/ccs/self_domain
	 * so that the user can use "cat < /proc/ccs/self_domain" to
	 * know the current process's domainname.
	 */
	if (type == CCS_SELFDOMAIN)
		ccs_read_control(file, NULL, 0);
	/*
	 * If the file is /proc/ccs/query , increment the observer counter.
	 * The obserber counter is used by ccs_check_supervisor() to see if
	 * there is some process monitoring /proc/ccs/query.
	 */
	else if (head->write == ccs_write_answer ||
		 head->read == ccs_read_query)
		atomic_inc(&ccs_query_observers);
	return 0;
}

/**
 * ccs_poll_control - poll() for /proc/ccs/ interface.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table".
 *
 * Waits for read readiness.
 * /proc/ccs/query is handled by /usr/lib/ccs/ccs-queryd and
 * /proc/ccs/grant_log and /proc/ccs/reject_log are handled by
 * /usr/lib/ccs/ccs-auditd.
 */
int ccs_poll_control(struct file *file, poll_table *wait)
{
	struct ccs_io_buffer *head = file->private_data;
	if (!head->poll)
		return -ENOSYS;
	return head->poll(file, wait);
}

/**
 * ccs_read_control - read() for /proc/ccs/ interface.
 *
 * @file:       Pointer to "struct file".
 * @buffer:     Poiner to buffer to write to.
 * @buffer_len: Size of @buffer.
 *
 * Returns bytes read on success, negative value otherwise.
 */
int ccs_read_control(struct file *file, char __user *buffer,
		     const int buffer_len)
{
	int len = 0;
	struct ccs_io_buffer *head = file->private_data;
	char *cp;
	if (!head->read)
		return -ENOSYS;
	if (!access_ok(VERIFY_WRITE, buffer, buffer_len))
		return -EFAULT;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	/* Call the policy handler. */
	len = head->read(head);
	if (len < 0)
		goto out;
	/* Write to buffer. */
	len = head->read_avail;
	if (len > buffer_len)
		len = buffer_len;
	if (!len)
		goto out;
	/* head->read_buf changes by some functions. */
	cp = head->read_buf;
	if (copy_to_user(buffer, cp, len)) {
		len = -EFAULT;
		goto out;
	}
	head->read_avail -= len;
	memmove(cp, cp + len, head->read_avail);
 out:
	mutex_unlock(&head->io_sem);
	return len;
}

/**
 * ccs_write_control - write() for /proc/ccs/ interface.
 *
 * @file:       Pointer to "struct file".
 * @buffer:     Pointer to buffer to read from.
 * @buffer_len: Size of @buffer.
 *
 * Returns @buffer_len on success, negative value otherwise.
 */
int ccs_write_control(struct file *file, const char __user *buffer,
		      const int buffer_len)
{
	struct ccs_io_buffer *head = file->private_data;
	int error = buffer_len;
	int avail_len = buffer_len;
	char *cp0 = head->write_buf;
	if (!head->write)
		return -ENOSYS;
	if (!access_ok(VERIFY_READ, buffer, buffer_len))
		return -EFAULT;
	/* Don't allow updating policies by non manager programs. */
	if (head->write != ccs_write_pid &&
#ifdef CONFIG_TOMOYO
	    head->write != ccs_write_domain_policy &&
#endif
	    !ccs_is_policy_manager())
		return -EPERM;
	if (mutex_lock_interruptible(&head->io_sem))
		return -EINTR;
	/* Read a line and dispatch it to the policy handler. */
	while (avail_len > 0) {
		char c;
		if (head->write_avail >= head->writebuf_size - 1) {
			error = -ENOMEM;
			break;
		} else if (get_user(c, buffer)) {
			error = -EFAULT;
			break;
		}
		buffer++;
		avail_len--;
		cp0[head->write_avail++] = c;
		if (c != '\n')
			continue;
		cp0[head->write_avail - 1] = '\0';
		head->write_avail = 0;
		ccs_normalize_line(cp0);
		head->write(head);
	}
	mutex_unlock(&head->io_sem);
	return error;
}

/**
 * ccs_close_control - close() for /proc/ccs/ interface.
 *
 * @file: Pointer to "struct file".
 *
 * Releases memory and returns 0.
 */
int ccs_close_control(struct file *file)
{
	struct ccs_io_buffer *head = file->private_data;
	/*
	 * If the file is /proc/ccs/query , decrement the observer counter.
	 */
	if (head->write == ccs_write_answer || head->read == ccs_read_query)
		atomic_dec(&ccs_query_observers);
	/* Release memory used for policy I/O. */
	ccs_free(head->read_buf);
	head->read_buf = NULL;
	ccs_free(head->write_buf);
	head->write_buf = NULL;
	ccs_free(head);
	head = NULL;
	file->private_data = NULL;
	return 0;
}

/**
 * ccs_alloc_acl_element - Allocate permanent memory for ACL entry.
 *
 * @acl_type:  Type of ACL entry.
 * @condition: Pointer to condition part of the ACL entry. May be NULL.
 *
 * Returns pointer to the ACL entry on success, NULL otherwise.
 */
void *ccs_alloc_acl_element(const u8 acl_type,
			    const struct ccs_condition_list *condition)
{
	int len;
	struct ccs_acl_info *ptr;
	switch (acl_type) {
	case TYPE_SINGLE_PATH_ACL:
		len = sizeof(struct ccs_single_path_acl_record);
		break;
	case TYPE_DOUBLE_PATH_ACL:
		len = sizeof(struct ccs_double_path_acl_record);
		break;
	case TYPE_IOCTL_ACL:
		len = sizeof(struct ccs_ioctl_acl_record);
		break;
	case TYPE_ARGV0_ACL:
		len = sizeof(struct ccs_argv0_acl_record);
		break;
	case TYPE_ENV_ACL:
		len = sizeof(struct ccs_env_acl_record);
		break;
	case TYPE_CAPABILITY_ACL:
		len = sizeof(struct ccs_capability_acl_record);
		break;
	case TYPE_IP_NETWORK_ACL:
		len = sizeof(struct ccs_ip_network_acl_record);
		break;
	case TYPE_SIGNAL_ACL:
		len = sizeof(struct ccs_signal_acl_record);
		break;
	case TYPE_EXECUTE_HANDLER:
	case TYPE_DENIED_EXECUTE_HANDLER:
		len = sizeof(struct ccs_execute_handler_record);
		break;
	default:
		return NULL;
	}
	/*
	 * If the ACL doesn't have condition part, reduce memory usage
	 * by eliminating sizeof(struct ccs_condition_list *).
	 */
	if (!condition)
		len -= sizeof(ptr->access_me_via_ccs_get_condition_part);
	ptr = ccs_alloc_element(len);
	if (!ptr)
		return NULL;
	if (condition) {
		ptr->access_me_via_ccs_get_condition_part = condition;
		ptr->type = acl_type | ACL_WITH_CONDITION;
		return ptr;
	}
	/*
	 * Substract sizeof(struct ccs_condition_list *) because I eliminated
	 * sizeof(struct ccs_condition_list *) from "struct ccs_acl_info"
	 * but I must return the start address of "struct ccs_acl_info".
	 */
	ptr = (void *) (((u8 *) ptr)
			- sizeof(ptr->access_me_via_ccs_get_condition_part));
	ptr->type = acl_type;
	return ptr;
}
