/*
 * mod_tomoyo.c - Apache module for TOMOYO Linux.
 *
 * About this module:
 *
 *   This module allows Apache 2.x running on TOMOYO Linux kernels to process
 *   requests under different TOMOYO Linux's domains based on requested
 *   server's name (and optionally based on requested resource's pathname) by
 *   requesting TOMOYO Linux's domain transition before processing requests.
 *
 *   Access restrictions are provided by TOMOYO Linux kernel's Mandatory Access
 *   Control functionality. Therefore, if you want Apache to process requests
 *   with limited set of permissions, you have to configure TOMOYO Linux's
 *   policy and assign "enforcing mode".
 *
 * Runtime dependency:
 *
 *   TOMOYO Linux 2.5.0 (or later).
 *
 * How to build and install:
 *
 *   Install packages needed for developing Apache modules and run below
 *   command. If your system has apxs2, use apxs2 rather than apxs.
 *
 *     apxs -i -a -c mod_tomoyo.c
 *
 * How to configure:
 *
 *   TOMOYO_TransitionMap directive is provided by this module.
 *   You may perform domain transition based on requested resource's pathname
 *   using this directive.
 *
 *   This directive can appear in the server-wide configuration files
 *   (e.g., httpd.conf) outside <Directory> or <Location> containers.
 *
 *     DocumentRoot /var/www/html/
 *     ServerName www.example.com
 *     TOMOYO_TransitionMap /etc/tomoyo/apache2_transition_table.conf
 *
 *     <VirtualHost *:80>
 *         DocumentRoot /home/cat/html/
 *         ServerName cat.example.com
 *         TOMOYO_TransitionMap /home/cat/apache2_transition_table.conf
 *     </VirtualHost>
 *
 *     <VirtualHost *:80>
 *         DocumentRoot /home/dog/html/
 *         ServerName dog.example.com
 *         TOMOYO_TransitionMap /home/dog/apache2_transition_table.conf
 *     </VirtualHost>
 *
 *   This directive takes one parameter which specifies pathname to mapping
 *   table file. The mapping table file contains list of "pathname patterns"
 *   and "domainname" pairs, written in accordance with TOMOYO Linux's pathname
 *   representation rule and wildcard characters. For example,
 *
 *     /var/www/cgi-bin/\*        <kernel> //apache /www.example.com /cgi-programs
 *     /usr/share/horde/\{\*\}/\* <kernel> //apache /www.example.com /horde
 *     /var/www/html/\{\*\}/\*    <kernel> //apache /www.example.com /static-files
 *
 *   in /etc/tomoyo/apache2_transition_table.conf and
 *
 *     /home/cat/html/\*          <kernel> //apache /cat.example.com
 *     /home/cat/html/\{\*\}/\*   <kernel> //apache /cat.example.com
 *
 *   in /home/cat/apache2_transition_table.conf and
 *
 *     /home/dog/html/\*          <kernel> //apache /dog.example.com
 *     /home/dog/html/\{\*\}/\*   <kernel> //apache /dog.example.com
 *
 *   in /home/dog/apache2_transition_table.conf .
 *
 *   You need to beforehand specify domainnames in the mapping table to
 *   /sys/kernel/security/tomoyo/domain_policy using "task manual_domain_transition" directive
 *   (e.g.
 *
 *     <kernel> /usr/sbin/httpd
 *     task manual_domain_transition <kernel> //apache /www.example.com /cgi-programs
 *     task manual_domain_transition <kernel> //apache /www.example.com /horde
 *     task manual_domain_transition <kernel> //apache /www.example.com /static-files
 *     task manual_domain_transition <kernel> //apache /cat.example.com
 *     task manual_domain_transition <kernel> //apache /dog.example.com
 *
 *   ).
 *
 *   If the requested pathname did not match the pathname patterns listed in
 *   the mapping table file, the request will fail with internal error.
 *   Be sure to cover all possible pathnames you want to allow access.
 *
 *   If you want to use this module for separating virtual hosts and not for
 *   separating permissions within a virtual host, you can specify like
 *
 *     /var/www/cgi-bin/\*        <kernel> //apache /www.example.com
 *     /usr/share/horde/\{\*\}/\* <kernel> //apache /www.example.com
 *     /var/www/html/\{\*\}/\*    <kernel> //apache /www.example.com
 *
 *   in /etc/tomoyo/apache2_transition_table.conf and
 *
 *     /home/cat/html/\*          <kernel> //apache /cat.example.com
 *     /home/cat/html/\{\*\}/\*   <kernel> //apache /cat.example.com
 *
 *   in /home/cat/apache2_transition_table.conf and
 *
 *     /home/dog/html/\*          <kernel> //apache /dog.example.com
 *     /home/dog/html/\{\*\}/\*   <kernel> //apache /dog.example.com
 *
 *   in /home/dog/apache2_transition_table.conf .
 *
 * Author:
 *
 *   Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 *   The idea to use one-time worker thread is borrowed from mod_selinux.c
 *   developed by KaiGai Kohei.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define s8 char
#define u8 unsigned char
#define bool _Bool
#define false 0
#define true 1

/**
 * ccs_is_byte_range - Check whether the string is a \ooo style octal value.
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
 * ccs_file_matches_pattern2 - Pattern matching without '/' character and "\-" pattern.
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
			    && !strncmp(filename + 1, pattern, 3)) {
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
 * ccs_file_matches_pattern - Pattern matching without '/' character.
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
 * ccs_path_matches_pattern2 - Do pathname pattern matching.
 *
 * @f: The start of string to check.
 * @p: The start of pattern to compare.
 *
 * Returns true if @f matches @p, false otherwise.
 */
static bool ccs_path_matches_pattern2(const char *f, const char *p)
{
	const char *f_delimiter;
	const char *p_delimiter;
	while (*f && *p) {
		f_delimiter = strchr(f, '/');
		if (!f_delimiter)
			f_delimiter = f + strlen(f);
		p_delimiter = strchr(p, '/');
		if (!p_delimiter)
			p_delimiter = p + strlen(p);
		if (*p == '\\' && *(p + 1) == '{')
			goto recursive;
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
 recursive:
	/*
	 * The "\{" pattern is permitted only after '/' character.
	 * This guarantees that below "*(p - 1)" is safe.
	 * Also, the "\}" pattern is permitted only before '/' character
	 * so that "\{" + "\}" pair will not break the "\-" operator.
	 */
	if (*(p - 1) != '/' || p_delimiter <= p + 3 || *p_delimiter != '/' ||
	    *(p_delimiter - 1) != '}' || *(p_delimiter - 2) != '\\')
		return false; /* Bad pattern. */
	do {
		/* Compare current component with pattern. */
		if (!ccs_file_matches_pattern(f, f_delimiter, p + 2,
					      p_delimiter - 2))
			break;
		/* Proceed to next component. */
		f = f_delimiter;
		if (!*f)
			break;
		f++;
		/* Continue comparison. */
		if (ccs_path_matches_pattern2(f, p_delimiter + 1))
			return true;
		f_delimiter = strchr(f, '/');
	} while (f_delimiter);
	return false; /* Not matched. */
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
 * ccs_path_matches_pattern - Check whether the given filename matches the given pattern.
 *
 * @filename: The filename to check.
 * @pattern:  The pattern to compare.
 *
 * Returns true if matches, false otherwise.
 *
 * The following patterns are available.
 *   \\     \ itself.
 *   \ooo   Octal representation of a byte.
 *   \*     Zero or more repetitions of characters other than '/'.
 *   \@     Zero or more repetitions of characters other than '/' or '.'.
 *   \?     1 byte character other than '/'.
 *   \$     One or more repetitions of decimal digits.
 *   \+     1 decimal digit.
 *   \X     One or more repetitions of hexadecimal digits.
 *   \x     1 hexadecimal digit.
 *   \A     One or more repetitions of alphabet characters.
 *   \a     1 alphabet character.
 *
 *   \-     Subtraction operator.
 *
 *   /\{dir\}/   '/' + 'One or more repetitions of dir/' (e.g. /dir/ /dir/dir/
 *               /dir/dir/dir/ ).
 */
static bool ccs_path_matches_pattern(const char *filename, const char *pattern)
{
	const char *f = filename;
	const char *p = pattern;
	const int len = ccs_const_part_length(pattern);
	/* If @pattern doesn't contain pattern, I can use strcmp(). */
	if (len == strlen(pattern))
		return !strcmp(filename, pattern);
	/* Compare the initial length without patterns. */
	if (strncmp(f, p, len))
		return false;
	f += len;
	p += len;
	return ccs_path_matches_pattern2(f, p);
}

/**
 * ccs_normalize_line - Format string.
 *
 * @line: The line to normalize.
 *
 * Leading and trailing whitespaces are removed.
 * Multiple whitespaces are packed into single space.
 *
 * Returns nothing.
 */
static void ccs_normalize_line(unsigned char *line)
{
	unsigned char *sp = line;
	unsigned char *dp = line;
	_Bool first = true;
	while (*sp && (*sp <= ' ' || 127 <= *sp))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (' ' < *sp && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || 127 <= *sp))
			sp++;
	}
	*dp = '\0';
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
static u8 ccs_make_byte(const u8 c1, const u8 c2, const u8 c3)
{
	return ((c1 - '0') << 6) + ((c2 - '0') << 3) + (c3 - '0');
}

/**
 * ccs_correct_word2 - Check whether the given string follows the naming rules.
 *
 * @string: The byte sequence to check. Not '\0'-terminated.
 * @len:    Length of @string.
 *
 * Returns true if @string follows the naming rules, false otherwise.
 */
static bool ccs_correct_word2(const char *string, size_t len)
{
	const char *const start = string;
	bool in_repetition = false;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	if (!len)
		goto out;
	while (len--) {
		c = *string++;
		if (c == '\\') {
			if (!len--)
				goto out;
			c = *string++;
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
				continue;
			case '{':   /* "/\{" */
				if (string - 3 < start || *(string - 3) != '/')
					break;
				in_repetition = true;
				continue;
			case '}':   /* "\}/" */
				if (*string != '/')
					break;
				if (!in_repetition)
					break;
				in_repetition = false;
				continue;
			case '0':   /* "\ooo" */
			case '1':
			case '2':
			case '3':
				if (!len-- || !len--)
					break;
				d = *string++;
				e = *string++;
				if (d < '0' || d > '7' || e < '0' || e > '7')
					break;
				c = ccs_make_byte(c, d, e);
				if (c <= ' ' || c >= 127)
					continue;
			}
			goto out;
		} else if (in_repetition && c == '/') {
			goto out;
		} else if (c <= ' ' || c >= 127) {
			goto out;
		}
	}
	if (in_repetition)
		goto out;
	return true;
out:
	return false;
}

/**
 * ccs_correct_word - Check whether the given string follows the naming rules.
 *
 * @string: The string to check.
 *
 * Returns true if @string follows the naming rules, false otherwise.
 */
static bool ccs_correct_word(const char *string)
{
	return ccs_correct_word2(string, strlen(string));
}

/**
 * ccs_correct_path - Check whether the given pathname follows the naming rules.
 *
 * @filename: The pathname to check.
 *
 * Returns true if @filename follows the naming rules, false otherwise.
 */
static bool ccs_correct_path(const char *filename)
{
	return *filename == '/' && ccs_correct_word(filename);
}

/**
 * ccs_domain_def - Check whether the given token can be a domainname.
 *
 * @buffer: The token to check.
 *
 * Returns true if @buffer possibly be a domainname, false otherwise.
 */
static bool ccs_domain_def(const char *buffer)
{
	const char *cp;
	int len;
	if (*buffer != '<')
		return false;
	cp = strchr(buffer, ' ');
	if (!cp)
		len = strlen(buffer);
	else
		len = cp - buffer;
	if (buffer[len - 1] != '>' || !ccs_correct_word2(buffer + 1, len - 2))
		return false;
	return true;
}

/**
 * ccs_correct_domain - Check whether the given domainname follows the naming rules.
 *
 * @domainname: The domainname to check.
 *
 * Returns true if @domainname follows the naming rules, false otherwise.
 */
static bool ccs_correct_domain(const char *domainname)
{
	if (!domainname || !ccs_domain_def(domainname))
		return false;
	domainname = strchr(domainname, ' ');
	if (!domainname++)
		return true;
	while (1) {
		const char *cp = strchr(domainname, ' ');
		if (!cp)
			break;
		if (*domainname != '/' ||
		    !ccs_correct_word2(domainname, cp - domainname))
			return false;
		domainname = cp + 1;
	}
	return ccs_correct_path(domainname);
}

#include "httpd.h"
#include "apr_strings.h"
#include "ap_listen.h"
#include "http_log.h"

module AP_MODULE_DECLARE_DATA ccs_module;

static int ccs_transition_fd = EOF;
static int ccs_open_error = 0;

struct ccs_map_entry {
	const char *pathname;
	const char *domainname;
};

struct ccs_map_table {
	struct ccs_map_entry *entry;
	int len;
};

static char *ccs_encode_string(const char *str)
{
	char *cp = malloc(strlen(str) * 4 + 1);
	char *cp0 = cp;
	if (!cp)
		return NULL;
	while (*str) {
		const unsigned char c = *str++;
		if (c == '\\') {
			*cp++ = '\\';
			*cp++ = '\\';
		} else if (c > ' ' && c < 127) {
			*cp++ = c;
		} else {
			*cp++ = '\\';
			*cp++ = (c >> 6) + '0';
			*cp++ = ((c >> 3) & 7) + '0';
			*cp++ = (c & 7) + '0';
		}
	}
	*cp = '\0';
	return cp0;
}

static _Bool ccs_set_context(request_rec *r)
{
	struct ccs_map_table *ptr =
		ap_get_module_config(r->server->module_config, &ccs_module);
	int i;
	/* Transit domain by requested pathname. */
	const char *name = ccs_encode_string(r->filename);
	if (!name) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, EPERM, r, "mod_tomoyo: "
			      "Unable to set security context. "
			      "Out of memory.");
		return 0;
	}
	for (i = 0; i < ptr->len; i++) {
		int len;
		if (!ccs_path_matches_pattern(name, ptr->entry[i].pathname))
			continue;
		free((void *) name);
		name = ptr->entry[i].domainname;
		len = strlen(name) + 1;
		if (write(ccs_transition_fd, name, len) == len)
			return 1;
		ap_log_rerror(APLOG_MARK, APLOG_ERR, EPERM, r, "mod_tomoyo: "
			      "Unable to set security context. "
			      "Can't transit to %s", name);
		return 0;
	}
	ap_log_rerror(APLOG_MARK, APLOG_ERR, EPERM, r, "mod_tomoyo: "
		      "Unable to set security context. "
		      "No matching entry for %s", name);
	free((void *) name);
	return 0;
}

static int __thread volatile am_worker = 0;

static void *APR_THREAD_FUNC ccs_worker_handler(apr_thread_t *thread,
						void *data)
{
	request_rec *r = (request_rec *) data;
	int result = HTTP_INTERNAL_SERVER_ERROR;
	am_worker = 1;
	/* Set security context. */
	if (ccs_set_context(r)) {
		/*
		 * Invoke content handler again.
		 * Thread local variable am_worker prevents from
		 * being called infinitely.
		 */
		result = ap_run_handler(r);
		if (result == DECLINED)
			result = HTTP_INTERNAL_SERVER_ERROR;
	}
	apr_thread_exit(thread, result);
	return NULL;
}

static int ccs_handler(request_rec *r)
{
	apr_threadattr_t *thread_attr = NULL;
	apr_thread_t *thread = NULL;
	apr_status_t rv;
	apr_status_t thread_rv;
	if (am_worker)
		return DECLINED;
	if (ccs_open_error) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, ccs_open_error, r,
			      "mod_tomoyo: Unable to open "
			      "/sys/kernel/security/tomoyo/self_domain "
			      "for writing.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (ccs_transition_fd == EOF)
		return DECLINED;
	apr_threadattr_create(&thread_attr, r->pool);
	apr_threadattr_detach_set(thread_attr, 0);
	rv = apr_thread_create(&thread, thread_attr, ccs_worker_handler, r,
			       r->pool);
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, "mod_tomoyo: "
			      "Unable to launch a one-time worker thread.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	rv = apr_thread_join(&thread_rv, thread);
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, "mod_tomoyo: "
			      "Unable to join the one-time worker thread.");
		r->connection->aborted = 1;
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return thread_rv;
}

static void ccs_hooks(apr_pool_t *p)
{
	ap_hook_handler(ccs_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

static void *ccs_create_server_config(apr_pool_t *p, server_rec *s)
{
	void *ptr = apr_palloc(p, sizeof(struct ccs_map_table));
	if (ptr)
		memset(ptr, 0, sizeof(struct ccs_map_table));
	/*
	 * We can share because /sys/kernel/security/tomoyo/self_domain
	 * interface has no data.
	 */
	if (ccs_transition_fd == EOF) {
		ccs_transition_fd =
			open("/sys/kernel/security/tomoyo/self_domain",
			     O_WRONLY);
		/*
		 * Some access control mechanisms might reject opening
		 * /sys/kernel/security/tomoyo/self_domain for writing.
		 * This failure is reported by ccs_parse_table() if
		 * TOMOYO_TransitionMap keyword is specified, by ccs_handler()
		 * otherwise.
		 */
		if (ccs_transition_fd == EOF && errno != ENOENT)
			ccs_open_error = errno;
	}
	/* Allocation failure is reported by ccs_parse_table(). */
	return ptr;
}

static const char *ccs_parse_table(cmd_parms *parms, void *mconfig,
				   const char *args)
{
	static const int buffer_len = 8192;
	char *buffer = apr_palloc(parms->pool, buffer_len);
	int line = 0;
	FILE *fp = NULL;
	struct ccs_map_table *ptr =
		ap_get_module_config(parms->server->module_config,
				     &ccs_module);
	if (!ptr || !buffer)
		goto no_memory;
	if (ccs_open_error)
		goto no_interface;
	fp = fopen(args, "r");
	if (!fp)
		goto no_file;
	{
		int c;
		while ((c = fgetc(fp)) != EOF)
			if (c == '\n')
				line++;
		if (!line) {
			fclose(fp);
			goto no_file;
		}
	}
	ptr->entry = apr_palloc(parms->pool,
				line * sizeof(struct ccs_map_entry));
	if (!ptr->entry)
		goto no_memory;
	ptr->len = line;
	line = 0;
	rewind(fp);
	memset(buffer, 0, buffer_len);
	while (fgets(buffer, buffer_len - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (line == ptr->len)
			goto invalid_line;
		if (!cp) {
			fclose(fp);
			snprintf(buffer, buffer_len - 1, "mod_tomoyo: "
				 "Line %u of %s : Too long.", line + 1, args);
			return buffer;
		}
		ccs_normalize_line((unsigned char *) buffer);
		cp = strchr(buffer, ' ');
		if (!cp)
			goto invalid_line;
		*cp++ = '\0';
		if (!ccs_correct_path(buffer)) {
			fclose(fp);
			snprintf(buffer, buffer_len - 1, "mod_tomoyo: "
				 "Line %u of %s : Bad pathname.", line + 1,
				 args);
			return buffer;
		}
		if (!ccs_correct_domain(cp)) {
			fclose(fp);
			snprintf(buffer, buffer_len - 1, "mod_tomoyo: "
				 "Line %u of %s : Bad domainname.", line + 1,
				 args);
			return buffer;
		}
		cp = apr_pstrdup(parms->pool, cp);
		if (!cp)
			goto no_memory;
		ptr->entry[line].domainname = cp;
		cp = apr_pstrdup(parms->pool, buffer);
		if (!cp)
			goto no_memory;
		ptr->entry[line++].pathname = cp;
	}
	fclose(fp);
	return NULL;
 no_memory:
	if (fp)
		fclose(fp);
	return "mod_tomoyo: Out of memory.";
 no_interface:
	snprintf(buffer, buffer_len - 1,
		 "mod_tomoyo: Unable to open "
		 "/sys/kernel/security/tomoyo/self_domain for writing. "
		 "(errno = %d)", ccs_open_error);
	return buffer;
 no_file:
	snprintf(buffer, buffer_len - 1, "mod_tomoyo: %s : Can't read.", args);
	return buffer;
 invalid_line:
	fclose(fp);
	snprintf(buffer, buffer_len - 1, "mod_tomoyo: "
		 "Line %u of %s : Bad line.", line + 1, args);
	return buffer;
}

static command_rec ccs_cmds[2] = {
	AP_INIT_RAW_ARGS("TOMOYO_TransitionMap", ccs_parse_table, NULL,
			 RSRC_CONF, "Path to path/domain mapping table."),
	{ NULL }
};

module AP_MODULE_DECLARE_DATA ccs_module = {
	STANDARD20_MODULE_STUFF, NULL, NULL,
	ccs_create_server_config, NULL, ccs_cmds, ccs_hooks
};
