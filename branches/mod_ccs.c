#include "httpd.h"
#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_thread_proc.h"
#include "ap_listen.h"
#include "ap_mpm.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"
#include <unistd.h>

#define bool _Bool
#define false 0
#define true 1

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
	/* Don't compare directory and non-directory. */
	//if (filename->is_dir != pattern->is_dir)
	//	return false;
	/* Compare the initial length without patterns. */
	if (strncmp(f, p, len))
		return false;
	f += len;
	p += len;
	return ccs_path_matches_pattern2(f, p);
}

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

static int ccs_transition_fd = EOF;

static _Bool ccs_set_context(request_rec *r)
{
	static char buffer[8192];
	FILE *fp;
	int len;
	_Bool success = 0;
	memset(buffer, 0, sizeof(buffer));
	fp = fopen("/etc/apache_domain_map.conf", "r");
	{ /* Transit domain by virtual host's name. */
		char *name = r->server->server_hostname;
		snprintf(buffer, sizeof(buffer) - 1, "servername=%s", name);
		len = strlen(buffer) + 1;
		success = write(ccs_transition_fd, buffer, len) == len;
		if (!success)
			goto out;
	}
	if (fp) {
		/* Transit domain by requested pathname. */
		success = 0;
		while (fgets(buffer, sizeof(buffer) - 1, fp)) {
			char *cp = strchr(buffer, '\n');
			if (!cp)
				break;
			ccs_normalize_line(buffer);
			cp = strchr(buffer, ' ');
			if (!cp)
				break;
			*cp = '\0';
			if (!ccs_path_matches_pattern(r->filename,
						      buffer))
				continue;
			len = strlen(cp + 1) + 1;
			success = write(ccs_transition_fd, cp + 1, len) == len;
			break;
		}
		fclose(fp);
	}
 out:
	return success;
}

static int __thread volatile am_worker = 0;

static void *APR_THREAD_FUNC ccs_worker_handler(apr_thread_t *thread,
						void *data)
{
	request_rec *r = (request_rec *) data;
	int result = HTTP_INTERNAL_SERVER_ERROR;
	/* marks as the current context is worker thread */
	am_worker = 1;
	/* set security context */
	if (ccs_set_context(r)) {
		/* invoke content handler */
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
	if (ccs_transition_fd == EOF) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, ENOENT, r,
			      "mod_ccs: /proc/ccs/.transition is not available.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	apr_threadattr_create(&thread_attr, r->pool);
	apr_threadattr_detach_set(thread_attr, 0);
	rv = apr_thread_create(&thread, thread_attr, ccs_worker_handler, r,
			       r->pool);
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
			      "Unable to launch a one-time worker thread");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	rv = apr_thread_join(&thread_rv, thread);
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
			      "Unable to join the one-time worker thread");
		r->connection->aborted = 1;
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return thread_rv;
}

static void ccs_hooks(apr_pool_t *p)
{
	ap_hook_handler(ccs_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

static void *ccs_server_config(apr_pool_t *p, server_rec *s)
{
	if (ccs_transition_fd == EOF)
		ccs_transition_fd = open("/proc/ccs/.transition", O_WRONLY);
	return NULL;
}

module AP_MODULE_DECLARE_DATA ccs_module = {
	STANDARD20_MODULE_STUFF,
	NULL,                   /* create per-directory config */
	NULL,                   /* merge per-directory config */
	ccs_server_config,      /* server config creator */
	NULL,                   /* server config merger */
	NULL,                   /* command table */
	ccs_hooks,              /* set up other hooks */
};
