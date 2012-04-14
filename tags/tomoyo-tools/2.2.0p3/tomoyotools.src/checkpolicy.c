/*
 * checkpolicy.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 2.2.0+   2010/02/25
 *
 */
#include "tomoyotools.h"

static _Bool strendswith(const char *name, const char *tail)
{
	int len;
	if (!name || !tail)
		return false;
	len = strlen(name) - strlen(tail);
	return len >= 0 && !strcmp(name + len, tail);
}

static unsigned int line = 0;
static unsigned int errors = 0;
static unsigned int warnings = 0;

static void check_file_policy(char *data)
{
	static const struct {
		const char * const keyword;
		const int paths;
	} acl_type_array[] = {
		{ "execute",    1 },
		{ "read/write", 1 },
		{ "read",       1 },
		{ "write",      1 },
		{ "create",     1 },
		{ "unlink",     1 },
		{ "mkdir",      1 },
		{ "rmdir",      1 },
		{ "mkfifo",     1 },
		{ "mksock",     1 },
		{ "mkblock",    1 },
		{ "mkchar",     1 },
		{ "truncate",   1 },
		{ "symlink",    1 },
		{ "link",       2 },
		{ "rename",     2 },
		{ "rewrite",    1 },
		{ "ioctl",      1 },
		{ "chmod",      1 },
		{ "chown",      1 },
		{ "chgrp",      1 },
		{ "mount",      1 },
		{ "unmount",    1 },
		{ "chroot",     1 },
		{ "pivot_root", 2 },
		{ NULL, 0 }
	};
	char *filename = strchr(data, ' ');
	char *cp;
	unsigned int perm;
	if (!filename) {
		printf("%u: ERROR: Unknown command '%s'\n", line, data);
		errors++;
		return;
	}
	*filename++ = '\0';
	if (sscanf(data, "%u", &perm) == 1 && perm > 0 && perm <= 7) {
		if (strendswith(filename, "/")) {
			printf("%u: WARNING: Only 'mkdir' and 'rmdir' are "
			       "valid for directory '%s'.\n", line, filename);
			warnings++;
		}
		if (!is_correct_path(filename, 0, 0, 0))
			goto out1;
		/* "1", "3", "5", "7" don't accept patterns. */
		if ((perm & 1) == 1 && !is_correct_path(filename, 1, -1, -1))
			goto out1;
		return;
	}
	if (!strncmp(data, "allow_", 6)) {
		int type;
		for (type = 0; acl_type_array[type].keyword; type++) {
			if (strcmp(data + 6, acl_type_array[type].keyword))
				continue;
			if (acl_type_array[type].paths == 2) {
				cp = strchr(filename, ' ');
				if (!cp || !is_correct_path(cp + 1, 0, 0, 0))
					break;
				*cp = '\0';
			}
			if (!is_correct_path(filename, 0, 0, 0))
				break;
			/* "allow_execute" doesn't accept patterns. */
			if (!type && filename[0] != '@' &&
			    !is_correct_path(filename, 1, -1, -1))
				break;
			return;
		}
		if (!acl_type_array[type].keyword)
			goto out2;
out1:
		printf("%u: ERROR: '%s' is a bad pathname.\n", line, filename);
		errors++;
		return;
	}
out2:
	printf("%u: ERROR: Invalid permission '%s %s'\n", line, data, filename);
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

static void check_domain_policy(void)
{
	static int domain = EOF;
	_Bool is_delete = false;
	_Bool is_select = false;
	_Bool is_undelete = false;
	if (str_starts(shared_buffer, KEYWORD_DELETE))
		is_delete = true;
	else if (str_starts(shared_buffer, KEYWORD_SELECT))
		is_select = true;
	if (is_domain_def(shared_buffer)) {
		if (!is_correct_domain(shared_buffer) ||
		    strlen(shared_buffer) >= CCS_MAX_PATHNAME_LEN) {
			printf("%u: ERROR: '%s' is a bad domainname.\n",
			       line, shared_buffer);
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
	} else if (is_undelete) {
		printf("%u: ERROR: Command 'undelete' is valid for undeleting "
		       "domains only.\n", line);
		errors++;
	} else if (domain == EOF) {
		printf("%u: WARNING: '%s' is unprocessed because domain is not "
		       "selected.\n", line, shared_buffer);
		warnings++;
	} else if (str_starts(shared_buffer, KEYWORD_USE_PROFILE)) {
		unsigned int profile;
		if (sscanf(shared_buffer, "%u", &profile) != 1 ||
		    profile >= 256) {
			printf("%u: ERROR: '%s' is a bad profile.\n",
			       line, shared_buffer);
			errors++;
		}
	} else if (!strcmp(shared_buffer, "ignore_global_allow_read")) {
		/* Nothing to do. */
	} else if (!strcmp(shared_buffer, "transition_failed")) {
		/* Nothing to do. */
	} else if (!strcmp(shared_buffer, "quota_exceeded")) {
		/* Nothing to do. */
	} else {
		check_file_policy(shared_buffer);
	}
}

static void check_exception_policy(void)
{
	str_starts(shared_buffer, KEYWORD_DELETE);
	if (str_starts(shared_buffer, KEYWORD_ALLOW_READ)) {
		if (!is_correct_path(shared_buffer, 1, 0, -1)) {
			printf("%u: ERROR: '%s' is a bad pathname.\n",
			       line, shared_buffer);
			errors++;
		}
	} else if (str_starts(shared_buffer, KEYWORD_INITIALIZE_DOMAIN)) {
		check_domain_initializer_policy(shared_buffer);
	} else if (str_starts(shared_buffer, KEYWORD_NO_INITIALIZE_DOMAIN)) {
		check_domain_initializer_policy(shared_buffer);
	} else if (str_starts(shared_buffer, KEYWORD_KEEP_DOMAIN)) {
		check_domain_keeper_policy(shared_buffer);
	} else if (str_starts(shared_buffer, KEYWORD_NO_KEEP_DOMAIN)) {
		check_domain_keeper_policy(shared_buffer);
	} else if (str_starts(shared_buffer, KEYWORD_ALIAS)) {
		char *cp = strchr(shared_buffer, ' ');
		if (!cp) {
			printf("%u: ERROR: Too few parameters.\n", line);
			errors++;
		} else {
			*cp++ = '\0';
			if (!is_correct_path(shared_buffer, 1, -1, -1)) {
				printf("%u: ERROR: '%s' is a bad pathname.\n",
				       line, shared_buffer);
				errors++;
			}
			if (!is_correct_path(cp, 1, -1, -1)) {
				printf("%u: ERROR: '%s' is a bad pathname.\n",
				       line, cp);
				errors++;
			}
		}
	} else if (str_starts(shared_buffer, KEYWORD_AGGREGATOR)) {
		char *cp = strchr(shared_buffer, ' ');
		if (!cp) {
			printf("%u: ERROR: Too few parameters.\n", line);
			errors++;
		} else {
			*cp++ = '\0';
			if (!is_correct_path(shared_buffer, 1, 0, -1)) {
				printf("%u: ERROR: '%s' is a bad pattern.\n",
				       line, shared_buffer);
				errors++;
			}
			if (!is_correct_path(cp, 1, -1, -1)) {
				printf("%u: ERROR: '%s' is a bad pathname.\n",
				       line, cp);
				errors++;
			}
		}
	} else if (str_starts(shared_buffer, KEYWORD_FILE_PATTERN)) {
		if (!is_correct_path(shared_buffer, 0, 1, 0)) {
			printf("%u: ERROR: '%s' is a bad pattern.\n",
			       line, shared_buffer);
			errors++;
		}
	} else if (str_starts(shared_buffer, KEYWORD_DENY_REWRITE)) {
		if (!is_correct_path(shared_buffer, 0, 0, 0)) {
			printf("%u: ERROR: '%s' is a bad pattern.\n",
			       line, shared_buffer);
			errors++;
		}
	} else {
		printf("%u: ERROR: Unknown command '%s'.\n",
		       line, shared_buffer);
		errors++;
	}
}

int checkpolicy_main(int argc, char *argv[])
{
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
	get();
	while (memset(shared_buffer, 0, sizeof(shared_buffer)),
	       fgets(shared_buffer, sizeof(shared_buffer) - 1, stdin)) {
		char *cp = strchr(shared_buffer, '\n');
		line++;
		if (!cp) {
			printf("%u: ERROR: Line too long.\n", line);
			errors++;
			break;
		}
		*cp = '\0';
		{
			int c;
			for (c = 1; c < 256; c++) {
				if (c == '\t' || c == '\r' ||
				    (c >= ' ' && c < 127))
					continue;
				if (!strchr(shared_buffer, c))
					continue;
				printf("%u: WARNING: Line contains illegal "
				       "character (\\%03o).\n", line, c);
				warnings++;
				break;
			}
		}
		normalize_line(shared_buffer);
		if (!shared_buffer[0])
			continue;
		switch (policy_type) {
		case POLICY_TYPE_DOMAIN_POLICY:
			check_domain_policy();
			break;
		case POLICY_TYPE_EXCEPTION_POLICY:
			check_exception_policy();
			break;
		}
	}
	put();
	printf("Total:   %u Line%s   %u Error%s   %u Warning%s\n",
	       line, line > 1 ? "s" : "", errors, errors > 1 ? "s" : "",
	       warnings, warnings > 1 ? "s" : "");
	return errors ? 2 : (warnings ? 1 : 0);
}
