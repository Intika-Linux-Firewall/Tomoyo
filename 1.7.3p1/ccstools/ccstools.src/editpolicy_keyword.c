/*
 * editpolicy_keyword.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include "ccstools.h"

/* Variables */

struct editpolicy_directive directives[MAX_DIRECTIVE_INDEX] = {
	[DIRECTIVE_NONE] = { "", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_EXECUTE]    = { "allow_execute", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_READ]       = { "allow_read", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_WRITE]      = { "allow_write", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_READ_WRITE] = { "allow_read/write", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_CREATE]     = { "allow_create", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_UNLINK]     = { "allow_unlink", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_MKDIR]      = { "allow_mkdir", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_RMDIR]      = { "allow_rmdir", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_MKFIFO]     = { "allow_mkfifo", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_MKSOCK]     = { "allow_mksock", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_MKBLOCK]    = { "allow_mkblock", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_MKCHAR]     = { "allow_mkchar", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_TRUNCATE]   = { "allow_truncate", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_SYMLINK]    = { "allow_symlink", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_LINK]       = { "allow_link", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_RENAME]     = { "allow_rename", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_REWRITE]    = { "allow_rewrite", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_TRANSIT]    = { "allow_transit", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_IOCTL]      = { "allow_ioctl", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_SIGNAL]     = { "allow_signal", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_NETWORK]    = { "allow_network", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_ENV]        = { "allow_env", NULL, 0, 0 },
	[DIRECTIVE_ADDRESS_GROUP]    = { "address_group", NULL, 0, 0 },
	[DIRECTIVE_AGGREGATOR]       = { "aggregator", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_CAPABILITY] = { "allow_capability", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_CHROOT]     = { "allow_chroot", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_MOUNT]      = { "allow_mount", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_PIVOT_ROOT] = { "allow_pivot_root", NULL, 0, 0 },
	[DIRECTIVE_DENY_AUTOBIND]    = { "deny_autobind", NULL, 0, 0 },
	[DIRECTIVE_DENY_REWRITE]     = { "deny_rewrite", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_UNMOUNT]    = { "allow_unmount", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_CHMOD]      = { "allow_chmod", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_CHOWN]      = { "allow_chown", NULL, 0, 0 },
	[DIRECTIVE_ALLOW_CHGRP]      = { "allow_chgrp", NULL, 0, 0 },
	[DIRECTIVE_FILE_PATTERN]     = { "file_pattern", NULL, 0, 0 },
	[DIRECTIVE_EXECUTE_HANDLER]  = { "execute_handler", NULL, 0, 0 },
	[DIRECTIVE_DENIED_EXECUTE_HANDLER] = {
		"denied_execute_handler", NULL, 0, 0 },
	[DIRECTIVE_IGNORE_GLOBAL_ALLOW_ENV] = {
		"ignore_global_allow_env", NULL, 0, 0 },
	[DIRECTIVE_IGNORE_GLOBAL_ALLOW_READ] = {
		"ignore_global_allow_read", NULL, 0, 0 },
	[DIRECTIVE_INITIALIZE_DOMAIN]    = { "initialize_domain", NULL, 0, 0 },
	[DIRECTIVE_KEEP_DOMAIN]          = { "keep_domain", NULL, 0, 0 },
	[DIRECTIVE_NO_INITIALIZE_DOMAIN] = {
		"no_initialize_domain", NULL, 0, 0 },
	[DIRECTIVE_NO_KEEP_DOMAIN]       = { "no_keep_domain", NULL, 0, 0 },
	[DIRECTIVE_PATH_GROUP]       = { "path_group", NULL, 0, 0 },
	[DIRECTIVE_NUMBER_GROUP]     = { "number_group", NULL, 0, 0 },
	[DIRECTIVE_QUOTA_EXCEEDED]   = { "quota_exceeded", NULL, 0, 0 },
	[DIRECTIVE_USE_PROFILE]      = { "use_profile", NULL, 0, 0 },
	[DIRECTIVE_TRANSITION_FAILED] = { "transition_failed", NULL, 0, 0 },
};

/* Main functions */

u8 find_directive(const _Bool forward, char *line)
{
	u8 i;
	for (i = 1; i < MAX_DIRECTIVE_INDEX; i++) {
		if (forward) {
			const int len = directives[i].original_len;
			if (strncmp(line, directives[i].original, len) ||
			    (line[len] != ' ' && line[len]))
				continue;
			if (line[len])
				memmove(line, line + len + 1,
					strlen(line + len + 1) + 1);
			else
				line[0] = '\0';
			return i;
		} else {
			const int len = directives[i].alias_len;
			if (strncmp(line, directives[i].alias, len) ||
			    (line[len] != ' ' && line[len]))
				continue;
			if (line[len])
				memmove(line, line + len + 1,
					strlen(line + len + 1) + 1);
			else
				line[0] = '\0';
			return i;
		}
	}
	return DIRECTIVE_NONE;
}

void editpolicy_init_keyword_map(void)
{
	FILE *fp = fopen(CCSTOOLS_CONFIG_FILE, "r");
	int i;
	if (!fp)
		goto use_default;
	get();
	while (true) {
		char *line = freadline(fp);
		char *cp;
		if (!line)
			break;
		if (!str_starts(line, "editpolicy.keyword_alias "))
			continue;
		cp = strchr(line, '=');
		if (!cp)
			continue;
		*cp++ = '\0';
		normalize_line(line);
		normalize_line(cp);
		if (!*line || !*cp)
			continue;
		for (i = 1; i < MAX_DIRECTIVE_INDEX; i++) {
			if (strcmp(line, directives[i].original))
				continue;
			free((void *) directives[i].alias);
			cp = strdup(cp);
			if (!cp)
				out_of_memory();
			directives[i].alias = cp;
			directives[i].alias_len = strlen(cp);
			break;
		}
	}
	put();
	fclose(fp);
use_default:
	for (i = 1; i < MAX_DIRECTIVE_INDEX; i++) {
		if (!directives[i].alias)
			directives[i].alias = directives[i].original;
		directives[i].original_len = strlen(directives[i].original);
		directives[i].alias_len = strlen(directives[i].alias);
	}
}
