/*
 * editpolicy_keyword.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.3.0+   2011/09/29
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
#include "tomoyotools.h"
#include "editpolicy.h"

/* Variables */

struct tomoyo_editpolicy_directive tomoyo_directives[CCS_MAX_DIRECTIVE_INDEX] = {
	[CCS_DIRECTIVE_NONE] = { "", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_EXECUTE]    = { "allow_execute", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_READ]       = { "allow_read", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_WRITE]      = { "allow_write", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_READ_WRITE] = { "allow_read/write", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_CREATE]     = { "allow_create", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_UNLINK]     = { "allow_unlink", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_MKDIR]      = { "allow_mkdir", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_RMDIR]      = { "allow_rmdir", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_MKFIFO]     = { "allow_mkfifo", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_MKSOCK]     = { "allow_mksock", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_MKBLOCK]    = { "allow_mkblock", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_MKCHAR]     = { "allow_mkchar", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_TRUNCATE]   = { "allow_truncate", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_SYMLINK]    = { "allow_symlink", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_LINK]       = { "allow_link", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_RENAME]     = { "allow_rename", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_REWRITE]    = { "allow_rewrite", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_TRANSIT]    = { "allow_transit", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_IOCTL]      = { "allow_ioctl", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_SIGNAL]     = { "allow_signal", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_NETWORK]    = { "allow_network", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_ENV]        = { "allow_env", NULL, 0, 0 },
	[CCS_DIRECTIVE_ADDRESS_GROUP]    = { "address_group", NULL, 0, 0 },
	[CCS_DIRECTIVE_AGGREGATOR]       = { "aggregator", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_CAPABILITY] = { "allow_capability", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_CHROOT]     = { "allow_chroot", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_MOUNT]      = { "allow_mount", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_PIVOT_ROOT] = { "allow_pivot_root", NULL, 0, 0 },
	[CCS_DIRECTIVE_DENY_AUTOBIND]    = { "deny_autobind", NULL, 0, 0 },
	[CCS_DIRECTIVE_DENY_REWRITE]     = { "deny_rewrite", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_UNMOUNT]    = { "allow_unmount", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_CHMOD]      = { "allow_chmod", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_CHOWN]      = { "allow_chown", NULL, 0, 0 },
	[CCS_DIRECTIVE_ALLOW_CHGRP]      = { "allow_chgrp", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_PATTERN]     = { "file_pattern", NULL, 0, 0 },
	[CCS_DIRECTIVE_EXECUTE_HANDLER]  = { "execute_handler", NULL, 0, 0 },
	[CCS_DIRECTIVE_DENIED_EXECUTE_HANDLER] = {
		"denied_execute_handler", NULL, 0, 0 },
	[CCS_DIRECTIVE_IGNORE_GLOBAL_ALLOW_ENV] = {
		"ignore_global_allow_env", NULL, 0, 0 },
	[CCS_DIRECTIVE_IGNORE_GLOBAL_ALLOW_READ] = {
		"ignore_global_allow_read", NULL, 0, 0 },
	[CCS_DIRECTIVE_INITIALIZE_DOMAIN]    = { "initialize_domain", NULL, 0, 0 },
	[CCS_DIRECTIVE_KEEP_DOMAIN]          = { "keep_domain", NULL, 0, 0 },
	[CCS_DIRECTIVE_NO_INITIALIZE_DOMAIN] = {
		"no_initialize_domain", NULL, 0, 0 },
	[CCS_DIRECTIVE_NO_KEEP_DOMAIN]       = { "no_keep_domain", NULL, 0, 0 },
	[CCS_DIRECTIVE_PATH_GROUP]       = { "path_group", NULL, 0, 0 },
	[CCS_DIRECTIVE_NUMBER_GROUP]     = { "number_group", NULL, 0, 0 },
	[CCS_DIRECTIVE_QUOTA_EXCEEDED]   = { "quota_exceeded", NULL, 0, 0 },
	[CCS_DIRECTIVE_USE_PROFILE]      = { "use_profile", NULL, 0, 0 },
	[CCS_DIRECTIVE_TRANSITION_FAILED] = { "transition_failed", NULL, 0, 0 },
};

/* Main functions */

u8 tomoyo_find_directive(const _Bool forward, char *line)
{
	u8 i;
	for (i = 1; i < CCS_MAX_DIRECTIVE_INDEX; i++) {
		if (forward) {
			const int len = tomoyo_directives[i].original_len;
			if (strncmp(line, tomoyo_directives[i].original, len) ||
			    (line[len] != ' ' && line[len]))
				continue;
			if (line[len])
				memmove(line, line + len + 1,
					strlen(line + len + 1) + 1);
			else
				line[0] = '\0';
			return i;
		} else {
			const int len = tomoyo_directives[i].alias_len;
			if (strncmp(line, tomoyo_directives[i].alias, len) ||
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
	return CCS_DIRECTIVE_NONE;
}

void tomoyo_editpolicy_init_keyword_map(void)
{
	FILE *fp = fopen(CCS_CONFIG_FILE, "r");
	int i;
	if (!fp)
		goto use_default;
	tomoyo_get();
	while (true) {
		char *line = tomoyo_freadline(fp);
		char *cp;
		if (!line)
			break;
		if (!tomoyo_str_starts(line, "editpolicy.keyword_alias "))
			continue;
		cp = strchr(line, '=');
		if (!cp)
			continue;
		*cp++ = '\0';
		tomoyo_normalize_line(line);
		tomoyo_normalize_line(cp);
		if (!*line || !*cp)
			continue;
		for (i = 1; i < CCS_MAX_DIRECTIVE_INDEX; i++) {
			if (strcmp(line, tomoyo_directives[i].original))
				continue;
			free((void *) tomoyo_directives[i].alias);
			cp = strdup(cp);
			if (!cp)
				tomoyo_out_of_memory();
			tomoyo_directives[i].alias = cp;
			tomoyo_directives[i].alias_len = strlen(cp);
			break;
		}
	}
	tomoyo_put();
	fclose(fp);
use_default:
	for (i = 1; i < CCS_MAX_DIRECTIVE_INDEX; i++) {
		if (!tomoyo_directives[i].alias)
			tomoyo_directives[i].alias = tomoyo_directives[i].original;
		tomoyo_directives[i].original_len = strlen(tomoyo_directives[i].original);
		tomoyo_directives[i].alias_len = strlen(tomoyo_directives[i].alias);
	}
}
