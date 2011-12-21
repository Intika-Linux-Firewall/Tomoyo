/*
 * editpolicy_keyword.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3   2011/09/29
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
#include "ccstools.h"
#include "editpolicy.h"

/* keyword array for rewriting keywords upon display. */
struct ccs_editpolicy_directive ccs_directives[CCS_MAX_DIRECTIVE_INDEX] = {
	[CCS_DIRECTIVE_ACL_GROUP] = { "acl_group", NULL, 0, 0 },
	[CCS_DIRECTIVE_ADDRESS_GROUP] = { "address_group", NULL, 0, 0 },
	[CCS_DIRECTIVE_AGGREGATOR]    = { "aggregator", NULL, 0, 0 },
	[CCS_DIRECTIVE_CAPABILITY]    = { "capability", NULL, 0, 0 },
	[CCS_DIRECTIVE_DEFAULT_TRANSITION]
	= { "default_transition", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_APPEND]   = { "file append", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_CHGRP]    = { "file chgrp", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_CHMOD]    = { "file chmod", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_CHOWN]    = { "file chown", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_CHROOT]   = { "file chroot", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_CREATE]   = { "file create", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_EXECUTE]  = { "file execute", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_GETATTR]  = { "file getattr", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_IOCTL]    = { "file ioctl", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_LINK]     = { "file link", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_MKBLOCK]  = { "file mkblock", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_MKCHAR]   = { "file mkchar", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_MKDIR]    = { "file mkdir", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_MKFIFO]   = { "file mkfifo", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_MKSOCK]   = { "file mksock", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_MOUNT]    = { "file mount", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_PIVOT_ROOT] = { "file pivot_root", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_READ]     = { "file read", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_RENAME]   = { "file rename", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_RMDIR]    = { "file rmdir", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_SYMLINK]  = { "file symlink", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_TRUNCATE] = { "file truncate", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_UNLINK]   = { "file unlink", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_UNMOUNT]  = { "file unmount", NULL, 0, 0 },
	[CCS_DIRECTIVE_FILE_WRITE]    = { "file write", NULL, 0, 0 },
	[CCS_DIRECTIVE_IPC_PTRACE]    = { "ipc ptrace", NULL, 0, 0 },
	[CCS_DIRECTIVE_MISC_ENV]      = { "misc env", NULL, 0, 0 },
	[CCS_DIRECTIVE_NETWORK_INET]  = { "network inet", NULL, 0, 0 },
	[CCS_DIRECTIVE_NETWORK_UNIX]  = { "network unix", NULL, 0, 0 },
	[CCS_DIRECTIVE_NONE]          = { "", NULL, 0, 0 },
	[CCS_DIRECTIVE_NUMBER_GROUP]  = { "number_group", NULL, 0, 0 },
	[CCS_DIRECTIVE_PATH_GROUP]    = { "path_group", NULL, 0, 0 },
	[CCS_DIRECTIVE_QUOTA_EXCEEDED] = { "quota_exceeded", NULL, 0, 0 },
	[CCS_DIRECTIVE_TASK_AUTO_DOMAIN_TRANSITION]
	= { "task auto_domain_transition", NULL, 0, 0 },
	[CCS_DIRECTIVE_TASK_AUTO_EXECUTE_HANDLER]
	= { "task auto_execute_handler", NULL, 0, 0 },
	[CCS_DIRECTIVE_TASK_DENIED_EXECUTE_HANDLER]
	= { "task denied_execute_handler", NULL, 0, 0 },
	[CCS_DIRECTIVE_TASK_MANUAL_DOMAIN_TRANSITION]
	= { "task manual_domain_transition", NULL, 0, 0 },
	[CCS_DIRECTIVE_TRANSITION_FAILED]
	= { "transition_failed", NULL, 0, 0 },
	[CCS_DIRECTIVE_USE_GROUP]     = { "use_group", NULL, 0, 0 },
	[CCS_DIRECTIVE_USE_PROFILE]   = { "use_profile", NULL, 0, 0 },
};

/**
 * ccs_find_directive - Find keyword index.
 *
 * @forward: True if original -> alias conversion, false otherwise.
 * @line: A line containing keyword and operand.
 *
 * Returns one of values in "enum ccs_editpolicy_directives".
 */
enum ccs_editpolicy_directives ccs_find_directive(const _Bool forward,
						  char *line)
{
	u16 i;
	for (i = 1; i < CCS_MAX_DIRECTIVE_INDEX; i++) {
		if (forward) {
			const int len = ccs_directives[i].original_len;
			if (strncmp(line, ccs_directives[i].original, len) ||
			    (line[len] != ' ' && line[len]))
				continue;
			if (line[len])
				memmove(line, line + len + 1,
					strlen(line + len + 1) + 1);
			else
				line[0] = '\0';
			return i;
		} else {
			const int len = ccs_directives[i].alias_len;
			if (strncmp(line, ccs_directives[i].alias, len) ||
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

/**
 * ccs_editpolicy_init_keyword_map - Initialize keyword mapping table.
 *
 * Returns nothing.
 */
void ccs_editpolicy_init_keyword_map(void)
{
	FILE *fp = fopen(CCS_EDITPOLICY_CONF, "r");
	int i;
	if (!fp)
		goto use_default;
	ccs_get();
	while (true) {
		char *line = ccs_freadline(fp);
		char *cp;
		if (!line)
			break;
		if (!ccs_str_starts(line, "keyword_alias "))
			continue;
		cp = strchr(line, '=');
		if (!cp)
			continue;
		*cp++ = '\0';
		ccs_normalize_line(line);
		ccs_normalize_line(cp);
		if (!*line || !*cp)
			continue;
		for (i = 1; i < CCS_MAX_DIRECTIVE_INDEX; i++) {
			if (strcmp(line, ccs_directives[i].original))
				continue;
			free((void *) ccs_directives[i].alias);
			cp = ccs_strdup(cp);
			ccs_directives[i].alias = cp;
			ccs_directives[i].alias_len = strlen(cp);
			break;
		}
	}
	ccs_put();
	fclose(fp);
use_default:
	for (i = 1; i < CCS_MAX_DIRECTIVE_INDEX; i++) {
		if (!ccs_directives[i].alias)
			ccs_directives[i].alias = ccs_directives[i].original;
		ccs_directives[i].original_len =
			strlen(ccs_directives[i].original);
		ccs_directives[i].alias_len = strlen(ccs_directives[i].alias);
	}
}
