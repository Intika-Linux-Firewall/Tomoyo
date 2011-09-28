/*
 * editpolicy_color.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.5.0   2011/09/29
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

#ifdef COLOR_ON

/**
 * ccs_editpolicy_color_init - Initialize line coloring table.
 *
 * Returns nothing.
 */
void ccs_editpolicy_color_init(void)
{
	static struct ccs_color_env_t {
		enum ccs_color_pair tag;
		short int fore;
		short int back;
		const char *name;
	} color_env[] = {
		{ CCS_DOMAIN_HEAD,      COLOR_BLACK,
		  COLOR_GREEN,      "DOMAIN_HEAD" },
		{ CCS_DOMAIN_CURSOR,    COLOR_BLACK,
		  COLOR_GREEN,      "DOMAIN_CURSOR" },
		{ CCS_EXCEPTION_HEAD,   COLOR_BLACK,
		  COLOR_CYAN,       "EXCEPTION_HEAD" },
		{ CCS_EXCEPTION_CURSOR, COLOR_BLACK,
		  COLOR_CYAN,       "EXCEPTION_CURSOR" },
		{ CCS_ACL_HEAD,         COLOR_BLACK,
		  COLOR_YELLOW,     "ACL_HEAD" },
		{ CCS_ACL_CURSOR,       COLOR_BLACK,
		  COLOR_YELLOW,     "ACL_CURSOR" },
		{ CCS_PROFILE_HEAD,     COLOR_WHITE,
		  COLOR_RED,        "PROFILE_HEAD" },
		{ CCS_PROFILE_CURSOR,   COLOR_WHITE,
		  COLOR_RED,        "PROFILE_CURSOR" },
		{ CCS_MANAGER_HEAD,     COLOR_WHITE,
		  COLOR_GREEN,      "MANAGER_HEAD" },
		{ CCS_MANAGER_CURSOR,   COLOR_WHITE,
		  COLOR_GREEN,      "MANAGER_CURSOR" },
		{ CCS_STAT_HEAD,        COLOR_BLACK,
		  COLOR_YELLOW,     "STAT_HEAD" },
		{ CCS_STAT_CURSOR,      COLOR_BLACK,
		  COLOR_YELLOW,     "STAT_CURSOR" },
		{ CCS_DEFAULT_COLOR,    COLOR_WHITE,
		  COLOR_BLACK,      "DEFAULT_COLOR" },
		{ CCS_NORMAL,           COLOR_WHITE,
		  COLOR_BLACK,      NULL }
	};
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
		if (!ccs_str_starts(line, "line_color "))
			continue;
		cp = strchr(line, '=');
		if (!cp)
			continue;
		*cp++ = '\0';
		ccs_normalize_line(line);
		ccs_normalize_line(cp);
		if (!*line || !*cp)
			continue;
		for (i = 0; color_env[i].name; i++) {
			short int fore;
			short int back;
			if (strcmp(line, color_env[i].name))
				continue;
			if (strlen(cp) != 2)
				break;
			fore = (*cp++) - '0'; /* foreground color */
			back = (*cp) - '0';   /* background color */
			if (fore < 0 || fore > 7 || back < 0 || back > 7)
				break;
			color_env[i].fore = fore;
			color_env[i].back = back;
			break;
		}
	}
	ccs_put();
	fclose(fp);
use_default:
	start_color();
	for (i = 0; color_env[i].name; i++) {
		struct ccs_color_env_t *colorp = &color_env[i];
		init_pair(colorp->tag, colorp->fore, colorp->back);
	}
	init_pair(CCS_DISP_ERR, COLOR_RED, COLOR_BLACK); /* error message */
	bkgdset(A_NORMAL | COLOR_PAIR(CCS_DEFAULT_COLOR) | ' ');
	for (i = 0; i < CCS_MAXSCREEN; i++)
		ccs_screen[i].saved_color_current = -1;
}

/**
 * ccs_editpolicy_color_save - Save or load current color.
 *
 * @flg: True if save request, false otherwise.
 *
 * Returns nothing.
 */
static void ccs_editpolicy_color_save(const _Bool flg)
{
	static attr_t save_color = CCS_DEFAULT_COLOR;
	if (flg)
		save_color = getattrs(stdscr);
	else
		attrset(save_color);
}

/**
 * ccs_editpolicy_color_change - Change current color.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void ccs_editpolicy_color_change(const attr_t attr, const _Bool flg)
{
	if (flg)
		attron(COLOR_PAIR(attr));
	else
		attroff(COLOR_PAIR(attr));
}

/**
 * ccs_editpolicy_attr_change - Change current attribute.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void ccs_editpolicy_attr_change(const attr_t attr, const _Bool flg)
{
	if (flg)
		attron(attr);
	else
		attroff(attr);
}

/**
 * ccs_editpolicy_sttr_save - Save current color.
 *
 * Returns nothing.
 */
void ccs_editpolicy_sttr_save(void)
{
	ccs_editpolicy_color_save(true);
}

/**
 * ccs_editpolicy_sttr_restore - Load current color.
 *
 * Returns nothing.
 */
void ccs_editpolicy_sttr_restore(void)
{
	ccs_editpolicy_color_save(false);
}

/**
 * ccs_editpolicy_color_head - Get color to use for header line.
 *
 * Returns one of values in "enum ccs_color_pair".
 */
enum ccs_color_pair ccs_editpolicy_color_head(void)
{
	switch (ccs_current_screen) {
	case CCS_SCREEN_DOMAIN_LIST:
		return CCS_DOMAIN_HEAD;
	case CCS_SCREEN_EXCEPTION_LIST:
		return CCS_EXCEPTION_HEAD;
	case CCS_SCREEN_PROFILE_LIST:
		return CCS_PROFILE_HEAD;
	case CCS_SCREEN_MANAGER_LIST:
		return CCS_MANAGER_HEAD;
	case CCS_SCREEN_STAT_LIST:
		return CCS_STAT_HEAD;
	default:
		return CCS_ACL_HEAD;
	}
}

/**
 * ccs_editpolicy_color_cursor - Get color to use for cursor line.
 *
 * Returns one of values in "enum ccs_color_pair".
 */
static inline enum ccs_color_pair ccs_editpolicy_color_cursor(void)
{
	switch (ccs_current_screen) {
	case CCS_SCREEN_DOMAIN_LIST:
		return CCS_DOMAIN_CURSOR;
	case CCS_SCREEN_EXCEPTION_LIST:
		return CCS_EXCEPTION_CURSOR;
	case CCS_SCREEN_PROFILE_LIST:
		return CCS_PROFILE_CURSOR;
	case CCS_SCREEN_MANAGER_LIST:
		return CCS_MANAGER_CURSOR;
	case CCS_SCREEN_STAT_LIST:
		return CCS_STAT_CURSOR;
	default:
		return CCS_ACL_CURSOR;
	}
}

/**
 * ccs_editpolicy_line_draw - Update colored line.
 *
 * Returns nothing.
 */
void ccs_editpolicy_line_draw(void)
{
	struct ccs_screen *ptr = &ccs_screen[ccs_current_screen];
	const int current = ccs_editpolicy_get_current();
	int y;
	int x;

	if (current == EOF)
		return;

	getyx(stdscr, y, x);
	if (-1 < ptr->saved_color_current &&
	    current != ptr->saved_color_current) {
		move(CCS_HEADER_LINES + ptr->saved_color_y, 0);
		chgat(-1, A_NORMAL, CCS_DEFAULT_COLOR, NULL);
	}

	move(y, x);
	chgat(-1, A_NORMAL, ccs_editpolicy_color_cursor(), NULL);
	touchwin(stdscr);

	ptr->saved_color_current = current;
	ptr->saved_color_y = ptr->y;
}

#else

/**
 * ccs_editpolicy_color_init - Initialize line coloring table.
 *
 * Returns nothing.
 */
void ccs_editpolicy_color_init(void)
{
}

/**
 * ccs_editpolicy_color_change - Change current color.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void ccs_editpolicy_color_change(const attr_t attr, const _Bool flg)
{
}

/**
 * ccs_editpolicy_attr_change - Change current attribute.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void ccs_editpolicy_attr_change(const attr_t attr, const _Bool flg)
{
}

/**
 * ccs_editpolicy_sttr_save - Save current color.
 *
 * Returns nothing.
 */
void ccs_editpolicy_sttr_save(void)
{
}

/**
 * ccs_editpolicy_sttr_restore - Load current color.
 *
 * Returns nothing.
 */
void ccs_editpolicy_sttr_restore(void)
{
}

/**
 * ccs_editpolicy_color_head - Get color to use for header line.
 *
 * Returns one of values in "enum ccs_color_pair".
 */
enum ccs_color_pair ccs_editpolicy_color_head(void)
{
	return CCS_DEFAULT_COLOR;
}

/**
 * ccs_editpolicy_line_draw - Update colored line.
 *
 * Returns nothing.
 */
void ccs_editpolicy_line_draw(void)
{
}

#endif
