/*
 * editpolicy_color.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.8.3+   2015/04/21
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

#ifdef COLOR_ON

/**
 * editpolicy_color_init - Initialize line coloring table.
 *
 * Returns nothing.
 */
void editpolicy_color_init(void)
{
	static struct ccs_color_env_t {
		enum color_type tag;
		short int fore;
		short int back;
		const char *name;
	} color_env[] = {
		{ COLOR_DOMAIN_HEAD,      COLOR_BLACK,
		  COLOR_GREEN,      "DOMAIN_HEAD" },
		{ COLOR_DOMAIN_CURSOR,    COLOR_BLACK,
		  COLOR_GREEN,      "DOMAIN_CURSOR" },
		{ COLOR_EXCEPTION_HEAD,   COLOR_BLACK,
		  COLOR_CYAN,       "EXCEPTION_HEAD" },
		{ COLOR_EXCEPTION_CURSOR, COLOR_BLACK,
		  COLOR_CYAN,       "EXCEPTION_CURSOR" },
		{ COLOR_ACL_HEAD,         COLOR_BLACK,
		  COLOR_YELLOW,     "ACL_HEAD" },
		{ COLOR_ACL_CURSOR,       COLOR_BLACK,
		  COLOR_YELLOW,     "ACL_CURSOR" },
		{ COLOR_PROFILE_HEAD,     COLOR_WHITE,
		  COLOR_RED,        "PROFILE_HEAD" },
		{ COLOR_PROFILE_CURSOR,   COLOR_WHITE,
		  COLOR_RED,        "PROFILE_CURSOR" },
		{ COLOR_MANAGER_HEAD,     COLOR_WHITE,
		  COLOR_GREEN,      "MANAGER_HEAD" },
		{ COLOR_MANAGER_CURSOR,   COLOR_WHITE,
		  COLOR_GREEN,      "MANAGER_CURSOR" },
		{ COLOR_STAT_HEAD,        COLOR_BLACK,
		  COLOR_YELLOW,     "STAT_HEAD" },
		{ COLOR_STAT_CURSOR,      COLOR_BLACK,
		  COLOR_YELLOW,     "STAT_CURSOR" },
		{ COLOR_DEFAULT_COLOR,    COLOR_WHITE,
		  COLOR_BLACK,      "DEFAULT_COLOR" },
		{ COLOR_NORMAL,           COLOR_WHITE,
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
	init_pair(COLOR_DISP_ERR, COLOR_RED, COLOR_BLACK); /* error message */
	bkgdset(A_NORMAL | COLOR_PAIR(COLOR_DEFAULT_COLOR) | ' ');
	for (i = 0; i < MAX_SCREEN_TYPE; i++)
		screen[i].saved_color_current = -1;
}

/**
 * editpolicy_color_save - Save or load current color.
 *
 * @flg: True if save request, false otherwise.
 *
 * Returns nothing.
 */
static void editpolicy_color_save(const _Bool flg)
{
	static attr_t save_color = COLOR_DEFAULT_COLOR;
	if (flg)
		save_color = getattrs(stdscr);
	else
		attrset(save_color);
}

/**
 * editpolicy_color_change - Change current color.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void editpolicy_color_change(const attr_t attr, const _Bool flg)
{
	if (flg)
		attron(COLOR_PAIR(attr));
	else
		attroff(COLOR_PAIR(attr));
}

/**
 * editpolicy_attr_change - Change current attribute.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void editpolicy_attr_change(const attr_t attr, const _Bool flg)
{
	if (flg)
		attron(attr);
	else
		attroff(attr);
}

/**
 * editpolicy_sttr_save - Save current color.
 *
 * Returns nothing.
 */
void editpolicy_sttr_save(void)
{
	editpolicy_color_save(true);
}

/**
 * editpolicy_sttr_restore - Load current color.
 *
 * Returns nothing.
 */
void editpolicy_sttr_restore(void)
{
	editpolicy_color_save(false);
}

/**
 * editpolicy_color_head - Get color to use for header line.
 *
 * Returns one of values in "enum color_type".
 */
enum color_type editpolicy_color_head(void)
{
	switch (active) {
	case SCREEN_DOMAIN_LIST:
		return COLOR_DOMAIN_HEAD;
	case SCREEN_EXCEPTION_LIST:
		return COLOR_EXCEPTION_HEAD;
	case SCREEN_PROFILE_LIST:
		return COLOR_PROFILE_HEAD;
	case SCREEN_MANAGER_LIST:
		return COLOR_MANAGER_HEAD;
	case SCREEN_STAT_LIST:
		return COLOR_STAT_HEAD;
	default:
		return COLOR_ACL_HEAD;
	}
}

/**
 * editpolicy_color_cursor - Get color to use for cursor line.
 *
 * Returns one of values in "enum color_type".
 */
static inline enum color_type editpolicy_color_cursor(void)
{
	switch (active) {
	case SCREEN_DOMAIN_LIST:
		return COLOR_DOMAIN_CURSOR;
	case SCREEN_EXCEPTION_LIST:
		return COLOR_EXCEPTION_CURSOR;
	case SCREEN_PROFILE_LIST:
		return COLOR_PROFILE_CURSOR;
	case SCREEN_MANAGER_LIST:
		return COLOR_MANAGER_CURSOR;
	case SCREEN_STAT_LIST:
		return COLOR_STAT_CURSOR;
	default:
		return COLOR_ACL_CURSOR;
	}
}

/**
 * editpolicy_line_draw - Update colored line.
 *
 * Returns nothing.
 */
void editpolicy_line_draw(void)
{
	struct ccs_screen *ptr = &screen[active];
	const int current = editpolicy_get_current();
	int y;
	int x;

	if (current == EOF)
		return;

	getyx(stdscr, y, x);
	if (-1 < ptr->saved_color_current &&
	    current != ptr->saved_color_current) {
		move(CCS_HEADER_LINES + ptr->saved_color_y, 0);
		chgat(-1, A_NORMAL, COLOR_DEFAULT_COLOR, NULL);
	}

	move(y, x);
	chgat(-1, A_NORMAL, editpolicy_color_cursor(), NULL);
	touchwin(stdscr);

	ptr->saved_color_current = current;
	ptr->saved_color_y = ptr->y;
}

#else

/**
 * editpolicy_color_init - Initialize line coloring table.
 *
 * Returns nothing.
 */
void editpolicy_color_init(void)
{
}

/**
 * editpolicy_color_change - Change current color.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void editpolicy_color_change(const attr_t attr, const _Bool flg)
{
}

/**
 * editpolicy_attr_change - Change current attribute.
 *
 * @attr: Coloe to use.
 * @flg:  True if turn on, false otherwise.
 *
 * Returns nothing.
 */
void editpolicy_attr_change(const attr_t attr, const _Bool flg)
{
}

/**
 * editpolicy_sttr_save - Save current color.
 *
 * Returns nothing.
 */
void editpolicy_sttr_save(void)
{
}

/**
 * editpolicy_sttr_restore - Load current color.
 *
 * Returns nothing.
 */
void editpolicy_sttr_restore(void)
{
}

/**
 * editpolicy_color_head - Get color to use for header line.
 *
 * Returns one of values in "enum color_type".
 */
enum color_type editpolicy_color_head(void)
{
	return COLOR_DEFAULT_COLOR;
}

/**
 * editpolicy_line_draw - Update colored line.
 *
 * Returns nothing.
 */
void editpolicy_line_draw(void)
{
}

#endif
