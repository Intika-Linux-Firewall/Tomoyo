/*
 * dummyfs.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 2.5.0   2011/09/29
 *
 * This dummy filesystem is for 2.6.29. Build with "obj-y += dummyfs.o".
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
#include <linux/fs.h>
#include <linux/init.h>

static int dummy_get_sb(struct file_system_type *fs_type,
			int flags, const char *dev_name, void *data,
			struct vfsmount *mnt)
{
	return -ENOMEM;
}

static struct file_system_type dummy_fs_type = {
	.name       = "fs\tname",
	.get_sb     = dummy_get_sb,
	.kill_sb    = kill_litter_super,
};

static int __init dummyfs_init(void)
{
	return register_filesystem(&dummy_fs_type);
}

__initcall(dummyfs_init);
