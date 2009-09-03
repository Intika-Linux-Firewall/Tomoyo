/*
 * ccs_filesystem_test.c
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0-pre   2009/08/24
 *
 */
#define _GNU_SOURCE
#include "include.h"

static void show_prompt(const char *str, const int should_fail)
{
	printf("Testing %60s: (%s) ", str,
	       should_fail ? "must fail" : "should success");
	errno = 0;
}

#ifndef MS_MOVE
#define MS_MOVE         8192
#endif

static const char *pivot_root_dir = "/proc/";

static int child(void *arg)
{
	errno = 0;
	pivot_root(pivot_root_dir, proc_policy_dir);
	return errno;
}

static void mount2(const char *source, const char *target,
		   const char *filesystemtype)
{
	if (mount(source, target, filesystemtype, 0, NULL)) {
		printf("BUG: mount() failed\n");
		fflush(stdout);
	}
}

int main(int argc, char *argv[])
{
	char c = 0;
	ccs_test_init();

	/* Test mount(). */
	{
		set_profile(3, "file::mount");
		show_prompt("mount('dev\\011name', '/', 'fs\\011name') ", 1);
		if (mount("dev\tname", "/", "fs\tname", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else if (errno == ENODEV)
			printf("OK: No such device.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		set_profile(1, "file::mount");
		show_prompt("mount('dev\\011name', '/', 'fs\\011name') ", 0);
		if (mount("dev\tname", "/", "fs\tname", 0, NULL) == EOF &&
		    errno == ENOMEM)
			printf("OK: Out of memory.\n");
		else if (errno == ENODEV)
			printf("OK: No such device.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		set_profile(3, "file::mount");
		show_prompt("mount('dev\\011name', '/', 'fs\\011name') ", 0);
		if (mount("dev\tname", "/", "fs\tname", 0, NULL) == EOF &&
		    errno == ENOMEM)
			printf("OK: Out of memory.\n");
		else if (errno == ENODEV)
			printf("OK: No such device.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		fprintf(domain_fp, "delete allow_mount dev\\011name / "
			"fs\\011name 0\n");
		show_prompt("mount('dev\\011name', '/', 'fs\\011name') ", 1);
		if (mount("dev\tname", "/", "fs\tname", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else if (errno == ENODEV)
			printf("OK: No such device.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		set_profile(1, "file::mount");
		show_prompt("mount(NULL, '/', 'tmpfs') ", 0);
		if (mount(NULL, "/", "tmpfs", 0, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success\n");
		set_profile(3, "file::mount");
		show_prompt("mount(NULL, '/', 'tmpfs') ", 0);
		if (mount(NULL, "/", "tmpfs", 0, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success\n");
		show_prompt("mount('anydev', '/', 'tmpfs') ", 0);
		if (mount("anydev", "/", "tmpfs", 0, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success\n");
		fprintf(domain_fp, "delete allow_mount <NULL> / tmpfs 0\n");
		fprintf(domain_fp, "allow_mount anydev / tmpfs 0\n");
		show_prompt("mount(NULL, '/', 'tmpfs') ", 0);
		if (mount(NULL, "/", "tmpfs", 0, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success\n");
		fprintf(domain_fp, "delete allow_mount anydev / tmpfs 0\n");
		set_profile(2, "file::mount");
		show_prompt("mount(NULL, NULL, 'tmpfs') ", 1);
		if (mount(NULL, NULL, "tmpfs", 0, NULL))
			printf("OK: %s\n", strerror(errno));
		else
			printf("BUG: Did not fail.\n");
		show_prompt("mount(NULL, NULL, NULL) ", 1);
		if (mount(NULL, NULL, NULL, 0, NULL))
			printf("OK: %s\n", strerror(errno));
		else
			printf("BUG: Did not fail.\n");
		show_prompt("mount('/', NULL, NULL) ", 1);
		if (mount("/", NULL, NULL, 0, NULL))
			printf("OK: %s\n", strerror(errno));
		else
			printf("BUG: Did not fail.\n");
		show_prompt("mount('/', NULL, 'tmpfs') ", 1);
		if (mount("/", NULL, "tmpfs", 0, NULL))
			printf("OK: %s\n", strerror(errno));
		else
			printf("BUG: Did not fail.\n");
		show_prompt("mount('/', '/', 'nonexistentfs') ", 1);
		if (mount("/", "/", "nonexistentfs", 0, NULL))
			printf("OK: %s\n", strerror(errno));
		else
			printf("BUG: Did not fail.\n");
		set_profile(0, "file::mount");
	}

	mkdir("/tmp/mount/", 0755);
	mkdir("/tmp/mount_bind/", 0755);
	mkdir("/tmp/mount_move/", 0755);

	/* Test mount(). */
	{
		static char buf[4096];
		char *dev_ram_path = canonicalize_file_name("/dev/ram0");
		if (!dev_ram_path)
			dev_ram_path = canonicalize_file_name("/dev/ram");
		if (!dev_ram_path) {
			dev_ram_path = "/dev/ram0";
			mknod(dev_ram_path, S_IFBLK, MKDEV(1, 0));
		}
		memset(buf, 0, sizeof(buf));
		set_profile(3, "file::mount");

		/* Test standard case */
		show_prompt("mount('none', '/tmp/mount/', 'tmpfs') for "
			    "'/tmp/mount/'", 1);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test device_name with pattern */
		snprintf(buf, sizeof(buf) - 1, "mount('%s', '/tmp/mount/', "
			 "'ext2') for '%s\\*'", dev_ram_path, dev_ram_path);
		show_prompt(buf, 1);
		if (mount(dev_ram_path, "/tmp/mount/", "ext2", MS_RDONLY, NULL)
		    == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test dir_name with pattern */
		show_prompt("mount('none', '/tmp/mount/', 'tmpfs') for "
			    "'/tmp/\\?\\?\\?\\?\\?/'", 1);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test standard case */
		fprintf(domain_fp, "allow_mount none /tmp/mount/ tmpfs 0\n");
		show_prompt("mount('none', '/tmp/mount/', 'tmpfs') for "
			    "'/tmp/mount/'", 0);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		fprintf(domain_fp,
			"delete allow_mount none /tmp/mount/ tmpfs 0\n");

		/* Test device_name with pattern */
		fprintf(domain_fp, "allow_mount %s\\* /tmp/mount/ ext2 1\n",
			dev_ram_path);
		snprintf(buf, sizeof(buf) - 1, "mount('%s', '/tmp/mount/', "
			 "'ext2') for '%s\\*'", dev_ram_path, dev_ram_path);
		show_prompt(buf, 0);
		if (mount(dev_ram_path, "/tmp/mount/", "ext2", MS_RDONLY, NULL)
		    == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		fprintf(domain_fp, "delete allow_mount %s\\* "
			"/tmp/mount/ ext2 1\n", dev_ram_path);

		/* Test dir_name with pattern */
		fprintf(domain_fp,
			"allow_mount none /tmp/\\?\\?\\?\\?\\?/ tmpfs 0\n");
		show_prompt("mount('none', '/tmp/mount/', 'tmpfs') for "
			    "'/tmp/\\?\\?\\?\\?\\?/'", 0);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		fprintf(domain_fp, "delete allow_mount none "
			"/tmp/\\?\\?\\?\\?\\?/ tmpfs 0\n");

		set_profile(0, "file::mount");
		while (umount("/tmp/mount/") == 0)
			c++; /* Dummy. */
	}

	/* Test mount(). */
	{
		mount2("none", "/tmp/mount/", "tmpfs");
		set_profile(3, "file::mount");

		/* Test remount case */
		show_prompt("mount('/tmp/mount/', MS_REMOUNT)", 1);
		if (mount("none", "/tmp/mount/", "tmpfs", MS_REMOUNT, NULL)
		    == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		show_prompt("mount('/tmp/mount/', MS_REMOUNT)", 1);
		if (mount(NULL, "/tmp/mount/", NULL, MS_REMOUNT, NULL) == EOF
		    && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		fprintf(domain_fp, "allow_mount something /tmp/mount/ "
			"--remount 0\n");
		show_prompt("mount('/tmp/mount/', MS_REMOUNT)", 0);
		if (mount(NULL, "/tmp/mount/", NULL, MS_REMOUNT, NULL))
			printf("BUG: %s\n", strerror(errno));
		else
			printf("OK: Success.\n");
		fprintf(domain_fp, "delete allow_mount something /tmp/mount/ "
			"--remount 0\n");

		/* Test bind case */
		show_prompt("mount('/tmp/mount/', '/tmp/mount_bind/', "
			    "MS_BIND)", 1);
		if (mount("/tmp/mount/", "/tmp/mount_bind/", NULL, MS_BIND,
			  NULL) == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test move case */
		show_prompt("mount('/tmp/mount/', '/tmp/mount_move/', "
			    "MS_MOVE)", 1);
		if (mount("/tmp/mount/", "/tmp/mount_move/", NULL, MS_MOVE,
			  NULL) == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		/* Test remount case */
		fprintf(domain_fp,
			"allow_mount any /tmp/mount/ --remount 0\n");
		show_prompt("mount('/tmp/mount/', MS_REMOUNT)", 0);
		if (mount("none", "/tmp/mount/", "tmpfs", MS_REMOUNT, NULL)
		    == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		fprintf(domain_fp, "delete allow_mount any /tmp/mount/ "
			"--remount 0\n");

		/* Test bind case */
		fprintf(domain_fp,
			"allow_mount /tmp/mount/ /tmp/mount_bind/ --bind 0\n");
		show_prompt("mount('/tmp/mount/', '/tmp/mount_bind', MS_BIND)",
			    0);
		if (mount("/tmp/mount/", "/tmp/mount_bind/", NULL, MS_BIND,
			  NULL) == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		set_profile(0, "file::mount");
		umount("/tmp/mount_bind/");
		fprintf(domain_fp, "delete allow_mount /tmp/mount/ "
			"/tmp/mount_bind/ --bind 0\n");

		/* Test move case */
		set_profile(3, "file::mount");
		fprintf(domain_fp, "allow_unmount /tmp/mount/\n");
		fprintf(domain_fp, "allow_mount /tmp/mount/ /tmp/mount_move/ "
			"--move 0\n");
		show_prompt("mount('/tmp/mount/', '/tmp/mount_move/', "
			    "MS_MOVE)", 0);
		if (mount("/tmp/mount/", "/tmp/mount_move/", NULL, MS_MOVE,
			  NULL) == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));
		set_profile(0, "file::mount");
		umount("/tmp/mount_move/");
		fprintf(domain_fp, "delete allow_unmount /tmp/mount/\n");
		fprintf(domain_fp, "delete allow_mount /tmp/mount/ "
			"/tmp/mount_move/ --move 0\n");

		while (umount("/tmp/mount/") == 0)
			c++; /* Dummy. */
	}

	/* Test mount(). */
	{
		show_prompt("mount('none', '/tmp/mount/', 'tmpfs')", 0);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == 0)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));
		set_profile(3, "capability::conceal_mount");

		show_prompt("mount('none', '/tmp/mount/', 'tmpfs')", 1);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		show_prompt("mount('none', '/tmp/', 'tmpfs')", 1);
		if (mount("none", "/tmp/", "tmpfs", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		show_prompt("mount('none', '/', 'tmpfs')", 1);
		if (mount("none", "/", "tmpfs", 0, NULL) == EOF &&
		    errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		set_profile(2, "capability::conceal_mount");

		show_prompt("mount('none', '/tmp/mount/', 'tmpfs')", 0);
		if (mount("none", "/tmp/mount/", "tmpfs", 0, NULL) == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));

		set_profile(0, "capability::conceal_mount");
		while (umount("/tmp/mount/") == 0)
			c++; /* Dummy. */
	}

	/* Test umount(). */
	{
		/* Test standard case */
		fprintf(domain_fp, "allow_unmount /tmp/mount/\n");

		set_profile(0, "file::umount");
		mount2("none", "/tmp/mount/", "tmpfs");
		set_profile(3, "file::umount");
		show_prompt("umount('/tmp/mount/') for '/tmp/mount/'", 0);
		if (umount("/tmp/mount/") == 0)
			printf("OK\n");
		else
			printf("BUG: %s\n", strerror(errno));
		fprintf(domain_fp, "delete allow_unmount /tmp/mount/\n");

		set_profile(0, "file::umount");

		mount2("none", "/tmp/mount/", "tmpfs");
		set_profile(3, "file::umount");
		show_prompt("umount('/tmp/mount/') for '/tmp/mount/'", 1);
		if (umount("/tmp/mount/") == EOF && errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("FAILED: %s\n", strerror(errno));

		/* Test pattern */
		fprintf(domain_fp, "allow_unmount /tmp/\\?\\?\\?\\?\\?/\n");
		set_profile(0, "file::umount");
		mount2("none", "/tmp/mount/", "tmpfs");
		set_profile(3, "file::umount");
		show_prompt("umount('/tmp/mount/') for "
			    "'/tmp/\\?\\?\\?\\?\\?/'", 1);
		if (umount("/tmp/mount/") == 0)
			printf("OK\n");
		else
			printf("BUG: %s\n", strerror(errno));
		fprintf(domain_fp,
			"delete allow_unmount /tmp/\\?\\?\\?\\?\\?/\n");

		set_profile(0, "file::umount");
		while (umount("/tmp/mount/") == 0)
			c++; /* Dummy. */
	}

	/* Test chroot(). */
	{
		set_profile(3, "file::chroot");

		/* Test standard case */
		fprintf(domain_fp, "allow_chroot /tmp/mount/\n");
		show_prompt("chroot('/tmp/mount/') for '/tmp/mount/'", 0);
		fflush(stdout);
		if (fork() == 0) {
			if (chroot("/tmp/mount/") == 0)
				printf("OK\n");
			else
				printf("FAILED: %s\n", strerror(errno));
			fflush(stdout);
			_exit(0);
		}
		wait(NULL);
		fprintf(domain_fp, "delete allow_chroot /tmp/mount/\n");

		show_prompt("chroot('/tmp/mount/') for '/tmp/mount/'", 1);
		fflush(stdout);
		if (fork() == 0) {
			if (chroot("/tmp/mount/") == EOF && errno == EPERM)
				printf("OK: Permission denied.\n");
			else
				printf("BUG: %s\n", strerror(errno));
			fflush(stdout);
			_exit(0);
		}
		wait(NULL);

		/* Test pattern */
		fprintf(domain_fp, "allow_chroot /tmp/\\?\\?\\?\\?\\?/\n");
		show_prompt("chroot('/tmp/mount/') for "
			    "'/tmp/\\?\\?\\?\\?\\?/'", 0);
		fflush(stdout);
		if (fork() == 0) {
			if (chroot("/tmp/mount/") == 0)
				printf("OK\n");
			else
				printf("FAILED: %s\n", strerror(errno));
			fflush(stdout);
			_exit(0);
		}
		wait(NULL);
		fprintf(domain_fp,
			"delete allow_chroot /tmp/\\?\\?\\?\\?\\?/\n");

		set_profile(0, "file::chroot");
	}

	/* Test pivot_root(). */
	{
		int error;
		char *stack = malloc(8192);
		set_profile(3, "file::pivot_root");
		fprintf(domain_fp, "allow_pivot_root %s %s\n",
			 pivot_root_dir, proc_policy_dir);
		snprintf(stack, 8191, "pivot_root('%s', '%s')", pivot_root_dir,
			 proc_policy_dir);
		show_prompt(stack, 0);
		{
			const pid_t pid = clone(child, stack + (8192 / 2),
						CLONE_NEWNS, NULL);
			while (waitpid(pid, &error, __WALL) == EOF &&
			       errno == EINTR)
				c++; /* Dummy. */
		}
		errno = WIFEXITED(error) ? WEXITSTATUS(error) : -1;
		if (errno == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));

		fprintf(domain_fp, "delete allow_pivot_root %s %s\n",
			pivot_root_dir, proc_policy_dir);
		snprintf(stack, 8191, "pivot_root('%s', '%s')", pivot_root_dir,
			 proc_policy_dir);
		show_prompt(stack, 1);
		{
			const pid_t pid = clone(child, stack + (8192 / 2),
						CLONE_NEWNS, NULL);
			while (waitpid(pid, &error, __WALL) == EOF &&
			       errno == EINTR)
				c++; /* Dummy. */
		}
		errno = WIFEXITED(error) ? WEXITSTATUS(error) : -1;
		if (errno == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: %s\n", strerror(errno));

		set_profile(2, "file::pivot_root");
		snprintf(stack, 8191, "pivot_root('%s', '%s')", pivot_root_dir,
			 proc_policy_dir);
		show_prompt(stack, 0);
		{
			const pid_t pid = clone(child, stack + (8192 / 2),
						CLONE_NEWNS, NULL);
			while (waitpid(pid, &error, __WALL) == EOF &&
			       errno == EINTR)
				c++; /* Dummy. */
		}
		errno = WIFEXITED(error) ? WEXITSTATUS(error) : -1;
		if (errno == 0)
			printf("OK\n");
		else
			printf("FAILED: %s\n", strerror(errno));

		set_profile(0, "file::pivot_root");

		free(stack);
	}

	rmdir("/tmp/mount_move/");
	rmdir("/tmp/mount_bind/");
	rmdir("/tmp/mount/");

	clear_status();
	return 0;
}
