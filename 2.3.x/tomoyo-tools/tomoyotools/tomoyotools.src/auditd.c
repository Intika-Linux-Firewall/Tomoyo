/*
 * auditd.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2009  NTT DATA CORPORATION
 *
 * Version: 1.7.0   2009/09/03
 *
 */
#include "tomoyotools.h"

int auditd_main(int argc, char *argv[])
{
	const char *procfile_path[TOMOYO_AUDITD_MAX_FILES] = {
		proc_policy_grant_log,
		proc_policy_reject_log
	};
	int i;
	int fd_in[TOMOYO_AUDITD_MAX_FILES];
	FILE *fp_out[TOMOYO_AUDITD_MAX_FILES];
	int need_flush = 0;
	const char *logfile_path[2] = { "/dev/null", "/dev/null" };
	if (access(procfile_path[0], R_OK) || access(procfile_path[1], R_OK)) {
		fprintf(stderr, "You can't run this daemon for this kernel.\n");
		return 0;
	}
	if (argc < 3) {
		fprintf(stderr, "%s grant_log_file reject_log_file\n"
			"  These files may /dev/null, if needn't to be saved."
			"\n", argv[0]);
		return 0;
	}
	logfile_path[0] = argv[1];
	logfile_path[1] = argv[2];
	{ /* Get exclusive lock. */
		int fd = open("/proc/self/exe", O_RDONLY);
		if (flock(fd, LOCK_EX | LOCK_NB) == EOF)
			return 0;
	}
	umask(077);
	for (i = 0; i < TOMOYO_AUDITD_MAX_FILES; i++) {
		fp_out[i] = fopen(logfile_path[i], "a");
		if (!fp_out[i]) {
			fprintf(stderr, "Can't open %s for writing.\n",
				logfile_path[i]);
			return 1;
		}
	}
	switch (fork()) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "Can't fork()\n");
		return 1;
	default:
		return 0;
	}
	if (setsid() == EOF) {
		fprintf(stderr, "Can't setsid()\n");
		return 1;
	}
	switch (fork()) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "Can't fork()\n");
		return 1;
	default:
		return 0;
	}
	if (chdir("/")) {
		fprintf(stderr, "Can't chdir()\n");
		return 1;
	}
	close(0);
	close(1);
	close(2);
	openlog("tomoyo-auditd", 0,  LOG_USER);
	for (i = 0; i < TOMOYO_AUDITD_MAX_FILES; i++) {
		fd_in[i] = open(procfile_path[i], O_RDONLY);
		if (fd_in[i] == EOF) {
			syslog(LOG_WARNING, "Can't open %s for reading.\n",
			       procfile_path[i]);
			return 1;
		}
	}
	syslog(LOG_WARNING, "Started.\n");
	while (true) {
		char buffer[32768];
		fd_set rfds;
		FD_ZERO(&rfds);
		for (i = 0; i < TOMOYO_AUDITD_MAX_FILES; i++)
			FD_SET(fd_in[i], &rfds);
		/* Wait for data. */
		if (need_flush) {
			struct timeval tv = { 1, 0 };
			need_flush = 0;
			if (select(FD_SETSIZE, &rfds, NULL, NULL, &tv) == 0) {
				fflush(fp_out[0]);
				fflush(fp_out[1]);
			}
		} else if (select(FD_SETSIZE, &rfds, NULL, NULL, NULL) == EOF)
			break;
		for (i = 0; i < TOMOYO_AUDITD_MAX_FILES; i++) {
			time_t stamp;
			char *cp;
			if (!FD_ISSET(fd_in[i], &rfds))
				continue;
			memset(buffer, 0, sizeof(buffer));
			if (read(fd_in[i], buffer, sizeof(buffer) - 1) < 0)
				continue;
			/* Open destination file. */
			if (access(logfile_path[i], F_OK)) {
				fclose(fp_out[i]);
				fp_out[i] = fopen(logfile_path[i], "a");
				if (!fp_out[i]) {
					syslog(LOG_WARNING,
					       "Can't open %s for writing.\n",
					       logfile_path[i]);
					goto out;
				}
			}
			cp = strchr(buffer, ' ');
			if (sscanf(buffer, "#timestamp=%lu", &stamp) == 1
			    && cp) {
				struct tm *tm = localtime(&stamp);
				fprintf(fp_out[i],
					"#%04d-%02d-%02d %02d:%02d:%02d#%s\n",
					tm->tm_year + 1900, tm->tm_mon + 1,
					tm->tm_mday, tm->tm_hour, tm->tm_min,
					tm->tm_sec, cp);
			} else
				fprintf(fp_out[i], "%s\n", buffer);
			need_flush = 1;
		}
	}
out:
	syslog(LOG_WARNING, "Terminated.\n");
	closelog();
	return 0;
}
