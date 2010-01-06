/*
 * editpolicy_offline.c
 *
 * TOMOYO Linux's utilities.
 *
 * Copyright (C) 2005-2010  NTT DATA CORPORATION
 *
 * Version: 1.7.1+   2010/01/04
 *
 */
#include "ccstools.h"

struct misc_policy {
	const struct path_info **list;
	int list_len;
};

/* Prototypes */

static void handle_misc_policy(struct misc_policy *mp, FILE *fp,
			       _Bool is_write);

/* Utility functions */

static void handle_misc_policy(struct misc_policy *mp, FILE *fp, _Bool is_write)
{
	int i;
	if (!is_write)
		goto read_policy;
	while (true) {
		char *line = freadline(fp);
		const struct path_info *cp;
		_Bool is_delete;
		if (!line)
			break;
		if (!line[0])
			continue;
		is_delete = str_starts(line, "delete ");
		cp = savename(line);
		if (!cp)
			out_of_memory();
		if (!is_delete)
			goto append_policy;
		for (i = 0; i < mp->list_len; i++)
			/* Faster comparison, for they are savename'd. */
			if (mp->list[i] == cp)
				break;
		if (i < mp->list_len)
			for (mp->list_len--; i < mp->list_len; i++)
				mp->list[i] = mp->list[i + 1];
		continue;
append_policy:
		for (i = 0; i < mp->list_len; i++)
			/* Faster comparison, for they are savename'd. */
			if (mp->list[i] == cp)
				break;
		if (i < mp->list_len)
			continue;
		mp->list = realloc(mp->list, (mp->list_len + 1)
				   * sizeof(const struct path_info *));
		if (!mp->list)
			out_of_memory();
		mp->list[mp->list_len++] = cp;
	}
	return;
read_policy:
	for (i = 0; i < mp->list_len; i++)
		fprintf(fp, "%s\n", mp->list[i]->name);
}

/* Variables */

int persistent_fd = EOF;

/* Main functions */

void send_fd(char *data, int *fd)
{
	struct msghdr msg;
	struct iovec iov = { data, strlen(data) };
	char cmsg_buf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg = (struct cmsghdr *) cmsg_buf;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	msg.msg_controllen = cmsg->cmsg_len;
	memmove(CMSG_DATA(cmsg), fd, sizeof(int));
	sendmsg(persistent_fd, &msg, 0);
	close(*fd);
}

void editpolicy_offline_daemon(void)
{
	struct misc_policy mp[3];
	struct domain_policy dp;
	static const int buffer_len = 8192;
	char *buffer = malloc(buffer_len);
	if (!buffer)
		out_of_memory();
	memset(&dp, 0, sizeof(dp));
	memset(&mp, 0, sizeof(mp));
	find_or_assign_new_domain(&dp, ROOT_NAME, false, false);
	while (true) {
		FILE *fp;
		struct msghdr msg;
		struct iovec iov = { buffer, buffer_len - 1 };
		char cmsg_buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr *cmsg = (struct cmsghdr *) cmsg_buf;
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsg_buf;
		msg.msg_controllen = sizeof(cmsg_buf);
		memset(buffer, 0, buffer_len);
		errno = 0;
		if (recvmsg(persistent_fd, &msg, 0) <= 0)
			break;
		cmsg = CMSG_FIRSTHDR(&msg);
		if (!cmsg)
			break;
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS &&
		    cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
			const int *fdp = (int *) CMSG_DATA(cmsg);
			const int fd = *fdp;
			fp = fdopen(fd, "w+");
			if (!fp) {
				close(fd);
				continue;
			}
		} else {
			break;
		}
		if (str_starts(buffer, "POST ")) {
			if (!strcmp(buffer, proc_policy_domain_policy))
				handle_domain_policy(&dp, fp, true);
			else if (!strcmp(buffer, proc_policy_exception_policy))
				handle_misc_policy(&mp[0], fp, true);
			else if (!strcmp(buffer, proc_policy_profile))
				handle_misc_policy(&mp[1], fp, true);
			else if (!strcmp(buffer, proc_policy_manager))
				handle_misc_policy(&mp[2], fp, true);
		} else if (str_starts(buffer, "GET ")) {
			if (!strcmp(buffer, proc_policy_domain_policy))
				handle_domain_policy(&dp, fp, false);
			else if (!strcmp(buffer, proc_policy_exception_policy))
				handle_misc_policy(&mp[0], fp, false);
			else if (!strcmp(buffer, proc_policy_profile))
				handle_misc_policy(&mp[1], fp, false);
			else if (!strcmp(buffer, proc_policy_manager))
				handle_misc_policy(&mp[2], fp, false);
		}
		fclose(fp);
	}
	clear_domain_policy(&dp);
	{
		int i;
		for (i = 0; i < 3; i++) {
			free(mp[i].list);
			mp[i].list = NULL;
			mp[i].list_len = 0;
		}
	}
	free(buffer);
	_exit(0);
}
