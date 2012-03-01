/*
 * ccs_bprm_test.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * Version: 1.7.3   2011/04/01
 *
 */
#include "include.h"

static void try_exec(const char *policy, char *argv[], char *envp[],
		     const char should_success) {
	FILE *fp;
	char buffer[8192];
	int domain_found = 0;
	int policy_found = 0;
	int err = 0;
	int pipe_fd[2] = { EOF, EOF };
	set_profile(3, "file::open");
	fp = fopen(proc_policy_domain_policy, "r");
	set_profile(3, "file::open");
	pipe(pipe_fd);
	printf("%s: ", policy);
	fflush(stdout);
	fprintf(domain_fp, "%s\n", policy);
	if (!fp) {
		printf("BUG: policy read failed\n");
		return;
	}
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		char *cp = strchr(buffer, '\n');
		if (cp)
			*cp = '\0';
		if (!strncmp(buffer, "<kernel>", 8))
			domain_found = !strcmp(self_domain, buffer);
		if (!domain_found)
			continue;
		/* printf("<%s>\n", buffer); */
		if (!strcmp(buffer, policy)) {
			policy_found = 1;
			break;
		}
	}
	fclose(fp);
	if (!policy_found) {
		printf("BUG: policy write failed\n");
		return;
	}
	if (fork() == 0) {
		execve("/bin/true", argv, envp);
		err = errno;
		write(pipe_fd[1], &err, sizeof(err));
		_exit(0);
	}
	close(pipe_fd[1]);
	read(pipe_fd[0], &err, sizeof(err));
	close(pipe_fd[0]);
	fprintf(domain_fp, "delete %s\n", policy);
	if (should_success) {
		if (!err)
			printf("OK\n");
		else
			printf("BUG: failed (%d)\n", err);
	} else {
		if (err == EPERM)
			printf("OK: Permission denied.\n");
		else
			printf("BUG: failed (%d)\n", err);
	}
}

static void stage_exec_test(void)
{
	int i;
	static char *argv[128];
	static char *envp[128];
	for (i = 0; i < 10; i++) {
		memset(argv, 0, sizeof(argv));
		memset(envp, 0, sizeof(envp));

		argv[0] = "/bin/true";
		try_exec("allow_execute /bin/true "
			 "if task.gid=0-100 exec.argc=1", argv, envp, 1);
		argv[0] = NULL;
		try_exec("allow_execute /bin/true "
			 "if task.gid=0-100 exec.argc=1", argv, envp, 0);

		envp[0] = "";
		try_exec("allow_execute /bin/true if task.gid!=100 task.euid=0 "
			 "path1.uid=0 path1.parent.uid=0 exec.envc=1", argv,
			 envp, 1);
		envp[0] = NULL;
		try_exec("allow_execute /bin/true if task.gid!=100 task.euid=0 "
			 "path1.uid=0 path1.parent.uid=0 exec.envc=1", argv,
			 envp, 0);

		argv[0] = "/bin/true";
		argv[1] = "--";
		try_exec("allow_execute /bin/true if 0=0 exec.argc=1-5", argv,
			 envp, 1);
		try_exec("allow_execute /bin/true if 0=0 exec.argc!=1-5", argv,
			 envp, 0);

		envp[0] = "";
		envp[1] = "";
		try_exec("allow_execute /bin/true if task.uid=0 "
			 "task.gid!=1-100 path1.parent.uid!=1 path1.gid=0 "
			 "exec.envc=1-5", argv, envp, 1);
		try_exec("allow_execute /bin/true if task.uid=0 "
			 "task.gid!=1-100 path1.parent.uid!=1 path1.gid=0 "
			 "exec.envc!=1-5", argv, envp, 0);

		argv[0] = "/bin/true";
		argv[1] = "--";
		try_exec("allow_execute /bin/true if task.uid=0 task.gid=0 "
			 "path1.parent.uid=0 path1.uid=0 exec.argv[1]=\"--\"",
			 argv, envp, 1);
		try_exec("allow_execute /bin/true if task.uid=0 task.gid=0 "
			 "path1.parent.uid=0 path1.uid=0 exec.argv[1]!=\"--\"",
			 argv, envp, 0);

		argv[0] = "/bin/true";
		argv[1] = "-";
		try_exec("allow_execute /bin/true if 1!=0 exec.argv[1]=\"--\"",
			 argv, envp, 0);
		try_exec("allow_execute /bin/true if 1!=0 exec.argv[1]!=\"--\"",
			 argv, envp, 1);

		envp[0] = "HOME=/";
		try_exec("allow_execute /bin/true if task.euid=0 "
			 "exec.envp[\"HOME\"]!=NULL", argv, envp, 1);
		try_exec("allow_execute /bin/true if task.euid=0 "
			 "exec.envp[\"HOME\"]=NULL", argv, envp, 0);
		try_exec("allow_execute /bin/true if 0!=1 "
			 "exec.envp[\"HOME\"]=\"/\"", argv, envp, 1);
		try_exec("allow_execute /bin/true if 0!=1 "
			 "exec.envp[\"HOME\"]!=\"/\"", argv, envp, 0);

		envp[0] = "HOME2=/";
		try_exec("allow_execute /bin/true if path1.uid=0 "
			 "exec.envp[\"HOME\"]!=NULL", argv, envp, 0);
		try_exec("allow_execute /bin/true if path1.uid=0 "
			 "exec.envp[\"HOME\"]=NULL", argv, envp, 1);
		try_exec("allow_execute /bin/true if 100=1-1000 "
			 "exec.envp[\"HOME\"]=\"/\"", argv, envp, 0);
		try_exec("allow_execute /bin/true if 100=1-1000 "
			 "exec.envp[\"HOME\"]!=\"/\"", argv, envp, 1);
		try_exec("allow_execute /bin/true if path1.parent.gid!=100 "
			 "exec.envp[\"HOME\"]!=NULL exec.envp[\"HOME3\"]=NULL",
			 argv, envp, 0);
		try_exec("allow_execute /bin/true if path1.parent.gid!=100 "
			 "exec.envp[\"HOME\"]=NULL exec.envp[\"HOME3\"]=NULL",
			 argv, envp, 1);
		try_exec("allow_execute /bin/true if path1.parent.gid=0 "
			 "exec.envp[\"HOME\"]=\"/\" exec.envp[\"HOME3\"]=NULL",
			 argv, envp, 0);
		try_exec("allow_execute /bin/true if path1.parent.gid=0 "
			 "exec.envp[\"HOME\"]!=\"/\" exec.envp[\"HOME3\"]=NULL",
			 argv, envp, 1);
	}
}

int main(int argc, char *argv[])
{
	ccs_test_init();
	fprintf(domain_fp, "%s /bin/true\n", self_domain);
	fprintf(domain_fp, "use_profile 255\n");
	fprintf(domain_fp, "select pid=%u\n", pid);
	fprintf(domain_fp, "allow_read/write %s\n", proc_policy_domain_policy);
	set_profile(3, "file::execute");
	stage_exec_test();
	set_profile(3, "file::execute");
	clear_status();
	return 0;
}
