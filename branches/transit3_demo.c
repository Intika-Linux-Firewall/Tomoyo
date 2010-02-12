#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static void show_self_domain(void)
{
	FILE *fp = fopen("/proc/ccs/self_domain", "r");
	char buffer[8192];
	memset(buffer, 0, sizeof(buffer));
	fgets(buffer, sizeof(buffer) - 1, fp);
	puts(buffer);
	fclose(fp);
}

int main(int argc, char *argv[]) {
	char *cp;
	const int fd = open("/proc/ccs/.transition", O_WRONLY);
	if (fd == EOF)
		return 1;
	show_self_domain();
	cp = "transit domain test";
	write(fd, cp, strlen(cp) + 1);
	show_self_domain();
	cp = "transit domain test again";
	write(fd, cp, strlen(cp) + 1);
	show_self_domain();
	close(fd);
	return 0;
}
