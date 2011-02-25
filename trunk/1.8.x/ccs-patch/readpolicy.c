#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	int i;
	char buffer[1024];
	for (i = 0; i < 1024; i++) {
		if (0 && fork() == 0) {
			int fd = open("/proc/ccs/domain_policy", O_RDONLY);
			read(fd, buffer, sizeof(buffer));
			read(fd, buffer, sizeof(buffer));
			read(fd, buffer, sizeof(buffer));
			read(fd, buffer, sizeof(buffer));
			if (read(fd, buffer, i) == i) {
				pause();
				while (read(fd, buffer, sizeof(buffer)) > 0);
			}
			close(fd);
			_exit(0);
		}
		if (fork() == 0) {
			int fd = open("/proc/ccs/exception_policy", O_RDONLY);
			read(fd, buffer, sizeof(buffer));
			read(fd, buffer, sizeof(buffer));
			read(fd, buffer, sizeof(buffer));
			read(fd, buffer, sizeof(buffer));
			read(fd, buffer, sizeof(buffer));
			read(fd, buffer, sizeof(buffer));
			read(fd, buffer, sizeof(buffer) / 2);
			if (read(fd, buffer, i) == i) {
				pause();
				while (read(fd, buffer, sizeof(buffer)) > 0);
			}
			close(fd);
			_exit(0);
		}
	}
	return 0;
}
