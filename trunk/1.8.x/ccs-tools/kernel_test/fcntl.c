#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	int fd;
	system("touch "
	       "/tmp/O_RDONLY /tmp/O_RDONLY+O_APPEND "
	       "/tmp/O_WRONLY /tmp/O_WRONLY+O_APPEND "
	       "/tmp/O_RDWR /tmp/O_RDWR+O_APPEND "
	       "/tmp/O_IOCTL /tmp/O_IOCTL+O_APPEND");
	fprintf(stderr, "file read /tmp/O_RDONLY\n");
	fd = open("/tmp/O_RDONLY", O_RDONLY);
	fprintf(stderr, "file append /tmp/O_RDONLY\n");
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_APPEND) == EOF)
		fprintf(stderr, "fcntl(O_APPEND) rejected for O_RDONLY.\n");
	if (write(fd, "", 1) != EOF)
		fprintf(stderr, "write() not rejected for "
			"O_RDONLY | O_APPEND.\n");
	close(fd);
	fprintf(stderr, "file read /tmp/O_RDONLY+O_APPEND\n");
	fd = open("/tmp/O_RDONLY+O_APPEND", O_RDONLY | O_APPEND);
	fprintf(stderr, "file write /tmp/O_RDONLY+O_APPEND\n");
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_APPEND) == EOF)
		fprintf(stderr, "fcntl(~O_APPEND) rejected for "
			"O_RDONLY | O_APPEND.\n");
	if (write(fd, "", 1) != EOF)
		fprintf(stderr, "write() not rejected for O_RDONLY.\n");
	close(fd);
	fprintf(stderr, "file write /tmp/O_WRONLY\n");
	fd = open("/tmp/O_WRONLY", O_WRONLY);
	fprintf(stderr, "file append /tmp/O_WRONLY\n");
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_APPEND) == EOF)
		fprintf(stderr, "fcntl(O_APPEND) rejected for O_WRONLY.\n");
	if (write(fd, "", 1) == EOF)
		fprintf(stderr, "write() rejected for O_WRONLY | O_APPEND.\n");
	close(fd);
	fprintf(stderr, "file append /tmp/O_WRONLY+O_APPEND\n");
	fd = open("/tmp/O_WRONLY+O_APPEND", O_WRONLY | O_APPEND);
	fprintf(stderr, "file write /tmp/O_WRONLY+O_APPEND\n");
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_APPEND) == EOF)
		fprintf(stderr, "fcntl(~O_APPEND) rejected for "
			"O_WRONLY | O_APPEND.\n");
	if (write(fd, "", 1) == EOF)
		fprintf(stderr, "write() rejected for O_WRONLY.\n");
	close(fd);
	fprintf(stderr, "file read/write /tmp/O_RDWR\n");
	fd = open("/tmp/O_RDWR", O_RDWR);
	fprintf(stderr, "file append /tmp/O_RDWR\n");
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_APPEND) == EOF)
		fprintf(stderr, "fcntl(O_APPEND) rejected for O_RDWR.\n");
	if (write(fd, "", 1) == EOF)
		fprintf(stderr, "write() rejected for O_RDWR | O_APPEND.\n");
	close(fd);
	fprintf(stderr, "file read/append /tmp/O_RDWR+O_APPEND\n");
	fd = open("/tmp/O_RDWR+O_APPEND", O_RDWR | O_APPEND);
	fprintf(stderr, "file write /tmp/O_RDWR+O_APPEND\n");
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_APPEND) == EOF)
		fprintf(stderr, "fcntl(~O_APPEND) rejected for "
			"O_RDWR | O_APPEND.\n");
	if (write(fd, "", 1) == EOF)
		fprintf(stderr, "write() rejected for O_RDWR.\n");
	close(fd);
	fd = open("/tmp/O_IOCTL", 3);
	fprintf(stderr, "file append /tmp/O_IOCTL\n");
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_APPEND) == EOF)
		fprintf(stderr, "fcntl(O_APPEND) rejected for O_IOCTL.\n");
	if (write(fd, "", 1) != EOF)
		fprintf(stderr, "write() not rejected for "
			"O_IOCTL | O_APPEND.\n");
	close(fd);
	fd = open("/tmp/O_IOCTL+O_APPEND", 3 | O_APPEND);
	fprintf(stderr, "file write /tmp/O_IOCTL+O_APPEND\n");
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_APPEND) == EOF)
		fprintf(stderr, "fcntl(~O_APPEND) rejected for "
			"O_IOCTL | O_APPEND.\n");
	if (write(fd, "", 1) != EOF)
		fprintf(stderr, "write() not rejected for O_IOCTL.\n");
	close(fd);
	return 0;
}
