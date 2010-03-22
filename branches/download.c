#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

static in_addr_t get_addr(const char *hostname)
{
	struct hostent *hp = gethostbyname(hostname);
	if (hp)
		return *(in_addr_t *) hp->h_addr_list[0];
	return INADDR_NONE;
}

int main(int argc, char *argv[]) {
	static char buffer[8192];
	struct sockaddr_in addr;
	int len;
	int fd;
	FILE *fp;
	unsigned int status;
	char *server;
	char *query = getenv("QUERY_STRING");
	if (!query)
		goto query_error;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = get_addr("sourceforge.jp");
	addr.sin_port = htons(80);
	memset(buffer, 0, sizeof(buffer));
	/* Call redir.php to determine download server. */
	snprintf(buffer, sizeof(buffer) - 1,
		 "GET /frs/redir.php?%s HTTP/1.0\r\n\r\n", query);
	len = strlen(buffer);
	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) ||
	    send(fd, buffer, len, 0) != len || shutdown(fd, SHUT_WR))
		goto connect_error;
	memset(buffer, 0, sizeof(buffer));
	recv(fd, buffer, sizeof(buffer) - 1, MSG_WAITALL);
	close(fd);
	if (sscanf(buffer, "HTTP/%*u.%*u %u", &status) != 1 ||
	    (status != 301 && status != 302))
		goto file_error;
	server = strstr(buffer, "http://");
	if (!server)
		goto file_error;
	server += 7;
	query = strchr(server, '\r');
	if (!query)
		goto file_error;
	*query = '\0';
	query = strchr(server, '/');
	if (!query)
		goto file_error;
	*query++ = '\0';
	addr.sin_addr.s_addr = get_addr(server);
	/* Call download server. */
	snprintf(buffer, sizeof(buffer) - 1, "GET /%s HTTP/1.0\r\n\r\n",
		 query);
	len = strlen(buffer);
	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) ||
	    send(fd, buffer, len, 0) != len || shutdown(fd, SHUT_WR))
		goto connect_error;
	fp = fdopen(fd, "r");
	if (!fp)
		goto connect_error;
	memset(buffer, 0, sizeof(buffer));
	fgets(buffer, sizeof(buffer) - 1, fp);
	if (sscanf(buffer, "HTTP/%*u.%*u %u", &status) != 1 || status != 200)
		goto file_error;
	printf("Status: 200 OK\r\n");
	while (memset(buffer, 0, sizeof(buffer)),
	       fgets(buffer, sizeof(buffer) - 1, fp)) {
		if (strcmp(buffer, "\r\n") == 0) {
			printf("\r\n");
			break;
		}
		if (strncmp(buffer, "Last-Modified:", 14) == 0 ||
		    strncmp(buffer, "Etag:", 5) == 0 ||
		    strncmp(buffer, "Accept-Ranges:", 14) == 0 ||
		    strncmp(buffer, "Content-Length:", 15) == 0 ||
		    strncmp(buffer, "Content-Type:", 13) == 0)
			printf("%s", buffer);
	}
	while (1) {
		len = fread(buffer, 1, sizeof(buffer), fp);
		if (len <= 0 ||
		    fwrite(buffer, 1, len, stdout) != len)
			break;
	}
	fclose(fp);
	return 0;
 query_error:
	printf("Status: 500 Internal Server Error.\r\n");
	printf("Content-Length: 0\r\n");
	printf("Content-type: text/plain\r\n\r\n");
	return 0;
 connect_error:
	printf("Status: 500 Internal Server Error.\r\n");
	printf("Content-Length: 0\r\n");
	printf("Content-type: text/plain\r\n\r\n");
	return 0;
 file_error:
	printf("Status: 404 Not found.\r\n");
	printf("Content-Length: 0\r\n");
	printf("Content-type: text/plain\r\n\r\n");
	return 0;
}
