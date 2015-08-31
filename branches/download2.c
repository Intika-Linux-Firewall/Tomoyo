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

/*
 * QUERY_STRING is in "f=/tomoyo/$ReleaseID/$Filename" format.
 * $ReleaseID is known to be a decimal integer.
 * Since $Filename may contain '+' character, we need to encode it.
 */
static char *encode(const char *query) {
	char *cp;
	char *new_query = malloc(strlen(query) * 3) + 1;
	if (!new_query)
		return NULL;
	cp = new_query;
	while (1) {
		const unsigned char c = * (const unsigned char *) query++;
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '.' ||
		    c == '_' || c == '~' || c == '/' || c == '=') {
			*cp++ = c;
		} else if (c) {
			const unsigned char h = c >> 4;
			const unsigned char l = c & 15;
			*cp++ = '%';
			*cp++ = h >= 10 ? h + 'A' - 10 : h + '0';
			*cp++ = l >= 10 ? l + 'A' - 10 : l + '0';
		} else {
			*cp = '\0';
			break;
		}
	}
	return new_query;
}

int main(int argc, char *argv[]) {
	static char buffer[8192];
	struct sockaddr_in addr;
	int len;
	int fd;
	unsigned int status;
	char *server = "osdn.jp";
	char *query = getenv("QUERY_STRING");
	if (!query)
		goto query_error;
	/* Make QUERY_STRING const. */
	query = strdup(query);
	if (!query)
		goto query_error;
	/* Encode QUERY_STRING . */
	query = encode(query);
	if (!query)
		goto query_error;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = get_addr(server);
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
	query = strchr(server, '\r');
	if (!query)
		goto file_error;
	*query = '\0';
	printf("Status: %u Found\r\n", status);
	printf("Location: %s\r\n\r\n", server);
	return 0;
 query_error:
	printf("Status: 500 Internal Server Error.\r\n");
	printf("Content-type: text/plain\r\n\r\n");
	printf("Environment variable QUERY_STRING was not given.\n");
	return 0;
 connect_error:
	printf("Status: 500 Internal Server Error.\r\n");
	printf("Content-type: text/plain\r\n\r\n");
	printf("Unable to connect to %s .\n", server);
	return 0;
 file_error:
	printf("Status: 404 Not found.\r\n");
	printf("Content-type: text/plain\r\n\r\n");
	printf("%s was not found.\n", getenv("QUERY_STRING"));
	return 0;
}
