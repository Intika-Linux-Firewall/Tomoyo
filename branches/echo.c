#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	char *query = getenv("QUERY_STRING");
	if (!query)
		query = "Environment variable QUERY_STRING was not given.\n";
	printf("Status: 200 OK\r\n");
	printf("Content-type: text/plain\r\n\r\n");
	printf("%s", query);
	return 0;
}
