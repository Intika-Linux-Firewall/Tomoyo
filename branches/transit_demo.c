#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
	FILE *fp = fopen("/proc/ccs/self_domain", "r+");
	char buffer[8192];
	memset(buffer, 0, sizeof(buffer));
	fgets(buffer, sizeof(buffer) - 1, fp);
	puts(buffer);
	fprintf(fp, "/transit/domain/test\n");
	fflush(fp);
	rewind(fp);
	fgets(buffer, sizeof(buffer) - 1, fp);
	puts(buffer);
	fprintf(fp, "/transit/domain/test\n");
	fflush(fp);
	rewind(fp);
	fgets(buffer, sizeof(buffer) - 1, fp);
	puts(buffer);
	fclose(fp);
	return 0;
}
