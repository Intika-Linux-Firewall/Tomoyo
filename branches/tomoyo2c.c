#include <stdio.h>
#include <unistd.h>

static void dump_encoded(const char *filename, const char *varname)
{
	FILE *fp = fopen(filename, "r");
	_Bool newline = 0;
	printf("static char ccs_builtin_%s[] __initdata =\n", varname);
	putchar('"');
	if (fp) {
		int c;
		while ((c = fgetc(fp)) != EOF) {
			if (newline)
				putchar('"');
			newline = 0;
			if (c == '\\') {
				putchar('\\');
				putchar('\\');
			} else if (c == '"') {
				putchar('\\');
				putchar('"');
			} else if (c == '\n') {
				putchar('\\');
				putchar('n');
				putchar('"');
				putchar('\n');
				newline = 1;
			} else {
				putchar(c);
			}
		}
		fclose(fp);
		if (!newline)
			fprintf(stderr, "WARNING: The last line in %s "
				"will be ignored\n", filename);
	} else {
		fprintf(stderr, "WARNING: Can't read %s\n", filename);
	}
	if (!newline)
		putchar('"');
	putchar(';');
	putchar('\n');
}

int main(int argc, char *argv[])
{
	if (argc > 1 && chdir(argv[1])) {
		fprintf(stderr, "%s [policy_dir]\n", argv[0]);
		return 1;
	}
	dump_encoded("profile.conf", "profile");
	dump_encoded("exception_policy.conf", "exception_policy");
	dump_encoded("domain_policy.conf", "domain_policy");
	dump_encoded("manager.conf", "manager");
	dump_encoded("stat.conf", "stat");
	return 0;
}
