BUILD_FILES = candy chaplet checktoken gettoken groovy honey mailauth proxy timeauth falsh audit-exec-param convert-exec-param convert-audit-log ccs-editpolicy-agent init_policy

all: $(BUILD_FILES)

install: all
	mkdir -p $(INSTALLDIR)/usr/lib/ccs
	chmod 755 $(INSTALLDIR)/usr/lib/ccs
	chown -R root:root .
	cp -af --remove-destination $(BUILD_FILES) ../README.ccs ../COPYING.ccs $(INSTALLDIR)/usr/lib/ccs/

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses5-dev'"
	sleep 10

/usr/include/readline/readline.h:
	@echo "/usr/include/readline/readline.h is missing."
	@echo "Run 'yum install readline-devel' or 'apt-get install libreadline5-dev'"
	sleep 10

falsh: falsh.c /usr/include/curses.h /usr/include/readline/readline.h
	chmod 755 dummy
	$(CC) $(CFLAGS) -o falsh falsh.c -lncurses -lreadline || ln -f dummy falsh

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f -- $(BUILD_FILES)

.PHONY: clean install
