USR_LIB_CCS_LIST = candy chaplet checktoken gettoken groovy honey mailauth proxy timeauth falsh ccs-notifyd force-logout audit-exec-param convert-exec-param convert-audit-log ccs-editpolicy-agent init_policy

all: $(USR_LIB_CCS_LIST)

install: all
	mkdir -p $(INSTALLDIR)/usr/lib/ccs
	chmod 755 $(INSTALLDIR)/usr/lib/ccs
	chmod 755 $(USR_LIB_CCS_LIST) init_policy.sh
	chmod 4711 force-logout
	chown -R root:root .
	cp -af --remove-destination $(USR_LIB_CCS_LIST) ccstools.conf init_policy.sh README.ccs COPYING.ccs $(INSTALLDIR)/usr/lib/ccs/

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses5-dev'"
	sleep 10

/usr/include/readline/readline.h:
	@echo "/usr/include/readline/readline.h is missing."
	@echo "Run 'yum install readline-devel' or 'apt-get install libreadline5-dev'"
	sleep 10

falsh: falsh.c /usr/include/curses.h /usr/include/readline/readline.h
	$(CC) $(CFLAGS) -o falsh falsh.c -lncurses -lreadline

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(USR_LIB_CCS_LIST)

.PHONY: clean install
