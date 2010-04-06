INSTALLDIR = /

SBIN_LIST = ccs-init

USR_LIB_CCS_LIST = candy chaplet checktoken gettoken groovy honey mailauth proxy timeauth falsh ccs-notifyd force-logout audit-exec-param convert-exec-param convert-audit-log ccs-editpolicy-agent init_policy

USR_SBIN_LIST = ccs-auditd ccs-queryd ccs-pstree ccs-checkpolicy ccs-editpolicy ccs-findtemp ccs-ld-watch ccs-loadpolicy ccs-pathmatch ccs-patternize ccs-savepolicy ccs-setlevel ccs-setprofile ccs-sortpolicy ccs-diffpolicy ccs-selectpolicy

all: $(SBIN_LIST) $(USR_SBIN_LIST) $(USR_LIB_CCS_LIST)

install: all
	mkdir -p $(INSTALLDIR)/usr/lib/ccs $(INSTALLDIR)/sbin $(INSTALLDIR)/usr/sbin $(INSTALLDIR)/usr/share/man/man8
	chmod 755 $(INSTALLDIR)/usr/lib/ccs
	chmod 700 ccs-init
	chmod 755 ccs-domainmatch init_policy.sh
	chmod 4711 force-logout
	chown -R root:root .
	cp -af --remove-destination $(SBIN_LIST) $(INSTALLDIR)/sbin/
	cp -af --remove-destination $(USR_SBIN_LIST) ccs-domainmatch $(INSTALLDIR)/usr/sbin/
	cp -af --remove-destination $(USR_LIB_CCS_LIST) ccstools.conf init_policy.sh README.ccs COPYING.ccs $(INSTALLDIR)/usr/lib/ccs/
	cp -af --remove-destination man/man8/* $(INSTALLDIR)/usr/share/man/man8/

CC=gcc

CFLAGS=-Wall -O2 ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

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
	rm -f $(SBIN_LIST) $(USR_SBIN_LIST) $(USR_LIB_CCS_LIST)

.PHONY: clean install
