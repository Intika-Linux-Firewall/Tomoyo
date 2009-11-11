INSTALLDIR = /

MAIN_FILES = ccstools init_policy ccs-init

MISC_FILES = candy chaplet checktoken gettoken groovy honey mailauth proxy timeauth falsh ccs-notifyd force-logout audit-exec-param convert-exec-param convert-audit-log ccs-editpolicy-agent

ALIAS_LIST = ccs-auditd ccs-queryd ccs-pstree ccs-checkpolicy ccs-editpolicy ccs-findtemp ccs-ld-watch ccs-loadpolicy ccs-pathmatch ccs-patternize ccs-savepolicy ccs-setlevel ccs-setprofile ccs-sortpolicy ccs-diffpolicy ccs-selectpolicy

all: main misc

main: $(MAIN_FILES)

misc: $(MISC_FILES)

install: all
	mkdir -p $(INSTALLDIR)/usr/lib/ccs $(INSTALLDIR)/sbin $(INSTALLDIR)/usr/sbin
	chmod 755 $(INSTALLDIR)/usr/lib/ccs
	chmod 755 ccs-domainmatch init_policy.sh
	cp -af --remove-destination ccstools $(INSTALLDIR)/usr/sbin/
	cp -af --remove-destination ccstools.conf $(INSTALLDIR)/usr/lib/ccs/
	for i in $(ALIAS_LIST); do ln -f $(INSTALLDIR)/usr/sbin/ccstools $(INSTALLDIR)/usr/sbin/$$i; done
	rm -f $(INSTALLDIR)/usr/sbin/ccstools
	cp -af --remove-destination ccs-domainmatch $(INSTALLDIR)/usr/sbin/
	cp -af --remove-destination $(MISC_FILES) init_policy init_policy.sh README.ccs COPYING.ccs $(INSTALLDIR)/usr/lib/ccs/
	chown -R root:root ccs-init $(INSTALLDIR)/usr/lib/ccs/
	chmod 4711 $(INSTALLDIR)/usr/lib/ccs/force-logout
	chmod 700 ccs-init
	cp -af --remove-destination ccs-init $(INSTALLDIR)/sbin/
	mkdir -p $(INSTALLDIR)/usr/share/man/man8/
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

ccstools: ccstools.src/*.c ccstools.src/*.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o ccstools ccstools.src/*.c -lncurses -DCOLOR_ON

falsh: falsh.c /usr/include/curses.h /usr/include/readline/readline.h
	$(CC) $(CFLAGS) -o falsh falsh.c -lncurses -lreadline

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(MAIN_FILES) $(MISC_FILES)

.PHONY: clean install
