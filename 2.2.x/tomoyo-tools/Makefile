INSTALLDIR = /

MAIN_FILES = tomoyotools tomoyo_init_policy tomoyo-init

MISC_FILES = candy chaplet checktoken gettoken groovy honey mailauth timeauth falsh tomoyo-editpolicy-agent

ALIAS_LIST = pstree checkpolicy editpolicy findtemp ld-watch loadpolicy pathmatch patternize savepolicy setlevel setprofile sortpolicy domainmatch

all: main misc

main: $(MAIN_FILES)

misc: $(MISC_FILES)

install: all
	mkdir -p $(INSTALLDIR)/usr/lib/tomoyo $(INSTALLDIR)/sbin $(INSTALLDIR)/usr/sbin
	chmod 755 $(INSTALLDIR)/usr/lib/tomoyo
	cp -af --remove-destination tomoyotools $(INSTALLDIR)/usr/sbin/
	cp -af --remove-destination tomoyotools.conf $(INSTALLDIR)/usr/lib/tomoyo/
	for i in $(ALIAS_LIST); do ln -f /usr/sbin/tomoyotools $(INSTALLDIR)/usr/sbin/tomoyo-$$i; done
	rm -f $(INSTALLDIR)/usr/sbin/tomoyotools
	cp -af --remove-destination tomoyo_init_policy $(INSTALLDIR)/usr/lib/tomoyo/
	ln -sf tomoyo_init_policy $(INSTALLDIR)/usr/lib/tomoyo/tomoyo_init_policy.sh
	cp -af --remove-destination $(MISC_FILES) $(INSTALLDIR)/usr/lib/tomoyo/
	cp -af --remove-destination README.tomoyo COPYING.tomoyo $(INSTALLDIR)/usr/lib/tomoyo/
	chown -R root:root tomoyo-init $(INSTALLDIR)/usr/lib/tomoyo/
	chmod 700 tomoyo-init
	cp -af --remove-destination tomoyo-init $(INSTALLDIR)/sbin/
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

tomoyotools: tomoyotools.src/*.c tomoyotools.src/*.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o tomoyotools tomoyotools.src/*.c -lncurses -DCOLOR_ON

falsh: falsh.c /usr/include/curses.h /usr/include/readline/readline.h
	$(CC) $(CFLAGS) -o falsh falsh.c -lncurses -lreadline

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(MAIN_FILES) $(MISC_FILES)

.PHONY: clean install
