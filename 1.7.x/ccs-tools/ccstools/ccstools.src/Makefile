
USR_SBIN_LIST = ccs-auditd ccs-queryd ccs-pstree ccs-checkpolicy ccs-editpolicy ccs-findtemp ccs-ld-watch ccs-loadpolicy ccs-pathmatch ccs-patternize ccs-savepolicy ccs-setlevel ccs-setprofile ccs-sortpolicy ccs-diffpolicy ccs-selectpolicy

all: $(USR_SBIN_LIST)

CC=gcc

CFLAGS=-Wall -O2 ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses5-dev'"
	sleep 10

ccs-editpolicy: ccstools.c editpolicy*.c readline.h ccstools.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o ccs-editpolicy ccstools.c editpolicy*.c -lncurses -DCOLOR_ON

ccs-queryd: ccstools.c ccs-queryd.c readline.h ccstools.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o ccs-queryd ccstools.c ccs-queryd.c -lncurses

.c:
	$(CC) $(CFLAGS) -o $@ ccstools.c $<

clean:
	rm -f -- $(USR_SBIN_LIST)

.PHONY: clean install
