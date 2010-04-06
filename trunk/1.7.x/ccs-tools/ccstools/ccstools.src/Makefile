
USR_SBIN_LIST = ccs-auditd ccs-queryd ccs-pstree ccs-checkpolicy ccs-editpolicy ccs-findtemp ccs-ld-watch ccs-loadpolicy ccs-pathmatch ccs-patternize ccs-savepolicy ccs-setlevel ccs-setprofile ccs-sortpolicy ccs-diffpolicy ccs-selectpolicy

all: $(USR_SBIN_LIST)

CC=gcc

CFLAGS=-Wall -O2 ${shell $(CC) -Wno-pointer-sign -S -o /dev/null -x c - < /dev/null > /dev/null 2>&1 && echo "-Wno-pointer-sign"}

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses5-dev'"
	sleep 10

ccs-editpolicy: ccstools.h editpolicy*.c readline.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o ccs-editpolicy editpolicy*.c -lncurses -lccstools -L. -DCOLOR_ON

ccs-queryd: ccstools.h ccs-queryd.c readline.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o ccs-queryd ccs-queryd.c -lncurses -lccstools -L.

libccstools.so: ccstools.c ccstools.h
	$(CC) $(CFLAGS) -fPIC ccstools.c -shared -Wl,-soname,libccstools.so.1 -o libccstools.so.1.0.0
	ln -sf libccstools.so.1.0.0 libccstools.so

.c:
	[ -r libccstools.so ] || $(MAKE) libccstools.so
	$(CC) $(CFLAGS) -o $@ -lccstools -L. $<

clean:
	rm -f -- $(USR_SBIN_LIST) libccstools.so*

.PHONY: clean install
