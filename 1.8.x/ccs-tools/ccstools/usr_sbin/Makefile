BUILD_FILES = ccs-auditd ccs-domainmatch ccs-queryd ccs-pstree ccs-checkpolicy ccs-editpolicy ccs-findtemp ccs-loadpolicy ccs-patternize ccs-savepolicy ccs-setlevel ccs-setprofile ccs-sortpolicy ccs-diffpolicy ccs-selectpolicy ccs-notifyd

all: libccstools.so $(BUILD_FILES)

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses5-dev'"
	sleep 10

ccs-editpolicy: ccstools.h editpolicy*.c readline.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o ccs-editpolicy editpolicy*.c -lncurses -lccstools -L. -DCOLOR_ON || ln -f dummy ccs-editpolicy

ccs-queryd: ccstools.h ccs-queryd.c readline.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o ccs-queryd ccs-queryd.c -lncurses -lccstools -L. || ln -f dummy ccs-queryd

libccstools.so: ccstools.c ccstools.h
	$(CC) $(CFLAGS) -fPIC ccstools.c -shared -Wl,-soname,libccstools.so.1 -o libccstools.so.1.0.1
	ln -sf libccstools.so.1.0.1 libccstools.so

.c:
	$(CC) $(CFLAGS) -o $@ -lccstools -L. $<

install: all
	mkdir -p $(INSTALLDIR)/usr/sbin $(INSTALLDIR)/usr/lib
	cp -af --remove-destination $(BUILD_FILES) $(INSTALLDIR)/usr/sbin/
	cp -ad --remove-destination libccstools.so.1.0.1 $(INSTALLDIR)/usr/lib/
	ln -sf libccstools.so.1.0.1 $(INSTALLDIR)/usr/lib/libccstools.so.1
	ldconfig || true

clean:
	rm -f -- $(BUILD_FILES) libccstools.so*

.PHONY: clean install
