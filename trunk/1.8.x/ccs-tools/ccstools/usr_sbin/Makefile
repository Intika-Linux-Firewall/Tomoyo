include ../Include.make

BUILD_FILES := ccs-auditd ccs-checkpolicy ccs-diffpolicy ccs-domainmatch \
	ccs-editpolicy ccs-findtemp ccs-loadpolicy ccs-notifyd ccs-patternize \
	ccs-pstree ccs-queryd ccs-savepolicy ccs-selectpolicy ccs-setlevel \
	ccs-setprofile ccs-sortpolicy

all: libccstools.so $(BUILD_FILES)

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses-dev'"
	sleep 10

libccstools.so: ccstools.c ccstools.h
	$(CC) $(CFLAGS) $(NO_POINTER_SIGN) -fPIC ccstools.c -shared -Wl,-soname,libccstools.so.1 -o libccstools.so.1.0.2
	ln -sf libccstools.so.1.0.2 libccstools.so

.c:
	$(CC) $(CFLAGS) $(NO_POINTER_SIGN) -o $@ -lccstools -L. $<

ccs-editpolicy: ccstools.h editpolicy*.c readline.h /usr/include/curses.h libccstools.so
	$(CC) $(CFLAGS) $(NO_POINTER_SIGN) -o ccs-editpolicy editpolicy*.c -lncurses -lccstools -L. -DCOLOR_ON

ccs-queryd: ccstools.h ccs-queryd.c readline.h /usr/include/curses.h libccstools.so
	$(CC) $(CFLAGS) $(NO_POINTER_SIGN) -o ccs-queryd ccs-queryd.c -lncurses -lccstools -L.

install: all
	mkdir -p -m 0755 $(INSTALLDIR)$(USRLIBDIR)
	$(INSTALL) -m 0755 libccstools.so.1.0.2 $(INSTALLDIR)$(USRLIBDIR)
	ln -sf libccstools.so.1.0.2 $(INSTALLDIR)$(USRLIBDIR)/libccstools.so.1
ifeq ($(INSTALLDIR),)
	ldconfig || true
endif
	mkdir -p -m 0755 $(INSTALLDIR)$(USRSBINDIR)
	$(INSTALL) -m 0755 $(BUILD_FILES) $(INSTALLDIR)$(USRSBINDIR)

clean:
	rm -f -- $(BUILD_FILES) libccstools.so*

.PHONY: clean install
