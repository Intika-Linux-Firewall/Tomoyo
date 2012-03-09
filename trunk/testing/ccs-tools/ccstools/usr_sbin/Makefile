include ../Include.make

BUILD_FILES := ccs-auditd ccs-loadpolicy ccs-notifyd ccs-pstree ccs-queryd \
	ccs-savepolicy

all: libccstools.so $(BUILD_FILES)

$(BUILD_FILES): libccstools.so

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses-dev'"
	sleep 10

libccstools.so: ccstools.c ccstools.h
	$(CC) $(CFLAGS) -fPIC ccstools.c -shared -Wl,-soname,libccstools.so.4 -o libccstools.so.4.0.0
	ln -sf libccstools.so.4.0.0 libccstools.so

.c:
	$(CC) $(CFLAGS) -o $@ $< -lccstools -L. 

ccs-queryd: ccstools.h ccs-queryd.c readline.h /usr/include/curses.h libccstools.so
	$(CC) $(CFLAGS) -o ccs-queryd ccs-queryd.c -lncurses -lccstools -L.

install: all
	mkdir -p -m 0755 $(INSTALLDIR)$(USRLIBDIR)
	$(INSTALL) -m 0755 libccstools.so.4.0.0 $(INSTALLDIR)$(USRLIBDIR)
	ln -sf libccstools.so.4.0.0 $(INSTALLDIR)$(USRLIBDIR)/libccstools.so.4
ifeq ($(INSTALLDIR),)
	ldconfig || true
endif
	mkdir -p -m 0755 $(INSTALLDIR)$(USRSBINDIR)
	$(INSTALL) -m 0755 $(BUILD_FILES) $(INSTALLDIR)$(USRSBINDIR)

clean:
	rm -f -- $(BUILD_FILES) libccstools.so*

.PHONY: clean install
