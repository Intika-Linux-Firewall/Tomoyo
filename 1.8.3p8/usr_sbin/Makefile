include ../Include.make

BUILD_FILES := ccs-auditd ccs-checkpolicy ccs-diffpolicy ccs-domainmatch \
	ccs-editpolicy ccs-findtemp ccs-loadpolicy ccs-notifyd ccs-patternize \
	ccs-pstree ccs-queryd ccs-savepolicy ccs-selectpolicy ccs-setlevel \
	ccs-setprofile ccs-sortpolicy

all: libccstools.so $(BUILD_FILES)

$(BUILD_FILES): libccstools.so

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses-dev'"
	sleep 10

# -fPIE conflicts with -fPIC, disable it for libraries.
CFLAGS_PIC  := $(filter-out -fPIE,$(CFLAGS))
LDFLAGS_PIC := $(filter-out -pie,$(filter-out -fPIE,$(LDFLAGS)))

libccstools.so: ccstools.c ccstools.h
	$(CC) $(CPPFLAGS) $(CFLAGS_PIC) $(LDFLAGS_PIC) -fPIC ccstools.c -shared -Wl,-soname,libccstools.so.3 -o libccstools.so.3.0.2
	ln -sf libccstools.so.3.0.2 libccstools.so

.c:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< -lccstools -L. 

ccs-editpolicy: ccstools.h editpolicy*.c readline.h /usr/include/curses.h libccstools.so
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o ccs-editpolicy editpolicy*.c -lncurses -lccstools -L. -DCOLOR_ON

ccs-queryd: ccstools.h ccs-queryd.c readline.h /usr/include/curses.h libccstools.so
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o ccs-queryd ccs-queryd.c -lncurses -lccstools -L.

install: all
	mkdir -p -m 0755 $(INSTALLDIR)$(USRLIBDIR)
	$(INSTALL) -m 0755 libccstools.so.3.0.2 $(INSTALLDIR)$(USRLIBDIR)
	ln -sf libccstools.so.3.0.2 $(INSTALLDIR)$(USRLIBDIR)/libccstools.so.3
ifeq ($(INSTALLDIR),)
	ldconfig || true
endif
	mkdir -p -m 0755 $(INSTALLDIR)$(USRSBINDIR)
	$(INSTALL) -m 0755 $(BUILD_FILES) $(INSTALLDIR)$(USRSBINDIR)

clean:
	rm -f -- $(BUILD_FILES) libccstools.so*

.PHONY: clean install
