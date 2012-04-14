include Include.make

BUILD_FILES := tomoyotools tomoyo_init_policy tomoyo-init tomoyo-editpolicy-agent

ALIAS_LIST := pstree checkpolicy editpolicy findtemp ld-watch loadpolicy pathmatch patternize savepolicy setlevel setprofile sortpolicy domainmatch

all: $(BUILD_FILES)

install: all
	mkdir -p -m 0755 $(INSTALLDIR)/$(USRLIBDIR)/tomoyo $(INSTALLDIR)/$(SBINDIR) $(INSTALLDIR)/$(USRSBINDIR) $(INSTALLDIR)/$(MAN8)/
	chmod 755 $(INSTALLDIR)/$(USRLIBDIR)/tomoyo
	$(INSTALL) -m 0755 $(BUILD_FILES) $(INSTALLDIR)/$(USRLIBDIR)/tomoyo/
	mv $(INSTALLDIR)/$(USRLIBDIR)/tomoyo/tomoyo-init $(INSTALLDIR)/$(SBINDIR)/
	for i in $(ALIAS_LIST); do ln -f $(INSTALLDIR)/$(USRLIBDIR)/tomoyo/tomoyotools $(INSTALLDIR)/$(USRSBINDIR)/tomoyo-$$i; done
	rm -f $(INSTALLDIR)/$(USRLIBDIR)/tomoyo/tomoyotools
	$(INSTALL) -m 0644 tomoyotools.conf $(INSTALLDIR)/$(USRLIBDIR)/tomoyo/
	$(INSTALL) -m 0644 README.tomoyo COPYING.tomoyo $(INSTALLDIR)/$(USRLIBDIR)/tomoyo/
	$(INSTALL) -m 0644 man/man8/* $(INSTALLDIR)/$(MAN8)/

/usr/include/curses.h:
	@echo "/usr/include/curses.h is missing."
	@echo "Run 'yum install ncurses-devel' or 'apt-get install libncurses5-dev'"
	sleep 10

tomoyotools: tomoyotools.src/*.c tomoyotools.src/*.h /usr/include/curses.h
	$(CC) $(CFLAGS) -o tomoyotools tomoyotools.src/*.c -lncurses -DCOLOR_ON

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BUILD_FILES)

.PHONY: clean install
