BUILD_FILES = tomoyo-notifyd tomoyo-editpolicy-agent init_policy

all: $(BUILD_FILES)

install: all
	mkdir -p $(INSTALLDIR)/usr/lib/tomoyo
	chmod 755 $(INSTALLDIR)/usr/lib/tomoyo
	chown -R root:root .
	cp -af --remove-destination $(BUILD_FILES) tomoyotools.conf ../README.tomoyo ../COPYING.tomoyo $(INSTALLDIR)/usr/lib/tomoyo/

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f -- $(BUILD_FILES)

.PHONY: clean install
