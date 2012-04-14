include ../Include.make

BUILD_FILES = tomoyo-notifyd tomoyo-editpolicy-agent init_policy

all: $(BUILD_FILES)

install: all
	mkdir -p -m 0755 $(INSTALLDIR)/$(USRLIBDIR)/tomoyo
	$(INSTALL) -m 0755 $(BUILD_FILES) $(INSTALLDIR)/$(USRLIBDIR)/tomoyo/
	$(INSTALL) -m 0644 tomoyotools.conf ../README.tomoyo ../COPYING.tomoyo $(INSTALLDIR)/$(USRLIBDIR)/tomoyo/

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f -- $(BUILD_FILES)

.PHONY: clean install
