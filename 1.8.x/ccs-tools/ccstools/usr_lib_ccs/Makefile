include ../Include.make

BUILD_FILES = audit-exec-param convert-exec-param convert-audit-log ccs-editpolicy-agent init_policy

all: $(BUILD_FILES)

install: all
	mkdir -p $(INSTALLDIR)/$(USRLIBDIR)/ccs
	chmod 755 $(INSTALLDIR)/$(USRLIBDIR)/ccs
	chown -R root:root .
	cp -af --remove-destination $(BUILD_FILES) ../README.ccs ../COPYING.ccs $(INSTALLDIR)/$(USRLIBDIR)/ccs/

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f -- $(BUILD_FILES)

.PHONY: clean install
