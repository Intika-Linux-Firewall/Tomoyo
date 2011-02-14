include ../Include.make

BUILD_FILES = audit-exec-param ccs-editpolicy-agent convert-audit-log \
	convert-exec-param init_policy

all: $(BUILD_FILES)

install: all
	mkdir -p -m 0755 $(INSTALLDIR)/$(USRLIBDIR)/ccs
	$(INSTALL) -m 0755 $(BUILD_FILES) $(INSTALLDIR)/$(USRLIBDIR)/ccs/
	$(INSTALL) -m 0644 ../README.ccs ../COPYING.ccs $(INSTALLDIR)/$(USRLIBDIR)/ccs/

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f -- $(BUILD_FILES)

.PHONY: clean install
