include ../Include.make

BUILD_FILES = audit-exec-param tomoyo-editpolicy-agent convert-audit-log \
	convert-exec-param init_policy

all: $(BUILD_FILES)

install: all
	mkdir -p -m 0755 $(INSTALLDIR)/$(USRLIBDIR)/tomoyo
	$(INSTALL) -m 0755 $(BUILD_FILES) $(INSTALLDIR)/$(USRLIBDIR)/tomoyo/
	$(INSTALL) -m 0644 ../README.tomoyo ../COPYING.tomoyo $(INSTALLDIR)/$(USRLIBDIR)/tomoyo/

.c:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f -- $(BUILD_FILES)

.PHONY: clean install
