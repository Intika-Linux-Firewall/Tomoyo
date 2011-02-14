include ../Include.make

BUILD_FILES = ccs-init

all: $(BUILD_FILES)

install: all
	mkdir -p -m 0755 $(INSTALLDIR)$(SBINDIR)
	$(INSTALL) -m 0700 $(BUILD_FILES) $(INSTALLDIR)$(SBINDIR)

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f -- $(BUILD_FILES)

.PHONY: clean install
