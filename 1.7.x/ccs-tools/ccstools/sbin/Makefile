SBIN_LIST = ccs-init

all: $(SBIN_LIST)

install: all
	mkdir -p $(INSTALLDIR)/sbin
	chmod 700 $(SBIN_LIST)
	chown -R root:root .
	cp -af --remove-destination $(SBIN_LIST) $(INSTALLDIR)/sbin/

.c:
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(SBIN_LIST)

.PHONY: clean install
