all:
	mkdir -p man8
	chmod 755 tomoyo-* init_policy
	for i in tomoyo-* init_policy; do ./$$i; done

install: all
	mkdir -p $(INSTALLDIR)/usr/share/man/man8
	cp -af --remove-destination man8/* $(INSTALLDIR)/usr/share/man/man8/

clean:
	rm -f man8/*

.PHONY: clean install
