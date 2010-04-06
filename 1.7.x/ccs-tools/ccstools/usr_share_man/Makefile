all:
	mkdir -p man8
	for i in ccs-* init_policy; do ./$$i; done

install: all
	mkdir -p $(INSTALLDIR)/usr/share/man/man8
	cp -af --remove-destination man8/* $(INSTALLDIR)/usr/share/man/man8/


clean:
	rm -f man8/*

.PHONY: clean install
