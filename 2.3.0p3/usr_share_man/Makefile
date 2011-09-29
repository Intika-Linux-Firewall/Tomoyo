SRC = init_policy tomoyo-checkpolicy tomoyo-diffpolicy tomoyo-domainmatch tomoyo-editpolicy tomoyo-editpolicy-agent tomoyo-findtemp tomoyo-init tomoyo-ld-watch tomoyo-loadpolicy tomoyo-notifyd tomoyo-patternize tomoyo-pstree tomoyo-queryd tomoyo-savepolicy tomoyo-selectpolicy tomoyo-setlevel tomoyo-setprofile tomoyo-sortpolicy

man8/%.8.gz : %
	@mkdir -p man8
	chmod 755 ./$<
	sh ./$<

all: $(patsubst %,man8/%.8.gz,$(SRC))

install:
	mkdir -p $(INSTALLDIR)/usr/share/man/man8
	cp -af --remove-destination man8/* $(INSTALLDIR)/usr/share/man/man8/

clean:
	rm -f man8/*

.PHONY: clean install
