SRC = init_policy ccs-auditd ccs-checkpolicy ccs-diffpolicy ccs-domainmatch ccs-editpolicy ccs-editpolicy-agent ccs-findtemp ccs-init ccs-ld-watch ccs-loadpolicy ccs-notifyd ccs-patternize ccs-pstree ccs-queryd ccs-savepolicy ccs-selectpolicy ccs-setlevel ccs-setprofile ccs-sortpolicy

man8/%.8.gz : %
	@mkdir -p man8
	@chmod 755 $^
	./$^

all: $(patsubst %,man8/%.8.gz,$(SRC))

install: all
	mkdir -p $(INSTALLDIR)/usr/share/man/man8
	cp -af --remove-destination man8/* $(INSTALLDIR)/usr/share/man/man8/

clean:
	rm -f man8/*

.PHONY: clean install
