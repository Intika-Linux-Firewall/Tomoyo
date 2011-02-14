include ../Include.make

SRC = ccs-auditd ccs-checkpolicy ccs-diffpolicy ccs-domainmatch \
	ccs-editpolicy ccs-editpolicy-agent ccs-findtemp ccs-init \
	ccs-loadpolicy ccs-notifyd ccs-patternize ccs-pstree ccs-queryd \
	ccs-savepolicy ccs-selectpolicy ccs-setlevel ccs-setprofile \
	ccs-sortpolicy init_policy

PAGES := $(patsubst %,man8/%.8.gz,$(SRC))

man8/%.8.gz : %
	@mkdir -p man8
	sh ./$<

all: $(PAGES)

install:
	mkdir -p -m 0755 $(INSTALLDIR)$(MAN8)
	$(INSTALL) -m 0644 $(PAGES) $(INSTALLDIR)$(MAN8)

clean:
	-rm -f man8/*

.PHONY: clean install
