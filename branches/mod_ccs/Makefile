#   the used tools
APXS=apxs
APACHECTL=apachectl

#   defines the base directories
builddir=.
top_srcdir=/etc/httpd
top_builddir=$(shell $(APXS) -q libdir)/httpd
include $(top_builddir)/build/special.mk

#   additional defines, includes and libraries
#DEFS=-Dmy_define=my_value
#INCLUDES=-Imy/include/dir
#LIBS=-Lmy/lib/dir -lmylib

#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes

#   cleanup
clean:
	-rm -f mod_ccs.o mod_ccs.lo mod_ccs.slo mod_ccs.la

#   simple test
test: reload
	lynx -mime_header http://localhost/

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

