
builddir=.
top_srcdir=/usr/local/apache24
top_builddir=$(top_srcdir)
include $(top_builddir)/build/special.mk

#   the used tools
APXS=$(top_srcdir)/bin/apxs
APACHECTL=$(top_srcdir)/bin/apachectl

#   additional defines, includes and libraries
MOD_CFLAGS=-Wall -g -O0
MOD_LDFLAGS=-lsodium

#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes

#   format the code according to apache's style guide
format:
	indent -i4 -npsl -di0 -br -nce -d0 -cli0 -npcs -nfc1 -nut *.[ch]

#   cleanup
clean:
	-rm -f mod_sqrl.o mod_sqrl.lo mod_sqrl.slo mod_sqrl.la 

#   simple test
test: reload
	curl http://localhost/sqrl

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

