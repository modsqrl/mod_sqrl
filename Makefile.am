ACLOCAL_AMFLAGS = -I m4
SUBDIRS = libsqrl apache2

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 autoscan.log config.h.in* \
                       configure configure.scan m4/libtool.m4 m4/lt*

maintainer-clean-local:
	-rm -rf $(ac_aux_dir)

start:
	$(APXS_HTTPD) -k start

stop:
	$(APXS_HTTPD) -k stop

restart:
	$(APXS_HTTPD) -k restart

