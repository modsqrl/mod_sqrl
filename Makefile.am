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

deploy-apache2-sample:
	cp -r apache2/sample/conf/* "$(APXS_SYSCONFDIR)"
	mkdir -p /tmp/sqrl-sample
	cp -r apache2/sample/htdocs/* /tmp/sqrl-sample
	@echo "**************************************************"
	@echo -e "The sample configuration file has been copied to"\
	         "\"$(APXS_SYSCONFDIR)/extra/sqrl.conf\"\nYou need to add"\
	         "the following line to \"$(APXS_SYSCONFDIR)/httpd.conf\"\n"\
	         " Include conf/extra/sqrl.conf"
	@echo "Start apache2 then go to \"http://127.0.0.1/\""
	@echo "**************************************************"

