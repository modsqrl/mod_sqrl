SUBDIRS = src
MAINTAINERCLEANFILES = Makefile.in

deploy-apache2-sample:
	cp -r sample/conf/* "$(APXS_SYSCONFDIR)"
	mkdir -p /tmp/sqrl-sample
	cp -r sample/htdocs/* /tmp/sqrl-sample
	@echo "**************************************************"
	@echo -e "The sample configuration file has been copied to"\
	         "\"$(APXS_SYSCONFDIR)/extra/sqrl.conf\"\nYou need to add"\
	         "the following line to \"$(APXS_SYSCONFDIR)/httpd.conf\"\n"\
	         " Include conf/extra/sqrl.conf"
	@echo "Start apache2 then go to \"http://127.0.0.1/\""
	@echo "**************************************************"

