
VER=24
APXS=/usr/local/bin/apxs$(VER)
APACHECTL=/usr/local/bin/apachectl$(VER)
HTDOCS=/usr/local/apache$(VER)/htdocs

.PHONY: format install clean

mod_sqrl.la: mod_sqrl.c
	$(APXS) -c mod_sqrl.c

format:
	indent -i4 -npsl -di0 -br -nce -d0 -cli0 -npcs -nfc1 -nut *.c

install: mod_sqrl.la
	sudo $(APXS) -i mod_sqrl.la

reinstall: mod_sqrl.la
	sudo $(APACHECTL) stop
	sudo $(APXS) -i mod_sqrl.la
	sudo cp ../test/login.html $(HTDOCS)
	sudo $(APACHECTL) start

clean:
	rm -f *.la *.lo *.o *.slo

