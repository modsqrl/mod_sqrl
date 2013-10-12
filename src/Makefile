
APXS=/usr/local/bin/apxs22

.PHONY: install clean

mod_sqrl.la: mod_sqrl.c
	$(APXS) -c mod_sqrl.c

install: mod_sqrl.la
	sudo $(APXS) -i mod_sqrl.la

clean:
	rm -f *.la *.lo *.o *.slo

