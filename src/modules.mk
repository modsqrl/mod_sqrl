mod_sqrl.la: mod_sqrl.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_sqrl.lo

DISTCLEAN_TARGETS = modules.mk
shared =  mod_sqrl.la
