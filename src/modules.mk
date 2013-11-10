mod_sqrl.la: mod_sqrl.slo sqrl.slo utils.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_sqrl.lo sqrl.lo utils.lo

DISTCLEAN_TARGETS = modules.mk
shared =  mod_sqrl.la

