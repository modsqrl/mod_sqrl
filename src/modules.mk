mod_sqrl.la: mod_sqrl.slo sqrl.slo sqrl_encodings.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_sqrl.lo sqrl.lo sqrl_encodings.lo

DISTCLEAN_TARGETS = modules.mk
shared =  mod_sqrl.la

