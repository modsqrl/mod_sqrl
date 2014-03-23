moddir = ${APXS_LIBEXECDIR}
mod_LTLIBRARIES = mod_sqrl.la
mod_sqrl_la_SOURCES = mod_sqrl.c
mod_sqrl_la_CFLAGS = @APR_CFLAGS@ @APU_CFLAGS@ \
                     @APREQ_CFLAGS@ @APXS_CFLAGS@
mod_sqrl_la_CPPFLAGS = -I$(top_srcdir)/libsqrl/src \
                       @APR_CPPFLAGS@
mod_sqrl_la_LIBADD = @APR_LDADD@ @APU_LDADD@ \
                     @APREQ_LDADD@ @APXS_LIBS@ \
					 $(top_srcdir)/libsqrl/src/libsqrl.la
mod_sqrl_la_LDFLAGS = -module -avoid-version \
                      @APR_LDFLAGS@ @APU_LDFLAGS@

MAINTAINERCLEANFILES = Makefile.in

