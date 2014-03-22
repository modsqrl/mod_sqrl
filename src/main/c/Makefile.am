noinst_LTLIBRARIES = libsqrl.la
libsqrl_la_SOURCES = sqrl.c sqrl_encodings.c sqrl_encodings.h sqrl.h
libsqrl_la_CFLAGS = @APR_CFLAGS@ @APU_CFLAGS@
libsqrl_la_CPPFLAGS = @APR_CPPFLAGS@
libsqrl_la_LIBADD = @APR_LDADD@ @APU_LDADD@

moddir = ${APXS_LIBEXECDIR}
mod_LTLIBRARIES = mod_sqrl.la
mod_sqrl_la_SOURCES = mod_sqrl.c
mod_sqrl_la_CFLAGS = @APR_CFLAGS@ @APU_CFLAGS@ \
                     @APREQ_CFLAGS@ @APXS_CFLAGS@
mod_sqrl_la_LIBADD = @APR_LDADD@ @APU_LDADD@ \
                     @APREQ_LDADD@ @APXS_LIBS@ \
					 libsqrl.la
mod_sqrl_la_LDFLAGS = -module -avoid-version \
                      @APR_LDFLAGS@ @APU_LDFLAGS@

MAINTAINERCLEANFILES = Makefile.in

