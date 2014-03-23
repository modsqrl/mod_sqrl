TESTS = test
check_PROGRAMS = test
test_SOURCES = sqrl_encodings_test.c \
               $(top_builddir)/libsqrl/sqrl_encodings.h
test_CFLAGS = @APR_CFLAGS@ @APU_CFLAGS@ \
              @CHECK_CFLAGS@
test_CPPFLAGS = -I$(top_srcdir)/libsqrl @APR_CPPFLAGS@
test_LDADD = $(top_builddir)/libsqrl/libsqrl.la \
             @APR_LDADD@ @APU_LDADD@ \
             @CHECK_LIBS@

MAINTAINERCLEANFILES = Makefile.in

