TESTS = test
check_PROGRAMS = test
test_SOURCES = sqrl_encodings_test.c $(top_builddir)/src/main/c/sqrl_encodings.h
test_CFLAGS = -I$(top_srcdir)/src/main/c \
              @APR_CFLAGS@ @APU_CFLAGS@ \
              @CHECK_CFLAGS@
test_CPPFLAGS = @APR_CPPFLAGS@
test_LDADD = $(top_builddir)/src/main/c/libsqrl.la \
             @APR_LDADD@ @APU_LDADD@ \
             @CHECK_LIBS@

MAINTAINERCLEANFILES = Makefile.in

