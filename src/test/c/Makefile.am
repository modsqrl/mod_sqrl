TESTS = test
check_PROGRAMS = test
test_SOURCES = sqrl_encodings_test.c
test_CFLAGS = -I$(top_srcdir)/src/main/c \
              @APR_CFLAGS@ @APU_CFLAGS@
test_CPPFLAGS = @APR_CPPFLAGS@
test_LDADD = $(top_srcdir)/src/main/c/libsqrl.la \
             @APR_LDADD@ @APU_LDADD@

MAINTAINERCLEANFILES = Makefile.in

