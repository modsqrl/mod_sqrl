bin_PROGRAMS = test
test_SOURCES = sqrl_encodings_test.c
test_CFLAGS = -I$(srcdir)/../../main/c \
              @APR_CFLAGS@ @APU_CFLAGS@
test_CPPFLAGS = @APR_CPPFLAGS@
test_LDADD = ../../main/c/libsqrl.a @APR_LDADD@ @APU_LDADD@

MAINTAINERCLEANFILES = Makefile.in

