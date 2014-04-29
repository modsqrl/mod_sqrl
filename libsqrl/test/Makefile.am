TESTS = test
check_PROGRAMS = test
test_SOURCES = sqrl_encodings_test.c \
               ../src/sqrl_encodings.h \
			   sqrl_test.c \
			   test.c
test_CFLAGS = @APR_CFLAGS@ @APU_CFLAGS@ \
              @CHECK_CFLAGS@
test_CPPFLAGS = -I../src @APR_CPPFLAGS@
test_LDADD = ../src/libsqrl.la \
             @APR_LDADD@ @APU_LDADD@ \
             @CHECK_LIBS@

MAINTAINERCLEANFILES = Makefile.in

