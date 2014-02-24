
BASEDIR=/usr/local/apache22

AP_INC=${BASEDIR}/bin/apxs -q APR_INCLUDEDIR
APR_INC=$(BASEDIR/bin/apxs -q INCLUDEDIR)
INCLUDE=-I$(BASEDIR)/include -I/usr/include -I/usr/local/include
LIBRARY=-L$(BASEDIR)/lib -L/usr/lib64 -lcheck -lapr-1 -laprutil-1 -lsodium
CFLAGS=-g -Wall -O0 $(INCLUDE) $(LIBRARY)
CXXFLAGS=$(CFLAGS)

.PHONY: all test

all: base64

base64: base64.c

test: sqrl_encodings_test.o
	$(CC) $(CFLAGS) sqrl_encodings_test.o -o test
	LD_LIBRARY_PATH=/usr/local/lib ./test

