
BASEDIR=/usr/local/apache24

AP_INC=${BASEDIR}/bin/apxs -q APR_INCLUDEDIR
APR_INC=$(BASEDIR/bin/apxs -q INCLUDEDIR)
INCLUDE=-I$(BASEDIR)/include -I/usr/local/include
LIBRARY=-L$(BASEDIR)/lib -lapr-1 -laprutil-1 -lsodium
CFLAGS=-g -Wall -O0 $(INCLUDE) $(LIBRARY)

all: base64

base64: base64.c

