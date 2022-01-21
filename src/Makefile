DEPS=-Wall -pthread -ldl

OPTIMIZE=-O0 -g

ifeq ($(OPENSSLDIR),)
OPENSSLDIR=/usr/src/openssl-3.0.1
endif

all: client

client:
	gcc -g ${OPTIMIZE} ${DEPS} -I${OPENSSLDIR}/include testclient.c sslcommon.c ${OPENSSLDIR}/libssl.a ${OPENSSLDIR}/libcrypto.a -o client

clean:
	rm -f client