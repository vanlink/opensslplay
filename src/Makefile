DEPS=-Wall -pthread -ldl

OPTIMIZE=-O0 -g

ifeq ($(OPENSSLDIR),)
OPENSSLDIR=/usr/src/openssl-3.0.1
endif

all: client async

client:
	gcc -g ${OPTIMIZE} ${DEPS} -I${OPENSSLDIR}/include testclient.c sslcommon.c ${OPENSSLDIR}/libssl.a ${OPENSSLDIR}/libcrypto.a -o client

async:
	gcc -g ${OPTIMIZE} ${DEPS} -I${OPENSSLDIR}/include testasync.c sslcommon.c ${OPENSSLDIR}/libssl.a ${OPENSSLDIR}/libcrypto.a -o async

clean:
	rm -f client async