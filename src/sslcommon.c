#include <stdio.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "sslcommon.h"

int get_date_from_ssl(SSL *ssl, char *buff, int buff_len)
{
    BIO *wbio = SSL_get_wbio(ssl);
    int ret = 0;

    if(BIO_pending(wbio) > 0){
        ret = BIO_read(wbio, buff, buff_len);
    }

    return ret;
}

int put_data_into_ssl(SSL *ssl, const char *buff, int buff_len)
{
    BIO *rbio = SSL_get_rbio(ssl);

    return BIO_write(rbio, buff, buff_len);
}

int get_date_from_ssl_and_send_to_socket(SSL *ssl, int sockfd)
{
    int len;
    char buff[4096];

    len = get_date_from_ssl(ssl, buff, sizeof(buff));
    if(!len){
        return 0;
    }

    return send(sockfd, buff, len, 0);
}

int get_date_from_socket_and_send_to_ssl(SSL *ssl, int sockfd)
{
    int len;
    char buff[4096];

    len = recv(sockfd, buff, sizeof(buff), 0);
    if(len < 1){
        return len;
    }

    return put_data_into_ssl(ssl, buff, len);
}

