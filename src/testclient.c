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
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "sslcommon.h"

static char *reqstr = "GET / HTTP/1.1\r\nUser-Agent: curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3\r\nHost: www.baidu.com\r\n\r\n";

int main(int argc, char *argv[])
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    int sockfd = -1;
    struct sockaddr_in serv_addr;
    int ret, error;
    char buff[4096];

    printf("openssl test client, %s\n", OPENSSL_VERSION_TEXT);

    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ASYNC | OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);
    ERR_clear_error();

    if (!ASYNC_is_capable()) {
        printf("ASYNC_is_capable err.\n");
        goto exit;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx){
        printf("SSL_CTX_new err.\n");
        goto exit;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_ASYNC);

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if(!rbio || !wbio){
        printf("BIO_new err.\n");
        goto exit;
    }

    BIO_set_nbio(wbio, 1);
    BIO_set_nbio(rbio, 1);

    ssl = SSL_new(ctx);
    if(!ssl){
        printf("SSL_new err.\n");
        goto exit;
    }

    SSL_set_connect_state(ssl);
    SSL_set_bio(ssl, rbio, wbio);

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        goto exit;
    }

    memset(&serv_addr, 0, sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(443); 

    if(inet_pton(AF_INET, "39.156.66.14", &serv_addr.sin_addr)<=0){
        printf("\n inet_pton error occured\n");
        goto exit;
    }

    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
       printf("\n Error : Connect Failed \n");
       goto exit;
    }

    do{
        ret = SSL_do_handshake(ssl);
        error = SSL_get_error(ssl, ret);
        printf("ret=%d, error=%d\n", ret, error);

        get_date_from_ssl_and_send_to_socket(ssl, sockfd);

        if(!error){
            break;
        }

        get_date_from_socket_and_send_to_ssl(ssl, sockfd);
    }while(error);

    SSL_write(ssl, reqstr, strlen(reqstr));
    get_date_from_ssl_and_send_to_socket(ssl, sockfd);

    get_date_from_socket_and_send_to_ssl(ssl, sockfd);
    SSL_read(ssl, buff, sizeof(buff));

    printf("--------- rsp ----------\n");
    printf("%s", buff);

exit:

    if(sockfd >= 0){
        close(sockfd);
    }

    if(ssl){
        SSL_free(ssl);
    }

    if(ctx){
        SSL_CTX_free(ctx);
    }

    return 0;
}

