#ifndef OSSL_APPS_H
#define OSSL_APPS_H
#include <openssl/crypto.h>
#include <openssl/ssl.h>

extern int get_date_from_ssl(SSL *ssl, char *buff, int buff_len);
extern int put_data_into_ssl(SSL *ssl, const char *buff, int buff_len);
extern int get_date_from_ssl_and_send_to_socket(SSL *ssl, int sockfd);
extern int get_date_from_socket_and_send_to_ssl(SSL *ssl, int sockfd);

#endif

