#ifndef __TLS_H__

#define __TLS_H__

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <assert.h>

int tls_write(SSL *ssl_fd, char *plain_buffer, unsigned int plain_buffer_len);

int tls_read(SSL *ssl_fd, char *plain_buffer, unsigned int plain_buffer_len);
				
SSL *tls_main(int tcp_fd);
				
SSL_CTX *tls_init(void);

int tls_peek(SSL *ssl_fd, char *plain_buffer, unsigned int plain_buffer_len);

#endif
