/* mode: c; c-basic-offset: 2
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*
================================================================================
Date        Author                        Remarks
--------------------------------------------------------------------------------
05/15/2016  naushad.dln@gmail.com         Inital Draft

------------------------------------------------------------------------------*/

#ifndef __TLS_C__
#define __TLS_C__

#include "tls.h"


/**
 * This function is used to create the TCP socket of INTERNET TYPE
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     none
 * @return    Newly created file descriptor upon success or an error upon
 *            failure.
 */

SSL_CTX *tls_init(void)
{
  const SSL_METHOD *method;
  SSL_CTX    *ctx;

  OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
  SSL_load_error_strings();			/* Bring in and register error messages */
  method = SSLv23_client_method();		/* Create new client-method instance */
  //method = TLS_method();		/* Create new client-method instance */
  //method = TLSv1_2_client_method();
  ctx = SSL_CTX_new(method);			/* Create new context */
  if(ctx == NULL)
  {
    fprintf(stderr, "Context for SSL creation Failed\n");					
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* ---------------------------------------------------------- *
   * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
   * ---------------------------------------------------------- */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  return ctx;  				
}/*tls_init*/

/**
 * This function is used to create the TCP socket of INTERNET TYPE
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     none
 * @return    Newly created file descriptor upon success or an error upon
 *            failure.
 */

SSL *tls_main(int tcp_fd)
{
  SSL_CTX *ctx;
  SSL *ssl;
  int rc = -1;

  ctx = tls_init();
  assert(ctx != NULL);

  /*create new SSL connection state*/
  ssl = SSL_new(ctx);
  assert(ssl != NULL);

  /*attach the tcp socket descriptor to SSL*/
  rc = SSL_set_fd(ssl, tcp_fd);
  assert(rc == 1);
 
  	
  /*Initiate ClientHello Message to TLS Server*/
  if((rc = SSL_connect(ssl)) != 1)
  {
#if 0					
    while(SSL_ERROR_WANT_WRITE == SSL_get_error(ssl, rc))
    {
      sleep(10000);
      rc = SSL_connect(ssl);			
    }
#endif		
    fprintf(stderr, "SSL Connect Failed rc = %d %d\n",rc, SSL_get_error(ssl, rc));
    /*TLS/SSL handshake is not successfullu*/
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return (NULL);
  }				
  return (ssl);
}/*tls_main*/

/**
 * This function is used to create the TCP socket of INTERNET TYPE
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     none
 * @return    Newly created file descriptor upon success or an error upon
 *            failure.
 */
int tls_peek(SSL *ssl_fd, char *plain_buffer, unsigned int plain_buffer_len)
{
  int rc = -1;

  assert(plain_buffer != NULL);

  rc = SSL_peek(ssl_fd, 
                plain_buffer, 
                /*Max plain buffer size*/
                plain_buffer_len);
  return(rc);

}/*tls_peek*/



/**
 * This function is used to create the TCP socket of INTERNET TYPE
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     none
 * @return    Newly created file descriptor upon success or an error upon
 *            failure.
 */
int tls_read(SSL *ssl_fd, char *plain_buffer, unsigned int plain_buffer_len)
{
  int rc = -1;

  assert(plain_buffer != NULL);

  rc = SSL_read(ssl_fd, 
                plain_buffer, 
                /*Max plain buffer size*/
                plain_buffer_len);

  return(rc);

}/*tls_read*/

/**
 * This function is used to create the TCP socket of INTERNET TYPE
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     none
 * @return    Newly created file descriptor upon success or an error upon
 *            failure.
 */
int tls_write(SSL *ssl_fd, char *plain_buffer, unsigned int plain_buffer_len)
{
  int rc = -1;

  assert(plain_buffer != NULL);

  rc = SSL_write(ssl_fd, 
                 plain_buffer, 
                 /*Max plain buffer size*/
                 plain_buffer_len);

  return(rc);
			
}/*tls_write*/

#endif
