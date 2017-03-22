#ifndef __OAUTH20_H__
#define __OAUTH20_H__


#include "tcp.h"

/*---------------------------------------
 * Macro Definitions.
 *-------------------------------------- */

#define GOOGLE_CLIENT_ID "158114768257-iajnjdgg8nstsbrb6t7hclb4vcqboroc.apps.googleusercontent.com"

#define GOOGLE_CLIENT_SECRET "bz00RXv3Fh__JaqYmV_MiT1p"

/*---------------------------------------
 * Enumeration Definitions.
 *-------------------------------------- */

typedef enum
{
  OAUTH20_AUTHORIZE_REQUEST = 0,
  OAUTH20_AUTHORIZE_RESPONSE,
  OAUTH20_ACCESS_TOKEN_REQUEST,
  OAUTH20_ACCESS_TOKEN_RESPONSE
  	
}oauth20_command_t;

typedef enum
{
  OAUTH20_AUTHORIZE_REQUEST_ST,
	OAUTH20_USER_CONSENT_REQUEST_ST,
	OAUTH20_AUTHORIZE_RESPONSE_ST,
	OAUTH20_ACCESS_TOKEN_REQUEST_ST,
	OAUTH20_ACCESS_TOKEN_RESPONSE_ST,
  OAUTH20_ERROR_ST,
  OAUTH20_DONE_ST	
}oauth20_command_state_t;

/*--------------------------------------
 * Data Structure Definitions.
 *------------------------------------ */

typedef struct
{
  oauth20_command_t cmd;
  oauth20_command_state_t cmd_state;
  int  request_length;
	int  response_length;
	char *request_ptr;
  char *response_ptr;
  	
}oauth20_command_context_t;


/*Refer RFC6749 sec-4.1.1*/				

/*!
 * 
   GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
        &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
   Host: server.example.com
 * */
typedef struct 
{
  /*Media Type shall be application/x-www-form-urlencoded*/				
  char media_type[128];
	/*Request URI*/
	char uri[256];
	/*Its value must be set to "code"*/
  char response_type[64];
	/*client id can be retrieve from google develope page*/
  char client_id[512];
	/*It is this URL at which google will contact to provide token*/
  char redirect_uri[1024];
	/**/
  char scope[256];
	/*should be long random numbers atleast 32 Bytes*/
  char state[512];
	/*Host name*/
	char host[256];

}oauth20_authorization_request_t;

/*!
 * HTTP/1.1 302 Found
   Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
    &state=xyz
 *
 * */
typedef struct
{
  char code[512];
  char state[512];
  char host_name[256];
	char uri[256];
	char protocol[16];
	char status_code[8];
	char status_str[256];

}oauth20_authorization_response_t;

/*!Error Response
  HTTP/1.1 302 Found
   Location: https://client.example.com/cb?error=access_denied&state=xyz
   int get_access_token(char **token, int *token_len);
*/

typedef struct
{
  unsigned char error_str[256];
  unsigned char state[512];
  unsigned char host_name[256];
}oauth20_error_t;



typedef struct
{
  /*!Must be set to "authorization_code*/				
  unsigned char grant_type[64];
	/*Authorization code received from authorization server*/
	unsigned char response_type[64];
	unsigned char redirect_uri[512];
	unsigned char client_id[512];
	unsigned char client_secret[512];
	unsigned char scope[256];
	unsigned char state[256];
	unsigned char code[256];
	unsigned char host_name[256];
	unsigned char user_id[256];
	unsigned char passwd[256];
	char uri[256];
  /*Media Type shall be application/x-www-form-urlencoded*/				
  char media_type[128];
/*!
 * Request shall be made with TLS
 * POST /token HTTP/1.1
   Host: server.example.com
   Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
   &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
 * */
}oauth20_access_token_request_t;

/*!
 * HTTP/1.1 200 OK
   Content-Type: application/json;charset=UTF-8
   Cache-Control: no-store
   Pragma: no-cache

   {
     "access_token":"2YotnFZFEjr1zCsicMWpAA",
     "token_type":"example",
     "expires_in":3600,
     "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
     "example_parameter":"example_value"
   }
 * */

typedef struct
{
  char host_name[256];
  char access_token[256];
  char expires_in[32];
	char token_type[64];
  char scope[32];
  char state[32];
	char id_token[1024];

}oauth20_access_token_response_t;

/*------------------------------------------------
 *Function Signature/Prototype.
 *---------------------------------------------- */

int oauth20_set_code(char *code_value, int code_value_length);

int oauth20_set_state(char *state_value, int state_value_length);

char *oauth20_process_request(const char *command_request_ptr, int command_request_length, int *request_length_ptr);

char *oauth20_process_response(const char *response_ptr, int response_length, int *new_request_length);

int oauth20_authorize_request(unsigned char *oauth20, unsigned int *oauth20_len);

int oauth20_authorize_response(const char *auth_response, unsigned int auth_response_len);

int oauth20_access_token_request(unsigned char *in_param, unsigned int *token_request_len);

char *oauth20_access_token_response(const char *token_response, unsigned int token_response_len, int *out_length_ptr);

int oauth20_error_handle(const char *response, unsigned int response_len);

#endif
