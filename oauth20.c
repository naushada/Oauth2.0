#ifndef __OAUTH20_C__

#define __OAUTH20_C__

#include "common.h"
#include "oauth20.h"
#include "http.h"
#include "util.h"

oauth20_authorization_response_t g_authorize_response = 
{
  .code        = "",
  .state       = "",
  .host_name   = "",
  .uri         = "",
  .protocol    = "",
  .status_code = "",
  .status_str  = ""
};

/* For Google Sign-In, scope would have any one from three
 * 1) scope=profile -> View your basic profile
 * 2) scope=email   -> View your e-mail address
 * 3) scope=openID  -> Authenticate using OpenID
 * */
oauth20_authorization_request_t g_authorize_request = 
{
  .media_type     = "application/x-www-form-urlencoded",
  .uri            = "https://accounts.google.com/o/oauth2/v2/auth",
  .response_type  = "code",
  .client_id      = GOOGLE_CLIENT_ID,
  /*callback URI*/
  .redirect_uri   = "http://localhost:8084/oauth20_code_callback",
  /*scopes can be found by visiting this link - https://developers.google.com/identity/protocols/googlescopes */
  .scope          = "email",
  .state          = "",
  .host           = "www.accounts.google.com"
};


oauth20_error_t g_error = 
{
  .error_str = "access_denined",
  .state     = "",
  .host_name = "", 	
};


oauth20_access_token_request_t g_access_token_req = 
{
  .media_type     = "application/x-www-form-urlencoded ;charset=UTF-8",
  .uri           = "/oauth2/v4/token"	,
  .grant_type    = "authorization_code",
  .response_type = "token",
  .redirect_uri  = "http://localhost:8084/oauth20_code_callback",
  .client_id     = GOOGLE_CLIENT_ID,
  .client_secret = GOOGLE_CLIENT_SECRET,
  .scope         = "email",
  /*32 Bytes Random number encoded in base64 character in authorization request*/
  .state         = "",
  /*Received in Authorization_response*/
  .code          = "",
  .host_name     = "www.googleapis.com"
};

oauth20_access_token_response_t g_access_token_rsp = 
{
  .access_token    = "authorization_code",
  .expires_in      = "token",
  .token_type      = "",
  .scope           = "",
  /*32 Bytes Random number encoded in base64 character in authorization request*/
  .state           = "",
  .host_name       = "" 
};

oauth20_command_context_t g_oauth20_ctx =
{
  .cmd              = OAUTH20_AUTHORIZE_REQUEST,
  .cmd_state        = OAUTH20_AUTHORIZE_REQUEST_ST,
  .request_length   = 0,
  .response_length  = 0,
  .request_ptr      = NULL,
  .response_ptr     = NULL	
};

/*----------------------------------------
 * Function Definitions.
 *-------------------------------------- */


int oauth20_set_code(char *code_value, int code_value_length)
{
  strncpy((char *)g_access_token_req.code, 
			code_value, 
			code_value_length);	
  return(0);
}/*oauth20_set_code*/


int oauth20_set_state(char *state_value, int state_value_length)
{
  strncpy((char *)g_access_token_req.state, 
			state_value, 
			state_value_length);	
  return(0);	
}/*oauth20_set_state*/


int oauth20_authorize_request(unsigned char *oauth20, unsigned int *oauth20_len)
{
  int rc = -1;

  unsigned char *state = NULL;
  unsigned char *base64_char = NULL;

  assert(NULL != oauth20);
  state = util_get_access_token(&rc);
  assert(NULL != state);

#ifdef __DEBUG
  util_print_hex(state, rc);
#endif

  base64_char = util_base64_encode(state, (unsigned int)rc, (unsigned int *)&rc);
  assert(NULL != base64_char);
  
  strncpy((char *)g_authorize_request.state, (const char *)base64_char, rc);
  
  /*Freeing the allocated memory*/
  free(state);
  free(base64_char);

  /*
   * https://accounts.google.com/o/oauth2/v2/auth?
     scope=email%20profile&
     response_type=code&
     state=security_token%3D138r5719ru3e1%26url%3Dhttps://oauth2.example.com/token&
     redirect_uri=http://127.0.0.1:9004&
     client_id=client_id
  */
  rc = snprintf((char *)oauth20,
                *oauth20_len,
                "%s%s%s%s%s"
                "%s%s%s%s%s"
                "%s%s%s%s%s"
                "%s%s%s%s%s"
                "%s%s",
                "GET ",
                g_authorize_request.uri,
                "?scope=",
                g_authorize_request.scope,
                "&response_type=",
                g_authorize_request.response_type,
                "&state=",
                g_authorize_request.state,
                "&redirect_uri=",
                g_authorize_request.redirect_uri,
                "&client_id=",
                g_authorize_request.client_id,
                /*A blank space is left purposely*/
                " HTTP/1.1",
                "\r\n",
                "Host:",
                g_authorize_request.host,
                "\r\n",
                "Content-Type:",
                g_authorize_request.media_type,
                "\r\n",
                "Content-length: 0",
                /*Separation B/W header and body*/
                "\r\n\r\n");
#ifdef __DEBUG
  util_print_string(oauth20);
#endif
  *oauth20_len = rc;
	fprintf(stderr, "Authorize Request is %s\n",oauth20);
  return(rc);
}/*oauth20_authorize_request*/


int oauth20_error_handle(const char *response_ptr, unsigned int response_length)
{
  int rc = -1;
  char *status;
  char *contents;
  char *replica_ptr = NULL;

  /*Calling proces terminates once expression evaluates to false*/
  assert(response_ptr != NULL);
 
	replica_ptr = (char *)malloc(response_length);
  assert(replica_ptr != NULL);
  memset((void *)replica_ptr, 0, response_length);

	memcpy((void *)replica_ptr, response_ptr, response_length);

  status = strtok((char *)replica_ptr, "\r\n");
  assert(status != NULL);  
	
  contents = strtok(NULL, "\r\n");
  assert(contents != NULL);
  /*!
   * HTTP/1.1 302 Found
     Location: https://client.example.com/cb?error=access_denied&state=xyz
   * */
  rc = sscanf(contents, "%*s %[^?]?error=%[^&]&state=%s",
              g_error.host_name,
              g_error.error_str,
              g_error.state);
#ifdef __DEBUG
  fprintf(stderr, "Host Name %s error_string %s state %s\n",
           g_error.host_name,
           g_error.error_str,
           g_error.state);

#endif /*__DEBUG*/

	free(replica_ptr);
	replica_ptr = NULL;
  assert(rc == 3);

  return(0);

}/*oauth20_error_handle*/


int oauth20_access_token_request(unsigned char *token_req, unsigned int *token_req_len)
{
  int           rc = -1;
  char          req_body[1024];
  char          *form_urlencoded_body = NULL;
	unsigned int  encoded_body_length   = 0;

#ifdef __DEBUG
  util_print_hex(state, rc);
#endif

  rc = snprintf(req_body, sizeof(req_body),
                "%s%s%s%s%s"
                "%s%s%s%s%s",
                "code=",
                g_access_token_req.code,
                "&client_id=",
                g_access_token_req.client_id,
                "&client_secret=",
                g_access_token_req.client_secret,
                "&redirect_uri=",
                g_access_token_req.redirect_uri,
                "&grant_type=",
                g_access_token_req.grant_type);

  form_urlencoded_body = http_x_www_form_urlencode(req_body, 
			          rc,
			          &encoded_body_length); 

  rc = snprintf((char *)token_req, *token_req_len,
                "%s%s%s%s%s"
                "%s%s%s%s%s"
                "%d%s%s%s",
                "POST ",
                /*Need to check with google*/
                g_access_token_req.uri,
                " HTTP/1.1\r\n",
                "Host: ",
                g_access_token_req.host_name,
                "\r\n",
                "Content-Type: ",
                g_access_token_req.media_type,
                "\r\n",
                "Content-Length: ",
                encoded_body_length,
                "\r\n",
                "\r\n",
								form_urlencoded_body);
	
	free(form_urlencoded_body);
  form_urlencoded_body = NULL;
	*token_req_len = rc;

  return (rc);
}/*oauth20_access_token_request*/


char *oauth20_access_token_response(const char *response_ptr, 
		unsigned int response_length,
		int *out_data_length_ptr)
{
  int rc = -1;
  char *line_string;
  char *replica_ptr = NULL;
	char http_response_ok[512];

	replica_ptr = (char *) malloc(response_length);
	assert(replica_ptr != NULL);

	memset((void *)replica_ptr, 0, response_length);
	memcpy((void *)replica_ptr, response_ptr, response_length);

  rc = http_get_content_length(replica_ptr, response_length);

	
	if(rc <= 0)
	{
		free(replica_ptr);
		replica_ptr = NULL;
    return(replica_ptr);		
	}

  /*Re-using replica-ptr*/
  memset((void *)replica_ptr, 0, response_length);  
  memcpy((void *)replica_ptr, (const void *)&response_ptr[response_length - rc], rc);

  line_string = strtok(replica_ptr, "\n");
  /*Ignore the first string*/

	rc = sscanf(line_string, "%*[^:]:%s", g_access_token_rsp.access_token);
	
	line_string = strtok(NULL, "\n");

	rc = sscanf(line_string, "%*[^:]:%s", g_access_token_rsp.token_type);
	
	line_string = strtok(NULL, "\n");

	rc = sscanf(line_string, "%*[^:]:%s", g_access_token_rsp.expires_in);

	line_string = strtok(NULL, "\n");

	if(NULL != line_string)
	{
		/*id_token will be received in access token response,
		 * if scope in request set to either email or profile*/
	  rc = sscanf(line_string, "%*[^:]:%s", g_access_token_rsp.id_token);
	}

  free(replica_ptr);
	replica_ptr = NULL;

	memset((void *)http_response_ok, 0, sizeof(http_response_ok));

	rc = snprintf((char *)http_response_ok, sizeof(http_response_ok),
			"%s%s%s%s%s"
			"%s",
			"HTTP/1.1 200 OK\r\n",
			"Host:",
			g_access_token_req.host_name,
			"\r\n",
			"Content-Length: 0\r\n",
			"\r\n\r\n");
  /*Re-using replica_ptr*/
	replica_ptr = (char *)malloc(rc);
	assert(replica_ptr != NULL);

	memset((void *)replica_ptr, 0, rc);
	memcpy((void *)replica_ptr, http_response_ok, rc);
  *out_data_length_ptr = rc;
	fprintf(stderr, "\nresponse response is %s\n", replica_ptr);
	return(replica_ptr);	            	
}/*oauth20_access_token_response*/


/*!
 * HTTP/1.1 302 Found
   Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
            &state=xyz
 * */
int oauth20_authorize_response(const char *response, unsigned int response_length)
{
  int rc = -1;
  unsigned char dummy[64];
  char *status;
  char *contents;
  
  /*Calling proces terminates once expression evaluates to false*/
  assert(response != NULL);
  
  status = strtok((char *)response, "\r\n");
  assert(status != NULL);
  
  contents = strtok(NULL, "\r\n");
  assert(contents != NULL);

/*!
 * HTTP/1.1 302 Found
   Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
            &state=xyz
 * */
  rc = sscanf(status, "%s %s %s",
        g_authorize_response.protocol,
        g_authorize_response.status_code,
        g_authorize_response.status_str);
#ifdef __DEBUG
  fprintf(stderr, "protocol %s status_code %s status_str %s\n",
      g_authorize_response.protocol,
      g_authorize_response.status_code,
      g_authorize_response.status_str);
#endif /*__DEBUG*/

  assert(rc == 3);

  /*Validates whether Response is success or not*/
  rc = sscanf(contents, "%*s %*[^?]?%[^=]=%*s", dummy);
  assert(rc == 1);

  if(!strncmp((const char *)dummy, (const char *)"error", 5))
  {
    /*Process the error message received from Authorization Server*/
    oauth20_error_handle(response, response_length); 
    return (-1);					
  }
  else
  {
    /* %*s will match the string and suppress /discard it (Do not need to put value in any variable)*/
    rc = sscanf(contents, "%*s %[^?]?%*[^=]=%[^&]&%*[^=]=%s",
    g_authorize_response.host_name,
    /*Storing the code value and is valid for 10 minutes only*/
    g_authorize_response.code,
    /*Storing the value of state*/
    g_authorize_response.state);
#ifdef __DEBUG
    fprintf(stderr, "Host Name %s response_code %s state %s\n",
    g_authorize_response.host_name,
    g_authorize_response.code,
    g_authorize_response.state);
#endif /*__DEBUG*/
    assert(rc == 3);
  }
  return(0);

}/*oauth20_authorize_response*/


char *oauth20_process_response(const char *data_ptr, 
	 	                           int        data_length, 
                               int        *request_length_ptr)
{
  return(oauth20_process_request(data_ptr, 
				                         data_length, 
				                         request_length_ptr)); 			
  
}/*oauth20_process_response*/

char *oauth20_process_request(const char *data_ptr, 
		                          int        data_length, 
                              int        *request_length_ptr)
{
	int rc = -1;

  switch(g_oauth20_ctx.cmd_state)
	{
		case OAUTH20_AUTHORIZE_REQUEST_ST:
		{
			*request_length_ptr = 1024;
      char *auth_req_ptr = (char *) malloc(*request_length_ptr);
      
			memset(auth_req_ptr, 0, *request_length_ptr);

      (void)oauth20_authorize_request((unsigned char *)auth_req_ptr, 
					                            (unsigned int *)request_length_ptr);

			g_oauth20_ctx.cmd_state = OAUTH20_USER_CONSENT_REQUEST_ST;
			//g_oauth20_ctx.cmd_state = OAUTH20_ACCESS_TOKEN_REQUEST_ST;

			return(auth_req_ptr);
		}
		case OAUTH20_USER_CONSENT_REQUEST_ST:
		{
      unsigned int header_length = 0;
			unsigned int body_length   = 0;
			unsigned char mime_value[1024];
      char *http_request_ptr = NULL;
			unsigned int  mime_value_length = 0;
			unsigned char host_name[256];
      unsigned int  host_name_length = 0;

			/*Returning on purpose */
			g_oauth20_ctx.cmd_state = OAUTH20_ACCESS_TOKEN_REQUEST_ST;
			*request_length_ptr = 0;
			return(http_request_ptr);
			
			header_length = http_get_header_length(data_ptr, data_length);
			body_length   = http_get_content_length(data_ptr, data_length);
     
		  memset((void *)mime_value, 0, sizeof(mime_value));	
		  http_get_status_code(data_ptr, header_length, (unsigned char *)mime_value);
		 	
			if(!strncmp((const char *)mime_value, "Found", 5))
			{
		    memset((void *)mime_value, 0, sizeof(mime_value));
        mime_value_length = http_get_location_value((const char *)data_ptr, 
						                                        header_length, 
						                                        (unsigned char *)mime_value);
			}
	    if(mime_value_length > 0)
			{
				memset((void *)host_name, 0, sizeof(host_name));
				host_name_length = http_get_host_value(data_ptr, header_length, (unsigned char *)host_name);

				http_request_ptr = (char *)malloc(mime_value_length + 512);

        /*Prepare HTTP/1.1 Request*/
        rc = snprintf(http_request_ptr,(mime_value_length + 512) ,
	                   "%s%s%s%s%s"
	                   "%s%s%s%s",
						         "GET ",
										 /*8 = https:// & 4 = www.*/
                    // (char *)&mime_value[8 + (host_name_length - 4)],
										 mime_value,
										 " HTTP/1.1\r\n",
										 "Host: ",
										 host_name,
										 "\r\n",
										 "Content-Length: 0",
										 "\r\n",
										 "\r\n\r\n");

			}		
			/*In this state It will receive code & state value via unix ipc*/
			/*Forward it to we-browser*/
			g_oauth20_ctx.cmd_state = OAUTH20_ACCESS_TOKEN_REQUEST_ST;
			*request_length_ptr = rc;
			return(http_request_ptr);
		}
    case OAUTH20_ACCESS_TOKEN_REQUEST_ST:
		{
      char state_value[256];
      char code_value[256];
      int rc = -1;
			
			*request_length_ptr = 2048;
      char *access_req_ptr = (char *) malloc(*request_length_ptr);
      assert(access_req_ptr != NULL);

			memset(access_req_ptr, 0, *request_length_ptr);
			memset((void *)state_value, 0, sizeof(state_value));
      memset((void *)code_value,  0, sizeof(code_value));
      fprintf(stderr, "QS \n%s\n", data_ptr);

			rc = sscanf(data_ptr, "state=%[^&]&code=%s",
				          state_value,	
					        code_value);
			assert(rc == 2);
			
			oauth20_set_code(code_value,   strlen(code_value));
			oauth20_set_state(state_value, strlen(state_value));

      oauth20_access_token_request((unsigned char *)access_req_ptr, 
					                         (unsigned int *)request_length_ptr);

			g_oauth20_ctx.cmd_state = OAUTH20_ACCESS_TOKEN_RESPONSE_ST;
			return(access_req_ptr);
		}
		case OAUTH20_ACCESS_TOKEN_RESPONSE_ST:
		{
			char *http_response_ptr = NULL;
			int  http_response_length = 0;

      http_response_ptr = oauth20_access_token_response(data_ptr, 
					data_length, 
					&http_response_length);
			*request_length_ptr = http_response_length;

		  return(http_response_ptr);	
		}
    case OAUTH20_DONE_ST:
      break;
    case OAUTH20_ERROR_ST:
      break;			
	}
  return(NULL);	
}/*oauth20_process_request*/

#endif
