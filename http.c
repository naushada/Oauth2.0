#ifndef __HTTP_C__
#define __HTTP_C__

#include "http.h"

#ifdef __UNIX_SOCKET_IPC__
#include "unix.h"
#endif /*__UNIX_SOCKET_IPC__*/

/*-----------------------------------
 * extern declaration
 *---------------------------------- */
#ifdef __UNIX_SOCKET_IPC__
extern un_sock_ipc_ctx_t g_un_ctx;
#endif /*__UNIX_SOCKET_IPC__*/

/*----------------------------------
 * Functions Definition
 *--------------------------------- */


char *http_x_www_form_urlencode(char *in_data_ptr, unsigned int in_data_length, unsigned int *out_data_length)
{
  int idx = 0;
	char *out_data_ptr = NULL;
  char tmp_buff[1024];
  
	*out_data_length = 0;
	memset((void *)tmp_buff, 0, sizeof(tmp_buff));

  for(idx = 0; (in_data_ptr[idx] != '\0'|| idx < in_data_length); idx++)
	{
    if('/' == in_data_ptr[idx])
		{
      tmp_buff[(*out_data_length)++] = '%';
      tmp_buff[(*out_data_length)++] = '2';
      tmp_buff[(*out_data_length)++] = 'F';
		}
    else if(':' == in_data_ptr[idx])
    {
      tmp_buff[(*out_data_length)++] = '%';
      tmp_buff[(*out_data_length)++] = '3';
      tmp_buff[(*out_data_length)++] = 'A';
    }
    else
		{
      tmp_buff[(*out_data_length)++] = in_data_ptr[idx];			
		}		
	}	
  out_data_ptr = (char *) malloc(*out_data_length);
	
	assert(out_data_ptr != NULL);
  
	memset((void *)out_data_ptr, 0, *out_data_length);
	memcpy((void *)out_data_ptr, (void *)tmp_buff, *out_data_length);
	return(out_data_ptr);
}/*http_x_www_form_urlencode*/

int http_process_uri(char *uri)
{
  fprintf(stderr, "Received uri is %s\n", uri);
  return(0);

}/*http_process_uri*/


char *http_process_code_callback_request(const char *request_ptr,
                                         unsigned int request_length,
                                         char *qs,
                                         unsigned int *response_length)
{
  int rc = -1;
  char http_header[1024];
	char code_value[256];

	/*Value of state is sent in request and is used to map request to response*/
	char state_value[256];
  unsigned int http_header_length = 0;
  char *response_ptr = NULL;
#ifdef __UNIX_SOCKET_IPC__
	int  un_fd            = -1;
	char *un_path_ptr     = NULL;
	int  un_rc            = -1;
	char *byte_data_ptr   = NULL;
	int  byte_data_length = -1;
	int  message_length = -1;
#endif /*__UNIX_SOCKET_IPC__*/

	memset((void *)code_value, 0, sizeof(code_value));

  /*
	 * GET /oauth20_code_callback?state=QivGaqeJfTf+r6DaRFZyicUkUkiDktDAFBXZOXAhn4g%3D&
	 * code=4/UMa4FUpyW99jMxej9sWBzEImY3mbT9yFiZHNOEIYt4s 
	 * HTTP/1.1
	 * */ 
  rc = sscanf(qs, "state=%[^&]&code=%s",state_value, code_value);
	
	/*Now value of code shall be used to request to Token*/
  /*Send code to Oauth20 Client to request for Token*/
  /*Prepare HTTP/1.1 Response*/ 
  http_header_length = snprintf(http_header, 
			                          sizeof(http_header),
																"%s%s%s%s%s"
																"%s%s%s",
		  	                        "HTTP/1.1 200 OK\r\n",
                                "Host: www.accounts.google.com\r\n",
																"Connection: Keep-Alive\r\n",
																"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n",
                                "Accept-Encoding: gzip, deflate, sdch, br\r\n",
                                "Accept-Language: en-US,en;q=0.8\r\n",
																/*No Response Body*/
																"Content-Length: 0\r\n",
																/*HTTP Header delimeter - meaning Header end at this point*/
																"\r\n\r\n");

  response_ptr = (char *)malloc(http_header_length);
  assert(response_ptr != NULL);
	
  memset(response_ptr, 0, http_header_length);
  memcpy(response_ptr, http_header, http_header_length);
	
  *response_length = http_header_length;

#ifdef __UNIX_SOCKET_IPC__
  /*Sending code to Oauth2.0 client via unix socket ipc*/
  byte_data_length = strlen((const char *)qs) + 4 + 2;
  message_length    = strlen((const char *)qs);

  byte_data_ptr = (char *)malloc(byte_data_length);
  memset(byte_data_ptr, 0, byte_data_length);
  /*encoding length in big-endian order*/
  byte_data_ptr[0] = (message_length >> 24) & 0xFF;
  byte_data_ptr[1] = (message_length >> 16) & 0xFF;
  byte_data_ptr[2] = (message_length >> 8)  & 0xFF;
  byte_data_ptr[3] = (message_length >> 0)  & 0xFF;
  /*encoding of verion field*/
  byte_data_ptr[4] = (2 >> 8)  & 0xFF;
  byte_data_ptr[5] = (0 >> 0)  & 0xFF;
  /*copying message itself*/
  memcpy((void *)&byte_data_ptr[6], qs, message_length);	

  un_fd = un_socket(IPPROTO_TCP);
  un_path_ptr = un_get_unix_port();
  un_rc = un_connect(un_fd, un_path_ptr);
  un_rc = un_write(un_fd, byte_data_ptr, (unsigned int)byte_data_length);
  un_rc = un_close(un_fd);
	free(byte_data_ptr);
#endif /*__UNIX_SOCKET_IPC__*/
  return(response_ptr);

}/*http_process_code_callback_request*/


/*!
 * This function will be invoked if both uri and qs are received
 * in HTTP Request.
 * uri - It is a request type
 * qs  - Query String holds parameters in the form of param=value
 *       Delimited by &.
 *
 * */
char *http_process_uri_qs(const char *request_ptr,
                          unsigned int request_length,		
                          char *uri, 
                          char *qs,
                          unsigned int *response_length)
{
  fprintf(stderr, "Received uri is %s qs is %s\n", uri, qs);

  if(!strncmp(uri, "/oauth20_code_callback", 22))
  {
    return(http_process_code_callback_request(request_ptr, 
					                                    request_length,
					                                    qs, 
					                                    response_length));
  }
  return(0);

}/*http_process_uri_qs*/

char *http_process_request(const char *request_ptr, 
                           unsigned int request_length, 
                           unsigned int *response_length)
{
  int rc = -1;
  
  char *replica_ptr  = NULL;
  char *line_ptr     = NULL;
  char *response_ptr = NULL; 
  
  char uri_qs[1024];
  char uri[512];
  char qs[1024];

	memset((void *)uri, 0, sizeof(uri));
	memset((void *)qs, 0, sizeof(qs));
	memset((void *)uri_qs, 0, sizeof(uri_qs));
  
	replica_ptr = (char *)malloc(request_length);
	assert(replica_ptr != NULL);

	memset(replica_ptr, 0, request_length);
	memcpy(replica_ptr, request_ptr, request_length);

  line_ptr = strtok(replica_ptr, "\r\n");
 

  rc = sscanf(line_ptr, "%*s %s %*s", uri_qs); 
  assert(rc == 1);
  free(replica_ptr);

  /*Check whether uri has query string or not*/
  rc = sscanf((const char *)uri_qs, "%[^?]?%s",uri, qs);

  if(1 == rc)
  {
    /*may be that qs (Query String is not present*/
    if(!strncmp((char *)uri_qs, uri, strlen((const char *)uri_qs)))
    {
      /**/
      http_process_uri(uri);
    }
  }
  else
  {
    /*Both URI & QS are Present*/
    response_ptr = http_process_uri_qs(request_ptr,
                                       request_length,
                                       uri, 
                                       qs, 
                                       response_length);
    return(response_ptr);
  }
  return(NULL);

}/*http_process_request*/


int http_process_response(const char    *response_ptr, 
		                      unsigned int  response_length, 
		                      unsigned char *http_header_ptr, 
		                      unsigned int  *http_header_length_ptr,
		                      unsigned char *http_body_ptr,
		                      unsigned int  *http_body_length_ptr) 
{
  unsigned int header_length = 0;
	unsigned int body_length   = 0;

  header_length = http_get_header_length((const char *)response_ptr, response_length);

	body_length   = http_get_content_length((const char *)response_ptr, response_length);
  
	if(header_length > 0)
	{
    memcpy((void *)http_header_ptr, (const void *)response_ptr, header_length);
		*http_header_length_ptr = header_length;
	}

	if(body_length > 0)
	{
    memcpy((void *)http_body_ptr, (const void *)&response_ptr[header_length], (response_length - header_length));
    *http_body_length_ptr = body_length;    		
	}
  return(0);

}/*http_process_response*/


unsigned int http_get_header_length(const char *response_ptr, unsigned int response_length)
{
  char         *line_str            = NULL;
  unsigned int header_length        = 0;
  unsigned char is_empty_line_found = 0;
	char          *replica_ptr        = NULL;

	replica_ptr = (char *)malloc(response_length);
	assert(replica_ptr != NULL);

	memset((void *)replica_ptr, 0, response_length);
  memcpy((void *)replica_ptr, response_ptr, response_length);

  /* strtok function splits response into smaller components called token
   * so make sure that response shall not be used any further.
   * */	
  line_str = strtok(replica_ptr, "\n");
  assert(line_str != NULL);
  
  header_length = strlen((const char *)line_str) + 1;
	
  while(NULL != (line_str = strtok(NULL, "\n")))
  {
   	/*An empty line is the delimeter B/W message header and its body*/					
    if(!strncmp(line_str, "\r", 1))
    {
	    is_empty_line_found = 1;
      break;
    }					
    header_length += strlen((const char *)line_str) + 1;  					
  }
  /*Token is exhausted */
  if(1 == is_empty_line_found)
  {
	  free(replica_ptr);
    return(header_length);
  }
	/*what if header with no empty line - partial data has beed received*/
	free(replica_ptr);
  return(0);					

}/*http_get_header_length*/


unsigned int http_get_content_length(const char *response_ptr, unsigned int response_length)
{
  int rc = -1;
  char *header = NULL;
  char mime_attr[512];
  char mime_value[2024];
  char status_code[8];
  char is_chunked_len_next = 0;
  
	char *replica_ptr = NULL;

	replica_ptr = (char *)malloc(response_length);
	assert(replica_ptr != NULL);

	memset((void *)replica_ptr, 0, response_length);
	memcpy((void *)replica_ptr, response_ptr, response_length);

  header = strtok(replica_ptr, "\r\n");
  assert(header != NULL);
  
  rc = sscanf(header, "%*s %s %*s", status_code);
  assert(rc == 1);
 
  /* Content-Length will not be present in following status code*/
  /* 1)status code 1xx
   * 2)status code 204 and
   * 3)status code 304
   * For more details, Refer to https://tools.ietf.org/html/rfc2616#section-4.4
   * */
  rc = atoi(status_code);
  
  if((1 == ((rc >>16) & 1)) ||
     (204 == rc) ||
     (304 == rc))
  {
		 free(replica_ptr);
    /*Content-Length shall not be present*/					
    return(0);					
  }
  
  while((header = strtok(NULL, "\r\n")) != NULL)
  {
    memset((void *)mime_attr,  0, sizeof(mime_attr));
		memset((void *)mime_value, 0, sizeof(mime_value));

    if(1 == is_chunked_len_next)
    {
      rc = sscanf(header, "%s", mime_value);
      assert(rc == 1);
      snprintf(mime_attr, sizeof(mime_attr), "0x%s", mime_value);
      rc = 0;
      sscanf(mime_attr, "0x%X", &rc);
      free(replica_ptr);
			return(rc);			
    }
    else
    {
      rc = sscanf(header, "%[^:]:%s",mime_attr, mime_value);
      assert(rc == 2);

      if(!strncmp(mime_attr, "Content-Length", 14))
      {
        fprintf(stderr, "Content Length is %d\n", atoi(mime_value));
        free(replica_ptr);
        return(atoi(mime_value));						
      }
      else if((!strncmp(mime_attr, "Transfer-Encoding", 17)) &&
              (!strncmp(mime_value, "chunked", 7)))
      {
        is_chunked_len_next = 1;      						
      }
    }
  }/*while*/
  free(replica_ptr);
  return(0);

}/*http_get_content_length*/

int http_get_status_code(const char *http_header_ptr, unsigned int http_header_length, unsigned char *status_code)
{
  int rc = -1;
  
  rc = sscanf(http_header_ptr, "%*s %*s %s",status_code);
  assert(rc == 1);
  return(0);	
}/*http_get_status_code*/


int http_get_location_value(const char *http_header_ptr, unsigned int http_header_length, unsigned char *location_value)
{
  int rc = -1;
	char *replica_ptr = NULL;
  char *line_string = NULL;
	char mime_attr[256];

	replica_ptr = (char *)malloc(http_header_length);
	assert(replica_ptr != NULL);

	memset((void *)replica_ptr, 0, http_header_length);
	memcpy((void *)replica_ptr, http_header_ptr, http_header_length);
  
	line_string = strtok(replica_ptr, "\r\n");

	while(NULL != (line_string = strtok(NULL, "\r\n")))
	{
		memset((void *)mime_attr, 0, sizeof(mime_attr));
    rc = sscanf((const char *)line_string, "%[^:]:%s", mime_attr, location_value);
		assert(rc == 2);

		if(!strncmp(mime_attr, "Location", 8))
		{
			free(replica_ptr);
			return(strlen((const char *)location_value));
		}
	}
	return(0);

}/*http_get_location_value*/


int http_get_host_value(const char *http_header_ptr, unsigned int http_header_length, unsigned char *host_name)
{
	char *replica_ptr     = NULL;
	char *line_string_ptr = NULL;
  char mime_attr[256];
	char mime_value[1024];

 	replica_ptr = (char *)malloc(http_header_length);
	assert(replica_ptr != NULL);

	memset((void *)replica_ptr, 0, http_header_length);
	memcpy((void *)replica_ptr, http_header_ptr, http_header_length);
 
  line_string_ptr = strtok(replica_ptr, "\r\n");
  
  while(NULL != (line_string_ptr = strtok(NULL, "\r\n")))
	{
    memset((void *)mime_attr,  0, sizeof(mime_attr));
    memset((void *)mime_value, 0, sizeof(mime_value));
		sscanf((const char *)line_string_ptr, "%[^:]:%s", mime_attr, mime_value);
	
		if(!strncmp(mime_attr, "Location", 8))
		{
      /*Get the host name*/
      memset((void *)mime_attr,  0, sizeof(mime_attr));
      sscanf((const char *)mime_value, "https://%[^/]/%*s",	mime_attr);
			memcpy((void *)host_name, "www.", 4);
	    memcpy((void *)&host_name[4], mime_attr, strlen((const char *)mime_attr));
			return(strlen((const char *)host_name));
		}
		else if(!strncmp(mime_attr, "Host", 4))
		{
      memcpy(host_name, mime_value, strlen((const char *)mime_value));
			return(strlen((const char *)host_name));
		}
	}	
  return(0);

}/*http_get_host_value*/
#endif /*__HTTP_C__*/
