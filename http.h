#ifndef __HTTP_H__
#define __HTTP_H__

#include "common.h"

char *http_x_www_form_urlencode(char *in_data_ptr, unsigned int in_data_length, unsigned int *out_data_length);

unsigned int http_get_content_length(const char *response, unsigned int response_length);

unsigned int http_get_header_length(const char *response, unsigned int response_length);

int http_process_uri(char *uri);

char *http_process_uri_qs(const char *request_ptr,
                          unsigned int request_length,		
                          char *uri, 
                          char *qs,
                          unsigned int *response_length);


char *http_process_request(const char *request_ptr, 
                           unsigned int request_length, 
                           unsigned int *response_length);



int http_process_response(const char    *response_ptr, 
		                      unsigned int  response_length, 
		                      unsigned char *http_header_ptr, 
		                      unsigned int  *http_header_length_ptr,
		                      unsigned char *http_body_ptr,
		                      unsigned int  *http_body_length_ptr);


char *http_process_code_callback_request(const char *request_ptr,
                                         unsigned int request_length,
                                         char *qs,
                                         unsigned int *response_length);


int http_get_status_code(const char *http_header_ptr, unsigned int http_header_length, unsigned char *status_code);


int http_get_location_value(const char *http_header_ptr, unsigned int http_header_length, unsigned char *location_value);


int http_get_host_value(const char *http_header_ptr, unsigned int http_header_length, unsigned char *host_name);

#endif /*__HTPP_H__*/
