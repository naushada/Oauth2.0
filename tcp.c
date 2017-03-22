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

#ifndef __TCP_C__
#define __TCP_C__

#include "common.h"
#include "http.h"
#include "opt.h"
#include "tcp.h"
#include "unix.h"
#include "tls.h"
#include "oauth20.h"

/*--------------------------------------
 *extern declaration.
 *-------------------------------------*/
extern oauth20_command_context_t g_oauth20_ctx;


/*-------------------------------------
 * Function Definitions.
 *----------------------------------- */
/**
 * This function is used to create the TCP socket of INTERNET TYPE
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     none
 * @return    Newly created file descriptor upon success or an error upon
 *            failure.
 */
int tcp_socket(void)
{
  int sock_fd = -1;

  sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  return(sock_fd);
}/* tcp_socket */


int tcp_connect(int conn_fd, const char* ip, unsigned short port)
{
  struct sockaddr_in remote_addr;

  memset((void*)&remote_addr,0,sizeof(remote_addr));

  remote_addr.sin_family        = AF_INET;
  remote_addr.sin_addr.s_addr   = inet_addr(ip);
  remote_addr.sin_port          = htons(port);

  memset((void *)&remote_addr.sin_zero,
         0,
         (size_t)sizeof(remote_addr.sin_zero));
 return(connect(conn_fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr))); 

}/* tcp_connect */


/**
 * This function makes the file descriptor addressable by binding
 * file descriptor to IP address and port.
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     IP Address to be bind and this shall be IPv4.
 * @param     TCP port on which IP Address to associated with.
 * @param     TCP file descriptor.
 * @return    return code of bind function.
 */
int tcp_bind(const char *ip_address, int ip_port, int sock_fd)
{
  int rc = -1;
  struct sockaddr_in self_addr;

  memset((void*)&self_addr,0,sizeof(self_addr));

  self_addr.sin_family        = AF_INET;
  self_addr.sin_addr.s_addr   = inet_addr(ip_address);
  self_addr.sin_port          = htons(ip_port);

  memset((void *)&self_addr.sin_zero,
         0,
         (size_t)sizeof(self_addr.sin_zero));

  rc =  bind((int)sock_fd,
             (struct sockaddr *)&self_addr,
             (size_t)sizeof(self_addr));

  return(rc);
}/* tcp_bind */


/**
 * This function sets the back log of simultaneous connection of the adderssed
 * file descriptor.
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     file descriptor
 * @param     TCP connection back log (queue size).
 * @return    return code of listen function.
 */
int tcp_listen(int sock_fd, int back_log)
{
  int rc = -1;
  rc = listen (sock_fd,back_log);

  return(rc);
}/* tcp_listen */


/**
 * This function is used to accept a new cllient connection and updates the
 * max_fd. Also stores the IP Address of the TCP client and marks the fd_state 
 * as FD_STATE_CONNECTED.
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     listen file descriptor on which TCP client can connect.
 * @return    returns the newly connected file descriptor.
 */
int tcp_accept(int listen_fd)
{
  int       sock_fd = -1;
  struct    sockaddr_in addr;
  socklen_t addr_len;
  
  sock_fd =  accept (listen_fd,
                     (struct sockaddr *)&addr,
                     (socklen_t *)&addr_len);
  
  return(sock_fd);
}/* tcp_accept */


/**
 *  This function is used to read the incoming data from TCP client for given 
 *  file descriptor.
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     file descriptor on which data has arrived.
 * @param     pointer to char data buffer in which read data to be stored.
 * @param     maximum data buffer length.
 * @return    actual number of bytes read.
 */
int tcp_read(int sock_fd, char *buffer, int buffer_len)
{
  return (recv(sock_fd, (void *)buffer, buffer_len, 0));
} /* tcp_read */


/**
 * This function is used to send data on TCP connection for given 
 * file descriptor.
 *
 * @author    Mohd Naushad Ahmed
 * @version   1.0
 * @param     file descriptor on which data to be writen.
 * @param     data buffer to be sent.
 * @param     actual data length to be sent over TCP connection.
 * @return    bytes sent to TCP client.
 */
int tcp_write(int sock_fd, char *data_buffer, int data_len)
{
  int sent_data = 0;
  char *data_buff_ptr = NULL;

  data_buff_ptr = (char *) malloc(data_len);
  if (data_buff_ptr == NULL)
  {
    fprintf(stderr,"Buffer Allocation Failed for length %d\n",data_len);
  }
  memcpy(data_buff_ptr, data_buffer, data_len); 
  
  sent_data = send(sock_fd, data_buff_ptr, data_len, (int)0);
  free(data_buff_ptr);
  return(sent_data);
}/* tcp_write */

int tcp_display_fdlist(int *fd_list, int fd_list_length)
{
  int idx = 0;
  
	for(idx =0; idx <fd_list_length; idx++)
	{
    fprintf(stderr, "fd_list[%d] %d ", idx, fd_list[idx]);		
	}	
}/*tcp_display_fdlist*/

int tcp_rearrange_fdlist(int *fd_list, int *fd_list_length)
{
  int idx = 0;
  int idx_in = 0;
  int tmp_fd_list[256];

	memset((void *)tmp_fd_list, 0, sizeof(tmp_fd_list));
  

  for(idx = 0; idx < *fd_list_length; idx++)
	{
	  if(fd_list[idx] > 0)
		{
	    tmp_fd_list[idx_in++] = fd_list[idx];		
		}	
	}

	memset((void *)fd_list, 0, (sizeof(int) * (*fd_list_length)));
  memcpy((void *)fd_list, tmp_fd_list, (idx_in * sizeof(int)));
  *fd_list_length = idx_in;

  return(idx_in);

}/*tcp_rearrange_fdlist*/

int process_mime_header(char *mime_tag_name, unsigned char *mime_tag_value) 
{
 
  if(!strncmp(mime_tag_name,"Transfer-Encoding", 17 )) 
  {
    /* mime header contains the number of bytes equivalent to mime_tag_value */
    fprintf(stderr, "Payload length %s\n", mime_tag_value);					
  }				
  return(0);
}/* process_mime_header */


int tcp_get_ip_address(char * hostname , char* ip)
{
  struct hostent *he;
  struct in_addr **addr_list;
  int i;
        
  if((he = gethostbyname(hostname)) == NULL) 
  {
    // get the host info
    fprintf(stderr, "gethostbyname is returning an error\n");
    herror("gethostbyname");
    return (-1);
  }
 
  addr_list = (struct in_addr **) he->h_addr_list;
     
  for(i = 0; addr_list[i] != NULL; i++) 
  {
    //Return the first one;
    strcpy(ip ,inet_ntoa(*addr_list[i]));
    fprintf(stderr, "IP Address is %s\n", ip);
    return 0;
  }
  return (-2);
}/*tcp_get_ip_address*/

char *tcp_full_read_ex(int fd, unsigned int *data_len)
{
	char recv_buffer[2048];
	int  rc = -1;
	char *request_ptr = NULL;

	/*peek until we get an empty line*/
	memset(recv_buffer, 0, sizeof(recv_buffer));
	
	rc = tcp_read(fd, (char *)recv_buffer, sizeof(recv_buffer));

  if(!rc)
	{
		fprintf(stderr, "Peer has closed the connection %d\n", rc);
    *data_len = 0;
    return((char *)0);		
	}

	request_ptr = (char *)malloc(rc);
	memset((void *)request_ptr, 0, rc);

	memcpy((void *)request_ptr, recv_buffer, rc);

	*data_len = rc;
	fprintf(stderr, "Receive Request is %s\n", request_ptr);
	return(request_ptr);
  	
}/*tcp_full_read_ex*/


char *tcp_full_read(SSL *ssl, unsigned int *data_len)
{
  unsigned int header_len = 0;
  unsigned int body_len = 0;
  unsigned int actual_len = 0;
  int remaining_len = -1;
  unsigned int offset = 0;

  char *data_ptr = NULL;
  char recv_buffer[2048];
  char for_header[2048];

  int rc = -1;

  /*peek until we get an empty line*/
  do
  {
		memset((void *)recv_buffer, 0, sizeof(recv_buffer));
		memset((void *)for_header,  0, sizeof(for_header));
    sleep(1);
    rc = tls_peek(ssl, (char *)recv_buffer, sizeof(recv_buffer));
#if 0
    fprintf(stderr, "====================\n");
	  fprintf(stderr, "%s\n", recv_buffer);
    fprintf(stderr, "====================\n");
    fprintf(stderr, "Length is %d\n", rc);
#endif
		memcpy(for_header, recv_buffer, rc);
    header_len = http_get_header_length((char *)for_header, rc);

  }while(header_len == 0);

  body_len   = http_get_content_length((char *)recv_buffer, rc);

  actual_len = header_len + body_len;

  data_ptr = (char *)malloc(actual_len);
  assert(data_ptr != NULL);

  memset(data_ptr, 0, actual_len);

  rc = tls_read(ssl, (char *)data_ptr, actual_len);
  
  offset = rc; 
  remaining_len = actual_len - rc;

  while (remaining_len > 0)
  {
    rc = tls_read(ssl, (char *)&data_ptr[offset], remaining_len);
    remaining_len -= rc;
    offset += rc;
  }
  remaining_len = SSL_pending(ssl);
  rc = tls_read(ssl, (char *)&data_ptr[offset], remaining_len);
  /*Now read for Header part*/
  fprintf(stderr, "Received Request/Response is %s\n", data_ptr);
  *data_len = offset + rc;
  return (data_ptr);
}/*tcp_full_read*/

char *tcp_process_ipc_request(char *request_ptr, int request_length, int *response_length)
{
  unsigned int message_length = 0;
  unsigned int version        = 0;
	unsigned int acctual_request_length = 0;

  fprintf(stderr, "Request Length is %d\n", request_length);
  message_length = (((request_ptr[0] >> 24 ) & 0xFF) |
		((request_ptr[1] >> 16) & 0xFF) |
		((request_ptr[2] >> 8)  & 0xFF) |
		(request_ptr[3] >> 0));
  fprintf(stderr, "Message Length is %d\n", message_length);
  version = (((unsigned char)request_ptr[4] >> 8) & 0xFF) |
		((request_ptr[5] >> 0) & 0xFF);
  fprintf(stderr, "Value of Version is %d\n", version);

	acctual_request_length = message_length;
	//acctual_request_ptr = (char *) malloc(sizeof(char) * acctual_request_length);
	//assert(acctual_request_ptr != NULL);

	//memset((void *)acctual_request_ptr, 0, acctual_request_length);
	//memcpy((void *)acctual_request_ptr, (void *)&request_ptr[6], acctual_request_length);

	//free(request_ptr);
	/**/
	return(oauth20_process_response(/*acctual_request_ptr*/(char *)&request_ptr[6], 
				                          acctual_request_length, 
				                          response_length));

}/*tcp_process_ipc_request*/



int tcp_select(SSL *ssl, int listen_fd)
{
  int rc = -1;
	int new_fd = 0;
	int ssl_fd = -1;
  int idx = 0;

  fd_set rd_fd;
  int  fd_max = -1;
	int  fd_list[FD_SETSIZE];
	int  fd_list_idx = 0;
	int  response_length = -1;
	int  request_length = -1;
  char *response_ptr  = NULL;
  char *request_ptr   = NULL;
  
	struct timeval to;

  memset(fd_list, 0, sizeof(int)*FD_SETSIZE);
	
	ssl_fd = SSL_get_fd(ssl);

	fd_max = ssl_fd > listen_fd ? ssl_fd : listen_fd;
  
	fd_list[fd_list_idx++] = ssl_fd;
	fd_list[fd_list_idx++] = listen_fd;

  FD_ZERO(&rd_fd);
	
	for(;;)
  {
    to.tv_sec  = 0;
    to.tv_usec = 500;

    for(rc = 0; rc < fd_list_idx; rc++)
    {
			if(fd_list[rc] > 0)
			{
        FD_SET(fd_list[rc], &rd_fd);
			}
    }/*inner for loop*/

    rc = select(fd_max + 1, 
				        (fd_set *)&rd_fd, 
				        (fd_set *)NULL, 
				        (fd_set *)NULL, 
				        &to);
	  
		if(0 == rc)
    {
      /*timeout has happened*/		 
    }
	  else if(rc < 0)
    {
      /*An error has occurred */	
	    fprintf(stderr, "An error has occurred\n");		
    }
	  else
    {
      for(idx = 0; idx < fd_max; idx++)
      {
        if((FD_ISSET(fd_list[idx], &rd_fd)) && (fd_list[idx] == ssl_fd))
        {
			    /*Perform SSL_read Operation*/	 
          request_ptr = tcp_full_read(ssl, (unsigned int *)&request_length);
					response_ptr = oauth20_process_response((const char *)request_ptr, request_length, &response_length);
					
					if(NULL != response_ptr)
					{
					  tls_write(ssl, response_ptr, response_length);
					  free(response_ptr);
						response_ptr = NULL;
					}
					if(NULL != request_ptr)
					{
					  free(request_ptr);
						request_ptr = NULL;
					}
        }
        else if((FD_ISSET(fd_list[idx], &rd_fd)) && (listen_fd == fd_list[idx]))
        {
				   new_fd = un_accept(listen_fd);
				   fd_max = fd_max > new_fd ? fd_max : new_fd;
				   fd_list[fd_list_idx++] = new_fd;
			    /*New connection request for Unix IPC*/	 
        }
        else if(FD_ISSET(fd_list[idx], &rd_fd))
			  {
					/*Request/Response has come via unix ipc*/
					fprintf(stderr, "unL Read \n");
				  request_ptr = un_read(fd_list[idx], &request_length);
					fprintf(stderr, "Request Length Received is %d \n", request_length);

					if(!request_length)
					{
            close(fd_list[idx]);
						FD_CLR(fd_list[idx], &rd_fd);
						fd_list[idx] = -1;
					}
					else
					{
					  response_ptr = tcp_process_ipc_request(request_ptr, 
								                                   request_length, 
								                                   &response_length);
						if(NULL != response_ptr)
						{
							fprintf(stderr, "Data Written to SSL is\n%s\n", response_ptr);
						  rc = tls_write(ssl, response_ptr, response_length);
						  free(response_ptr);	
							response_ptr = NULL;
						}
						if(request_ptr != NULL)
						{
				      free(request_ptr);
							request_ptr = NULL;
						}
					}
          /*Perform unix socket ipc read*/				 
			  }
        else
			  {
          /*Should not have come here*/				 
			  }			 
      }/*Inner for loop*/		 
    }/*else*/
  }/*for(;;)*/
  return(0);

}/*tcp_select*/



int main(int argc, char *argv[])
{
  char ip[16]; 
  int fd = -1;
  int rc = -1;
  char *auth_req_ptr = NULL;
  unsigned int  auth_req_len = 0;
  unsigned char recv_buffer[8000];
  cmd_option_t *cmd_opt = NULL;

#ifdef __UNIX_SOCKET_IPC__
  int un_fd = -1;
  char *path = "un_sock_ipc";
#endif /*__UNIX_SOCKET_IPC__*/
	
#ifdef __TLS__
 SSL_CTX *ctx = NULL;
 SSL     *ssl = NULL; 
#endif /*__TLS__*/

  cmd_opt = (cmd_option_t *)opt_process_options(argc, argv);
  assert(NULL != cmd_opt);

  fd = tcp_socket();

  if(cmd_opt->is_self_ip)
  {
    strncpy((char *)ip, cmd_opt->self_ip, sizeof(cmd_opt->self_ip)); 					
  }
  else if(cmd_opt->is_self_host_name)
  {
    rc = tcp_get_ip_address(cmd_opt->self_host_name, (char *)ip);
    assert(rc == 0);
  }

  rc = tcp_bind(ip, cmd_opt->self_port, fd);
  
  if(cmd_opt->is_remote_ip)
  {
    strncpy((char *)ip, cmd_opt->remote_ip, sizeof(cmd_opt->remote_ip)); 					
  }
  else if(cmd_opt->is_remote_host_name)
  {
    /*Domain Name shall be in the form 
     * http://www.googleapis.com
     * */
    rc = tcp_get_ip_address(cmd_opt->remote_host_name, (char *)ip);
    assert(rc == 0);
  }
#ifdef __UNIX_SOCKET_IPC__
  un_fd = un_socket(IPPROTO_TCP);
  rc = un_bind(un_fd, path);
  rc = un_listen(un_fd, 5);
#endif /*__UNIX_SOCKET_IPC__*/

#ifdef __TLS__
  if(tcp_connect(fd, ip, cmd_opt->remote_port) < 0)
  {
    perror("Connect Failed\n");					
  }

  ctx = tls_init();
  ssl = tls_main(fd);
  assert(ssl != NULL);
#else
  if(tcp_connect(fd, ip, cmd_opt->remote_port) < 0)
  {
    perror("Connect Failed\n");					
  }
#endif /*__TLS__*/

  free(cmd_opt);
  auth_req_len = 0;
  //auth_req_ptr = (char *) malloc(auth_req_len);
  //memset(auth_req_ptr, 0, auth_req_len);
  
	auth_req_ptr = oauth20_process_request(NULL, 0, (int *)&auth_req_len);
  //auth_req_len = oauth20_authorize_request((unsigned char *)auth_req_ptr, &auth_req_len);
  //auth_req_len = oauth20_access_token_request((unsigned char *)auth_req_ptr, &auth_req_len);
  fprintf(stderr, "Oauth20 Request is \n%s", auth_req_ptr);

	//g_oauth20_ctx.cmd_state =OAUTH20_USER_CONSENT_REQUEST_ST; 
#if 0
  /*Verifiy the req/response with dummy data*/
  memset((char *)auth_req_ptr, 0, auth_req_len);
  strcpy(auth_req_ptr, "HTTP/1.1 302 Found \r\n Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA&state=xyz&token_type=example&expires_in=3600");
  auth_req_len = strlen(auth_req_ptr);
  fprintf(stderr, "Oauth20 Request is \n%s", auth_req_ptr);
  //oauth20_error_handle((unsigned char *)auth_req_ptr, auth_req_len);
  //oauth20_access_token_request((unsigned char *)auth_req_ptr, &auth_req_len);
  oauth20_access_token_response((unsigned char *)auth_req_ptr, auth_req_len);
  //oauth20_authorize_response((unsigned char *)auth_req_ptr, auth_req_len);
  fprintf(stderr, "Oauth20 Request is \n%s", auth_req_ptr);
#endif

#ifdef __TLS__

  rc = tls_write(ssl, (char *)auth_req_ptr, auth_req_len);	
  fprintf(stderr, "tls_write code %d\n", rc);
#else

  tcp_write(fd, auth_req_ptr, auth_req_len);

#endif /*__TLS__*/

  free(auth_req_ptr);

  memset(recv_buffer, 0 , sizeof(recv_buffer));

#ifdef __TLS__
  /*Get the Length of Payload/Message Body*/
  //auth_req_len = 0;
  /*peek how many bytes of response going to come*/
  //rc = tls_peek(ssl, (char *)recv_buffer, auth_req_len);
  //fprintf(stderr, "recv_buffer is ===> %s", recv_buffer);
  //char *data_ptr = NULL;
  //data_ptr = tcp_full_read(ssl, &auth_req_len);
  tcp_select(ssl, un_fd);

#else	
  if((rc = tcp_read(fd, (char *)&recv_buffer, 8000)) > 0)
  {
    fprintf(stderr, "Received Message is %s\n", recv_buffer);
    FILE *fp = NULL;
    fp = fopen("/tmp/auth_response.xml", "w");
    fwrite((char *)recv_buffer, 1, rc, fp);
    fclose(fp);
  }
#endif /*__TLS__*/

  //data_ptr = tcp_full_read(ssl, &auth_req_len);
  //fprintf(stderr, "\nCODE====\n%s", data_ptr);
}/*main*/




#endif
