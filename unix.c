#ifndef __UNIX_C__
#define __UNIX_C__

#include "unix.h"

un_sock_ipc_ctx_t g_un_ctx = 
{
  .un_fd   = -1,
  .un_port = ""	
};

int un_close(int un_fd)
{
  return(close(un_fd));
 	
}/*un_close*/


char *un_get_unix_port(void)
{
  return(g_un_ctx.un_port);	

}/*un_get_unix_port*/


int un_set_unix_port(char *path)
{
  int path_length = -1;

  if('\0' == *path)
  {
    path_length = strlen((char *)&path[1]);
		/*+1 for null character (file name begins with null character)*/
    path_length += 1;		
  }
  else
	{
    path_length = strlen(path);		
	}

  memset(g_un_ctx.un_port, 0, sizeof(g_un_ctx.un_port));
  strncpy(g_un_ctx.un_port, path, path_length);
	return(0);

}/*un_set_unix_port*/
int un_socket(int protocol)
{
  int fd = -1;
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  return (fd);

}/*un_socket*/


int un_bind(int un_fd, const char *path)
{
  struct sockaddr_un un_sock_self;
	int un_sock_len = -1;
  int rc = -1;

	un_sock_self.sun_family = AF_UNIX;
	assert(path != NULL);
  
  if('\0' == *path)
	{
    /*path for unix socket starts with null character*/
    un_sock_len = strlen((const char *)&path[1]) + 
			1 /*For First Null character*/;		
	}
	else
	{
    un_sock_len = strlen(path);
	}
	strncpy(un_sock_self.sun_path, path, un_sock_len);

  un_sock_len += sizeof(un_sock_self.sun_family);
	/*Need to be fixed for path starts with null character*/
  un_sock_len = sizeof(un_sock_self);	
	/*Once socket file is created, It is not deleted once server
	 * exits the program and in subsequent call to bind will fail
	 * so always unlink first*/
  unlink(un_sock_self.sun_path);

	rc = bind(un_fd, (struct sockaddr *)&un_sock_self, (socklen_t)un_sock_len);
  
  return(rc);
}/*un_bind*/

int un_connect(int fd, const char *path)
{
  int rc = -1;
	int un_sock_len = -1;
  struct sockaddr_un un_distant_addr;

	un_distant_addr.sun_family = AF_UNIX;

  if('\0' == *path)
	{
    un_sock_len = strlen((const char *)&path[1]) + 1;    		
	}
	else
	{
    un_sock_len = strlen(path);		
	}

	memcpy(un_distant_addr.sun_path, path, un_sock_len);
  
	rc = connect(fd, 	(const struct sockaddr *)&un_distant_addr, (socklen_t)un_sock_len);
	return(rc);

}/*un_connect*/

int un_accept(int fd)
{
  int rc = -1;
  struct sockaddr_un peer_addr;
  int peer_addr_len = sizeof(peer_addr);

  rc = accept(fd, (struct sockaddr *)&peer_addr, (socklen_t *)&peer_addr_len);
  return(rc);

}/*un_accept*/

int un_listen(int fd, int backlog)
{
  int rc = -1;
  
  rc = listen(fd, backlog);
  return(rc);

}/*un_listen*/

char *un_read(int fd, int *data_len)
{
  int rc = -1;
	char recv_buffer[8];
	int  message_length = 0;
	char *data_ptr = NULL;

  /*Received message will have following format
	 * 4 Bytes of length and
	 * payload followed
	 * |-----------|-------|-------------|
	 * |Message_len|Version|Message Body |
	 * |4-Bytes    |2-bytes|             |
	 * |___________|_______|_____________|
	 * */
	do
	{
	  memset((void *)recv_buffer, 0, sizeof(recv_buffer));
	  rc = recv(fd, (char *)recv_buffer, 4, MSG_PEEK);
		if(0 == rc) 
		{
	    rc = recv(fd, (char *)recv_buffer, 4, 0);
      fprintf(stderr, "Peer has closed the Connection\n");
			*data_len = 0;
			return(data_ptr);
		}
	}while(rc != 4);

  /*length of message has been received, now decode it.*/
	message_length = (recv_buffer[3] >> 0  |
		                recv_buffer[2] >> 8  |
                    recv_buffer[1] >> 16 |
                    recv_buffer[0] >> 24);

  /*Complete Message Length is*/
	message_length += 4/*For message Length*/ + 2/*Version*/;

  data_ptr = (char *)malloc(message_length);

  do
  {
		memset((void *)data_ptr, 0, message_length);
	  rc = recv(fd, (char *)data_ptr, message_length, MSG_PEEK);  	
  }while(rc != message_length);

  /*Now entire message has been received*/
  rc = recv(fd, (char *)data_ptr, message_length, 0);
  *data_len = message_length;

	return(data_ptr);

}/*un_read*/

int un_write(int fd, char *data_ptr, unsigned int data_length)
{
  int rc = -1;
  unsigned int offset = 0;
  unsigned int remaining_length = 0;
  do
	{
    rc = send(fd, (char *)&data_ptr[offset],(data_length - remaining_length), 0);
    remaining_length += rc;	
	  offset += rc;	
	}while(remaining_length != data_length);
  
	return(remaining_length);

}/*un_write*/



#endif /*__UNIX_C__*/
