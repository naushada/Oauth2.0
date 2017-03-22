#ifndef __UNIX_H__
#define __UNIX_H__

#include "common.h"
#include <sys/un.h>


typedef struct
{
  int  un_fd;
  char un_port[256];	
}un_sock_ipc_ctx_t;


int un_close(int un_fd);

int un_set_unix_port(char *path);

char *un_get_unix_port(void);

int un_socket(int protocol);

int un_bind(int un_fd, const char *path);

int un_connect(int fd, const char *path);

int un_accept(int fd);

int un_listen(int fd, int backlog);

char *un_read(int fd, int *data_len);

int un_write(int fd, char *data_ptr, unsigned int data_length);



#endif /*UNIX_H__*/
