#ifndef __TCP_H__

#define __TCP_H__

int tcp_socket(void);


int tcp_connect(int conn_fd, const char* ip, unsigned short port);


int tcp_bind(const char *ip_address, int ip_port, int sock_fd);


int tcp_listen(int sock_fd, int back_log);


int tcp_accept(int listen_fd);


int tcp_read(int sock_fd, char *buffer, int buffer_len);


int tcp_write(int sock_fd, char *data_buffer, int data_len);


int process_mime_header(char *mime_tag_name, unsigned char *mime_tag_value);


int tcp_get_ip_address(char * hostname , char* ip);

#endif
