#ifndef __OPT_H__
#define __OPT_H__

#include "tcp.h"

/*! Option Details are as follows.
 *  -s <self ip>   -p <self port>
 *  -r <remote ip> -q <remote port>
 *  -h <self host name>
 *  -t <remote host name>
 *
 * */
typedef struct
{
  char is_remote_port;				
  int  remote_port;
  char is_self_port;
  int  self_port;
  char is_self_ip;
  char self_ip[16];
  char is_remote_ip;
  char remote_ip[16];
  char is_self_host_name;
  char self_host_name[256];
  char is_remote_host_name;
  char remote_host_name[256];

}cmd_option_t;


char *opt_process_options(int argc, char **argv);


#endif
