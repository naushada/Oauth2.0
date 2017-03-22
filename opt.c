
#ifndef __OPT_C__
#define __OPT_C__


#include "common.h"
#include "opt.h"

/*! Option Details are as follows.
 *  -s <self ip>   -p <self port>
 *  -r <remote ip> -q <remote port>
 *  -h <self host name>
 *  -t <remote host name>
 *
 * */
char *opt_process_options(int argc, char **argv)
{
  cmd_option_t *cmd_opt = NULL;  				
  char opt = 0;
  
  cmd_opt = (cmd_option_t *)malloc(sizeof(cmd_option_t));
  
  if(NULL == cmd_opt)
  {
    return(NULL);					
  }

  while((opt = getopt(argc, argv, "s:p:r:q:h:t:")) != -1)
  {
    switch(opt)
    {
      case 's':
        cmd_opt->is_self_ip = 1;
        strncpy((char *)cmd_opt->self_ip, optarg, sizeof(cmd_opt->self_ip));
        break;
      case 'p':
        cmd_opt->is_self_port = 1;
        cmd_opt->self_port = atoi(optarg);
        break;
      case 'r':
        cmd_opt->is_remote_ip = 1;
        strncpy((char *)cmd_opt->remote_ip, optarg, sizeof(cmd_opt->remote_ip));
        break;
      case 'q':
        cmd_opt->is_remote_port = 1;
        cmd_opt->remote_port = atoi(optarg);
        break;
      case 'h':
        cmd_opt->is_self_host_name = 1;
        strncpy((char *)cmd_opt->self_host_name, optarg, sizeof(cmd_opt->self_host_name));
        break;
      case 't':
        cmd_opt->is_remote_host_name = 1;
        strncpy((char *)cmd_opt->remote_host_name, optarg, sizeof(cmd_opt->remote_host_name));
        break;
      default:
        fprintf(stderr, "No match in provided Option\n");
        break;
    }/*switch*/
  }/*while*/
  return((char *)cmd_opt);
}/*opt_process_options*/

#endif
