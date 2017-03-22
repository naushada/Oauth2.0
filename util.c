#ifndef __UTILITY_C__
#define __UTILITY_C__

#include "common.h"
#include "util.h"


unsigned char *util_get_access_token(int *token_len)
{
  int fd = -1;
  int rc = -1;
  unsigned char *tmp_tkn = NULL;
  
  *token_len = 32;

  if((NULL == (tmp_tkn = (unsigned char *)malloc(*token_len))) ||
     ((fd = open("/dev/urandom", O_RDONLY)) < 0) ||
     ((rc = read(fd, tmp_tkn, *token_len)) < *token_len))
  {
    /*!case1:- open is successful and read failed
     * case2:- open is failed. For case1, close will return 0, so -2 will be reurned.
     * for case2, close will retuen less than 0, so -3 will be returned.
     * */	
    rc = (NULL == tmp_tkn) ? -1 : (close(fd) < 0) ? -2 : -3;					
  }
  return (tmp_tkn);
}/*util_get_access_token*/

unsigned char *util_base64_decode(unsigned char *base64, 
                                  unsigned int  b64_len, 
                                  unsigned int  *buffer_len)
{
  unsigned int  offset    = 0;
  unsigned int  idx       = 0;
  unsigned int  tmp       = 0;
  unsigned char *buffer   = NULL;

  assert(NULL != base64);

  buffer = (unsigned char *)malloc(b64_len);
  assert(buffer != NULL);

  /*resetting idx to 0, so that It can be re-used*/
  idx = 0;
  
  for(; offset < b64_len; offset +=4)
  {
    tmp = (((((b64[base64[offset + 0]] <<  6  |
               b64[base64[offset + 1]]) << 6) |
               b64[base64[offset + 2]]) << 6) |
               b64[base64[offset + 3]]);

    if(b64[base64[offset + 2]] == 0x40)
    {	
      /*There are two padd characters '=='*/
      buffer[idx++] = (tmp & 0xFF0000U) >> 16;
    }
    else if(b64[base64[offset + 3]] == 0x40)
    {
      /*There is only one pad character '='*/			
      buffer[idx++] = (tmp & 0xFF0000U) >> 16;
      buffer[idx++] = (tmp & 0x00FF00U) >> 8 ;
    }
    else
    {
      /*There are no pad character*/				
      buffer[idx++] = (tmp & 0xFF0000U) >> 16;
      buffer[idx++] = (tmp & 0x00FF00U) >> 8 ;
      buffer[idx++] = (tmp & 0x0000FFU) >> 0 ;
    }
  }
  *buffer_len = idx - 1;
  return (buffer);

}/*util_base64_decode*/

unsigned char *util_base64_encode(unsigned char *byte_string, 
                                  unsigned int byte_string_len, 
                                  unsigned int *base64_string_len)
{
  unsigned int  offset    = 0;
  unsigned int  idx       = 0;
  unsigned int  tmp       = 0;
  unsigned char *base64_buffer = NULL;

  unsigned char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  
  /*! Terminate the calling process if expression of
   *  assert evaluates to false
   * */
  assert(NULL != byte_string);

  /*! Calculating the base64 string length
   *  Base64 is all about converting 3 bytes into 4 bytes
   *  whose character sets mentioned in base64
   * */
  offset = ((byte_string_len / 3) * 4) + (byte_string_len % 3) + 32;

  base64_buffer = (unsigned char *)malloc(offset);
  assert(NULL != base64_buffer);
  
  memset((void *)base64_buffer, 0, offset);

  for(offset = 0; offset < byte_string_len; offset += 3)
  {
    					
    if((byte_string_len - offset) > 2)
    {	
      /*!
       * The final quantum of encoding input is an integral multiple of 24
         bits; here, the final unit of encoded output will be an integral
         multiple of 4 characters with no "=" padding.
       * */				
      tmp = ((byte_string[offset] << 8 |
      byte_string[offset + 1]) << 8 |
      byte_string[offset + 2]) & 0xFFFFFF;

      base64_buffer[idx++] = base64[(tmp >> 18)  & 0x3F];
      base64_buffer[idx++] = base64[(tmp >> 12)  & 0x3F];
      base64_buffer[idx++] = base64[(tmp >> 6 )  & 0x3F];
      base64_buffer[idx++] = base64[(tmp >> 0 )  & 0x3F];
    }
    else if(2 == (byte_string_len - offset))
    {
      /*! The final quantum of encoding input is exactly 16 bits; here, the
          final unit of encoded output will be two characters followed by
          one "=" padding characters.
      */
      tmp = (byte_string[offset] << 8 |
      byte_string[offset + 1]) & 0xFFFF;

      base64_buffer[idx++] = base64[(tmp >> 10)  & 0x3F];
      base64_buffer[idx++] = base64[(tmp >> 4 )  & 0x3F];
      /*!
       * When fewer than 24 input
         bits are available in an input group, bits with value zero are added
         (on the right) to form an integral number of 6-bit groups.  Padding
         at the end of the data is performed using the '=' character.
       * */
      base64_buffer[idx++] = base64[((tmp << 2) + 0)  & 0x3F];
      /*One Pad character is added*/
      base64_buffer[idx++] = '=';
    }
    else
    {
      /*! The final quantum of encoding input is exactly 8 bits; here, the
          final unit of encoded output will be three characters followed by
          two "=" padding character.
       */
      tmp = (byte_string[offset] << 8) & 0xFF; 

      base64_buffer[idx++] = base64[(tmp >> 2)  & 0x3F];
      /*!
       * When fewer than 8 bits input
         bits are available in an input group, bits with value zero are added
         (on the right) to form an integral number of 6-bit groups.  Padding
         at the end of the data is performed using the '=' character.
       * */
      base64_buffer[idx++] = base64[((tmp << 4) + 0 )  & 0x3F];
      /*Two Pad character is added*/
      base64_buffer[idx++] = '=';
      base64_buffer[idx++] = '=';
    }

#if 0
    if(offset % 64)
    {
      /*Add line feeds at every 64 characters*/						
      base64_buffer[idx++] = '\n';						
    }
#endif

  }/*for*/

  /*Make it null character terminated*/
  base64_buffer[idx] = '\0';
  *base64_string_len = idx;	
  return ((unsigned char *)base64_buffer);
}/*util_base64_encode*/


#ifdef __DEBUG

void util_print_hex(unsigned char *byte_stream, int len)
{
  unsigned int idx = 0;
  
  for(; idx < len; idx++)
  {
    if(idx % 16) fprintf(stderr, "\n");
		
    fprintf(stderr, "%0.2X ", byte_stream[idx]);
  }	
}/*util_print_hex*/


void util_print_string(unsigned char *str)
{
  fprintf(stderr, "%s", str);				
}

#endif /*__DEBUG*/



#endif
