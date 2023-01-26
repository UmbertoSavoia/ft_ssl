#ifndef FT_BASE64_H
#define FT_BASE64_H

#define ENCODE_BASE64 0
#define DECODE_BASE64 1

void    decode_base64(int fd_in, int fd_out);
void    encode_base64(int fd_in, int fd_out);

#endif