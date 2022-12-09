#ifndef FT_SSL_FT_MD5_H
#define FT_SSL_FT_MD5_H

#include "ft_ssl.h"

#define S_FLAG 0b00000001
#define Q_FLAG 0b00000010
#define R_FLAG 0b00000100

#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))

typedef struct  s_md5_ctx
{
    uint64_t    size;
    uint8_t     buffer[64];
    uint32_t    state[4];
}               t_md5_ctx;

#endif