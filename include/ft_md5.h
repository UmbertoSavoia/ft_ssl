#ifndef FT_SSL_FT_MD5_H
#define FT_SSL_FT_MD5_H

#include "ft_ssl.h"

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

void    md5_init(void);
void    md5_update(uint8_t *input, size_t len);
void    md5_final(uint8_t digest[]);

#endif