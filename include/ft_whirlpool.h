#ifndef FT_WHIRLPOOL_H
#define FT_WHIRLPOOL_H

#include "ft_ssl.h"

#define ROUND(b, a, n, c)                                       \
{                                                               \
   b = T[(a[n] >> 56) & 0xFF];                                  \
   b ^= ROTATE_RIGHT64(T[(a[(n + 7) % 8] >> 48) & 0xFF], 8);    \
   b ^= ROTATE_RIGHT64(T[(a[(n + 6) % 8] >> 40) & 0xFF], 16);   \
   b ^= ROTATE_RIGHT64(T[(a[(n + 5) % 8] >> 32) & 0xFF], 24);   \
   b ^= ROTATE_RIGHT64(T[(a[(n + 4) % 8] >> 24) & 0xFF], 32);   \
   b ^= ROTATE_RIGHT64(T[(a[(n + 3) % 8] >> 16) & 0xFF], 40);   \
   b ^= ROTATE_RIGHT64(T[(a[(n + 2) % 8] >> 8) & 0xFF], 48);    \
   b ^= ROTATE_RIGHT64(T[a[(n + 1) % 8] & 0xFF], 56);           \
   b ^= c;                                                      \
}

typedef struct  s_whirlpool_ctx
{
    uint64_t    size;
    uint8_t     buffer[64];
    uint64_t    state[8];
}               t_whirlpool_ctx;

void    whirlpool_init(void);
void    whirlpool_update(uint8_t *input, size_t len);
void    whirlpool_final(uint8_t digest[]);

#endif