#ifndef FT_DIGEST_H
#define FT_DIGEST_H

#include "ft_ssl.h"

#define S_FLAG 0b00000001
#define Q_FLAG 0b00000010
#define R_FLAG 0b00000100

typedef void (*digest_init)(void);
typedef void (*digest_update)(uint8_t *, size_t);
typedef void (*digest_final)(uint8_t *);

typedef struct  s_digest
{
    char            name_lo[32];
    char            name_up[32];
    digest_init     init;
    digest_update   update;
    digest_final    final;
    uint32_t        digest_len;
    uint32_t        block_size;
}               t_digest;

#endif