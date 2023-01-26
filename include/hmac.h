#ifndef HMAC_H
#define HMAC_H

#include "ft_digest.h"

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5C
#define HMAC_MAX_SIZE 64

typedef struct  s_hmac_ctx
{
    t_digest *hash;
    uint8_t key[HMAC_MAX_SIZE];
    uint8_t digest[HMAC_MAX_SIZE];
}               t_hmac_ctx;

void    hmac_init(t_digest *hash, uint8_t *key, size_t key_len);
void    hmac_update(uint8_t *input, size_t len);
void    hmac_final(uint8_t digest[]);

#endif