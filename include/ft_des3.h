#ifndef FT_DES3_H
#define FT_DES3_H

#include "ft_ssl.h"
#include "ft_des.h"

#define DES3_BLOCK_SIZE 8

typedef struct  s_des3_ctx
{
    uint8_t     keys1[32];
    uint8_t     keys2[32];
    uint8_t     keys3[32];
}               t_des3_ctx;

void    des3_init(uint8_t *key, uint32_t key_len);
void    des3_encrypt(uint8_t *input, uint8_t *output);
void    des3_decrypt(uint8_t *input, uint8_t *output);

#endif