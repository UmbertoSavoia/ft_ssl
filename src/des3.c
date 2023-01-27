#include "ft_ssl.h"
#include "ft_des3.h"

static t_des3_ctx ctx = {0};

void    des3_init(uint8_t *key, uint32_t key_len)
{
    memcpy(ctx.keys1, key, key_len);
    memcpy(ctx.keys2, key+8, key_len);
    memcpy(ctx.keys3, key+16, key_len);
}

void    des3_encrypt(uint8_t *input, uint8_t *output)
{
    des_init(ctx.keys1, 8);
    des_encrypt(input, output);

    des_init(ctx.keys2, 8);
    des_decrypt(output, output);

    des_init(ctx.keys3, 8);
    des_encrypt(output, output);
}

void    des3_decrypt(uint8_t *input, uint8_t *output)
{
    des_init(ctx.keys3, 8);
    des_decrypt(input, output);

    des_init(ctx.keys2, 8);
    des_encrypt(output, output);

    des_init(ctx.keys1, 8);
    des_decrypt(output, output);
}
