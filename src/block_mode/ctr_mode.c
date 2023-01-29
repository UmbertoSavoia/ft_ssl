#include "ft_ssl.h"
#include "ft_cipher.h"

void    ctr_encrypt(t_cipher *cipher, t_mode_arg *args)
{
    uint32_t r = 0;
    uint8_t *in = 0, *out = 0;

    if (!(args->key) || !(args->iv))
        return;
    if (!(in = malloc(cipher->block_size)))
        return;
    if (!(out = malloc(cipher->block_size)))
        return;

    cipher->init(args->key, cipher->key_size);
    while ((r = ft_read(args->fd_in, in, cipher->block_size)) > 0) {
        cipher->encrypt(args->iv, out);
        for (uint32_t i = 0; i < r; ++i)
            out[i] = in[i] ^ out[i];
        write(args->fd_out, out, r);

        for (uint32_t tmp = 1, i = 1; i <= cipher->block_size; ++i) {
            tmp += args->iv[cipher->block_size - i];
            args->iv[cipher->block_size - i] = tmp & 0xFF;
            tmp >>= 8;
        }
    }
    free(in);
    free(out);
}

void    ctr_decrypt(t_cipher *cipher, t_mode_arg *args)
{
    ctr_encrypt(cipher, args);
}