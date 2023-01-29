#include "ft_ssl.h"
#include "ft_cipher.h"

void    ofb_encrypt(t_cipher *cipher, t_mode_arg *args)
{
    uint32_t r = 0;
    uint8_t *in = 0, *out = 0, *t = 0;

    if (!(args->key) || !(args->iv))
        return;
    if (!(in = malloc(cipher->block_size)))
        return;
    if (!(out = malloc(cipher->block_size)))
        return;
    if (!(t = malloc(cipher->block_size)))
        return;

    cipher->init(args->key, cipher->key_size);
    while ((r = ft_read(args->fd_in, in, cipher->block_size)) > 0) {
        cipher->encrypt(args->iv, out);
        memcpy(t, out, r);
        for (uint32_t i = 0; i < r; ++i)
            out[i] = in[i] ^ out[i];
        write(args->fd_out, out, r);
        memmove(args->iv, args->iv+r, cipher->block_size-r);
        memcpy(args->iv+cipher->block_size-r, t, r);
    }
    free(in);
    free(out);
    free(t);
}

void    ofb_decrypt(t_cipher *cipher, t_mode_arg *args)
{
    ofb_encrypt(cipher, args);
}