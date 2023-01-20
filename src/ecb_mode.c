#include "ft_ssl.h"
#include "ft_cipher.h"

void    ecb_encrypt(t_cipher *cipher, t_mode_arg *args)
{
    uint32_t r = 0;
    uint8_t *in = 0, *out = 0;

    if (!(in = malloc(cipher->block_size)))
        return;
    if (!(out = malloc(cipher->block_size)))
        return;

    cipher->init(args->key, args->key_len);
    while ((r = ft_read(args->fd_in, in, cipher->block_size)) > 0) {
        cipher->encrypt(in, out);
        for (int i = 0; i < 8; ++i)
            dprintf(args->fd_out, "%02x", out[i]);
    }

}

void    ecb_decrypt(t_cipher *cipher, t_mode_arg *args)
{

}