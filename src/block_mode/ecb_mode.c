#include "ft_ssl.h"
#include "ft_cipher.h"

void    ecb_encrypt(t_cipher *cipher, t_mode_arg *args)
{
    uint32_t r = 0;
    uint8_t *in = 0, *out = 0, final_pad = 1;

    if (!(args->key))
        return;
    if (!(in = malloc(cipher->block_size)))
        return;
    if (!(out = malloc(cipher->block_size)))
        return;

    cipher->init(args->key, cipher->key_size);
    while ((r = ft_read(args->fd_in, in, cipher->block_size)) > 0) {
        if (r < cipher->block_size) {
            pad_pkcs5(&in[r], r, cipher->block_size);
            final_pad = 0;
        }
        cipher->encrypt(in, out);
        write(args->fd_out, out, cipher->block_size);
    }
    if (final_pad) {
        pad_pkcs5(in, r, cipher->block_size);
        cipher->encrypt(in, out);
        write(args->fd_out, out, cipher->block_size);
    }

    free(in);
    free(out);
}

void    ecb_decrypt(t_cipher *cipher, t_mode_arg *args)
{
    uint32_t r = 0, size = 0;
    uint8_t *in = 0, *out = 0;

    if (!(in = malloc(cipher->block_size)))
        return;
    if (!(out = malloc(cipher->block_size)))
        return;

    cipher->init(args->key, cipher->key_size);
    while ((r = ft_read(args->fd_in, in, cipher->block_size)) > 0) {
        cipher->decrypt(in, out);
        size = unpad_pkcs5(out, r, cipher->block_size);
        write(args->fd_out, out, size);
    }

    free(in);
    free(out);
}