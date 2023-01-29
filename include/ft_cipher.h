#ifndef FT_CIPHER_H
#define FT_CIPHER_H

#include "ft_ssl.h"

#define E_FLAG 0b00000001
#define D_FLAG 0b00000010
#define A_FLAG 0b00000100

typedef void (*cipher_init)(uint8_t *key, uint32_t key_len);
typedef void (*cipher_encrypt)(uint8_t *input, uint8_t *output);
typedef void (*cipher_decrypt)(uint8_t *input, uint8_t *output);

typedef struct  s_cipher
{
    char            name[32];
    size_t          block_size;
    size_t          key_size;
    cipher_init     init;
    cipher_encrypt  encrypt;
    cipher_decrypt  decrypt;
}               t_cipher;

typedef struct s_mode_arg
{
    int         fd_in;
    int         fd_out;
    int         fd_cache;
    uint8_t     *key;
    uint8_t     *iv;
    uint8_t     *salt;
    char        *pass;
    uint8_t     flags;
}               t_mode_arg;

typedef void (*cipher_mode)(t_cipher *cipher, t_mode_arg *args);

typedef struct  s_cipher_modes
{
    char name[32];
    cipher_mode encrypt;
    cipher_mode decrypt;
}               t_cipher_modes;

void    ecb_encrypt(t_cipher *cipher, t_mode_arg *args);
void    ecb_decrypt(t_cipher *cipher, t_mode_arg *args);
void    cbc_encrypt(t_cipher *cipher, t_mode_arg *args);
void    cbc_decrypt(t_cipher *cipher, t_mode_arg *args);
void    pcbc_encrypt(t_cipher *cipher, t_mode_arg *args);
void    pcbc_decrypt(t_cipher *cipher, t_mode_arg *args);
void    cfb_encrypt(t_cipher *cipher, t_mode_arg *args);
void    cfb_decrypt(t_cipher *cipher, t_mode_arg *args);
void    ofb_encrypt(t_cipher *cipher, t_mode_arg *args);
void    ofb_decrypt(t_cipher *cipher, t_mode_arg *args);
void    ctr_encrypt(t_cipher *cipher, t_mode_arg *args);
void    ctr_decrypt(t_cipher *cipher, t_mode_arg *args);

#endif