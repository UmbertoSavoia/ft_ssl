#ifndef FT_SSL_H
#define FT_SSL_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <byteswap.h>
#include <errno.h>

#include "ft_digest.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define PRINT_DIGEST(digest, n)        \
    do {                               \
        for (int i = 0; i < n; ++i) {  \
            printf("%02x", digest[i]); \
        }                              \
    } while (0)

#define ROTATE_LEFT32(x, n)   ((x << n) | (x >> (32 - n)))
#define ROTATE_RIGHT32(x,n)   ((x >> n) | (x << (32 - n)))
#define ROTATE_RIGHT64(x, n)  ((x >> n) | (x << (64 - n)))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define BYTE_TO_DWORD_LITTLE(a,b,c,d)      (a | b << 8 | c << 16 | d << 24)
#define BYTE_TO_DWORD_BIG(a,b,c,d)         (a << 24 | b << 16 | c << 8 | d)
#define BSWAP64(x)                              \
        ((((x) & 0xff00000000000000ull) >> 56)  \
       | (((x) & 0x00ff000000000000ull) >> 40)  \
       | (((x) & 0x0000ff0000000000ull) >> 24)  \
       | (((x) & 0x000000ff00000000ull) >>  8)  \
       | (((x) & 0x00000000ff000000ull) <<  8)  \
       | (((x) & 0x0000000000ff0000ull) << 24)  \
       | (((x) & 0x000000000000ff00ull) << 40)  \
       | (((x) & 0x00000000000000ffull) << 56))
#define LOAD_DWORD_BIG(a)                        \
        (((uint32_t)(((uint8_t *)(a))[0]) << 24) \
       | ((uint32_t)(((uint8_t *)(a))[1]) << 16) \
       | ((uint32_t)(((uint8_t *)(a))[2]) <<  8) \
       | ((uint32_t)(((uint8_t *)(a))[3]) <<  0))
#define STORE_DWORD_BIG(a, b)                            \
    ((uint8_t *)(b))[0] = ((uint32_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(b))[1] = ((uint32_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(b))[2] = ((uint32_t)(a) >>  8) & 0xFFU, \
    ((uint8_t *)(b))[3] = ((uint32_t)(a) >>  0) & 0xFFU

typedef struct  s_dispatch
{
    char algo[32];
    int (*func)(int, char **);
}               t_dispatch;

int     ft_digest(int ac, char **av);
int     ft_base64(int ac, char **av);
int     ft_cipher(int ac, char **av);

size_t  ft_read(int fd, void *buf, size_t count);
int     ft_open(char *file, int flag);
uint8_t *str_to_hex(char *s, uint32_t len_bit);

void        pad_pkcs5(uint8_t *dest, uint32_t buf_len, uint32_t block_size);
uint32_t    unpad_pkcs5(uint8_t *buf, uint32_t buf_len, uint32_t block_size);

#endif
