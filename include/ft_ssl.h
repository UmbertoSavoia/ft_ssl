#ifndef FT_SSL_H
#define FT_SSL_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define PRINT_DIGEST(digest, n)        \
    do {                               \
        for (int i = 0; i < n; ++i) {  \
            printf("%02x", digest[i]); \
        }                              \
    } while (0)

#define ROTATE_LEFT(x, n)           ((x << n) | (x >> (32 - n)))
#define BYTE_TO_WORD(a, b, c, d)    (a | b << 8 | c << 16 | d << 24)

typedef struct  s_dispatch
{
    char algo[32];
    int (*func)(int, char **);
}               t_dispatch;

int     ft_digest(int ac, char **av);

#endif
