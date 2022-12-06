#ifndef FT_SSL_H
#define FT_SSL_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define ROTATE_LEFT(x, n)           ((x << n) | (x >> (32 - n)))
#define BYTE_TO_WORD(a, b, c, d)    (a | b << 8 | c << 16 | d << 24)

typedef struct  s_dispatch
{
    char algo[32];
    int (*func)(int, char **);
}               t_dispatch;

int     ft_md5(int ac, char **av);
int     ft_sha256(int ac, char **av);

#endif
