#ifndef FT_SSL_H
#define FT_SSL_H

#include "stdio.h"
#include "string.h"

typedef struct  s_dispatch
{
    char algo[32];
    int (*func)(int, char **);
}               t_dispatch;

int     md5(int ac, char **av);
int     sha256(int ac, char **av);

#endif
