#ifndef DSA_H
#define DSA_H

#include "ft_ssl.h"

typedef struct  s_dsa_param
{
    uint64_t p;
    uint64_t q;
    uint64_t g;
}               t_dsa_param;

typedef struct  s_dsa_key_priv
{
    t_dsa_param param;
    uint64_t priv;
    uint64_t pub;
}               t_dsa_key_priv;

#endif