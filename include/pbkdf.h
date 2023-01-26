#ifndef PBKDF_H
#define PBKDF_H

#include "ft_ssl.h"
#include "ft_digest.h"

#define PBKDF_ITERATIONS_DEFAULT 10000

void    pbkdf2(t_digest *hash, uint8_t *pass, size_t pass_len, uint8_t *salt, size_t salt_len,
               uint32_t iter, uint8_t derived_key[], size_t derived_key_len);

#endif
