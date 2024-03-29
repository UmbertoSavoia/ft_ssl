#ifndef FT_SHA256_H
#define FT_SHA256_H

#include "ft_ssl.h"

// https://www.rfc-editor.org/rfc/rfc4634#section-5.1
#define CH(x,y,z)  ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x)   (ROTATE_RIGHT32(x,2) ^ ROTATE_RIGHT32(x,13) ^ ROTATE_RIGHT32(x,22))
#define BSIG1(x)   (ROTATE_RIGHT32(x,6) ^ ROTATE_RIGHT32(x,11) ^ ROTATE_RIGHT32(x,25))
#define SSIG0(x)   (ROTATE_RIGHT32(x,7) ^ ROTATE_RIGHT32(x,18) ^ (x >> 3))
#define SSIG1(x)   (ROTATE_RIGHT32(x,17) ^ ROTATE_RIGHT32(x,19) ^ (x >> 10))

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct  s_sha256_ctx
{
    uint64_t    size;
    uint8_t     buffer[64];
    uint32_t    state[8];
}               t_sha256_ctx;

void    sha256_init(void);
void    sha256_update(uint8_t *input, size_t len);
void    sha256_final(uint8_t digest[]);

#endif