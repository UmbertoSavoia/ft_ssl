#include "ft_ssl.h"

void    pad_pkcs5(uint8_t *dest, uint32_t buf_len, uint32_t block_size)
{
    int size = block_size - buf_len;

    memset(dest, size, size);
}

uint32_t    unpad_pkcs5(uint8_t *buf, uint32_t buf_len, uint32_t block_size)
{
    uint8_t pad = buf[block_size - 1];

    for (uint32_t i = 0; i < pad; ++i)
        if (buf[--buf_len] != pad)
            return block_size;
    return buf_len;
}