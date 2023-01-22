#include "ft_ssl.h"

size_t    ft_read(int fd, void *buf, size_t count)
{
    size_t r = 0, ret = 0;

    while (r != count) {
        buf += r;
        count -= r;
        r = read(fd, buf, count);
        ret += r;
        if (r <= 0)
            break;
    }
    return ret;
}

int     ft_open(char *file, int flag)
{
    errno = 0;
    int fd = open(file, flag, 0666);
    if (fd < 0)
        printf("ft_ssl: %s\n", strerror(errno));
    return fd;
}

uint8_t *str_to_hex(char *s, uint32_t bytes)
{
    uint8_t *padded = 0, *out = 0;
    uint8_t in[3] = {0};

    if (!(padded = calloc((bytes * 2) + 1, sizeof(uint8_t))))
        return 0;
    if (!(out = malloc(bytes)))
        return 0;
    for (uint32_t i = 0; i < (bytes * 2); ++i) {
        if (*s)
            padded[i] = *s++;
        else
            padded[i] = '0';
    }

    for (uint32_t i = 0, j = 0; padded[j]; ++i, j += 2) {
        memcpy(in, &padded[j], 2);
        out[i] = strtol(in, 0, 16);
    }
    free(padded);
    return out;
}