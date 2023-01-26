#include "ft_ssl.h"
#include "ft_sha256.h"

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

int     key_derivation(t_mode_arg *args, uint32_t block_size)
{
    if (args->key)
        return 0;
    if (!(args->pass) || !(args->salt))
        return -1;
    t_digest hash = {
            .init = sha256_init, .update = sha256_update, .final = sha256_final,
            .block_size = SHA256_BLOCK_SIZE, .digest_len = SHA256_DIGEST_SIZE
    };
    uint8_t *derived = 0;

    if (!(derived = malloc(block_size)))
        return -1;
    pbkdf2(&hash,
           args->pass, strlen(args->pass),
           args->salt, strlen(args->salt),
           PBKDF_ITERATIONS_DEFAULT,
            derived, block_size);
    args->key = derived;

    if (args->flags & E_FLAG)
        dprintf(args->fd_out, "%s%s", SALTED, args->salt);

    if (args->flags & D_FLAG) {
        char buf[8] = {0};
        read(args->fd_in, buf, sizeof(buf));
        if (!memcmp(buf, SALTED, strlen(SALTED))) {
            read(args->fd_in, buf, sizeof(buf));
        } else {
            lseek(args->fd_in, 0, SEEK_SET);
        }
    }
    return 0;
}