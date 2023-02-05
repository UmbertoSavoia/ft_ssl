#include "ft_ssl.h"
#include "ft_sha256.h"
#include "ft_base64.h"

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

void    resolve_base64(t_mode_arg *args)
{
    int fd_cache = 0;

    if (!(args->flags & A_FLAG))
        return;
    fd_cache = memfd_create("cache", 0);
    if (args->flags & E_FLAG) {
        args->fd_cache = args->fd_out;
        args->fd_out = fd_cache;
    } else if (args->flags & D_FLAG) {
        decode_base64(args->fd_in, fd_cache);
        close(args->fd_in);
        lseek(fd_cache, 0, SEEK_SET);
        args->fd_in = fd_cache;
    }
}

uint32_t    count_num_bits(uint64_t n)
{
    uint32_t count = 0;

    while (n) {
        count++;
        n >>= 1;
    }
    return count;
}

int     generate_rand_range(uint64_t *ret, uint64_t lower, uint64_t upper)
{
    int fd = 0;

    if ((fd = open("/dev/urandom", O_RDONLY)) < 0)
        return -1;
    if (read(fd, ret, sizeof(uint64_t)) < 0)
        return -1;
    close(fd);
    *ret = (*ret % (upper - lower + 1)) + lower;
    return 0;
}

// (a*b) (mod n)
uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t d = 0, mp2 = m >> 1;

    if (a >= m)
        a %= m;
    if (b >= m)
        b %= m;
    for (int i = 0; i < 64; ++i) {
        d = (d > mp2) ? (d << 1) - m : d << 1;
        if (a & 0x8000000000000000ULL)
            d += b;
        if (d >= m)
            d -= m;
        a <<= 1;
    }
    return d;
}

// (a^b) (mod m)
uint64_t power_mod(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r = m == 1 ? 0 : 1;
    while (b > 0) {
        if (b & 1)
            r = mul_mod(r, a, m);
        b = b >> 1;
        a = mul_mod(a, a, m);
    }
    return r;
}

void    swap(uint64_t *a, uint64_t *b)
{
    uint64_t t = *a;

    *a = *b;
    *b = t;
}

__int128_t mul_inv(__int128_t n, __int128_t mod)
{
    __int128_t a = mod, b = a, c = 0, d = 0, e = 1, f, g;
    for (n *= a > 1; n > 1 && (n *= a > 0); e = g, c = (c & 3) | (c & 1) << 2) {
        g = d, d *= n / (f = a);
        a = n % a, n = f;
        c = (c & 6) | (c & 2) >> 1;
        f = c > 1 && c < 6;
        c = (c & 5) | (f || e > d ? (c & 4) >> 1 : ~c & 2);
        d = f ? d + e : e > d ? e - d : d - e;
    }
    return n ? c & 4 ? b - e : e : 0;
}
