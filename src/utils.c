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