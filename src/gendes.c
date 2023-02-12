#include "ft_ssl.h"
#include "ft_des.h"
#include "ft_getopt.h"

int     gendes(int ac, char **av)
{
    t_option opt[] = { {.name = "out", .has_arg = 1} };
    ft_optind = 2;
    uint8_t buf[DES_BLOCK_SIZE] = {0};
    int idx = 0, fd_out = 1;

    while ((idx = ft_getopt_long(ac, av, opt, ARRAY_SIZE(opt))) != -1) {
        switch (idx) {
            case 0:
                if ((fd_out = ft_open(ft_optarg, O_RDWR|O_CREAT)) < 0)
                    return -1;
                break;
        }
    }

    if (generate_rand_range((uint64_t *)buf, (uint64_t)1 << (64-1), ((uint64_t)1UL << (64-1)) - 2) < 0) {
        puts("Key generation error");
        return 0;
    }

    for (int i = 0; i < DES_BLOCK_SIZE; ++i)
        dprintf(fd_out, "%02x", buf[i]);
    dprintf(fd_out, "\n");
    return 0;
}