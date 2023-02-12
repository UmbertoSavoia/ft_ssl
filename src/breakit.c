#include "ft_ssl.h"
#include "ft_getopt.h"
#include "rsa.h"
#include "asn1.h"

int     get_option_breakit(int ac, char **av, t_option *opt, uint32_t size_opt, t_rsa_key *key, int *fd_out, uint8_t *flag)
{
    int idx = 0, fd = 0;
    char *key_file = 0;

    while ((idx = ft_getopt_long(ac, av, opt, size_opt)) != -1) {
        switch (idx) {
            case RSA_OPT_OUT:
                if ((*fd_out = ft_open(ft_optarg, O_RDWR|O_CREAT)) < 0)
                    return -1;
                break;
            case RSA_OPT_IN:
                key_file = ft_optarg;
                break;
            case RSA_OPT_PUBIN:
                *flag |= RSA_FLAG_PUBIN;
                break;
        }
    }

    if ((fd = open(key_file, O_RDWR)) < 0) {
        dprintf(2, "Error file key\n");
        return -1;
    }
    if (*flag & RSA_FLAG_PUBIN) {
        if (asn1_parse_pem_rsa_public_key(key, fd) < 0) {
            dprintf(2, "Wrong key\n");
            return -1;
        }
    } else {
        if (asn1_parse_pem_rsa_private_key(key, fd) < 0) {
            dprintf(2, "Wrong key\n");
            return -1;
        }
    }
    close(fd);
    return 0;
}

int     breakit(int ac, char **av)
{
    t_option opt[] = {
            { .name = "out",      .has_arg = 1 },
            { .name = "in",       .has_arg = 1 },
            { .name = "",         .has_arg = 0 },
            { .name = "",         .has_arg = 0 },
            { .name = "",         .has_arg = 0 },
            { .name = "",         .has_arg = 0 },
            { .name = "pubin",    .has_arg = 0 },
    };
    t_rsa_key rsa_key = {0};
    int fd_out = 1;
    uint8_t flag = 0;
    ft_optind = 2;

    if (get_option_breakit(ac, av, opt, ARRAY_SIZE(opt), &rsa_key, &fd_out, &flag) < 0)
        return 0;

    int prime = 2;
    for (uint64_t i = 1; i <= rsa_key.n && prime; ++i) {
        if (!(rsa_key.n % i) && miller_rabin(i, PRIME_ITERATIONS_FOR_SIZE(i), 0)) {
            dprintf(fd_out, "Prime number %d: %lu (%#lx)\n", prime--, i, i);
        }
    }

    if (fd_out != 1) close(fd_out);
    return 0;
}