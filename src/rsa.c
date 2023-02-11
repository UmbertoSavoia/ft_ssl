#include "ft_ssl.h"
#include "asn1.h"
#include "rsa.h"
#include "ft_getopt.h"

int    get_option_rsa(int ac, char **av, t_option *opt, uint32_t size_opt, int *fd_in, int *fd_out, uint8_t *flag)
{
    int idx = 0;

    while ((idx = ft_getopt_long(ac, av, opt, size_opt)) != -1) {
        switch (idx) {
            case RSA_OPT_OUT:
                if ((*fd_out = open(ft_optarg, O_RDWR|O_CREAT)) < 0)
                    return -1;
                break;
            case RSA_OPT_IN:
                if ((*fd_in = open(ft_optarg, O_RDWR)) < 0)
                    return -1;
                break;
            case RSA_OPT_TEXT:
                *flag |= RSA_FLAG_TEXT;
                break;
            case RSA_OPT_NOOUT:
                *flag |= RSA_FLAG_NOOUT;
                break;
            case RSA_OPT_PUBIN:
                *flag |= RSA_FLAG_PUBIN;
                break;
            case RSA_OPT_PUBOUT:
                *flag |= RSA_FLAG_PUBOUT;
                break;
        }
    }
    return 0;
}

void    print_info_rsa_key(t_rsa_key *key, char *type_key, uint8_t is_pub, int fd_out)
{
    dprintf(fd_out,
            "%s\n"
            "modulus: %lu (%#lx)\n"
            "publicExponent: %lu (%#lx)\n",
            type_key,
            key->n, key->n,
            key->e, key->e);
    if (is_pub)
        return;
    dprintf(fd_out,
            "privateExponent: %lu (%#lx)\n"
            "prime1: %lu (%#lx)\n"
            "prime2: %lu (%#lx)\n"
            "exponent1: %lu (%#lx)\n"
            "exponent2: %lu (%#lx)\n"
            "coefficient: %lu (%#lx)\n",
            key->d, key->d,
            key->p, key->p,
            key->q, key->q,
            key->dp, key->dp,
            key->dq, key->dq,
            key->qinv, key->qinv);
}

int     rsa(int ac, char **av)
{
    t_option opt[] = {
            { .name = "out",      .has_arg = 1 },
            { .name = "in",       .has_arg = 1 },
            { .name = "inform",   .has_arg = 1 },
            { .name = "outform",  .has_arg = 1 },
            { .name = "text",     .has_arg = 0 },
            { .name = "noout",    .has_arg = 0 },
            { .name = "pubin",    .has_arg = 0 },
            { .name = "pubout",   .has_arg = 0 },
    };
    t_rsa_key rsa_key = {0};
    int fd_in = 0, fd_out = 1;
    uint8_t flag = 0;
    ft_optind = 2;

    if (get_option_rsa(ac, av, opt, ARRAY_SIZE(opt), &fd_in, &fd_out, &flag) < 0)
        return -1;

    if (flag & RSA_FLAG_PUBIN) {
        if (asn1_parse_pem_rsa_public_key(&rsa_key, fd_in) < 0) {
            dprintf(2, "Wrong key\n");
            return 0;
        }
    } else {
        if (asn1_parse_pem_rsa_private_key(&rsa_key, fd_in) < 0) {
            dprintf(2, "Wrong key\n");
            return 0;
        }
    }

    if (flag & RSA_FLAG_TEXT) {
        if (flag & RSA_FLAG_PUBIN)
            print_info_rsa_key(&rsa_key, "RSA Public-Key: (64 bit)", 1, fd_out);
        else
            print_info_rsa_key(&rsa_key, "RSA Private-Key: (64 bit, 2 primes)", 0, fd_out);
    }
    if (!(flag & RSA_FLAG_NOOUT)) {
        if ((flag & RSA_FLAG_PUBOUT) || (flag & RSA_FLAG_PUBIN)) {
            asn1_pkcs1_rsa_public_key(&rsa_key, fd_out);
        } else {
            asn1_pkcs1_rsa_private_key(&rsa_key, fd_out);
        }
    }

    if (fd_in != 0) close(fd_in);
    if (fd_out != 1) close(fd_out);
    return 0;
}