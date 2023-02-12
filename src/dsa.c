#include "ft_ssl.h"
#include "dsa.h"
#include "rsa.h"
#include "asn1.h"
#include "ft_getopt.h"

int     gendsa(int ac, char **av)
{
    t_option opt[] = { {.name = "out", .has_arg = 1} };
    int idx = 0, fd_out = 1;
    ft_optind = 2;
    t_dsa_key_priv key = {0};
    uint64_t p_m_1 = 0, h = 0;

    while ((idx = ft_getopt_long(ac, av, opt, ARRAY_SIZE(opt))) != -1) {
        switch (idx) {
            case 0:
                if ((fd_out = ft_open(ft_optarg, O_RDWR|O_CREAT)) < 0)
                    return -1;
                break;
        }
    }
    dprintf(2, "Generating DSA parameters, 64 bit long prime\n");
    generate_prime_num(&key.param.q, 32);
    key.param.p = (key.param.q * 2) + 1;
    while (!miller_rabin(key.param.p, PRIME_ITERATIONS_FOR_SIZE(64), 1))
        key.param.p += 2;
    dprintf(2, "\n");
    p_m_1 = key.param.p - 1;
    do {
        generate_rand_range(&h, 2, key.param.p - 2);
    } while ( (power_mod(h-2, key.param.q, key.param.p)) == 0 );
    key.param.g = power_mod(h, p_m_1 / key.param.q, key.param.p);

    generate_rand_range(&key.priv, 1, key.param.q - 1);
    key.pub = power_mod(h, key.priv, key.param.p);

    asn1_pkcs1_dsa_param(&key.param, fd_out);
    asn1_pkcs1_dsa_private_key(&key, fd_out);
    return 0;
}