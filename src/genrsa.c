#include "ft_ssl.h"
#include "ft_getopt.h"
#include "rsa.h"
#include "primes.h"
#include "asn1.h"

int     sieve_zimmermann(uint64_t *rnd, uint32_t bits)
{
    uint64_t delta = 0;
    uint64_t maxdelta = 0xffffffffffffffffL - primes[NUMPRIMES-1];
    uint64_t mods[NUMPRIMES] = {0};

again:
    generate_rand_range(rnd, (uint64_t)1 << (bits-1), ((uint64_t)1 << bits) - 2);
    *rnd = *rnd | (3L << (bits-2));
    *rnd |= 1;
    for (int i = 1; i < NUMPRIMES; ++i)
        mods[i] = *rnd % primes[i];
    delta = 0;
loop:
    for (int i = 1; i < NUMPRIMES; ++i) {
        if (bits <= 31 && delta <= 0x7fffffff && sqrt(primes[i]) > *rnd + delta)
            break;
        if ((mods[i] + delta) % primes[i] == 0) {
            delta += 2;
            if (delta > maxdelta)
                goto again;
            goto loop;
        }
    }
    *rnd += delta;
    if (count_num_bits(*rnd) != bits)
        goto again;
    return 0;
}

int      miller_rabin(uint64_t p, int iteration)
{
    int i = 0;
    uint64_t s = 0;

    if ((p < 2) || (p != 2 && !(p % 2)))
        return 0;

    s = p - 1;
    while (s % 2 == 0)
        s /= 2;
    for (i = 0; i < iteration; i++) {
        uint64_t a = rand() % (p - 1) + 1, temp = s;
        uint64_t mod = power_mod(a, temp, p);
        while (temp != p - 1 && mod != 1 && mod != p - 1) {
            mod = mul_mod(mod, mod, p);
            temp *= 2;
        }
        if (mod != p - 1 && temp % 2 == 0)
            return 0;
        write(2, "+", 1);
    }
    return 1;
}

int     generate_prime_num(uint64_t *ret, int bits)
{
    int iterations = PRIME_ITERATIONS_FOR_SIZE(bits);

    while (1) {
        sieve_zimmermann(ret, bits);
        write(2, ".", 1);
        if (miller_rabin(*ret, iterations))
            break;
    }
    write(2, "\n", 1);
    return 1;
}

int     genrsa(int ac, char **av)
{
    t_rsa_key rsa_key = {0};
    rsa_key.e = PUB_EXP;
    int fd_out = 1, idx = 0;
    t_option opt[] = { {.name = "out", .has_arg = 1} };
    ft_optind = 2;

    while ((idx = ft_getopt_long(ac, av, opt, ARRAY_SIZE(opt))) != -1) {
        switch (idx) {
            case RSA_OPT_OUT:
                if ((fd_out = ft_open(ft_optarg, O_RDWR|O_CREAT)) < 0)
                    return -1;
                break;
        }
    }
    dprintf(2, "Generating RSA private key, %d bit long modulus (2 primes)\n", RSA_KEY_LEN);
    do {
        generate_prime_num(&rsa_key.p, RSA_KEY_LEN / 2);
        generate_prime_num(&rsa_key.q, RSA_KEY_LEN / 2);
    } while (rsa_key.p == rsa_key.q);
    if (rsa_key.p < rsa_key.q)
        swap(&(rsa_key.p), &(rsa_key.q));

    rsa_key.n = rsa_key.p * rsa_key.q;                          // n    = pq
    rsa_key.phi = (rsa_key.p - 1) * (rsa_key.q - 1);            // phi  = (p-1)(q-1)
    rsa_key.d = mul_inv(rsa_key.e, rsa_key.phi);       // d    = e^-1 mo d phi
    rsa_key.dp = rsa_key.d % (rsa_key.p - 1);                   // dp   = d mod (p-1)
    rsa_key.dq = rsa_key.d % (rsa_key.q - 1);                   // dq   = d mod (q-1)
    rsa_key.qinv = mul_inv(rsa_key.q, rsa_key.p);      // qInv = q^-1 mod p

#if defined(__APPLE__)
    dprintf(2, "e is %llu (0x%06llX)\n", rsa_key.e, rsa_key.e);
#else
    dprintf(2, "e is %lu (0x%06lX)\n", rsa_key.e, rsa_key.e);
#endif
    asn1_pkcs1_rsa_private_key(&rsa_key, fd_out);
    return 0;
}