#ifndef RSA_H
#define RSA_H

#define PRIME_ITERATIONS_FOR_SIZE(b) ((b) >= 3747 ? 3 : (b) >= 1345 ? 4 : (b) >= 476 ? 5 : (b) >= 400 ? 6 : (b) >= 347 ? 7 : (b) >= 308 ? 8 : (b) >= 55 ? 27 : 34)
#define NUMPRIMES 2048
#define RSA_KEY_LEN 64
#define PUB_EXP 65537

typedef struct  s_rsa_key
{
    uint64_t p;    // First factor
    uint64_t q;    // Secondo factor
    uint64_t n;    // Modulus
    uint64_t e;    // Public exponent
    uint64_t d;    // Private exponent
    uint64_t dp;   // First factor's CRT exponent
    uint64_t dq;   // Second factor's CRT exponent
    uint64_t qinv; // CRT coefficient
    uint64_t phi;  // Totient
}               t_rsa_key;

#endif