#ifndef RSA_H
#define RSA_H

#define PRIME_ITERATIONS_FOR_SIZE(b) ((b) >= 3747 ? 3 : (b) >= 1345 ? 4 : (b) >= 476 ? 5 : (b) >= 400 ? 6 : (b) >= 347 ? 7 : (b) >= 308 ? 8 : (b) >= 55 ? 27 : 34)
#define NUMPRIMES 2048
#define RSA_KEY_LEN 64
#define PUB_EXP 65537

#define RSA_OPT_OUT     0
#define RSA_OPT_IN      1
#define RSA_OPT_INFORM  2
#define RSA_OPT_OUTFORM 3
#define RSA_OPT_TEXT    4
#define RSA_OPT_NOOUT   5
#define RSA_OPT_PUBIN   6
#define RSA_OPT_PUBOUT  7
#define RSA_OPT_INKEY   8
#define RSA_OPT_ENC     9
#define RSA_OPT_DEC     10
#define RSA_OPT_HEX     11

#define RSA_FLAG_NOOUT  0b00000001
#define RSA_FLAG_TEXT   0b00000010
#define RSA_FLAG_PUBIN  0b00000100
#define RSA_FLAG_PUBOUT 0b00001000
#define RSA_FLAG_ENC    0b00010000
#define RSA_FLAG_DEC    0b00100000
#define RSA_FLAG_HEX    0b01000000

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