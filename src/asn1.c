#include "ft_ssl.h"
#include "rsa.h"
#include "asn1.h"
#include "ft_base64.h"

uint32_t    asn1_parse_len(uint8_t *buf, uint32_t *offset)
{
    uint32_t ret = 0;
    uint32_t len = 0;

    if (buf[*offset] & 0x80) {
        len = buf[*offset] & 0b01111111;
        (*offset)++;
        for (uint32_t i = 0; i < len-1; ++i, (*offset)++) {
            ret |= buf[*offset];
            ret <<= 8;
        }
        ret |= buf[(*offset)++];
    } else {
        ret = buf[(*offset)++];
    }
    return ret;
}

uint64_t    asn1_parse_integer(uint8_t *buf, uint32_t *offset, uint32_t len_int)
{
    uint64_t ret = 0;

    for (uint32_t i = 0; i < len_int-1; ++i, (*offset)++) {
        ret |= buf[*offset];
        ret <<= 8;
    }
    ret |= buf[(*offset)++];
    return ret;
}

int     asn1_parse_der_public_key(t_rsa_key *rsa, uint8_t *buf)
{
    uint32_t offset = 0, len_sequence = 0;
    uint8_t AlgorithmIdentifier[] = { 0x30, 0x0d, 0x06, 0x09,
                                      0x2a, 0x86, 0x48, 0x86,
                                      0xf7, 0x0d, 0x01, 0x01,
                                      0x01, 0x05, 0x00 };

    if (buf[offset++] != ANS1_TAG_SEQUENCE) return -1;
    len_sequence = asn1_parse_len(buf, &offset);
    if (memcmp(&(buf[offset]), AlgorithmIdentifier, sizeof(AlgorithmIdentifier))) return -1;
    offset += sizeof(AlgorithmIdentifier);
    if (buf[offset++] != ASN1_TAG_BITSTRING) return -1;
    len_sequence = asn1_parse_len(buf, &offset);
    if (buf[offset++] != 0x00) return -1;
    if (buf[offset++] != ANS1_TAG_SEQUENCE) return -1;
    len_sequence = asn1_parse_len(buf, &offset);
    if (buf[offset++] != ASN1_TAG_INTEGER) return -1;
    rsa->n = asn1_parse_integer(buf, &offset, asn1_parse_len(buf, &offset));
    if (buf[offset++] != ASN1_TAG_INTEGER) return -1;
    rsa->e = asn1_parse_integer(buf, &offset, asn1_parse_len(buf, &offset));

    return 0;
}

int     asn1_parse_der_private_key(t_rsa_key *rsa, uint8_t *buf)
{
    uint32_t offset = 0, len_sequence = 0;

    if (buf[offset++] != ANS1_TAG_SEQUENCE) return -1;
    len_sequence = asn1_parse_len(buf, &offset);
    if (memcmp(&(buf[offset]), "\x02\x01\x00", 3)) return -1;
    offset += 3;

    if (buf[offset++] != ASN1_TAG_INTEGER) return -1;
    rsa->n = asn1_parse_integer(buf, &offset, asn1_parse_len(buf, &offset));
    if (buf[offset++] != ASN1_TAG_INTEGER) return -1;
    rsa->e = asn1_parse_integer(buf, &offset, asn1_parse_len(buf, &offset));
    if (buf[offset++] != ASN1_TAG_INTEGER) return -1;
    rsa->d = asn1_parse_integer(buf, &offset, asn1_parse_len(buf, &offset));
    if (buf[offset++] != ASN1_TAG_INTEGER) return -1;
    rsa->p = asn1_parse_integer(buf, &offset, asn1_parse_len(buf, &offset));
    if (buf[offset++] != ASN1_TAG_INTEGER) return -1;
    rsa->q = asn1_parse_integer(buf, &offset, asn1_parse_len(buf, &offset));
    if (buf[offset++] != ASN1_TAG_INTEGER) return -1;
    rsa->dp = asn1_parse_integer(buf, &offset, asn1_parse_len(buf, &offset));
    if (buf[offset++] != ASN1_TAG_INTEGER) return -1;
    rsa->dq = asn1_parse_integer(buf, &offset, asn1_parse_len(buf, &offset));
    if (buf[offset++] != ASN1_TAG_INTEGER) return -1;
    rsa->qinv = asn1_parse_integer(buf, &offset, asn1_parse_len(buf, &offset));

    /*printf("n: %lX\ne: %lX\nd: %lX\np: %lX\nq: %lX\ndp: %lX\ndq: %lX\nqinv: %lX\n",
           rsa->n, rsa->e, rsa->d, rsa->p, rsa->q, rsa->dp, rsa->dq, rsa->qinv);*/
    return 0;
}

int     asn1_parse_pem_rsa_public_key(t_rsa_key *rsa, int fd_in)
{
    char buf[2048] = {0};
    uint8_t der[2048] = {0};
    char *ptr_start = 0, *ptr_end = 0;
    int fd_cache_in = 0, fd_cache_out = 0;

    ft_read(fd_in, buf, sizeof(buf));
    if (!(ptr_start = strstr(buf, PEM_HEADER_RSA_PUBLIC)))
        return -1;
    if (!(ptr_end = strstr(buf, PEM_FOOTER_RSA_PUBLIC)))
        return -1;

    if ((fd_cache_in = memfd_create("cache", 0)) < 0)
        return -1;
    if ((fd_cache_out = memfd_create("cache", 0)) < 0)
        return -1;
    ptr_start += strlen(PEM_HEADER_RSA_PUBLIC) + 1;
    write(fd_cache_in, ptr_start, ptr_end - ptr_start - 1);
    lseek(fd_cache_in, 0, SEEK_SET);
    decode_base64(fd_cache_in, fd_cache_out);
    lseek(fd_cache_out, 0, SEEK_SET);
    ft_read(fd_cache_out, der, sizeof(der));
    close(fd_cache_in);
    close(fd_cache_out);
    if (asn1_parse_der_public_key(rsa, der) < 0)
        return -1;
    return 0;
}

int     asn1_parse_pem_rsa_private_key(t_rsa_key *rsa, int fd_in)
{
    char buf[2048] = {0};
    uint8_t der[2048] = {0};
    char *ptr_start = 0, *ptr_end = 0;
    int fd_cache_in = 0, fd_cache_out = 0;

    ft_read(fd_in, buf, sizeof(buf));
    if (!(ptr_start = strstr(buf, PEM_HEADER_RSA_PRIVATE)))
        return -1;
    if (!(ptr_end = strstr(buf, PEM_FOOTER_RSA_PRIVATE)))
        return -1;

    if ((fd_cache_in = memfd_create("cache", 0)) < 0)
        return -1;
    if ((fd_cache_out = memfd_create("cache", 0)) < 0)
        return -1;
    ptr_start += strlen(PEM_HEADER_RSA_PRIVATE) + 1;
    write(fd_cache_in, ptr_start, ptr_end - ptr_start - 1);
    lseek(fd_cache_in, 0, SEEK_SET);
    decode_base64(fd_cache_in, fd_cache_out);
    lseek(fd_cache_out, 0, SEEK_SET);
    ft_read(fd_cache_out, der, sizeof(der));
    close(fd_cache_in);
    close(fd_cache_out);
    if (asn1_parse_der_private_key(rsa, der) < 0)
        return -1;
    return 0;
}

void    asn1_add_len(uint8_t *buf, uint32_t *offset, uint64_t len)
{
    uint32_t bytes_len = count_num_bytes(len);

    if ((bytes_len > 1) || (len & 0x80)) {
        buf[(*offset)++] = bytes_len | 0x80;
        for (uint32_t i = 0; i < bytes_len; i++) {
            buf[*offset + bytes_len - i - 1] = len & 0xff;
            len >>= 8;
        }
        *offset += bytes_len;
    } else {
        buf[(*offset)++] = len;
    }
}

void    asn1_add_integer(uint8_t *buf, uint32_t *offset, uint64_t n)
{
    uint32_t bytes_n = count_num_bytes(n);

    if ((n >> ((bytes_n * 8) - 1)) & 1)
        bytes_n++;

    buf[(*offset)++] = ASN1_TAG_INTEGER;

    asn1_add_len(buf, offset, bytes_n);

    for (uint32_t i = 0; i < bytes_n; i++) {
        buf[*offset + bytes_n - i - 1] = n & 0xff;
        n >>= 8;
    }
    *offset += bytes_n;
}

/*
 * https://www.rfc-editor.org/rfc/rfc3447#page-45
 *     RSAPrivateKey ::= SEQUENCE {
 *        version           Version,
 *        modulus           INTEGER,  -- n
 *        publicExponent    INTEGER,  -- e
 *        privateExponent   INTEGER,  -- d
 *        prime1            INTEGER,  -- p
 *        prime2            INTEGER,  -- q
 *        exponent1         INTEGER,  -- d mod (p-1)
 *        exponent2         INTEGER,  -- d mod (q-1)
 *        coefficient       INTEGER,  -- (inverse of q) mod p
 *        otherPrimeInfos   OtherPrimeInfos OPTIONAL
 *    }
 */
void    asn1_pkcs1_rsa_private_key(t_rsa_key *key, int fd_out)
{
    int fd_cache = -1;
    uint8_t der[1024] = {0}, tmp[1024] = {0};
    uint32_t len_tmp = 0, offset = 0;
#if defined(__APPLE__)
    if ((fd_cache = open("/tmp/cache", O_CREAT | O_RDWR, 0666)) < 0)
#else
    if ((fd_cache = memfd_create("cache", 0)) < 0)
#endif
        return;
    asn1_add_integer(tmp, &len_tmp, 0); // version
    asn1_add_integer(tmp, &len_tmp, key->n);
    asn1_add_integer(tmp, &len_tmp, key->e);
    asn1_add_integer(tmp, &len_tmp, key->d);
    asn1_add_integer(tmp, &len_tmp, key->p);
    asn1_add_integer(tmp, &len_tmp, key->q);
    asn1_add_integer(tmp, &len_tmp, key->dp);
    asn1_add_integer(tmp, &len_tmp, key->dq);
    asn1_add_integer(tmp, &len_tmp, key->qinv);

    der[offset++] = ANS1_TAG_SEQUENCE;
    asn1_add_len(der, &offset, len_tmp);
    memcpy(&(der[offset]), tmp, len_tmp);
    offset += len_tmp;

    write(fd_cache, der, offset);
    lseek(fd_cache, 0, SEEK_SET);
    dprintf(fd_out, "%s\n", PEM_HEADER_RSA_PRIVATE);
    encode_base64(fd_cache, fd_out);
    dprintf(fd_out, "%s\n", PEM_FOOTER_RSA_PRIVATE);

    close(fd_cache);
}

/*
 *  PublicKeyInfo ::= SEQUENCE {
 *    algorithm   AlgorithmIdentifier,
 *    PublicKey   BIT STRING
 *  }
 *
 *  AlgorithmIdentifier ::= SEQUENCE {
 *    algorithm   OBJECT IDENTIFIER,
 *    parameters  ANY DEFINED BY algorithm OPTIONAL
 *  }
 *
 * https://www.rfc-editor.org/rfc/rfc3447#page-44
 *    RSAPublicKey ::= SEQUENCE {
 *        modulus           INTEGER,  -- n
 *        publicExponent    INTEGER   -- e
 *    }
 *
 *  30 24                                           SEQUENCE            PublicKeyInfo
 *      30 0d                                       SEQUENCE            AlgorithmIdentifier
 *          06 09 2a 86 48 86 f7 0d 01 01 01        OBJECT IDENTIFIER       rsaEncryption
 *          05 00                                   NULL
 *      03 13 00                                    BIT STRING
 *          30 10                                   SEQUENCE            RSAPublicKey
 *              02 09 00 ca b6 c0 5d db 74 c0 ed    INTEGER
 *              02 03 01 00 01                      INTEGER
*/
void    asn1_pkcs1_rsa_public_key(t_rsa_key *key, int fd_out)
{
    int fd_cache = -1;
    uint8_t der[1024] = {0}, tmp[1024] = {0},
        tmp_RSAPublicKey[1024] = {0}, RSAPublicKey[1024] = {0},
        BitString[1024] = {0};
    uint32_t len_tmp = 0, len_tmp_RSAPublicKey = 0, len_RSAPublicKey = 0,
        len_BitString = 0, offset = 0;
    uint8_t AlgorithmIdentifier[] = { 0x30, 0x0d, 0x06, 0x09,
                                     0x2a, 0x86, 0x48, 0x86,
                                     0xf7, 0x0d, 0x01, 0x01,
                                     0x01, 0x05, 0x00 };

#if defined(__APPLE__)
    if ((fd_cache = open("/tmp/cache", O_CREAT | O_RDWR, 0666)) < 0)
#else
    if ((fd_cache = memfd_create("cache", 0)) < 0)
#endif
        return;
    memcpy(tmp, AlgorithmIdentifier, sizeof(AlgorithmIdentifier));
    len_tmp += sizeof(AlgorithmIdentifier);

    asn1_add_integer(tmp_RSAPublicKey, &len_tmp_RSAPublicKey, key->n);
    asn1_add_integer(tmp_RSAPublicKey, &len_tmp_RSAPublicKey, key->e);
    RSAPublicKey[len_RSAPublicKey++] = ANS1_TAG_SEQUENCE;
    asn1_add_len(RSAPublicKey, &len_RSAPublicKey, len_tmp_RSAPublicKey);
    memcpy(RSAPublicKey + len_RSAPublicKey, tmp_RSAPublicKey, len_tmp_RSAPublicKey);
    len_RSAPublicKey += len_tmp_RSAPublicKey;

    BitString[len_BitString++] = ASN1_TAG_BITSTRING;
    asn1_add_len(BitString, &len_BitString, len_RSAPublicKey + 1);
    BitString[len_BitString++] = 0x00;
    memcpy(BitString + len_BitString, RSAPublicKey, len_RSAPublicKey);
    len_BitString += len_RSAPublicKey;

    memcpy(tmp + len_tmp, BitString, len_BitString);
    len_tmp += len_BitString;

    der[offset++] = ANS1_TAG_SEQUENCE;
    asn1_add_len(der, &offset, len_tmp);
    memcpy(der + offset, tmp, len_tmp);
    offset += len_tmp;

    write(fd_cache, der, offset);
    lseek(fd_cache, 0, SEEK_SET);
    dprintf(fd_out, "%s\n", PEM_HEADER_RSA_PUBLIC);
    encode_base64(fd_cache, fd_out);
    dprintf(fd_out, "%s\n", PEM_FOOTER_RSA_PUBLIC);

    close(fd_cache);
}
