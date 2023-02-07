#include "ft_ssl.h"
#include "rsa.h"
#include "asn1.h"
#include "ft_base64.h"

void    asn1_add_len(uint8_t *buf, uint32_t *offset, uint64_t len)
{
    uint32_t bytes_len = count_num_bytes(len);

    if ((bytes_len > 1) || (len & 0x80)) {
        buf[(*offset)++] = bytes_len | 0x80;
        for (int i = 0; i < bytes_len; i++) {
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

    for (int i = 0; i < bytes_n; i++) {
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

    if ((fd_cache = memfd_create("cache", 0)) < 0)
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

    write(fd_cache, der, offset + len_tmp);
    lseek(fd_cache, 0, SEEK_SET);
    dprintf(fd_out, "%s\n", "-----BEGIN RSA PRIVATE KEY-----");
    encode_base64(fd_cache, fd_out);
    dprintf(fd_out, "%s\n", "-----END RSA PRIVATE KEY-----");

    close(fd_cache);
}