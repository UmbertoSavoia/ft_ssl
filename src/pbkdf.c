#include "ft_ssl.h"
#include "ft_digest.h"
#include "hmac.h"

void    pbkdf2(t_digest *hash, uint8_t *pass, size_t pass_len, uint8_t *salt, size_t salt_len,
               uint32_t iter, uint8_t derived_key[], size_t derived_key_len)
{
    uint32_t k = 0;
    uint8_t a[4] = {0};
    uint8_t t[HMAC_MAX_SIZE] = {0};
    uint8_t u[HMAC_MAX_SIZE] = {0};

    for (uint32_t i = 1; derived_key_len > 0; ++i) {
        STORE_DWORD_BIG(i, a);
        hmac_init(hash, pass, pass_len);
        hmac_update(salt, salt_len);
        hmac_update(a, 4);
        hmac_final(u);
        memcpy(t, u, hash->digest_len);

        for (uint32_t j = 1; j < iter; ++j) {
            hmac_init(hash, pass, pass_len);
            hmac_update(u, hash->digest_len);
            hmac_final(u);

            for(k = 0; k < hash->digest_len; k++)
                t[k] ^= u[k];
        }
        k = MIN(derived_key_len, hash->digest_len);
        memcpy(derived_key, t, k);
        derived_key += k;
        derived_key_len -= k;
    }
}