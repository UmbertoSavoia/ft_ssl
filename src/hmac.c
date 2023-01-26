#include "ft_ssl.h"
#include "hmac.h"

static t_hmac_ctx ctx = {0};

void    hmac_init(t_digest *hash, uint8_t *key, size_t key_len)
{
    ctx.hash = hash;

    if (key_len > hash->block_size) {
        hash->init();
        hash->update(key, key_len);
        hash->final(ctx.key);
    } else {
        memcpy(ctx.key, key, key_len);
    }
    for (uint32_t i = 0; i < hash->block_size; ++i)
        ctx.key[i] ^= HMAC_IPAD;
    hash->init();
    hash->update(ctx.key, hash->block_size);
}

void    hmac_update(uint8_t *input, size_t len)
{
    ctx.hash->update(input, len);
}

void    hmac_final(uint8_t digest[])
{
    ctx.hash->final(ctx.digest);

    for (uint32_t i = 0; i < ctx.hash->block_size; ++i)
        ctx.key[i] ^= HMAC_IPAD ^ HMAC_OPAD;

    ctx.hash->init();
    ctx.hash->update(ctx.key, ctx.hash->block_size);
    ctx.hash->update(ctx.digest, ctx.hash->digest_len);
    ctx.hash->final(ctx.digest);
    memcpy(digest, ctx.digest, HMAC_MAX_SIZE);
    bzero(&ctx, sizeof(t_hmac_ctx));
}