#include "ft_ssl.h"
#include "ft_sha256.h"

static t_sha256_ctx ctx = {0};

static const uint32_t K[] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint8_t pad[] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void    sha256_init(void)
{
    ctx.size = 0;
    ctx.state[0] = 0x6a09e667;
    ctx.state[1] = 0xbb67ae85;
    ctx.state[2] = 0x3c6ef372;
    ctx.state[3] = 0xa54ff53a;
    ctx.state[4] = 0x510e527f;
    ctx.state[5] = 0x9b05688c;
    ctx.state[6] = 0x1f83d9ab;
    ctx.state[7] = 0x5be0cd19;
}

void    sha256_transform(void)
{
    uint32_t A = ctx.state[0];
    uint32_t B = ctx.state[1];
    uint32_t C = ctx.state[2];
    uint32_t D = ctx.state[3];
    uint32_t E = ctx.state[4];
    uint32_t F = ctx.state[5];
    uint32_t G = ctx.state[6];
    uint32_t H = ctx.state[7];
    uint32_t t1 = 0, t2 = 0;
    uint32_t m[64] = {0};

    for (uint32_t j = 0; j < 16; ++j)
        m[j] = BYTE_TO_DWORD_BIG(ctx.buffer[j*4], ctx.buffer[(j*4) + 1], ctx.buffer[(j*4) + 2], ctx.buffer[(j*4) + 3]);
    for (uint32_t j = 16; j < 64; ++j)
        m[j] = SSIG1(m[j - 2]) + m[j - 7] + SSIG0(m[j - 15]) + m[j - 16];

    for (uint32_t i = 0; i < 64; ++i) {
        t1 = H + BSIG1(E) + CH(E, F, G) + K[i] + m[i];
        t2 = BSIG0(A) + MAJ(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + t1;
        D = C;
        C = B;
        B = A;
        A = t1 + t2;
    }
    ctx.state[0] += A;
    ctx.state[1] += B;
    ctx.state[2] += C;
    ctx.state[3] += D;
    ctx.state[4] += E;
    ctx.state[5] += F;
    ctx.state[6] += G;
    ctx.state[7] += H;
}

void    sha256_update(uint8_t *input, size_t len)
{
    uint32_t offset = ctx.size % 64;
    ctx.size += len;

    for (uint32_t i = 0; i < len; ++i) {
        ctx.buffer[offset++] = input[i];
        if (!(offset % 64)) {
            sha256_transform();
            offset = 0;
        }
    }
}

void    sha256_final(uint8_t digest[])
{
    uint32_t offset = ctx.size % 64;
    uint32_t pad_len = offset < 56 ? 56 - offset : (56 + 64) - offset;

    sha256_update(pad, pad_len);
    ctx.size -= pad_len;

    ctx.buffer[63] = (ctx.size * 8);
    ctx.buffer[62] = (ctx.size * 8) >> 8;
    ctx.buffer[61] = (ctx.size * 8) >> 16;
    ctx.buffer[60] = (ctx.size * 8) >> 24;
    ctx.buffer[59] = (ctx.size * 8) >> 32;
    ctx.buffer[58] = (ctx.size * 8) >> 40;
    ctx.buffer[57] = (ctx.size * 8) >> 48;
    ctx.buffer[56] = (ctx.size * 8) >> 56;
    sha256_transform();

    for (uint32_t i = 0; i < 4; ++i) {
        digest[i     ] = (ctx.state[0] >> (24 - i * 8)) & 0xff;
        digest[i +  4] = (ctx.state[1] >> (24 - i * 8)) & 0xff;
        digest[i +  8] = (ctx.state[2] >> (24 - i * 8)) & 0xff;
        digest[i + 12] = (ctx.state[3] >> (24 - i * 8)) & 0xff;
        digest[i + 16] = (ctx.state[4] >> (24 - i * 8)) & 0xff;
        digest[i + 20] = (ctx.state[5] >> (24 - i * 8)) & 0xff;
        digest[i + 24] = (ctx.state[6] >> (24 - i * 8)) & 0xff;
        digest[i + 28] = (ctx.state[7] >> (24 - i * 8)) & 0xff;
    }
    bzero(&ctx, sizeof(t_sha256_ctx));
}