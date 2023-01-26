#include "ft_ssl.h"
#include "ft_md5.h"
#include "ft_getopt.h"

static t_md5_ctx ctx = {0};

static const uint32_t S[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static const uint32_t K[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
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

void    md5_init(void)
{
    ctx.size = 0;
    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xefcdab89;
    ctx.state[2] = 0x98badcfe;
    ctx.state[3] = 0x10325476;
}

void    md5_transform(uint32_t m[])
{
    uint32_t A = ctx.state[0];
    uint32_t B = ctx.state[1];
    uint32_t C = ctx.state[2];
    uint32_t D = ctx.state[3];
    uint32_t FF = 0, g = 0;

    for (uint32_t i = 0; i < 64; ++i) {
        if (0 <= i && i <= 15) {
            FF = F(B, C, D);
            g = i;
        } else if (16 <= i && i <= 31) {
            FF = G(B, C, D);
            g = ((i * 5) + 1) % 16;
        } else if (32 <= i && i <= 47) {
            FF = H(B, C, D);
            g = ((i * 3) + 5) % 16;
        } else if (48 <= i && i <= 63) {
            FF = I(B, C, D);
            g = (i * 7) % 16;
        }
        FF = FF + A + K[i] + m[g];
        A = D;
        D = C;
        C = B;
        B = B + ROTATE_LEFT32(FF, S[i]);
    }
    ctx.state[0] += A;
    ctx.state[1] += B;
    ctx.state[2] += C;
    ctx.state[3] += D;
}

void    md5_update(uint8_t *input, size_t len)
{
    uint32_t m[16] = {0};
    uint32_t offset = ctx.size % 64;
    ctx.size += len;

    for (uint32_t i = 0; i < len; ++i) {
        ctx.buffer[offset++] = input[i];
        if (!(offset % 64)) {
            for (uint32_t j = 0; j < 16; ++j)
                m[j] = BYTE_TO_DWORD_LITTLE(ctx.buffer[j*4], ctx.buffer[(j*4)+1],
                                    ctx.buffer[(j*4)+2], ctx.buffer[(j*4)+3]);
            md5_transform(m);
            offset = 0;
        }
    }
}

void    md5_final(uint8_t digest[])
{
    uint32_t m[16] = {0};
    uint32_t offset = ctx.size % 64;
    uint32_t pad_len = offset < 56 ? 56 - offset : (56 + 64) - offset;

    md5_update(pad, pad_len);
    ctx.size -= pad_len;
    for (uint32_t i = 0; i < 14; ++i)
        m[i] = BYTE_TO_DWORD_LITTLE(ctx.buffer[i*4], ctx.buffer[(i*4)+1],
                            ctx.buffer[(i*4)+2], ctx.buffer[(i*4)+3]);
    m[14] = ctx.size * 8;
    m[15] = (ctx.size * 8) >> 32;
    md5_transform(m);

    for (uint32_t i = 0; i < 4; ++i) {
        digest[i     ]  = ctx.state[0] >> (i * 8) & 0xff;
        digest[i +  4]  = ctx.state[1] >> (i * 8) & 0xff;
        digest[i +  8]  = ctx.state[2] >> (i * 8) & 0xff;
        digest[i + 12]  = ctx.state[3] >> (i * 8) & 0xff;
    }
    bzero(&ctx, sizeof(t_md5_ctx));
}
