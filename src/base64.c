#include "ft_ssl.h"
#include "ft_base64.h"
#include "ft_getopt.h"

static uint8_t table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void    process_block_base64(int fd_out, uint32_t block, uint8_t len, uint8_t mode)
{
    uint8_t c = 0;

    if (mode == ENCODE_BASE64) {
        for (int i = 0; i < 4; ++i) {
            c = len >= i ? table[ (block & (0xFC0000 >> (i * 6))) >> (18 - (i * 6)) ] : '=';
            write(fd_out, &c, 1);
        }
    } else if (mode == DECODE_BASE64) {
        for (int i = 0; i < 3 && (len - 1) > i; ++i) {
            c = ((0xFF0000 >> (i * 8)) & block) >> (16 - (i * 8));
            write(fd_out, &c, 1);
        }
    }
}

void    encode_base64(int fd_in, int fd_out)
{
    uint8_t r = 0;
    uint32_t in = 0;

    while ((r = ft_read(fd_in, &in, 3)) > 0) {
        in = bswap_32(in);
        in = in >> 8;
        process_block_base64(fd_out, in, r, ENCODE_BASE64);
        in = 0;
    }
    write(fd_out, "\n", 1);
}

void    decode_base64(int fd_in, int fd_out)
{
    uint8_t r = 0;
    uint8_t in[4] = {0};
    uint8_t idx[4] = {0};
    uint32_t tmp = 0;

    while ((r = ft_read(fd_in, &in, 4)) > 0) {
        for (int i = 0; i < 4; ++i) {
            if (in[i] == '=') {
                --r;
                continue;
            }
            idx[i] = (uint8_t *)strchr((const char *)table, in[i]) - table;
            tmp |= idx[i] << (18 - (i * 6));
        }
        process_block_base64(fd_out, tmp, r, DECODE_BASE64);
        tmp = 0;
        bzero(idx, sizeof(idx));
        bzero(in, sizeof(in));
    }
}

int     ft_base64(int ac, char **av)
{
    int fd_in = 0, fd_out = 1, c = 0, d_flag = 0;
    ft_optind = 2;

    while ((c = ft_getopt(ac, av, "i:o:ed")) != -1) {
        switch (c) {
            case 'i':
                if ((fd_in = ft_open(ft_optarg, O_RDWR)) < 0)
                    return 1;
                break;
            case 'o':
                if ((fd_out = ft_open(ft_optarg, O_RDWR|O_CREAT)) < 0)
                    return 1;
                break;
            case 'd':
                d_flag = 1;
                break;
            case 'e':
                break;
            default:
                printf("usage: %s %s [-d | -e] [-i input_file] [-o output_file]\n\n"
                       " -d     Decode incoming Base64 stream into binary data.\n"
                       " -e     Decode incoming binary data into Base64 stream.\n",
                       av[0], "base64");
        }
    }
    if (d_flag)
        decode_base64(fd_in, fd_out);
    else
        encode_base64(fd_in, fd_out);

    if (fd_in != 0) close(fd_in);
    if (fd_out != 1) close(fd_out);
    return 0;
}
