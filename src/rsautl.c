#include "ft_ssl.h"
#include "ft_getopt.h"
#include "asn1.h"
#include "rsa.h"

int    get_option_rsautl(int ac, char **av, t_option *opt, uint32_t size_opt, t_rsa_key *key, int *fd_in, int *fd_out, uint8_t *flag)
{
    int idx = 0, fd = 0;
    char *key_file = 0;

    while ((idx = ft_getopt_long(ac, av, opt, size_opt)) != -1) {
        switch (idx) {
            case RSA_OPT_OUT:
                if ((*fd_out = ft_open(ft_optarg, O_RDWR|O_CREAT)) < 0)
                    return -1;
                break;
            case RSA_OPT_IN:
                if ((*fd_in = open(ft_optarg, O_RDWR)) < 0)
                    return -1;
                break;
            case RSA_OPT_ENC:
                *flag |= RSA_FLAG_ENC;
                break;
            case RSA_OPT_DEC:
                *flag |= RSA_FLAG_DEC;
                break;
            case RSA_OPT_PUBIN:
                *flag |= RSA_FLAG_PUBIN;
                break;
            case RSA_OPT_PUBOUT:
                *flag |= RSA_FLAG_PUBOUT;
                break;
            case RSA_OPT_HEX:
                *flag |= RSA_FLAG_HEX;
                break;
            case RSA_OPT_INKEY:
                key_file = ft_optarg;
                break;
        }
    }

    if ((fd = open(key_file, O_RDWR)) < 0) {
        dprintf(2, "Error file key\n");
        return -1;
    }
    if (*flag & RSA_FLAG_PUBIN) {
        if (asn1_parse_pem_rsa_public_key(key, fd) < 0) {
            dprintf(2, "Wrong key\n");
            return -1;
        }
    } else {
        if (asn1_parse_pem_rsa_private_key(key, fd) < 0) {
            dprintf(2, "Wrong key\n");
            return -1;
        }
    }
    close(fd);
    return 0;
}

void    rsautl_hexdump(uint64_t output, int fd_out)
{
    dprintf(fd_out, "%04x - ", 0);
    for (int i = 0; i < sizeof(uint64_t); ++i)
        dprintf(fd_out, "%02x ", (output >> (i*8)) & 0xff);
    dprintf(fd_out, "  ");
    for (int i = 0; i < sizeof(uint64_t); ++i)
        dprintf(fd_out, "%c",
                isprint((output >> (i*8)) & 0xff) ? (output >> (i*8)) & 0xff : '.');
    dprintf(fd_out, "\n");
}

/*
 *  Encryption c = (msg ^ e) % n
 *  Decryption m = (c ^ d) % n
 */
int     rsautl(int ac, char **av)
{
    t_option opt[] = {
            { .name = "out",      .has_arg = 1 },
            { .name = "in",       .has_arg = 1 },
            { .name = "",         .has_arg = 0 },
            { .name = "",         .has_arg = 0 },
            { .name = "",         .has_arg = 0 },
            { .name = "",         .has_arg = 0 },
            { .name = "pubin",    .has_arg = 0 },
            { .name = "pubout",   .has_arg = 0 },
            { .name = "inkey",    .has_arg = 1 },
            { .name = "encrypt",  .has_arg = 0 },
            { .name = "decrypt",  .has_arg = 0 },
            { .name = "hexdump",  .has_arg = 0 },
    };
    t_rsa_key rsa_key = {0};
    int fd_in = 0, fd_out = 1;
    uint64_t input = 0, output = 0;
    uint8_t flag = 0;
    ft_optind = 2;

    if (get_option_rsautl(ac, av, opt, ARRAY_SIZE(opt), &rsa_key, &fd_in, &fd_out, &flag) < 0)
        return 0;
    ft_read(fd_in, &input, RSA_KEY_LEN / 8);
    input = BSWAP64(input);

    if (flag & RSA_FLAG_ENC) {
        output = power_mod(input, rsa_key.e, rsa_key.n);
    } else if (flag & RSA_FLAG_DEC) {
        output = power_mod(input, rsa_key.d, rsa_key.n);
    }
    output = BSWAP64(output);

    if (flag & RSA_FLAG_HEX)
        rsautl_hexdump(output, fd_out);
    else
        write(fd_out, &output, RSA_KEY_LEN / 8);

    if (fd_in != 0) close(fd_in);
    if (fd_out != 1) close(fd_out);
}
