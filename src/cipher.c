#include "ft_ssl.h"
#include "ft_cipher.h"
#include "ft_getopt.h"
#include "ft_base64.h"
#include "ft_des.h"

uint32_t search_cipher(t_cipher *ciphers, uint32_t len_ciphers, char *name)
{
    for (uint32_t i = 0; i < len_ciphers; ++i)
        if (!memcmp(name, ciphers[i].name, strlen(ciphers[i].name)))
            return i;
    return 0;
}

void    get_option(int ac, char **av, t_mode_arg *args, uint32_t block_size)
{
    int c = 0;

    while ((c = ft_getopt(ac, av, "adei:o:k:v:p:s:")) != -1) {
        switch (c) {
            case 'i':
                if ((args->fd_in = ft_open(ft_optarg, O_RDONLY)) < 0)
                    return ;
                break;
            case 'o':
                if ((args->fd_out = ft_open(ft_optarg, O_WRONLY|O_CREAT)) < 0)
                    return ;
                break;
            case 'k':
                args->key = str_to_hex(ft_optarg, block_size);
                args->key_len = block_size;
                break;
            case 'v':
                args->iv = str_to_hex(ft_optarg, block_size);
                break;
            case 's':
                args->salt = str_to_hex(ft_optarg, block_size);
                break;
            case 'a':
                args->flags |= A_FLAG;
                break;
            case 'd':
                args->flags ^= D_FLAG | E_FLAG;
                break;
            case 'p':
                args->pass = ft_optarg;
                break;
        }
    }
}

int     ft_cipher(int ac, char **av)
{
    t_cipher ciphers[] = {
            { .name = "des",     .block_size = DES_BLOCK_SIZE, .init = &des_init, .encrypt = &des_encrypt, .decrypt = &des_decrypt },
            { .name = "des-ecb", .block_size = DES_BLOCK_SIZE, .init = &des_init, .encrypt = &des_encrypt, .decrypt = &des_decrypt },
            { .name = "des-cbc", .block_size = DES_BLOCK_SIZE, .init = &des_init, .encrypt = &des_encrypt, .decrypt = &des_decrypt }
    };
    t_cipher_modes modes[] = {
            { .name = "-ecb", .encrypt = ecb_encrypt, .decrypt = ecb_decrypt },
            { .name = "-cbc", .encrypt = cbc_encrypt, .decrypt = cbc_decrypt }
    };
    t_mode_arg args = {0};
    args.fd_out = args.flags = 1;
    ft_optind = 2;
    uint32_t idx_cipher = 0;

    idx_cipher = search_cipher(ciphers, sizeof(ciphers) / sizeof(ciphers[0]),av[1]);
    get_option(ac, av, &args, ciphers[idx_cipher].block_size);
    resolve_base64(&args);

    if (!key_derivation(&args, ciphers[idx_cipher].block_size)) {
        for (uint32_t i = 0; i < (sizeof(modes) / sizeof(modes[0])); ++i) {
            if (strstr(av[1], modes[i].name)) {
                if (args.flags & E_FLAG)
                    modes[i].encrypt(&ciphers[idx_cipher], &args);
                else if (args.flags & D_FLAG)
                    modes[i].decrypt(&ciphers[idx_cipher], &args);
            }
        }
    }
    if ((args.flags & A_FLAG) && (args.flags & E_FLAG)) {
        lseek(args.fd_out, 0, SEEK_SET);
        encode_base64(args.fd_out, args.fd_cache);
    }

    if (args.key) free(args.key);
    if (args.iv) free(args.iv);
    if (args.salt) free(args.salt);
    if (args.fd_in != 0) close(args.fd_in);
    if (args.fd_out != 1) close(args.fd_out);
    return 0;
}