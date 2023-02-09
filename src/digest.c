#include "ft_ssl.h"
#include "ft_md5.h"
#include "ft_sha256.h"
#include "ft_whirlpool.h"
#include "ft_digest.h"
#include "ft_getopt.h"

void    digest_stdin(t_digest *algo, int tee)
{
    int r = 0;
    uint8_t buf[512] = {0};
    uint8_t *digest = 0;

    if (!(digest = malloc(algo->digest_len)))
        return ;
    algo->init();
    while ((r = read(0, buf, sizeof(buf))) > 0) {
        if (tee)
            write(1, buf, r);
        algo->update(buf, r);
    }
    algo->final(digest);
    PRINT_HEX(digest, algo->digest_len);
    printf("\n");
    free(digest);
}

void    digest_file(t_digest *algo, char *filename, uint8_t opt)
{
    int fd = 0, r = 0;
    uint8_t buf[512] = {0};
    errno = 0;
    uint8_t *digest = 0;

    if (!(digest = malloc(algo->digest_len)))
        return ;
    if ((fd = open(filename, O_RDONLY)) < 0) {
        printf("%s: %s: %s\n", "ft_ssl", filename, strerror(errno));
        return;
    }
    algo->init();
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        algo->update(buf, r);
    }
    algo->final(digest);
    close(fd);
    if (opt & Q_FLAG) {
        PRINT_HEX(digest, algo->digest_len);
    } else if (opt & R_FLAG) {
        PRINT_HEX(digest, algo->digest_len);
        printf(" %s", filename);
    } else {
        printf("%s (%s) = ", algo->name_up, filename);
        PRINT_HEX(digest, algo->digest_len);
    }
    printf("\n");
    free(digest);
}

void    digest_string(t_digest *algo, char *str, uint8_t opt)
{
    uint8_t *digest = 0;

    if (!(digest = malloc(algo->digest_len)))
        return ;
    algo->init();
    algo->update((uint8_t *)str, strlen(str));
    algo->final(digest);

    if (opt & Q_FLAG) {
        PRINT_HEX(digest, algo->digest_len);
    } else if (opt & R_FLAG) {
        PRINT_HEX(digest, algo->digest_len);
        printf(" \"%s\"", str);
    } else {
        printf("%s (\"%s\") = ", algo->name_up, str);
        PRINT_HEX(digest, algo->digest_len);
    }
    printf("\n");
    free(digest);
}

int     ft_digest(int ac, char **av)
{
    t_digest algo[] = {
            {.name_lo = "md5", .name_up = "MD5", .init = &md5_init, .update = &md5_update, .final = &md5_final, .digest_len = MD5_DIGEST_SIZE},
            {.name_lo = "sha256", .name_up = "SHA256", .init = &sha256_init, .update = &sha256_update, .final = &sha256_final, .digest_len = SHA256_DIGEST_SIZE},
            {.name_lo = "whirlpool", .name_up = "WHIRLPOOL", .init = &whirlpool_init, .update = &whirlpool_update, .final = &whirlpool_final, .digest_len = WHIRLPOOL_DIGEST_SIZE}
    };
    t_digest *p_algo = 0;
    uint8_t opt = 0;
    int c = 0;
    ft_optind = 2;

    for (int i = 0; (i < ARRAY_SIZE(algo)) && ac >= 1; ++i)
        if (!memcmp(algo[i].name_lo, av[1], strlen(algo[i].name_lo)))
            p_algo = &algo[i];

    if (!p_algo)
        return -1;
    while ((c = ft_getopt(ac, av, "s:pqr")) != -1) {
        switch (c) {
            case 'p':
                digest_stdin(p_algo, 1);
                break;
            case 'q':
                opt |= Q_FLAG;
                break;
            case 'r':
                opt |= R_FLAG;
                break;
            case 's':
                opt |= S_FLAG;
                digest_string(p_algo, ft_optarg, opt);
                break;
            default:
                printf("usage: %s %s [-pqr] [-s string] [file]\n", av[0], p_algo->name_lo);
        }
    }
    ac -= ft_optind;
    av += ft_optind;
    if (*av) {
        while (*av) {
            digest_file(p_algo, *av, opt);
            ++av;
        }
    } else if (!(opt & S_FLAG) && (ft_optind == 2 || (opt & Q_FLAG) || (opt & R_FLAG)))
        digest_stdin(p_algo, 0);
    return 0;
}