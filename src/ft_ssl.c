#include "ft_ssl.h"

int     list_command(void)
{
    printf("Standard commands:\n"
           "genrsa\n"
           "rsa\n"
           "rsautl\n\n"
           "Message Digest commands:\n"
           "md5\n"
           "sha256\n\n"
           "Cipher commands:\n"
           "base64\n"
           "des\n"
           "des-ecb\n"
           "des-cbc\n");
    return 1;
}

int     main(int ac, char **av)
{
    t_dispatch dispatch[] = {
            { .algo = "md5",    .func = &ft_md5 },
            { .algo = "sha256", .func = &ft_sha256 },
    };

    if (ac < 2)
        return printf("usage: %s command [command opts] [command args]\n", av[0]);

    for (int i = 0; i < sizeof(dispatch); ++i) {
        if (!memcmp(av[1], dispatch[i].algo, strlen(av[1])))
            return dispatch[i].func(ac, av);
    }
    return printf("%s: Error: '%s' is an invalid command.\n", av[0], av[1]) && list_command();
}
