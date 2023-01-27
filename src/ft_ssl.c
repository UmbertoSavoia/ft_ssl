#include "ft_ssl.h"

int     list_command(void)
{
    printf("Standard commands:\n"
           "genrsa\n"
           "rsa\n"
           "rsautl\n\n"
           "Message Digest commands:\n"
           "md5\n"
           "sha256\n"
           "whirlpool\n\n"
           "Cipher commands:\n"
           "base64\n"
           "des\n"
           "des-ecb\n"
           "des-cbc\n");
    return 1;
}

int    dispatcher(int ac, char **av)
{
    t_dispatch dispatch[] = {
            { .algo = "md5",       .func = &ft_digest },
            { .algo = "sha256",    .func = &ft_digest },
            { .algo = "whirlpool", .func = &ft_digest },
            { .algo = "base64",    .func = &ft_base64 },
            //{ .algo = "des",       .func = &ft_cipher },
            { .algo = "des-ecb",   .func = &ft_cipher },
            { .algo = "des-cbc",   .func = &ft_cipher },
            { .algo = "des3-ecb",  .func = &ft_cipher },
            { .algo = "des3-cbc",  .func = &ft_cipher },
    };

    for (int i = 0; (i < ARRAY_SIZE(dispatch)) && ac >= 1; ++i) {
        if (!memcmp(av[1], dispatch[i].algo, strlen(av[1])))
            return dispatch[i].func(ac, av);
    }
    return -1;
}

int     interactive(void)
{
    int r = 0, ac = 0;
    char *av[1024] = {0};
    char buf[1024] = {0};
    char prompt[] = "ft_ssl > ";

    while (42) {
        write(1, prompt, strlen(prompt));
        if ((r = read(0, buf, sizeof(buf))) <= 0)
            break;
        buf[r-1] = 0;
        if (!memcmp(buf, "q", 2) || !memcmp(buf, "exit", 5))
            return 0;
        int j = 0, f = 1;
        av[j++] = "ft_ssl";
        for (int i = 0; buf[i]; ++i) {
            if (f) {
                av[j++] = &buf[i];
                f = 0;
            }
            if (buf[i] == ' ') {
                buf[i] = 0;
                f = 1;
            }
        }
        av[j] = 0;
        ac = j;
        if (dispatcher(ac, av) < 0) {
            printf("%s: Error: '%s' is an invalid command.\n", av[0], av[1]);
            list_command();
        }
    }
    return 0;
}

int     main(int ac, char **av)
{
    if (ac < 2)
        return interactive();

    if (dispatcher(ac, av) < 0)
        return printf("%s: Error: '%s' is an invalid command.\n", av[0], av[1]) && list_command();
    return 0;
}
