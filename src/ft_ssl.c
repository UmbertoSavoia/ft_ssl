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
           "des-cbc\n"
           "des-pcbc\n"
           "des-cfb\n"
           "des-ofb\n"
           "des-ctr\n"
           "des3\n"
           "des3-ecb\n"
           "des3-cbc\n"
           "des3-pcbc\n"
           "des3-cfb\n"
           "des3-ofb\n"
           "des3-ctr\n"
           );
    return 1;
}

int    dispatcher(int ac, char **av)
{
    t_dispatch dispatch[] = {
            { .algo = "md5",        .func = &ft_digest },
            { .algo = "sha256",     .func = &ft_digest },
            { .algo = "whirlpool",  .func = &ft_digest },
            { .algo = "base64",     .func = &ft_base64 },
            { .algo = "des-ecb",    .func = &ft_cipher },
            { .algo = "des-cbc",    .func = &ft_cipher },
            { .algo = "des-pcbc",   .func = &ft_cipher },
            { .algo = "des-cfb",    .func = &ft_cipher },
            { .algo = "des-ofb",    .func = &ft_cipher },
            { .algo = "des-ctr",    .func = &ft_cipher },
            { .algo = "des3-ecb",  .func = &ft_cipher },
            { .algo = "des3-cbc",  .func = &ft_cipher },
            { .algo = "des3-pcbc", .func = &ft_cipher },
            { .algo = "des3-cfb",  .func = &ft_cipher },
            { .algo = "des3-ofb",  .func = &ft_cipher },
            { .algo = "des3-ctr",  .func = &ft_cipher },
            { .algo = "genrsa",    .func = &genrsa },
            { .algo = "rsa",       .func = &rsa },
            { .algo = "rsautl",    .func = &rsautl },
            { .algo = "gendes",    .func = &gendes },
            { .algo = "breakit",   .func = &breakit },
            { .algo = "gendsa",    .func = &gendsa },
    };

    for (int i = 0; (i < (int)ARRAY_SIZE(dispatch)) && ac >= 1; ++i) {
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
