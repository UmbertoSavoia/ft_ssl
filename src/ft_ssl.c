#include "ft_ssl.h"

int     main(int ac, char **av)
{
    t_dispatch dispatch[] = {
            { .algo = "md5",    .func = &md5 },
            { .algo = "sha256", .func = &sha256 },
    };

    if (ac < 2)
        return 1;

    for (int i = 0; i < sizeof(dispatch); ++i) {
        if (!memcmp(av[1], dispatch[i].algo, strlen(av[1])))
            return dispatch[i].func(ac, av);
    }
}
