#include "ft_getopt.h"

char *optarg = 0;
int  optind = 1;

int     ft_getopt(int argc, char *const argv[], const char *optstring)
{
    char *ptr = 0;
    optarg = 0;

    if (!argv || !optstring || optind > argc || argc == optind)
        return -1;

    if (argv[optind][0] == '-') {
        if ((ptr = strchr(optstring, argv[optind][1]))) {
            if (*(ptr + 1) == ':') {
                if (argv[optind][2] == 0) {
                    optarg = argv[optind+1];
                    ++optind;
                } else {
                    optarg = argv[optind] + 2;
                }
            }
            ++optind;
            return *ptr;
        } else {
            ++optind;
            return '?';
        }
    }
    return -1;
}
