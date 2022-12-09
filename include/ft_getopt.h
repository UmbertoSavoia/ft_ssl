#ifndef FT_GETOPT_H
#define FT_GETOPT_H

#include <unistd.h>
#include <string.h>

extern char *ft_optarg;
extern int  ft_optind;

int ft_getopt(int argc, char *const argv[], const char *optstring);

#endif