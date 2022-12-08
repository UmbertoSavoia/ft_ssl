#ifndef FT_GETOPT_H
#define FT_GETOPT_H

#include <unistd.h>
#include <string.h>

extern char *optarg;
extern int  optind;

int ft_getopt(int argc, char *const argv[], const char *optstring);

#endif