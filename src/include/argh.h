//
// Created by root on 2020/3/21.
//

#ifndef ELFSIGN_ARGH_H
#define ELFSIGN_ARGH_H

#include <getopt.h>

typedef struct {
    char *pripath;      // -p private key path
    char *pubpath;      // -p public key path
    char *elf;          // -e ELF file path

    int generateKey;    // -g generate public/private key
    int checkSign;      // -c check sign of ELF and execute it
    int sign;           // -s sign the ELF file
} Argh;


const char *optString = "p:e:gcsh";

const struct option longOptions[] = {
        {"elf",   required_argument, NULL, 'e'},
        {"check", no_argument,       NULL, 'c'},
        {"sign",  no_argument,       NULL, 's'},
        {"help",  no_argument,       NULL, 'h'},
        {"path",  required_argument, NULL, 'p'},
        {NULL,    no_argument,       NULL, 0}
};

#endif //ELFSIGN_ARGH_H
