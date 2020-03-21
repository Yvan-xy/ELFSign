//
// Created by root on 2020/3/21.
//

#ifndef ELFSIGN_ARGH_H
#define ELFSIGN_ARGH_H

#include <getopt.h>

#define USAGE_FORMAT "USAGE: %s [options] file...\n"

typedef struct {
    char *pripath;      // -p private key path
    char *pubpath;      // -p public key path
    char *elf;          // -e ELF file path

    int generateKey;    // -g generate public/private key
    int checkSign;      // -c check sign of ELF and execute it
    int sign;           // -s sign the ELF file
} Argh;


const char *optString = "p:e:gcsh?";

const struct option longOptions[] = {
        {"elf",      required_argument, NULL, 'e'},
        {"check",    no_argument,       NULL, 'c'},
        {"sign",     no_argument,       NULL, 's'},
        {"help",     no_argument,       NULL, 'h'},
        {"path",     required_argument, NULL, 'p'},
        {"generate", no_argument,       NULL, 'g'},
        { NULL, no_argument, NULL, 0 }
};

void ShowTips(const char *argv[]) {
    printf(USAGE_FORMAT, argv[0]);
    printf("Options:\n");
    printf("\t-c, --check Check ELF file and execute it\n");
    printf("\t-s, --sign Sign a ELF file\n");
    printf("\t-g, --generate Generate public and private key pair\n");
    printf("\t-p, --path Set the path of public/private key\n");
    printf("\t-e, --elf Set the path of ELF file\n");
    printf("\nExample:\n");
    printf("\t ./ELFSign --sign -p ./prikey.pem -e hello.out\n");
    printf("\t ./ELFSign -c -p ./pubkey.pem -e hello.out\n");
}

#endif //ELFSIGN_ARGH_H
