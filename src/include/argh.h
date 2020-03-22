//
// Created by root on 2020/3/21.
//

#ifndef ELFSIGN_ARGH_H
#define ELFSIGN_ARGH_H

#include <getopt.h>

#define USAGE_FORMAT "USAGE: %s [options] file...\n"

typedef struct {
    char *pripath;          // -p private key path
    char *pubpath;          // -p public key path
    char *elf;              // -e ELF file path
    char *args;             // -a Arguments of ELF file
    char **argsArr;

    int generateKey;        // -g generate public/private key
    int checkSign;          // -c check sign of ELF and execute it
    int checkSignX509;
    int hasArgs;
    int sign;               // -s sign the ELF file
} Argh;

Argh argh;

static const char *optString = "p:e:a:gxcshX?";

static const struct option longOptions[] = {
        {"argument",    required_argument, NULL, 'a'},
        {"elf",         required_argument, NULL, 'e'},
        {"path",        required_argument, NULL, 'p'},
        {"check",       no_argument,       NULL, 'c'},
        {"sign",        no_argument,       NULL, 's'},
        {"help",        no_argument,       NULL, 'h'},
        {"generate",    no_argument,       NULL, 'g'},
        {"create-X509", no_argument,       NULL, 'x'},
        {"check-X509",  no_argument,       NULL, 'X'},
        {NULL,          no_argument,       NULL, 0}
};

static void ShowTips(const char *argv[]) {
    printf(USAGE_FORMAT, argv[0]);
    printf("Options:\n");
    printf("\t-c, --check Check ELF file and execute it\n");
    printf("\t-X, --check-X509 Check ELF file with X509 and execute it\n");
    printf("\t-s, --sign Sign a ELF file\n");
    printf("\t-a, --argument Set arguments of ELF file to execute\n");
    printf("\t-g, --generate Generate public and private key pair\n");
    printf("\t-x, --create-X509 Generate X509 certificate\n");
    printf("\t-p, --path Set the path of public/private key\n");
    printf("\t-e, --elf Set the path of ELF file\n");
    printf("\nExample:\n");
    printf("\t ./ELFSign --sign -p ./prikey.pem -e hello.out\n");
    printf("\t ./ELFSign -c -p ./pubkey.pem -e hello.out\n");
    printf("\t ./ELFSign -X -p ./ELFSign.pem -e /usr/bin/cat -a a.txt\n");
}

static void ParseArgs() {
    char *tmp[20];
    memset(tmp, 0, sizeof(tmp));
    int i = 1;
    char *pch;
    pch = strtok(argh.args, " ");
    tmp[0] = pch;
    while (pch = strtok(NULL, " ")) {
        tmp[i] = pch;
        i++;
    }
    for (i = 0; tmp[i] != NULL; i++) {
        i++;
    }
    argh.argsArr = (char **) malloc(sizeof(char *) * i);
    for (int k = 0; k < i; k++) {
        argh.argsArr[k] = tmp[k];
    }
    argh.argsArr[i] = NULL;
}

#endif //ELFSIGN_ARGH_H
