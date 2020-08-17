//
// Created by root on 2020/3/21.
//

#ifndef ELFSIGN_ARGH_H
#define ELFSIGN_ARGH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
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
    printf("Options:\n"
        "\t-c, --check Check ELF file and execute it\n"
        "\t-X, --check-X509 Check ELF file with X509 and execute it\n"
        "\t-s, --sign Sign a ELF file\n"
        "\t-a, --argument Set arguments of ELF file to execute\n"
        "\t-g, --generate Generate public and private key pair\n"
        "\t-x, --create-X509 Generate X509 certificate\n"
        "\t-p, --path Set the path of public/private key\n"
        "\t-e, --elf Set the path of ELF file\n"
        "\nExample:\n"
        "\t ./ELFSign --sign -p ./prikey.pem -e hello.out\n"
        "\t ./ELFSign -c -p ./pubkey.pem -e hello.out\n"
        "\t ./ELFSign -X -p ./ELFSign.pem -e /usr/bin/cat -a a.txt\n");
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

enum M_TYPE {
    X86, X86_64, ARM_32, ARM_64, MIPS_32, MIPS_64, ERROR
};

#endif //ELFSIGN_ARGH_H
