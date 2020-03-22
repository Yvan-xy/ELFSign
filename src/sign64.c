//
// Created by root on 2020/3/16.
//

#include <apue.h>
#include <sign.h>
#include <argh.h>
#include <elf_64.h>
#include <sign64.h>
#include <stdbool.h>

Elf64 *InitELF64(const char *path) {
    Elf64 *elf64 = (Elf64 *) malloc(sizeof(Elf64));
    SetElf64Path(elf64, path);
    bool ret = GetEhdr64(elf64);
    if (!ret)
        return NULL;

    ret = Getshstrtabhdr64(elf64);
    if (!ret)
        return NULL;

    ret = Getshstrtab64(elf64);
    if (!ret)
        return NULL;

    ret = GetFileSize64(elf64);
    if (!ret)
        return NULL;

    return elf64;
}

bool SignToELF64(Elf64 *elf64, RSA *pri) {
    unsigned char sign[256];


    int ret = HashText64(elf64);
    if (!ret)
        return false;

    ret = AddSectionHeader64(elf64);
    if (!ret)
        return false;

    ret = AddSectionName64(elf64);
    if (!ret)
        return false;

    GetSign(elf64->digest, sign, pri);

    FILE *fd = fopen(elf64->path, "ab+");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    ret = fwrite(sign, 1, 256, fd);
    fclose(fd);
    if (ret != 256) {
        err_msg("Write .text hash failed");
        return false;
    }
    return true;
}

bool ReadELF64Sign(Elf64 *elf64) {
    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    fseek(fd, -256, SEEK_END);
    int ret = fread(elf64->sign, 1, 256, fd);
    if (ret != 256) {
        err_msg("Read digest failed");
        return false;
    }
    return true;
}

bool CheckSignELF64(Elf64 *elf64, RSA *pub) {
    return RSA_verify(NID_sha1, elf64->digest, SHA_DIGEST_LENGTH, elf64->sign, 256, pub);
}

bool Sign64(const char *priv, const char *elfPath) {
    printf("\033[34m---------- Sign to ELF ----------\033[0m\n");
    Elf64 *elf64;
    elf64 = InitELF64(elfPath);
    RSA *pri = ReadPrivateKey(priv);
    int ret = SignToELF64(elf64, pri);
    if (ret == false) {
        err_msg("Sign ELF64 %s failed", elfPath);
    }
    log_msg("Sign ELF64 %s success!\n", elfPath);
    Destract64(elf64);
    return ret;
}

bool CheckSign64(const char *pub, const char *elfPath) {
    printf("\033[34m---------- Verify ELF's Sign ----------\033[0m\n");
    Elf64 *elf64;

    elf64 = InitELF64(elfPath);
    RSA *public = ReadPublicKey(pub);

    ReadELF64Sign(elf64);
    HashText64(elf64);
    int ret = CheckSignELF64(elf64, public);
    if (ret == false) {
        err_msg("ELF64 %s verify failed!\n", elfPath);
        return ret;
    }
    log_msg("ELF64 %s verify success!\n", elfPath);
    exec64(elfPath);
    Destract64(elf64);
    return ret;
}

bool exec64(const char *elf64) {
    char *cmd;
    extern Argh argh;
    if (argh.hasArgs == 1) {
        int argsLen = strlen(argh.args);
        log_msg("argh.args is %s", argh.args);
        if ((elf64[0] == '.' && elf64[1] == '/') || elf64[0] == '/') {
            cmd = (char *) malloc(strlen(elf64) + argsLen + 1);
            strcpy(cmd, elf64);
            cmd[strlen(elf64)] = ' ';
            strcpy(cmd + strlen(elf64) + 1, argh.args);
        } else {
            cmd = (char *) malloc(2 + strlen(elf64) + 1 + strlen(argh.args));
            cmd[0] = '.';
            cmd[1] = '/';
            strcpy(cmd + 2, elf64);
            cmd[2 + strlen(elf64)] = ' ';
            strcpy(cmd + 3 + strlen(elf64), argh.args);
        }
        system(cmd);
        free(cmd);
    } else {
        if ((elf64[0] == '.' && elf64[1] == '/') || elf64[0] == '/') {
            cmd = (char *) malloc(strlen(elf64));
            strcpy(cmd, elf64);
        } else {
            cmd = (char *) malloc(2 + strlen(elf64));
            cmd[0] = '.';
            cmd[1] = '/';
            strcpy(cmd + 2, elf64);
        }
        system(cmd);
        free(cmd);
    }
    return true;
}

bool X509CheckSign64(const char *x509Path, const char *elfPath) {
    printf("\033[34m---------- Verify ELF's Sign with X509----------\033[0m\n");

    RSA *public;
    X509 *x509;
    Elf64 *elf64;
    EVP_PKEY *pubKey;

    elf64 = InitELF64(elfPath);

    x509 = ReadX509File(x509Path);
    pubKey = X509_get_pubkey(x509);

    if (pubKey == NULL) {
        err_msg("Get public key failed\n");
        return false;
    }

    public = EVP_PKEY_get1_RSA(pubKey);
    EVP_PKEY_free(pubKey);
    if (public == NULL) {
        err_msg("Get public key failed\n");
        return false;
    }

    ReadELF64Sign(elf64);
    HashText64(elf64);
    int ret = CheckSignELF64(elf64, public);
    if (ret == false) {
        err_msg("ELF64 %s verify failed!\n", elfPath);
        return ret;
    }
    log_msg("ELF64 %s verify success!\n", elfPath);
    exec64(elfPath);
    Destract64(elf64);
    X509_free(x509);
    return ret;
}