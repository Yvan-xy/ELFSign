//
// Created by root on 2020/3/21.
//

#include <sign.h>
#include <argh.h>
#include <elf_32.h>
#include <sign32.h>
#include <stdbool.h>

Elf32 *InitELF32(const char *path) {
    Elf32 *elf32 = (Elf32 *) malloc(sizeof(Elf32));
    SetElf32Path(elf32, path);
    bool ret = GetEhdr32(elf32);
    if (!ret)
        return NULL;

    ret = Getshstrtabhdr32(elf32);
    if (!ret)
        return NULL;

    ret = Getshstrtab32(elf32);
    if (!ret)
        return NULL;

    ret = GetFileSize32(elf32);
    if (!ret)
        return NULL;

    return elf32;
}

bool SignToELF32(Elf32 *elf32, RSA *pri) {
    unsigned char sign[256];


    int ret = HashText32(elf32);
    if (!ret)
        return false;

    ret = AddSectionHeader32(elf32);
    if (!ret)
        return false;

    ret = AddSectionName32(elf32);
    if (!ret)
        return false;

    GetSign(elf32->digest, sign, pri);

    FILE *fd = fopen(elf32->path, "ab+");
    if (!fd) {
        err_msg("Can not open file %s", elf32->path);
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

bool ReadELF32Sign(Elf32 *elf32) {
    FILE *fd = fopen(elf32->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf32->path);
        return false;
    }
    fseek(fd, -256, SEEK_END);
    int ret = fread(elf32->sign, 1, 256, fd);
    if (ret != 256) {
        err_msg("Read digest failed");
        return false;
    }
    return true;
}

bool CheckSignELF32(Elf32 *elf32, RSA *pub) {
    return RSA_verify(NID_sha1, elf32->digest, SHA_DIGEST_LENGTH, elf32->sign, 256, pub);
}

bool Sign32(const char *priv, const char *elfPath) {
    printf("\033[34m---------- Sign to ELF ----------\033[0m\n");
    Elf32 *elf32;
    elf32 = InitELF32(elfPath);
    RSA *pri = ReadPrivateKey(priv);
    int ret = SignToELF32(elf32, pri);
    if (ret == false) {
        err_msg("Sign ELF32 %s failed", elfPath);
    }
    log_msg("Sign ELF32 %s success!\n", elfPath);
    Destract32(elf32);
    return ret;
}

bool CheckSign32(const char *pub, const char *elfPath) {
    printf("\033[34m---------- Verify ELF's Sign ----------\033[0m\n");
    Elf32 *elf32;

    elf32 = InitELF32(elfPath);
    RSA *public = ReadPublicKey(pub);

    ReadELF32Sign(elf32);
    HashText32(elf32);

    int ret = CheckSignELF32(elf32, public);
    if (ret == false) {
        err_msg("ELF32 %s verify failed!\n", elfPath);
        return ret;
    }
    log_msg("ELF32 %s verify success!\n", elfPath);
    exec32(elfPath);
    Destract32(elf32);
    return ret;
}

bool exec32(const char *elf32) {
    char *cmd;
    extern Argh argh;
    if (argh.hasArgs == 1) {

        int argsLen = strlen(argh.args);
        log_msg("argh.args is %s", argh.args);
        if ((elf32[0] == '.' && elf32[1] == '/') || elf32[0] == '/') {
            cmd = (char *) malloc(strlen(elf32) + argsLen + 1);
            strcpy(cmd, elf32);
            cmd[strlen(elf32)] = ' ';
            strcpy(cmd + strlen(elf32) + 1, argh.args);
        } else {
            cmd = (char *) malloc(2 + strlen(elf32) + 1 + strlen(argh.args));
            cmd[0] = '.';
            cmd[1] = '/';
            strcpy(cmd + 2, elf32);
            cmd[2 + strlen(elf32)] = ' ';
            strcpy(cmd + 3 + strlen(elf32), argh.args);
        }
        system(cmd);
        free(cmd);
    } else {
        if ((elf32[0] == '.' && elf32[1] == '/') || elf32[0] == '/') {
            cmd = (char *) malloc(strlen(elf32));
            strcpy(cmd, elf32);
        } else {
            cmd = (char *) malloc(2 + strlen(elf32));
            cmd[0] = '.';
            cmd[1] = '/';
            strcpy(cmd + 2, elf32);
        }
        system(cmd);
        free(cmd);
    }
    return true;
}

bool X509CheckSign32(const char *x509Path, const char *elfPath) {
    printf("\033[34m---------- Verify ELF's Sign with X509----------\033[0m\n");

    RSA *public;
    X509 *x509;
    Elf32 *elf32;
    EVP_PKEY *pubKey;

    elf32 = InitELF32(elfPath);

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

    ReadELF32Sign(elf32);
    HashText32(elf32);
    int ret = CheckSignELF32(elf32, public);
    if (ret == false) {
        err_msg("ELF32 %s verify failed!\n", elfPath);
        return ret;
    }
    log_msg("ELF32 %s verify success!\n", elfPath);
    exec32(elfPath);
    Destract32(elf32);
    X509_free(x509);
    return ret;
}