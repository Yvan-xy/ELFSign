//
// Created by root on 2020/3/16.
//

#include <elf_64.h>
#include <sign.h>
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
        err_msg("ELF32 %s verify failed!\n", elfPath);
        return ret;
    }
    log_msg("ELF32 %s verify success!\n", elfPath);
    exec64(elfPath);
    Destract64(elf64);
    return ret;
}

bool exec64(const char *elf64) {
    char *name;
    if (elf64[0] == '.' || elf64[1] == '/')
        system(elf64);
    else if (elf64[0] == '/')
        system(elf64);
    else {
        name = (char *) malloc(2 + strlen(elf64));
        name[0] = '.';
        name[1] = '/';
        strcpy(name + 2, elf64);
        system(name);
        free(name);
    }
}