//
// Created by root on 2020/3/16.
//

#include <elf_64.h>
#include <sign.h>
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
