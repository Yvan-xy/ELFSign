//
// Created by root on 2020/3/21.
//

#include <elf_32.h>
#include <sign.h>
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
