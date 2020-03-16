//
// Created by root on 2020/3/16.
//

#include <elf_64.h>

bool IsELF(const char *file) {
    unsigned char ident[EI_NIDENT];
    FILE *fd = fopen(file, "rb");
    if (!fd) {
        err_msg("Can not open file %s", file);
        return false;
    }
    int ret = fread(ident, 1, EI_NIDENT, fd);
    fclose(fd);
    if (ret != EI_NIDENT) {
        err_msg("Read ELF magic failed!");
        return false;
    }
    if (ident[0] == 0x7f && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F') {
        return true;
    } else {
        return false;
    }
}

void SetElfPath(Elf64 *elf64, const char *path) {
    int len = strlen(path);
    elf64->path = (char *) malloc(len);
    strcpy(elf64->path, path);
}

bool GetEhdr(Elf64 *elf64) {
    if (elf64->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }
    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    int ret = fread(&elf64->ehdr, 1, sizeof(Elf64_Ehdr), fd);
    fclose(fd);
    if (ret != sizeof(Elf64_Ehdr)) {
        err_msg("Read ELF Header failed");
        return false;
    }
    return true;
}

bool Getshstrtabhdr(Elf64 *elf64) {
    int offset = 0;
    if (elf64->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }
    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    offset = elf64->ehdr.e_shoff + elf64->ehdr.e_shentsize * elf64->ehdr.e_shstrndx;
    fseek(fd, offset, SEEK_SET);
    int ret = fread(&elf64->shstrtabhdr, 1, sizeof(Elf64_Shdr), fd);
    if (ret != sizeof(Elf64_Shdr)) {
        err_msg("Read Section Header Table failed");
        return false;
    }
    return true;
}

bool Getshstrtab(Elf64 *elf64) {
    if (elf64->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }
    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    elf64->shstrtab = (char *) malloc(elf64->shstrtabhdr.sh_size);
    fseek(fd, elf64->shstrtabhdr.sh_offset, SEEK_SET);
    int ret = fread(elf64->shstrtab, 1, elf64->shstrtabhdr.sh_size, fd);
    fclose(fd);
    if (ret != elf64->shstrtabhdr.sh_size) {
        err_msg("Read shstrtab Section failed");
        return false;
    }
    return true;
}

int GetFileSize(Elf64 *elf64) {
    if (!elf64->path) {
        err_msg("ELF file not set");
        return -1;
    }
    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return -1;
    }
    fseek(fd, 0, SEEK_END);
    elf64->size = ftell(fd);
    return elf64->size;
}

void Destract(Elf64 *elf64) {
    if (elf64->path != NULL) {
        free(elf64->path);
    }
}

