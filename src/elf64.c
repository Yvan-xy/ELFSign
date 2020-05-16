//
// Created by root on 2020/3/16.
//

#include <elf_64.h>

bool IsELF64(const char *file) {
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
        if (ident[4] == 2)
            return true;
        else
            return false;
    } else {
        return false;
    }
}

void SetElf64Path(Elf64 *elf64, const char *path) {
    int len = strlen(path);
    elf64->path = (char *) malloc(len);
    strcpy(elf64->path, path);
}

bool GetEhdr64(Elf64 *elf64) {
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

bool Getshstrtabhdr64(Elf64 *elf64) {
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

bool Getshstrtab64(Elf64 *elf64) {
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

// Get orign file size
int GetFileSize64(Elf64 *elf64) {
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

// Add a new section header at the end of file
bool AddSectionHeader64(Elf64 *elf64) {
    if (elf64->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }
    FILE *fd = fopen(elf64->path, "ab+");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    fseek(fd, 0, SEEK_END);

    Elf64_Shdr signSection;
    CreateSignSection64(elf64, &signSection);
    int ret = fwrite(&signSection, 1, sizeof(Elf64_Shdr), fd);
    fclose(fd);
    if (ret != sizeof(Elf64_Shdr)) {
        err_msg("Write Sign Section Header Failded");
        return false;
    }
    return true;
}

// Init a new section header
bool CreateSignSection64(Elf64 *elf64, Elf64_Shdr *signSection) {
    int shstrOffset = elf64->shstrtabhdr.sh_offset;
    signSection->sh_name = sizeof(Elf64_Shdr) + elf64->size - shstrOffset;
    signSection->sh_type = SHT_NOTE;
    signSection->sh_flags = SHF_ALLOC;
    signSection->sh_addr = elf64->size + sizeof(Elf64_Shdr) + 8;
    signSection->sh_offset = elf64->size + sizeof(Elf64_Shdr) + 8;
    signSection->sh_size = 256; // RSA sign length
    signSection->sh_link = 0;
    signSection->sh_info = 0;
    signSection->sh_addralign = 1;
    signSection->sh_entsize = 0;
    return true;
}

// Add section name ".sign" at the end of file
bool AddSectionName64(Elf64 *elf64) {
    const char *sectionName = ".sign\0\0\0";
    if (elf64->path == NULL) {
        err_msg("ELF file not set");
        return false;
    }

    FILE *fd = fopen(elf64->path, "ab+");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    int ret = fwrite(sectionName, 1, 8, fd);
    fclose(fd);
    if (ret != 8) {
        err_msg("Write section name failed");
        return false;
    }
    ret = UpdateShstrtabSize64(elf64);
    if (!ret)
        return false;
    ret = UpdateShnum64(elf64);
    if (!ret)
        return false;
    return true;
}

bool UpdateShstrtabSize64(Elf64 *elf64) {
    int offset = 0, size = 0;
    FILE *fd = fopen(elf64->path, "rb+");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }

    // offset to Section shstrtab's Header -> sh_size
    // 1. Go to shstrtab header item
    offset = elf64->ehdr.e_shoff + elf64->ehdr.e_shentsize * elf64->ehdr.e_shstrndx;
    // 2. sh_name + sh_type + sh_flags + sh_offset
    offset += sizeof(Elf64_Word) * 2 + sizeof(Elf64_Xword) + sizeof(Elf64_Addr) + sizeof(Elf64_Off);
    fseek(fd, offset, SEEK_SET);


    // end + section_header + name - shstrtab_offset
    size = elf64->size + sizeof(Elf64_Shdr) + 6 - elf64->shstrtabhdr.sh_offset;
    int ret = fwrite(&size, 1, sizeof(size), fd);
    fclose(fd);
    if (ret != sizeof(size)) {
        err_msg("Write new section size failed");
        return false;
    }
    return true;
}

bool UpdateShnum64(Elf64 *elf64) {
    int offset = 0;
    Elf64_Half newSize = elf64->ehdr.e_shnum + 1;
    FILE *fd = fopen(elf64->path, "rb+");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }

    offset = sizeof(Elf64_Ehdr) - sizeof(Elf64_Half) * 2;
//    log_msg("Offset number of sections is %d(%p)", offset, offset);
    fseek(fd, offset, SEEK_SET);
    int ret = fwrite(&newSize, 1, sizeof(newSize), fd);
    fclose(fd);
    if (ret != sizeof(newSize)) {
        err_msg("Write new section number failed");
        return false;
    }
    return true;
}

bool HashText64(Elf64 *elf64) {
    Elf64_Off programHeaderTable = elf64->ehdr.e_phoff;
    Elf64_Phdr tmp;
    char name[20];
    unsigned char *content = NULL;
    unsigned char buf[1];

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return false;
    }
    fseek(fd, programHeaderTable, SEEK_SET);
    for (int count = 0; count < elf64->ehdr.e_phnum; ++count) {

        size_t ret = fread(&tmp, 1, sizeof(Elf64_Phdr), fd);
        if (ret != sizeof(Elf64_Phdr)) {
            err_msg("Read Program Header failed");
            return false;
        }

#if(LOG_MODE == 1)
        log_msg("p_type is %d", tmp.p_type);
        log_msg("p_offset is %p", tmp.p_offset);
        log_msg("p_vaddr is %p", tmp.p_vaddr);
        log_msg("p_filez is %p", tmp.p_filesz);
        log_msg("----------->");
#endif

        /* Judge if Load Segment */
        if (tmp.p_type != PT_LOAD || tmp.p_offset == 0)
            continue;

        content = GetLoadSegment64(elf64, &tmp);

#if(LOG_MODE == 1)
        printf("\n----------> Load Segment Content\n");
        for (int i = 0; i < tmp.p_filesz; i++) {
            printf("%p ", content[i]);
        }
#endif

        SHA1_Update(&ctx, content, tmp.p_filesz);

        if (content != NULL)
            free(content);

        content = NULL;
    }

    fclose(fd);
    SHA1_Final(elf64->digest, &ctx);
    return true;
}

unsigned char *GetLoadSegment64(Elf64 *elf64, Elf64_Phdr *phdr) {
    if (phdr == NULL) {
        err_msg("phdr not exist");
        return false;
    }
    Elf64_Off p_offset = phdr->p_offset;
    Elf64_Word p_filesz = phdr->p_filesz;

    FILE *fd = fopen(elf64->path, "rb");
    if (!fd) {
        err_msg("Can not open file %s", elf64->path);
        return NULL;
    }

    char *content = malloc(p_filesz);

    fseek(fd, p_offset, SEEK_SET);

    int ret = fread(content, 1, p_filesz, fd);
    fclose(fd);
    if (ret != p_filesz) {
        err_msg("Read Program Header -> content failed");
        return NULL;
    }
    return content;
}

void Destract64(Elf64 *elf64) {
    if (elf64->path != NULL) {
        free(elf64->path);
    }
    if (elf64->shstrtab != NULL) {
        free(elf64->shstrtab);
    }
}



















