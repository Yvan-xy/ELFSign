//
// Created by root on 2020/3/16.
//

#include <elf_64.h>
#include <assert.h>


void elf64Tester() {
    log_msg("\n---------- ELF TEST ----------");
    Elf64 elf64;
    bool isElf = IsELF("./out");
    assert(isElf);
    isElf = IsELF("./Makefile");
    assert(isElf == false);
    log_msg("Is ELF check pass!");

    // Test reading ELF Header
    SetElfPath(&elf64, "./a");
    log_msg("ELF path is %s", elf64.path);
    assert(!strcmp(elf64.path, "./a"));
    bool ret = GetEhdr(&elf64);
    assert(ret);
    log_msg("Read ELF Head success!");

    // Test reading Section Header offset
    log_msg("\n----------> ELF Header");
    log_msg("Section Header Offset is %ld(%p)", elf64.ehdr.e_shoff, elf64.ehdr.e_shoff);
    log_msg("Size of Section Header Entry %d(%p)", elf64.ehdr.e_shentsize, elf64.ehdr.e_shentsize);
    log_msg("Section header string table index %d(%p)", elf64.ehdr.e_shstrndx, elf64.ehdr.e_shstrndx);

    // Test reading Section name string table section header
    ret = Getshstrtabhdr(&elf64);
    assert(ret);
    log_msg("shstrtab offset is %d(%p)", elf64.shstrtabhdr.sh_offset, elf64.shstrtabhdr.sh_offset);
    log_msg("shstrtab size is %d(%p)", elf64.shstrtabhdr.sh_size, elf64.shstrtabhdr.sh_size);
    log_msg("Section shstrtab aligned size %d(%p)", elf64.shstrtabhdr.sh_addralign, elf64.shstrtabhdr.sh_addralign);
    log_msg("Name offset in shstrtab %d(%p)", elf64.shstrtabhdr.sh_name, elf64.shstrtabhdr.sh_name);

    // Test reading shstrtab contain
    ret = Getshstrtab(&elf64);
    assert(ret);
    for (uint16_t i = 0; i < elf64.shstrtabhdr.sh_size; i++) {
        if (elf64.shstrtab[i] == 0)
            printf(" ");
        else
            printf("%c", elf64.shstrtab[i]);
    }

    // Test get elf file size
    log_msg("\n----------> Rewrite ELF");
    long int size = GetFileSize(&elf64);
    assert(size == elf64.size);
    log_msg("ELF file size is %p", elf64.size);

    Destract(&elf64);

    // Test reading
}