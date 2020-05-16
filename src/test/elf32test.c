//
// Created by root on 2020/3/21.
//

#include <elf_32.h>
#include <assert.h>

void elf32BaseTester() {
    log_msg("\n---------- ELF64 Base Function TEST ----------");
    Elf32 elf32;
    bool isElf = IsELF32("./a");
    assert(isElf);
    isElf = IsELF32("./Makefile");
    assert(isElf == false);
    log_msg("Is ELF check pass!");

    // Test reading ELF Header
    SetElf32Path(&elf32, "./a");
    log_msg("ELF path is %s", elf32.path);
    assert(!strcmp(elf32.path, "./a"));
    bool ret = GetEhdr32(&elf32);
    assert(ret);
    log_msg("Read ELF Head success!");

    // Test reading Section Header offset
    log_msg("\n----------> ELF Header");
    log_msg("Section Header Offset is %ld(%p)", elf32.ehdr.e_shoff, elf32.ehdr.e_shoff);
    log_msg("Size of Section Header Entry %d(%p)", elf32.ehdr.e_shentsize, elf32.ehdr.e_shentsize);
    log_msg("Section header string table index %d(%p)", elf32.ehdr.e_shstrndx, elf32.ehdr.e_shstrndx);


    // Test reading Section name string table section header
    ret = Getshstrtabhdr32(&elf32);
    assert(ret);
    log_msg("shstrtab offset is %d(%p)", elf32.shstrtabhdr.sh_offset, elf32.shstrtabhdr.sh_offset);
    log_msg("shstrtab size is %d(%p)", elf32.shstrtabhdr.sh_size, elf32.shstrtabhdr.sh_size);
    log_msg("Section shstrtab aligned size %d(%p)", elf32.shstrtabhdr.sh_addralign, elf32.shstrtabhdr.sh_addralign);
    log_msg("Name offset in shstrtab %d(%p)", elf32.shstrtabhdr.sh_name, elf32.shstrtabhdr.sh_name);

    // Test reading shstrtab contain
    ret = Getshstrtab32(&elf32);
    assert(ret);
//    for (uint16_t i = 0; i < elf32.shstrtabhdr.sh_size; i++) {
//        if (elf32.shstrtab[i] == 0)
//            printf(" ");
//        else
//            printf("%c", elf64.shstrtab[i]);
//    }

    // Test reading Program Header Table
    log_msg("\n----------> Program Header Table");
    log_msg("Program Entry Size is %d", elf32.ehdr.e_phentsize);
    log_msg("Program Entry Number is %d", elf32.ehdr.e_phnum);

    // Test get elf file size
    log_msg("\n----------> Rewrite ELF");
    long int size = GetFileSize32(&elf32);
    assert(size == elf32.size);
    log_msg("ELF file size is %p", elf32.size);

//    ret = AddSectionHeader32(&elf32);
//    assert(ret);
//    ret = AddSectionName32(&elf32);
//    assert(ret);

    HashText32(&elf32);
    printf("\n----------> Hash of .text:\n");
    for (int i = 0; i < 20; i++)
        printf("%p ", elf32.digest[i]);

    Destract32(&elf32);
    log_msg("ELF32 base function test pass!");

}