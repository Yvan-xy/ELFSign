//
// Created by root on 2020/3/16.
//

#ifndef ELFSIGN_ELF_64_H
#define ELFSIGN_ELF_64_H

#include <elf.h>
#include <stdio.h>
#include <apue.h>
#include <stdbool.h>

typedef struct {
    long int size;
    char *path;
    Elf64_Ehdr ehdr;
    Elf64_Shdr shstrtabhdr;
    char *shstrtab;
} Elf64;


bool IsELF(const char *file);

void SetElfPath(Elf64 *elf64, const char *path);

bool GetEhdr(Elf64 *elf64);

bool Getshstrtabhdr(Elf64 *elf64);

bool Getshstrtab(Elf64 *elf64);

int GetFileSize(Elf64 *elf64);

void Destract(Elf64 *elf64);

#endif //ELFSIGN_ELF_64_H
