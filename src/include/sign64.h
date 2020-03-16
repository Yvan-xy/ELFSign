//
// Created by root on 2020/3/16.
//

#ifndef ELFSIGN_SIGN64_H
#define ELFSIGN_SIGN64_H

#include <elf_64.h>
#include <sign.h>

Elf64 *InitELF64(const char *path);

bool SignToELF64(Elf64 *elf64, RSA *pri);

bool ReadELF64Sign(Elf64 *elf64);

bool CheckSignELF64(Elf64 *elf64, RSA *pub);

#endif //ELFSIGN_SIGN64_H
