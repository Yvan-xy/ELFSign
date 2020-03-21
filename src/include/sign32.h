//
// Created by root on 2020/3/21.
//

#ifndef ELFSIGN_SIGN32_H
#define ELFSIGN_SIGN32_H

#include <elf_32.h>
#include <sign.h>

Elf32 *InitELF32(const char *path);

bool SignToELF32(Elf32 *elf32, RSA *pri);

bool ReadELF32Sign(Elf32 *elf32);

bool CheckSignELF32(Elf32 *elf32, RSA *pub);

#endif //ELFSIGN_SIGN32_H
