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

bool Sign32(const char *priv, const char *elfPath);

bool CheckSign32(const char *pub, const char *elfPath);

bool exec32(const char *elf32);

#endif //ELFSIGN_SIGN32_H
