//
// Created by root on 2020/3/21.
//

#include <elf_32.h>
#include <sign32.h>

void sign32Tester() {
    log_msg("---------- Sign to ELF TEST ----------");
    Elf32 *elf32;
    elf32 = InitELF32("./a");
    RSA *pri = ReadPrivateKey("./pem/prikey.pem");
    RSA *pub = ReadPublicKey("./pem/pubkey.pem");
    int ret = SignToELF32(elf32, pri);
    assert(ret);

    // Test check sign of elf
    ret = ReadELF32Sign(elf32);
    assert(ret);
    ret = CheckSignELF32(elf32, pub);
    assert(ret);
    log_msg("Check Sign Pass");
}

