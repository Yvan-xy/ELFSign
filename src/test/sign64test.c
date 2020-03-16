//
// Created by root on 2020/3/16.
//

#include <elf_64.h>
#include <sign64.h>

void sign64Tester() {
    log_msg("---------- Sign to ELF TEST ----------");
    Elf64 *elf64;
    elf64 = InitELF64("./a");
    RSA *pri = ReadPrivateKey("./pem/prikey.pem");
    RSA *pub = ReadPublicKey("./pem/pubkey.pem");
    int ret = SignToELF64(elf64, pri);
    assert(ret);

    // Test check sign of elf
    ret = ReadELF64Sign(elf64);
    assert(ret);
    ret = CheckSignELF64(elf64, pub);
    assert(ret);
    log_msg("Check Sign Pass");
}

