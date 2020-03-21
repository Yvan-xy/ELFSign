#include <sign.h>
#include <test.h>
#include <argh.h>
#include <sign32.h>
#include <sign64.h>

int main(int argc, char *argv[]) {
//    sign32Tester();
    Argh argh;
    int opt = 0, longIndex;

    opt = getopt_long(argc, argv, optString, longOptions, &longIndex);

    while (opt != -1) {
        switch (opt) {
            case 'g':
                GenerateRSAKey();
                log_msg("Generate key success!\n");
                exit(0);
            case 'e':
                argh.elf = optarg;
                break;
            case 's':
                argh.sign = 1;
                argh.pubpath = 0;
                break;
            case 'c':
                argh.sign = 0;
                argh.checkSign = 1;
                break;
            case 'p':
                if (argh.sign == 1)
                    argh.pripath = optarg;
                else if (argh.checkSign == 1)
                    argh.pubpath = optarg;
                break;
            default:
                break;
        }
        opt = getopt_long(argc, argv, optString, longOptions, &longIndex);
    }

    if (argh.sign == 1) {
        int type = IsELF32(argh.elf);
        if (type)
            Sign32(argh.pripath, argh.elf);
        else {
            type = IsELF64(argh.elf);
            if (type)
                Sign64(argh.pripath, argh.elf);
            else {
                log_msg("%s is not ELF file!", argh.elf);
                return 0;
            }
        }
    } else if (argh.checkSign == 1) {
        int type = IsELF32(argh.elf);
        if (type)
            CheckSign32(argh.pubpath, argh.elf);
        else {
            type = IsELF64(argh.elf);
            if (type)
                CheckSign64(argh.pubpath, argh.elf);
            else {
                log_msg("%s is not ELF file!", argh.elf);
                return 0;
            }
        }
    }

    return 0;
}
