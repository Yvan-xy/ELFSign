#include <sign.h>
#include <test.h>
#include <argh.h>
#include <sign32.h>
#include <sign64.h>

int main(int argc, char *argv[]) {
//    sign32Tester();
//    elf64BaseTester();
    elf32BaseTester();
    exit(0);

    int opt = 0, longIndex;

    if (argc == 1) {
        ShowTips((const char **) argv);
        return 0;
    }

    do {
        opt = getopt_long(argc, argv, optString, longOptions, &longIndex);
        switch (opt) {
            case 'g':
                GenerateRSAKey();
                log_msg("Generate key success!");
                exit(0);
            case 'x':
                GenerateX509();
                log_msg("Generate X509 success!");
                exit(0);
            case 'e':
                argh.elf = optarg;
                break;
            case 's':
                argh.sign = 1;
                argh.pubpath = 0;
                argh.checkSignX509 = 0;
                break;
            case 'c':
                argh.sign = 0;
                argh.checkSign = 1;
                argh.checkSignX509 = 0;
                break;
            case 'X':
                argh.sign = 0;
                argh.checkSign = 0;
                argh.checkSignX509 = 1;
                break;
            case 'p':
                if (argh.sign)
                    argh.pripath = optarg;
                else if (argh.checkSign || argh.checkSignX509)
                    argh.pubpath = optarg;
                break;
            case 'a':
                argh.args = optarg;
                argh.hasArgs = 1;
                ParseArgs();
                break;
            case 'h':
                ShowTips((const char **) argv);
                return 0;
            case '?':
                printf("Use -h|--help for more help\n");
                return 0;
            default:
                break;
        }
    } while (opt != -1);

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
    } else if (argh.checkSignX509 == 1) {
        int type = IsELF32(argh.elf);
        if (type)
            X509CheckSign32(argh.pubpath, argh.elf);
        else {
            type = IsELF64(argh.elf);
            if (type)
                X509CheckSign64(argh.pubpath, argh.elf);
            else {
                log_msg("%s is not ELF file!", argh.elf);
                return 0;
            }
        }
    }

    return 0;
}
