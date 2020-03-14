#include <sign.h>

void signTester() {
    // Generate key
    GenerateRSAKey();

    log_msg("-------------------");
    // Set public key path
    SetPublicKeyPath("./pubkey.pem");
    char *pubpath = GetPublicKeyPath();
    log_msg("Public key path is %s", pubpath);

    // Set private key path
    log_msg("\n-------------------");
    SetPrivateKeyPath("./prikey.pem");
    char *privpath = GetPrivateKeyPath("./prikey.pem");
    log_msg("Private key path is %s", privpath);

    // Read public key
    log_msg("\n-------------------");
    RSA *pub = ReadPublicKey(READ_PUB_KEY_PATH);
    log_msg("pub addr is %p", pub);

    // Read private key
    log_msg("\n-------------------");
    RSA *pri = ReadPrivateKey(READ_PRIV_KEY_PATH);
    log_msg("pub addr is %p", pri);

    // Test hash function
    log_msg("\n-------------------");
    unsigned const char msg[] = "Hello world!";
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    SHA1_Init(&ctx);

    SHA1_Update(&ctx, msg, 12);
    SHA1_Final(digest, &ctx);
    for (int i = 0; i < 20; i++)
        printf("%02x ", digest[i]);

    // Test RSA_sign
    log_msg("\n-------------------");
    unsigned char sign[10240];
    int signLen = GetSign(digest, sign, pri);
    for (int i=0;i<signLen;i++)
        printf("%02d ", sign[i]);

    FILE *signfd = fopen("sign.txt", "w");
    FileWrite(signfd, sign);

    log_msg("\nSign len is %d", signLen);
    char *base64sign = Base64Encode(sign, signLen);
    log_msg("Base64 sign: %s", base64sign);

    // Test
}



























