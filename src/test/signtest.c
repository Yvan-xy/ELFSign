#include <sign.h>
#include <base64.h>

void signTester() {
    // Generate key
    GenerateRSAKey();

    log_msg("-------------------");
    // Set public key path
    SetPublicKeyPath("./pem/pubkey.pem");
    SetPublicKeyPath("./pem/pubkey.pem");

    char *pubpath = GetPublicKeyPath();
    log_msg("Public key path is %s", pubpath);

    // Set private key path
    log_msg("\n-------------------");
    SetPrivateKeyPath("./pem/prikey.pem");
    SetPrivateKeyPath("./pem/prikey.pem");

    char *privpath = GetPrivateKeyPath("./pem/prikey.pem");
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
        printf("%p ", digest[i]);

    // Test RSA_sign
    log_msg("\n\n-------------------");
    unsigned char sign[10240];
    int signLen = GetSign(digest, sign, pri);
    for (int i=0;i<signLen;i++)
        printf("%p ", sign[i]);

    FILE *signfd = fopen("sign.txt", "w");
    fwrite(sign, 1, signLen, signfd);

    // Test Base64
    log_msg("\n\n-------------------");
    log_msg("Sign len is %d", signLen);
    int flen;
    char *base64sign = base64(sign, signLen, &flen);
    log_msg("Base64 sign: %s", base64sign);
    log_msg("Base64 len is %d", flen);
    int unflen;
    unsigned char *base64decode = unbase64(base64sign, flen, &unflen);
    for (int i=0;i<signLen;i++)
        printf("%p ", base64decode[i]);
    log_msg("\nBase decode len is %d", unflen);
    // Test
}



























