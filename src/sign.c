#include <sign.h>

void GenerateRSAKey() {
    int ret = 0;
    int privLen, pubLen;
    char *privKey, *pubKey;
    BIGNUM *bne = BN_new();
    RSA *rsa = RSA_new();

    ret = BN_set_word(bne, RSA_F4);
    if (ret != 1)
        err_quit("MakeLocalKeySSL BN_set_word err \n");

    ret = RSA_generate_key_ex(rsa, KEY_LENGTH, bne, NULL);
    if (ret != 1)
        err_quit("RSA generate failed");

    /* To get the C-string PEM form: */
    BIO *priv = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, rsa);

    privLen = BIO_pending(priv);
    pubLen = BIO_pending(pub);

    privKey = calloc(privLen + 1, 1); /* Null-terminate */
    pubKey = calloc(pubLen + 1, 1);

    BIO_read(priv, privKey, privLen);
    BIO_read(pub, pubKey, pubLen);

    // 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private
    // key开头的）
    FILE *pubFile = fopen(PUB_KEY_FILE, "w");
    FileWrite(pubFile, pubKey);

    FILE *privFile = fopen(PRI_KEY_FILE, "w");
    FileWrite(privFile, privKey);

    BIO_free_all(priv);
    BIO_free_all(pub);

    RSA_free(rsa);
    free(privKey);
    free(pubKey);
}

void FileWrite(FILE *fd, char *contain) {
    if (fd == NULL) {
        assert(false);
        return;
    }
    int ret = fputs(contain, fd);
    if (ret == EOF) {
        err_quit("File puts error");
    } else {
        log_msg("File write success");
    }
    fclose(fd);
}

void SetPublicKeyPath(const char *path) {
    unsigned long len = strlen(path);
    if (READ_PUB_KEY_PATH != NULL)
        free(READ_PUB_KEY_PATH);
    READ_PUB_KEY_PATH = (char *) malloc(len);
    if (READ_PUB_KEY_PATH == NULL)
        err_msg("Set public key path failed");
    strcpy(READ_PUB_KEY_PATH, path);
}

void SetPrivateKeyPath(const char *path) {
    unsigned long len = strlen(path);
    if (READ_PRIV_KEY_PATH != NULL)
        free(READ_PRIV_KEY_PATH);
    READ_PRIV_KEY_PATH = (char *) malloc(len);
    if (READ_PRIV_KEY_PATH == NULL)
        err_msg("Set private key path failed");
    strcpy(READ_PRIV_KEY_PATH, path);
}

char *GetPublicKeyPath() {
    return READ_PUB_KEY_PATH;
}

char *GetPrivateKeyPath() {
    return READ_PRIV_KEY_PATH;
}

/*读取公匙*/
RSA *ReadPublicKey(const char *path) {
    BIO *pub = NULL;

    RSA *pubRsa = NULL;

    log_msg("PublicKeyPath [%s]", path);

    pub = BIO_new(BIO_s_file());

    /*	打开密钥文件 */
    BIO_read_filename(pub, path);
    pubRsa = PEM_read_bio_RSAPublicKey(pub, NULL, NULL, NULL);
    if (pubRsa == NULL) {
        err_quit("Read error");
    }

    BIO_free_all(pub);

    return pubRsa;
}

/*读取私钥*/
RSA *ReadPrivateKey(const char *path) {
    RSA *priRsa = NULL;
    BIO *pri = NULL;

    log_msg("PrivateKeyPath [%s]", path);

    pri = BIO_new(BIO_s_file());

    /* 打开公钥文件 */
    BIO_read_filename(pri, path);
    priRsa = PEM_read_bio_RSAPrivateKey(pri, NULL, NULL, NULL);
    if (priRsa == NULL) {
        err_quit("Read private key error");
    }

    BIO_free_all(pri);

    return priRsa;
}

int GetSign(unsigned char *hash, unsigned char *sign, RSA *pri) {
    unsigned int signLen;
    int ret;
    ret = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sign, &signLen, pri);
    if (ret != 1)
        err_msg("RSA sign failed");
    return signLen;
}

int RSACheckSign(const char *contain, unsigned char *sign, int signLen, RSA *pub) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    SHA1_Init(&ctx);

    SHA1_Update(&ctx, contain, 12);
    SHA1_Final(digest, &ctx);
    return RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, sign,
                      signLen,
                      pub);//==1
}


void GenerateX509() {
    int ret = 0;
    int privLen, pubLen;
    char *privKey;
    BIGNUM *bne = BN_new();
    RSA *rsa = RSA_new();

    ret = BN_set_word(bne, RSA_F4);
    if (ret != 1)
        err_quit("BN_set_word failed\n");

    ret = RSA_generate_key_ex(rsa, KEY_LENGTH, bne, NULL);
    if (ret != 1)
        err_quit("RSA generate failed");

    /* Write private key to pem file */
    BIO *priv = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL);
    privLen = BIO_pending(priv);

    privKey = calloc(privLen + 1, 1);
    BIO_read(priv, privKey, privLen);

    FILE *priFile = fopen(PRI_KEY_FILE, "w");
    FileWrite(priFile, privKey);

    EVP_PKEY *pubKey = EVP_PKEY_new();
    if (!pubKey)
        err_quit("Create EVP_PKEY structure failed\n");

    ret = EVP_PKEY_assign_RSA(pubKey, rsa);
    if (ret != 1)
        err_quit("Assign RSA key failed\n");

    X509 *x509 = X509_new();
    if (!x509)
        err_quit("Create X509 structure failed\n");

    /* Set the serial number */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    /* This certificate is valid from now until exactly one year from now */
    X509_gmtime_adj(X509_get_notBefore(x509), 1);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    /* Set the public key for the certificate */
    X509_set_pubkey(x509, pubKey);

    /*  Copy the subject name to the issuer name. */
    X509_NAME *name = X509_get_subject_name(x509);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *) "CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *) "Dyf", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) "blog.dyf.ink", -1, -1, 0);

    /* Now set the issuer name */
    X509_set_issuer_name(x509, name);

    /* Sign the certificate with key */
    ret = X509_sign(x509, pubKey, EVP_sha1());
    if (!ret)
        err_quit("Sign certificate failed\n");

    /* Write to disk */
    FILE *x509File = fopen(CERTIFICATE_FILE, "w");
    if (!x509File)
        err_quit("Open certificate file failed\n");

    ret = PEM_write_X509(x509File, x509);
    fclose(x509File);
    if (!ret)
        err_quit("Write certificate to disk failed\n");

    /* Free memory */
    BIO_free_all(priv);
    free(privKey);
    RSA_free(rsa);
}


// Read contain of X509 pem
X509 *ReadX509File(const char *path) {
    X509 *x509 = X509_new();
    FILE *x509File = NULL;
    log_msg("X509 certificate [%s]", path);

    /* Open X509 File */
    BIO* bio_cert = BIO_new_file(path, "rb");
    PEM_read_bio_X509(bio_cert, &x509, NULL, NULL);

    /* Read contain */
    if (x509 == NULL)
        err_quit("Read X509 file failed\n");

    BIO_free_all(bio_cert);
    return x509;
}




















