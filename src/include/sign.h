#ifndef SIGN_H
#define SIGN_H

#include <apue.h>
#include <config.h>
#include <errno.h>  // for definition of errno
#include <stdarg.h> // ISO C variable aruments
#include <assert.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>

// ---- rsa非对称加解密 ---- //


char *READ_PUB_KEY_PATH;
char *READ_PRIV_KEY_PATH;

void GenerateRSAKey();

void FileWrite(FILE *fd, char *contain);

void SetPublicKeyPath(const char *path);

void SetPrivateKeyPath(const char *path);

char *GetPublicKeyPath();

char *GetPrivateKeyPath();

RSA *ReadPublicKey(char *path);

RSA *ReadPrivateKey(char *path);

int GetSign(unsigned char *hash, unsigned char *sign, RSA *pri);

int RSACheckSign(char *contain, unsigned char *sign, int signLen, RSA *pub);

char *Base64Encode(const unsigned char *input, int length);

char *Base64Decode(const char *input, int length);

#endif
