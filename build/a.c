 #include <stdio.h>
 #include <string.h>
 #include <openssl/sha.h>

int main()
{
    unsigned const char ibuf[] = "Hello world!";
    unsigned char obuf[20];
    printf("%d\n", strlen(ibuf));

    SHA1(ibuf, strlen((const char * )ibuf), obuf);
    int i;

    for(i = 0; i < 20; i++)
    {
        printf("%02x ", obuf[i]);

    }    
    printf("\n");

// Error checking omitted for expository purposes

// Object to hold the current state of the hash
SHA_CTX ctx;
SHA1_Init(&ctx);

// Hash each piece of data as it comes in:
SHA1_Update(&ctx, "Hello ", 6);
SHA1_Update(&ctx, "world!", 6);
// etc.
// When you're done with the data, finalize it:
unsigned char hash[SHA_DIGEST_LENGTH];
SHA1_Final(hash, &ctx);
for(i=0;i<20;i++){
    printf("%02x ", hash[i]);
}

    return 0;
}
