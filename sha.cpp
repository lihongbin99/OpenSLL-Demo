#include <iostream>
#include <openssl/sha.h>

void shaTest() {
    const unsigned char msg[] = "Hello World!";
    const int msgLen = sizeof(msg) - 1;

    unsigned char sha1Result[20] { 0 };
    SHA_CTX sha1CTX;
    SHA1_Init(&sha1CTX);
    SHA1_Update(&sha1CTX, msg, msgLen);
    SHA1_Final(sha1Result, &sha1CTX);
    printf("sha1: ");
    for (int i = 0; i < sizeof(sha1Result); ++i) {
        printf("%02X ", sha1Result[i]);
    }
    printf("\n");

    unsigned char sha224Result[28] { 0 };
    SHA256_CTX sha224CTX;
    SHA224_Init(&sha224CTX);
    SHA224_Update(&sha224CTX, msg, msgLen);
    SHA224_Final(sha224Result, &sha224CTX);
    printf("sha224: ");
    for (int i = 0; i < sizeof(sha224Result); ++i) {
        printf("%02X ", sha224Result[i]);
    }
    printf("\n");

    unsigned char sha256Result[32] { 0 };
    SHA256_CTX sha256CTX;
    SHA256_Init(&sha256CTX);
    SHA256_Update(&sha256CTX, msg, msgLen);
    SHA256_Final(sha256Result, &sha256CTX);
    printf("sha256: ");
    for (int i = 0; i < sizeof(sha256Result); ++i) {
        printf("%02X ", sha256Result[i]);
    }
    printf("\n");

    unsigned char sha384Result[48] { 0 };
    SHA512_CTX sha384CTX;
    SHA384_Init(&sha384CTX);
    SHA384_Update(&sha384CTX, msg, msgLen);
    SHA384_Final(sha384Result, &sha384CTX);
    printf("sha384: ");
    for (int i = 0; i < sizeof(sha384Result); ++i) {
        printf("%02X ", sha384Result[i]);
    }
    printf("\n");

    unsigned char sha512Result[64] { 0 };
    SHA512_CTX sha512CTX;
    SHA512_Init(&sha512CTX);
    SHA512_Update(&sha512CTX, msg, msgLen);
    SHA512_Final(sha512Result, &sha512CTX);
    printf("sha512: ");
    for (int i = 0; i < sizeof(sha512Result); ++i) {
        printf("%02X ", sha512Result[i]);
    }
    printf("\n");
}