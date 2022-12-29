#include <iostream>

#include <openssl/md5.h>
#include <openssl/sha.h>

int main() {
    std::cout << "Hello World!" << std::endl;

    const unsigned char msg[] = "Hello World!";
    const unsigned char key[] = "00000000000000000000000000000000";
    const unsigned char iv[]  = "00000000000000000000000000000000";
    const int msgLen = sizeof(msg) - 1;

    unsigned char md5Result[16] { 0 };
    MD5_CTX md5CTX;
    MD5_Init(&md5CTX);
    MD5_Update(&md5CTX, msg, msgLen);
    MD5_Final(md5Result, &md5CTX);
    printf("md5: ");
    for (int i = 0; i < sizeof(md5Result); ++i) {
        printf("%02X ", md5Result[i]);
    }
    printf("\n");

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
    printf("sha384: ");
    for (int i = 0; i < sizeof(sha512Result); ++i) {
        printf("%02X ", sha512Result[i]);
    }
    printf("\n");
}
