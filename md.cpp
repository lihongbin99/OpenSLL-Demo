#include <iostream>
#include <openssl/md5.h>

void mdTest() {
    const unsigned char msg[] = "Hello World!";
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
}
