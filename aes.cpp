#include <iostream>

#include <openssl/aes.h>
#include <openssl/evp.h>

void aesTest() {
    const unsigned char msg[] = "Hello World!";
    const unsigned char key[] = "00000000000000000000000000000000";
    const unsigned char iv [] = "00000000000000000000000000000000";
    const int msgLen = sizeof(msg) - 1;

    int outLen;
    int totalOutLen;
    EVP_CIPHER_CTX* ctx;

    unsigned char aes128ecbResult[16];
    outLen = totalOutLen = 0;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_128_ecb(), key, NULL, AES_ENCRYPT);
    EVP_CipherUpdate(ctx, aes128ecbResult, &outLen, msg, msgLen);
    totalOutLen += outLen;
    EVP_CipherFinal(ctx, aes128ecbResult + totalOutLen, &outLen);
    totalOutLen += outLen;
    EVP_CIPHER_CTX_free(ctx);
    printf("aes128ecb: ");
    for (int i = 0; i < totalOutLen; ++i) {
        printf("%02X ", aes128ecbResult[i]);
    }
    printf("\n");

    unsigned char aes256ecbResult[16];
    outLen = totalOutLen = 0;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_256_ecb(), key, NULL, AES_ENCRYPT);
    EVP_CipherUpdate(ctx, aes256ecbResult, &outLen, msg, msgLen);
    totalOutLen += outLen;
    EVP_CipherFinal(ctx, aes256ecbResult + totalOutLen, &outLen);
    totalOutLen += outLen;
    EVP_CIPHER_CTX_free(ctx);
    printf("aes256ecb: ");
    for (int i = 0; i < totalOutLen; ++i) {
        printf("%02X ", aes256ecbResult[i]);
    }
    printf("\n");

    unsigned char aes256cbcResult[16];
    outLen = totalOutLen = 0;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, iv, AES_ENCRYPT);
    EVP_CipherUpdate(ctx, aes256cbcResult, &outLen, msg, msgLen);
    totalOutLen += outLen;
    EVP_CipherFinal(ctx, aes256cbcResult + totalOutLen, &outLen);
    totalOutLen += outLen;
    EVP_CIPHER_CTX_free(ctx);
    printf("aes256cbc: ");
    for (int i = 0; i < totalOutLen; ++i) {
        printf("%02X ", aes256cbcResult[i]);
    }
    printf("\n");

    unsigned char aes256ctrResult[msgLen];
    outLen = totalOutLen = 0;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_256_ctr(), key, iv, AES_ENCRYPT);
    EVP_CipherUpdate(ctx, aes256ctrResult, &outLen, msg, msgLen);
    totalOutLen += outLen;
    EVP_CipherFinal(ctx, aes256ctrResult + totalOutLen, &outLen);
    totalOutLen += outLen;
    EVP_CIPHER_CTX_free(ctx);
    printf("aes256ctr: ");
    for (int i = 0; i < totalOutLen; ++i) {
        printf("%02X ", aes256ctrResult[i]);
    }
    printf("\n");

    unsigned char aes256gcmResult[msgLen];
    outLen = totalOutLen = 0;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_256_gcm(), key, iv, AES_ENCRYPT);
    EVP_CipherUpdate(ctx, aes256gcmResult, &outLen, msg, msgLen);
    totalOutLen += outLen;
    EVP_CipherFinal(ctx, aes256gcmResult + totalOutLen, &outLen);
    totalOutLen += outLen;
    EVP_CIPHER_CTX_free(ctx);
    printf("aes256gcm: ");
    for (int i = 0; i < totalOutLen; ++i) {
        printf("%02X ", aes256gcmResult[i]);
    }
    printf("\n");

}
