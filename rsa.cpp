#include <iostream>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

using namespace std;

void rsaTest() {
  const unsigned char msg[] = "Hello World!";
  // const unsigned char msg[245] = "Hello World!";
  // const unsigned char msg[256] = "Hello World!";
  const int msgLen = sizeof(msg);
  unsigned char result[256];

  // 1. 生成 RSA 密钥对
  RSA* rsa1 = RSA_generate_key(2048, RSA_F4, NULL, NULL);
  RSA* rsa_pub = rsa1;
  RSA* rsa_pri = rsa1;
  // 将密钥写入文件
  // FILE *pubkey_file = fopen("pubkey.pem", "wb");
  // PEM_write_RSAPublicKey(pubkey_file, rsa_pub);
  // fclose(pubkey_file);
  // FILE *privkey_file = fopen("privkey.pem", "wb");
  // PEM_write_RSAPrivateKey(privkey_file, rsa_pri, NULL, NULL, 0, NULL, NULL);
  // fclose(privkey_file);

  // 2. 读取 RSA 密钥对
  // FILE* pubkey_file = fopen("pubkey.pem", "rb");
  // RSA* rsa_pub = PEM_read_RSAPublicKey(pubkey_file, NULL, NULL, NULL);
  // fclose(pubkey_file);
  // FILE *prikey_file = fopen("privkey.pem", "rb");
  // RSA *rsa_pri = PEM_read_RSAPrivateKey(prikey_file, NULL, NULL, NULL);
  // fclose(prikey_file);

  int resultLen = 0;
  resultLen = RSA_public_encrypt(msgLen, msg, result, rsa_pub, RSA_PKCS1_OAEP_PADDING);
  if (resultLen < 0) {
    return;
  }
  printf("RSA Ciphertext: ");
  for (int i = 0; i < resultLen; ++i) {
    printf("%02X", result[i]);
  }
  printf("\n");

  resultLen = RSA_private_decrypt(resultLen, result, result, rsa_pri, RSA_PKCS1_OAEP_PADDING);
  if (resultLen < 0) {
    return;
  }
  result[resultLen] = 0;
  printf("RSA Plaintext: %s\n", result);

  // 释放内存
  // RSA_free(rsa_pub);
  // RSA_free(rsa_pri);
}
