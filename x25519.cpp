#include <iostream>

#include <openssl/evp.h>

using namespace std;

void x25519Test() {
    unsigned char pri1[32]{
        1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    unsigned char pri2[32]{
        0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    EVP_PKEY* pri_key1 = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, pri1, sizeof(pri1));
    EVP_PKEY* pri_key2 = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, pri2, sizeof(pri2));

    unsigned char pub1[32];
    size_t size1 = sizeof(pub1);
    unsigned char pub2[32];
    size_t size2 = sizeof(pub2);

    EVP_PKEY_get_raw_public_key(pri_key1, pub1, &size1);
    EVP_PKEY_get_raw_public_key(pri_key2, pub2, &size2);

    printf("pri1:\n");
    for (int i = 0; i < sizeof(pri1); ++i) {
        printf("%02X", pri1[i]);
    }
    printf("\n");
    printf("pri2:\n");
    for (int i = 0; i < sizeof(pri2); ++i) {
        printf("%02X", pri2[i]);
    }
    printf("\n");
    printf("pub1:\n");
    for (int i = 0; i < size1; ++i) {
        printf("%02X", pub1[i]);
    }
    printf("\n");
    printf("pub2:\n");
    for (int i = 0; i < size2; ++i) {
        printf("%02X", pub2[i]);
    }
    printf("\n");

    EVP_PKEY* pub_key1 = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub1, size1);
    EVP_PKEY* pub_key2 = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub2, size2);

    unsigned char share_key1[32];
    size_t share_key1_len = sizeof(share_key1);
    EVP_PKEY_CTX* ctx1 = EVP_PKEY_CTX_new(pri_key1, NULL);
    EVP_PKEY_derive_init(ctx1);
    EVP_PKEY_derive_set_peer(ctx1, pub_key2);
    EVP_PKEY_derive(ctx1, share_key1, &share_key1_len);

    unsigned char share_key2[32];
    size_t share_key2_len = sizeof(share_key2);
    EVP_PKEY_CTX* ctx2 = EVP_PKEY_CTX_new(pri_key2, NULL);
    EVP_PKEY_derive_init(ctx2);
    EVP_PKEY_derive_set_peer(ctx2, pub_key1);
    EVP_PKEY_derive(ctx2, share_key2, &share_key2_len);

    printf("share1:\n");
    for (int i = 0; i < share_key1_len; ++i) {
        printf("%02X", share_key1[i]);
    }
    printf("\n");
    printf("share2:\n");
    for (int i = 0; i < share_key2_len; ++i) {
        printf("%02X", share_key2[i]);
    }
    printf("\n");
}